using System.Net;
using ScanPhoneNetwork;

/// <summary>
/// 망을 건드리지 않고 판정·보고 로직만 확인하는 자체 점검.
///
/// 무단 장비가 실제로 없는 학교에서도 "이런 게 잡히면 이렇게 보고된다"를
/// 눈으로 확인할 수 있어야 한다. 특히 핫스팟처럼 재현하기 곤란한 상황
/// (검증하겠다고 업무망에서 핫스팟을 켤 수는 없다)은 이 방법 말고는 확인할 길이 없다.
///
/// 실행: scan-phone-network.exe --selftest
/// </summary>
internal static class SelfTest
{
    public static int Run()
    {
        Console.WriteLine("=== 자체 점검 (합성 데이터 · 네트워크 접근 없음) ===\n");

        var local = IPAddress.Parse("10.50.60.10");
        var mask = NetworkInfo.PrefixToMask(23);
        var gateway = IPAddress.Parse("10.50.60.1");

        var hosts = new List<DiscoveredHost>
        {
            Pc("10.50.60.10", "DESKTOP-NORMAL"),
            Infra("10.50.60.1", "SECUI (방화벽)"),
            Infra("10.50.60.5", "Ubiquoss (스위치)"),
        };

        // 핫스팟을 켠 PC 가 업무망 쪽으로 주소를 뿌리는 상황
        var observations = new List<PassiveObservation>
        {
            new("DHCP-OFFER", IPAddress.Parse("192.168.137.1"), null, "제안 주소 192.168.137.42"),
            new("mDNS", IPAddress.Parse("192.168.137.1"), null, "DESKTOP-HOTSPOT.local"),

            // IP 를 못 받고 DHCP 만 조르는 장비 (핑 스윕으로는 안 잡히는 부류)
            new("DHCP-DISCOVER", IPAddress.Any, "B0-B9-8A-11-22-33", "IP 미할당 상태"),

            // 분리돼야 할 다른 망이 같은 구간에서 들리는 상황
            new("mDNS", IPAddress.Parse("10.77.88.21"), null, "DESKTOP-OTHERNET.local"),

            // DHCP 를 못 받아 APIPA 로 떨어진 기기
            new("mDNS", IPAddress.Parse("169.254.10.20"), null, null),
        };

        var report = SegregationAnalyzer.Analyze(
            local, mask, gateway, hosts, observations, arpSightings: null, upstream: null);

        Console.WriteLine(SegregationAnalyzer.FormatBriefing(report));

        var violations = SegregationAnalyzer.ToViolations(report);
        Console.WriteLine($"── 위반 {violations.Count}건 ──\n");
        foreach (var v in violations)
        {
            Console.WriteLine($"[{v.Severity}] {v.Kind} · {v.Title}");
            Console.WriteLine($"   원칙: {v.Principle}");
            Console.WriteLine($"   상황: {v.Detail}");
            Console.WriteLine($"   조치: {v.Action}\n");
        }

        // 기대한 판정이 실제로 나왔는지 확인
        var checks = new (string Name, bool Ok)[]
        {
            ("핫스팟(ICS) 탐지",        report.AnyHotspot),
            ("ICS 를 일반 무단DHCP 로 중복 신고하지 않음", report.RogueDhcp.Count == 0),
            ("IP 없는 장비 탐지",        report.Unaddressed.Count == 1),
            ("타 대역 탐지",            report.Foreign.Any(f => f.Subnet.StartsWith("10.77.88"))),
            ("ICS 대역을 혼선으로 중복 신고하지 않음",
                                        !violations.Any(v => v.Kind == ViolationKind.CrossLink
                                                          && v.Title.Contains("192.168.137"))),
            ("APIPA 를 타 대역으로 오분류하지 않음",
                                        !report.Foreign.Any(f => f.Subnet.StartsWith("169.254"))),
            ("핫스팟 위반에 제한 안내 포함",
                                        violations.Any(v => v.Kind == ViolationKind.Hotspot
                                                         && v.Action.Contains("수업에 꼭 필요한 경우가 아니면"))),
        };

        checks = checks.Concat(SnmpBerChecks()).ToArray();

        Console.WriteLine("── 검증 ──");
        int failed = 0;
        foreach (var (name, ok) in checks)
        {
            Console.WriteLine($"  {(ok ? "통과" : "실패")}  {name}");
            if (!ok) failed++;
        }
        Console.WriteLine();
        Console.WriteLine(failed == 0 ? "전부 통과" : $"{failed}건 실패");
        return failed == 0 ? 0 : 1;
    }

    /// <summary>
    /// SNMP BER 인코더·디코더 검증. 스위치 SNMP 가 막혀 있어도 여기는 확인할 수 있다.
    /// 실제로 버그가 숨는 자리(OID 마디 127 초과, 길이 127 초과)를 노려서 만든다.
    /// </summary>
    private static IEnumerable<(string Name, bool Ok)> SnmpBerChecks()
    {
        // dot1qTpFdbPort + VLAN 4094 + MAC. 4094 는 한 바이트에 안 들어가
        // base-128 로 두 바이트가 되어야 한다. 여기가 틀리면 FDB 조회가 통째로 실패한다.
        var mac = new[] { 0x00, 0xBE, 0x43, 0x74, 0xF4, 0xDA };
        var oid = new[] { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2, 4094 }
                  .Concat(mac).ToArray();

        var pkt = ScanPhoneNetwork.Probes.Snmp.BuildResponse(
            "public", oid, ScanPhoneNetwork.Probes.Snmp.TypeInteger, new byte[] { 0x0E });
        var vb = ScanPhoneNetwork.Probes.Snmp.ParseFirstVarBind(pkt);

        yield return ("SNMP OID 왕복 (VLAN 4094 = 마디 127 초과)",
            vb is not null && vb.Oid.SequenceEqual(oid));
        yield return ("SNMP 정수값 디코딩 (포트 14)",
            vb is not null && vb.AsLong() == 14);

        // 긴 값 — 길이가 127 을 넘으면 길이 필드가 장형(0x81 nn)으로 바뀐다
        var longText = new string('A', 200);
        var pkt2 = ScanPhoneNetwork.Probes.Snmp.BuildResponse(
            "public", new[] { 1, 3, 6, 1, 2, 1, 1, 1, 0 },
            ScanPhoneNetwork.Probes.Snmp.TypeOctetString,
            System.Text.Encoding.ASCII.GetBytes(longText));
        var vb2 = ScanPhoneNetwork.Probes.Snmp.ParseFirstVarBind(pkt2);

        yield return ("SNMP 장형 길이 처리 (200바이트 문자열)",
            vb2 is not null && vb2.AsString() == longText);

        // 워크 종료 조건: 접두사를 벗어나면 멈춰야 한다
        yield return ("SNMP 테이블 경계 판정",
            ScanPhoneNetwork.Probes.Snmp.StartsWith(oid, new[] { 1, 3, 6, 1, 2, 1, 17, 7 })
            && !ScanPhoneNetwork.Probes.Snmp.StartsWith(oid, new[] { 1, 3, 6, 1, 2, 1, 17, 4 }));
    }

    private static DiscoveredHost Pc(string ip, string name)
    {
        var h = new DiscoveredHost { Ip = IPAddress.Parse(ip), Hostname = name };
        h.Category = DeviceCategory.Pc;
        return h;
    }

    private static DiscoveredHost Infra(string ip, string vendor)
    {
        var h = new DiscoveredHost { Ip = IPAddress.Parse(ip), Vendor = vendor };
        h.Category = DeviceCategory.Infrastructure;
        return h;
    }
}
