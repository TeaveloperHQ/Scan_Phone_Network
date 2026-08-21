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
