using System.Net;
using System.Text;
using ScanPhoneNetwork.Probes;

namespace ScanPhoneNetwork;

/// <summary>
/// ARP 로 관측한 "어느 대역의 누가 우리 브로드캐스트 도메인에서 말했다" 1건.
/// 수동 UDP 청취로는 MAC 을 못 얻으므로, pktmon 등으로 뜬 ARP 를 넣어줄 때 쓴다.
/// </summary>
public sealed record ArpSighting(string Ip, string Mac, string? Vendor);

/// <summary>업무망과 같은 L2 에 올라와 있는 남의 대역 1개.</summary>
public sealed class ForeignNetwork
{
    public required string Subnet { get; init; }
    public SchoolNetwork Guess { get; set; } = SchoolNetwork.Unknown;
    public int Observations { get; set; }
    public List<string> Devices { get; } = new();
    public List<string> Evidence { get; } = new();

    /// <summary>윈도우 모바일 핫스팟(ICS) 고정 대역 192.168.137.0/24 인가.</summary>
    public bool IsWindowsIcs { get; set; }
}

/// <summary>망 분리 점검 결과 한 묶음.</summary>
public sealed class SegregationReport
{
    public UpstreamInfo? Upstream { get; set; }
    public string LocalSubnet { get; set; } = "";
    public string? Gateway { get; set; }
    public string? GatewayVendor { get; set; }

    public List<ForeignNetwork> Foreign { get; } = new();
    public List<string> Apipa { get; } = new();
    public List<string> Unaddressed { get; } = new();
    public List<string> RogueDhcp { get; } = new();

    /// <summary>
    /// 윈도우 모바일 핫스팟(ICS)으로 확정된 신호. 192.168.137.0/24 는 윈도우가 고정으로 쓰는
    /// 대역이라 다른 해석의 여지가 거의 없다. 조치가 "장비를 뽑으세요"가 아니라
    /// "그 PC 에서 기능을 끄세요"라 따로 모은다.
    /// </summary>
    /// <remarks>
    /// 키 = 핫스팟 주소(사실상 192.168.137.1), 값 = 그 주소에서 관측된 신호들.
    /// 한 대에서 DHCP·mDNS 가 같이 잡히므로 신호 수가 아니라 <b>주소 수</b>로 세야
    /// "핫스팟 1대"를 "3건"으로 부풀리지 않는다.
    /// </remarks>
    public Dictionary<string, List<string>> IcsHotspots { get; } = new();
    public List<DiscoveredHost> Routers { get; } = new();
    public List<DiscoveredHost> Infrastructure { get; } = new();

    /// <summary>혼선이 들어오는 지점으로 지목된 장비(두 대역에 동시에 걸친 인프라).</summary>
    public List<string> CrossLinkPoints { get; } = new();

    public bool AnyForeign => Foreign.Count > 0;
    public bool AnyRogueRouter => Routers.Count > 0 || Unaddressed.Count > 0 || RogueDhcp.Count > 0;
    public bool AnyHotspot => IcsHotspots.Count > 0;
}

/// <summary>
/// "업무망이 전화망·학생망·무선망과 실제로 분리돼 있는가"를 판정한다.
///
/// 판정 근거는 단순하고 반박하기 어렵다.
/// <b>분리돼 있다면 우리 브로드캐스트 도메인에서는 우리 대역 주소만 들려야 한다.</b>
/// 다른 대역 주소가 들린다면 그 대역은 우리와 같은 L2 에 올라와 있다는 뜻이고,
/// 그것이 곧 분리 실패다.
/// </summary>
public static class SegregationAnalyzer
{
    public static SegregationReport Analyze(
        IPAddress localIp,
        IPAddress localMask,
        IPAddress? gateway,
        IReadOnlyList<DiscoveredHost> hosts,
        IReadOnlyList<PassiveObservation> observations,
        IReadOnlyList<ArpSighting>? arpSightings = null,
        UpstreamInfo? upstream = null)
    {
        int prefix = NetworkInfo.MaskToPrefix(localMask);
        var report = new SegregationReport
        {
            Upstream = upstream,
            LocalSubnet = $"{NetworkInfo.NetworkBase(localIp, localMask)}/{prefix}",
            Gateway = gateway?.ToString(),
        };

        // 같은 핫스팟에서 여러 신호가 잡히므로 주소 단위로 묶는다.
        void AddIcs(string ip, string signal)
        {
            if (!report.IcsHotspots.TryGetValue(ip, out var signals))
                report.IcsHotspots[ip] = signals = new List<string>();
            if (!signals.Contains(signal)) signals.Add(signal);
        }

        uint localNet = NetworkInfo.ToUInt(localIp) & NetworkInfo.ToUInt(localMask);
        uint maskv = NetworkInfo.ToUInt(localMask);
        bool IsLocal(IPAddress ip) => (NetworkInfo.ToUInt(ip) & maskv) == localNet;

        // 게이트웨이 제조사(= 이 망을 누가 물고 있는지)
        if (gateway is not null)
        {
            var gwHost = hosts.FirstOrDefault(h => h.Ip.Equals(gateway));
            report.GatewayVendor = gwHost?.Vendor ?? OuiDatabase.Lookup(gwHost?.Mac)?.Vendor;
        }

        report.Routers.AddRange(hosts.Where(h =>
            h.Category is DeviceCategory.Router or DeviceCategory.WirelessAp));
        report.Infrastructure.AddRange(hosts
            .Where(h => h.Category is DeviceCategory.Infrastructure)
            .OrderBy(h => NetworkInfo.ToUInt(h.Ip)));

        var foreign = new Dictionary<string, ForeignNetwork>();

        ForeignNetwork Bucket(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            string key = $"{b[0]}.{b[1]}.{b[2]}.0/24";
            if (!foreign.TryGetValue(key, out var fn))
                foreign[key] = fn = new ForeignNetwork { Subnet = key };
            return fn;
        }

        // 1) 수동 청취 결과 분류
        foreach (var o in observations)
        {
            // 주소를 못 받은 장비 — 핑 스윕으로는 절대 안 잡히는 부류
            if (o.SourceIp.Equals(IPAddress.Any))
            {
                if (o.Mac is not null)
                {
                    var vendor = OuiDatabase.Lookup(o.Mac)?.Vendor ?? "제조사 미상";
                    string line = $"{o.Mac} · {vendor} · {o.Protocol}";
                    if (!report.Unaddressed.Contains(line)) report.Unaddressed.Add(line);
                }
                continue;
            }

            if (o.Protocol == "DHCP-OFFER")
            {
                string line = $"{o.SourceIp} · {o.Detail}";

                // 192.168.137.1 이 DHCP 로 답했다 = 윈도우 PC 가 핫스팟을 켠 채
                // 업무망 쪽으로 주소를 나눠 주고 있다. 무단 공유기보다 이쪽 설명이 정확하다.
                bool ics = NetworkInfo.IsWindowsIcsRange(o.SourceIp)
                           || (o.Detail?.Contains("192.168.137.") ?? false);
                if (ics)
                {
                    AddIcs(o.SourceIp.ToString(), $"DHCP 응답 — {o.Detail}");
                }
                else if (!report.RogueDhcp.Contains(line))
                {
                    report.RogueDhcp.Add(line);
                }
            }

            // APIPA — 별도 망이 아니라 "DHCP 를 못 받은 우리 쪽 기기"
            if (o.SourceIp.GetAddressBytes() is [169, 254, ..])
            {
                string line = o.SourceIp.ToString();
                if (!report.Apipa.Contains(line)) report.Apipa.Add(line);
                continue;
            }

            if (IsLocal(o.SourceIp)) continue;

            var fn = Bucket(o.SourceIp);
            fn.Observations++;
            string dev = o.Detail is null ? o.SourceIp.ToString() : $"{o.SourceIp} · {o.Detail}";
            if (!fn.Devices.Contains(dev)) fn.Devices.Add(dev);
            if (!fn.Evidence.Contains(o.Protocol)) fn.Evidence.Add(o.Protocol);

            if (NetworkInfo.IsWindowsIcsRange(o.SourceIp))
            {
                fn.IsWindowsIcs = true;
                if (!fn.Evidence.Contains("ICS 고정 대역")) fn.Evidence.Add("ICS 고정 대역");
                if (o.Protocol != "DHCP-OFFER")   // DHCP 는 위에서 이미 기록했다
                    AddIcs(o.SourceIp.ToString(), $"{o.Protocol}{(o.Detail is null ? "" : " — " + o.Detail)}");
            }
        }

        // 2) ARP 관측(있으면) — MAC 까지 나오므로 판정이 훨씬 강해진다
        foreach (var a in arpSightings ?? Array.Empty<ArpSighting>())
        {
            if (!IPAddress.TryParse(a.Ip, out var ip)) continue;
            if (ip.GetAddressBytes() is [169, 254, ..]) continue;
            if (IsLocal(ip)) continue;

            var fn = Bucket(ip);
            fn.Observations++;
            var vendor = a.Vendor ?? OuiDatabase.Lookup(a.Mac)?.Vendor ?? "제조사 미상";
            string dev = $"{a.Ip} · {a.Mac} · {vendor}";
            if (!fn.Devices.Contains(dev)) fn.Devices.Add(dev);
            if (!fn.Evidence.Contains("ARP")) fn.Evidence.Add("ARP");

            // ARP 로 잡히면 MAC 까지 나온다. 핫스팟을 켠 PC 를 MAC 으로 특정할 수 있는
            // 유일한 경로다(UDP 청취로는 보내는 쪽 MAC 을 알 수 없다).
            if (NetworkInfo.IsWindowsIcsRange(ip))
            {
                fn.IsWindowsIcs = true;
                if (!fn.Evidence.Contains("ICS 고정 대역")) fn.Evidence.Add("ICS 고정 대역");
                AddIcs(a.Ip, $"ARP — MAC {a.Mac} ({vendor})");
            }

            // 전화망 라우터/공유기 벤더가 그 대역에 있으면 망 종류를 특정할 수 있다
            var cat = OuiDatabase.Lookup(a.Mac)?.Category;
            if (cat is DeviceCategory.VoipPhone || vendor.Contains("DAVOLINK", StringComparison.OrdinalIgnoreCase))
                fn.Guess = SchoolNetwork.Phone;
            else if (cat is DeviceCategory.Router && fn.Guess is SchoolNetwork.Unknown)
                fn.Guess = SchoolNetwork.StudentWifi;
        }

        report.Foreign.AddRange(foreign.Values.OrderByDescending(f => f.Observations));

        // 3) 혼선 진입점 — 같은 장비가 두 대역에 걸쳐 있으면 거기가 통로다.
        //    MAC 앞 5바이트가 같고 마지막 바이트만 조금 다른 것은 한 장비의 다른 인터페이스다.
        report.CrossLinkPoints.AddRange(FindCrossLinkPoints(hosts, arpSightings));

        return report;
    }

    /// <summary>
    /// 우리 대역의 장비와 남의 대역의 장비가 "같은 장비"로 보이면 그 장비가 혼선 통로다.
    /// 판단 기준: MAC 완전 일치(브리지), 또는 앞 5바이트 일치 + 마지막 바이트 차이 8 이하
    /// (같은 섀시의 인접 인터페이스. 실측 사례: …86-56 = 업무망, …86-58 = 전화망).
    /// </summary>
    private static List<string> FindCrossLinkPoints(
        IReadOnlyList<DiscoveredHost> hosts,
        IReadOnlyList<ArpSighting>? sightings)
    {
        var result = new List<string>();
        if (sightings is null || sightings.Count == 0) return result;

        foreach (var h in hosts)
        {
            if (string.IsNullOrEmpty(h.Mac)) continue;
            var mine = Hex(h.Mac);
            if (mine is null) continue;

            foreach (var s in sightings)
            {
                var theirs = Hex(s.Mac);
                if (theirs is null) continue;
                if (mine.SequenceEqual(theirs))
                {
                    result.Add($"{h.Ip} ({h.Vendor ?? "제조사 미상"}) — MAC {h.Mac} 이 {s.Ip} 로도 관측됨 · 동일 장비가 두 대역에 직접 연결");
                    continue;
                }
                bool samePrefix = mine.Take(5).SequenceEqual(theirs.Take(5));
                int diff = Math.Abs(mine[5] - theirs[5]);
                if (samePrefix && diff is > 0 and <= 8)
                {
                    result.Add($"{h.Ip} ({h.Vendor ?? "제조사 미상"}) — MAC {h.Mac} 과 {s.Mac}({s.Ip}) 는 같은 장비의 다른 인터페이스 · 이 장비가 두 망을 물고 있음");
                }
            }
        }
        return result.Distinct().ToList();
    }

    private static byte[]? Hex(string mac)
    {
        var clean = mac.Replace(":", "").Replace("-", "").Trim();
        if (clean.Length != 12) return null;
        var b = new byte[6];
        for (int i = 0; i < 6; i++)
        {
            if (!byte.TryParse(clean.AsSpan(i * 2, 2),
                    System.Globalization.NumberStyles.HexNumber, null, out b[i]))
                return null;
        }
        return b;
    }

    private static string Ko(SchoolNetwork n) => n switch
    {
        SchoolNetwork.Phone => "전화망",
        SchoolNetwork.StudentWired => "학생 유선망",
        SchoolNetwork.StudentWifi => "학생 무선망",
        SchoolNetwork.TeacherWork => "교사 업무망",
        _ => "미상",
    };

    /// <summary>
    /// 분리 판정 결과를 기존 위반 목록 형식으로 변환한다.
    /// 이걸 거치지 않으면 브리핑은 "분리 안 됨"인데 상세 보고는 "이상 없음"이 되어
    /// 읽는 사람이 어느 쪽을 믿어야 할지 알 수 없게 된다.
    /// </summary>
    public static List<PolicyViolation> ToViolations(SegregationReport r)
    {
        var list = new List<PolicyViolation>();

        if (r.IcsHotspots.Count > 0)
        {
            list.Add(new PolicyViolation
            {
                Kind = ViolationKind.Hotspot,
                Severity = Severity.Warning,
                Title = $"PC 모바일 핫스팟 사용 확인 {r.IcsHotspots.Count}대 (192.168.137.0/24)",
                Principle = "업무망 PC 는 자기 회선을 다른 기기에 나눠 주지 않아야 함",
                Detail =
                    "192.168.137.x 가 업무망 구간에서 관측됐다. 이 대역은 윈도우가 '모바일 핫스팟'\n"
                  + "       (인터넷 연결 공유)을 켤 때 항상 쓰는 고정 대역이고 사용자가 바꿀 수 없다.\n"
                  + "       따라서 교내 PC 한 대가 자기 회선을 무선으로 나눠 주고 있다고 봐도 된다.\n"
                  + string.Join("\n", r.IcsHotspots.Select(
                        kv => $"       · {kv.Key}  ({string.Join(" / ", kv.Value)})")) + "\n"
                  + "       업무망 회선이 그 PC 를 거쳐 밖으로 퍼진다. 관리대장에 없는 개인 휴대폰·태블릿이\n"
                  + "       붙어도 접속 기록에는 그 PC 한 대로만 남아 누가 접속했는지 구분되지 않는다.\n"
                  + "       DHCP 응답까지 나왔다면 공유 방향을 잘못 잡아 업무망 쪽으로 주소를 뿌리는\n"
                  + "       상태이므로 더 급하다. 다른 PC 가 엉뚱한 주소를 받아 통신이 끊길 수 있다.",
                Action =
                    "수업에 꼭 필요한 경우가 아니면 제한한다. 수업용으로 켰다면 끝난 뒤 반드시 끈다.\n"
                  + "       끄는 곳: 설정 → 네트워크 및 인터넷 → 모바일 핫스팟\n"
                  + "       상시 필요하면 업무망이 아니라 학생 무선망을 쓰도록 안내한다.\n"
                  + "       어느 PC 인지 못 좁히면 스위치 MAC 주소 테이블에서 해당 포트를 찾는다.",
            });
        }

        foreach (var f in r.Foreign)
        {
            // ICS 대역은 위에서 핫스팟으로 이미 설명했다. 같은 사실을 두 번 신고하지 않는다.
            if (f.IsWindowsIcs) continue;

            var v = new PolicyViolation
            {
                Kind = ViolationKind.CrossLink,
                Severity = Severity.Critical,
                Title = $"다른 대역 {f.Subnet} 이 업무망과 같은 구간에서 관측됨",
                Principle = "업무망은 전화망·학생 유선망·학생 무선망과 분리되어야 함",
                Detail = $"분리돼 있다면 업무망 구간에서는 업무망 주소만 들려야 한다. "
                       + $"{f.Subnet} 주소가 {f.Observations}회 관측됨({string.Join(", ", f.Evidence)}) "
                       + $"= 두 망이 같은 브로드캐스트 도메인에 있다. 추정 망: {Ko(f.Guess)}.",
                Action = "해당 대역이 들어오는 스위치 구간을 찾아 VLAN 분리 또는 물리 분리. "
                       + "스위치 MAC 주소 테이블로 어느 포트에서 들어오는지 확인.",
            };
            list.Add(v);
        }

        if (r.Unaddressed.Count > 0)
        {
            var v = new PolicyViolation
            {
                Kind = ViolationKind.UnauthorizedDevice,
                Severity = Severity.Critical,
                Title = $"주소를 못 받은 미등록 장비 {r.Unaddressed.Count}대 (스캔으로는 안 잡힘)",
                Principle = "업무망에는 등록된 장비만 연결할 수 있음",
                Detail = "IP 를 받지 못한 채 DHCP 요청만 반복하는 장비다. IP 가 없으니 "
                       + "핑 스윕에는 절대 안 잡히지만, MAC 제조사로 정체가 드러난다:\n"
                       + string.Join("\n", r.Unaddressed.Select(u => "       " + u)),
                Action = "MAC 을 스위치 주소 테이블에서 찾아 물리 포트를 특정하고 분리.",
            };
            list.Add(v);
        }

        if (r.RogueDhcp.Count > 0)
        {
            var v = new PolicyViolation
            {
                Kind = ViolationKind.CrossLink,
                Severity = Severity.Critical,
                Title = "업무망에서 DHCP 응답이 관측됨",
                Principle = "업무망은 고정 IP 만 사용하며 DHCP 서버가 없어야 함",
                Detail = "이 망에는 원래 DHCP 서버가 없다. 응답이 왔다는 것은 "
                       + "무단 공유기가 자체 DHCP 를 돌리고 있다는 뜻이다:\n"
                       + string.Join("\n", r.RogueDhcp.Select(d => "       " + d)),
                Action = "응답 출처를 스위치 포트 단위로 추적해 즉시 분리.",
            };
            list.Add(v);
        }

        foreach (var c in r.CrossLinkPoints)
        {
            list.Add(new PolicyViolation
            {
                Kind = ViolationKind.CrossLink,
                Severity = Severity.Critical,
                Title = "두 망을 동시에 물고 있는 장비 발견",
                Principle = "한 장비가 분리돼야 할 두 망에 동시에 연결되면 분리는 무효",
                Detail = c,
                Action = "해당 장비의 인터페이스 구성을 확인하고 망별로 분리.",
            });
        }

        return list;
    }

    // ==================================================================
    // 브리핑 — 비전문가가 읽고 바로 판단할 수 있게
    // ==================================================================

    public static string FormatBriefing(SegregationReport r)
    {
        var sb = new StringBuilder();

        sb.AppendLine("══════════════════════════════════════════════════════");
        sb.AppendLine("  현재 네트워크 브리핑");
        sb.AppendLine("══════════════════════════════════════════════════════");
        sb.AppendLine();

        // ── 상단: 내가 어디에 붙어 있는가 ──
        sb.AppendLine("【 접속 경로 】");
        sb.AppendLine($"  상위망   {(r.Upstream is null ? "확인 불가(외부 조회 차단)" : r.Upstream.Display)}");
        sb.AppendLine($"    ↓");
        sb.AppendLine($"  교사망   {r.LocalSubnet}");
        string gw = r.Gateway ?? "미확인";
        if (!string.IsNullOrEmpty(r.GatewayVendor)) gw += $"  [{r.GatewayVendor}]";
        sb.AppendLine($"  게이트웨이 {gw}");
        sb.AppendLine();

        // ── 핵심 질문 1: 무단 공유기 ──
        sb.AppendLine("【 1. 무단 공유기가 있는가 】");
        if (!r.AnyRogueRouter && !r.AnyHotspot)
        {
            sb.AppendLine("  ✅ 발견되지 않음");
        }
        else
        {
            sb.AppendLine("  ⛔ 발견됨");
            foreach (var h in r.Routers)
                sb.AppendLine($"     · {h.Ip} · {h.Mac ?? "MAC 미확인"} · {h.Vendor ?? "제조사 미상"} (신뢰도 {h.Confidence}%)");
            foreach (var u in r.Unaddressed)
                sb.AppendLine($"     · [IP 없음] {u}  ← 주소를 못 받아 스캔으로는 안 잡히는 장비");
            foreach (var d in r.RogueDhcp)
                sb.AppendLine($"     · [DHCP 응답] {d}  ← 자체 DHCP 운영 = 뒤에 별도 망을 만들고 있음");
        }
        sb.AppendLine();

        // ── PC 핫스팟은 따로 ── 산 장비가 아니라 켜 둔 기능이라 조치가 다르다
        if (r.AnyHotspot)
        {
            sb.AppendLine($"【 1-1. PC 모바일 핫스팟 {r.IcsHotspots.Count}대 (192.168.137.0/24) 】");
            sb.AppendLine("  📶 켜져 있음");
            foreach (var (ip, signals) in r.IcsHotspots)
            {
                sb.AppendLine($"     · {ip}");
                foreach (var s in signals)
                    sb.AppendLine($"         - {s}");
            }
            sb.AppendLine();
            sb.AppendLine("     192.168.137.x 는 윈도우가 '모바일 핫스팟'(인터넷 연결 공유)을 켤 때");
            sb.AppendLine("     항상 쓰는 고정 대역입니다. 사용자가 바꿀 수 있는 값이 아니라서,");
            sb.AppendLine("     이 주소가 보이면 교내 PC 한 대가 자기 회선을 무선으로 나눠 주고 있는 것입니다.");
            sb.AppendLine();
            sb.AppendLine("     ⚠ 업무망 회선이 그 PC 를 거쳐 밖으로 퍼집니다. 관리대장에 없는 개인");
            sb.AppendLine("       휴대폰·태블릿이 붙어도, 접속 기록에는 그 PC 한 대로만 남아 구분되지 않습니다.");
            sb.AppendLine();
            sb.AppendLine("     ▸ 수업에 꼭 필요한 경우가 아니면 제한해야 합니다.");
            sb.AppendLine("       수업용으로 켰다면 수업이 끝난 뒤 반드시 끕니다.");
            sb.AppendLine("       끄는 곳: 설정 → 네트워크 및 인터넷 → 모바일 핫스팟");
            sb.AppendLine();
        }

        // ── 핵심 질문 2·3: 망 분리 ──
        sb.AppendLine("【 2. 전화망·학생망·무선망과 분리되어 있는가 】");

        // ICS 대역은 학교의 다른 망이 아니라 PC 가 켜 둔 기능이다.
        // 1-1 에서 이미 설명했으므로 여기서 또 세면 같은 사실을 두 번 신고하는 셈이 된다.
        var otherNets = r.Foreign.Where(f => !f.IsWindowsIcs).ToList();
        if (otherNets.Count == 0)
        {
            sb.AppendLine("  ✅ 분리됨 — 우리 대역 밖의 주소가 관측되지 않음");
            if (r.AnyHotspot)
                sb.AppendLine("     (192.168.137.x 는 위 1-1 의 PC 핫스팟이라 여기서 세지 않습니다)");
        }
        else
        {
            sb.AppendLine($"  ⛔ 분리 안 됨 — 남의 대역 {otherNets.Count}개가 같은 구간에서 관측됨");
            sb.AppendLine();
            sb.AppendLine("     분리돼 있다면 이 자리에서는 우리 대역 주소만 들려야 합니다.");
            sb.AppendLine("     아래 대역이 들린다는 것은 같은 스위치 구간에 함께 물려 있다는 뜻입니다.");
            sb.AppendLine();
            foreach (var f in otherNets)
            {
                sb.AppendLine($"     ▸ {f.Subnet}   추정: {Ko(f.Guess)}   관측 {f.Observations}회 ({string.Join(", ", f.Evidence)})");
                foreach (var d in f.Devices.Take(6))
                    sb.AppendLine($"         - {d}");
                if (f.Devices.Count > 6)
                    sb.AppendLine($"         - … 외 {f.Devices.Count - 6}건");
            }
        }
        sb.AppendLine();

        // ── 혼선 진입점 ──
        sb.AppendLine("【 3. 혼선은 어디서 들어오는가 】");
        if (r.CrossLinkPoints.Count > 0)
        {
            sb.AppendLine("  다음 장비가 두 망에 동시에 걸쳐 있습니다. 여기가 통로입니다.");
            foreach (var c in r.CrossLinkPoints)
                sb.AppendLine($"     ⛔ {c}");
        }
        else if (r.AnyForeign)
        {
            sb.AppendLine("  통로 장비를 자동으로 특정하지 못했습니다.");
            sb.AppendLine("  아래 장비를 게이트웨이에서 가까운 순서로 확인하십시오.");
        }
        else
        {
            sb.AppendLine("  해당 없음");
        }

        if (r.Infrastructure.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("  [점검할 스위치·보안장비 — 게이트웨이에서 가까운 순]");
            int i = 1;
            foreach (var h in r.Infrastructure)
                sb.AppendLine($"     {i++}. {h.Ip} · {h.Vendor ?? "제조사 미상"} · {h.Mac ?? "MAC 미확인"}");
            sb.AppendLine();
            sb.AppendLine("  각 장비에서 MAC 주소 테이블(포워딩 테이블)을 조회하면");
            sb.AppendLine("  문제 장비가 몇 번 포트에 물려 있는지까지 나옵니다.");
        }
        sb.AppendLine();

        // ── 참고 ──
        if (r.Apipa.Count > 0)
        {
            sb.AppendLine("【 참고: 주소를 못 받은 기기 】");
            sb.AppendLine($"  {r.Apipa.Count}대가 169.254 주소 상태입니다. 최근 누가 뭔가 새로 꽂았다는 신호입니다.");
            sb.AppendLine($"  {string.Join(", ", r.Apipa.Take(10))}");
            sb.AppendLine();
        }

        sb.AppendLine("══════════════════════════════════════════════════════");
        return sb.ToString();
    }
}
