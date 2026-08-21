using System.Text;

namespace ScanPhoneNetwork;

/// <summary>이상 유형: 두 망이 연결됨(혼선) vs 개별 무단 장비.</summary>
public enum ViolationKind
{
    CrossLink,           // 혼선 — 분리돼야 할 망끼리 연결됨
    UnauthorizedDevice,  // 비인가 장비 — 업무망에 무단 연결된 장비
    NameConflict,        // 관리 이상 — PC 이름 중복으로 대장에서 장비 식별 불가
    Hotspot,             // PC 가 모바일 핫스팟을 켜 둠 — 장비가 아니라 기능 문제
}

public enum Severity { Info, Warning, Critical }

/// <summary>4개 망 분리 원칙 위반 1건.</summary>
public sealed class PolicyViolation
{
    public required ViolationKind Kind { get; init; }
    public required Severity Severity { get; init; }
    public required string Title { get; init; }
    public required string Principle { get; init; }   // 어떤 원칙을 어겼나
    public required string Detail { get; init; }       // 왜 이상인가
    public required string Action { get; init; }       // 권고 조치
    public List<DiscoveredHost> Hosts { get; } = new(); // 관련 장비(IP/MAC 노출)
}

/// <summary>
/// 학교 4개 망 분리 원칙에 비춰 스캔 결과를 평가한다. (실행 PC = 교사 업무망 전제)
/// 업무망은 유선·고정 IP·무선 없음·DHCP 없음이어야 하므로,
/// 그 외 신호는 모두 혼선 또는 비인가 장비로 본다.
/// </summary>
public static class PolicyAnalyzer
{
    public static List<PolicyViolation> Analyze(ScanReport report)
    {
        var violations = new List<PolicyViolation>();

        // 1) 무선/공유기 장비 = 비인가 장비 (업무망 무선 연결 금지 위반)
        // 핫스팟(=PC 기능)은 아래에서 따로 다룬다. 조치가 다르기 때문이다.
        var wireless = report.Hosts
            .Where(h => h.Category is DeviceCategory.Router or DeviceCategory.WirelessAp)
            .Where(h => !h.HotspotSuspected)
            .ToList();
        foreach (var h in wireless)
        {
            bool runsDhcp = h.DhcpServer;
            var v = new PolicyViolation
            {
                Kind = ViolationKind.UnauthorizedDevice,
                Severity = Severity.Critical,
                Title = "비인가 무선/공유기 장비",
                Principle = "교사 업무망에는 무선 네트워크(공유기·AP)를 연결할 수 없음",
                Detail = runsDhcp
                    ? "무선/공유기 장비가 업무망에 연결됨. 자체 DHCP까지 운영 → 뒤에 별도 망 생성(학생 무선망 성격)."
                    : "무선/공유기 장비가 업무망에 무단 연결됨.",
                Action = "해당 스위치 포트에서 장비 분리 후 포트·배선 점검",
            };
            v.Hosts.Add(h);
            violations.Add(v);
        }

        // 2) DHCP 서버(공유기로 식별 안 된 것) = 혼선 (DHCP 쓰는 학생 무선망 유입 의심)
        var dhcpOnly = report.Hosts
            .Where(h => h.DhcpServer && h.Category is not (DeviceCategory.Router or DeviceCategory.WirelessAp))
            .ToList();
        if (dhcpOnly.Count > 0)
        {
            var v = new PolicyViolation
            {
                Kind = ViolationKind.CrossLink,
                Severity = Severity.Critical,
                Title = "업무망에서 DHCP 서버 감지 (망 혼선 의심)",
                Principle = "업무망·학생 유선망은 고정 IP만 사용(DHCP 없음). DHCP는 학생 무선망에만 존재",
                Detail = "업무망에서 DHCP 응답이 잡힘 = DHCP를 쓰는 학생 무선망이 업무망에 연결됐거나, 무단 DHCP가 동작 중.",
                Action = "DHCP 출처 IP의 연결 경로 추적 → 학생 무선망과의 분리 확인",
            };
            v.Hosts.AddRange(dhcpOnly);
            violations.Add(v);
        }

        // 3) VoIP 전화기가 업무망에 보임 = 전화망 혼선
        var phones = report.Hosts.Where(h => h.Category is DeviceCategory.VoipPhone).ToList();
        if (phones.Count > 0)
        {
            var v = new PolicyViolation
            {
                Kind = ViolationKind.CrossLink,
                Severity = Severity.Warning,
                Title = "전화망 장비가 업무망에서 발견 (망 혼선 의심)",
                Principle = "전화망은 업무망과 분리되어야 함",
                Detail = "VoIP 전화기가 업무망 구간에서 응답함 = 전화망과 업무망이 연결됐을 가능성.",
                Action = "전화기 연결 포트가 전화망인지 확인 → 업무망과 분리",
            };
            v.Hosts.AddRange(phones);
            violations.Add(v);
        }

        // 3-1) PC 가 모바일 핫스팟을 켜 둔 경우
        //      장비를 새로 꽂은 게 아니라 PC 기능이 켜져 있는 것이라 조치가 다르다.
        var hotspots = report.Hosts.Where(h => h.HotspotSuspected).ToList();
        if (hotspots.Count > 0)
        {
            var v = new PolicyViolation
            {
                Kind = ViolationKind.Hotspot,
                Severity = Severity.Warning,
                Title = $"PC 모바일 핫스팟 사용 의심 {hotspots.Count}대",
                Principle = "업무망 PC 는 자기 회선을 다른 기기에 나눠 주지 않아야 함",
                Detail =
                    "PC 로 확인된 장비에서 공유기 신호가 함께 나왔다. 별도로 구입한 공유기를 꽂은 것이 아니라, "
                  + "그 PC 가 윈도우 '모바일 핫스팟'(인터넷 연결 공유)을 켜 둔 상태로 보인다.\n"
                  + "       이 상태에서는 업무망 회선이 PC 를 거쳐 무선으로 퍼져 나간다. "
                  + "관리대장에 없는 개인 휴대폰·태블릿이 업무망에 붙게 되고, 그 접속은 로그에 "
                  + "핫스팟을 켠 PC 한 대로만 남아 누가 접속했는지 구분되지 않는다.\n"
                  + "       수업에 꼭 필요한 경우가 아니면 제한해야 한다. "
                  + "수업용으로 켰다면 수업이 끝난 뒤 반드시 끈다.",
                Action =
                    "해당 PC 에서 '설정 → 네트워크 및 인터넷 → 모바일 핫스팟' 을 끈다.\n"
                  + "       수업에 상시 필요하면 업무망이 아니라 학생 무선망을 쓰도록 안내하고, "
                  + "부득이한 경우에만 사용 사유와 기간을 남긴다.",
            };
            v.Hosts.AddRange(hotspots);
            violations.Add(v);
        }

        // 4) PC 이름 중복 = 관리대장에서 장비 구분 불가
        var dupNames = report.Hosts
            .Where(h => h.HasDuplicateName && h.Hostname is not null)
            .GroupBy(h => h.Hostname!.Trim(), StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase);
        foreach (var g in dupNames)
        {
            var v = new PolicyViolation
            {
                Kind = ViolationKind.NameConflict,
                Severity = Severity.Warning,
                Title = $"PC 이름 중복: {g.Key} ({g.Count()}대)",
                Principle = "IP 관리대장은 장비를 1:1로 식별할 수 있어야 함(PC 이름 중복 불가)",
                Detail = "같은 PC 이름을 여러 대가 쓰고 있음. 복제 이미지로 설치한 뒤 이름을 바꾸지 않은 경우가 대부분이며, "
                       + "이 상태로는 대장·접속 로그에서 어느 장비인지 구분되지 않는다.",
                Action = "중복된 PC 중 한 대만 남기고 컴퓨터 이름 변경(설정 → 시스템 → 정보 → 이 PC의 이름 바꾸기). "
                       + "대장 정리는 이름이 아니라 MAC 기준으로.",
            };
            v.Hosts.AddRange(g);
            violations.Add(v);
        }

        // 5) 망 분리 판정 결과 합류 — 스캔만으로는 안 보이는 이상이 여기서 들어온다.
        //    (타 대역 혼선, IP 없는 장비, 무단 DHCP, 두 망을 물고 있는 장비)
        if (report.Segregation is not null)
            violations.AddRange(SegregationAnalyzer.ToViolations(report.Segregation));

        return violations
            .OrderByDescending(v => v.Severity)
            .ToList();
    }

    /// <summary>경고용 상세 보고 텍스트 생성(화면·CSV·CLI 공통).</summary>
    public static string FormatReport(ScanReport report, IReadOnlyList<PolicyViolation> violations)
    {
        var sb = new StringBuilder();
        sb.AppendLine("══════ 업무망 점검 상세 보고 ══════");
        sb.AppendLine($"대상: {report.TargetRange}");
        sb.AppendLine($"시각: {report.FinishedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"발견 호스트 {report.Hosts.Count}대 · 이상 {violations.Count}건");
        sb.AppendLine();

        if (violations.Count == 0)
        {
            sb.AppendLine("✅ 이상 없음 — 4개 망 분리 원칙 위반이 감지되지 않았습니다.");
            return sb.ToString();
        }

        int n = 1;
        foreach (var v in violations)
        {
            string sev = v.Severity switch
            {
                Severity.Critical => "[심각]",
                Severity.Warning => "[주의]",
                _ => "[정보]",
            };
            string kind = v.Kind switch
            {
                ViolationKind.CrossLink => "혼선(망 간 연결)",
                ViolationKind.NameConflict => "관리 이상(PC 이름 중복)",
                ViolationKind.Hotspot => "PC 핫스팟(기능 사용)",
                _ => "비인가 장비 연결",
            };
            sb.AppendLine($"{n}. {sev} {v.Title}  · 유형: {kind}");
            sb.AppendLine($"   원칙: {v.Principle}");
            sb.AppendLine($"   상황: {v.Detail}");
            foreach (var h in v.Hosts)
            {
                string mac = string.IsNullOrEmpty(h.Mac) ? "MAC 미확인" : h.Mac;
                string vendor = string.IsNullOrEmpty(h.Vendor) ? "" : $" · {h.Vendor}";
                sb.AppendLine($"     - IP {h.Ip} · {mac}{vendor} · 신뢰도 {h.Confidence}%");
                foreach (var ev in h.Evidence)
                    sb.AppendLine($"         · {ev}");
            }
            sb.AppendLine($"   조치: {v.Action}");
            sb.AppendLine();
            n++;
        }
        return sb.ToString();
    }
}
