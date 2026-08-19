using System.Text;

namespace ScanPhoneNetwork;

/// <summary>스캔 결과를 엑셀 호환 CSV(UTF-8 BOM)로 저장. 교육청 보고·대장용.</summary>
public static class CsvExporter
{
    public static void Save(ScanReport report, string path)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# 업무망 점검 결과");
        sb.AppendLine($"# 대상,{report.TargetRange}");
        sb.AppendLine($"# 시작,{report.StartedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"# 종료,{report.FinishedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"# 발견호스트,{report.Hosts.Count},의심장비,{report.Suspicious.Count()}");
        sb.AppendLine();

        // 정책 위반 상세(혼선/비인가 장비)
        var violations = PolicyAnalyzer.Analyze(report);
        sb.AppendLine($"# 정책위반,{violations.Count}건");
        if (violations.Count > 0)
        {
            sb.AppendLine("심각도,유형,제목,IP,MAC,제조사,원칙,조치");
            foreach (var v in violations)
            {
                string sev = v.Severity switch
                { Severity.Critical => "심각", Severity.Warning => "주의", _ => "정보" };
                string kind = v.Kind switch
                {
                    ViolationKind.CrossLink => "혼선",
                    ViolationKind.NameConflict => "이름중복",
                    _ => "비인가장비",
                };
                foreach (var h in v.Hosts)
                {
                    sb.Append(Csv(sev)).Append(',').Append(Csv(kind)).Append(',')
                      .Append(Csv(v.Title)).Append(',')
                      .Append(Csv(h.Ip.ToString())).Append(',').Append(Csv(h.Mac ?? "")).Append(',')
                      .Append(Csv(h.Vendor ?? "")).Append(',')
                      .Append(Csv(v.Principle)).Append(',').Append(Csv(v.Action));
                    sb.AppendLine();
                }
            }
            sb.AppendLine();
        }

        sb.AppendLine("IP,PC이름,MAC,종류,신뢰도(%),제조사,열린포트,근거");

        foreach (var h in report.Hosts)
        {
            sb.Append(Csv(h.Ip.ToString())).Append(',');
            sb.Append(Csv(h.Hostname ?? "")).Append(',');
            sb.Append(Csv(h.Mac ?? "")).Append(',');
            sb.Append(Csv(CategoryKo(h.Category))).Append(',');
            sb.Append(h.Confidence).Append(',');
            sb.Append(Csv(VendorModel(h))).Append(',');
            sb.Append(Csv(string.Join(" ", h.OpenPorts))).Append(',');
            sb.Append(Csv(string.Join(" / ", h.Evidence)));
            sb.AppendLine();
        }

        // 엑셀 한글 깨짐 방지: UTF-8 BOM
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
    }

    public static string CategoryKo(DeviceCategory c) => c switch
    {
        DeviceCategory.Router => "공유기(의심)",
        DeviceCategory.WirelessAp => "무선AP(의심)",
        DeviceCategory.VoipPhone => "인터넷전화기",
        DeviceCategory.Printer => "프린터",
        DeviceCategory.Pc => "PC",
        DeviceCategory.Infrastructure => "인프라",
        _ => "미상",
    };

    /// <summary>제조사 + 모델명을 합친 표시 문자열(프린터 모델 노출).</summary>
    public static string VendorModel(DiscoveredHost h)
    {
        var parts = new[] { h.Vendor, h.Model }
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct();
        return string.Join(" · ", parts);
    }

    public static string NetworkKo(SchoolNetwork n) => n switch
    {
        SchoolNetwork.TeacherWork => "교사 업무망",
        SchoolNetwork.StudentWired => "학생 유선망",
        SchoolNetwork.StudentWifi => "학생 무선망",
        SchoolNetwork.Phone => "전화망",
        _ => "(미지정)",
    };

    private static string Csv(string s)
    {
        if (s.Contains(',') || s.Contains('"') || s.Contains('\n'))
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }
}
