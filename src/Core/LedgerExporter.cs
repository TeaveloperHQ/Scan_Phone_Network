using System.Net;
using System.Text;

namespace ScanPhoneNetwork;

/// <summary>
/// IP 관리대장 CSV 출력. PC이름·장비종류·소속망 기준으로 정리한다.
/// append=true 면 기존 대장에 이어 붙여 4개 망을 한 파일에 누적할 수 있다.
/// </summary>
public static class LedgerExporter
{
    public static void Save(ScanReport report, string path, bool append)
    {
        bool fileExists = File.Exists(path);
        bool writeHeader = !(append && fileExists);

        int start = 0;
        if (append && fileExists)
            start = File.ReadLines(path).Count(l => l.Length > 0 && char.IsDigit(l[0]));

        var sb = new StringBuilder();
        if (writeHeader)
            sb.AppendLine("연번,소속망,장비종류,PC이름,IP,MAC,제조사,점검일시");

        string net = CsvExporter.NetworkKo(report.Network);
        string when = report.FinishedAt.ToString("yyyy-MM-dd HH:mm");

        int i = start;
        foreach (var h in report.Hosts.OrderBy(h => IpKey(h.Ip)))
        {
            i++;
            sb.Append(i).Append(',')
              .Append(Csv(net)).Append(',')
              .Append(Csv(CsvExporter.CategoryKo(h.Category))).Append(',')
              .Append(Csv(LedgerName(h))).Append(',')
              .Append(Csv(h.Ip.ToString())).Append(',')
              .Append(Csv(h.Mac ?? "")).Append(',')
              .Append(Csv(CsvExporter.VendorModel(h))).Append(',')
              .Append(Csv(when));
            sb.AppendLine();
        }

        if (append && fileExists)
            File.AppendAllText(path, sb.ToString(), new UTF8Encoding(false));
        else
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true)); // BOM (엑셀 한글)
    }

    /// <summary>
    /// 대장에 적을 PC 이름. 같은 이름을 다른 장비도 쓰고 있으면 뒤에 표시를 붙인다.
    /// (열을 늘리지 않아 기존 대장 파일에 계속 이어 붙일 수 있다)
    /// </summary>
    private static string LedgerName(DiscoveredHost h)
    {
        string name = h.Hostname ?? "";
        return h.HasDuplicateName ? name + " (이름중복)" : name;
    }

    private static uint IpKey(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static string Csv(string s)
    {
        if (s.Contains(',') || s.Contains('"') || s.Contains('\n'))
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }
}
