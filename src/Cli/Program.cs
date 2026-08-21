using ScanPhoneNetwork;

Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine("=== 업무망 무단 장비 점검 (CLI) ===\n");

string? csvPath = GetOpt("--csv");
string? ouiPath = GetOpt("--oui");

// 옵션 값으로 소비된 인덱스를 제외하고 남는 위치 인자 = 대상 대역(CIDR)
var consumed = new HashSet<int>();
MarkOpt("--csv"); MarkOpt("--oui"); MarkOpt("--ledger"); MarkOpt("--prefix"); MarkOpt("--listen"); MarkOpt("--snmp");
string? cidr = args.Where((a, i) => !a.StartsWith("--") && !consumed.Contains(i)).FirstOrDefault();
int autoPrefix = int.TryParse(GetOpt("--prefix"), out int pfx) ? pfx : Scanner.DefaultAutoPrefix;

// OUI 목록은 Scanner 가 알아서 챙긴다(없으면 IEEE 에서 받아 캐시).
// --oui 로 파일을 직접 줄 수도 있다.

// --selftest : 망을 건드리지 않고 판정·보고 로직만 확인한다.
// 실제 무단 장비가 없는 곳에서도 "이런 게 잡히면 이렇게 보고된다"를 검증할 수 있다.
if (args.Contains("--selftest"))
{
    return SelfTest.Run();
}

var progress = new Progress<ScanProgress>(p =>
    Console.WriteLine($"  [{p.Phase}] {p.Done}/{p.Total}"));

try
{
    int listenSec = int.TryParse(GetOpt("--listen"), out int ls) ? ls : Scanner.DefaultListenSeconds;
    var report = await new Scanner().RunAsync(
        cidr, progress, default, SchoolNetwork.Unknown, autoPrefix, listenSec,
        GetOpt("--snmp"), ouiPath);

    // 망 분리 브리핑 — 가장 먼저 보여준다. 이게 이 앱의 결론이다.
    if (report.Segregation is not null)
    {
        Console.WriteLine();
        Console.WriteLine(SegregationAnalyzer.FormatBriefing(report.Segregation));
    }

    Console.WriteLine(report.OuiEntriesLoaded > 0
        ? $"[제조사 DB] IEEE 목록 {report.OuiEntriesLoaded:N0}건 사용"
        : "[제조사 DB] 내장 목록만 사용 — 모르는 제조사는 '제조사 미상'으로 나옵니다");

    if (report.Timings.Count > 0)
    {
        Console.WriteLine($"[소요] 전체 {report.TotalElapsed.TotalSeconds:F1}초  ·  "
            + string.Join("  ", report.Timings.Select(t => $"{t.Key} {t.Value.TotalSeconds:F1}s")));
    }

    Console.WriteLine($"\n대상: {report.TargetRange}");
    Console.WriteLine($"발견 호스트: {report.Hosts.Count}대 / 의심 장비: {report.Suspicious.Count()}대\n");

    Console.WriteLine($"{"IP",-16}{"PC이름",-18}{"MAC",-20}{"종류",-12}{"신뢰도",-7}제조사");
    Console.WriteLine(new string('-', 100));
    foreach (var h in report.Hosts)
    {
        Console.WriteLine($"{h.Ip,-16}{h.Hostname ?? "-",-18}{h.Mac ?? "-",-20}{CsvExporter.CategoryKo(h.Category),-12}{h.Confidence + "%",-7}{CsvExporter.VendorModel(h)}");
    }

    // 4개 망 분리 원칙 위반 상세 보고
    var violations = PolicyAnalyzer.Analyze(report);
    Console.WriteLine();
    Console.WriteLine(PolicyAnalyzer.FormatReport(report, violations));

    if (csvPath is not null)
    {
        CsvExporter.Save(report, csvPath);
        Console.WriteLine($"CSV 저장: {csvPath}");
    }

    string? ledgerPath = GetOpt("--ledger");
    if (ledgerPath is not null)
    {
        LedgerExporter.Save(report, ledgerPath, append: true);
        Console.WriteLine($"IP 관리대장 저장(누적): {ledgerPath}");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"오류: {ex.Message}");
    return 1;
}
return 0;

string? GetOpt(string name)
{
    int i = Array.IndexOf(args, name);
    return (i >= 0 && i + 1 < args.Length) ? args[i + 1] : null;
}

void MarkOpt(string name)
{
    int i = Array.IndexOf(args, name);
    if (i >= 0) { consumed.Add(i); if (i + 1 < args.Length) consumed.Add(i + 1); }
}
