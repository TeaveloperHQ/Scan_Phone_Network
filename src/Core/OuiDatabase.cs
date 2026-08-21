namespace ScanPhoneNetwork;

/// <summary>
/// MAC 앞 3바이트(OUI)로 제조사·장비종류를 추정.
/// 내장 목록은 국내 학교망에서 자주 보이는 대표 벤더 위주.
/// 식별률을 높이려면 IEEE 공식 목록(oui.csv)을 exe 옆에 두면 자동 로드된다.
///   다운로드: https://standards-oui.ieee.org/oui/oui.csv
///   (주의: IEEE 서버는 스크립트 User-Agent 를 418 로 막는다. 브라우저 UA 를 써야 받아진다.)
/// </summary>
public static class OuiDatabase
{
    public sealed record Entry(string Vendor, DeviceCategory Category);

    // 키: OUI 6자리 16진수(구분자 없음, 대문자)
    //
    // 2026-08-21 개정: IEEE 공식 oui.csv 전수 대조 + 실제 학교 업무망 실측 반영.
    // 개정 전 39건 중 10건이 사실과 달랐다. 삭제·정정 내역은 파일 하단 주석 참조.
    private static readonly Dictionary<string, Entry> _builtin = Normalize(new()
    {
        // --- 공유기/AP (소비자용) → 업무망에 있으면 무단 의심 ---

        // EFM Networks = ipTIME 제조사. IEEE 등록 8건 전부 수록.
        // 개정 전에는 3건뿐이어서 실측 현장에서 발견된 58:86:94 를 놓쳤다.
        ["00:26:66"] = new("EFM Networks (ipTIME)", DeviceCategory.Router),
        ["88:36:6C"] = new("EFM Networks (ipTIME)", DeviceCategory.Router),
        ["64:E5:99"] = new("EFM Networks (ipTIME)", DeviceCategory.Router),
        ["00:08:9F"] = new("EFM Networks (ipTIME)", DeviceCategory.Router),
        ["58:86:94"] = new("EFM Networks (ipTIME)", DeviceCategory.Router),   // 실측 발견
        ["90:9F:33"] = new("EFM Networks (ipTIME)", DeviceCategory.Router),
        ["70:5D:CC"] = new("EFM Networks (ipTIME)", DeviceCategory.Router),
        ["B0:38:6C"] = new("EFM Networks (ipTIME)", DeviceCategory.Router),

        ["C4:6E:1F"] = new("TP-Link", DeviceCategory.Router),
        ["AC:84:C6"] = new("TP-Link", DeviceCategory.Router),
        ["50:C7:BF"] = new("TP-Link", DeviceCategory.Router),
        ["14:CC:20"] = new("TP-Link", DeviceCategory.Router),
        ["90:9A:4A"] = new("TP-Link", DeviceCategory.Router),
        ["B0:95:75"] = new("TP-Link", DeviceCategory.Router),                 // 개정 전 Netgear 로 오기

        ["00:1F:33"] = new("Netgear", DeviceCategory.Router),
        ["B0:B9:8A"] = new("Netgear", DeviceCategory.Router),                 // 실측 발견

        ["C8:3A:35"] = new("Tenda", DeviceCategory.Router),
        ["B4:0F:3B"] = new("Tenda", DeviceCategory.Router),
        ["8C:05:28"] = new("Tenda", DeviceCategory.Router),

        ["04:5E:A4"] = new("Netis", DeviceCategory.Router),
        ["64:EE:B7"] = new("Netis", DeviceCategory.Router),
        ["88:BD:09"] = new("Netis", DeviceCategory.Router),

        ["28:6C:07"] = new("Xiaomi", DeviceCategory.Router),
        ["50:64:2B"] = new("Xiaomi", DeviceCategory.Router),                  // 개정 전 ASUS 로 오기

        // 통신사 공유기·AP 의 대표 ODM. 실측에서 전화망 대역의 장비로 발견됨.
        ["94:FB:B2"] = new("Shenzhen Gongjin (공유기 ODM)", DeviceCategory.Router),
        ["AC:6E:1A"] = new("Shenzhen Gongjin (공유기 ODM)", DeviceCategory.Router),
        ["84:C9:C6"] = new("Shenzhen Gongjin (공유기 ODM)", DeviceCategory.Router),

        // --- 전화망 라우터 / VoIP 게이트웨이 ---
        // DAVOLINK(다볼링크) = 국내 VoIP 게이트웨이 제조사.
        // "전화업자가 업무망 스위치에 그냥 꽂아둔 장비"의 대표 주자다.
        // 실측에서 2대 발견 — 한 대는 전화망 대역, 한 대는 사설로 잘못 쓰인 공인 대역에 있었다.
        ["00:08:52"] = new("DAVOLINK (전화망 라우터)", DeviceCategory.Router),
        ["60:29:D5"] = new("DAVOLINK (전화망 라우터)", DeviceCategory.Router),

        // --- 정상 인프라 (오탐 방지) ---
        // 학교 스위치·방화벽을 무단장비로 신고하면 앱을 아무도 안 믿게 된다.
        ["00:05:66"] = new("SECUI (방화벽)", DeviceCategory.Infrastructure),
        ["00:06:C4"] = new("PIOLINK (L4/L7 스위치)", DeviceCategory.Infrastructure),
        ["70:30:5D"] = new("Ubiquoss (스위치)", DeviceCategory.Infrastructure),
        ["BC:76:F9"] = new("Ubiquoss (스위치)", DeviceCategory.Infrastructure),
        ["00:07:70"] = new("Ubiquoss (스위치)", DeviceCategory.Infrastructure),
        ["B8:91:C9"] = new("Handreamnet (스위치)", DeviceCategory.Infrastructure),
        ["00:1A:F4"] = new("Handreamnet (스위치)", DeviceCategory.Infrastructure),
        ["FC:75:E6"] = new("Handreamnet (스위치)", DeviceCategory.Infrastructure),

        // --- 프린터/복합기 ---
        ["00:1B:A9"] = new("Brother", DeviceCategory.Printer),
        ["00:80:77"] = new("Brother", DeviceCategory.Printer),
        ["00:00:48"] = new("Seiko Epson", DeviceCategory.Printer),
        ["00:26:AB"] = new("Seiko Epson", DeviceCategory.Printer),
        ["00:00:85"] = new("Canon", DeviceCategory.Printer),
        ["00:1E:8F"] = new("Canon", DeviceCategory.Printer),
        ["00:00:74"] = new("Ricoh", DeviceCategory.Printer),
        ["00:21:5A"] = new("HP", DeviceCategory.Printer),
        ["00:1B:78"] = new("HP", DeviceCategory.Printer),
        ["3C:D9:2B"] = new("HP", DeviceCategory.Printer),
        ["00:C0:EE"] = new("Kyocera", DeviceCategory.Printer),
        ["00:17:C8"] = new("Kyocera Display", DeviceCategory.Printer),        // 실측 발견
        ["00:20:6B"] = new("Konica Minolta", DeviceCategory.Printer),         // 개정 전 Kyocera 로 오기
        ["00:50:AA"] = new("Konica Minolta", DeviceCategory.Printer),         // 실측(복합기 7대)
        ["08:00:37"] = new("FUJIFILM Business Innovation", DeviceCategory.Printer),

        // --- VoIP 전화기 ---
        ["00:15:65"] = new("Yealink", DeviceCategory.VoipPhone),
        ["80:5E:C0"] = new("Yealink", DeviceCategory.VoipPhone),
        ["00:0B:82"] = new("Grandstream", DeviceCategory.VoipPhone),
    });

    // ------------------------------------------------------------------
    // 2026-08-21 개정에서 삭제한 항목 — IEEE 공식 등록과 대조해 사실과 다름이 확인됨.
    // 되살리려면 반드시 IEEE oui.csv 로 먼저 확인할 것.
    //
    //   00:1A:A0  "Cisco (IP Phone)"  → 실제 Dell Inc.
    //                                   Dell PC 를 전부 IP전화기로 오분류하던 항목.
    //   00:26:E1  "Moimstone"         → 실제 Stanford University, OpenFlow Group
    //                                   (Moimstone 은 IEEE 에 그 이름의 등록 자체가 없다)
    //   00:09:45  "Samsung (VoIP)"    → 실제 Palmmicro Communications
    //   00:1E:75  "LG (VoIP)"         → 실제 LG전자(휴대폰 사업부). 안드로이드 폰을 전화기로 오분류.
    //   00:00:39  "Konica Minolta"    → 실제 Toshiba Corporation
    //   00:00:F0  "Samsung Printer"   → 삼성전자 범용 OUI
    //   00:15:99  "Samsung Printer"   → 삼성전자 범용 OUI
    //        실측 교사망 77대 중 20대 이상이 삼성 계열 OUI 의 데스크톱이었다.
    //        삼성 OUI 를 프린터로 단정하면 대량 오탐이 난다.
    //   50:6F:9A  "TP-Link"           → 실제 Wi-Fi Alliance (인증용 OUI)
    //   FC:34:97  "Netis"             → 실제 ASUSTeK Computer
    //   AC:9E:17  "ASUS"              → ASUS 는 IEEE 등록 OUI 가 93개이고 메인보드·노트북과
    //        공유기가 섞여 있다. 실측 교사망의 ASUSTeK 6대는 전부 데스크톱이었으므로
    //        OUI 만으로 공유기 판정은 오탐이 크다. 공유기 여부는 SSDP/DHCP/배너로 판정한다.
    // ------------------------------------------------------------------

    // 외부 oui.csv 로 확장되는 부분(런타임 로드).
    private static Dictionary<string, Entry> _external = new();

    public static Entry? Lookup(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return null;
        var clean = mac.Replace(":", "").Replace("-", "").ToUpperInvariant();
        if (clean.Length < 6) return null;
        var oui = clean[..6];
        return _builtin.GetValueOrDefault(oui) ?? _external.GetValueOrDefault(oui);
    }

    /// <summary>
    /// MAC 의 로컬 관리 비트(첫 옥텟 bit1)가 켜져 있으면 랜덤화/사설 MAC 이다.
    /// 스마트폰·노트북이 Wi-Fi 에서 쓰는 방식이라, 유선 업무망에서 보이면
    /// (a) 개인 기기를 랜선에 꽂았거나 (b) AP 가 무선 단말을 유선망으로 브리지 중이다.
    /// OUI 조회로는 제조사가 안 잡히므로(IEEE 미등록) 별도 신호로 다뤄야 한다.
    /// 실측에서 1건 발견 — mDNS 로 _googlecast 를 광고하는 캐스트 기기였다.
    /// </summary>
    public static bool IsLocallyAdministered(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return false;
        var clean = mac.Replace(":", "").Replace("-", "").Trim();
        if (clean.Length < 2) return false;
        return byte.TryParse(clean[..2], System.Globalization.NumberStyles.HexNumber,
                             null, out var first)
               && (first & 0x02) != 0;
    }

    /// <summary>
    /// IEEE oui.csv 를 읽어 제조사 식별률을 높인다.
    /// CSV 형식: Registry,Assignment,Organization Name,Organization Address
    /// 종류(Category)는 알 수 없으므로 이름 키워드로 추정하고, 못 맞히면 제조사명만 표시한다.
    /// </summary>
    public static int LoadExternalCsv(string path)
    {
        if (!File.Exists(path)) return 0;
        var map = new Dictionary<string, Entry>();
        foreach (var line in File.ReadLines(path).Skip(1))
        {
            // 간단 CSV 파싱: 두 번째 필드 = OUI(예 AABBCC), 세 번째 = 회사명
            var cols = SplitCsv(line);
            if (cols.Count < 3) continue;
            var oui = cols[1].Replace("-", "").Replace(":", "").Trim().ToUpperInvariant();
            if (oui.Length != 6) continue;
            var vendor = cols[2].Trim();
            map[oui] = new Entry(vendor, GuessCategory(vendor));
        }
        _external = map;
        return map.Count;
    }

    /// <summary>
    /// IEEE OUI 목록을 확보해 로드한다. 없으면 받아 오고, 있으면 그대로 쓴다.
    ///
    /// <para>
    /// 내장 목록은 학교망에서 자주 보이는 벤더 위주라 그 밖의 장비는 "제조사 미상"이 된다.
    /// 실측에서 남의 대역 장비 대부분이 미상으로 나와 보고서의 쓸모가 크게 떨어졌다.
    /// 교사가 파일을 직접 내려받아 exe 옆에 두게 하는 건 현실적이지 않으므로 앱이 챙긴다.
    /// </para>
    ///
    /// <para>
    /// 주의: IEEE 서버는 스크립트로 보이는 User-Agent 를 <b>418</b> 로 막는다.
    /// 브라우저 UA 를 보내야 받아진다. 폐쇄망이면 실패해도 그냥 내장 목록으로 간다.
    /// </para>
    /// </summary>
    /// <returns>로드된 항목 수. 0 이면 내장 목록만 쓰는 상태.</returns>
    public static async Task<int> EnsureLoadedAsync(
        string? explicitPath = null, CancellationToken ct = default)
    {
        // 1) 사용자가 지정한 경로
        if (!string.IsNullOrWhiteSpace(explicitPath) && File.Exists(explicitPath))
            return LoadExternalCsv(explicitPath);

        // 2) exe 옆
        string beside = Path.Combine(AppContext.BaseDirectory, "oui.csv");
        if (File.Exists(beside)) return LoadExternalCsv(beside);

        // 3) 앱 데이터 폴더에 받아 둔 것 (1년이 지나면 다시 받는다)
        string cacheDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ScanPhoneNetwork");
        string cached = Path.Combine(cacheDir, "oui.csv");
        if (File.Exists(cached)
            && (DateTime.Now - File.GetLastWriteTime(cached)).TotalDays < 365)
            return LoadExternalCsv(cached);

        // 4) 내려받기
        try
        {
            Directory.CreateDirectory(cacheDir);
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(90) };
            http.DefaultRequestHeaders.Add("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                + "(KHTML, like Gecko) Chrome/126.0 Safari/537.36");
            var bytes = await http.GetByteArrayAsync(
                "https://standards-oui.ieee.org/oui/oui.csv", ct);

            // 받다 만 파일을 캐시로 남기지 않는다(3MB 를 훨씬 밑돌면 실패로 본다)
            if (bytes.Length < 1_000_000) return File.Exists(cached) ? LoadExternalCsv(cached) : 0;

            await File.WriteAllBytesAsync(cached, bytes, ct);
            return LoadExternalCsv(cached);
        }
        catch
        {
            // 폐쇄망·차단 — 예전에 받아 둔 게 있으면 낡았어도 없는 것보단 낫다
            return File.Exists(cached) ? LoadExternalCsv(cached) : 0;
        }
    }

    // 회사명에 키워드가 있으면 종류를 추정(내장 목록에 없을 때 보조).
    // 주의: IEEE 회사명은 대소문자 표기가 뒤죽박죽이라 반드시 소문자로 비교한다.
    private static DeviceCategory GuessCategory(string vendor)
    {
        var v = vendor.ToLowerInvariant();

        if (v.Contains("yealink") || v.Contains("grandstream") || v.Contains("polycom")
            || v.Contains("snom") || v.Contains("moimstone") || v.Contains("audiocodes"))
            return DeviceCategory.VoipPhone;

        if (v.Contains("brother") || v.Contains("epson") || v.Contains("canon")
            || v.Contains("ricoh") || v.Contains("kyocera") || v.Contains("xerox")
            || v.Contains("konica") || v.Contains("lexmark") || v.Contains("fujifilm business"))
            return DeviceCategory.Printer;

        // 전화망 라우터를 포함한 공유기류
        if (v.Contains("tp-link") || v.Contains("tenda") || v.Contains("netis")
            || v.Contains("d-link") || v.Contains("iptime") || v.Contains("efm")
            || v.Contains("netgear") || v.Contains("xiaomi") || v.Contains("davolink")
            || v.Contains("gongjin") || v.Contains("mercusys") || v.Contains("totolink"))
            return DeviceCategory.Router;

        // 국내 학교·교육청 백본에서 쓰이는 정상 인프라 벤더
        if (v.Contains("piolink") || v.Contains("secui") || v.Contains("ubiquoss")
            || v.Contains("handreamnet") || v.Contains("dasan"))
            return DeviceCategory.Infrastructure;

        return DeviceCategory.Unknown;
    }

    private static Dictionary<string, Entry> Normalize(Dictionary<string, Entry> src) =>
        src.ToDictionary(
            kv => kv.Key.Replace(" ", "").Replace(":", "").Replace("-", "").ToUpperInvariant(),
            kv => kv.Value);

    private static List<string> SplitCsv(string line)
    {
        var result = new List<string>();
        var cur = new System.Text.StringBuilder();
        bool inQuotes = false;
        foreach (var c in line)
        {
            if (c == '"') inQuotes = !inQuotes;
            else if (c == ',' && !inQuotes) { result.Add(cur.ToString()); cur.Clear(); }
            else cur.Append(c);
        }
        result.Add(cur.ToString());
        return result;
    }
}
