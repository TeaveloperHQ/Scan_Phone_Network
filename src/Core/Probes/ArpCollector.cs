using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace ScanPhoneNetwork.Probes;

/// <summary>
/// 같은 브로드캐스트 도메인에 흐르는 ARP 를 받아 적어, 우리 대역이 아닌 장비를 찾아낸다.
///
/// <para>
/// 왜 필요한가. mDNS·SSDP 는 그 프로토콜을 쓰는 기기만 말하지만
/// <b>ARP 는 통신하는 모든 기기가 반드시 쓴다.</b> 실측 비교가 그대로 보여준다.
///   - UDP 청취 30초  → 남의 대역 1개
///   - ARP 캡처 120초 → 남의 대역 10개 이상
/// </para>
///
/// <para>
/// 왜 pktmon 인가. 윈도우 raw socket 은 IP 계층만 보여줘서 ARP 를 볼 수 없다.
/// Npcap 같은 드라이버를 깔면 되지만, 교사 PC 마다 드라이버를 설치하는 건
/// "더블클릭 한 번" 도구로는 무리다. pktmon 은 윈도우에 기본 탑재라 설치가 필요 없다.
/// 대신 <b>관리자 권한이 필요하다.</b> 권한이 없으면 조용히 건너뛰고
/// 기존 UDP 청취 결과만으로 보고한다(기능이 줄 뿐 앱은 그대로 돈다).
/// </para>
/// </summary>
public static class ArpCollector
{
    /// <summary>관리자 권한으로 실행 중인가(윈도우 전용).</summary>
    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(id);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    /// <summary>pktmon 이 쓸 수 있는 상태인가.</summary>
    public static bool IsAvailable() =>
        OperatingSystem.IsWindows()
        && IsElevated()
        && File.Exists(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "pktmon.exe"));

    /// <summary>
    /// 작업 폴더. %TEMP% 는 쓰지 않는다 — 임시 폴더에 파일을 만들고 실행하는 패턴은
    /// 백신 휴리스틱이 잡는 대표 사례라, 정식 작업 폴더를 쓰는 편이 사고가 없다.
    /// </summary>
    private static string WorkDir
    {
        get
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ScanPhoneNetwork", "capture");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>
    /// 지정한 시간 동안 ARP 를 받아 적어 (보낸 IP, 보낸 MAC) 목록을 돌려준다.
    /// 권한이 없거나 pktmon 이 실패하면 빈 목록을 준다(예외를 던지지 않는다).
    /// </summary>
    public static async Task<List<ArpSighting>> CollectAsync(
        TimeSpan duration,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        var empty = new List<ArpSighting>();
        if (!IsAvailable()) return empty;

        string etl = Path.Combine(WorkDir, "arp.etl");
        string txt = Path.Combine(WorkDir, "arp.txt");

        try
        {
            // 남아 있던 필터를 지우고 ARP(ethertype 0x0806 = 2054)만 받는다.
            await RunPktmon("filter remove", ct);
            if (await RunPktmon("filter add SPN_ARP -d 2054", ct) != 0) return empty;

            TryDelete(etl);
            TryDelete(txt);

            // pkt-size 128 이면 ARP 헤더는 전부 들어온다(프레임 자체가 60바이트).
            if (await RunPktmon(
                    $"start --capture --pkt-size 128 --file-name \"{etl}\" --file-size 32", ct) != 0)
            {
                await RunPktmon("filter remove", ct);
                return empty;
            }

            int total = Math.Max(1, (int)duration.TotalSeconds);
            for (int s = 0; s < total; s++)
            {
                if (ct.IsCancellationRequested) break;
                progress?.Report(new ScanProgress("ARP 수집(정밀 점검)", s, total));
                try { await Task.Delay(1000, ct); } catch (OperationCanceledException) { break; }
            }
            progress?.Report(new ScanProgress("ARP 수집(정밀 점검)", total, total));

            await RunPktmon("stop", CancellationToken.None);
            await RunPktmon($"etl2txt \"{etl}\" -o \"{txt}\"", CancellationToken.None);
            await RunPktmon("filter remove", CancellationToken.None);

            return Parse(txt);
        }
        catch
        {
            try { await RunPktmon("stop", CancellationToken.None); } catch { }
            try { await RunPktmon("filter remove", CancellationToken.None); } catch { }
            return empty;
        }
        finally
        {
            TryDelete(etl);   // 캡처 원본은 남기지 않는다(내부 통신 내용이 들어 있다)
        }
    }

    // "A8-CA-B9-0A-B4-41 > FF-..., ethertype ARP (0x0806), ...: Request who-has 10.1.1.1 tell 10.1.1.9"
    // "... : Reply 10.1.1.9 is-at a8-ca-b9-0a-b4-41"
    private static readonly Regex TellRe =
        new(@"^([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s*>.*\btell\s+(\d{1,3}(?:\.\d{1,3}){3})",
            RegexOptions.Compiled);
    private static readonly Regex ReplyRe =
        new(@"^([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s*>.*\bReply\s+(\d{1,3}(?:\.\d{1,3}){3})\s+is-at",
            RegexOptions.Compiled);

    /// <summary>
    /// pktmon 의 etl2txt 출력은 <b>UTF-16LE</b> 다. 바이트 그대로 읽으면 글자 사이에
    /// 0x00 이 끼어 어떤 정규식도 안 맞는다. 인코딩을 반드시 지정해야 한다.
    /// </summary>
    private static List<ArpSighting> Parse(string txtPath)
    {
        var seen = new Dictionary<string, ArpSighting>();
        if (!File.Exists(txtPath)) return new List<ArpSighting>();

        // pktmon 은 어댑터를 가리지 않고 다 잡는다. 이 PC 의 Wi-Fi 가 다른 망에
        // 잠깐 붙어 있었다면 그 ARP 까지 딸려 들어와, 남의 학교 대역이 업무망에
        // 올라와 있는 것처럼 보인다. 내 NIC 이 보낸 것은 빼야 오탐이 안 난다.
        var localMacs = LocalMacs();

        foreach (var raw in File.ReadLines(txtPath, Encoding.Unicode))
        {
            var line = raw.TrimStart();
            if (line.Length == 0) continue;

            var m = TellRe.Match(line);
            if (!m.Success) m = ReplyRe.Match(line);
            if (!m.Success) continue;

            string mac = m.Groups[1].Value.ToUpperInvariant();
            string ip = m.Groups[2].Value;

            // 0.0.0.0 은 주소를 정하기 전에 보내는 중복확인용 ARP 라 장비 주소가 아니다.
            if (ip == "0.0.0.0") continue;
            if (localMacs.Contains(mac)) continue;   // 이 PC 자신의 어댑터

            string key = ip + "|" + mac;
            if (!seen.ContainsKey(key))
                seen[key] = new ArpSighting(ip, mac, OuiDatabase.Lookup(mac)?.Vendor);
        }

        TryDelete(txtPath);
        return seen.Values.ToList();
    }

    /// <summary>이 PC 에 달린 모든 어댑터의 MAC (AA-BB-CC-DD-EE-FF 형식, 대문자).</summary>
    private static HashSet<string> LocalMacs()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                var bytes = nic.GetPhysicalAddress().GetAddressBytes();
                if (bytes.Length == 6)
                    set.Add(string.Join("-", bytes.Select(b => b.ToString("X2"))));
            }
        }
        catch { }
        return set;
    }

    private static async Task<int> RunPktmon(string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "pktmon.exe",
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi);
        if (p is null) return -1;
        await p.WaitForExitAsync(ct);
        return p.ExitCode;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
