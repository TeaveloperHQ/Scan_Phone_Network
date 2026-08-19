using System.Net;
using System.Runtime.InteropServices;
using ScanPhoneNetwork.Probes;

namespace ScanPhoneNetwork;

/// <summary>스캔 진행 상황 알림.</summary>
public sealed record ScanProgress(string Phase, int Done, int Total);

/// <summary>한 번의 스캔 결과 묶음.</summary>
public sealed class ScanReport
{
    public DateTime StartedAt { get; init; } = DateTime.Now;
    public DateTime FinishedAt { get; set; }
    public string TargetRange { get; init; } = "";

    /// <summary>이 스캔이 어느 망인지(IP 관리대장 소속망). 사용자가 지정.</summary>
    public SchoolNetwork Network { get; set; } = SchoolNetwork.Unknown;

    public List<DiscoveredHost> Hosts { get; init; } = new();

    /// <summary>업무망에 있으면 안 되는(=의심) 장비만 추림.</summary>
    public IEnumerable<DiscoveredHost> Suspicious =>
        Hosts.Where(h => h.Category is DeviceCategory.Router
                                    or DeviceCategory.WirelessAp
                                    or DeviceCategory.VoipPhone);
}

/// <summary>전체 스캔 파이프라인을 묶는 오케스트레이터. UI 와 무관하게 재사용.</summary>
public sealed class Scanner
{
    /// <param name="cidr">"10.20.30.0/24" 형식. null 이면 실행 PC 대역 자동 탐지.</param>
    /// <summary>자동 탐지 시 기본 스캔 프리픽스. 학교가 /23(255.255.254.0)로 구성하므로 23 기본.</summary>
    public const int DefaultAutoPrefix = 23;

    /// <param name="autoPrefix">
    /// 자동 탐지 시 스캔 범위 프리픽스(기본 23=/23). 특별한 경우 22=/22 까지.
    /// PC 실제 마스크가 더 넓으면(작은 숫자) 그쪽을 따른다(과소 스캔 방지).
    /// cidr 을 직접 주면 무시된다.
    /// </param>
    public async Task<ScanReport> RunAsync(
        string? cidr,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default,
        SchoolNetwork schoolNetwork = SchoolNetwork.Unknown,
        int autoPrefix = DefaultAutoPrefix)
    {
        IPAddress network, mask;
        string label;

        if (!string.IsNullOrWhiteSpace(cidr))
        {
            if (!NetworkInfo.TryParseCidr(cidr, out network, out mask))
                throw new ArgumentException($"대역 형식 오류: '{cidr}' (예: 10.20.30.0/24)");
            label = cidr;
        }
        else
        {
            var sub = NetworkInfo.GetActiveSubnet()
                ?? throw new InvalidOperationException("활성 인터페이스를 찾지 못했습니다. 대역을 직접 지정하세요.");
            // 학교가 /23 으로 구성하고 빈 대역에 무단 라우터를 두는 경우가 있어,
            // PC 마스크(/24)보다 넓혀 점검한다. 단 PC 마스크가 더 넓으면 그쪽을 따름.
            int eff = Math.Min(autoPrefix, NetworkInfo.MaskToPrefix(sub.Mask));
            network = sub.LocalIp;
            mask = NetworkInfo.PrefixToMask(eff);
            label = $"{NetworkInfo.NetworkBase(sub.LocalIp, mask)}/{eff} (자동·{sub.InterfaceName})";
        }

        var report = new ScanReport { TargetRange = label, Network = schoolNetwork };
        var targets = NetworkInfo.EnumerateHosts(network, mask).ToList();

        // 어떤 마스크든 처리(/0~/32). 255.255.254.0(/23,510개)·/22(1022개)까지 정상.
        // 실수로 /18 이상 거대 대역을 넣은 경우만 차단.
        const int MaxHosts = 8192;
        if (targets.Count > MaxHosts)
            throw new InvalidOperationException(
                $"대상이 {targets.Count}개로 너무 큽니다(>{MaxHosts}). /24~/22 단위로 좁혀 지정하세요.");

        // 1) DHCP/SSDP 는 브로드캐스트라 호스트 목록과 별개로 1회씩
        progress?.Report(new ScanProgress("DHCP 서버 탐지", 0, 1));
        var dhcpServers = await DhcpProbe.FindDhcpServersAsync();
        ct.ThrowIfCancellationRequested();

        progress?.Report(new ScanProgress("SSDP(공유기) 탐지", 0, 1));
        var ssdp = await SsdpProbe.DiscoverAsync();
        ct.ThrowIfCancellationRequested();

        // 2) 핑 스윕
        progress?.Report(new ScanProgress("핑 스윕", 0, targets.Count));
        var hosts = await HostDiscovery.PingSweepAsync(targets);

        // SSDP/DHCP 로만 보인 호스트도 합류(핑에 응답 안 해도 잡기)
        MergeExtraHosts(hosts, ssdp.Keys);
        if (dhcpServers is not null) MergeExtraHosts(hosts, dhcpServers);

        // 3) MAC 해석 (Windows)
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            HostDiscovery.ResolveMacs(hosts);

        // 4) 호스트별 포트/배너 프로브 — 병렬(대역 넓어도 빠르게)
        int done = 0;
        using (var probeGate = new SemaphoreSlim(24))
        {
            await Task.WhenAll(hosts.Select(async h =>
            {
                await probeGate.WaitAsync(ct);
                try
                {
                    var pr = await PortProbe.ProbeAsync(h.Ip);
                    h.OpenPorts.AddRange(pr.OpenPorts);
                    h.Banners.AddRange(pr.Banners);
                    if (ssdp.TryGetValue(h.Ip, out var banner))
                    {
                        h.SsdpGateway = true;
                        if (!string.IsNullOrEmpty(banner)) h.Banners.Add("SSDP " + banner);
                    }
                    // 프린터 포트가 열렸으면 SNMP 로 모델명 수집
                    if (h.OpenPorts.Contains(9100) || h.OpenPorts.Contains(515) || h.OpenPorts.Contains(631))
                        h.Model = await SnmpProbe.GetSysDescrAsync(h.Ip);
                }
                finally
                {
                    probeGate.Release();
                    progress?.Report(new ScanProgress("포트/배너 프로브",
                        Interlocked.Increment(ref done), hosts.Count));
                }
            }));
        }

        // 5) PC 이름 해석 (NetBIOS/DNS) — 병렬
        progress?.Report(new ScanProgress("PC 이름 조회", 0, hosts.Count));
        using (var gate = new SemaphoreSlim(32))
        {
            int hdone = 0;
            await Task.WhenAll(hosts.Select(async h =>
            {
                await gate.WaitAsync(ct);
                try { h.Hostname = await HostnameResolver.ResolveAsync(h.Ip); }
                finally
                {
                    gate.Release();
                    progress?.Report(new ScanProgress("PC 이름 조회", Interlocked.Increment(ref hdone), hosts.Count));
                }
            }));
        }

        // 6) 분류
        foreach (var h in hosts)
            Classifier.Classify(h, dhcpServers);

        // 6-1) 결과 전체를 맞대봐야 보이는 이상(PC 이름 중복 등)
        HostAnomalies.MarkDuplicateNames(hosts);

        report.Hosts.AddRange(hosts
            .OrderByDescending(h => h.Confidence)
            .ThenBy(h => NetworkInfo.ToUInt(h.Ip)));
        report.FinishedAt = DateTime.Now;
        return report;
    }

    private static void MergeExtraHosts(List<DiscoveredHost> hosts, IEnumerable<IPAddress> extra)
    {
        var have = hosts.Select(h => h.Ip.ToString()).ToHashSet();
        foreach (var ip in extra)
            if (have.Add(ip.ToString()))
                hosts.Add(new DiscoveredHost { Ip = ip });
    }
}
