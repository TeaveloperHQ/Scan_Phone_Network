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

    /// <summary>수동 청취(듣기만)로 잡은 신호. 핑 스윕이 못 찾는 장비가 여기 들어온다.</summary>
    public List<PassiveObservation> Observations { get; init; } = new();

    /// <summary>ARP 로 관측한 (IP, MAC). 관리자 권한으로 실행했을 때만 채워진다.</summary>
    public List<ArpSighting> ArpSightings { get; init; } = new();

    /// <summary>망 분리 판정 결과. 청취를 건너뛰면 null.</summary>
    public SegregationReport? Segregation { get; set; }

    /// <summary>단계별 소요 시간. 느려졌을 때 어디가 범인인지 바로 보라고 남긴다.</summary>
    public Dictionary<string, TimeSpan> Timings { get; } = new();

    /// <summary>로드된 IEEE OUI 항목 수. 0 이면 내장 목록만 쓴 것이다.</summary>
    public int OuiEntriesLoaded { get; set; }

    /// <summary>스캔 전체 소요 시간.</summary>
    public TimeSpan TotalElapsed { get; set; }

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

    /// <summary>
    /// 망 분리 판정을 위한 수동 청취 기본 시간(초). 0 이면 청취를 건너뛴다.
    /// 실측상 30초면 mDNS·DHCP 가 충분히 잡힌다(타 대역 PC 1대, IP 없는 공유기 1대 확인).
    /// </summary>
    public const int DefaultListenSeconds = 30;

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
        int autoPrefix = DefaultAutoPrefix,
        int listenSeconds = DefaultListenSeconds,
        string? snmpCommunity = null,
        string? ouiCsvPath = null)
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

        var clock = System.Diagnostics.Stopwatch.StartNew();
        var lap = System.Diagnostics.Stopwatch.StartNew();
        void Mark(string phase)
        {
            report.Timings[phase] = lap.Elapsed;
            lap.Restart();
        }

        // 0) 수동 청취를 여기서 미리 띄운다.
        //    듣기는 CPU·대역폭을 거의 안 쓰고 그냥 기다리는 일이라, 스캔이 끝나기를
        //    기다렸다 시작하면 그 시간이 벽시계에 그대로 더해진다. 겹쳐 돌리면 공짜다.
        // OUI 목록도 미리 확보해 둔다. 없으면 장비 대부분이 "제조사 미상"으로 나와
        // 보고서를 읽어도 판단이 안 선다. 분류 직전에만 있으면 되므로 겹쳐서 받는다.
        var ouiTask = OuiDatabase.EnsureLoadedAsync(ouiCsvPath, ct);

        var localSub = NetworkInfo.GetActiveSubnet();
        Task<List<PassiveObservation>>? listenTask = null;
        Task<UpstreamInfo?>? upstreamTask = null;
        Task<List<ArpSighting>>? arpTask = null;
        if (listenSeconds > 0 && localSub is not null)
        {
            listenTask = PassiveListener.ListenAsync(TimeSpan.FromSeconds(listenSeconds), null, ct);
            upstreamTask = UpstreamProbe.QueryAsync(TimeSpan.FromSeconds(8), ct);

            // 관리자 권한이 있으면 ARP 까지 받아 적는다. 없으면 조용히 건너뛴다.
            // ARP 는 통신하는 모든 기기가 쓰므로 탐지 폭이 크게 는다.
            if (ArpCollector.IsAvailable())
                arpTask = ArpCollector.CollectAsync(TimeSpan.FromSeconds(listenSeconds), null, ct);
        }

        // 1~2) DHCP·SSDP·핑 스윕을 함께 시작한다.
        //      앞의 둘은 브로드캐스트를 한 번 뿌리고 응답을 기다리는 일이라 대부분 순수 대기다
        //      (실측 3.1초 + 2.5초). 순서대로 하면 그 대기가 그대로 더해지지만,
        //      셋은 서로 독립이라 동시에 돌리면 가장 오래 걸리는 하나로 수렴한다.
        progress?.Report(new ScanProgress("DHCP·SSDP·핑 스윕", 0, targets.Count));
        var dhcpTask = DhcpProbe.FindDhcpServersAsync();
        var ssdpTask = SsdpProbe.DiscoverAsync();
        var pingTask = HostDiscovery.PingSweepAsync(targets);

        var hosts = await pingTask;
        var dhcpServers = await dhcpTask;
        var ssdp = await ssdpTask;
        ct.ThrowIfCancellationRequested();
        Mark("DHCP·SSDP·핑 스윕(동시)");

        // SSDP/DHCP 로만 보인 호스트도 합류(핑에 응답 안 해도 잡기)
        MergeExtraHosts(hosts, ssdp.Keys);
        if (dhcpServers is not null) MergeExtraHosts(hosts, dhcpServers);

        // 3) MAC 해석 (Windows)
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            HostDiscovery.ResolveMacs(hosts);
        Mark("MAC 해석");

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

        Mark("포트/배너 프로브");

        // 5) PC 이름 해석 (NetBIOS/DNS) — 병렬
        progress?.Report(new ScanProgress("PC 이름 조회", 0, hosts.Count));
        // NetBIOS 질의는 응답 없는 호스트에서 700ms 를 그냥 기다린다.
        // 동시 처리 수를 올리는 만큼 그 대기가 겹쳐 사라진다.
        using (var gate = new SemaphoreSlim(64))
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

        Mark("PC 이름 조회");

        // 6) 분류 — 제조사 판정이 걸려 있으므로 OUI 목록을 먼저 기다린다
        try { report.OuiEntriesLoaded = await ouiTask; } catch { }
        foreach (var h in hosts)
            Classifier.Classify(h, dhcpServers);

        // 6-1) 결과 전체를 맞대봐야 보이는 이상(PC 이름 중복 등)
        HostAnomalies.MarkDuplicateNames(hosts);

        report.Hosts.AddRange(hosts
            .OrderByDescending(h => h.Confidence)
            .ThenBy(h => NetworkInfo.ToUInt(h.Ip)));

        Mark("분류");

        // 7) 망 분리 판정 — 스캔만으로는 알 수 없다.
        //    스캔은 "우리 대역에 누가 있나"를 볼 뿐이고, 분리 여부는
        //    "남의 대역이 같은 구간에서 들리는가"로 판정해야 한다.
        //    청취는 0단계에서 이미 시작해 뒀으므로, 여기서는 남은 시간만 기다린다.
        if (listenTask is not null && localSub is not null)
        {
            if (!listenTask.IsCompleted)
            {
                int remain = Math.Max(0, listenSeconds - (int)clock.Elapsed.TotalSeconds);
                progress?.Report(new ScanProgress("수동 청취 마무리", listenSeconds - remain, listenSeconds));
            }

            var observations = await listenTask;
            report.Observations.AddRange(observations);

            UpstreamInfo? upstream = null;
            if (upstreamTask is not null)
            {
                try { upstream = await upstreamTask; } catch { /* 폐쇄망이면 없어도 된다 */ }
            }

            List<ArpSighting>? arp = null;
            if (arpTask is not null)
            {
                try { arp = await arpTask; } catch { /* 권한·pktmon 문제면 없이 간다 */ }
            }
            if (arp is not null) report.ArpSightings.AddRange(arp);

            report.Segregation = SegregationAnalyzer.Analyze(
                localSub.LocalIp, localSub.Mask, localSub.Gateway,
                report.Hosts, observations, arpSightings: arp, upstream: upstream);
            report.Segregation.ArpCaptureUsed = arp is not null;
            Mark("수동 청취(스캔과 병행)");

            // 8) 찾아낸 문제 장비가 "몇 번 포트"에 있는지까지 좁힌다.
            //    여기까지 와야 실제로 뽑을 수 있다. 스위치만 그 답을 갖고 있다.
            if (!string.IsNullOrWhiteSpace(snmpCommunity))
            {
                var switches = report.Hosts
                    .Where(h => h.Category is DeviceCategory.Infrastructure && h.Mac is not null)
                    .Select(h => h.Ip)
                    .ToList();

                // 찾을 대상: 무단 공유기, 주소도 못 받은 장비, 남의 대역 장비
                var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var h in report.Segregation.Routers.Where(h => h.Mac is not null))
                    wanted.Add(FdbProbe.Normalize(h.Mac!));
                foreach (var u in report.Segregation.Unaddressed)
                    wanted.Add(FdbProbe.Normalize(u.Split(' ')[0]));
                foreach (var a in report.ArpSightings)
                    wanted.Add(FdbProbe.Normalize(a.Mac));

                if (switches.Count > 0 && wanted.Count > 0)
                {
                    progress?.Report(new ScanProgress("스위치 MAC 테이블 조회", 0, switches.Count));
                    var hits = await FdbProbe.LocateAsync(switches, wanted, snmpCommunity!, progress, ct);
                    report.Segregation.PortLocations.AddRange(hits);
                    Mark("스위치 MAC 테이블 조회");
                }
            }
        }

        report.TotalElapsed = clock.Elapsed;
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
