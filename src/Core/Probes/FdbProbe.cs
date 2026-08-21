using System.Net;

namespace ScanPhoneNetwork.Probes;

/// <summary>어떤 MAC 이 어느 스위치 어느 포트에 물려 있는지.</summary>
/// <param name="Mac">찾던 MAC (AA-BB-CC-DD-EE-FF)</param>
/// <param name="SwitchIp">그 MAC 을 자기 포트에서 본 스위치</param>
/// <param name="Port">사람이 읽는 포트 이름. 못 구하면 브리지 포트 번호</param>
/// <param name="Vlan">VLAN 번호(Q-BRIDGE 로 찾았을 때만). 없으면 null</param>
public sealed record FdbHit(string Mac, string SwitchIp, string Port, int? Vlan);

/// <summary>
/// 스위치의 MAC 주소 테이블(FDB)을 읽어 "몇 번 포트에 꽂혀 있나"에 답한다.
///
/// <para>
/// 이 앱이 찾아내는 것들(무단 공유기, 전화망 라우터, 주소 없는 장비)은 전부
/// "어딘가에 있다"까지만 말해 준다. 실제로 뽑으려면 물리 포트를 알아야 하고,
/// <b>그 답을 가진 것은 스위치뿐이다.</b>
/// </para>
///
/// <para>
/// 두 가지 MIB 을 본다. 옛 브리지 MIB(dot1d)만 채우는 장비도 있고,
/// VLAN 을 쓰는 장비는 Q-BRIDGE(dot1q)만 채우는 경우가 많아 둘 다 봐야 한다.
/// </para>
///
/// <para>
/// <b>선행 조건: 스위치에 SNMP 가 켜져 있고 읽기 community 를 알아야 한다.</b>
/// 없으면 이 기능은 아무것도 못 한다. 학교가 아니라 교육청·유지보수 업체가
/// 스위치를 관리하면 community 를 못 받을 수도 있다.
/// </para>
/// </summary>
public static class FdbProbe
{
    // dot1dTpFdbPort — OID 뒤에 MAC 6바이트가 붙고, 값은 브리지 포트 번호
    private static readonly int[] Dot1dTpFdbPort = { 1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2 };
    // dot1qTpFdbPort — 뒤에 VLAN 1개 + MAC 6바이트
    private static readonly int[] Dot1qTpFdbPort = { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 };
    // dot1dBasePortIfIndex — 브리지 포트 번호 → ifIndex
    private static readonly int[] Dot1dBasePortIfIndex = { 1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2 };
    // ifName — ifIndex → 사람이 읽는 포트 이름 (예 "gi1/0/14")
    private static readonly int[] IfName = { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1 };

    /// <summary>
    /// 주어진 스위치들에서 찾는 MAC 들의 위치를 조회한다.
    /// SNMP 가 막혀 있으면 빈 결과를 준다(예외를 던지지 않는다).
    /// </summary>
    public static async Task<List<FdbHit>> LocateAsync(
        IReadOnlyList<IPAddress> switches,
        IReadOnlyCollection<string> wantedMacs,
        string community,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        var hits = new List<FdbHit>();
        if (switches.Count == 0 || wantedMacs.Count == 0) return hits;

        var want = new HashSet<string>(wantedMacs.Select(Normalize), StringComparer.OrdinalIgnoreCase);

        int done = 0;
        foreach (var sw in switches)
        {
            if (ct.IsCancellationRequested) break;
            progress?.Report(new ScanProgress("스위치 MAC 테이블 조회", done, switches.Count));
            done++;

            // 먼저 이 장비가 이 community 로 답하는지 확인한다.
            // 안 답하는 장비에 테이블 워크를 걸면 타임아웃만 쌓인다.
            if (await Snmp.ProbeAsync(sw, community, 1200, ct) is null) continue;

            var portNames = await PortNameMapAsync(sw, community, ct);

            // dot1d — 뒤 6개 마디가 MAC
            foreach (var vb in await Snmp.WalkAsync(sw, community, Dot1dTpFdbPort, ct: ct))
            {
                var mac = MacFromTail(vb.Oid, Dot1dTpFdbPort.Length, 0);
                if (mac is null || !want.Contains(mac)) continue;
                hits.Add(new FdbHit(mac, sw.ToString(), Label(portNames, (int)vb.AsLong()), null));
            }

            // dot1q — 뒤 7개 마디가 VLAN + MAC
            foreach (var vb in await Snmp.WalkAsync(sw, community, Dot1qTpFdbPort, ct: ct))
            {
                var mac = MacFromTail(vb.Oid, Dot1qTpFdbPort.Length, 1);
                if (mac is null || !want.Contains(mac)) continue;
                int vlan = vb.Oid[Dot1qTpFdbPort.Length];
                if (hits.Any(h => h.Mac == mac && h.SwitchIp == sw.ToString())) continue;
                hits.Add(new FdbHit(mac, sw.ToString(), Label(portNames, (int)vb.AsLong()), vlan));
            }
        }

        progress?.Report(new ScanProgress("스위치 MAC 테이블 조회", switches.Count, switches.Count));
        return hits;
    }

    /// <summary>브리지 포트 번호 → 사람이 읽는 이름. 두 단계를 타야 한다.</summary>
    private static async Task<Dictionary<int, string>> PortNameMapAsync(
        IPAddress sw, string community, CancellationToken ct)
    {
        var map = new Dictionary<int, string>();
        try
        {
            // 브리지 포트 → ifIndex
            var bridgeToIf = new Dictionary<int, int>();
            foreach (var vb in await Snmp.WalkAsync(sw, community, Dot1dBasePortIfIndex, ct: ct))
            {
                if (vb.Oid.Length <= Dot1dBasePortIfIndex.Length) continue;
                bridgeToIf[vb.Oid[Dot1dBasePortIfIndex.Length]] = (int)vb.AsLong();
            }

            // ifIndex → 이름
            var ifNames = new Dictionary<int, string>();
            foreach (var vb in await Snmp.WalkAsync(sw, community, IfName, ct: ct))
            {
                if (vb.Oid.Length <= IfName.Length) continue;
                ifNames[vb.Oid[IfName.Length]] = vb.AsString();
            }

            foreach (var (bridgePort, ifIndex) in bridgeToIf)
                if (ifNames.TryGetValue(ifIndex, out var name) && !string.IsNullOrWhiteSpace(name))
                    map[bridgePort] = name;
        }
        catch { /* 이름을 못 구하면 번호로 보고한다 */ }
        return map;
    }

    private static string Label(Dictionary<int, string> names, int bridgePort) =>
        names.TryGetValue(bridgePort, out var n) ? $"{n} (포트 {bridgePort})" : $"포트 {bridgePort}";

    /// <summary>OID 꼬리의 6개 마디를 MAC 으로 읽는다.</summary>
    private static string? MacFromTail(int[] oid, int prefixLen, int skip)
    {
        int start = prefixLen + skip;
        if (oid.Length < start + 6) return null;
        var parts = new string[6];
        for (int i = 0; i < 6; i++)
        {
            int v = oid[start + i];
            if (v is < 0 or > 255) return null;
            parts[i] = v.ToString("X2");
        }
        return string.Join("-", parts);
    }

    public static string Normalize(string mac) =>
        mac.Replace(":", "-").ToUpperInvariant().Trim();
}
