using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ScanPhoneNetwork;

/// <summary>ICMP 핑 스윕으로 살아있는 호스트를 찾고, SendARP 로 MAC 을 해석한다.</summary>
public static class HostDiscovery
{
    /// <summary>대상 IP 목록을 병렬 핑. 응답한 호스트만 DiscoveredHost 로 반환.</summary>
    /// <remarks>
    /// 병렬도 128 · 타임아웃 500ms 는 학교 유선망(같은 L2, 왕복 1ms 안팎) 기준이다.
    /// /23 이면 죽은 주소가 450개쯤이라 이 구간이 전체 시간을 좌우한다.
    /// 살아 있는 호스트는 1ms 안에 답하므로 500ms 면 충분하고, 병렬도를 올리는 편이
    /// 타임아웃을 더 줄이는 것보다 안전하다(응답 느린 프린터를 놓치지 않는다).
    /// </remarks>
    public static async Task<List<DiscoveredHost>> PingSweepAsync(
        IEnumerable<IPAddress> targets, int timeoutMs = 500, int maxParallel = 128)
    {
        var found = new System.Collections.Concurrent.ConcurrentBag<DiscoveredHost>();
        using var gate = new SemaphoreSlim(maxParallel);

        var tasks = targets.Select(async ip =>
        {
            await gate.WaitAsync();
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, timeoutMs);
                if (reply.Status == IPStatus.Success)
                {
                    found.Add(new DiscoveredHost
                    {
                        Ip = ip,
                        Ttl = reply.Options?.Ttl,
                    });
                }
            }
            catch { /* 응답 없음 → 무시 */ }
            finally { gate.Release(); }
        });

        await Task.WhenAll(tasks);
        // 마지막 옥텟만 보면 /23·/22 처럼 3옥텟이 여러 개인 대역에서 순서가 섞인다.
        return found.OrderBy(h => NetworkInfo.ToUInt(h.Ip)).ToList();
    }

    /// <summary>같은 L2 세그먼트 호스트의 MAC 을 SendARP 로 채운다 (Windows 전용).</summary>
    [SupportedOSPlatform("windows")]
    public static void ResolveMacs(IEnumerable<DiscoveredHost> hosts)
    {
        // SendARP 는 동기 호출이고, ARP 캐시에 없는 주소는 응답을 기다리며 블로킹된다.
        // 한 대씩 돌면 그 대기가 그대로 누적되므로 나눠서 동시에 부른다.
        Parallel.ForEach(hosts, new ParallelOptions { MaxDegreeOfParallelism = 16 },
            h => h.Mac = SendArp(h.Ip));
    }

    [SupportedOSPlatform("windows")]
    private static string? SendArp(IPAddress ip)
    {
        byte[] mac = new byte[6];
        int len = mac.Length;
#pragma warning disable CS0618
        uint dest = BitConverter.ToUInt32(ip.GetAddressBytes(), 0);
#pragma warning restore CS0618
        int rc = SendARP(dest, 0, mac, ref len);
        if (rc != 0 || len != 6) return null;
        return string.Join(":", mac.Take(len).Select(b => b.ToString("X2")));
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int macAddrLen);
}
