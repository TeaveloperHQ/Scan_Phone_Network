using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ScanPhoneNetwork;

/// <summary>ICMP 핑 스윕으로 살아있는 호스트를 찾고, SendARP 로 MAC 을 해석한다.</summary>
public static class HostDiscovery
{
    /// <summary>대상 IP 목록을 병렬 핑. 응답한 호스트만 DiscoveredHost 로 반환.</summary>
    public static async Task<List<DiscoveredHost>> PingSweepAsync(
        IEnumerable<IPAddress> targets, int timeoutMs = 600, int maxParallel = 64)
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
        foreach (var h in hosts)
            h.Mac = SendArp(h.Ip);
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
