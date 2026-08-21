using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ScanPhoneNetwork;

/// <summary>수동 청취로 관측한 신호 1건.</summary>
/// <param name="Protocol">mDNS · DHCP-DISCOVER · DHCP-OFFER · SSDP</param>
/// <param name="SourceIp">보낸 쪽 IP. 0.0.0.0 이면 아직 주소를 못 받은 장비다.</param>
/// <param name="Mac">알아낼 수 있으면 MAC(DHCP 페이로드의 chaddr 등). 없으면 null.</param>
/// <param name="Detail">mDNS 이름, SSDP SERVER 헤더 같은 부가 정보.</param>
public sealed record PassiveObservation(
    string Protocol,
    IPAddress SourceIp,
    string? Mac,
    string? Detail);

/// <summary>
/// 스캔하지 않고 "듣기만" 해서 장비를 찾는다.
///
/// 핑 스윕이 못 찾는 두 부류를 잡는 것이 목적이다.
///   1. IP 가 아예 없는 장비 — DHCP DISCOVER 만 계속 뿌리는 무단 공유기.
///      BOOTP 페이로드의 chaddr 에 MAC 이 들어 있어 OUI 판정이 가능하다.
///   2. 다른 IP 대역을 쓰는 장비 — 같은 브로드캐스트 도메인에 올라와 있으면
///      mDNS·SSDP 가 그대로 들린다. 이게 망 분리 위반의 직접 증거다.
///
/// 전부 평범한 UDP 소켓이라 <b>관리자 권한이 필요 없다.</b>
/// (ARP 까지 보려면 pktmon 등 별도 권한이 필요하지만, 그 없이도 위 두 부류는 잡힌다.)
/// </summary>
public static class PassiveListener
{
    private static readonly IPAddress MdnsGroup = IPAddress.Parse("224.0.0.251");
    private static readonly IPAddress SsdpGroup = IPAddress.Parse("239.255.255.250");

    /// <summary>지정한 시간 동안 듣고 관측 목록을 돌려준다. 실패한 포트는 조용히 건너뛴다.</summary>
    public static async Task<List<PassiveObservation>> ListenAsync(
        TimeSpan duration,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        var results = new List<PassiveObservation>();
        var gate = new object();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(duration);

        var tasks = new List<Task>
        {
            Listen(5353, MdnsGroup, ParseMdns, results, gate, cts.Token),
            Listen(67,   null,      ParseDhcpClient, results, gate, cts.Token),
            Listen(68,   null,      ParseDhcpServer, results, gate, cts.Token),
            Listen(1900, SsdpGroup, ParseSsdp, results, gate, cts.Token),
        };

        // 진행률 표시(1초 단위)
        int total = Math.Max(1, (int)duration.TotalSeconds);
        for (int s = 0; s < total && !ct.IsCancellationRequested; s++)
        {
            progress?.Report(new ScanProgress("수동 청취(듣기만)", s, total));
            try { await Task.Delay(1000, ct); } catch (OperationCanceledException) { break; }
        }
        progress?.Report(new ScanProgress("수동 청취(듣기만)", total, total));

        try { await Task.WhenAll(tasks); } catch (OperationCanceledException) { }

        lock (gate) return results.ToList();
    }

    private static async Task Listen(
        int port,
        IPAddress? multicastGroup,
        Func<byte[], IPEndPoint, PassiveObservation?> parse,
        List<PassiveObservation> sink,
        object gate,
        CancellationToken ct)
    {
        UdpClient? udp = null;
        try
        {
            udp = new UdpClient();
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.Client.Bind(new IPEndPoint(IPAddress.Any, port));
            udp.EnableBroadcast = true;
            if (multicastGroup is not null)
            {
                try { udp.JoinMulticastGroup(multicastGroup); }
                catch (SocketException) { /* 그룹 가입 실패해도 브로드캐스트는 들린다 */ }
            }
        }
        catch (SocketException)
        {
            // 포트를 이미 다른 프로그램이 독점 중 — 그 신호만 포기하고 나머지는 계속한다.
            udp?.Dispose();
            return;
        }

        using (udp)
        {
            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult r;
                try { r = await udp.ReceiveAsync(ct); }
                catch (OperationCanceledException) { break; }
                catch (SocketException) { continue; }

                PassiveObservation? obs;
                try { obs = parse(r.Buffer, r.RemoteEndPoint); }
                catch { continue; }   // 형식이 깨진 패킷은 버린다

                if (obs is null) continue;
                lock (gate) sink.Add(obs);
            }
        }
    }

    // ------------------------------------------------------------------
    // DHCP / BOOTP
    // ------------------------------------------------------------------

    private const int BootpMinLen = 240;
    private const int ChaddrOffset = 28;

    /// <summary>포트 67 로 오는 것 = 클라이언트 요청. IP 없는 장비를 여기서 잡는다.</summary>
    private static PassiveObservation? ParseDhcpClient(byte[] buf, IPEndPoint from)
    {
        if (buf.Length < BootpMinLen || buf[0] != 1) return null;   // op=1 BOOTREQUEST
        var mac = ReadChaddr(buf);
        var type = ReadDhcpMessageType(buf) switch
        {
            1 => "DISCOVER",
            3 => "REQUEST",
            _ => null,
        };
        if (type is null) return null;
        return new PassiveObservation($"DHCP-{type}", from.Address, mac,
            from.Address.Equals(IPAddress.Any) ? "IP 미할당 상태" : null);
    }

    /// <summary>포트 68 로 오는 것 = 서버 응답. 여기서 뭔가 오면 무단 DHCP 서버다.</summary>
    private static PassiveObservation? ParseDhcpServer(byte[] buf, IPEndPoint from)
    {
        if (buf.Length < BootpMinLen || buf[0] != 2) return null;   // op=2 BOOTREPLY
        int t = ReadDhcpMessageType(buf);
        if (t is not (2 or 5)) return null;                          // OFFER=2, ACK=5
        var offered = new IPAddress(buf.AsSpan(16, 4).ToArray());    // yiaddr
        return new PassiveObservation("DHCP-OFFER", from.Address, ReadChaddr(buf),
            $"제안 주소 {offered}");
    }

    private static string ReadChaddr(byte[] buf) =>
        string.Join("-", buf.Skip(ChaddrOffset).Take(6).Select(b => b.ToString("X2")));

    /// <summary>옵션 53(DHCP Message Type) 값. 없으면 -1.</summary>
    private static int ReadDhcpMessageType(byte[] buf)
    {
        // 240 바이트 고정부 뒤부터 옵션. 앞 4바이트는 매직쿠키(99,130,83,99).
        int i = BootpMinLen;
        while (i + 1 < buf.Length)
        {
            byte code = buf[i];
            if (code == 255) break;      // End
            if (code == 0) { i++; continue; }  // Pad
            byte len = buf[i + 1];
            if (code == 53 && len >= 1 && i + 2 < buf.Length) return buf[i + 2];
            i += 2 + len;
        }
        return -1;
    }

    // ------------------------------------------------------------------
    // mDNS / SSDP
    // ------------------------------------------------------------------

    /// <summary>mDNS 질의·응답에서 첫 이름을 뽑는다(장비 이름·서비스 종류).</summary>
    private static PassiveObservation? ParseMdns(byte[] buf, IPEndPoint from)
    {
        if (buf.Length < 13) return null;
        var name = ReadDnsName(buf, 12);
        return new PassiveObservation("mDNS", from.Address, null, name);
    }

    private static string? ReadDnsName(byte[] buf, int offset)
    {
        var sb = new StringBuilder();
        int i = offset;
        int guard = 0;
        while (i < buf.Length && guard++ < 64)
        {
            byte len = buf[i];
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) break;          // 압축 포인터는 따라가지 않는다
            i++;
            if (i + len > buf.Length) break;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.UTF8.GetString(buf, i, len));
            i += len;
        }
        var s = sb.ToString();
        return string.IsNullOrWhiteSpace(s) ? null : s;
    }

    /// <summary>SSDP 응답/광고의 SERVER 헤더 = 기종 문자열.</summary>
    private static PassiveObservation? ParseSsdp(byte[] buf, IPEndPoint from)
    {
        var text = Encoding.ASCII.GetString(buf);
        var server = text.Split('\n')
            .FirstOrDefault(l => l.StartsWith("SERVER:", StringComparison.OrdinalIgnoreCase))
            ?.Split(':', 2)[1].Trim();
        return new PassiveObservation("SSDP", from.Address, null, server);
    }
}
