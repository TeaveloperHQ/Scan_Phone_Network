using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ScanPhoneNetwork;

/// <summary>
/// IP → PC 이름 해석. 업무망은 고정 IP라 DNS PTR이 없는 경우가 많으므로
/// NetBIOS 이름 조회(UDP 137)를 우선 쓰고, 안 되면 역방향 DNS를 시도한다.
/// </summary>
public static class HostnameResolver
{
    /// <summary>NetBIOS 이름은 해당 PC 의 ANSI 코드페이지로 인코딩된다.
    /// 한글 컴퓨터 이름이 ? 로 깨지지 않도록 CP949 로 디코딩한다.</summary>
    private static readonly Encoding NameEncoding = ResolveNameEncoding();

    private static Encoding ResolveNameEncoding()
    {
        try
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            return Encoding.GetEncoding(949);   // CP949 = 한글 확장 EUC-KR
        }
        catch { return Encoding.ASCII; }        // 코드페이지 미지원 환경 대비
    }

    public static async Task<string?> ResolveAsync(IPAddress ip, int timeoutMs = 700)
    {
        var nb = await NetbiosNameAsync(ip, timeoutMs);
        if (!string.IsNullOrEmpty(nb)) return nb;

        try
        {
            var entry = await Dns.GetHostEntryAsync(ip).WaitAsync(TimeSpan.FromMilliseconds(timeoutMs));
            if (!string.IsNullOrEmpty(entry.HostName))
                return entry.HostName.Split('.')[0];   // 짧은 이름만
        }
        catch { /* PTR 없음 */ }

        return null;
    }

    /// <summary>NetBIOS 노드 상태 질의(NBSTAT)로 Windows 컴퓨터명을 얻는다.</summary>
    private static async Task<string?> NetbiosNameAsync(IPAddress ip, int timeoutMs)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return null;
        try
        {
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            byte[] req = BuildNbstatRequest();
            await udp.SendAsync(req, req.Length, new IPEndPoint(ip, 137));

            using var cts = new CancellationTokenSource(timeoutMs);
            var res = await udp.ReceiveAsync(cts.Token);
            return ParseNbstatResponse(res.Buffer);
        }
        catch { return null; }
    }

    private static byte[] BuildNbstatRequest()
    {
        var p = new byte[50];
        p[0] = 0x9A; p[1] = 0x2C;        // transaction id (임의)
        p[5] = 0x01;                     // questions = 1
        int i = 12;
        p[i++] = 0x20;                   // 이름 길이 32
        // 와일드카드 이름 "*" + 15 null 의 2차 인코딩: '*'(0x2A)→"CK", null→"AA"
        p[i++] = (byte)'C'; p[i++] = (byte)'K';
        for (int k = 0; k < 15; k++) { p[i++] = (byte)'A'; p[i++] = (byte)'A'; }
        p[i++] = 0x00;                   // 이름 종료
        p[i++] = 0x00; p[i++] = 0x21;    // 질의 타입 NBSTAT
        p[i++] = 0x00; p[i++] = 0x01;    // 클래스 IN
        return p;
    }

    private static string? ParseNbstatResponse(byte[] buf)
    {
        // 헤더(12) + 응답이름(1+32+1=34) + 타입(2)+클래스(2)+TTL(4)+RDLEN(2) = 56
        int off = 12 + 34 + 2 + 2 + 4 + 2;
        if (buf.Length <= off) return null;
        int count = buf[off++];
        for (int n = 0; n < count; n++)
        {
            if (off + 18 > buf.Length) break;
            // 이름은 공백(0x20)으로 15바이트까지 패딩된다. 패딩을 먼저 떼고 디코딩해야
            // 한글 이름의 끝 바이트가 잘려 깨지지 않는다.
            int nlen = 15;
            while (nlen > 0 && (buf[off + nlen - 1] == 0x20 || buf[off + nlen - 1] == 0x00)) nlen--;
            string name = NameEncoding.GetString(buf, off, nlen).Trim();
            byte suffix = buf[off + 15];
            int flags = (buf[off + 16] << 8) | buf[off + 17];
            bool isGroup = (flags & 0x8000) != 0;
            off += 18;
            // 접미사 0x00 + 그룹 아님 = 워크스테이션(컴퓨터) 이름
            if (suffix == 0x00 && !isGroup && name.Length > 0)
                return name.Trim();
        }
        return null;
    }
}
