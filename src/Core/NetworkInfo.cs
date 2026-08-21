using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ScanPhoneNetwork;

/// <summary>실행 PC 가 속한 IPv4 대역을 알아내고 스캔 대상 IP 목록을 만든다.</summary>
public static class NetworkInfo
{
    public sealed record LocalSubnet(
        IPAddress LocalIp,
        IPAddress Mask,
        IPAddress? Gateway,
        string InterfaceName);

    /// <summary>업/다운 상태인 첫 번째 실 이더넷/무선 인터페이스의 IPv4 정보를 반환.</summary>
    public static LocalSubnet? GetActiveSubnet()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                continue;

            var props = nic.GetIPProperties();
            foreach (var ua in props.UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                if (IPAddress.IsLoopback(ua.Address)) continue;

                var gw = props.GatewayAddresses
                    .Select(g => g.Address)
                    .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);

                return new LocalSubnet(ua.Address, ua.IPv4Mask, gw, nic.Name);
            }
        }
        return null;
    }

    /// <summary>
    /// "10.20.30.0/24" 같은 CIDR 문자열을 (네트워크주소, 마스크)로 해석.
    /// 학교 10.x 대역을 인자로 직접 지정할 때 사용.
    /// </summary>
    public static bool TryParseCidr(string cidr, out IPAddress network, out IPAddress mask)
    {
        network = IPAddress.None;
        mask = IPAddress.None;

        var parts = cidr.Split('/');
        if (parts.Length != 2) return false;
        if (!IPAddress.TryParse(parts[0], out var ip)) return false;
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        if (!int.TryParse(parts[1], out int prefix) || prefix is < 0 or > 32) return false;

        uint maskv = prefix == 0 ? 0u : 0xFFFFFFFF << (32 - prefix);
        mask = FromUInt(maskv);
        network = FromUInt(ToUInt(ip) & maskv);
        return true;
    }

    /// <summary>서브넷 내 호스트 IP 전체를 열거 (네트워크/브로드캐스트 주소 제외).</summary>
    public static IEnumerable<IPAddress> EnumerateHosts(IPAddress ip, IPAddress mask)
    {
        uint ipv = ToUInt(ip);
        uint maskv = ToUInt(mask);
        uint network = ipv & maskv;
        uint broadcast = network | ~maskv;

        for (uint a = network + 1; a < broadcast; a++)
            yield return FromUInt(a);
    }

    /// <summary>프리픽스(예 23) → 서브넷마스크.</summary>
    public static IPAddress PrefixToMask(int prefix)
    {
        uint m = prefix <= 0 ? 0u : prefix >= 32 ? 0xFFFFFFFF : 0xFFFFFFFF << (32 - prefix);
        return FromUInt(m);
    }

    /// <summary>서브넷마스크 → 프리픽스 비트 수.</summary>
    public static int MaskToPrefix(IPAddress mask) =>
        mask.GetAddressBytes().Sum(b => System.Numerics.BitOperations.PopCount((uint)b));

    /// <summary>ip 를 mask 로 깎은 네트워크 주소 문자열.</summary>
    public static string NetworkBase(IPAddress ip, IPAddress mask) =>
        FromUInt(ToUInt(ip) & ToUInt(mask)).ToString();

    /// <summary>
    /// 윈도우 '모바일 핫스팟'(인터넷 연결 공유, ICS)이 쓰는 고정 대역인가.
    ///
    /// 윈도우는 ICS 를 켜면 공유하는 쪽 인터페이스에 <b>항상 192.168.137.1</b> 을 붙이고
    /// 192.168.137.0/24 로 DHCP 를 뿌린다. 사용자가 바꿀 수 있는 값이 아니라서,
    /// 이 대역이 보이면 "윈도우 PC 가 핫스팟을 켰다"로 사실상 확정할 수 있다.
    ///
    /// 업무망에서 이게 보이는 경우는 둘 중 하나다.
    ///   - PC 가 무선으로 공유 중이고 그 흔적이 유선까지 새어 나온 경우
    ///   - 공유 방향을 잘못 잡아 <b>업무망 쪽으로 DHCP 를 뿌리고 있는</b> 경우(이쪽이 훨씬 위험)
    /// </summary>
    public static bool IsWindowsIcsRange(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        return b[0] == 192 && b[1] == 168 && b[2] == 137;
    }

    /// <summary>IPv4 를 정렬·비교용 32비트 값으로. (10.0.0.9 &lt; 10.0.1.1 이 성립)</summary>
    public static uint ToUInt(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static IPAddress FromUInt(uint v) =>
        new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });
}
