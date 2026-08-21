using System.Net;

namespace ScanPhoneNetwork.Probes;

/// <summary>
/// SNMP 로 <c>sysDescr</c> 를 읽어 모델·설명을 얻는다.
/// 프린터·복합기는 읽기 community 만 있으면 모델명을 대부분 노출한다.
///
/// <para>
/// 예전에는 이 클래스가 요청 패킷을 바이트 배열로 통째로 박아 두고 있었고,
/// community 문자열까지 그 안에 들어 있어 바꿀 수 없었다. 지금은 <see cref="Snmp"/> 가
/// 제대로 인코딩하므로 community 를 인자로 받는다.
/// </para>
/// </summary>
public static class SnmpProbe
{
    /// <summary>
    /// 읽기 전용 community 의 사실상 표준 기본값.
    /// 장비마다 다를 수 있으므로 값을 바꿀 수 있어야 한다.
    /// </summary>
    public const string DefaultCommunity = "public";

    public static async Task<string?> GetSysDescrAsync(
        IPAddress ip,
        string? community = null,
        int timeoutMs = 800,
        CancellationToken ct = default)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;

        var text = await Snmp.ProbeAsync(
            ip, string.IsNullOrWhiteSpace(community) ? DefaultCommunity : community, timeoutMs, ct);
        if (string.IsNullOrWhiteSpace(text)) return null;

        // sysDescr 은 여러 줄짜리 장문인 경우가 있다. 표에 넣을 수 있게 앞부분만 남긴다.
        int cut = text.IndexOfAny(new[] { ';', '\n', '\r' });
        if (cut > 0) text = text[..cut];
        text = text.Trim();
        return text.Length > 60 ? text[..60] : text;
    }
}
