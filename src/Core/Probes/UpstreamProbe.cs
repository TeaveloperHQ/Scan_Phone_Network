using System.Text.Json;

namespace ScanPhoneNetwork.Probes;

/// <summary>이 학교가 어느 상위망(교육청 회선) 밑에 붙어 있는지.</summary>
/// <param name="PublicIp">밖에서 보이는 공인 IP</param>
/// <param name="Org">회선 소유 기관. 교육청 회선이면 교육청 이름이 나온다.</param>
public sealed record UpstreamInfo(string PublicIp, string? Org, string? City, string? Region)
{
    /// <summary>브리핑 상단에 한 줄로 쓸 표기.</summary>
    public string Display =>
        string.IsNullOrWhiteSpace(Org) ? PublicIp : $"{Org}  ({PublicIp})";
}

/// <summary>
/// 공인 IP 와 그 IP 를 보유한 기관명을 조회한다.
/// 브리핑 상단에 "지금 이 PC 는 ○○교육청 회선 밑에 있다"를 보여주기 위한 것.
///
/// 주의: 유일하게 <b>바깥으로 나가는</b> 조회다. 보내는 것은 조회 요청뿐이고
/// 학교 내부 정보(MAC·내부 IP·장비 목록)는 전송하지 않는다.
/// 폐쇄망이거나 차단돼 있으면 null 을 돌려주고 나머지 점검은 그대로 진행한다.
/// </summary>
public static class UpstreamProbe
{
    private static readonly string[] Endpoints =
    {
        "https://ipinfo.io/json",
        "https://ipapi.co/json/",
    };

    public static async Task<UpstreamInfo?> QueryAsync(
        TimeSpan timeout,
        CancellationToken ct = default)
    {
        using var http = new HttpClient { Timeout = timeout };
        http.DefaultRequestHeaders.Add("User-Agent", "ScanPhoneNetwork/1.0");

        foreach (var url in Endpoints)
        {
            try
            {
                var json = await http.GetStringAsync(url, ct);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                string? ip = Str(root, "ip");
                if (string.IsNullOrWhiteSpace(ip)) continue;

                // ipinfo 는 "org", ipapi 는 "asn"+"org" 를 쓴다.
                string? org = Str(root, "org");
                if (string.IsNullOrWhiteSpace(org))
                {
                    string? asn = Str(root, "asn");
                    string? name = Str(root, "org_name") ?? Str(root, "organization");
                    org = string.Join(' ', new[] { asn, name }.Where(s => !string.IsNullOrWhiteSpace(s)));
                }

                return new UpstreamInfo(
                    ip!,
                    string.IsNullOrWhiteSpace(org) ? null : org,
                    Str(root, "city"),
                    Str(root, "region"));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return null;
            }
            catch
            {
                // 다음 엔드포인트로
            }
        }
        return null;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;
}
