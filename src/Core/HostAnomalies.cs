namespace ScanPhoneNetwork;

/// <summary>
/// 호스트 한 대만 봐서는 알 수 없고, 결과 전체를 맞대봐야 보이는 이상.
/// (예: 같은 PC 이름을 여러 대가 쓰는 상태 — 이미지 복제 설치 후 이름을 안 바꾼 경우)
/// </summary>
public static class HostAnomalies
{
    /// <summary>
    /// 같은 PC 이름이 서로 다른 장비에서 나오면 관련된 모든 호스트에 표시한다.
    /// 장비 구분은 MAC 기준이고, MAC 을 못 얻은 경우에만 IP 로 대신한다
    /// (한 대가 IP 두 개로 잡힌 경우를 이름 중복으로 오해하지 않기 위함).
    /// </summary>
    public static void MarkDuplicateNames(IEnumerable<DiscoveredHost> hosts)
    {
        var named = hosts.Where(h => !string.IsNullOrWhiteSpace(h.Hostname));

        foreach (var g in named.GroupBy(h => h.Hostname!.Trim(), StringComparer.OrdinalIgnoreCase))
        {
            var devices = g.Select(DeviceKey).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (devices < 2) continue;

            foreach (var h in g)
            {
                string me = DeviceKey(h);
                foreach (var other in g)
                {
                    if (DeviceKey(other).Equals(me, StringComparison.OrdinalIgnoreCase)) continue;
                    h.NameConflicts.Add($"{other.Ip} · {other.Mac ?? "MAC 미확인"}");
                }
                h.Evidence.Add($"PC 이름 중복 — '{g.Key}' 을(를) {devices}대가 함께 사용");
            }
        }
    }

    private static string DeviceKey(DiscoveredHost h) =>
        string.IsNullOrEmpty(h.Mac) ? "ip:" + h.Ip : "mac:" + h.Mac;
}
