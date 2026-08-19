using System.Net;

namespace ScanPhoneNetwork;

/// <summary>수집한 모든 신호를 합쳐 장비 종류와 신뢰도(0~100)를 판정.</summary>
public static class Classifier
{
    public static void Classify(DiscoveredHost h, IReadOnlySet<IPAddress>? dhcpServers)
    {
        // 1) OUI 제조사
        var oui = OuiDatabase.Lookup(h.Mac);
        if (oui is not null)
        {
            h.Vendor = oui.Vendor;
            if (oui.Category != DeviceCategory.Unknown)
            {
                h.Category = oui.Category;
                h.Confidence += 50;
                h.Evidence.Add($"OUI 제조사 = {oui.Vendor}");
            }
            else
            {
                h.Evidence.Add($"제조사 = {oui.Vendor}");
            }
        }

        // 2) DHCP 서버 = 무단 라우터의 결정적 신호
        if (h.DhcpServer || (dhcpServers is not null && dhcpServers.Contains(h.Ip)))
        {
            h.DhcpServer = true;
            h.Category = DeviceCategory.Router;
            h.Confidence += 45;
            h.Evidence.Add("DHCP OFFER 응답 → 자체 DHCP 서버(공유기)");
        }

        // 3) SSDP InternetGatewayDevice
        if (h.SsdpGateway)
        {
            if (h.Category is DeviceCategory.Unknown) h.Category = DeviceCategory.Router;
            h.Confidence += 30;
            h.Evidence.Add("SSDP InternetGatewayDevice 광고");
        }

        // 4) SIP 포트 = 전화기
        if (h.OpenPorts.Contains(5060) || h.OpenPorts.Contains(5061))
        {
            if (h.Category is DeviceCategory.Unknown) h.Category = DeviceCategory.VoipPhone;
            h.Confidence += 25;
            h.Evidence.Add("SIP 포트(5060/5061) 열림");
        }

        // 4-1) 프린터 포트(9100/515/631)
        if (h.OpenPorts.Contains(9100) || h.OpenPorts.Contains(515) || h.OpenPorts.Contains(631))
        {
            if (h.Category is DeviceCategory.Unknown or DeviceCategory.Pc)
                h.Category = DeviceCategory.Printer;
            h.Evidence.Add("프린터 포트(9100/515/631) 열림");
        }

        // 5) HTTP/SIP 배너 키워드
        foreach (var b in h.Banners)
        {
            var lower = b.ToLowerInvariant();
            if (lower.Contains("iptime") || lower.Contains("tp-link") || lower.Contains("dd-wrt")
                || lower.Contains("openwrt") || lower.Contains("router") || lower.Contains("gateway"))
            {
                if (h.Category is DeviceCategory.Unknown) h.Category = DeviceCategory.Router;
                h.Confidence += 20;
                h.Evidence.Add($"배너에 공유기 키워드: {b}");
            }
            else if (lower.Contains("sip") || lower.Contains("yealink") || lower.Contains("grandstream")
                || lower.Contains("voip") || lower.Contains("phone"))
            {
                if (h.Category is DeviceCategory.Unknown) h.Category = DeviceCategory.VoipPhone;
                h.Confidence += 15;
                h.Evidence.Add($"배너에 전화기 키워드: {b}");
            }
        }

        // 6) TTL 추가 홉(NAT 뒤)
        //    출발 TTL 은 OS 마다 다르다(윈도우 128, 리눅스/프린터/스위치 64, 일부 장비 255).
        //    따라서 "다른 호스트보다 낮은 TTL" 이 아니라 "자기 출발값에서 몇 칸 깎였나"로 봐야 한다.
        if (h.Ttl is int t && HopCount(t) is int hops && hops > 0)
        {
            h.Confidence += 10;
            h.Evidence.Add($"TTL {t} → 라우터 {hops}홉 경유 → 중간 라우팅 장비(공유기) 의심");
        }

        // 7) 그 외 PC 이름이 잡힌 미상 장비 = 일반 PC (관리대장용)
        if (h.Category is DeviceCategory.Unknown && !string.IsNullOrEmpty(h.Hostname))
        {
            h.Category = DeviceCategory.Pc;
            h.Evidence.Add($"NetBIOS/DNS 이름 = {h.Hostname}");
        }

        if (h.Confidence > 100) h.Confidence = 100;
    }

    /// <summary>
    /// 관측 TTL 로 경유한 라우터 홉 수를 추정. 출발 TTL 후보(64/128/255) 중
    /// 관측값 이상인 가장 작은 값을 원래 값으로 보고 차이를 홉으로 센다.
    /// 예) 64→0홉(같은 망), 63→1홉, 127→1홉.
    /// </summary>
    private static int? HopCount(int ttl)
    {
        if (ttl is <= 0 or > 255) return null;
        int initial = ttl <= 64 ? 64 : ttl <= 128 ? 128 : 255;
        return initial - ttl;
    }
}
