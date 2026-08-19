using Avalonia.Media;

namespace ScanPhoneNetwork.Gui;

/// <summary>DataGrid 한 행을 위한 표시용 래퍼.</summary>
public sealed class HostRow
{
    public HostRow(DiscoveredHost h)
    {
        Ip = h.Ip.ToString();
        Hostname = h.Hostname ?? "";
        Mac = h.Mac ?? "-";
        Category = CsvExporter.CategoryKo(h.Category);
        Confidence = h.Confidence;
        Vendor = CsvExporter.VendorModel(h);
        OpenPorts = string.Join(" ", h.OpenPorts);
        Evidence = string.Join("  |  ", h.Evidence);
        Source = h;
        IsSuspicious = h.Category is DeviceCategory.Router
                                  or DeviceCategory.WirelessAp
                                  or DeviceCategory.VoipPhone;
        HasDuplicateName = h.HasDuplicateName;
        BadgeTip = HasDuplicateName
            ? "같은 PC 이름을 쓰는 다른 장비:" + Environment.NewLine
              + string.Join(Environment.NewLine, h.NameConflicts.Select(c => "  · " + c))
              + Environment.NewLine + Environment.NewLine
              + "복제 이미지로 설치한 뒤 이름을 안 바꾼 경우가 대부분입니다." + Environment.NewLine
              + "대장 정리·장비 구분은 이름이 아니라 MAC 기준으로 하세요."
            : "";
    }

    public string Ip { get; }
    public string Hostname { get; }
    public string Mac { get; }
    public string Category { get; }
    public int Confidence { get; }
    public string Vendor { get; }
    public string OpenPorts { get; }
    public string Evidence { get; }
    public bool IsSuspicious { get; }
    public DiscoveredHost Source { get; }

    /// <summary>PC 이름이 다른 장비와 겹침 → 표에 경고 뱃지 표시.</summary>
    public bool HasDuplicateName { get; }

    /// <summary>뱃지에 마우스를 올렸을 때 보여줄 상세(겹치는 장비 목록).</summary>
    public string BadgeTip { get; }

    public bool HasBadge => HasDuplicateName;
    public string Badge => HasDuplicateName ? "⚠ 이름중복" : "";

    /// <summary>뱃지 색: 주의(호박색).</summary>
    public IBrush BadgeBackground => new SolidColorBrush(Color.FromRgb(0xD9, 0x77, 0x06));

    /// <summary>의심 장비는 빨간 계열, 이름 중복은 호박색 계열로 강조.</summary>
    public IBrush RowBackground => IsSuspicious
        ? new SolidColorBrush(Color.FromRgb(0xFF, 0xE0, 0xE0))
        : HasDuplicateName
            ? new SolidColorBrush(Color.FromRgb(0xFE, 0xF3, 0xC7))
            : Brushes.Transparent;
}
