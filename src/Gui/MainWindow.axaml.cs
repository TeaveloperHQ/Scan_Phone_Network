using System.Collections.ObjectModel;
using System.IO;
using Avalonia.Controls;
using Avalonia.Controls.Notifications;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

namespace ScanPhoneNetwork.Gui;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<HostRow> _rows = new();
    private readonly MonitorService _monitor;
    private CancellationTokenSource? _scanCts;
    private ScanReport? _lastReport;
    private string _reportText = "";
    private WindowNotificationManager? _notify;
    private TrayIcon? _tray;

    private static string AllowListPath =>
        Path.Combine(AppContext.BaseDirectory, "allowlist.json");

    // 디자이너용 기본 생성자
    public MainWindow() : this(false) { }

    public MainWindow(bool startInMonitorMode)
    {
        InitializeComponent();
        Grid.ItemsSource = _rows;

        // exe 옆 oui.csv 있으면 제조사 식별률 향상
        var ouiPath = Path.Combine(AppContext.BaseDirectory, "oui.csv");
        if (File.Exists(ouiPath)) OuiDatabase.LoadExternalCsv(ouiPath);

        _monitor = new MonitorService(AllowListPath);
        _monitor.ScanCompleted += r => Dispatcher.UIThread.Post(() => ShowReport(r));
        _monitor.NewSuspicious += h => Dispatcher.UIThread.Post(() => AlertNewDevice(h));
        _monitor.StatusChanged += s => Dispatcher.UIThread.Post(() => StatusText.Text = s);

        AutoStartCheck.IsChecked = AutoStart.IsEnabled();
        LoadAppIcon();
        SetupTray();

        Opened += (_, _) => _notify = new WindowNotificationManager(this) { MaxItems = 3 };
        if (startInMonitorMode) MonitorCheck.IsChecked = true;
    }

    // ---------- 1회 스캔 ----------

    private async void OnScanClick(object? sender, RoutedEventArgs e)
    {
        _rows.Clear();
        _scanCts = new CancellationTokenSource();
        SetScanning(true);

        var progress = new Progress<ScanProgress>(p =>
        {
            StatusText.Text = $"{p.Phase} ({p.Done}/{p.Total})";
            Progress.Value = p.Total > 0 ? p.Done * 100.0 / p.Total : 0;
        });

        try
        {
            string? cidr = string.IsNullOrWhiteSpace(TargetBox.Text) ? null : TargetBox.Text!.Trim();
            var report = await new Scanner().RunAsync(cidr, progress, _scanCts.Token, SelectedNetwork(), SelectedPrefix());
            ShowReport(report);
            StatusText.Text = $"완료 · {report.TargetRange}";
        }
        catch (OperationCanceledException) { StatusText.Text = "중지됨"; }
        catch (Exception ex) { StatusText.Text = "오류: " + ex.Message; }
        finally { SetScanning(false); }
    }

    private void OnStopClick(object? sender, RoutedEventArgs e) => _scanCts?.Cancel();

    private void ShowReport(ScanReport report)
    {
        _lastReport = report;
        _rows.Clear();
        foreach (var h in report.Hosts) _rows.Add(new HostRow(h));
        Watermark.IsVisible = _rows.Count == 0;   // 결과 차면 워터마크 숨김
        Progress.Value = 100;

        var violations = PolicyAnalyzer.Analyze(report);

        // 브리핑을 맨 위에 둔다. 교사가 제일 먼저 봐야 할 것은 장비 목록이 아니라
        // "무단 공유기가 있는가 / 다른 망과 분리돼 있는가" 두 줄이다.
        _reportText = report.Segregation is not null
            ? SegregationAnalyzer.FormatBriefing(report.Segregation) + "\n"
              + PolicyAnalyzer.FormatReport(report, violations)
            : PolicyAnalyzer.FormatReport(report, violations);

        if (violations.Count > 0)
        {
            int cross = violations.Count(v => v.Kind == ViolationKind.CrossLink);
            int dev = violations.Count(v => v.Kind == ViolationKind.UnauthorizedDevice);
            int dupName = violations.Count(v => v.Kind == ViolationKind.NameConflict);
            var parts = new List<string>();
            if (cross > 0) parts.Add($"혼선 {cross}");
            if (dev > 0) parts.Add($"비인가 장비 {dev}");
            if (dupName > 0) parts.Add($"이름중복 {dupName}");
            SummaryText.Text = $"⚠ 이상 {violations.Count}건 ({string.Join(" · ", parts)})";
        }
        else SummaryText.Text = "✅ 이상 없음";

        // 이상이 없어도 브리핑은 읽을 수 있어야 한다("분리돼 있다"는 것도 결과다).
        ReportButton.IsEnabled = violations.Count > 0 || report.Segregation is not null;
        CsvButton.IsEnabled = report.Hosts.Count > 0;
        LedgerButton.IsEnabled = report.Hosts.Count > 0;
    }

    private SchoolNetwork SelectedNetwork() => NetCombo.SelectedIndex switch
    {
        1 => SchoolNetwork.TeacherWork,
        2 => SchoolNetwork.StudentWired,
        3 => SchoolNetwork.StudentWifi,
        4 => SchoolNetwork.Phone,
        _ => SchoolNetwork.Unknown,
    };

    /// <summary>스캔 범위 콤보 → 프리픽스(/24·/23·/22). 기본 /23.</summary>
    private int SelectedPrefix() => ScopeCombo.SelectedIndex switch
    {
        0 => 24,
        2 => 22,
        _ => 23,
    };

    private void SetScanning(bool on)
    {
        ScanButton.IsEnabled = !on;
        StopButton.IsEnabled = on;
    }

    // ---------- 상세 보고 ----------

    private void OnReportClick(object? sender, RoutedEventArgs e)
    {
        var box = new TextBox
        {
            Text = _reportText,
            IsReadOnly = true,
            AcceptsReturn = true,
            TextWrapping = Avalonia.Media.TextWrapping.Wrap,
            FontFamily = new Avalonia.Media.FontFamily("Consolas, D2Coding, monospace"),
        };
        new Window
        {
            Title = "업무망 점검 상세 보고",
            Width = 720,
            Height = 560,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = new ScrollViewer { Content = box },
        }.ShowDialog(this);
    }

    // ---------- CSV 내보내기 ----------

    private async void OnExportClick(object? sender, RoutedEventArgs e)
    {
        if (_lastReport is null) return;
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            SuggestedFileName = $"업무망점검_{DateTime.Now:yyyyMMdd_HHmm}.csv",
            FileTypeChoices = new[] { new FilePickerFileType("CSV") { Patterns = new[] { "*.csv" } } },
        });
        if (file is not null)
        {
            CsvExporter.Save(_lastReport, file.Path.LocalPath);
            StatusText.Text = "저장 완료: " + file.Path.LocalPath;
        }
    }

    // ---------- IP 관리대장 ----------

    private async void OnLedgerClick(object? sender, RoutedEventArgs e)
    {
        if (_lastReport is null) return;
        _lastReport.Network = SelectedNetwork();  // 내보내기 시점의 망 선택 반영
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            SuggestedFileName = "IP관리대장.csv",
            FileTypeChoices = new[] { new FilePickerFileType("CSV") { Patterns = new[] { "*.csv" } } },
        });
        if (file is null) return;

        string path = file.Path.LocalPath;
        bool append = File.Exists(path);   // 기존 파일이면 이어붙여 4개 망 누적
        LedgerExporter.Save(_lastReport, path, append);
        StatusText.Text = (append ? "관리대장 누적 저장: " : "관리대장 저장: ") + path;
    }

    // ---------- 감시 모드 ----------

    private void OnMonitorToggle(object? sender, RoutedEventArgs e)
    {
        if (MonitorCheck.IsChecked == true) StartMonitor();
        else _monitor.Stop();
    }

    private void StartMonitor()
    {
        _monitor.TargetCidr = string.IsNullOrWhiteSpace(TargetBox.Text) ? null : TargetBox.Text!.Trim();
        _monitor.AutoPrefix = SelectedPrefix();
        _monitor.Network = SelectedNetwork();
        if (int.TryParse(IntervalBox.Text, out int min) && min > 0)
            _monitor.Interval = TimeSpan.FromMinutes(min);
        _monitor.Start();
        StatusText.Text = "감시 시작...";
    }

    private void AlertNewDevice(DiscoveredHost h)
    {
        bool crossLink = h.Category == DeviceCategory.VoipPhone
            || (h.DhcpServer && h.Category is not (DeviceCategory.Router or DeviceCategory.WirelessAp));
        string kind = crossLink ? "망 혼선 의심" : "비인가 장비 연결";
        string msg = $"유형: {kind}\nIP: {h.Ip} · {h.Mac ?? "-"}\n" +
                     $"{CsvExporter.CategoryKo(h.Category)} ({h.Confidence}%) {h.Vendor ?? ""}";

        // 트레이 감시 중이면 창을 띄워 알림
        Show();
        WindowState = WindowState.Normal;
        Activate();
        _notify?.Show(new Notification("⚠ 업무망 이상 감지", msg, NotificationType.Warning));
        if (OperatingSystem.IsWindows()) { try { Console.Beep(); } catch { } }
    }

    // ---------- 승인 ----------

    private void OnApproveClick(object? sender, RoutedEventArgs e)
    {
        if (Grid.SelectedItem is HostRow row)
        {
            if (row.Source.Mac is null) { StatusText.Text = "MAC 미확인 장비는 승인 불가"; return; }
            _monitor.Approve(row.Source);
            StatusText.Text = $"승인됨: {row.Mac}";
        }
    }

    // ---------- 자동 시작 ----------

    private void OnAutoStartToggle(object? sender, RoutedEventArgs e)
    {
        if (AutoStartCheck.IsChecked == true) AutoStart.Enable();
        else AutoStart.Disable();
    }

    // ---------- 숨김 고급 옵션 ----------

    private void OnWindowKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.A && e.KeyModifiers.HasFlag(KeyModifiers.Control)
            && e.KeyModifiers.HasFlag(KeyModifiers.Shift))
        {
            AdvancedPanel.IsVisible = !AdvancedPanel.IsVisible;
        }
    }

    // ---------- 아이콘 / 트레이 ----------

    private void LoadAppIcon()
    {
        try
        {
            var asm = typeof(MainWindow).Assembly.GetName().Name;
            var uri = new Uri($"avares://{asm}/Assets/icon-256.png");
            using (var s = AssetLoader.Open(uri)) Icon = new WindowIcon(s);
            // 빈 결과 영역의 은은한 엠블럼 워터마크
            using (var s2 = AssetLoader.Open(uri))
                Watermark.Source = new Avalonia.Media.Imaging.Bitmap(s2);
        }
        catch { /* 리소스 없으면 무시 */ }
    }

    private void SetupTray()
    {
        try
        {
            var open = new NativeMenuItem("창 열기");
            open.Click += (_, _) => { Show(); WindowState = WindowState.Normal; Activate(); };
            var exit = new NativeMenuItem("종료");
            exit.Click += (_, _) =>
            {
                if (Avalonia.Application.Current?.ApplicationLifetime
                    is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime d)
                    d.Shutdown();
            };

            _tray = new TrayIcon { Icon = Icon, ToolTipText = "업무망 점검기" };
            _tray.Menu = new NativeMenu { open, exit };
            _tray.Clicked += (_, _) => { Show(); WindowState = WindowState.Normal; Activate(); };

            var icons = new TrayIcons { _tray };
            if (Avalonia.Application.Current is { } app) TrayIcon.SetIcons(app, icons);
        }
        catch { /* 트레이 미지원 환경이면 무시 */ }
    }

    // 최소화 시 자동 숨김은 제거(일부 환경에서 창이 사라지는 문제 방지).
    // 트레이로 보내려면 트레이 메뉴/감시 모드를 사용.
}
