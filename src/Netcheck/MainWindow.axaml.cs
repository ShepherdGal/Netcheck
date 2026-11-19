using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media.Transformation;
using Netcheck.Pages;

namespace Netcheck;

public sealed partial class MainWindow : Window
{
    private readonly Dictionary<string, Control> pages = new();
    private string current = "";

    // The design size. The window never resizes freely; Settings → App size scales everything evenly instead.
    internal const double BaseWidth = 1120, BaseHeight = 920;
    // 100 % is the smallest window (user, 2026-11-17): no 90 %, and nothing smaller even on a small screen.
    internal static readonly double[] Scales = [1.0, 1.1, 1.25, 1.5];
    // Caption buttons: two 36 px buttons, 4 px apart, 12 px from the edge (NcChrome); the gear sits 4 px before them.
    private const double TitleBar = 56, CaptionButtons = 36 + 4 + 36 + 12;

    public MainWindow()
    {
        InitializeComponent();
        foreach (var tab in Tabs.Children.OfType<RadioButton>())
            tab.IsCheckedChanged += OnTabChecked;
        SettingsButton.Click += (_, _) => ShowSettings();
        Netcheck.Controls.SelectionSlider.Attach(TabIndicator, Tabs);
        Navigate("check");
        Opened += (_, _) =>
        {
            ApplyScale(UiPreferences.Current.AppScale, save: false);
            _ = Updater.CheckIfDueAsync();
            _ = PrewarmAsync();
        };
        Updater.Changed += ShowUpdateDot;
        ConfirmOk.Click += (_, _) => CloseConfirm(true);
        ConfirmCancel.Click += (_, _) => CloseConfirm(false);
        KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Escape && ConfirmLayer.IsVisible)
            {
                CloseConfirm(false);
                e.Handled = true;
            }
        };
    }

    private TaskCompletionSource<bool>? confirm;

    /// <summary>Shows the one confirm dialog; Cancel has focus. True only when the user clicks <paramref name="ok"/>.</summary>
    internal Task<bool> ConfirmAsync(string title, string text, string ok)
    {
        confirm?.TrySetResult(false);
        confirm = new TaskCompletionSource<bool>();
        ConfirmTitle.Text = title;
        ConfirmText.Text = text;
        ConfirmOk.Content = ok;
        foreach (var behind in new Control[] { PageHost, NavFrame, SettingsButton })
            behind.IsEnabled = false;
        ConfirmLayer.IsVisible = true;
        Motion.EnterPage(ConfirmLayer);
        ConfirmCancel.Focus();
        return confirm.Task;
    }

    private void CloseConfirm(bool result)
    {
        ConfirmLayer.IsVisible = false;
        foreach (var behind in new Control[] { PageHost, NavFrame, SettingsButton })
            behind.IsEnabled = true;
        var pending = confirm;
        confirm = null;
        pending?.TrySetResult(result);
    }

    internal double AppScale { get; private set; } = 1;

    /// <summary>Scales that fit this screen's working area (taskbar excluded).</summary>
    internal bool Fits(double scale)
    {
        var screen = Screens.ScreenFromWindow(this) ?? Screens.Primary;
        if (screen is null)
            return scale <= 1;
        var area = screen.WorkingArea.Size.ToSize(screen.Scaling);
        return BaseWidth * scale <= area.Width && BaseHeight * scale <= area.Height;
    }

    /// <summary>
    /// Sets the app size. 0 = automatic: 100 % if it fits, otherwise the largest size that does.
    /// The window is resized to match and kept on screen; the glow is redrawn at the new real size.
    /// </summary>
    internal void ApplyScale(double requested, bool save = true)
    {
        // An older saved 90 % counts as 100 %; a size that doesn't fit this screen falls back to 100 %, never below.
        var scale = requested >= 1 && Fits(requested) ? requested : 1.0;
        AppScale = scale;
        Scaler.LayoutTransform = new Avalonia.Media.ScaleTransform(scale, scale);
        Width = BaseWidth * scale;
        Height = BaseHeight * scale;
        ExtendClientAreaTitleBarHeightHint = TitleBar * scale;
        // The gear sits just left of the (unscaled) caption buttons.
        SettingsButton.Margin = new Thickness(0, 0, (CaptionButtons + 4) / scale, 0);
        KeepOnScreen();
        if (save)
            UiPreferences.Change(p => p with { AppScale = requested });
    }

    private void KeepOnScreen()
    {
        var screen = Screens.ScreenFromWindow(this) ?? Screens.Primary;
        if (screen is null)
            return;
        var area = screen.WorkingArea;
        var w = (int)(Width * screen.Scaling);
        var h = (int)(Height * screen.Scaling);
        var x = Math.Clamp(Position.X, area.X, Math.Max(area.X, area.Right - w));
        var y = Math.Clamp(Position.Y, area.Y, Math.Max(area.Y, area.Bottom - h));
        Position = new PixelPoint(x, y);
    }

    /// <summary>Lets pages switch tabs (e.g. "Make it faster" opens DNS).</summary>
    internal void Navigate(string key)
    {
        var tab = Tabs.Children.OfType<RadioButton>().FirstOrDefault(t => (string?)t.Tag == key);
        if (tab is not null && tab.IsChecked != true)
        {
            tab.IsChecked = true; // raises OnTabChecked → Show
            return;
        }
        Show(key);
    }

    /// <summary>History → Open: shows a saved check on the Check tab.</summary>
    internal void OpenSavedCheck(HistoryItem item)
    {
        Navigate("check");
        if (pages.TryGetValue("check", out var page) && page is CheckPage check)
            check.ShowSaved(item);
    }

    /// <summary>History's empty state: go to Check and start a check.</summary>
    internal void StartCheck()
    {
        Navigate("check");
        if (pages.TryGetValue("check", out var page) && page is CheckPage check)
            _ = check.StartAsync();
    }

    /// <summary>True once the Check tab has a finished result to explain.</summary>
    internal bool HasCheckResult => pages.TryGetValue("check", out var page) && page is CheckPage { HasResult: true };

    /// <summary>Settings → "How the last check was measured": back to Check, showing its details view.</summary>
    internal void ShowCheckDetails()
    {
        if (pages.TryGetValue("check", out var page) && page is CheckPage check)
        {
            Navigate("check");
            check.OpenDetails();
        }
    }

    private void OnTabChecked(object? sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { IsChecked: true, Tag: string key })
            Show(key);
    }

    private string? seenUpdate;

    /// <summary>The gear's green dot: a verified newer release that hasn't been seen in Settings yet.</summary>
    private void ShowUpdateDot() =>
        UpdateDot.IsVisible = Updater.HasOffer && Updater.Offer?.Version.ToString() != seenUpdate && current != "settings";

    private void ShowSettings()
    {
        seenUpdate = Updater.Offer?.Version.ToString();
        UpdateDot.IsVisible = false;
        foreach (var tab in Tabs.Children.OfType<RadioButton>())
            tab.IsChecked = false;
        Show("settings");
    }

    /// <summary>
    /// Shortly after start, scan Boost's settings and build the other tabs in the background, so opening any tab is
    /// instant (user, 2026-11-16: Boost made you wait a moment). Read-only; nothing is measured or changed.
    /// </summary>
    private async Task PrewarmAsync()
    {
        await Task.Delay(TimeSpan.FromSeconds(1));
        try { await BoostAdvisor.ScanAsync(); }
        catch (Exception) { /* the tab scans again when opened */ }
        foreach (var key in new[] { "boost", "dns", "history" })
        {
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                if (!pages.ContainsKey(key))
                    pages[key] = Create(key);
            }, Avalonia.Threading.DispatcherPriority.Background);
        }
    }

    private static Control Create(string key) => key switch
    {
        "check" => new CheckPage(),
        "dns" => new DnsPage(),
        "boost" => new BoostPage(),
        "history" => new HistoryPage(),
        _ => new SettingsPage(),
    };

    private void Show(string key)
    {
        if (key == current)
            return;
        current = key;
        if (!pages.TryGetValue(key, out var page))
        {
            page = Create(key);
            pages[key] = page;
        }
        PageHost.Content = page;
        Motion.EnterPage(page);
        SettingsButton.Classes.Set("active", key == "settings");
    }
}
