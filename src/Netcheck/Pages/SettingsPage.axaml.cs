using System.Globalization;
using Avalonia.Controls;
using Avalonia.Media;
using Netcheck.Core.Updates;
using Netcheck.Elevation;

namespace Netcheck.Pages;

public sealed partial class SettingsPage : UserControl
{
    internal const string SupportUrl = "https://ko-fi.com/trueshepherdmusic";

    private int savedChecks = -1;
    private string? installState;   // portable install: null, "busy" or a short outcome line

    private readonly Netcheck.Controls.SelectionSlider sizeSlider;

    public SettingsPage()
    {
        InitializeComponent();
        // The maintainer's donation page (user, 2026-11-17). A fixed address: nothing from the network or the user goes in.
        SupportLink.Click += (_, _) => Updater.Open(SupportUrl);
        sizeSlider = Netcheck.Controls.SelectionSlider.Attach(SizePill, Sizes);
        Netcheck.Controls.SelectionSlider.Attach(UnitPill, Units);
        AttachedToVisualTree += (_, _) =>
        {
            BuildSizes();
            var hasResult = Window?.HasCheckResult == true;
            MethodButton.IsEnabled = hasResult;
            MethodHint.Text = hasResult
                ? "Servers, data used and how each reading is worked out."
                : "Run a check first, then see how it was measured.";
            var bytes = SpeedUnits.Family(UiPreferences.Current.SpeedUnit) == SpeedFamily.Bytes;
            BitsUnit.IsChecked = !bytes;
            BytesUnit.IsChecked = bytes;
            AutoSwitch.IsChecked = UiPreferences.Current.AutoUpdateCheck;
            AutoSwitch.Classes.Set("motion", !Motion.Reduced);
            Updater.Changed += ShowUpdates;
            CheckHistory.Changed += CountChecksLater;
            ShowUpdates();
            _ = CountChecksAsync();
        };
        DetachedFromVisualTree += (_, _) =>
        {
            Updater.Changed -= ShowUpdates;
            CheckHistory.Changed -= CountChecksLater;
        };

        MethodButton.Click += (_, _) => Window?.ShowCheckDetails();
        BitsUnit.IsCheckedChanged += (_, _) => SetUnits();
        BytesUnit.IsCheckedChanged += (_, _) => SetUnits();
        FolderButton.Click += (_, _) =>
        {
            try { Directory.CreateDirectory(AppPaths.DataDirectory); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
            Updater.Open(AppPaths.DataDirectory);
        };
        ClearLink.Click += async (_, _) => await ClearHistoryAsync();
        CheckNowLink.Click += async (_, _) => await Updater.CheckAsync();
        AutoSwitch.IsCheckedChanged += (_, _) =>
        {
            var on = AutoSwitch.IsChecked == true;
            if (on != UiPreferences.Current.AutoUpdateCheck)
                UiPreferences.Change(p => p with { AutoUpdateCheck = on });
            ShowUpdates();
        };
        UpdateLink.Click += (_, _) =>
        {
            if (AppPaths.Edition == AppEdition.Installed)
                VersionButton.Focus();
            else
                Updater.OpenReleasePage();
        };
    }

    private MainWindow? Window => TopLevel.GetTopLevel(this) as MainWindow;

    private void SetUnits()
    {
        if (BitsUnit.IsChecked != true && BytesUnit.IsChecked != true)
            return;
        var unit = BytesUnit.IsChecked == true ? SpeedUnit.AutomaticBytes : SpeedUnit.Automatic;
        if (SpeedUnits.Family(unit) != SpeedUnits.Family(UiPreferences.Current.SpeedUnit))
            UiPreferences.Change(p => p with { SpeedUnit = unit });
    }

    // ---------- Your data ----------

    private void CountChecksLater() => Avalonia.Threading.Dispatcher.UIThread.Post(() => _ = CountChecksAsync());

    private async Task CountChecksAsync()
    {
        var (items, _) = await CheckHistory.LoadAsync();
        savedChecks = items.Count;
        var where = AppPaths.Edition == AppEdition.Portable ? "beside Netcheck.exe" : "in your user folder";
        DataHint.Text = savedChecks switch
        {
            0 => $"No saved checks yet. Settings are kept {where}.",
            1 => $"1 saved check and your settings, kept {where}.",
            var n => $"{n} saved checks and your settings, kept {where}.",
        };
        ClearLink.IsVisible = savedChecks > 0;
    }

    private async Task ClearHistoryAsync()
    {
        if (Window is not { } window || savedChecks <= 0)
            return;
        var what = savedChecks == 1 ? "1 saved check" : $"{savedChecks} saved checks";
        if (!await window.ConfirmAsync($"Delete {what}?",
                "This can't be undone. Your settings and undo records stay.", "Delete"))
        {
            ClearLink.Focus();
            return;
        }
        var cleared = await CheckHistory.ClearAsync();
        await CountChecksAsync();
        if (!cleared)
            DataHint.Text = "Your history couldn't be changed. Nothing was deleted.";
        FolderButton.Focus();
    }

    // ---------- Updates and version ----------

    private void ShowUpdates()
    {
        var p = UiPreferences.Current;
        UpdatesWhen.Text = p.AutoUpdateCheck ? "Once a day, from GitHub. " : "Only when you ask. ";
        LastChecked.Text = Updater.Stage switch
        {
            UpdateStage.Checking => "Checking…",
            UpdateStage.CheckFailed => Updater.Problem,
            _ when p.LastUpdateCheck is { } at => "Last checked " + Dates.When(at).Replace("Today · ", "", StringComparison.Ordinal),
            _ => "",
        } + (ReleaseFeed.IsTestFeed ? " · test feed" : "");
        CheckNowLink.IsEnabled = Updater.Stage is not (UpdateStage.Checking or UpdateStage.Downloading or UpdateStage.Installing);
        UpdateLink.IsVisible = Updater.HasOffer && Updater.Stage is UpdateStage.Available or UpdateStage.UpToDate;
        ShowVersion();
    }

    private void ShowVersion()
    {
        var current = AppPaths.Version;
        VersionLink.IsVisible = VersionButton.IsVisible = ProgressTrack.IsVisible = false;
        VersionLabel.ClearValue(Avalonia.Controls.Documents.TextElement.ForegroundProperty);
        VersionButton.Theme = (Avalonia.Styling.ControlTheme)this.FindResource("NcPrimaryButton")!;
        var offer = Updater.Offer;
        var installed = AppPaths.Edition == AppEdition.Installed;

        if (installed && Updater.Stage is UpdateStage.Downloading && offer is not null)
        {
            Version("", $"Updating to {offer.Version}",
                $"Downloading {Updater.Received / 1e6:0} of {offer.Size / 1e6:0} MB. Netcheck restarts when it's done.");
            ProgressTrack.IsVisible = true;
            ProgressFill.Width = 300.0 * Math.Clamp((double)Updater.Received / offer.Size, 0, 1);
            Button("Stop", Updater.StopDownload, quiet: true);
            return;
        }
        if (installed && Updater.Stage is UpdateStage.Installing && offer is not null)
        {
            Version("", $"Updating to {offer.Version}", "Installing… Click Yes if your PC asks.");
            return;
        }
        if (installed && WindowsInstaller.Interrupted)
        {
            Version("", "The last update stopped halfway", "Netcheck can put the earlier files back.");
            Button("Fix", async () => await RunAndShow(Updater.RecoverAsync()));
            return;
        }
        if (installed && Updater.Stage is UpdateStage.Failed)
        {
            Version("", "Update didn't finish", $"Nothing changed. {Updater.Problem}".TrimEnd());
            if (Updater.HasOffer)
                Button("Try Again", () => _ = Updater.UpdateAsync());
            return;
        }
        // A button appears here only when a newer version exists (user rule, P8 review).
        if (Updater.HasOffer && offer is not null)
        {
            Version(offer.Version.ToString(), "  is ready", $"You have {current}.");
            VersionLabel.Foreground = (IBrush?)this.FindResource("GoodBrush");
            Link("What's new", Updater.OpenReleasePage);
            if (installed)
                Button("Update Now", () => _ = Updater.UpdateAsync());
            else
                Button("Download", Updater.OpenReleasePage);   // a portable copy can't replace itself
            return;
        }

        switch (AppPaths.Edition)
        {
            case AppEdition.Installed:
                Version(current.ToString(), "  Installed", StatusHint());
                if (AppPaths.PreviousVersion() is { } previous && !previous.Equals(current))
                    Link(previous < current ? $"Go Back to {previous}" : $"Switch to {previous}", async () => await GoBackAsync(previous));
                break;

            case AppEdition.Portable:
                // No Install button here any more: it read as an update. Installing is offered where it is needed.
                Version(current.ToString(), "  Portable", StatusHint());
                break;

            default:
                Version(current.ToString(), "  Development build", "Running from a build folder. Install and updates use the release package.");
                break;
        }
    }

    private static string StatusHint() => Updater.Stage switch
    {
        UpdateStage.UpToDate => "You have the newest version.",
        UpdateStage.Checking => "Looking for a newer version…",
        UpdateStage.CheckFailed => "Couldn't check for a newer version right now.",
        _ => UiPreferences.Current.AutoUpdateCheck ? "Netcheck looks for a newer version once a day." : "Automatic checks are off.",
    };

    private async Task GoBackAsync(AppVersion previous)
    {
        if (Window is not { } window)
            return;
        var back = previous < AppPaths.Version;
        if (!await window.ConfirmAsync(back ? $"Go Back to {previous}?" : $"Switch to {previous}?",
                "Netcheck restarts as that version. Your checks, settings and undo records stay as they are.",
                back ? "Go Back" : "Switch"))
        {
            VersionLink.Focus();
            return;
        }
        VersionHint.Text = "Switching… Click Yes if your PC asks.";
        VersionLink.IsVisible = false;
        var result = await Updater.GoBackAsync();
        if (result.Outcome != InstallOutcome.Done)
        {
            ShowVersion();
            VersionHint.Text = Outcome(result);
        }
    }

    private async Task InstallAsync()
    {
        installState = "busy";
        ShowVersion();
        var result = await Updater.InstallFromPortableAsync();
        installState = result.Outcome switch
        {
            InstallOutcome.Done => "busy",   // closing; the installed copy opens
            InstallOutcome.AlreadyInstalled => "already",
            _ => Outcome(result),
        };
        ShowVersion();
    }

    private async Task RunAndShow(Task<InstallResult> work)
    {
        VersionHint.Text = "Working… Click Yes if your PC asks.";
        VersionButton.IsVisible = false;
        var result = await work;
        ShowVersion();
        if (result.Outcome != InstallOutcome.Done)
            VersionHint.Text = Outcome(result);
    }

    private static string Outcome(InstallResult result) => result.Outcome switch
    {
        InstallOutcome.Cancelled => "Nothing changed. Windows asked for permission and it wasn't given.",
        InstallOutcome.RecoveryRequired => "It stopped halfway. Use Fix to put the earlier files back.",
        _ => "Nothing changed." + (result.Reason.Length > 0 ? $" ({result.Reason.TrimEnd('.')})" : ""),
    };

    private void Version(string number, string label, string hint)
    {
        VersionNumber.Text = number;
        VersionLabel.Text = number.Length == 0 ? label.TrimStart() : label;
        VersionHint.Text = hint;
    }

    private void Link(string text, Action click)
    {
        VersionLink.Content = text;
        VersionLink.IsVisible = true;
        handlers.link = click;
    }

    private void Button(string text, Action click, bool quiet = false)
    {
        VersionButton.Content = text;
        if (quiet)
            VersionButton.Theme = (Avalonia.Styling.ControlTheme)this.FindResource("NcQuietButton")!;
        VersionButton.IsVisible = true;
        handlers.button = click;
    }

    private (Action? link, Action? button) handlers;

    protected override void OnInitialized()
    {
        base.OnInitialized();
        VersionLink.Click += (_, _) => handlers.link?.Invoke();
        VersionButton.Click += (_, _) => handlers.button?.Invoke();
    }

    /// <summary>One pill per app size; sizes that would not fit this screen are disabled.</summary>
    private void BuildSizes()
    {
        if (Window is not { } window)
            return;
        Sizes.Children.Clear();
        sizeSlider.Reset();
        foreach (var scale in MainWindow.Scales)
        {
            var pill = new RadioButton
            {
                Theme = (Avalonia.Styling.ControlTheme)this.FindResource("NcTab")!,
                Classes = { "seg" },
                GroupName = "AppSize",
                Content = (scale * 100).ToString("0", CultureInfo.CurrentCulture) + "%",
                IsChecked = Math.Abs(scale - window.AppScale) < 0.001,
                IsEnabled = window.Fits(scale),
            };
            ToolTip.SetTip(pill, pill.IsEnabled ? null : "Too big for this screen");
            var chosen = scale;
            pill.IsCheckedChanged += (_, _) =>
            {
                if (pill.IsChecked == true && Math.Abs(chosen - window.AppScale) > 0.001)
                    window.ApplyScale(chosen);
            };
            Sizes.Children.Add(pill);
        }
    }
}
