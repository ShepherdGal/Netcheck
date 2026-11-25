using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Netcheck.Core;
using Netcheck.Elevation;

namespace Netcheck.Pages;

/// <summary>
/// Boost tab (direction A): detects safe improvements, applies them through the elevated tweak broker with a
/// restore point and a 15-second "Keep these changes?" guard, and can undo everything later.
/// </summary>
public sealed partial class BoostPage : UserControl
{
    private const int KeepSeconds = 15;
    private BoostScan? scan;
    private bool busy;
    private Func<Task>? primaryAction, secondaryAction, linkAction;
    private TaskCompletionSource<bool>? decision;

    private readonly Netcheck.Controls.InstallOffer applyInstall, chooseInstall;
    /// <summary>The work view shows a finished result (not a question or a fix): leaving the tab returns to the list.</summary>
    private bool workSettled;

    public BoostPage()
    {
        InitializeComponent();
        applyInstall = new Netcheck.Controls.InstallOffer(ApplyNote, ApplyInstall);
        chooseInstall = new Netcheck.Controls.InstallOffer(ChooseNote, ChooseInstall);
        ApplyButton.Click += async (_, _) => { if (scan is { } s) await ApplyAsync(s.Recommended.ToArray(), restorePoint: true); };
        ChooseLink.Click += (_, _) => { BuildChoose(); Show(ChooseView); };
        MythsLink.Click += (_, _) => Show(MythsView);
        UndoLink.Click += async (_, _) => await UndoAsync();
        ChooseBack.Click += (_, _) => Show(MainView);
        MythsBack.Click += (_, _) => Show(MainView);
        ChooseApply.Click += async (_, _) => await ApplyChosenAsync();
        WorkPrimary.Click += async (_, _) => { if (primaryAction is { } a) await a(); };
        WorkSecondary.Click += async (_, _) => { if (secondaryAction is { } a) await a(); };
        WorkLink.Click += async (_, _) => { if (linkAction is { } a) await a(); };
        BuildMyths();
        if (BoostAdvisor.Last is { } ready)
            Render(ready);   // built in the background after start: the list is there before the tab is ever opened
        AttachedToVisualTree += async (_, _) =>
        {
            if (busy)
                return;
            if (workSettled)
                WorkView.IsVisible = false;   // back on the tab after a finished apply/undo: show the list (P12b)
            await RescanAsync();
        };
    }

    private void Show(Control view)
    {
        foreach (var v in new Control[] { MainView, ChooseView, MythsView, WorkView })
            v.IsVisible = v == view;
        Motion.EnterPage(view);
    }

    // ---------- main ----------

    /// <summary>Shows the latest scan at once (no "Looking at Your PC…" wait), then refreshes it in place.</summary>
    private async Task RescanAsync()
    {
        if (scan is null && BoostAdvisor.Last is { } ready)
            Render(ready);
        Render(await BoostAdvisor.ScanAsync());
    }

    private void Render(BoostScan latest)
    {
        scan = latest;
        var recommended = scan.Recommended.ToArray();
        var good = scan.Good.ToArray();
        var installed = WindowsTweakBroker.IsEnabled;

        if (recommended.Length == 0)
        {
            MainTitle.Text = "Your PC is already set up well";
            MainLead.Text = scan.Optional.Any() ? "Nothing needs changing. A few optional extras are under Choose Myself."
                : "Nothing needs changing.";
        }
        else
        {
            MainTitle.Text = recommended.Length == 1 ? "1 safe improvement for this PC" : $"{recommended.Length} safe improvements for this PC";
            MainLead.Text = "Small fixes that keep your connection steady. Nothing risky.";
        }
        TunedText.Text = scan.TunedFor;
        TunedChip.IsVisible = scan.TunedFor.Length > 0;
        ApplyButton.IsVisible = recommended.Length > 0;
        ApplyButton.Content = recommended.Length == 1 ? "Apply 1 Improvement" : $"Apply {recommended.Length} Improvements";
        ApplyButton.IsEnabled = installed;
        // Portable copy (P12b): the install is offered even when only optional extras exist.
        var offerInstall = !installed && (recommended.Length > 0 || scan.Optional.Any());
        ApplyNote.IsVisible = recommended.Length > 0 || offerInstall;
        ApplyRow.IsVisible = ApplyNote.IsVisible;   // a hidden row must not keep its 16 px gap (measured 2026-11-17)
        if (installed)
        {
            ApplyNote.Text = "A restore point is made first. You can undo any time.";
            applyInstall.Hide();
        }
        else if (offerInstall)
            applyInstall.Show("Applying needs the installed app");
        else
            applyInstall.Hide();

        MainRows.Children.Clear();
        foreach (var item in recommended)
            MainRows.Children.Add(Row(Mark("+", "GoodBrush"), item.Name, item.Reason, null));
        if (good.Length > 0)
        {
            var show = new Button { Theme = Find<Avalonia.Styling.ControlTheme>("NcLinkButton"), Content = "Show", VerticalAlignment = VerticalAlignment.Center };
            show.Click += (_, _) => { BuildChoose(); Show(ChooseView); };
            var text = good.Length == 1 ? "1 more setting is already good" : $"{good.Length} more settings are already good";
            MainRows.Children.Add(Row(Mark("✓", "GoodBrush"), text, null, show, quiet: true));
        }
        Trim(MainRows);
        MainCard.IsVisible = MainRows.Children.Count > 0;

        var undo = installed && BoostAdvisor.Originals is { Length: > 0 };
        UndoLink.IsVisible = UndoDot.IsVisible = undo;
        // Re-scans run each time the tab opens, just after the page's own fade-in. Fading MainView again from 0
        // made the whole page blink, so an already-visible main view is updated in place.
        if (!WorkView.IsVisible && !MainView.IsVisible)
            Show(MainView);
    }

    // ---------- choose myself ----------

    private void BuildChoose()
    {
        ChooseRows.Children.Clear();
        if (scan is null)
            return;
        foreach (var item in scan.Recommended.Concat(scan.Optional))
        {
            var box = new CheckBox
            {
                Theme = Find<Avalonia.Styling.ControlTheme>("NcCheck"), Tag = item,
                IsChecked = item.Kind == BoostKind.Recommended,
                Content = Texts(item.Name, item.Reason),
            };
            box.IsCheckedChanged += (_, _) => UpdateChooseButton();
            var tag = new TextBlock
            {
                Text = item.Kind == BoostKind.Recommended ? "Recommended" : "Optional", FontSize = 16,
                Foreground = Brush(item.Kind == BoostKind.Recommended ? "Ink3Brush" : "FairBrush"), VerticalAlignment = VerticalAlignment.Center,
            };
            ChooseRows.Children.Add(Cell(Grid2(box, tag)));
        }
        foreach (var item in scan.Good)
            ChooseRows.Children.Add(Row(Mark("✓", "GoodBrush"), item.Label, null,
                new TextBlock { Text = "Already good", FontSize = 16, Foreground = Brush("GoodBrush"), VerticalAlignment = VerticalAlignment.Center }, quiet: true));
        Trim(ChooseRows);
        var installed = WindowsTweakBroker.IsEnabled;
        RestoreCheck.IsVisible = installed;
        ChooseInstallRow.IsVisible = !installed;
        if (installed)
            chooseInstall.Hide();
        else
            chooseInstall.Show("Applying needs the installed app");
        UpdateChooseButton();
    }

    private BoostItem[] Chosen() => ChooseRows.Children.OfType<Border>()
        .Select(b => (b.Child as Grid)?.Children.OfType<CheckBox>().FirstOrDefault())
        .Where(c => c is { IsChecked: true, Tag: BoostItem }).Select(c => (BoostItem)c!.Tag!).ToArray();

    private void UpdateChooseButton()
    {
        var n = Chosen().Length;
        ChooseApply.Content = n == 0 ? "Apply" : $"Apply {n}";
        ChooseApply.IsEnabled = n > 0 && WindowsTweakBroker.IsEnabled;
    }

    private async Task ApplyChosenAsync()
    {
        var chosen = Chosen();
        if (chosen.Length > 0)
            await ApplyAsync(chosen, RestoreCheck.IsChecked == true);
    }

    // ---------- apply / keep / done ----------

    private async Task ApplyAsync(BoostItem[] items, bool restorePoint)
    {
        if (busy || items.Length == 0)
            return;
        busy = true;
        Work("Applying…", restorePoint ? "Click Yes if your PC asks. The restore point can take up to a minute." : "Click Yes if your PC asks.");
        TweakApplyResult result;
        try
        {
            result = await WindowsTweakBroker.ApplyAsync(items.Select(i => i.Target).ToArray(), restorePoint, KeepAsync);
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            result = new(TweakOutcome.Rejected, RestorePointResult.NotRequested);
        }
        catch (Exception error) when (error is OperationCanceledException or IOException or Win32Exception or
            System.Text.Json.JsonException or InvalidOperationException or UnauthorizedAccessException)
        {
            // The helper stopped without a final answer. Only call it broken when a setting actually moved;
            // all still at their earlier values means nothing happened (same rule as the DNS switch, 2026-11-16).
            result = await Task.Run(() => Unchanged(items))
                ? new(TweakOutcome.Rejected, RestorePointResult.NotRequested, $"Netcheck's helper stopped before changing anything ({error.Message}).")
                : new(TweakOutcome.RecoveryRequired, RestorePointResult.NotRequested, error.Message);
        }
        finally { busy = false; }

        var note = RestoreNote(result.RestorePoint);
        BoostAdvisor.LogLast("apply", result.Outcome, result.Reason);
        ToolTip.SetTip(WorkTitle, result.Reason.Length > 0 ? result.Reason : null);
        switch (result.Outcome)
        {
            case TweakOutcome.Committed or TweakOutcome.NoChange:
                if (result.Outcome == TweakOutcome.Committed)
                    BoostAdvisor.RememberOriginals(items.Select(i => i.Current));
                Work(items.Length == 1 ? "1 improvement on" : $"{items.Length} improvements on", "Check your internet to see if it helped.",
                    tone: Tone.Good, primary: ("Check My Internet", OpenCheckAsync), secondary: ("Done", BackToMainAsync),
                    link: ("Undo", UndoAsync), meta: note, settled: true);
                break;
            case TweakOutcome.Rejected or TweakOutcome.Restored:
                Work("Nothing changed", "Your PC is the same as before.", tone: Tone.Neutral,
                    primary: ("Back", BackToMainAsync), meta: note, settled: true);
                break;
            default:
                Work("Some settings need a fix", "Netcheck can put your earlier settings back.", tone: Tone.Poor,
                    primary: ("Fix It", FixAsync));
                break;
        }
    }

    /// <summary>True when every item still reads its value from before the attempt (read-only, no elevation).</summary>
    private static bool Unchanged(IEnumerable<BoostItem> items)
    {
        try
        {
            return items.All(i => WindowsTweakBroker.Read(i.Target.Id, i.Target.Adapter).Value == i.Current.Value);
        }
        catch (Exception)
        {
            return false;   // can't tell: keep offering the fix
        }
    }

    /// <summary>Verify step, called from the broker exchange: "Keep these changes?" with an automatic undo after 15 s.</summary>
    private Task<bool> KeepAsync(CancellationToken token) => Dispatcher.UIThread.InvokeAsync(async () =>
    {
        decision = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var left = KeepSeconds;
        string Line() => $"Your PC will go back automatically in {left} s if you don't answer.";
        Work("Keep these changes?", Line(), primary: ("Keep", () => { decision.TrySetResult(true); return Task.CompletedTask; }),
            secondary: ("Undo", () => { decision.TrySetResult(false); return Task.CompletedTask; }));
        var timer = new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Normal, (_, _) =>
        {
            left--;
            if (left <= 0)
                decision.TrySetResult(false);
            else
                WorkLine.Text = Line();
        });
        timer.Start();
        try { return await decision.Task.WaitAsync(token); }
        catch (OperationCanceledException) { return false; }
        finally
        {
            timer.Stop();
            Work("Finishing…", "One moment.");
        }
    });

    private async Task UndoAsync()
    {
        if (busy || BoostAdvisor.Originals is not { Length: > 0 } originals)
            return;
        busy = true;
        Work("Undoing…", "Click Yes if your PC asks.");
        TweakOutcome outcome;
        try
        {
            var undo = await WindowsTweakBroker.ApplyAsync(originals, restorePoint: false, _ => Task.FromResult(true));
            outcome = undo.Outcome;
            BoostAdvisor.LogLast("undo", undo.Outcome, undo.Reason);
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223) { outcome = TweakOutcome.Rejected; }
        catch (Exception error) when (error is OperationCanceledException or IOException or Win32Exception or
            System.Text.Json.JsonException or InvalidOperationException or UnauthorizedAccessException)
        {
            outcome = TweakOutcome.RecoveryRequired;
        }
        finally { busy = false; }

        if (outcome is TweakOutcome.Committed or TweakOutcome.NoChange)
        {
            BoostAdvisor.ForgetOriginals();
            Work("Your earlier settings are back", "", tone: Tone.Good, primary: ("Done", BackToMainAsync), settled: true);
        }
        else if (outcome is TweakOutcome.Rejected or TweakOutcome.Restored)
            Work("Nothing changed", "Your Boost changes are still on.", tone: Tone.Neutral, primary: ("Back", BackToMainAsync),
                link: ("Try Again", UndoAsync), settled: true);
        else
            Work("Some settings need a fix", "Netcheck can put your earlier settings back.", tone: Tone.Poor, primary: ("Fix It", FixAsync));
    }

    private async Task FixAsync()
    {
        if (busy)
            return;
        busy = true;
        Work("Fixing…", "Click Yes if your PC asks.");
        TweakOutcome outcome;
        try { outcome = await WindowsTweakBroker.RecoverAsync(); }
        catch (Exception error) when (error is Win32Exception or OperationCanceledException or IOException or
            System.Text.Json.JsonException or InvalidOperationException or UnauthorizedAccessException)
        {
            outcome = TweakOutcome.RecoveryRequired;
        }
        finally { busy = false; }
        if (outcome is TweakOutcome.Restored or TweakOutcome.NoChange)
            Work("Fixed", "Your earlier settings are back.", tone: Tone.Good, primary: ("Done", BackToMainAsync), settled: true);
        else
            Work("Some settings need a fix", "Netcheck can put your earlier settings back.", tone: Tone.Poor, primary: ("Fix It", FixAsync));
    }

    private Task OpenCheckAsync()
    {
        (TopLevel.GetTopLevel(this) as MainWindow)?.Navigate("check");
        return BackToMainAsync();
    }

    private async Task BackToMainAsync()
    {
        workSettled = false;
        WorkView.IsVisible = false;
        await RescanAsync();
    }

    private static string RestoreNote(RestorePointResult point) => point switch
    {
        RestorePointResult.Made => "A restore point was made first.",
        RestorePointResult.Skipped => "Windows skipped the restore point because one was made recently.",
        RestorePointResult.Off => "Restore points are off on this PC, so none was made.",
        RestorePointResult.Failed => "Windows couldn't make a restore point.",
        _ => "",
    };

    private void Work(string title, string line, Tone tone = Tone.Neutral,
        (string Text, Func<Task> Act)? primary = null, (string Text, Func<Task> Act)? secondary = null,
        (string Text, Func<Task> Act)? link = null, string meta = "", bool settled = false)
    {
        workSettled = settled;
        WorkTitle.Text = title;
        WorkTitle.Foreground = tone == Tone.Neutral ? Brush("InkBrush") : Brush(tone switch
        {
            Tone.Good => "GoodBrush", Tone.Fair => "FairBrush", _ => "PoorBrush",
        });
        WorkLine.Text = line;
        WorkLine.IsVisible = line.Length > 0;
        WorkPrimary.Content = primary?.Text;
        WorkPrimary.IsVisible = primary is not null;
        primaryAction = primary?.Act;
        WorkSecondary.Content = secondary?.Text;
        WorkSecondary.IsVisible = secondary is not null;
        secondaryAction = secondary?.Act;
        WorkButtons.IsVisible = primary is not null || secondary is not null;
        WorkLink.Content = link?.Text;
        WorkLink.IsVisible = link is not null;
        linkAction = link?.Act;
        WorkMeta.Text = meta;
        WorkMeta.IsVisible = meta.Length > 0;
        if (!WorkView.IsVisible)
            Show(WorkView);
        if (primary is not null)
            WorkPrimary.Focus();
    }

    // ---------- myths ----------

    private void BuildMyths()
    {
        MythRows.Children.Clear();
        foreach (var (name, why) in BoostMyths.All)
        {
            var row = Row(Mark("–", "Ink3Brush"), name, why, null);
            row.Padding = new Thickness(24, 8);   // ten rows must fit the fixed window at the +2 px text size (2026-11-17)
            MythRows.Children.Add(row);
        }
        Trim(MythRows);
    }

    // ---------- row helpers ----------

    private static Netcheck.Controls.Divided Row(Control mark, string name, string? reason, Control? right, bool quiet = false)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("22,*,Auto"), ColumnSpacing = 12 };
        var text = Texts(name, reason, quiet);
        Grid.SetColumn(text, 1);
        grid.Children.Add(mark);
        grid.Children.Add(text);
        if (right is not null)
        {
            Grid.SetColumn(right, 2);
            grid.Children.Add(right);
        }
        return Cell(grid);
    }

    private static void Trim(Panel rows)
    {
        if (rows.Children.FirstOrDefault() is Border first)
            first.BorderThickness = new Thickness(0);
    }

    private static Grid Grid2(Control left, Control right)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), ColumnSpacing = 12 };
        Grid.SetColumn(right, 1);
        grid.Children.Add(left);
        grid.Children.Add(right);
        return grid;
    }

    /// <summary>Joined-card row: hairline above every row except the first (see <see cref="Trim"/>).</summary>
    private static Netcheck.Controls.Divided Cell(Control child)
    {
        return new Netcheck.Controls.Divided
        {
            Child = child, Padding = new Thickness(24, 12),
            Lines = new Thickness(0, 1, 0, 0),
        };
    }

    private static StackPanel Texts(string name, string? reason, bool quiet = false)
    {
        var stack = new StackPanel { Spacing = 2, VerticalAlignment = VerticalAlignment.Center };
        stack.Children.Add(new TextBlock { Text = name, FontSize = 18, Foreground = Brush(quiet ? "Ink2Brush" : "InkBrush"), TextWrapping = TextWrapping.Wrap });
        if (reason is not null)
            stack.Children.Add(new TextBlock { Text = reason, FontSize = 16, Foreground = Brush("Ink2Brush"), TextWrapping = TextWrapping.Wrap });
        return stack;
    }

    private static TextBlock Mark(string glyph, string brush) => new()
    {
        Text = glyph, FontSize = 19, FontWeight = FontWeight.SemiBold, Foreground = Brush(brush),
        HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
    };

    private static T? Find<T>(string key) where T : class =>
        ThemeManager.Resource(key) as T;

    private static IBrush Brush(string key) =>
        ThemeManager.Brush(key);
}
