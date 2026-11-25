using System.Globalization;
using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Layout;
using Avalonia.Media;
using Netcheck.Core;
using Netcheck.Measurements.Resolvers;

namespace Netcheck.Pages;

/// <summary>
/// DNS tab: choose a goal → live race (round 1 quick test, round 2 finalists) → result (winner, podium,
/// now vs. with the winner) → all results. "Switch to X" changes DNS through the elevated broker (installed app
/// only); "Switch back" restores the settings from before Netcheck's first switch.
/// </summary>
public sealed partial class DnsPage : UserControl
{
    private const double BarMaxMs = 120;
    private readonly Dictionary<DnsCandidate, (Border Bar, TextBlock Ms, Control Row)> lanes = new();
    private CancellationTokenSource? run;
    private ConnectionInfo connection = ConnectionInfo.Unknown;
    private DnsBenchmarkResult? last;
    private bool switching;
    private Func<Task>? primaryAction;

    private readonly Netcheck.Controls.InstallOffer useInstall;

    public DnsPage()
    {
        InitializeComponent();
        FindButton.Click += async (_, _) => await RunAsync();
        // The timing note lives behind an (i) beside the button, not as a line under it (user, 2026-11-17).
        AgainButton.Click += async (_, _) => await RunAsync();
        StopButton.Click += (_, _) => run?.Cancel();
        AllButton.Click += (_, _) => Show(AllView);
        BackButton.Click += (_, _) => Show(ResultView);
        useInstall = new Netcheck.Controls.InstallOffer(UseNote, UseInstall);
        UseButton.Click += async (_, _) => { if (primaryAction is { } act) await act(); };
        BackLink.Click += async (_, _) => await SwitchBackFromFormAsync();
        _ = ShowCurrentAsync();
    }

    private DnsGoal Goal => GoalMalware.IsChecked == true ? DnsGoal.BlocksMalware
        : GoalFamily.IsChecked == true ? DnsGoal.FamilySafe : DnsGoal.Fastest;

    private void Show(Control view)
    {
        foreach (var v in new Control[] { FormView, RaceView, ResultView, AllView })
            v.IsVisible = v == view;
        Motion.EnterPage(view);
    }

    /// <summary>Real data: the DNS server Windows uses now and the connection type.</summary>
    private async Task ShowCurrentAsync()
    {
        connection = await ConnectionInfo.ReadAsync();
        DnsName.Text = connection.DnsName.Length > 0 ? connection.DnsName : "Unknown";
        DnsAddress.Text = connection.DnsAddress.Length > 0 ? connection.DnsAddress : "—";
        ConnectionKind.Text = connection.Kind.Length > 0 ? connection.Kind : "—";
        UpdateBackLink();
    }

    // ---------- switching ----------

    /// <summary>Name of the DNS used before Netcheck's first switch ("Google"), or a plain fallback.</summary>
    private static string OriginalName() => DnsSwitcher.Original is { } o
        ? o.Resolvers.Count == 0 ? "automatic DNS"
          : ConnectionInfo.NameOf(o.Resolvers[0].Address) ?? "your previous DNS"
        : "your previous DNS";

    /// <summary>Form view: a quiet "Switch back to Google" while a Netcheck switch is in place.</summary>
    private void UpdateBackLink()
    {
        var show = DnsSwitcher.IsAvailable && DnsSwitcher.Original is not null && !switching;
        BackLink.IsVisible = show;
        if (show)
            BackLink.Content = $"Switch Back to {LabelCase(OriginalName())}";
    }

    /// <summary>Button labels are Title Case (design rules): "automatic DNS" → "Automatic DNS"; provider names stay as they are.</summary>
    private static string LabelCase(string name) => name switch
    {
        "automatic DNS" => "Automatic DNS",
        "your previous DNS" => "Your Previous DNS",
        _ => name,
    };

    private async Task SwitchToWinnerAsync()
    {
        if (switching || last?.Winner is not { } winner)
            return;
        await RunSwitchAsync(async () => await DnsSwitcher.SwitchToAsync(await OrderedAsync(winner.Server)), winner.Server.Name);
    }

    /// <summary>P11: the current DNS already wins; keep the provider and turn on private (encrypted) lookups.</summary>
    private async Task MakePrivateAsync()
    {
        if (switching || last?.Current is not { } current || !current.Server.SupportsEncryption)
            return;
        await RunSwitchAsync(async () => await DnsSwitcher.SwitchToAsync(await OrderedAsync(current.Server)),
            ProviderName(current.Server), makePrivate: true);
    }

    /// <summary>"Quad9 (no filter)" → ("Quad9", "No filter"); a name without brackets has no extra part.</summary>
    internal static (string Title, string? Extra) PodiumName(string name)
    {
        var open = name.IndexOf(" (", StringComparison.Ordinal);
        if (open <= 0 || !name.EndsWith(')'))
            return (name, null);
        var extra = name[(open + 2)..^1];
        return (name[..open], extra.Length == 0 ? null : char.ToUpper(extra[0], CultureInfo.CurrentCulture) + extra[1..]);
    }

    /// <summary>"Yours (Cloudflare)" → "Cloudflare" for status lines.</summary>
    private static string ProviderName(DnsCandidate server) =>
        server.Name.StartsWith("Yours (", StringComparison.Ordinal) && server.Name.EndsWith(')') ? server.Name[7..^1] : server.Name;

    // ---------- second address ----------

    // The benchmark times only a provider's first address (1.1.1.1); its second (1.0.0.1) is timed in the background
    // once the result shows, and the quicker one goes first when switching (Windows mostly uses the first).
    private (DnsCandidate For, Task<DnsCandidate> Order, CancellationTokenSource Stop)? secondTiming;

    private void StartSecondTiming(DnsCandidate winner)
    {
        StopSecondTiming();
        if (winner.Secondary is null)
            return;
        var stop = new CancellationTokenSource();
        // Timed as it will be used after switching: over HTTPS whenever the provider has a template.
        var timed = winner with { ViaHttps = winner.DohTemplate is not null };
        secondTiming = (winner, new DnsBenchmarkEngine().FasterFirstAsync(timed, stop.Token), stop);
    }

    private void StopSecondTiming()
    {
        if (secondTiming is { } t)
        {
            t.Stop.Cancel();
            secondTiming = null;
        }
    }

    /// <summary>The winner with its quicker address first; the provider's order if the timing isn't ready or failed.</summary>
    private async Task<DnsCandidate> OrderedAsync(DnsCandidate winner)
    {
        if (secondTiming is not { } t || t.For != winner)
            return winner;
        try { return await t.Order.WaitAsync(TimeSpan.FromSeconds(5)); }
        catch (Exception) { return winner; }   // a failed or slow timing never blocks the switch
    }

    private async Task SwitchBackAsync()
    {
        if (switching)
            return;
        var name = OriginalName();
        await RunSwitchAsync(() => DnsSwitcher.SwitchBackAsync(), name, back: true);
    }

    private async Task SwitchBackFromFormAsync()
    {
        if (switching)
            return;
        BackLink.IsEnabled = false;
        BackLink.Content = "Switching…";
        var outcome = await DnsSwitcher.SwitchBackAsync();
        BackLink.IsEnabled = true;
        await ShowCurrentAsync();
        if (outcome.Result != SwitchResult.Done)
        {
            BackLink.IsVisible = true;
            BackLink.Content = outcome.Result == SwitchResult.NeedsFix ? "Fix My DNS" : "Nothing Changed · Try Again";
            ToolTip.SetTip(BackLink, outcome.Reason);
        }
    }

    private async Task RunSwitchAsync(Func<Task<SwitchOutcome>> action, string name, bool back = false, bool makePrivate = false)
    {
        switching = true;
        UseButton.IsVisible = UseNote.IsVisible = false;
        useInstall.Hide();
        SetSwitch("Switching… click Yes if your PC asks", Tone.Neutral, null, null);
        SwitchOutcome outcome;
        try { outcome = await action(); }
        finally { switching = false; }

        switch (outcome.Result)
        {
            case SwitchResult.Done when back:
                SetSwitch($"You're back on {name}", Tone.Good, null, null, outcome.Reason);
                break;
            case SwitchResult.Done:
                // "private" only when Windows reads back encrypted-only settings (the Verify step already passed).
                var isPrivate = DnsSwitcher.ReadPrivateState() == PrivateState.On;
                SetSwitch(makePrivate ? (isPrivate ? $"Your lookups are private now · {name}" : $"You're on {name} now")
                        : isPrivate ? $"You're on {name} now · private" : $"You're on {name} now",
                    Tone.Good, "Switch Back", SwitchBackAsync, outcome.Reason, quiet: true);
                break;
            case SwitchResult.NothingChanged:
                // Neutral, not a warning (user, 2026-11-16): nothing happened and the internet is as before.
                SetSwitch("Nothing changed · your internet is the same", Tone.Neutral, "Try Again",
                    back ? SwitchBackAsync : makePrivate ? MakePrivateAsync : SwitchToWinnerAsync, outcome.Reason);
                break;
            default:
                SetSwitch("Your DNS needs a fix", Tone.Poor, "Fix It", FixAsync,
                    $"Netcheck can put your earlier settings back. ({outcome.Reason})");
                break;
        }
        await ShowCurrentAsync();
    }

    private async Task FixAsync()
    {
        switching = true;
        SetSwitch("Fixing… click Yes if your PC asks", Tone.Neutral, null, null);
        SwitchOutcome outcome;
        try { outcome = await DnsSwitcher.FixAsync(); }
        finally { switching = false; }
        if (outcome.Result == SwitchResult.NeedsFix)
            SetSwitch("Your DNS needs a fix", Tone.Poor, "Fix It", FixAsync,
                $"Netcheck can put your earlier settings back. ({outcome.Reason})");
        else
            SetSwitch("Fixed · your earlier DNS is back", Tone.Good, null, null, outcome.Reason);
        await ShowCurrentAsync();
    }

    /// <summary>A switch's status takes the verdict line's place; the one button changes role. Details go in a tooltip.</summary>
    private void SetSwitch(string title, Tone tone, string? button, Func<Task>? action, string? tip = null, bool quiet = false)
    {
        SetLine(tone, title);
        ToolTip.SetTip(ResultLinePanel, string.IsNullOrWhiteSpace(tip) ? null : tip);
        UseNote.IsVisible = false;
        useInstall.Hide();
        UseButton.IsVisible = button is not null;
        UseButton.IsEnabled = true;
        ToolTip.SetTip(UseButton, null);
        if (button is not null)
        {
            UseButton.Content = button;
            UseButton.Theme = (Avalonia.Styling.ControlTheme)Application.Current!.FindResource(quiet ? "NcQuietButton" : "NcPrimaryButton")!;
        }
        primaryAction = action;
        (button is not null ? (Control)UseButton : AgainButton).Focus();
    }

    /// <summary>
    /// The goal's list plus the DNS this PC uses now (marked as current; never listed twice). Each is timed the way it
    /// is really used (P12b): providers with a template over HTTPS, because switching turns private lookups on; the
    /// current DNS the way Windows reaches it now (<paramref name="currentTemplate"/> = its HTTPS template when private).
    /// </summary>
    private List<DnsCandidate> Candidates(string? currentTemplate)
    {
        var list = DnsCandidates.For(Goal).Select(c => c with { ViaHttps = c.DohTemplate is not null }).ToList();
        if (connection.DnsAddress.Length == 0)
            return list;
        var match = list.FindIndex(c => c.Address == connection.DnsAddress);
        var label = connection.DnsName.Length > 0 ? $"Yours ({connection.DnsName})" : "Yours";
        if (match >= 0)
            list[match] = list[match] with
            {
                Name = label, IsCurrent = true, ViaHttps = currentTemplate is not null,
                DohTemplate = currentTemplate ?? list[match].DohTemplate,
            };
        else
            list.Insert(0, new DnsCandidate(label, connection.DnsAddress, DohTemplate: currentTemplate, IsCurrent: true,
                ViaHttps: currentTemplate is not null));
        return list;
    }

    // ---------- race ----------

    private async Task RunAsync()
    {
        if (run is not null)
            return;
        if (connection.Kind.Length == 0)
            await ShowCurrentAsync();
        run = new CancellationTokenSource();
        StopSecondTiming();
        var address = connection.DnsAddress;
        var candidates = Candidates(await Task.Run(() => DnsSwitcher.HttpsTemplateFor(address)));
        RaceTitle.Text = "Testing DNS Servers";
        RaceLine.Text = $"Quick test of {candidates.Count} servers";
        BuildLanes(candidates);
        Show(RaceView);
        StopButton.Focus();

        var round = DnsRound.Quick;
        StartFill();
        var progress = new Progress<DnsBenchmarkProgress>(p =>
        {
            if (p.Round != round)
            {
                round = p.Round;
                RaceLine.Text = "Closer test of the fastest";
            }
            if (!lanes.TryGetValue(p.Server, out var lane))
                return;
            if (p.Out)
            {
                lane.Row.Opacity = 0.4;
                lane.Ms.Text = "Out";
                return;
            }
            if (p.Ms is { } ms)
            {
                lane.Bar.Width = Math.Max(6, 300 * Math.Clamp(1 - ms / BarMaxMs, 0.04, 1));
                lane.Ms.Text = $"{Ms(ms)} ms";
            }
        });

        DnsBenchmarkResult? result;
        try
        {
            result = await new DnsBenchmarkEngine().RunAsync(Goal, candidates, new DnsBenchmarkOptions(), progress, run.Token);
        }
        catch (Exception)
        {
            // An unexpected failure goes back to the start, like Stop; it used to be rethrown into the click handler,
            // which closed the app.
            result = null;
        }
        finally
        {
            run.Dispose();
            run = null;
        }
        last = result;
        if (result is null || result.Stopped || result.Ranked.Count == 0)
        {
            StopFillTimer();
            Show(FormView);
            FindButton.Focus();
            return;
        }
        await FinishFillAsync();   // the fill reaches 100 % before the result takes over
        ShowResult(result);
    }

    private void BuildLanes(IEnumerable<DnsCandidate> candidates)
    {
        Lanes.Children.Clear();
        lanes.Clear();
        foreach (var c in candidates)
        {
            var bar = new Border { Height = 8, Width = 0, CornerRadius = new CornerRadius(4), HorizontalAlignment = HorizontalAlignment.Left,
                Background = Brush(c.IsCurrent ? "UpFromBrush" : "AccentBrush") };
            if (!Motion.Reduced)
                bar.Transitions = [new DoubleTransition { Property = WidthProperty, Duration = TimeSpan.FromMilliseconds(260), Easing = Motion.EaseOut }];
            var ms = new TextBlock { Text = "…", FontSize = 18, HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center };
            var name = new StackPanel
            {
                VerticalAlignment = VerticalAlignment.Center,
                Children =
                {
                    new TextBlock { Text = c.Name, FontSize = 18, FontWeight = c.IsCurrent ? FontWeight.SemiBold : FontWeight.Normal },
                    new TextBlock { Text = c.Address, FontSize = 16, Foreground = Brush("Ink3Brush") },
                },
            };
            var track = new Border { Height = 8, Width = 300, CornerRadius = new CornerRadius(4), Background = Brush("Surface2Brush"),
                VerticalAlignment = VerticalAlignment.Center, Child = bar };
            var row = new Grid { ColumnDefinitions = new ColumnDefinitions("*,300,90"), ColumnSpacing = 20, Margin = new Thickness(24, 8) };
            Grid.SetColumn(track, 1);
            Grid.SetColumn(ms, 2);
            row.Children.Add(name);
            row.Children.Add(track);
            row.Children.Add(ms);
            var cell = new Netcheck.Controls.Divided { Child = row,
                Lines = new Thickness(0, Lanes.Children.Count == 0 ? 0 : 1, 0, 0) };
            if (!Motion.Reduced)
                cell.Transitions = [new DoubleTransition { Property = OpacityProperty, Duration = TimeSpan.FromMilliseconds(300) }];
            Lanes.Children.Add(cell);
            lanes[c] = (bar, ms, cell);
        }
    }

    // ---------- the Stop button's fill ----------
    // The fill is driven by a clock, not by the benchmark's progress reports (user, 2026-11-25): it glides from 0 to 100 %
    // without ever pausing, even while the test stalls or races ahead between reports (they are front-loaded and stop
    // for seconds, so following them made the fill jump and freeze). The clock's expected total is the page's "about
    // 20 seconds" at first, then the length of the previous finished test. If the test runs long the fill keeps
    // creeping toward (never reaching) the end; when the test finishes it eases to 100 % and the result appears.

    private Avalonia.Threading.DispatcherTimer? fillTimer;
    private readonly System.Diagnostics.Stopwatch fillClock = new();
    private TimeSpan fillLast;
    private double fillShown;
    private bool fillFinishing;
    private static double expectedSeconds = 20;   // learned from the last finished test, this session only

    private void StartFill()
    {
        StopFillTimer();
        fillShown = 0;
        fillFinishing = false;
        PaintFill();
        fillClock.Restart();
        fillLast = TimeSpan.Zero;
        fillTimer = new Avalonia.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(16) };
        fillTimer.Tick += (_, _) => TickFill();
        fillTimer.Start();
    }

    /// <summary>Where the clock says the fill should be: linear to 96 % at the expected time, then an ever-slower creep.</summary>
    private double FillTarget(double seconds)
    {
        var p = seconds / expectedSeconds;
        if (p <= 1)
            return 0.96 * p;
        return 0.96 + 0.035 * (1 - Math.Exp(-(p - 1) * 1.5));   // approaches 99.5 %, never arrives on its own
    }

    private void TickFill()
    {
        var now = fillClock.Elapsed;
        var dt = Math.Min((now - fillLast).TotalSeconds, 0.1);
        fillLast = now;
        var target = fillFinishing ? 1 : FillTarget(now.TotalSeconds);
        var tau = fillFinishing ? 0.12 : 0.35;   // seconds: how softly the fill follows its target (soft start, no steps)
        var next = Motion.Reduced ? target : fillShown + (target - fillShown) * (1 - Math.Exp(-dt / tau));
        fillShown = Math.Max(fillShown, next);
        PaintFill();
    }

    private void PaintFill()
    {
        // A scale, not a width: changing Width re-ran layout for the whole page 60 times a second.
        if (StopFill.RenderTransform is Avalonia.Media.ScaleTransform scale)
            scale.ScaleX = Math.Clamp(fillShown, 0, 1);
    }

    /// <summary>Eases the fill to 100 % (about a third of a second) so the result never cuts it off.</summary>
    private async Task FinishFillAsync()
    {
        fillFinishing = true;
        expectedSeconds = Math.Clamp(fillClock.Elapsed.TotalSeconds, 8, 60);   // the next test's clock fits this one
        var waited = 0;
        while (fillShown < 0.995 && waited < 700 && fillTimer is not null)
        {
            await Task.Delay(16);
            waited += 16;
        }
        fillShown = 1;
        PaintFill();
        await Task.Delay(Motion.Reduced ? 0 : 120);   // a beat at 100 %
        StopFillTimer();
    }

    private void StopFillTimer()
    {
        fillTimer?.Stop();
        fillTimer = null;
    }

    // ---------- result ----------

    private void ShowResult(DnsBenchmarkResult r)
    {
        var winner = r.Winner;
        var current = r.Current;
        var ratio = current?.TypicalMs is { } now && winner?.TypicalMs is { } best && best > 0 ? now / best : (double?)null;
        // Faster only beyond normal wobble across the three passes (P8), not by a 1 ms fluke.
        var privateNow = DnsSwitcher.ReadPrivateState();
        // P11: the current DNS wins but isn't private yet, and its provider offers encryption.
        var makePrivate = (!r.WinnerIsMeaningfullyFaster || winner is null) && current?.Server.SupportsEncryption == true &&
            privateNow is PrivateState.Off or PrivateState.Partly;
        if (!r.WinnerIsMeaningfullyFaster || winner is null)
        {
            ResultTitle.Text = "Your DNS is already a great choice";
            if (makePrivate)
                SetLine(Tone.Fair, "Quick, but your lookups aren't private yet");
            else if (privateNow == PrivateState.On)
                SetLine(Tone.Good, "Quick and private");
            else
                SetLine(Tone.Good, "Nothing tested was meaningfully faster");
        }
        else
        {
            ResultTitle.Text = $"{winner.Server.Name} is your fastest DNS";
            SetLine(Tone.Good, ratio is { } x
                ? $"Lookups about {x.ToString(x < 10 ? "0.#" : "0", CultureInfo.CurrentCulture)}× quicker than now"
                : "The quickest and steadiest server we tested");
        }
        var offer = winner is not null && r.WinnerIsMeaningfullyFaster || makePrivate;
        UseButton.Content = makePrivate ? "Make My DNS Private" : winner is null ? "Switch" : $"Switch to {winner.Server.Name}";
        UseButton.Theme = (Avalonia.Styling.ControlTheme)Application.Current!.FindResource("NcPrimaryButton")!;
        // Installed: the button, with "You can switch back any time" as its tooltip. Portable: one short line + Install.
        UseButton.IsVisible = offer && DnsSwitcher.IsAvailable;
        UseNote.IsVisible = offer && !DnsSwitcher.IsAvailable;
        UseButton.IsEnabled = DnsSwitcher.IsAvailable;
        ToolTip.SetTip(UseButton, "You can switch back any time.");
        ToolTip.SetTip(ResultLinePanel, null);
        primaryAction = makePrivate ? MakePrivateAsync : SwitchToWinnerAsync;
        if (DnsSwitcher.IsAvailable && UseButton.IsVisible && (makePrivate ? current : winner) is { } target)
            StartSecondTiming(target.Server);
        if (UseNote.IsVisible)
            useInstall.Show("Switching needs the installed app");
        else
            useInstall.Hide();

        BuildPodium(r.Ranked.Take(3).ToArray());
        BuildCompare(current, makePrivate ? current : winner, privateNow, makePrivate);
        BuildAll(r);
        Show(ResultView);
        AgainButton.Focus();
    }

    private void SetLine(Tone tone, string text)
    {
        ResultDot.Fill = ToneBrush(tone);
        ResultLine.Text = text;
        // Neutral facts read as plain text with a grey dot, not as a grey (or yellow) warning.
        ResultLine.Foreground = tone == Tone.Neutral ? Brush("InkBrush") : ToneBrush(tone);
    }

    /// <summary>Calm density: one row per server — rank, name, typical lookup. No stacked captions.</summary>
    private void BuildPodium(DnsServerResult[] top)
    {
        Podium.Children.Clear();
        for (var i = 0; i < top.Length; i++)
        {
            var s = top[i];
            var rank = new Border
            {
                // A bit bigger top 3 (user, 2026-11-17): badge 30, name 21, time 34, taller rows.
                Width = 30, Height = 30, CornerRadius = new CornerRadius(15), VerticalAlignment = VerticalAlignment.Center,
                Background = Brush(i == 0 ? "AccentSoftBrush" : "Surface2Brush"),
                Child = new TextBlock
                {
                    Text = (i + 1).ToString(CultureInfo.CurrentCulture), FontSize = 17, FontWeight = FontWeight.SemiBold,
                    Foreground = Brush(i == 0 ? "AccentBrush" : "Ink2Brush"),
                    HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
                },
            };
            // Two rows (user, 2026-11-17: "1 Yours (OpenDNS)" was cut): the provider gets the whole first line; a small
            // second line says "Your DNS now" for the current server, otherwise its address.
            // A bracketed part ("Quad9 (no filter)") moves to the small line, and a long name may wrap, so a name is
            // never cut (seen: "Quad9 (no filt…" with ~170 px beside the badge and the time).
            var (title, extra) = PodiumName(ProviderName(s.Server));
            var qualifier = s.Server.IsCurrent ? "Your DNS now" : s.Server.Address;
            var name = new StackPanel
            {
                VerticalAlignment = VerticalAlignment.Center, Spacing = 2,
                Children =
                {
                    new TextBlock { Text = title, FontSize = 21, TextWrapping = TextWrapping.Wrap, MaxLines = 2,
                        TextTrimming = TextTrimming.CharacterEllipsis },
                    new TextBlock { Text = extra is null ? qualifier : $"{extra} · {qualifier}", FontSize = 16,
                        Foreground = Brush("Ink3Brush"), TextTrimming = TextTrimming.CharacterEllipsis },
                },
            };
            var value = Number(s.TypicalMs, 34);
            value.VerticalAlignment = VerticalAlignment.Center;
            ((TextBlock)value.Children[1]).Margin = new Thickness(0, 0, 0, 5);
            // The best time reads green against the others in plain white (user, 2026-11-16).
            ((TextBlock)value.Children[0]).Foreground = Brush(i == 0 ? "GoodBrush" : "InkBrush");
            ToolTip.SetTip(value, "Typical lookup");
            var row = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"), ColumnSpacing = 14 };
            Grid.SetColumn(name, 1);
            Grid.SetColumn(value, 2);
            row.Children.Add(rank);
            row.Children.Add(name);
            row.Children.Add(value);
            var cell = new Netcheck.Controls.Divided
            {
                Padding = new Thickness(24, 16),
                Lines = new Thickness(i == 0 ? 0 : 1, 0, 0, 0), Child = row,
            };
            Grid.SetColumn(cell, i);
            Podium.Children.Add(cell);
        }
    }

    private void BuildCompare(DnsServerResult? now, DnsServerResult? best, PrivateState privateNow, bool makePrivate)
    {
        Compare.Children.Clear();
        Compare.RowDefinitions.Clear();
        var nowName = "Now";
        var bestName = makePrivate ? "After" : best is null ? "Fastest" : $"With {best.Server.Name}";
        // P11: the real state now (read from Windows), and what switching gives (encrypted only when offered).
        var privateNowText = privateNow switch
        {
            PrivateState.On => "On", PrivateState.Off => "Off", PrivateState.Partly => "Partly", _ => "Couldn't check",
        };
        var privateAfter = best is null ? (bool?)null : makePrivate || best.Server.SupportsEncryption;
        var privateAfterText = privateAfter switch { true => "On", false => "Not offered", null => "—" };
        var privateTone = (privateNow, privateAfter) switch
        {
            (not PrivateState.On, true) => "GoodBrush",
            (PrivateState.On, false) => "FairBrush",
            _ => "InkBrush",
        };
        string Time(double? ms) => ms is { } v ? $"{Ms(v)} ms" : "—";
        string Fail(DnsServerResult? s) => s is { Sent: > 0 } ? $"{s.Failed} of {s.Sent}" : "—";
        (string Label, string Now, string Best, string Tone, string? Meaning)[] rows =
        [
            ("", nowName, bestName, "InkBrush", null),
            ("Typical lookup", Time(now?.TypicalMs), Time(best?.TypicalMs), TimeTone(now?.TypicalMs, best?.TypicalMs),
                "Popular and new websites together. Lower is quicker."),
            ("New websites", Time(now?.FreshMs), Time(best?.FreshMs), TimeTone(now?.FreshMs, best?.FreshMs), null),
            ("Slowest lookups", Time(now?.SlowestMs), Time(best?.SlowestMs), TimeTone(now?.SlowestMs, best?.SlowestMs), null),
            ("Failed lookups", Fail(now), Fail(best), FailTone(now, best), null),
            ("Private lookups", privateNowText, privateAfterText, privateTone,
                "Your lookups are encrypted, so your internet provider and others on your network can't read which sites you look up. Speed stays about the same."),
            // Safety (P9): information only, never part of the ranking.
            ("Blocks fake answers", YesNo(now, now?.BlocksFakeAnswers), YesNo(best, best?.BlocksFakeAnswers),
                SafetyTone(now?.BlocksFakeAnswers, best?.BlocksFakeAnswers), "Stops replies that could send you to a fake site"),
            ("Guards home devices", YesNo(now, now?.GuardsHomeDevices), YesNo(best, best?.GuardsHomeDevices),
                SafetyTone(now?.GuardsHomeDevices, best?.GuardsHomeDevices), "Keeps websites away from your router and printer"),
        ];
        for (var i = 0; i < rows.Length; i++)
        {
            // Every row the same height (design rules); explanations sit behind an (i), never on a second line.
            Compare.RowDefinitions.Add(new RowDefinition(new GridLength(i == 0 ? 38 : 42)));
            var header = i == 0;
            if (!header)
            {
                // One divider across the whole row (not one per column), so it fades only near the card's edges.
                var line = new Netcheck.Controls.Divided { Lines = new Thickness(0, 1, 0, 0), IsHitTestVisible = false };
                Grid.SetRow(line, i);
                Grid.SetColumnSpan(line, 3);
                Compare.Children.Add(line);
            }
            for (var c = 0; c < 3; c++)
            {
                var text = c == 0 ? rows[i].Label : c == 1 ? rows[i].Now : rows[i].Best;
                var cell = new Border
                {
                    Padding = new Thickness(24, 0),
                    Child = new TextBlock
                    {
                        Text = text, FontSize = header ? 17 : 18,
                        Foreground = Brush(header || c == 0 ? "Ink2Brush" : c == 1 ? "Ink2Brush" : rows[i].Tone),
                        FontWeight = !header && c == 2 ? FontWeight.SemiBold : FontWeight.Normal,
                        VerticalAlignment = VerticalAlignment.Center,
                    },
                };
                if (c == 0 && rows[i].Meaning is { } meaning && cell.Child is { } label)
                {
                    cell.Child = null;   // detach before re-parenting the label
                    cell.Child = new StackPanel
                    {
                        Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center,
                        Children = { label, new Netcheck.Controls.InfoMark(meaning) },
                    };
                }
                Grid.SetRow(cell, i);
                Grid.SetColumn(cell, c);
                Compare.Children.Add(cell);
            }
        }
    }

    /// <summary>
    /// Colour of a "With …" time against "Now" (user's choice, P8): better = green, a bit worse = yellow, much worse
    /// = red. Differences inside normal run-to-run wobble (2 ms or 10 %, whichever is larger) stay plain.
    /// </summary>
    internal static string TimeTone(double? now, double? with)
    {
        if (now is not { } n || with is not { } w)
            return "InkBrush";
        var diff = w - n;
        if (Math.Abs(diff) <= Math.Max(2, 0.10 * n))
            return "InkBrush";
        return diff < 0 ? "GoodBrush" : diff <= 0.25 * n ? "FairBrush" : "PoorBrush";
    }

    private static string YesNo(DnsServerResult? server, bool? value) =>
        server is null ? "—" : value switch { true => "Yes", false => "No", null => "Couldn't check" };

    /// <summary>
    /// Safety rows: green when the new DNS adds the protection, yellow when it drops it (never red: most big public
    /// DNS services don't guard home devices), plain when the same, grey when it couldn't be checked.
    /// </summary>
    internal static string SafetyTone(bool? now, bool? with) => (now, with) switch
    {
        (_, null) => "NeutralBrush",
        (false, true) => "GoodBrush",
        (true, false) => "FairBrush",
        _ => "InkBrush",
    };

    /// <summary>Fewer failed lookups = green; one or two more = yellow; more than that = red.</summary>
    internal static string FailTone(DnsServerResult? now, DnsServerResult? with)
    {
        if (now is not { Sent: > 0 } n || with is not { Sent: > 0 } w)
            return "InkBrush";
        var diff = w.Failed - n.Failed;
        return diff < 0 ? "GoodBrush" : diff == 0 ? "InkBrush" : diff <= 2 ? "FairBrush" : "PoorBrush";
    }

    private void BuildAll(DnsBenchmarkResult r)
    {
        AllRows.Children.Clear();
        var ordered = r.Ranked.Concat(r.Servers.Where(s => !r.Ranked.Contains(s))).ToArray();
        var now = r.Current?.TypicalMs;
        for (var i = 0; i < ordered.Length; i++)
        {
            var s = ordered[i];
            // The typical time in its own column, coloured against your DNS now with the comparison table's rule
            // (user, 2026-11-17); failed lookups red when any failed; the rest of the line stays plain.
            var details = new TextBlock { FontSize = 17, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center,
                Foreground = Brush("Ink2Brush") };
            Control typical;
            if (s.Finalist)
            {
                typical = Number(s.TypicalMs, 26);
                if (!s.Server.IsCurrent)
                    ((TextBlock)((StackPanel)typical).Children[0]).Foreground = Brush(TimeTone(now, s.TypicalMs));
                details.Inlines!.Add(new Run($"new websites {Ms(s.FreshMs ?? 0)} · popular {Ms(s.CachedMs ?? 0)} · slowest {Ms(s.SlowestMs ?? 0)} ms · "));
                details.Inlines.Add(new Run($"{s.Failed} of {s.Sent} failed") { Foreground = Brush(s.Failed > 0 ? "PoorBrush" : "Ink2Brush") });
                if (s.Redirects > 0)
                    details.Inlines.Add(new Run(" · redirects missing sites") { Foreground = Brush("PoorBrush") });
            }
            else
            {
                typical = new TextBlock { Text = "—", FontSize = 26, FontWeight = FontWeight.Light, Foreground = Brush("Ink3Brush"),
                    VerticalAlignment = VerticalAlignment.Center };
                details.Text = s.QuickMs is { } q ? $"Quick test {Ms(q)} ms · not in the top {Math.Min(5, r.Ranked.Count)}" : "Didn't answer";
            }
            typical.VerticalAlignment = VerticalAlignment.Center;
            var row = new Grid { ColumnDefinitions = new ColumnDefinitions("230,110,*"), ColumnSpacing = 20, Margin = new Thickness(24, 8) };
            var name = new StackPanel
            {
                VerticalAlignment = VerticalAlignment.Center,
                Children =
                {
                    new TextBlock { Text = s.Server.Name, FontSize = 18, FontWeight = s.Server.IsCurrent ? FontWeight.SemiBold : FontWeight.Normal,
                        TextTrimming = TextTrimming.CharacterEllipsis },
                    new TextBlock { Text = s.Server.Address, FontSize = 16, Foreground = Brush("Ink3Brush") },
                },
            };
            Grid.SetColumn(typical, 1);
            Grid.SetColumn(details, 2);
            row.Children.Add(name);
            row.Children.Add(typical);
            row.Children.Add(details);
            AllRows.Children.Add(new Netcheck.Controls.Divided { Child = row,
                Lines = new Thickness(0, i == 0 ? 0 : 1, 0, 0) });
        }
    }

    // ---------- helpers ----------

    private static StackPanel Number(double? ms, double size) => new()
    {
        Orientation = Orientation.Horizontal, Spacing = 4,
        Children =
        {
            new TextBlock { Text = ms is { } v ? Ms(v) : "—", FontSize = size, FontWeight = FontWeight.Light, LetterSpacing = -0.8 },
            new TextBlock { Text = "ms", FontSize = 17, Foreground = Brush("Ink3Brush"), VerticalAlignment = VerticalAlignment.Bottom,
                Margin = new Thickness(0, 0, 0, 6) },
        },
    };

    private static string Ms(double ms) => ms.ToString(ms < 10 ? "0.#" : "0", CultureInfo.CurrentCulture);

    private static IBrush Brush(string key) =>
        ThemeManager.Brush(key);

    private static IBrush ToneBrush(Tone tone)
    {
        // The shared resource brush itself, so a theme switch can swap it for the other theme\'s copy.
        return Brush(tone switch { Tone.Good => "GoodBrush", Tone.Fair => "FairBrush", Tone.Poor => "PoorBrush", _ => "NeutralBrush" });
    }
}
