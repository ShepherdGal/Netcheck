using System.Globalization;
using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Shapes;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Netcheck.Controls;
using Netcheck.Core;
using Netcheck.Measurements.Check;

namespace Netcheck.Pages;

/// <summary>
/// Check tab (Dusk instrument cluster, v2): idle → running (live gauges, stage in the title) →
/// result (one-line verdict, settled gauges with meanings, readings strip), with the live Network activity card below.
/// One button per state. "How This Check Works" opens from Settings.
/// </summary>
public sealed partial class CheckPage : UserControl
{
    private static readonly string[] StageTitles = ["Measuring ping", "Measuring download", "Measuring upload", "Counting lost pings"];

    private readonly SmoothValue down, up;
    private static SpeedUnit preference => UiPreferences.Current.SpeedUnit;
    private SpeedUnit? downUnit, upUnit;
    private CancellationTokenSource? run;
    private InternetCheckResult? last;
    private ConnectionInfo connection = ConnectionInfo.Unknown;
    // What the DNS box and details describe: this PC now, or what was recorded with a saved check.
    private ConnectionInfo shownConnection = ConnectionInfo.Unknown;
    private HistoryItem? opened;
    private Assessed? dnsLookup;
    private CheckSummary? shown;
    private string pending = "Not checked yet";
    // While a check runs: the stage being measured, so unfinished readings can breathe (design rules "alive but calm").
    private CheckStage? liveStage;
    private readonly List<Control> stripValues = [];

    public CheckPage()
    {
        InitializeComponent();
        down = new SmoothValue(v => ShowGauge(v, upload: false));
        up = new SmoothValue(v => ShowGauge(v, upload: true));
        StartButton.Click += async (_, _) => await RunAsync();
        AgainButton.Click += async (_, _) => await RunAsync();
        StopButton.Click += (_, _) => run?.Cancel();
        BackButton.Click += (_, _) => ShowDetails(false);

        if (!Motion.Reduced)
        {
            DoubleTransition Fade() => new() { Property = OpacityProperty, Duration = TimeSpan.FromMilliseconds(420), Easing = Motion.EaseOut };
            DownMeaning.Transitions = [Fade()];
            UpMeaning.Transitions = [Fade()];
        }
        Activity.Format = Rate;
        ShowIdle();
        _ = ReadConnectionAsync();
        AttachedToVisualTree += (_, _) => RefreshUnits();
    }

    /// <summary>Settings may have changed the speed units while this page was hidden: redraw values in the new units.</summary>
    private void RefreshUnits()
    {
        if (run is not null)
            return;
        downUnit = upUnit = null;
        ShowGauge(shown?.Download.Value ?? 0, upload: false);
        ShowGauge(shown?.Upload.Value ?? 0, upload: true);
        if (last is not null && shown is not null)
            BuildFacts(last, shown);
    }

    // ---------- states ----------

    private void SetActions(params Button[] visible)
    {
        foreach (var button in new[] { StartButton, StopButton, AgainButton })
            button.IsVisible = visible.Contains(button);
    }

    /// <summary>Header = title + at most one line (verdict or short lead).</summary>
    private void SetHeader(string title, string lead = "", Verdict? verdict = null)
    {
        Title.Text = title;
        Sub.Text = lead;
        Sub.IsVisible = lead.Length > 0;
        VerdictLine.IsVisible = verdict is not null;
        if (verdict is null)
            return;
        VerdictDot.Fill = ToneBrush(verdict.Tone);
        VerdictText.Text = verdict.Headline;
        VerdictText.Foreground = verdict.Tone == Tone.Neutral ? Brush("InkBrush") : ToneBrush(verdict.Tone);
    }

    private void ShowIdle()
    {
        SetHeader("How's Your Internet?", "Speed, ping and stability in about 30 seconds.");
        SetActions(StartButton);
        opened = null;
        shownConnection = connection;
        down.Reset();
        up.Reset();
        Waiting("Not checked yet");
    }

    /// <summary>Gauges and strip before a result: values "—", neutral meanings.</summary>
    private void Waiting(string meaning)
    {
        pending = meaning;
        shown = null;
        var waiting = new Assessed(null, Tone.Neutral, meaning);
        Meaning(DownDot, DownMeaningText, waiting);
        Meaning(UpDot, UpMeaningText, waiting);
        BuildStrip(null);
    }

    private async Task RunAsync()
    {
        if (run is not null)
            return;
        run = new CancellationTokenSource();
        ShowDetails(false);
        opened = null;
        shownConnection = connection;
        SetHeader(StageTitles[0], Over());
        SetActions(StopButton);
        downUnit = upUnit = null;
        down.Reset();
        up.Reset();
        dnsLookup = null;
        liveStage = CheckStage.Ping;
        Waiting("Checking…");
        SetStage(0);
        StopButton.Focus();
        _ = ReadConnectionAsync();

        var stage = CheckStage.Ping;
        var progress = new Progress<CheckProgress>(p =>
        {
            if (run is null)
                return;
            if (p.Stage != stage)
            {
                stage = p.Stage;
                SetStage((int)p.Stage);
            }
            if (p.LiveMbps is { } mbps)
                (p.Stage == CheckStage.Upload ? up : down).Set(mbps);
        });

        InternetCheckResult result;
        try
        {
            result = await new InternetCheckEngine().RunAsync(Options(), progress, run.Token);
        }
        catch (Exception error) when (error is HttpRequestException or IOException or InvalidOperationException)
        {
            result = new InternetCheckResult(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, false,
                new LatencyReading(StageOutcome.Failed, [], 0), null, null, null, null, [error.Message]);
        }
        finally
        {
            run.Dispose();
            run = null;
            liveStage = null;
        }

        last = result;
        if (result.Stopped && result.Download is null)
        {
            ShowIdle();
            StartButton.Focus();
            return;
        }
        ShowResult(result);
    }

    /// <summary>Starts a check (History's empty state). Does nothing while one is running.</summary>
    internal Task StartAsync() => RunAsync();

    /// <summary>Shows a check saved in History (from the History tab's Open). Nothing is measured or saved again.</summary>
    internal void ShowSaved(HistoryItem item)
    {
        if (run is not null)
            return;
        ShowDetails(false);
        last = item.Result;
        ShowResult(item.Result, item);
    }

    private void ShowResult(InternetCheckResult result, HistoryItem? from = null)
    {
        var s = CheckAssessment.Summarize(result);
        opened = from;
        shownConnection = from is null ? connection : new ConnectionInfo(from.Kind ?? "", true, from.DnsName ?? "", from.DnsAddress ?? "");
        // Header stays at two lines: the title and the coloured verdict. Times and details live elsewhere.
        SetHeader(from is null ? "Your Internet Connection" : $"Your check from {Dates.When(from.Ended).Replace("Today", "today").Replace("Yesterday", "yesterday")}", verdict: s.Verdict);

        SetActions(AgainButton);

        // Gauges glide from their live values to the final results, then the meanings fade in.
        down.Set(s.Download.Value ?? 0);
        up.Set(s.Upload.Value ?? 0);
        Meaning(DownDot, DownMeaningText, s.Download);
        Meaning(UpDot, UpMeaningText, s.Upload);

        // The earlier version timed DNS through the Windows cache, so its number isn't rated with today's rules.
        dnsLookup = from is { Earlier: false, DnsLookupMs: { } savedMs } ? CheckAssessment.DnsLookup(savedMs) : null;
        shown = s;
        liveStage = null;
        BuildStrip(s);
        if (from is null)
            RevealStrip();
        BuildFacts(result, s);
        AgainButton.Focus();
        if (from is null)
            _ = TimeDnsAsync(result, s);
    }

    /// <summary>A few popular-name lookups to the DNS Windows uses (well under 1 KB), then the DNS box shows the result.</summary>
    private async Task TimeDnsAsync(InternetCheckResult result, CheckSummary s)
    {
        // Timed the way Windows reaches it: over HTTPS when private lookups are on (P12b).
        var address = connection.DnsAddress;
        var template = await Task.Run(() => DnsSwitcher.HttpsTemplateFor(address));
        var ms = await new Netcheck.Measurements.Resolvers.DnsBenchmarkEngine().QuickLookupAsync(address, CancellationToken.None,
            httpsTemplate: template);
        if (last != result || shown != s)
            return;   // a newer check started meanwhile
        dnsLookup = CheckAssessment.DnsLookup(ms);
        BuildStrip(s);
        BuildFacts(result, s);
        // Saved once the DNS timing is in, so History can compare it too.
        _ = CheckHistory.SaveAsync(new Netcheck.Storage.CheckRecord(Guid.NewGuid(), result, connection.Kind,
            connection.DnsName, connection.DnsAddress, dnsLookup.Value));
    }

    /// <summary>True once a check has finished, so Settings can offer "How the last check was measured".</summary>
    internal bool HasResult => last is not null && !(last.Stopped && last.Download is null);

    /// <summary>Opens the measurement details of the last check (from Settings).</summary>
    internal void OpenDetails()
    {
        if (HasResult)
            ShowDetails(true);
    }

    private void ShowDetails(bool show)
    {
        if (DetailView.IsVisible == show)
            return;
        ClusterView.IsVisible = !show;
        DetailView.IsVisible = show;
        Motion.EnterPage(show ? DetailView : ClusterView);
        if (show)
            BackButton.Focus();
    }

    private void OpenDns() => (TopLevel.GetTopLevel(this) as MainWindow)?.Navigate("dns");

    // ---------- running ----------

    private void SetStage(int active)
    {
        Title.Text = StageTitles[active];
        if (run is null)
            return;
        liveStage = (CheckStage)active;
        BuildStrip(null);   // the breathing dots follow the stage
    }

    /// <summary>What an unfinished reading says while a check runs, and whether it is being measured right now.</summary>
    private (string Text, bool Active)? Live(string name) => liveStage switch
    {
        null => null,
        CheckStage.Ping when name == "Ping loss" => ("Waiting…", false),
        CheckStage.Ping => ("Measuring…", true),
        CheckStage.PingLoss when name == "Ping loss" => ("Counting lost pings…", true),
        CheckStage.PingLoss => ("Finishing…", true),
        _ when name == "Ping loss" => ("Waiting…", false),
        _ => ("In a moment…", false),
    };

    private string Over() => connection.Kind.Length > 0 ? $"Over {connection.Kind}" : "";

    /// <summary>A traffic rate in the user's speed units (Mbps or MB/s, with kbps / kB/s for small amounts).</summary>
    private string Rate(double mbps)
    {
        var unit = SpeedUnits.Resolve(preference, Math.Max(mbps, 1e-6));
        // Never smaller than kbps / kB/s: single bits per second read as noise, not information.
        unit = unit switch { SpeedUnit.BitsPerSecond => SpeedUnit.KilobitsPerSecond, SpeedUnit.BytesPerSecond => SpeedUnit.KilobytesPerSecond, _ => unit };
        return SpeedUnits.Format(Math.Max(0, mbps), unit);
    }

    private void ShowGauge(double mbps, bool upload)
    {
        var gauge = upload ? UpGauge : DownGauge;
        gauge.Value = mbps <= 0 ? 0 : SpeedGaugeScale.Position(mbps, upload);
        ref var unit = ref upload ? ref upUnit : ref downUnit;
        // With no value (idle, failed, not reached) show the default unit, not one left over from a tiny early reading.
        unit = mbps <= 0 ? SpeedUnits.Resolve(preference, null) : SpeedUnits.Resolve(preference, mbps, unit);
        (upload ? UpValue : DownValue).Text = mbps <= 0 ? "—" : SpeedUnits.FormatNumber(mbps, unit.Value);
        (upload ? UpUnit : DownUnit).Text = SpeedUnits.Label(unit.Value);
    }

    // ---------- result ----------

    private static void Meaning(Ellipse dot, TextBlock text, Assessed a)
    {
        dot.Fill = ToneBrush(a.Tone);
        text.Foreground = ToneBrush(a.Tone);
        text.Text = a.Meaning;
    }

    /// <summary>The readings strip; with no summary yet every box shows "—" and the waiting meaning.</summary>
    private void BuildStrip(CheckSummary? s)
    {
        string Percent(double v) => v == 0 ? "0" : v.ToString(v < 1 ? "0.##" : "0.#", CultureInfo.CurrentCulture);
        var waiting = new Assessed(null, Tone.Neutral, pending);
        stripValues.Clear();
        Border[] boxes =
        [
            DnsBox(s is not null),
            Box("Ping", s?.Ping ?? waiting, v => (Ms(v), "ms"), "ms"),
            Box("Jitter", s?.Jitter ?? waiting, v => (Ms(v), "ms"), "ms"),
            Box("Ping loss", s?.Loss ?? waiting, v => (Percent(v), "%"), "%"),
        ];
        StripGrid.Children.Clear();
        for (var i = 0; i < boxes.Length; i++)
        {
            Grid.SetColumn(boxes[i], i);
            boxes[i].BorderThickness = new Thickness(i == 0 ? 0 : 1, 0, 0, 0);
            StripGrid.Children.Add(boxes[i]);
        }
    }

    private Border Box(string name, Assessed a, Func<double, (string Value, string Unit)> format, string unitWhenEmpty)
    {
        var (value, unit) = a.Value is { } v ? format(v) : ("—", unitWhenEmpty);
        var live = a.Value is null ? Live(name) : null;
        var reading = new StackPanel
        {
            Orientation = Orientation.Horizontal, Spacing = 4,
            Children =
            {
                new TextBlock { Text = value, FontSize = 36, FontWeight = FontWeight.Light, LetterSpacing = -0.8,
                    Foreground = live is not null ? Brush("Ink3Brush") : Brush("InkBrush") },
                new TextBlock { Text = unit, FontSize = 17, Foreground = Brush("Ink3Brush"),
                    VerticalAlignment = VerticalAlignment.Bottom, Margin = new Thickness(0, 0, 0, 6) },
            },
        };
        stripValues.Add(reading);
        // The reading and its meaning are centred in the cell; the label sits top-left like "DNS" (user, 2026-11-17).
        var meaning = live is { } l ? LiveDot(l.Text, l.Active) : Dot(a.Tone, a.Meaning);
        reading.HorizontalAlignment = meaning.HorizontalAlignment = HorizontalAlignment.Center;
        return Cell(LabelRow(Label(name)), reading, meaning);
    }

    /// <summary>DNS box: same three rows as the others; "Find a Faster DNS" is a link on the label row.</summary>
    private Border DnsBox(bool checkedNow)
    {
        var find = new Button { Theme = (Avalonia.Styling.ControlTheme)Resource("NcLinkButton"), Content = "Find a Faster DNS",
            Padding = new Thickness(0), FontSize = 17, FontWeight = FontWeight.SemiBold, VerticalAlignment = VerticalAlignment.Center };
        find.Click += (_, _) => OpenDns();
        var header = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), ColumnSpacing = 12 };
        Grid.SetColumn(find, 1);
        header.Children.Add(Label("DNS"));
        header.Children.Add(find);
        // The label and link stay at the sides; the name and its reading are centred like the other cells.
        var name = new TextBlock { Text = shownConnection.DnsName.Length > 0 ? shownConnection.DnsName : opened is not null ? "—" : "Unknown", FontSize = 36,
            FontWeight = FontWeight.Light, LetterSpacing = -0.8, TextTrimming = TextTrimming.CharacterEllipsis,
            HorizontalAlignment = HorizontalAlignment.Center };
        var meaning = dnsLookup is { Value: { } ms } a ? Dot(a.Tone, $"{Ms(ms)} ms · {a.Meaning}")
            : dnsLookup is { } failed ? Dot(failed.Tone, failed.Meaning)
            : opened is null && checkedNow ? LiveDot("Timing lookups…", true)
            : Dot(Tone.Neutral, opened is not null ? "Not recorded" : "Speed not timed yet");
        meaning.HorizontalAlignment = HorizontalAlignment.Center;
        return Cell(LabelRow(header), name, meaning);
    }

    private Border Cell(params Control[] rows)
    {
        var stack = new StackPanel { Spacing = 1 };
        foreach (var row in rows)
            stack.Children.Add(row);
        return new Border { Padding = new Thickness(24, 16), BorderBrush = Brush("LineBrush"), Child = stack };
    }

    private static TextBlock Label(string text) =>
        new() { Text = text, FontSize = 18, Foreground = Brush("Ink2Brush"), VerticalAlignment = VerticalAlignment.Center };

    /// <summary>
    /// Every cell's label row has the same fixed height, so "DNS · Find a Faster DNS" (a link is taller than plain text)
    /// sits on the same line as Ping, Jitter and Ping loss (user, 2026-11-17).
    /// </summary>
    private static Panel LabelRow(Control content)
    {
        content.VerticalAlignment = VerticalAlignment.Center;
        if (content is Grid grid)
            foreach (var child in grid.Children)
                child.VerticalAlignment = VerticalAlignment.Center;
        return new Panel { Height = 24, Children = { content } };
    }

    /// <summary>
    /// An unfinished reading (user, 2026-11-17): three dots on a soft spring until its result arrives, whether it is
    /// measured now or later in the check. Same height as a text line, so the cell doesn't move when the result
    /// arrives. The words ("Measuring…", "Waiting…") are kept for screen readers.
    /// </summary>
    private static Control LiveDot(string text, bool active) =>
        new Panel { Height = 21, Children = { new Netcheck.Controls.SpringWave(text) } };

    /// <summary>The finished numbers ease in one after another (about half a second each, 120 ms apart).</summary>
    private void RevealStrip()
    {
        if (Motion.Reduced)
            return;
        var delay = 0;
        foreach (var value in stripValues.ToArray())
        {
            value.Opacity = 0;
            var wait = delay;
            DispatcherTimer.RunOnce(() =>
            {
                value.Transitions = [new DoubleTransition { Property = OpacityProperty, Duration = TimeSpan.FromMilliseconds(520), Easing = Motion.EaseOut }];
                value.Opacity = 1;
            }, TimeSpan.FromMilliseconds(40 + wait));
            delay += 120;
        }
    }

    /// <summary>A reading's meaning in its status colour; no dot (user, 2026-11-17: the coloured words carry it).</summary>
    private static Control Dot(Tone tone, string text) =>
        new TextBlock { Text = text, FontSize = 17.5, FontWeight = FontWeight.SemiBold, Foreground = ToneBrush(tone),
            TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center };

    /// <summary>
    /// Eight short facts in one joined card (2 × 4), separated by hairlines like the result strip,
    /// so "How This Check Works" fits the window without scrolling.
    /// </summary>
    private void BuildFacts(InternetCheckResult r, CheckSummary s)
    {
        Facts.Children.Clear();
        void Tile(string name, string text)
        {
            var index = Facts.Children.Count;
            var cell = new Border
            {
                Padding = new Thickness(24, 12),
                BorderBrush = Brush("LineBrush"),
                BorderThickness = new Thickness(index % 2 == 0 ? 0 : 1, index < 2 ? 0 : 1, 0, 0),
                Child = new StackPanel
                {
                    Spacing = 3,
                    Children =
                    {
                        new TextBlock { Text = name, Classes = { "tileLabel" } },
                        new TextBlock { Text = text, Classes = { "tileText" } },
                    },
                },
            };
            Grid.SetColumn(cell, index % 2);
            Grid.SetRow(cell, index / 2);
            Facts.Children.Add(cell);
        }

        string Speed(double? mbps) => SpeedUnits.Format(mbps, SpeedUnits.Resolve(preference, mbps));
        string Transfer(SpeedReading? t, string how) => t switch
        {
            null => "Not measured.",
            { Outcome: StageOutcome.Failed } => $"Didn't finish: {t.Problem}",
            { Outcome: StageOutcome.Stopped } => "Stopped before it finished.",
            _ => $"{Speed(t.Mbps)} steady speed. {t.Bytes / 1e6:0} MB in {t.Elapsed.TotalSeconds:0.0} s over {t.Streams} connections" +
                 $"{(t.End == SpeedEnd.ByteCap ? ", stopped at the data limit" : "")}. {how}",
        };

        Tile("Download", Transfer(r.Download, "From Cloudflare's speed server."));
        Tile("Upload", Transfer(r.Upload, "Counted once the server confirmed it."));
        var targets = r.Loss?.Targets.Where(t => t.Reachable).Select(t => $"{t.Name} {Ms(t.MedianMs ?? 0)}") ?? [];
        Tile("Ping", s.PingFromIcmp
            ? $"{Ms(s.Ping.Value ?? 0)} ms typical reply ({string.Join(" · ", targets)} ms)."
            : s.Ping.Value is { } https ? $"{Ms(https)} ms from web requests; plain pings didn't run or were blocked." : "Not measured.");
        Tile("Jitter", s.Jitter.Value is { } j ? $"{Ms(j)} ms average change from one reply to the next." : "Not measured.");
        Tile("Ping loss", r.Loss is { } loss
            ? $"{loss.Sent - loss.Lost} of {loss.Sent} pings answered, {loss.Lost} lost." +
              (loss.Targets.Any(t => !t.Reachable && t.Sent > 0) ? " Servers that block pings aren't counted." : "")
            : "Not measured.");
        Tile("DNS", shownConnection.DnsName.Length > 0
            ? $"Windows uses {shownConnection.DnsName}{(shownConnection.DnsAddress.Length > 0 ? $" ({shownConnection.DnsAddress})" : "")}." +
              (dnsLookup?.Value is { } lookup ? $" A typical lookup takes {Ms(lookup)} ms (popular and new sites)." : "") +
              " The DNS tab compares it with others."
            : "Couldn't read the DNS server Windows uses.");
        Tile("Server response", r.Ping?.MedianMs is { } server
            ? $"{Ms(server)} ms for Cloudflare{(r.ServerLocation is { } colo ? $" ({colo})" : "")} to answer a tiny web request."
            : "The speed server didn't answer.");
        // Download/upload notes are already in their own tiles; keep only the rest (e.g. servers that block pings).
        var other = r.Notes.Where(n => !n.StartsWith("Download", StringComparison.Ordinal) && !n.StartsWith("Upload", StringComparison.Ordinal)
            && !n.Contains("didn't answer any pings", StringComparison.Ordinal)).ToArray();
        Tile("Notes", $"Rated with Netcheck rules {CheckAssessment.Version}; missing data is never rated." +
            (other.Length > 0 ? " " + string.Join(" ", other) : ""));
    }

    // ---------- helpers ----------

    private static string Ms(double ms) => ms.ToString(ms < 10 ? "0.#" : "0", CultureInfo.CurrentCulture);

    private static CheckOptions Options() =>
        // Development switch until Settings offers a lighter check: ~4 s per direction, < 100 MB.
        Environment.GetEnvironmentVariable("NETCHECK_LIGHT_CHECK") == "1"
            ? CheckOptions.Default with
            {
                DirectionDuration = TimeSpan.FromSeconds(4), DownloadByteCap = 60_000_000, UploadByteCap = 25_000_000,
                LossPingsPerTarget = 50,
            }
            : CheckOptions.Default;

    private async Task ReadConnectionAsync()
    {
        connection = await ConnectionInfo.ReadAsync();
        ActivitySub.Text = connection.Kind;
        ActivityKind.IsVisible = connection.Kind.Length > 0;
        if (opened is null)
            shownConnection = connection;
        if (run is not null)
            SetHeader(Title.Text ?? "", Over());
        BuildStrip(shown);   // the DNS box shows the server's name once it is known
    }

    private static object Resource(string key) =>
        Application.Current!.TryFindResource(key, out var value) ? value! : throw new InvalidOperationException(key);

    private static IBrush Brush(string key) => Resource(key) as IBrush ?? Brushes.Gray;

    private static IBrush ToneBrush(Tone tone)
    {
        var key = tone switch { Tone.Good => "GoodColor", Tone.Fair => "FairColor", Tone.Poor => "PoorColor", _ => "NeutralColor" };
        return new SolidColorBrush(Resource(key) is Color c ? c : Colors.Gray);
    }
}
