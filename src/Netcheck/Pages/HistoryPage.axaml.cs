using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Netcheck.Core;

namespace Netcheck.Pages;

/// <summary>History (P6): saved checks newest first; pick one to open it on Check, or two to compare.</summary>
public sealed partial class HistoryPage : UserControl
{
    private const int PerPage = 8;
    private const string Columns = "44,1.5*,0.9*,0.9*,0.6*,0.7*,0.8*,2.5*";   // Result wider: its sentence stays on one line (2026-11-17)
    private static readonly string BoostLastFile = AppPaths.Data("boost-last.json");

    private static SpeedUnit preference => UiPreferences.Current.SpeedUnit;
    private readonly List<Guid> picked = [];
    private IReadOnlyList<HistoryItem> items = [];
    private string? notice;
    private int page;

    public HistoryPage()
    {
        InitializeComponent();
        BuildHeader();
        NewerButton.Click += (_, _) => { page--; ShowList(); };
        OlderButton.Click += (_, _) => { page++; ShowList(); };
        GoButton.Click += (_, _) => Go();
        BackButton.Click += (_, _) => Show(ListView);
        EmptyButton.Click += (_, _) => (TopLevel.GetTopLevel(this) as MainWindow)?.StartCheck();
        AttachedToVisualTree += (_, _) => _ = ReloadAsync();
        CheckHistory.Changed += () => Dispatcher.UIThread.Post(() =>
        {
            if (TopLevel.GetTopLevel(this) is not null)
                _ = ReloadAsync();
        });
    }

    private async Task ReloadAsync()
    {
        (items, notice) = await CheckHistory.LoadAsync();
        picked.RemoveAll(id => items.All(i => i.Id != id));
        page = Math.Clamp(page, 0, Math.Max(0, (items.Count - 1) / PerPage));
        if (CompareView.IsVisible && picked.Count == 2)
            return;
        Show(items.Count == 0 ? EmptyView : ListView);
        if (items.Count == 0)
            EmptyLead.Text = notice ?? "Every check you run is saved here, so you can compare before and after a change.";
        else
            ShowList();
    }

    private void Show(Control view)
    {
        foreach (var v in new Control[] { ListView, CompareView, EmptyView })
            v.IsVisible = v == view;
        Motion.EnterPage(view);
        if (view == ListView && items.Count > 0)
            ShowList();
    }

    // ---------- list ----------

    private void BuildHeader()
    {
        HeaderRow.ColumnDefinitions = new ColumnDefinitions(Columns);
        string[] names = ["", "When", "Download", "Upload", "Ping", "Jitter", "Ping loss", "Result"];
        for (var i = 0; i < names.Length; i++)
        {
            var label = new TextBlock { Text = names[i], FontSize = 16, Foreground = Brush("Ink3Brush"), VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(label, i);
            HeaderRow.Children.Add(label);
        }
    }

    private void ShowList()
    {
        Rows.Children.Clear();
        var shown = items.Skip(page * PerPage).Take(PerPage).ToList();
        foreach (var item in shown)
            Rows.Children.Add(Row(item));
        var first = page * PerPage + 1;
        PageText.Text = $"{first}–{first + shown.Count - 1} of {items.Count}";
        NewerButton.IsEnabled = page > 0;
        OlderButton.IsEnabled = (page + 1) * PerPage < items.Count;
        GoButton.IsEnabled = picked.Count > 0;
        GoButton.Content = picked.Count == 1 ? "Open" : "Compare";
        Hint.Text = picked.Count switch { 0 => "Pick one or two", 1 => items.Count > 1 ? "Pick another to compare" : "", _ => "2 picked" };
        Lead.Text = notice ?? (items.Count == 1 ? "Run another check to compare." : "Pick one to open it, or two to compare.");
        Lead.Foreground = notice is null ? Brush("Ink2Brush") : ToneBrush(Tone.Fair);
    }

    private Control Row(HistoryItem item)
    {
        var s = item.Summary;
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions(Columns), Height = 53, Margin = new Thickness(24, 0) };
        var order = picked.OrderBy(id => items.First(i => i.Id == id).Ended).ToList();
        var number = order.IndexOf(item.Id);
        var selected = number >= 0;
        var pick = new Border
        {
            Width = 20, Height = 20, CornerRadius = new CornerRadius(10), BorderThickness = new Thickness(1.5),
            BorderBrush = selected ? Brush("AccentBrush") : Brush("OutlineBrush"),
            Background = selected ? Brush("AccentBrush") : Brushes.Transparent, HorizontalAlignment = HorizontalAlignment.Left,
            Child = new TextBlock
            {
                Text = selected ? (number + 1).ToString(CultureInfo.CurrentCulture) : "", FontSize = 14, FontWeight = FontWeight.SemiBold,
                Foreground = Brush("AccentInkBrush"), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
            },
        };
        var when = new StackPanel
        {
            VerticalAlignment = VerticalAlignment.Center,
            Children =
            {
                new TextBlock { Text = Dates.When(item.Ended), FontSize = 18 },
                new TextBlock { Text = item.Earlier ? "Earlier version" : item.Kind is { Length: > 0 } kind ? kind : "Connection not recorded",
                    FontSize = 16, Foreground = Brush("Ink3Brush") },
            },
        };
        var verdict = VerdictCell(s.Verdict.Tone, s.Verdict.Headline);
        Control[] cells =
        [
            pick, when,
            Value(Speed(s.Download.Value), item.Earlier), Value(Speed(s.Upload.Value), item.Earlier),
            Value(Ms(s.Ping.Value), item.Earlier), Value(Ms(s.Jitter.Value), item.Earlier),
            Value(s.Loss.Value is { } loss ? (Percent(loss), "%") : null, item.Earlier),
            verdict,
        ];
        for (var i = 0; i < cells.Length; i++)
        {
            Grid.SetColumn(cells[i], i);
            cells[i].VerticalAlignment = VerticalAlignment.Center;
            grid.Children.Add(cells[i]);
        }

        var row = new Border { Classes = { "row" }, Child = grid };
        row.Classes.Set("sel", selected);
        AutomationPropertiesName(row, $"{Dates.When(item.Ended)}, {s.Verdict.Headline}");
        row.PointerReleased += (_, e) =>
        {
            if (e.InitialPressMouseButton == MouseButton.Left)
                Toggle(item.Id);
        };
        row.KeyDown += (_, e) =>
        {
            if (e.Key is Key.Space or Key.Enter)
            {
                Toggle(item.Id);
                e.Handled = true;
            }
        };
        return new Border
        {
            BorderBrush = Brush("LineBrush"), BorderThickness = new Thickness(0, 1, 0, 0), Child = row,
        };
    }

    private void Toggle(Guid id)
    {
        if (!picked.Remove(id))
        {
            if (picked.Count == 2)
                picked.RemoveAt(0);
            picked.Add(id);
        }
        ShowList();
    }

    private void Go()
    {
        var chosen = picked.Select(id => items.First(i => i.Id == id)).OrderBy(i => i.Ended).ToList();
        if (chosen.Count == 1)
            (TopLevel.GetTopLevel(this) as MainWindow)?.OpenSavedCheck(chosen[0]);
        else if (chosen.Count == 2)
        {
            BuildCompare(chosen[0], chosen[1]);
            Show(CompareView);
            BackButton.Focus();
        }
    }

    // ---------- compare ----------

    private void BuildCompare(HistoryItem before, HistoryItem after)
    {
        CompareRows.Children.Clear();
        const string compareColumns = "1*,1.15*,1.15*,1.3*";
        var head = new Grid { ColumnDefinitions = new ColumnDefinitions(compareColumns), Height = 64, Margin = new Thickness(24, 0) };
        void Head(int column, string title, HistoryItem item)
        {
            var stack = new StackPanel
            {
                VerticalAlignment = VerticalAlignment.Center,
                Children =
                {
                    new TextBlock { Text = title, FontSize = 17, Foreground = Brush("Ink2Brush") },
                    new TextBlock { Text = $"{Dates.When(item.Ended)} · {(item.Earlier ? "Earlier version" : item.Kind ?? "")}".TrimEnd(' ', '·'),
                        FontSize = 16, Foreground = Brush("Ink3Brush"), TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(0, 0, 12, 0) },
                },
            };
            Grid.SetColumn(stack, column);
            head.Children.Add(stack);
        }
        Head(1, "Before", before);
        Head(2, "After", after);
        var changeLabel = new TextBlock { Text = "Change", FontSize = 16, Foreground = Brush("Ink3Brush"), VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(changeLabel, 3);
        head.Children.Add(changeLabel);
        CompareRows.Children.Add(head);

        var earlier = before.Earlier || after.Earlier;
        var rows = CheckComparison.Compare(before.Summary, before.DnsLookupMs, after.Summary, after.DnsLookupMs, earlier);
        foreach (var r in rows)
        {
            var grid = new Grid { ColumnDefinitions = new ColumnDefinitions(compareColumns), Height = 62, Margin = new Thickness(24, 0) };
            var name = new TextBlock { Text = r.Name, FontSize = 18, Foreground = Brush("Ink2Brush") };
            var (beforeValue, afterValue) = r.Unit == "Mbps"
                ? (Speed(r.Before), Speed(r.After))
                : r.Unit == "%" ? (r.Before is { } b ? (Percent(b), "%") : null, r.After is { } a ? (Percent(a), "%") : null)
                : (Ms(r.Before), Ms(r.After));
            // Better green, worse red (yellow within normal variation); numbers that read the same stay plain.
            var (beforeTone, afterTone) = beforeValue == afterValue ? (null, null) : CheckComparison.SideTones(r);
            var (beforeCell, afterCell) = (Big(beforeValue, beforeTone), Big(afterValue, afterTone));
            var change = Dot(r.Tone, r.Meaning, 17.5);
            if (Delta(r) is { } delta)
                ((StackPanel)change).Children.Add(new TextBlock { Text = delta, FontSize = 17, Foreground = Brush("Ink3Brush"),
                    VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 0, 0, 0) });
            Control[] cells = [name, beforeCell, afterCell, change];
            for (var i = 0; i < cells.Length; i++)
            {
                Grid.SetColumn(cells[i], i);
                cells[i].VerticalAlignment = VerticalAlignment.Center;
                grid.Children.Add(cells[i]);
            }
            CompareRows.Children.Add(new Border { BorderBrush = Brush("LineBrush"), BorderThickness = new Thickness(0, 1, 0, 0), Child = grid });
        }
        BetweenText.Text = Between(before, after);
    }

    private static string? Delta(ComparedReading r)
    {
        if (r.Change is not { } change || r.Meaning == "Same")
            return null;
        var sign = change > 0 ? "+" : change < 0 ? "−" : "";
        if (r.Unit == "Mbps")
            return r.Before is > 0 ? $"{sign}{Math.Abs(change / r.Before.Value * 100):0} %" : null;
        var size = Math.Abs(change);
        return r.Unit == "%" ? $"{sign}{size:0.#} %" : $"{sign}{size.ToString(size < 10 ? "0.#" : "0", CultureInfo.CurrentCulture)} ms";
    }

    /// <summary>What Netcheck knows changed between the two checks. Says so plainly when it knows of nothing.</summary>
    private static string Between(HistoryItem before, HistoryItem after)
    {
        var notes = new List<string>();
        if (before.Earlier || after.Earlier)
            notes.Add("The earlier version timed ping, jitter and DNS differently, so those aren't judged.");
        if (!before.Earlier && !after.Earlier && before.Kind is { Length: > 0 } k1 && after.Kind is { Length: > 0 } k2 && k1 != k2)
            notes.Add($"Connection changed from {k1} to {k2}.");
        if (before.DnsName is { Length: > 0 } d1 && after.DnsName is { Length: > 0 } d2 && d1 != d2)
            notes.Add($"DNS changed from {d1} to {d2}.");
        if (BoostBetween(before.Ended, after.Ended) is { } boost)
            notes.Add(boost);
        return notes.Count == 0 ? "Nothing Netcheck knows of changed." : string.Join(" ", notes);
    }

    private static string? BoostBetween(DateTimeOffset from, DateTimeOffset to)
    {
        try
        {
            if (!File.Exists(BoostLastFile) || new FileInfo(BoostLastFile).Length > 4096)
                return null;
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(BoostLastFile));
            var root = doc.RootElement;
            if (!root.TryGetProperty("At", out var at) || !at.TryGetDateTimeOffset(out var when) || when <= from || when >= to)
                return null;
            if (!root.TryGetProperty("Outcome", out var outcome) || outcome.GetString() != "Committed")
                return null;
            return root.TryGetProperty("Action", out var action) && action.GetString() == "undo"
                ? "Boost changes were undone." : "Boost changes were applied.";
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Text.Json.JsonException
            or InvalidOperationException)
        {
            return null;
        }
    }

    // ---------- cells ----------

    private (string, string)? Speed(double? mbps)
    {
        if (mbps is not { } v || !double.IsFinite(v) || v <= 0)
            return null;
        var unit = SpeedUnits.Resolve(preference, v);
        return (SpeedUnits.FormatNumber(v, unit), SpeedUnits.Label(unit));
    }

    private static (string, string)? Ms(double? ms) =>
        ms is { } v && double.IsFinite(v) ? (v.ToString(v < 10 ? "0.#" : "0", CultureInfo.CurrentCulture), "ms") : null;

    private static string Percent(double v) => v == 0 ? "0" : v.ToString(v < 1 ? "0.##" : "0.#", CultureInfo.CurrentCulture);

    private static Control Value((string Number, string Unit)? value, bool earlier) => Number(value, 22, 16, earlier);

    private static Control Big((string Number, string Unit)? value, Tone? tone = null) => Number(value, 28, 16, false, tone);

    private static Control Number((string Number, string Unit)? value, double size, double unitSize, bool muted, Tone? tone = null)
    {
        if (value is not { } v)
            return new TextBlock { Text = "—", FontSize = size, FontWeight = FontWeight.Light, Foreground = Brush("Ink3Brush") };
        return new StackPanel
        {
            Orientation = Orientation.Horizontal, Spacing = 4,
            Children =
            {
                new TextBlock { Text = v.Number, FontSize = size, FontWeight = FontWeight.Light,
                    Foreground = tone is { } t ? ToneBrush(t) : muted ? Brush("Ink2Brush") : Brush("InkBrush") },
                new TextBlock { Text = v.Unit, FontSize = unitSize, Foreground = Brush("Ink3Brush"),
                    VerticalAlignment = VerticalAlignment.Bottom, Margin = new Thickness(0, 0, 0, size > 22 ? 5 : 3) },
            },
        };
    }

    private static Control Dot(Tone tone, string text, double size) => new StackPanel
    {
        Orientation = Orientation.Horizontal, Spacing = 8,
        Children =
        {
            new Ellipse { Width = 7, Height = 7, Fill = ToneBrush(tone), VerticalAlignment = VerticalAlignment.Center },
            new TextBlock { Text = text, FontSize = size, FontWeight = FontWeight.SemiBold, Foreground = ToneBrush(tone),
                VerticalAlignment = VerticalAlignment.Center },
        },
    };

    /// <summary>
    /// The verdict in Check's exact words (P8: same wording everywhere) on one line (user, 2026-11-17): the text keeps
    /// its normal size and shrinks only as much as a long verdict needs to fit the cell. Only this text is scaled.
    /// </summary>
    private static Control VerdictCell(Tone tone, string text)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 8, VerticalAlignment = VerticalAlignment.Center };
        grid.Children.Add(new Ellipse { Width = 7, Height = 7, Fill = ToneBrush(tone), VerticalAlignment = VerticalAlignment.Center });
        var label = new TextBlock { Text = text, FontSize = 17, FontWeight = FontWeight.SemiBold, Foreground = ToneBrush(tone),
            TextWrapping = TextWrapping.NoWrap };
        var fit = new Viewbox { Child = label, Stretch = Stretch.Uniform, StretchDirection = StretchDirection.DownOnly,
            HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Center };
        ToolTip.SetTip(fit, text);
        Grid.SetColumn(fit, 1);
        grid.Children.Add(fit);
        return grid;
    }

    private static void AutomationPropertiesName(Control control, string name) =>
        Avalonia.Automation.AutomationProperties.SetName(control, name);

    private static IBrush Brush(string key) =>
        ThemeManager.Brush(key);

    private static IBrush ToneBrush(Tone tone)
    {
        // The shared resource brush itself, so a theme switch can swap it for the other theme\'s copy.
        return Brush(tone switch { Tone.Good => "GoodBrush", Tone.Fair => "FairBrush", Tone.Poor => "PoorBrush", _ => "NeutralBrush" });
    }
}
