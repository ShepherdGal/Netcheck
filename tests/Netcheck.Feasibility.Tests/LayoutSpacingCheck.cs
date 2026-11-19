using System.Text.RegularExpressions;

/// <summary>
/// The spacing scale (design rules "Spacing scale", user 2026-11-17): vertical gaps between blocks in the window and page
/// layouts are 8 / 16 / 24 / 32 (or 48 / 64 for centring). Optical nudges up to 6 px are allowed (aligning a link with
/// the text beside it). Two named exceptions belong to a control, not to the layout. Fails on anything else, so custom
/// gaps can't creep back in.
/// </summary>
internal static partial class LayoutSpacingCheck
{
    private static readonly int[] Scale = [0, 8, 16, 32, 48, 64];   // 24 is card padding only, never a gap (2026-11-17)

    // Control internals, not page gaps: the gauge number's place inside the arc, and the tab bar's offset in its row
    // (title-bar controls end at 46 px; 46 + 24 - 56 = 14 puts the tab bar exactly 24 px below them).
    private static readonly string[] Exceptions = ["Margin=\"0,58,0,0\"", "x:Name=\"NavFrame\""];

    internal static int Run()
    {
        var root = AppContext.BaseDirectory;
        while (root is not null && !File.Exists(Path.Combine(root, "Netcheck.slnx")))
            root = Path.GetDirectoryName(root);
        if (root is null)
        {
            Console.Error.WriteLine("FAIL layout spacing: Netcheck.slnx not found");
            return 1;
        }
        var ui = Path.Combine(root, "src", "Netcheck");
        var files = Directory.GetFiles(Path.Combine(ui, "Pages"), "*.axaml").Append(Path.Combine(ui, "MainWindow.axaml"));
        var problems = new List<string>();
        var checkedGaps = 0;
        foreach (var file in files)
        {
            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                if (Exceptions.Any(line.Contains))
                    continue;
                // Page titles and leads are trimmed to their letters (title 8 above / 8 below, lead 7 / 6), so the
                // visible gap is the margin plus the trim.
                // Link buttons carry 11 px padding + ~4 px letter space above their text (15, measured).
                var (trimTop, trimBottom) = line.Contains("Classes=\"pageTitle\"", StringComparison.Ordinal) ? (8, 8)
                    : line.Contains("Classes=\"pageLead\"", StringComparison.Ordinal) ? (7, 6)
                    // (Back links set their own padding and only nudge to line up with the title beside them.)
                    : line.Contains("NcLinkButton", StringComparison.Ordinal) && !line.Contains("Padding=", StringComparison.Ordinal) ? (15, 15)
                    : (0, 0);
                foreach (Match m in VerticalMargin().Matches(line))
                {
                    checkedGaps++;
                    var rawTop = int.Parse(m.Groups[1].Value);
                    var rawBottom = m.Groups[2].Success ? int.Parse(m.Groups[2].Value) : rawTop;
                    // A margin of exactly minus the trim means "flush to the letters" (0 visible).
                    var top = rawTop == 0 ? 0 : rawTop + trimTop;
                    var bottom = rawBottom == 0 ? 0 : rawBottom + trimBottom;
                    foreach (var value in new[] { top, bottom })
                        if (!Scale.Contains(value) && Math.Abs(value) > 6)
                            problems.Add($"{Path.GetFileName(file)}:{i + 1}: visible gap {value} is off the scale");
                }
                if (line.Contains("Orientation=\"Horizontal\"", StringComparison.Ordinal))
                    continue;
                foreach (Match m in StackSpacing().Matches(line))
                {
                    checkedGaps++;
                    var value = int.Parse(m.Groups[1].Value);
                    if (!Scale.Contains(value) && value is not (2 or 4))   // 2 / 4 = label + value pairs inside one cell
                        problems.Add($"{Path.GetFileName(file)}:{i + 1}: spacing {value} is off the scale");
                }
            }
        }
        foreach (var problem in problems)
            Console.Error.WriteLine("FAIL " + problem);
        if (problems.Count > 0)
            return 1;
        Console.WriteLine($"PASS layout spacing ({checkedGaps} vertical gaps on the visible 8/16/32 scale; 24 = card padding only)");
        return 0;
    }

    // "0,top,0,bottom" and the two-value "0,both" form (missed before: a 24 px gap slipped through, 2026-11-17).
    [GeneratedRegex("Margin=\"0,(-?\\d+)(?:,0,(-?\\d+))?\"")]
    private static partial Regex VerticalMargin();

    [GeneratedRegex("(?<!Column)Spacing=\"(\\d+)\"")]
    private static partial Regex StackSpacing();
}
