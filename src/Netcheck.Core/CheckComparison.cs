namespace Netcheck.Core;

/// <summary>One row of "Before and after". Change is null when either side is missing.</summary>
public sealed record ComparedReading(string Name, string Unit, double? Before, double? After, double? Change,
    Tone Tone, string Meaning);

/// <summary>
/// Before/after for two single checks (History, P6). A difference only counts when it is larger than normal
/// check-to-check variation; otherwise it reads "About the same". Pure: no I/O, no formatting of units.
/// </summary>
public static class CheckComparison
{
    public const string Version = "netcheck-compare-v1";

    /// <param name="earlierVersion">True when either side came from the earlier version, whose ping and jitter were timed
    /// with web requests and DNS through the Windows cache: those rows are shown but not judged.</param>
    public static IReadOnlyList<ComparedReading> Compare(CheckSummary before, double? dnsBefore, CheckSummary after,
        double? dnsAfter, bool earlierVersion = false) =>
    [
        Speed("Download", before.Download.Value, after.Download.Value),
        Speed("Upload", before.Upload.Value, after.Upload.Value),
        Lower("Ping", "ms", before.Ping.Value, after.Ping.Value, absolute: 3, relative: 0.15, "Quicker", "Slower", earlierVersion),
        Lower("Jitter", "ms", before.Jitter.Value, after.Jitter.Value, absolute: 2, relative: 0.30, "Steadier", "Less steady", earlierVersion),
        Loss(before.Loss.Value, after.Loss.Value),
        Lower("DNS lookups", "ms", dnsBefore, dnsAfter, absolute: 5, relative: 0.15, "Faster", "Slower", earlierVersion),
    ];

    /// <summary>Speeds swing about ±10 % between back-to-back checks on the same line.</summary>
    private static ComparedReading Speed(string name, double? before, double? after)
    {
        if (Missing(name, "Mbps", before, after) is { } missing)
            return missing;
        var change = after!.Value - before!.Value;
        var tolerance = Math.Max(1, before.Value * 0.10);
        return Math.Abs(change) <= tolerance
            ? new(name, "Mbps", before, after, change, Tone.Neutral, "About the same")
            : new(name, "Mbps", before, after, change, change > 0 ? Tone.Good : Tone.Poor, change > 0 ? "Faster" : "Slower");
    }

    private static ComparedReading Lower(string name, string unit, double? before, double? after, double absolute,
        double relative, string better, string worse, bool notJudged)
    {
        if (Missing(name, unit, before, after) is { } missing)
            return missing;
        var change = after!.Value - before!.Value;
        if (notJudged)
            return new(name, unit, before, after, change, Tone.Neutral, "Measured differently");
        var tolerance = Math.Max(absolute, before.Value * relative);
        return Math.Abs(change) <= tolerance
            ? new(name, unit, before, after, change, Tone.Neutral, "About the same")
            : new(name, unit, before, after, change, change < 0 ? Tone.Good : Tone.Poor, change < 0 ? better : worse);
    }

    /// <summary>Ping loss in percentage points: within 1 point is "About the same"; both zero is "Same".</summary>
    private static ComparedReading Loss(double? before, double? after)
    {
        if (Missing("Ping loss", "%", before, after) is { } missing)
            return missing;
        var change = after!.Value - before!.Value;
        if (before.Value == 0 && after.Value == 0)
            return new("Ping loss", "%", before, after, 0, Tone.Neutral, "Same");
        return Math.Abs(change) < 1
            ? new("Ping loss", "%", before, after, change, Tone.Neutral, "About the same")
            : new("Ping loss", "%", before, after, change, change < 0 ? Tone.Good : Tone.Poor, change < 0 ? "Fewer lost" : "More lost");
    }

    /// <summary>
    /// Colours for the two numbers (user, 2026-11-17): the better one green; the worse one red when the change counts,
    /// yellow when it is within normal check-to-check variation. Null = plain (equal, missing or not judged).
    /// Speeds: higher is better; everything else: lower is better.
    /// </summary>
    public static (Tone? Before, Tone? After) SideTones(ComparedReading r)
    {
        if (r.Before is not { } b || r.After is not { } a || r.Change is null || b == a || r.Meaning == "Measured differently")
            return (null, null);
        var afterBetter = r.Unit == "Mbps" ? a > b : a < b;
        var worse = r.Tone == Tone.Neutral ? Tone.Fair : Tone.Poor;
        return afterBetter ? (worse, Tone.Good) : (Tone.Good, worse);
    }

    private static ComparedReading? Missing(string name, string unit, double? before, double? after) =>
        before is { } b && after is { } a && double.IsFinite(b) && double.IsFinite(a)
            ? null
            : new(name, unit, before, after, null, Tone.Neutral, "Can't compare");

    /// <summary>
    /// Shows a check saved by the earlier version (<see cref="MeasurementResult"/>) in the new layout. Display only:
    /// the stored run is never rewritten. That version had no ping-loss stage, and its ping came from web requests.
    /// </summary>
    public static InternetCheckResult FromEarlierVersion(MeasurementResult run)
    {
        static SpeedReading? Speed(TransferMeasurement? t) => t is null ? null
            : new SpeedReading(t.MegabitsPerSecond is > 0 ? StageOutcome.Complete : StageOutcome.Failed, t.MegabitsPerSecond,
                t.Bytes, t.Elapsed, t.Samples, t.PeakBulkStreams ?? 0, SpeedEnd.Duration);
        var ping = run.Idle is { } idle ? new LatencyReading(StageOutcome.Complete, idle.Milliseconds, idle.Failed) : null;
        return new InternetCheckResult(run.Started, run.Ended, run.State == MeasurementState.Stopped, ping,
            Speed(run.Download), Speed(run.Upload), null, null, run.Notes);
    }

    /// <summary>Typical Windows DNS lookup of an earlier-version run (its A-record median), if it timed one.</summary>
    public static double? EarlierDnsLookup(MeasurementResult run) =>
        run.SystemDns.FirstOrDefault(d => d.RecordType == "A")?.MedianMs;
}
