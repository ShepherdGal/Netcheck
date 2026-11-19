namespace Netcheck.Core;

// Models for the rebuilt "Check my internet" engine (design plan §5). Raw measurements only:
// ratings and display formatting live elsewhere and never change these values.

public enum CheckStage { Ping, Download, Upload, PingLoss }

/// <summary>How a stage ended. Stopped/Failed/NotRun results are neutral, never "good" or "bad".</summary>
public enum StageOutcome { Complete, Stopped, Failed, NotRun }

public enum SpeedEnd { Duration, ByteCap, Stopped, Failed }

/// <summary>An ICMP echo target used for ping loss (D3). Public anycast resolvers by default.</summary>
public sealed record PingTarget(string Name, string Address)
{
    public static IReadOnlyList<PingTarget> Defaults { get; } =
    [
        new("Cloudflare", "1.1.1.1"),
        new("Google", "8.8.8.8"),
        new("Quad9", "9.9.9.9"),
    ];
}

public sealed record CheckOptions(
    Uri SpeedOrigin,
    IReadOnlyList<PingTarget> LossTargets,
    TimeSpan DirectionDuration,
    long DownloadByteCap,
    long UploadByteCap,
    int DownloadStreams = 6,
    int UploadStreams = 4,
    int LatencySamples = 20,
    int LossPingsPerTarget = 100,
    TimeSpan? LossInterval = null)
{
    public const long MaxByteCap = 2_000_000_000;

    /// <summary>
    /// About 28 s in total: ~2 s ping, 8 s each way, 10 s ping loss. Transfers are time-based; the byte caps are
    /// safety ceilings that only very fast lines approach (a 1 Gbps line uses roughly 1 GB down in 8 s).
    /// A 200 MB cap ended a 940 Mbps download after ~2.6 s and read 19 % low against Ookla (measured against Ookla).
    /// 700 MB down (user, 2026-11-17, P13: lighter on Cloudflare's servers and capped plans): ~6 s at 940 Mbps, still
    /// ~4.5 s of 1-second windows after the 1.5 s ramp-up. Slower lines never reach it (8 s × speed).
    /// </summary>
    public static CheckOptions Default { get; } = new(new Uri("https://speed.cloudflare.com/"), PingTarget.Defaults,
        TimeSpan.FromSeconds(8), 700_000_000, 400_000_000);

    public TimeSpan EffectiveLossInterval => LossInterval ?? TimeSpan.FromMilliseconds(100);

    public string? Validate()
    {
        if (!SpeedOrigin.IsAbsoluteUri || SpeedOrigin.Scheme != Uri.UriSchemeHttps || SpeedOrigin.AbsolutePath != "/" ||
            SpeedOrigin.UserInfo.Length != 0 || SpeedOrigin.Query.Length != 0)
            return "The speed server must be a plain https:// origin.";
        if (DirectionDuration < TimeSpan.FromSeconds(2) || DirectionDuration > TimeSpan.FromSeconds(30))
            return "Each direction must last 2–30 seconds.";
        if (DownloadByteCap is <= 0 or > MaxByteCap || UploadByteCap is <= 0 or > MaxByteCap)
            return "Byte caps must be between 1 byte and 2 GB.";
        if (DownloadStreams is < 1 or > 8 || UploadStreams is < 1 or > 8)
            return "Use 1–8 parallel streams.";
        if (LatencySamples is < 5 or > 50)
            return "Use 5–50 ping samples.";
        if (LossTargets.Count > 5 || LossPingsPerTarget is < 10 or > 300 ||
            EffectiveLossInterval < TimeSpan.FromMilliseconds(10) || EffectiveLossInterval > TimeSpan.FromSeconds(1))
            return "Ping loss needs at most 5 targets, 10–300 pings each, 10–1000 ms apart.";
        return null;
    }
}

/// <summary>Idle round trips to the speed server, with server processing time removed when the server reports it.</summary>
public sealed record LatencyReading(StageOutcome Outcome, IReadOnlyList<double> Milliseconds, int Failed)
{
    public const int MinimumSamples = 5;
    public bool Sufficient => Milliseconds.Count >= MinimumSamples;
    public double? MedianMs => Sufficient ? MeasurementStatistics.Median(Milliseconds) : null;

    /// <summary>Mean absolute difference between consecutive successful round trips.</summary>
    public double? JitterMs => Sufficient
        ? Milliseconds.Zip(Milliseconds.Skip(1), (a, b) => Math.Abs(b - a)).Average()
        : null;
}

/// <param name="ServerBusy">The speed server refused with "slow down" (HTTP 429) or "busy" (503) and the transfer
/// didn't finish because of it (P13, 2026-11-17). A flag rather than a new <see cref="SpeedEnd"/> value, so saved
/// history still opens in earlier versions (they ignore unknown fields).</param>
public sealed record SpeedReading(StageOutcome Outcome, double? Mbps, long Bytes, TimeSpan Elapsed,
    IReadOnlyList<ThroughputSample> Samples, int Streams, SpeedEnd End, string? Problem = null, bool ServerBusy = false)
{
    public double? AverageMbps => Bytes > 0 && Elapsed.TotalSeconds > 0 ? Bytes * 8e-6 / Elapsed.TotalSeconds : null;
}

public sealed record PingTargetReading(string Name, string Address, int Sent, int Answered, double? MedianMs,
    double? JitterMs = null)
{
    /// <summary>A target that never answered is treated as blocking pings, not as 100 % loss.</summary>
    public bool Reachable => Answered > 0;
    public int Lost => Sent - Answered;

    /// <summary>Mean absolute difference between consecutive replies (in send order); needs 5 replies.</summary>
    public static double? Jitter(IReadOnlyList<double> ordered) =>
        ordered.Count >= LatencyReading.MinimumSamples
            ? ordered.Zip(ordered.Skip(1), (a, b) => Math.Abs(b - a)).Average()
            : null;
}

public sealed record PingLossReading(StageOutcome Outcome, IReadOnlyList<PingTargetReading> Targets)
{
    public IEnumerable<PingTargetReading> Counted => Targets.Where(target => target.Reachable);
    public int Sent => Counted.Sum(target => target.Sent);
    public int Lost => Counted.Sum(target => target.Lost);
    public bool Measurable => Sent >= 10;

    /// <summary>Null means "Couldn't measure" (every target blocked pings, or too few were sent).</summary>
    public double? LossPercent => Measurable ? 100d * Lost / Sent : null;

    private IEnumerable<PingTargetReading> Timed => Counted.Where(t => t.Answered >= LatencyReading.MinimumSamples);

    /// <summary>Typical ping: the median of the answering targets' medians.</summary>
    public double? PingMs => MeasurementStatistics.Median(Timed.Select(t => t.MedianMs).OfType<double>());

    /// <summary>Average of the answering targets' jitter.</summary>
    public double? JitterMs => Timed.Select(t => t.JitterMs).OfType<double>().ToArray() is { Length: > 0 } j ? j.Average() : null;
}

public sealed record InternetCheckResult(DateTimeOffset Started, DateTimeOffset Ended, bool Stopped,
    LatencyReading? Ping, SpeedReading? Download, SpeedReading? Upload, PingLossReading? Loss,
    string? ServerLocation, IReadOnlyList<string> Notes)
{
    public const string Method = "netcheck-check-v1";
}

/// <summary>Live progress. LiveMbps is a display value only; the result's Mbps is computed separately.</summary>
public sealed record CheckProgress(CheckStage Stage, double StageFraction, double? LiveMbps = null);
