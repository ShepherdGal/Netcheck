namespace Netcheck.Core;

/// <summary>Status color + word. Neutral means "no judgement" (missing, stopped or couldn't measure).</summary>
public enum Tone { Good, Fair, Poor, Neutral }

/// <summary>One headline reading for display: raw value (no unit conversion here), tone and a 1–4 word meaning.</summary>
public sealed record Assessed(double? Value, Tone Tone, string Meaning);

public sealed record Verdict(Tone Tone, string Headline, string Detail);

/// <summary>The five headline readings of a check, all rated by the same rules.</summary>
public sealed record CheckSummary(Assessed Download, Assessed Upload, Assessed Ping, Assessed Jitter, Assessed Loss,
    Verdict Verdict, bool PingFromIcmp);

/// <summary>
/// Netcheck rating rules for the internet check (design plan §5, draft v1). Thresholds are triage labels for one
/// check, not universal standards. Speed is described by what it is enough for, using common streaming and
/// video-call bitrates (≈15 Mbps for 4K, ≈5 Mbps for HD, ≈4 Mbps up for HD calls). Missing data is never rated.
/// </summary>
public static class CheckAssessment
{
    // v2 (2026-11-17, user: "how are they supposed to be?"): DNS Fast < 40 / OK < 80 ms. The typical lookup includes new
    // websites (resolved from scratch, ~50–70 ms even on the best public servers) and is timed as really used (encrypted
    // when private), so good servers land at ~25–45 ms; < 20 ms was green for almost no one. Ping, jitter and loss
    // unchanged (games feel instant under ~30 ms, calls cope with jitter under ~5 ms, > 1–2 % loss stutters).
    public const string Version = "check-ratings-v2";

    public static CheckSummary Summarize(InternetCheckResult result)
    {
        var download = Busy(result.Download) ?? Download(Speed(result.Download));
        var upload = Busy(result.Upload) ?? Upload(Speed(result.Upload));

        // Ping and jitter come from plain pings when available (closest to what games and calls feel);
        // the HTTPS server time is shown in the details instead.
        var icmp = result.Loss?.PingMs is not null;
        var ping = Ping(icmp ? result.Loss!.PingMs : result.Ping?.MedianMs);
        var jitter = Jitter(icmp ? result.Loss!.JitterMs : result.Ping?.JitterMs);
        var loss = Loss(result.Loss);
        return new CheckSummary(download, upload, ping, jitter, loss, Judge(result, download, upload, ping, jitter, loss), icmp);
    }

    /// <summary>The server refused ("slow down"): neutral, and it says why the gauge is empty (P13).</summary>
    private static Assessed? Busy(SpeedReading? reading) =>
        reading is { ServerBusy: true, Outcome: not StageOutcome.Complete } ? new(null, Tone.Neutral, "Server busy") : null;

    private static double? Speed(SpeedReading? reading) =>
        reading is { Outcome: StageOutcome.Complete, Mbps: { } mbps } && double.IsFinite(mbps) && mbps >= 0 ? mbps : null;

    public static Assessed Download(double? mbps) => mbps switch
    {
        null => new(null, Tone.Neutral, "Not measured"),
        >= 100 => new(mbps, Tone.Good, "Enough for several 4K streams"),
        >= 15 => new(mbps, Tone.Good, "Enough for 4K streaming"),
        >= 5 => new(mbps, Tone.Fair, "Fine for HD video"),
        >= 1.5 => new(mbps, Tone.Fair, "OK for browsing"),
        _ => new(mbps, Tone.Poor, "Too slow for video"),
    };

    public static Assessed Upload(double? mbps) => mbps switch
    {
        null => new(null, Tone.Neutral, "Not measured"),
        >= 20 => new(mbps, Tone.Good, "Great for calls and big uploads"),
        >= 4 => new(mbps, Tone.Good, "Smooth video calls"),
        >= 1 => new(mbps, Tone.Fair, "OK for calls, slow uploads"),
        _ => new(mbps, Tone.Poor, "Too slow for video calls"),
    };

    public static Assessed Ping(double? ms) => ms switch
    {
        null => new(null, Tone.Neutral, "Not measured"),
        < 30 => new(ms, Tone.Good, "Quick"),
        < 80 => new(ms, Tone.Fair, "OK"),
        _ => new(ms, Tone.Poor, "Slow"),
    };

    public static Assessed Jitter(double? ms) => ms switch
    {
        null => new(null, Tone.Neutral, "Not measured"),
        < 5 => new(ms, Tone.Good, "Steady"),
        < 20 => new(ms, Tone.Fair, "Some wobble"),
        _ => new(ms, Tone.Poor, "Unstable"),
    };

    /// <summary>Typical lookup time of the DNS server in use (popular and new names weighted equally, design plan §5).</summary>
    public static Assessed DnsLookup(double? ms) => ms switch
    {
        null => new(null, Tone.Neutral, "Couldn't time it"),
        < 40 => new(ms, Tone.Good, "Fast"),
        < 80 => new(ms, Tone.Fair, "OK"),
        _ => new(ms, Tone.Poor, "Slow"),
    };

    public static Assessed Loss(PingLossReading? reading) => reading switch
    {
        null or { Outcome: StageOutcome.NotRun } => new(null, Tone.Neutral, "Not measured"),
        { LossPercent: null, Outcome: StageOutcome.Stopped } => new(null, Tone.Neutral, "Not measured"),
        { LossPercent: null } => new(null, Tone.Neutral, "Couldn't measure"),
        { LossPercent: 0 } => new(0, Tone.Good, "None lost"),
        { LossPercent: < 2 and var p } => new(p, Tone.Fair, "A little lost"),
        { LossPercent: var p } => new(p, Tone.Poor, "Too much lost"),
    };

    private static Verdict Judge(InternetCheckResult result, Assessed download, Assessed upload, Assessed ping,
        Assessed jitter, Assessed loss)
    {
        if (result.Stopped)
            return new(Tone.Neutral, StoppedHeadline(result),
                "Finished readings are shown below. Run the check again for the full picture.");

        if (result.Ping is { Outcome: StageOutcome.Failed } && result.Download is null)
            return result.Loss is { LossPercent: < 2 }
                ? new(Tone.Neutral, "Couldn't reach the speed test server",
                    "Your internet answers pings, so the test server may be busy. Try again in a minute.")
                : new(Tone.Poor, "Your internet looks down",
                    "Nothing answered. Check your Wi-Fi or cable, then try again.");

        // Cloudflare's shared speed server said "slow down" (seen live 2026-11-17 after several checks in a row).
        if (Busy(result.Download) is not null || Busy(result.Upload) is not null)
            return new(Tone.Neutral, "The speed server is busy · try again in a few minutes",
                "The finished readings are below.");

        if (download.Tone == Tone.Neutral || upload.Tone == Tone.Neutral)
            return new(Tone.Neutral, "Part of the check didn't finish",
                "The finished readings are below. Run the check again for the full picture.");

        if (loss.Tone == Tone.Poor)
            return new(Tone.Poor, "Some of your data is getting lost", "Video calls and games may stutter.");
        if (ping.Tone == Tone.Poor || jitter.Tone == Tone.Poor)
            return new(Tone.Poor, "Your connection is slow to respond", "Games and video calls may lag.");
        if (download.Tone == Tone.Poor || upload.Tone == Tone.Poor)
            return new(Tone.Poor, "Your internet is slow right now",
                download.Tone == Tone.Poor ? "Browsing works, but video may buffer." : "Video calls and uploads may struggle.");

        Assessed[] all = [download, upload, ping, jitter, loss];
        if (all.All(a => a.Tone == Tone.Good))
            return new(Tone.Good, "Great for 4K streaming, gaming and video calls",
                "Fast, quick to respond and steady. No lost pings.");
        if (all.Where(a => a != loss).All(a => a.Tone == Tone.Good))
            return new(Tone.Good, "Great for 4K streaming, gaming and video calls",
                "Fast, quick to respond and steady. Ping loss couldn't be measured on this network.");
        return new(Tone.Fair, "Good for everyday use", "A few readings could be better. See below.");
    }

    private static string StoppedHeadline(InternetCheckResult result) =>
        result.Download is null ? "Check stopped at the start"
        : result.Download.Outcome != StageOutcome.Complete ? "Check stopped during download"
        : result.Upload is null or { Outcome: not StageOutcome.Complete } ? "Check stopped during upload"
        : "Check stopped before the last step";
}
