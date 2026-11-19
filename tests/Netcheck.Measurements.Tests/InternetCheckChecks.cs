using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using Netcheck.Core;
using Netcheck.Measurements.Check;
using Netcheck.TestServer;

/// <summary>P2 engine checks: pure math, a rate-limited loopback fixture with known answers, and real loopback ICMP.</summary>
internal static class InternetCheckChecks
{
    private const double FixtureMbps = 4 * 1024 * 1024 * 8e-6; // 33.554 Mbps

    internal static async Task RunAsync()
    {
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
        PureChecks();
        RatingChecks();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        await KnownRateAsync(deadline.Token);
        await ByteCapAsync(deadline.Token);
        await StopDuringUploadAsync(deadline.Token);
        await UnreachableServerAsync(deadline.Token);
        await RateLimitedAsync(deadline.Token);
        await RateLimitBurstAsync(deadline.Token);
        await StalledServerAsync(deadline.Token);
        await LoopbackIcmpAsync(deadline.Token);
        Console.WriteLine("PASS all internet-check checks");
    }

    private static void PureChecks()
    {
        var latency = new LatencyReading(StageOutcome.Complete, [20, 30, 25, 25, 20], 0);
        Require(latency.MedianMs == 25 && latency.JitterMs == 5, "median 25 ms and jitter 5 ms from consecutive differences");
        Require(new LatencyReading(StageOutcome.Complete, [20, 30, 25, 25], 0) is { MedianMs: null, JitterMs: null },
            "fewer than 5 samples are not rated");

        var loss = new PingLossReading(StageOutcome.Complete,
            [new("A", "192.0.2.1", 100, 95, 12), new("B", "192.0.2.2", 100, 0, null)]);
        Require(loss is { Sent: 100, Lost: 5, LossPercent: 5 }, "a target that never answers is excluded, not 100 % loss");
        Require(new PingLossReading(StageOutcome.Complete, [new("B", "192.0.2.2", 100, 0, null)]).LossPercent is null,
            "all targets blocked means \"couldn't measure\"");
        Require(new PingLossReading(StageOutcome.Stopped, [new("A", "192.0.2.1", 6, 6, 9)]).LossPercent is null,
            "fewer than 10 counted pings are not reported");

        var steady = Enumerable.Range(0, 21).Select(i => (i * 0.25, (long)(i * 0.25 * 10_000_000))).ToList();
        Require(Math.Abs(SpeedMath.Summarize(steady)!.Value - 80) < 1e-9, "steady 10 MB/s summarises to exactly 80 Mbps");
        var rampUp = steady.Select(p => (p.Item1, p.Item1 < 1.5 ? p.Item2 / 4 : p.Item2 - 11_250_000)).ToList();
        Require(Math.Abs(SpeedMath.Summarize(rampUp)!.Value - 80) < 1, "slow start-up is ignored");
        Require(SpeedMath.Summarize([(0, 0)]) is null && SpeedMath.Summarize([(0, 0), (1, 0)]) is null, "no data, no speed");
        Require(SpeedMath.Summarize([(0, 0), (0.5, 1_000_000)]) is > 0, "very short transfer still reports its average");
        Require(SpeedMath.Spread([(0, 1, 1000), (0.5, 0.5, 200)], [0.25, 0.5, 2]) is [(_, 250), (_, 700), (_, 1200)],
            "confirmed upload bytes are spread over each request's own time");
        Require(SpeedMath.Recent(steady) is { } recent && Math.Abs(recent - 80) < 1e-9, "live rate over the last second");

        Require(InternetCheckEngine.ServerMilliseconds(["cfSpeedEdge;dur=6, cfSpeedWorker;dur=30",
                "cfL4;desc=\"?proto=TCP&rtt=9531\""]) == 30 &&
            InternetCheckEngine.ServerMilliseconds(["cfRequestDuration;dur=0.4"]) == 0.4 &&
            InternetCheckEngine.ServerMilliseconds(["cfL4;desc=\"x\""]) is null,
            "server processing time = largest Server-Timing duration");
        Require(CheckOptions.Default.Validate() is null, "default options valid");
        Require(CheckOptions.Default with { SpeedOrigin = new Uri("http://speed.cloudflare.com/") } is var plain &&
            plain.Validate() is not null, "plain http rejected");
        Require((CheckOptions.Default with { DownloadByteCap = 3_000_000_000 }).Validate() is not null, "byte cap limited to 2 GB");
        Console.WriteLine("PASS pure latency, jitter, ping-loss, throughput and option rules");
    }

    private static void RatingChecks()
    {
        Require(CheckAssessment.Ping(29.99).Meaning == "Quick" && CheckAssessment.Ping(30) is { Tone: Tone.Fair, Meaning: "OK" } &&
            CheckAssessment.Ping(79.99).Tone == Tone.Fair && CheckAssessment.Ping(80).Tone == Tone.Poor &&
            CheckAssessment.Ping(null).Tone == Tone.Neutral, "ping boundaries 30 / 80 ms");
        Require(CheckAssessment.Jitter(4.99).Tone == Tone.Good && CheckAssessment.Jitter(5).Tone == Tone.Fair &&
            CheckAssessment.Jitter(20).Tone == Tone.Poor, "jitter boundaries 5 / 20 ms");
        Require(CheckAssessment.Download(15).Meaning == "Enough for 4K streaming" && CheckAssessment.Download(14.99).Tone == Tone.Fair &&
            CheckAssessment.Download(1.49).Tone == Tone.Poor && CheckAssessment.Download(100).Meaning.Contains("several"),
            "download described by use (15 Mbps 4K, 5 Mbps HD)");
        Require(CheckAssessment.Upload(4).Tone == Tone.Good && CheckAssessment.Upload(3.99).Tone == Tone.Fair &&
            CheckAssessment.Upload(0.99).Tone == Tone.Poor, "upload boundaries 4 / 1 Mbps");

        PingLossReading Loss(int sent, int answered, double median = 9, double jitter = 1) =>
            new(StageOutcome.Complete, [new("A", "192.0.2.1", sent, answered, median, jitter)]);
        Require(CheckAssessment.Loss(Loss(100, 100)) is { Tone: Tone.Good, Meaning: "None lost" } &&
            CheckAssessment.Loss(Loss(300, 299)).Tone == Tone.Fair && CheckAssessment.Loss(Loss(100, 98)).Tone == Tone.Poor &&
            CheckAssessment.Loss(new(StageOutcome.Complete, [new("B", "192.0.2.2", 100, 0, null)])).Meaning == "Couldn't measure",
            "loss: 0 % good, <2 % fair, ≥2 % poor, all blocked = couldn't measure");
        Require(PingTargetReading.Jitter([10, 12, 10, 14, 10]) == 3 && PingTargetReading.Jitter([10, 12]) is null,
            "per-target jitter from replies in send order");

        var t = DateTimeOffset.UtcNow;
        SpeedReading Speed(double mbps) => new(StageOutcome.Complete, mbps, 1, TimeSpan.FromSeconds(8), [], 6, SpeedEnd.Duration);
        var https = new LatencyReading(StageOutcome.Complete, [20, 21, 19, 20, 22], 0);
        InternetCheckResult Result(PingLossReading? loss, bool stopped = false, SpeedReading? up = null) =>
            new(t, t, stopped, https, Speed(950), up ?? Speed(250), loss, "TLV", []);

        var great = CheckAssessment.Summarize(Result(Loss(300, 300, 7, 1)));
        Require(great.PingFromIcmp && great.Ping.Value == 7 && great.Jitter.Value == 1 &&
            great.Verdict is { Tone: Tone.Good, Headline: var h } && h.StartsWith("Great"), "all good → great, ping from ICMP");
        var noIcmp = CheckAssessment.Summarize(Result(new(StageOutcome.Complete, [new("B", "192.0.2.2", 100, 0, null)])));
        Require(!noIcmp.PingFromIcmp && noIcmp.Ping.Value == 20 && noIcmp.Verdict.Detail.Contains("couldn't be measured"),
            "pings blocked → HTTPS ping fallback and the verdict says loss is unknown");
        Require(CheckAssessment.Summarize(Result(Loss(100, 95))).Verdict is { Tone: Tone.Poor, Headline: var lost } &&
            lost.Contains("lost"), "high loss leads the verdict");
        var stopped = CheckAssessment.Summarize(Result(null, stopped: true,
            up: new(StageOutcome.Stopped, null, 5, TimeSpan.FromSeconds(2), [], 4, SpeedEnd.Stopped)));
        Require(stopped.Verdict is { Tone: Tone.Neutral, Headline: "Check stopped during upload" } &&
            stopped.Upload.Tone == Tone.Neutral && stopped.Loss.Meaning == "Not measured", "stopped check is neutral");
        var down = CheckAssessment.Summarize(new(t, t, false, new(StageOutcome.Failed, [], 5), null, null,
            new(StageOutcome.Complete, [new("A", "192.0.2.1", 100, 0, null)]), null, []));
        Require(down.Verdict is { Tone: Tone.Poor, Headline: "Your internet looks down" }, "nothing answers → internet down");
        Console.WriteLine("PASS check ratings v1: boundaries, ICMP ping preference, verdicts for good, lossy, stopped and offline");
    }

    private static async Task KnownRateAsync(CancellationToken token)
    {
        await using var fixture = await SpeedFixture.StartAsync(4 * 1024 * 1024, TimeSpan.FromMilliseconds(30), token);
        var pinger = new FakePinger();
        var stages = new List<CheckStage>();
        var result = await Engine(fixture, pinger).RunAsync(FixtureOptions(fixture),
            new InlineProgress<CheckProgress>(p => { if (stages.LastOrDefault() != p.Stage || stages.Count == 0) stages.Add(p.Stage); }),
            token);

        Require(!result.Stopped && stages.SequenceEqual([CheckStage.Ping, CheckStage.Download, CheckStage.Upload, CheckStage.PingLoss]),
            $"stages run in order ({string.Join(",", stages)})");
        Require(result.Ping is { Outcome: StageOutcome.Complete, MedianMs: >= 25 and <= 150, JitterMs: not null },
            $"ping reflects the 30 ms delay ({result.Ping?.MedianMs:0.0} ms)");
        Require(result.ServerLocation == "TST", "server location read from cf-ray");
        Require(result.Download is { Outcome: StageOutcome.Complete, Mbps: { } down } && Within(down, FixtureMbps, 0.1),
            $"download within 10 % of {FixtureMbps:0.00} Mbps ({result.Download?.Mbps:0.00})");
        Require(result.Upload is { Outcome: StageOutcome.Complete, Mbps: { } up } && Within(up, FixtureMbps, 0.1),
            $"upload within 10 % of {FixtureMbps:0.00} Mbps ({result.Upload?.Mbps:0.00})");
        Require(result.Download!.Bytes <= fixture.DownloadedBytes, "client never counts more than the server sent");
        Require(result.Loss is { PingMs: 12, JitterMs: 0 }, "ICMP ping and jitter come from the answering target");
        Require(result.Loss is { LossPercent: 5, Sent: 40 } && result.Notes.Any(n => n.Contains("192.0.2.2")),
            $"5 % loss from the answering target; blocked target noted ({result.Loss?.LossPercent})");
        Console.WriteLine($"PASS known rate: ping {result.Ping!.MedianMs:0.0} ms, jitter {result.Ping.JitterMs:0.0} ms, " +
            $"down {result.Download.Mbps:0.00} / up {result.Upload!.Mbps:0.00} Mbps (target {FixtureMbps:0.00}), loss {result.Loss!.LossPercent}%");
    }

    private static async Task ByteCapAsync(CancellationToken token)
    {
        await using var fixture = await SpeedFixture.StartAsync(null, null, token);
        var options = FixtureOptions(fixture) with { DownloadByteCap = 3_000_000, UploadByteCap = 2_000_000, LossTargets = [] };
        var result = await Engine(fixture, new FakePinger()).RunAsync(options, null, token);
        Require(result.Download is { End: SpeedEnd.ByteCap, Bytes: <= 3_000_000, Mbps: > 0 } && fixture.DownloadedBytes <= 3_000_000,
            $"download stops at 3 MB ({result.Download?.Bytes} counted, {fixture.DownloadedBytes} served)");
        Require(result.Upload is { End: SpeedEnd.ByteCap, Bytes: <= 2_000_000 } && fixture.UploadedBytes <= 2_000_000,
            $"upload stops at 2 MB ({result.Upload?.Bytes} counted, {fixture.UploadedBytes} received)");
        Require(result.Loss is null, "no loss targets, no loss stage");
        Console.WriteLine("PASS byte caps are never exceeded");
    }

    private static async Task StopDuringUploadAsync(CancellationToken token)
    {
        await using var fixture = await SpeedFixture.StartAsync(4 * 1024 * 1024, null, token);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        var result = await Engine(fixture, new FakePinger()).RunAsync(FixtureOptions(fixture),
            new InlineProgress<CheckProgress>(p => { if (p.Stage == CheckStage.Upload && p.StageFraction > 0.2) stop.Cancel(); }),
            stop.Token);
        Require(result.Stopped && result.Download is { Outcome: StageOutcome.Complete, Mbps: > 0 },
            "stopping keeps the finished download");
        Require(result.Upload is { Outcome: StageOutcome.Stopped, Mbps: null, End: SpeedEnd.Stopped },
            "the interrupted upload has no speed");
        Require(result.Loss is null, "stages after the stop are not run");
        Console.WriteLine("PASS stop keeps completed stages and leaves the interrupted one unrated");
    }

    private static async Task UnreachableServerAsync(CancellationToken token)
    {
        var options = CheckOptions.Default with
        {
            SpeedOrigin = new Uri("https://127.0.0.1:1/"),
            LossTargets = [new("A", "192.0.2.1")],
            LossPingsPerTarget = 20,
            LossInterval = TimeSpan.FromMilliseconds(10),
            LatencySamples = 5,
        };
        var clock = Stopwatch.StartNew();
        var result = await new InternetCheckEngine(new FakePinger()).RunAsync(options, null, token);
        Require(result.Ping is { Outcome: StageOutcome.Failed, MedianMs: null } && result.Download is null && result.Upload is null,
            "unreachable server fails the ping stage and skips transfers");
        Require(result.Notes.Any(n => n.Contains("Couldn't reach")) && result.Loss is { Outcome: StageOutcome.Complete },
            "ping loss still runs, which helps tell 'server down' from 'internet down'");
        Require(clock.Elapsed < TimeSpan.FromSeconds(10), $"fails fast ({clock.Elapsed.TotalSeconds:0.0} s)");
        Console.WriteLine("PASS unreachable speed server is reported, not guessed");
    }

    /// <summary>Real case from 2026-11-15: Cloudflare answered 429 after many tests and a 0.5 s fragment was shown as a result.</summary>
    private static async Task RateLimitedAsync(CancellationToken token)
    {
        await using var fixture = await SpeedFixture.StartAsync(4 * 1024 * 1024, null, token, refuseTransfersAfter: 8);
        var options = FixtureOptions(fixture) with { DownloadByteCap = 60_000_000, UploadByteCap = 25_000_000, LossTargets = [] };
        var result = await Engine(fixture, new FakePinger()).RunAsync(options, null, token);
        Require(result.Download is { Outcome: StageOutcome.Failed, Mbps: null, Problem: var p } && p!.Contains("429"),
            $"a download cut short by HTTP 429 is reported as failed, not as a speed ({result.Download?.Outcome}, {result.Download?.Mbps})");
        Require(result.Download!.End != SpeedEnd.ByteCap, "reserved-but-refused bytes don't count as reaching the data limit");
        Require(CheckAssessment.Summarize(result).Verdict.Tone == Tone.Neutral, "the verdict stays neutral");
        // P13 (2026-11-17): the page says why and what to do, and the gauge says why it's empty.
        var summary = CheckAssessment.Summarize(result);
        Require(result.Download.ServerBusy, "the refused download is flagged as server busy");
        Require(summary.Download is { Value: null, Tone: Tone.Neutral, Meaning: "Server busy" }, $"download gauge says Server busy ({summary.Download.Meaning})");
        Require(summary.Verdict.Headline.StartsWith("The speed server is busy", StringComparison.Ordinal),
            $"the line says the server is busy ({summary.Verdict.Headline})");
        Console.WriteLine("PASS rate-limited server (HTTP 429) is reported as 'server busy', not turned into a speed");
    }

    /// <summary>
    /// Real case 2026-11-16: Cloudflare answered 429 for a moment; every download connection gave up after 0.3 s, the
    /// gauge froze and the result became "—". Connections now wait (Retry-After) and carry on.
    /// </summary>
    private static async Task RateLimitBurstAsync(CancellationToken token)
    {
        await using var fixture = await SpeedFixture.StartAsync(4 * 1024 * 1024, null, token, refuseTransfersAfter: 8, refuseFor: 18);
        var options = FixtureOptions(fixture) with { DownloadByteCap = 200_000_000, UploadByteCap = 200_000_000, LossTargets = [] };
        var reports = new List<CheckProgress>();
        var result = await Engine(fixture, new FakePinger()).RunAsync(options,
            new InlineProgress<CheckProgress>(p => { lock (reports) reports.Add(p); }), token);
        Require(result.Download is { Outcome: StageOutcome.Complete, Mbps: > 20 and < 45 },
            $"a short 429 burst is waited out and the download still measures (≈ 33.5 Mbps): {result.Download?.Outcome} {result.Download?.Mbps:0.0}");
        Require(result.Download!.Problem is { } p && p.Contains("429"), "the burst is noted in the details");
        Require(!result.Download.ServerBusy && CheckAssessment.Summarize(result).Download.Tone != Tone.Neutral,
            "a waited-out burst is a normal result, not 'server busy'");
        var lastDown = reports.Last(r => r.Stage == CheckStage.Download);
        Require(lastDown.LiveMbps is { } shown && Math.Abs(shown - result.Download.Mbps!.Value) < 0.01,
            "the gauge's last download value is the result itself, so nothing jumps afterwards");
        Console.WriteLine($"PASS a short 429 burst is waited out: download {result.Download.Mbps:0.0} Mbps, gauge ends on the result");

        // Steady line: in the second half the live value is the same calculation as the result, so it stays close.
        await using var steady = await SpeedFixture.StartAsync(4 * 1024 * 1024, null, token);
        var steadyOptions = FixtureOptions(steady) with { DownloadByteCap = 200_000_000, UploadByteCap = 200_000_000, LossTargets = [] };
        var seen = new List<CheckProgress>();
        var calm = await Engine(steady, new FakePinger()).RunAsync(steadyOptions,
            new InlineProgress<CheckProgress>(p => { lock (seen) seen.Add(p); }), token);
        var final = calm.Download!.Mbps!.Value;
        var late = seen.Where(r => r.Stage == CheckStage.Download && r.StageFraction is > 0.5 and < 1 && r.LiveMbps is not null)
            .Select(r => r.LiveMbps!.Value).ToArray();
        Require(late.Length > 0 && late.All(v => Math.Abs(v - final) < final * 0.15),
            $"steady line: the live value stays within 15 % of the result ({string.Join(", ", late.Select(v => v.ToString("0.0")))} vs {final:0.0})");
        Console.WriteLine($"PASS steady line: live download stays near the result ({final:0.0} Mbps)");
    }

    /// <summary>
    /// Real case from 2026-11-16: 49 MB arrived in ~1 s, then the server stopped sending and one request hung until
    /// time ran out; the check showed "0 Mbps" rated red. A stall early on must read as "didn't finish" (neutral);
    /// a late stall keeps the speed of the part that ran, with a note.
    /// </summary>
    private static async Task StalledServerAsync(CancellationToken token)
    {
        await using (var early = await SpeedFixture.StartAsync(8 * 1024 * 1024, null, token, stallAfterBytes: 3_000_000))
        {
            var options = FixtureOptions(early) with { DownloadByteCap = 60_000_000, UploadByteCap = 25_000_000, LossTargets = [] };
            var result = await Engine(early, new FakePinger()).RunAsync(options, null, token);
            Require(result.Download is { Outcome: StageOutcome.Failed, Mbps: null, Problem: var p } && p!.Contains("stopped sending"),
                $"a download that stalls early is 'didn't finish', not 0 Mbps ({result.Download?.Outcome}, {result.Download?.Mbps}, {result.Download?.Problem})");
            Require(result.Upload is { Outcome: StageOutcome.Failed, Mbps: null },
                $"an upload that stalls early is 'didn't finish' ({result.Upload?.Outcome}, {result.Upload?.Mbps}, {result.Upload?.Problem})");
            Require(CheckAssessment.Summarize(result).Verdict.Tone == Tone.Neutral, "the verdict stays neutral, never red");
        }
        await using (var late = await SpeedFixture.StartAsync(4 * 1024 * 1024, null, token, stallAfterBytes: 10_000_000))
        {
            var options = FixtureOptions(late) with { DownloadByteCap = 60_000_000, UploadByteCap = 60_000_000, LossTargets = [] };
            var result = await Engine(late, new FakePinger()).RunAsync(options, null, token);
            var expected = 4 * 1024 * 1024 * 8 / 1e6;
            Require(result.Download is { Outcome: StageOutcome.Complete, Mbps: { } m, Problem: var p } && Math.Abs(m - expected) / expected < 0.25
                    && p!.Contains("part that ran"),
                $"a late stall keeps the speed of the part that ran (~{expected:0.#} Mbps; got {result.Download?.Mbps:0.#}, {result.Download?.Problem})");
        }
        Console.WriteLine("PASS a stalled server is 'didn't finish' early on, and never turned into 0 Mbps");
    }

    private static async Task LoopbackIcmpAsync(CancellationToken token)
    {
        var pinger = new IcmpPinger();
        var answered = 0;
        for (var i = 0; i < 10; i++)
            if (await pinger.SendAsync(IPAddress.Loopback, TimeSpan.FromSeconds(1), token) is not null)
                answered++;
        Require(answered == 10, $"real unprivileged ICMP to 127.0.0.1 answered {answered}/10");
        Console.WriteLine("PASS real ICMP echo works without administrator rights");
    }

    /// <summary>Runs the full default check against speed.cloudflare.com and the default ping targets.</summary>
    internal static async Task LiveAsync(bool small)
    {
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
        var options = small
            ? CheckOptions.Default with
            {
                DirectionDuration = TimeSpan.FromSeconds(5), DownloadByteCap = 30_000_000, UploadByteCap = 15_000_000,
                LossPingsPerTarget = 50,
            }
            : CheckOptions.Default;
        Console.WriteLine($"Live check against {options.SpeedOrigin} (caps {options.DownloadByteCap / 1e6:0} MB down, " +
            $"{options.UploadByteCap / 1e6:0} MB up, {options.DirectionDuration.TotalSeconds:0} s each way)");
        CheckStage? last = null;
        var result = await new InternetCheckEngine().RunAsync(options, new InlineProgress<CheckProgress>(p =>
        {
            if (p.Stage != last)
                Console.WriteLine($"  … {p.Stage}");
            last = p.Stage;
        }), CancellationToken.None);
        Console.WriteLine($"Server location: {result.ServerLocation ?? "unknown"}");
        Console.WriteLine($"Ping:      {result.Ping?.MedianMs:0.0} ms (n={result.Ping?.Milliseconds.Count}, failed {result.Ping?.Failed})");
        Console.WriteLine($"Jitter:    {result.Ping?.JitterMs:0.0} ms");
        Console.WriteLine($"Download:  {result.Download?.Mbps:0.0} Mbps (avg {result.Download?.AverageMbps:0.0}, " +
            $"{result.Download?.Bytes / 1e6:0.0} MB, {result.Download?.End})");
        Console.WriteLine($"Upload:    {result.Upload?.Mbps:0.0} Mbps (avg {result.Upload?.AverageMbps:0.0}, " +
            $"{result.Upload?.Bytes / 1e6:0.0} MB, {result.Upload?.End})");
        Console.WriteLine($"Ping loss: {(result.Loss?.LossPercent is { } l ? $"{l:0.##} %" : "couldn't measure")} " +
            $"({string.Join("; ", result.Loss?.Targets.Select(t => $"{t.Name} {t.Answered}/{t.Sent}, {t.MedianMs:0} ms") ?? [])})");
        foreach (var note in result.Notes)
            Console.WriteLine($"Note: {note}");
    }

    private static CheckOptions FixtureOptions(SpeedFixture fixture) => CheckOptions.Default with
    {
        SpeedOrigin = fixture.Address,
        DirectionDuration = TimeSpan.FromSeconds(4),
        LatencySamples = 10,
        LossTargets = [new("Answers", "192.0.2.1"), new("Blocks pings", "192.0.2.2")],
        LossPingsPerTarget = 40,
        LossInterval = TimeSpan.FromMilliseconds(25),
    };

    private static InternetCheckEngine Engine(SpeedFixture fixture, IPinger pinger) => new(pinger, handler =>
    {
        handler.UseProxy = false;
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
            certificate is not null && CryptographicOperations.FixedTimeEquals(
                certificate.GetCertHash(HashAlgorithmName.SHA256), fixture.CertificateHash);
    });

    private static bool Within(double value, double expected, double fraction) =>
        Math.Abs(value - expected) <= expected * fraction;

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException("FAIL " + message);
    }

    /// <summary>192.0.2.1 loses every 20th echo (5 %); 192.0.2.2 never answers.</summary>
    private sealed class FakePinger : IPinger
    {
        private int count;

        public async Task<double?> SendAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken)
        {
            await Task.Delay(5, cancellationToken);
            if (address.Equals(IPAddress.Parse("192.0.2.2")))
                return null;
            return Interlocked.Increment(ref count) % 20 == 0 ? null : 12;
        }
    }

    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }
}
