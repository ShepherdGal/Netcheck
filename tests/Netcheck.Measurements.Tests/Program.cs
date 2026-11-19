using System.Net;
using System.Diagnostics;
using Netcheck.Core;
using Netcheck.Measurements;
using Netcheck.TestServer;

try
{
    if (args is ["--updates"])
        UpdateChecks.Run();
    else if (args is ["--history"])
        await HistoryChecks.RunAsync();
    else if (args is ["--assessments"])
        AssessmentChecks.Run();
    else if (args is ["--speed-units"])
        SpeedUnitChecks.Run();
    else if (args is ["--history-copy", var original])
        HistoryChecks.OpenCopy(original);
    else if (args is ["--interrupt-history", var database])
        HistoryChecks.Interrupt(database);
    else if (args is ["--dns-benchmark"])
        await DnsBenchmarkChecks.RunAsync();
    else if (args is ["--dns-https-live"])
        await DnsBenchmarkChecks.LiveHttpsAsync();
    else if (args is ["--live-dns-pairs"])
        await DnsBenchmarkChecks.LivePairsAsync();
    else if (args is ["--live-dns", ..])
        await DnsBenchmarkChecks.LiveAsync(args.Length > 1 ? args[1] : null);
    else if (args is ["--internet-check"])
        await InternetCheckChecks.RunAsync();
    else if (args is ["--live-check"] or ["--live-check", "small"])
        await InternetCheckChecks.LiveAsync(small: args.Length == 2);
    else if (args is ["--compare-curl"])
        await CurlComparison.RunAsync();
    else
        await Run();
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(error);
    return 1;
}

static async Task Run()
{
    Require(MeasurementProtocol.TryOrigin("https://127.0.0.1:7443", out _), "HTTPS origin accepted");
    Require(!MeasurementProtocol.TryOrigin("http://127.0.0.1:7443", out _) &&
        !MeasurementProtocol.TryOrigin("https://user:secret@localhost/", out _) &&
        !MeasurementProtocol.TryOrigin("https://localhost/test?q=1", out _), "unsupported origins rejected");
    var stats = new ProbeMeasurement([20, 30, 25], 1, 0, 1);
    Require(stats.MedianMs == 25 && stats.JitterMs == 7.5 && stats.TimeoutPercent == 25,
        "median, jitter, and HTTPS timeout rate exclude local cancellations");
    Console.WriteLine("PASS origin validation and probe calculations");

    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(180));
    await using var server = await LocalTestEndpoint.StartAsync(deadline.Token, MeasurementProtocol.MiB, TimeSpan.FromMilliseconds(40));
    var provider = new HttpsSpeedTestProvider(_ => null, server.CertificateHash);
    var standard = new MeasurementOptions(server.Address, MeasurementMode.Standard, 4 * MeasurementProtocol.MiB,
        TimeSpan.FromSeconds(18), IncludeSystemDns: false);

    var quick = await provider.RunAsync(standard with { Mode = MeasurementMode.Quick, PayloadBudget = 0 }, null, deadline.Token);
    Require(quick.State == MeasurementState.Complete && quick.PayloadBytes == 0 && quick.Download is null && quick.Upload is null,
        $"quick check has no transfer payload ({quick.State}, {string.Join(", ", quick.Notes)})");
    Require(quick.Idle is { Sent: 6, MedianMs: >= 35 and <= 160 } &&
        quick.Paths.Any(path => IPAddress.IsLoopback(path.LocalAddress)), "40 ms test delay and observed loopback path");
    Console.WriteLine($"PASS Quick HTTPS check and known latency ({quick.Idle!.MedianMs:0.0} ms)");

    var result = await provider.RunAsync(standard, null, deadline.Token);
    Require(result.State == MeasurementState.Complete, $"complete standard measurement ({result.State}, {string.Join(", ", result.Notes)})");
    Require(result.PayloadBytes == standard.PayloadBudget, "counted payload equals budget including warmup");
    Require(result.Download is { MegabitsPerSecond: >= 7.2 and <= 10.5, Loaded.Sent: > 0, PeakMbps: > 0 } &&
        result.Upload is { MegabitsPerSecond: >= 7.2 and <= 10.5, Loaded.Sent: > 0, Acknowledged: true },
        "known 8.39 Mbps cap and direction-specific loaded probes");
    Console.WriteLine($"PASS controlled throughput ({result.Download!.MegabitsPerSecond:0.00} down, " +
        $"{result.Upload!.MegabitsPerSecond:0.00} up Mbps) and exact payload budget");

    using var cancel = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
    MeasurementReadings? readingsAtUpload = null;
    var stopped = await provider.RunAsync(standard, new InlineProgress(report =>
    {
        if (report.Stage == MeasurementStage.Upload)
        {
            readingsAtUpload = report.Readings;
            cancel.Cancel();
        }
    }), cancel.Token);
    Require(stopped.State == MeasurementState.Stopped && stopped.Download?.MegabitsPerSecond is > 0 &&
        stopped.Upload is null && stopped.PayloadBytes < standard.PayloadBudget, "stop retains completed direction");
    Require(readingsAtUpload is { DownloadMbps: > 0, UploadMbps: null, LatencyMs: > 0 } &&
        readingsAtUpload.DownloadMbps == stopped.Download?.MegabitsPerSecond,
        "progress exposes completed download and latency before upload, matching the stopped result");
    Console.WriteLine("PASS cancellation retains the completed download");

    var wrongRoute = await provider.RunAsync(standard with { SelectedAdapter = Guid.NewGuid() }, null, deadline.Token);
    Require(wrongRoute.State == MeasurementState.Failed && wrongRoute.PayloadBytes == 0 &&
        wrongRoute.Notes.Any(note => note.Contains("selected adapter", StringComparison.Ordinal)), "adapter mismatch blocks transfers");
    Console.WriteLine("PASS selected-adapter mismatch blocks payload");

    var wrongPin = new HttpsSpeedTestProvider(_ => null, new byte[32]);
    var untrusted = await wrongPin.RunAsync(standard, null, deadline.Token);
    Require(untrusted.State == MeasurementState.Failed && untrusted.PayloadBytes == 0, "invalid local certificate pin rejected");
    Console.WriteLine("PASS local certificate pin enforced");

    var expired = await provider.RunAsync(standard with { Duration = TimeSpan.FromMilliseconds(20) }, null, deadline.Token);
    Require(expired.State == MeasurementState.TimedOut && expired.PayloadBytes == 0, "overall time allowance is enforced");
    Console.WriteLine("PASS overall deadline");

    var sustained = standard with
    {
        PayloadBudget = MeasurementProtocol.SustainedBudgetLimit,
        SustainedDuration = TimeSpan.FromSeconds(4)
    };
    var steady = await provider.RunAsync(sustained, null, deadline.Token);
    Require(steady.State == MeasurementState.Complete && steady.PayloadBytes < sustained.PayloadBudget,
        $"sustained stage deadline with 64-bit budget ({steady.State}, {string.Join(", ", steady.Notes)})");
    foreach (var transfer in new[] { steady.Download, steady.Upload })
    {
        Require(transfer is { End: TransferEnd.TargetDuration, PeakBulkStreams: 3, Samples.Count: 3,
            MegabitsPerSecond: >= 14 and <= 38, Loaded.MedianMs: >= 35 and <= 180 },
            $"sustained paced workload, excluding calibration ({transfer})");
    }
    Require(steady.Upload!.VerifiedBytes > 0 && steady.Upload.VerifiedBytes <= steady.Upload.Bytes,
        "only server-acknowledged chunks feed final upload rate");
    Console.WriteLine($"PASS sustained pacing ({steady.Download!.MegabitsPerSecond:0.0} down, " +
        $"{steady.Upload.MegabitsPerSecond:0.0} up Mbps), loaded latency and 6 GiB allowance");

    var lowCap = sustained with { PayloadBudget = 2L * MeasurementProtocol.MiB + 1 };
    var capped = await provider.RunAsync(lowCap, null, deadline.Token);
    Require(capped.State == MeasurementState.Partial && capped.PayloadBytes == lowCap.PayloadBudget &&
        capped.Download is { End: TransferEnd.ByteLimit, Bytes: 1048576, MegabitsPerSecond: null } &&
        capped.Upload is { End: TransferEnd.ByteLimit, Bytes: 1048577, MegabitsPerSecond: null },
        "parallel workers share exact split caps and short transfers do not yield sustained rates");
    Console.WriteLine("PASS cap in both directions and insufficient sampling");

    using var stopSustained = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
    var partial = await provider.RunAsync(sustained, new InlineProgress(report =>
    {
        if (report.Stage == MeasurementStage.Upload && report.CurrentMbps is > 0)
            stopSustained.Cancel();
    }), stopSustained.Token);
    Require(partial.State == MeasurementState.Stopped &&
        partial.Download is { End: TransferEnd.TargetDuration, MegabitsPerSecond: > 0 } &&
        partial.Upload is { End: TransferEnd.Interrupted, Bytes: > 0 },
        "cancellation preserves completed download and in-progress upload evidence");
    Console.WriteLine("PASS stop during sustained upload retains both directions");

    var gatewayChanged = false;
    var routeAware = new HttpsSpeedTestProvider(_ => null, server.CertificateHash, _ =>
        new RouteObservation(null, IPAddress.Loopback, gatewayChanged ? IPAddress.IPv6Loopback : IPAddress.Loopback));
    var changed = await routeAware.RunAsync(sustained, new InlineProgress(report =>
    {
        if (report.Stage == MeasurementStage.Download && report.CurrentMbps is > 0)
            gatewayChanged = true;
    }), deadline.Token);
    Require(changed.State == MeasurementState.Partial && changed.Download is { End: TransferEnd.RouteChanged, Bytes: > 0 } &&
        changed.Upload is null, "a changed gateway interrupts the measured direction and skips upload");
    Console.WriteLine("PASS observed route change retains download evidence and skips upload");

    var expiredSustained = await provider.RunAsync(sustained with { Duration = TimeSpan.FromSeconds(3) }, null, deadline.Token);
    Require(expiredSustained.State == MeasurementState.TimedOut && expiredSustained.Download is { Bytes: > 0 } &&
        expiredSustained.Upload is null, "the overall deadline retains the active direction");
    Console.WriteLine("PASS sustained overall deadline retains active samples");

    await using var fastServer = await LocalTestEndpoint.StartAsync(deadline.Token);
    var fastProvider = new HttpsSpeedTestProvider(_ => null, fastServer.CertificateHash);
    using var process = Process.GetCurrentProcess();
    var baseline = process.PrivateMemorySize64;
    var peak = baseline;
    var fastRun = fastProvider.RunAsync(sustained with
    {
        Endpoint = fastServer.Address,
        PayloadBudget = 512L * MeasurementProtocol.MiB
    }, null, deadline.Token);
    while (!fastRun.IsCompleted)
    {
        await Task.WhenAny(fastRun, Task.Delay(50, deadline.Token));
        process.Refresh();
        peak = Math.Max(peak, process.PrivateMemorySize64);
    }
    var fast = await fastRun;
    Require(fast.State is MeasurementState.Partial or MeasurementState.Complete &&
        fast.PayloadBytes <= fast.Options.PayloadBudget && fast.PayloadBytes > fast.Options.PayloadBudget / 4 &&
        fast.Download?.PeakBulkStreams is <= 3 && fast.Upload?.PeakBulkStreams is <= 3,
        "fast loopback load remains bounded");
    Console.WriteLine($"PASS fast loopback, {fast.PayloadBytes / (double)MeasurementProtocol.MiB:0.#} MiB streamed");
    Require(peak - baseline < 128L * MeasurementProtocol.MiB, "fast run stays below the fixture's private memory growth ceiling");
    Console.WriteLine($"PASS sampled private memory growth ({(peak - baseline) / (double)MeasurementProtocol.MiB:0.0} MiB, client and fixture in one process)");

    var productionWorkload = await provider.RunAsync(sustained with
    {
        Duration = TimeSpan.FromSeconds(55),
        SustainedDuration = TimeSpan.FromSeconds(20),
        PayloadBudget = 512L * MeasurementProtocol.MiB
    }, null, deadline.Token);
    Require(productionWorkload.State == MeasurementState.Complete &&
        productionWorkload.Download is { End: TransferEnd.TargetDuration, Samples.Count: 19 } &&
        productionWorkload.Upload is { End: TransferEnd.TargetDuration, Samples.Count: 19 } &&
        productionWorkload.Ended - productionWorkload.Started < TimeSpan.FromSeconds(55),
        $"default timed workload completes on the paced fixture ({string.Join(", ", productionWorkload.Notes)})");
    Console.WriteLine($"PASS both full 20-second stages within the 55-second deadline, " +
        $"{productionWorkload.PayloadBytes / (double)MeasurementProtocol.MiB:0.0} MiB transferred");

    await using var stalledServer = await LocalTestEndpoint.StartAsync(deadline.Token, bytesPerSecond: 1);
    var stalledProvider = new HttpsSpeedTestProvider(_ => null, stalledServer.CertificateHash);
    var stalled = await stalledProvider.RunAsync(sustained with
    {
        Endpoint = stalledServer.Address,
        SustainedDuration = TimeSpan.FromSeconds(10)
    }, null, deadline.Token);
    Require(stalled.State == MeasurementState.Partial &&
        stalled.Download is { End: TransferEnd.TimeLimit, MegabitsPerSecond: null } &&
        stalled.Upload is { End: TransferEnd.TimeLimit, MegabitsPerSecond: null },
        "stalled requests stop at their request deadlines and do not publish sustained rates");
    Console.WriteLine("PASS stalled transfer deadlines and unavailable throughput");

    var interruption = 0;
    await using var unstableServer = await LocalTestEndpoint.StartAsync(deadline.Token, MeasurementProtocol.MiB,
        interruptTransfers: () => Volatile.Read(ref interruption) != 0);
    var unstableProvider = new HttpsSpeedTestProvider(_ => null, unstableServer.CertificateHash);
    var recoveryOptions = sustained with { Endpoint = unstableServer.Address };
    var disconnected = await unstableProvider.RunAsync(recoveryOptions, new InlineProgress(report =>
    {
        if (report.Stage == MeasurementStage.Upload && report.CurrentMbps is > 0)
            Interlocked.Exchange(ref interruption, 1);
    }), deadline.Token);
    Require(disconnected.State == MeasurementState.Partial &&
        disconnected.Download is { End: TransferEnd.TargetDuration, MegabitsPerSecond: > 0 } &&
        disconnected.Upload is { End: TransferEnd.Interrupted, Bytes: > 0 },
        "a sustained endpoint disconnect retains completed and partial directions");
    Interlocked.Exchange(ref interruption, 0);
    var reconnected = await unstableProvider.RunAsync(recoveryOptions, null, deadline.Token);
    Require(reconnected.State == MeasurementState.Complete, "a new test recovers after the endpoint reconnects");
    Console.WriteLine("PASS injected disconnect, partial retention and fresh run on the same endpoint");

    var wide = await fastProvider.RunAsync(sustained with
    {
        Endpoint = fastServer.Address,
        Duration = TimeSpan.FromSeconds(55),
        SustainedDuration = TimeSpan.FromSeconds(20)
    }, null, deadline.Token);
    Require(wide.State is MeasurementState.Complete or MeasurementState.Partial &&
        wide.PayloadBytes is > int.MaxValue and <= MeasurementProtocol.SustainedBudgetLimit &&
        wide.Download is { Bytes: > 0 } && wide.Upload is { VerifiedBytes: > 0 } &&
        wide.Download.Bytes + wide.Upload.Bytes == wide.PayloadBytes,
        "actual loopback traffic crosses the signed 32-bit boundary without exceeding the selected cap");
    Console.WriteLine($"PASS 64-bit transfer accounting ({wide.PayloadBytes:N0} measured bytes)");

    var thorough = sustained with { Mode = MeasurementMode.Thorough, PayloadBudget = 512L * MeasurementProtocol.MiB + 2 };
    var seen = new List<long>();
    async Task<MeasurementResult> Repeat(MeasurementOptions attempt, CancellationToken token)
    {
        seen.Add(attempt.PayloadBudget);
        return await provider.RunAsync(attempt, null, token);
    }
    var repeats = await RepeatedHttpsTest.RunAsync(thorough, Repeat, () => true, deadline.Token);
    Require(repeats.State == MeasurementState.Complete && repeats.Repeats?.Count == 3 &&
        seen.Count == 3 && seen.Sum() == thorough.PayloadBudget && seen.Max() - seen.Min() == 1 &&
        repeats.PayloadBytes == repeats.Repeats?.Sum(run => run.PayloadBytes),
        "three sustained runs use one evenly split allowance");
    Console.WriteLine("PASS Thorough completes three runs under a single reviewed cap");

    var cappedRepeat = await RepeatedHttpsTest.RunAsync(thorough with { PayloadBudget = 6L * MeasurementProtocol.MiB },
        Repeat, () => true, deadline.Token);
    Require(cappedRepeat.State == MeasurementState.Partial && cappedRepeat.Repeats?.Count == 1 &&
        cappedRepeat.PayloadBytes == 2L * MeasurementProtocol.MiB, "a cap-limited repeat stops the batch");
    var costChanged = await RepeatedHttpsTest.RunAsync(thorough,
        (_, _) => throw new InvalidOperationException("No repeat should start"), () => false, deadline.Token);
    Require(costChanged.State == MeasurementState.Partial && costChanged.Repeats?.Count == 0 &&
        costChanged.PayloadBytes == 0, "changed connection cost blocks a repeat before traffic");
    Console.WriteLine("PASS Thorough stops on partial results and skips traffic when the connection cost changes");
}

static void Require(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}

file sealed class InlineProgress(Action<MeasurementProgress> report) : IProgress<MeasurementProgress>
{
    public void Report(MeasurementProgress value) => report(value);
}
