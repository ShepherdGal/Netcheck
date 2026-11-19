using System.Diagnostics;
using System.Globalization;
using System.Net;
using Netcheck.Core;

namespace Netcheck.Measurements.Check;

/// <summary>
/// "Check my internet": idle ping and jitter → download → upload → ping loss, one after another so the
/// stages don't disturb each other. Stopping keeps every completed stage; failures are reported, never guessed.
/// </summary>
public sealed class InternetCheckEngine(IPinger? pinger = null, Action<SocketsHttpHandler>? configureHandler = null)
{
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(2);
    private readonly IPinger pinger = pinger ?? new IcmpPinger();

    public async Task<InternetCheckResult> RunAsync(CheckOptions options, IProgress<CheckProgress>? progress,
        CancellationToken cancellationToken)
    {
        if (options.Validate() is { } invalid)
            throw new ArgumentException(invalid, nameof(options));

        var started = DateTimeOffset.UtcNow;
        var notes = new List<string>();
        LatencyReading? ping = null;
        SpeedReading? download = null, upload = null;
        PingLossReading? loss = null;
        string? location = null;

        using var probeHandler = CreateHandler(1);
        using var probeClient = CreateClient(probeHandler);
        using var transferHandler = CreateHandler(Math.Max(options.DownloadStreams, options.UploadStreams));
        using var transferClient = CreateClient(transferHandler);

        progress?.Report(new CheckProgress(CheckStage.Ping, 0));
        (ping, location) = await MeasureLatencyAsync(probeClient, options, f =>
            progress?.Report(new CheckProgress(CheckStage.Ping, f)), cancellationToken).ConfigureAwait(false);

        var reachable = ping.Milliseconds.Count > 0;
        if (!reachable && !cancellationToken.IsCancellationRequested)
            notes.Add("Couldn't reach the speed server, so download and upload were skipped.");

        if (reachable && !cancellationToken.IsCancellationRequested)
        {
            progress?.Report(new CheckProgress(CheckStage.Download, 0));
            download = await SpeedTransfer.RunAsync(transferClient, options.SpeedOrigin, upload: false,
                options.DownloadStreams, options.DirectionDuration, options.DownloadByteCap,
                (f, mbps) => progress?.Report(new CheckProgress(CheckStage.Download, f, mbps)), cancellationToken)
                .ConfigureAwait(false);
            AddNote(notes, "Download", download);
            // The gauge shows the stage's real outcome straight away: the result, or "—" when it didn't finish.
            progress?.Report(new CheckProgress(CheckStage.Download, 1, download.Mbps ?? 0));
        }

        if (reachable && !cancellationToken.IsCancellationRequested)
        {
            progress?.Report(new CheckProgress(CheckStage.Upload, 0));
            upload = await SpeedTransfer.RunAsync(transferClient, options.SpeedOrigin, upload: true,
                options.UploadStreams, options.DirectionDuration, options.UploadByteCap,
                (f, mbps) => progress?.Report(new CheckProgress(CheckStage.Upload, f, mbps)), cancellationToken)
                .ConfigureAwait(false);
            AddNote(notes, "Upload", upload);
            progress?.Report(new CheckProgress(CheckStage.Upload, 1, upload.Mbps ?? 0));
        }

        if (options.LossTargets.Count > 0 && !cancellationToken.IsCancellationRequested)
        {
            progress?.Report(new CheckProgress(CheckStage.PingLoss, 0));
            loss = await PingLossRunner.RunAsync(pinger, options,
                f => progress?.Report(new CheckProgress(CheckStage.PingLoss, f)), cancellationToken).ConfigureAwait(false);
            foreach (var blocked in loss.Targets.Where(t => !t.Reachable && t.Sent > 0))
                notes.Add($"{blocked.Name} ({blocked.Address}) didn't answer any pings, so it wasn't counted.");
        }

        return new InternetCheckResult(started, DateTimeOffset.UtcNow, cancellationToken.IsCancellationRequested,
            ping, download, upload, loss, location, notes);
    }

    private static void AddNote(List<string> notes, string direction, SpeedReading reading)
    {
        if (reading.Outcome == StageOutcome.Failed)
            notes.Add($"{direction} failed: {reading.Problem}");
        else if (reading.Outcome == StageOutcome.Complete && reading.End == SpeedEnd.ByteCap)
            notes.Add($"{direction} reached its data limit before the time was up.");
        else if (reading.Outcome == StageOutcome.Complete && reading.Problem is { } problem)
            notes.Add($"{direction}: some connections had trouble ({problem}).");
    }

    /// <summary>
    /// Warm-up request (opens the TLS connection), then sequential tiny requests on that one connection.
    /// The server's own processing time (Server-Timing dur) is subtracted when reported.
    /// </summary>
    private static async Task<(LatencyReading Reading, string? Location)> MeasureLatencyAsync(HttpClient client,
        CheckOptions options, Action<double> report, CancellationToken cancellationToken)
    {
        var samples = new List<double>();
        var failed = 0;
        string? location = null;
        var target = new Uri(options.SpeedOrigin, "__down?bytes=0");
        try
        {
            for (var i = -1; i < options.LatencySamples; i++)
            {
                using var probe = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                probe.CancelAfter(ProbeTimeout);
                try
                {
                    var clock = Stopwatch.StartNew();
                    using var response = await client.GetAsync(target, HttpCompletionOption.ResponseHeadersRead, probe.Token)
                        .ConfigureAwait(false);
                    var elapsed = clock.Elapsed.TotalMilliseconds;
                    response.EnsureSuccessStatusCode();
                    await response.Content.CopyToAsync(Stream.Null, probe.Token).ConfigureAwait(false);
                    location ??= Colo(response);
                    if (i < 0)
                        continue; // warm-up includes connection setup
                    var server = ServerMilliseconds(response);
                    samples.Add(server is { } s && s >= 0 && s < elapsed ? elapsed - s : elapsed);
                }
                catch (Exception error) when (!cancellationToken.IsCancellationRequested &&
                    error is HttpRequestException or IOException or OperationCanceledException)
                {
                    if (i >= 0)
                        failed++;
                    else if (error is HttpRequestException { StatusCode: null })
                        return (new LatencyReading(StageOutcome.Failed, samples, options.LatencySamples), null);
                }
                report((i + 1d) / options.LatencySamples);
            }
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            return (new LatencyReading(StageOutcome.Stopped, samples, failed), location);
        }
        var outcome = samples.Count == 0 ? StageOutcome.Failed : StageOutcome.Complete;
        return (new LatencyReading(outcome, samples, failed), location);
    }

    internal static double? ServerMilliseconds(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Server-Timing", out var values) ? ServerMilliseconds(values) : null;

    /// <summary>
    /// Server processing time from <c>Server-Timing</c>. Cloudflare reports several overlapping timings
    /// (e.g. <c>cfSpeedEdge;dur=6, cfSpeedWorker;dur=30</c>), so the largest one is used: subtracting their sum
    /// would remove real network time. Entries without <c>dur</c> (such as <c>cfL4;desc=…</c>) are ignored.
    /// </summary>
    public static double? ServerMilliseconds(IEnumerable<string> values)
    {
        double? largest = null;
        foreach (var part in values.SelectMany(v => v.Split([',', ';'], StringSplitOptions.TrimEntries)))
            if (part.StartsWith("dur=", StringComparison.OrdinalIgnoreCase) &&
                double.TryParse(part.AsSpan(4), NumberStyles.Float, CultureInfo.InvariantCulture, out var ms) &&
                double.IsFinite(ms) && ms >= 0)
                largest = Math.Max(largest ?? 0, ms);
        return largest;
    }

    /// <summary>Cloudflare data-centre code from the <c>cf-ray</c> header ("…-TLV" → "TLV"). Not an address.</summary>
    private static string? Colo(HttpResponseMessage response) =>
        response.Headers.TryGetValues("cf-ray", out var values) && values.FirstOrDefault() is { } ray &&
        ray.LastIndexOf('-') is var dash and > 0 && ray.Length - dash - 1 is >= 2 and <= 5
            ? ray[(dash + 1)..].ToUpperInvariant()
            : null;

    private SocketsHttpHandler CreateHandler(int connections)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            MaxConnectionsPerServer = connections,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
        };
        configureHandler?.Invoke(handler);
        return handler;
    }

    private static HttpClient CreateClient(HttpMessageHandler handler)
    {
        var client = new HttpClient(handler, disposeHandler: false)
        {
            Timeout = Timeout.InfiniteTimeSpan,
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Netcheck/1.0");
        client.DefaultRequestHeaders.AcceptEncoding.ParseAdd("identity");
        return client;
    }
}
