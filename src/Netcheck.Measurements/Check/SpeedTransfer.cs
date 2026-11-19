using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using Netcheck.Core;

namespace Netcheck.Measurements.Check;

/// <summary>
/// Multi-stream download or upload against Cloudflare-style endpoints (<c>__down?bytes=N</c>, <c>POST __up</c>).
/// Requests grow from 100 kB so slow links still finish requests quickly, and every stream stops at the shared
/// byte cap or when the direction's time runs out.
/// </summary>
internal static class SpeedTransfer
{
    // Up to 50 MB per request (P13, 2026-11-17): a fast check makes about half as many requests to the shared speed
    // server (Cloudflare rate-limits with HTTP 429). Bytes are counted as they arrive, so the size doesn't change the speed.
    private static readonly long[] DownloadSizes = [100_000, 1_000_000, 10_000_000, 25_000_000, 50_000_000];
    private const long FirstUploadSize = 100_000;
    private static readonly TimeSpan Tick = TimeSpan.FromMilliseconds(250);

    internal static async Task<SpeedReading> RunAsync(HttpClient client, Uri origin, bool upload, int streams,
        TimeSpan duration, long cap, Action<double, double?>? report, CancellationToken userToken)
    {
        long transferred = 0, reserved = 0;
        var capHit = 0;
        var busy = 0;   // 1 once the server said "slow down" (429) or "busy" (503)
        string? problem = null;
        // Upload bytes only count once the server has confirmed the whole request; each request's bytes are
        // spread evenly over its own start→finish time. Counting at write time would include data still sitting
        // in Windows' send buffers and overstate the speed.
        var confirmed = new List<(double Start, double End, long Bytes)>();
        using var window = CancellationTokenSource.CreateLinkedTokenSource(userToken);
        window.CancelAfter(duration);
        var clock = Stopwatch.StartNew();

        // "Slow down" (429) or "busy" (503): wait as long as the server asks (at most 2 s, else 1 s) and try again.
        // Until 2026-11-16 a connection gave up for good on the first 429; in a real check all six download
        // connections died after 0.3 s, the gauge froze at its last value and the result turned into "—".
        async Task<bool> BackedOffAsync(HttpResponseMessage response)
        {
            if (response.StatusCode is not (HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable))
                return false;
            Interlocked.Exchange(ref busy, 1);
            Interlocked.CompareExchange(ref problem, response.StatusCode == HttpStatusCode.TooManyRequests
                ? "The speed server asked us to slow down (HTTP 429)." : "The speed server was busy (HTTP 503).", null);
            var wait = response.Headers.RetryAfter?.Delta ??
                       (response.Headers.RetryAfter?.Date is { } at ? at - DateTimeOffset.UtcNow : (TimeSpan?)null) ??
                       TimeSpan.FromSeconds(1);
            wait = wait < TimeSpan.FromMilliseconds(200) ? TimeSpan.FromMilliseconds(200) : wait > MaxBackoff ? MaxBackoff : wait;
            await Task.Delay(wait, window.Token).ConfigureAwait(false);
            return true;
        }

        async Task Worker()
        {
            var sizes = DownloadSizes;
            var step = 0;
            long uploadSize = FirstUploadSize;
            try
            {
                while (!window.IsCancellationRequested)
                {
                    var size = upload ? uploadSize : sizes[Math.Min(step++, sizes.Length - 1)];
                    var before = Interlocked.Add(ref reserved, size) - size;
                    if (before >= cap)
                    {
                        Interlocked.Exchange(ref capHit, 1);
                        return;
                    }
                    size = Math.Min(size, cap - before);
                    if (upload)
                    {
                        var start = clock.Elapsed.TotalSeconds;
                        using var content = new CountingContent(size, _ => { });
                        using var response = await client.PostAsync(new Uri(origin, "__up"), content, window.Token)
                            .ConfigureAwait(false);
                        if (await BackedOffAsync(response).ConfigureAwait(false))
                        {
                            Interlocked.Add(ref reserved, -size);   // nothing arrived: give the reservation back
                            continue;
                        }
                        response.EnsureSuccessStatusCode();
                        var end = clock.Elapsed.TotalSeconds;
                        lock (confirmed)
                            confirmed.Add((start, end, size));
                        Interlocked.Add(ref transferred, size);
                        uploadSize = NextUploadSize(size, end - start);
                    }
                    else
                    {
                        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(origin, $"__down?bytes={size}"));
                        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, window.Token)
                            .ConfigureAwait(false);
                        if (await BackedOffAsync(response).ConfigureAwait(false))
                        {
                            Interlocked.Add(ref reserved, -size);   // nothing arrived: give the reservation back
                            continue;
                        }
                        response.EnsureSuccessStatusCode();
                        await using var body = await response.Content.ReadAsStreamAsync(window.Token).ConfigureAwait(false);
                        var buffer = new byte[64 * 1024];
                        int read;
                        while ((read = await body.ReadAsync(buffer, window.Token).ConfigureAwait(false)) > 0)
                            Interlocked.Add(ref transferred, read);
                    }
                }
            }
            catch (Exception) when (window.IsCancellationRequested)
            {
                // Time is up (or the user stopped): in-flight bytes already counted.
            }
            catch (Exception error) when (error is HttpRequestException or IOException)
            {
                if (error is HttpRequestException { StatusCode: HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable })
                    Interlocked.Exchange(ref busy, 1);
                Interlocked.CompareExchange(ref problem, Describe(error), null);
            }
        }

        IReadOnlyList<(double, long)> Confirmed(IEnumerable<double> times)
        {
            lock (confirmed)
                return SpeedMath.Spread(confirmed, times);
        }

        var points = new List<(double Seconds, long Bytes)> { (0, 0) };
        var workers = Task.WhenAll(Enumerable.Range(0, streams).Select(_ => Task.Run(Worker)));
        using (var timer = new PeriodicTimer(Tick))
        {
            while (!workers.IsCompleted)
            {
                await Task.WhenAny(timer.WaitForNextTickAsync().AsTask(), workers).ConfigureAwait(false);
                points.Add((clock.Elapsed.TotalSeconds, Interlocked.Read(ref transferred)));
                // Live value = the same "typical high speed" the result uses, over the seconds so far, once there is
                // enough to work it out; before that, the last second's rate. The gauge then settles towards the result
                // instead of jumping at the end (user report 2026-11-16: live 0–1,163 Mbps, result 956 Mbps).
                var sofar = upload ? Confirmed(points.Select(p => p.Seconds)) : points;
                var live = clock.Elapsed >= LiveSettled ? SpeedMath.Summarize(sofar) ?? SpeedMath.Recent(sofar) : SpeedMath.Recent(sofar);
                report?.Invoke(Math.Min(1, clock.Elapsed / duration), live);
            }
        }
        await workers.ConfigureAwait(false);
        var elapsed = clock.Elapsed;
        var bytes = Interlocked.Read(ref transferred);
        if (points[^1].Bytes != bytes || points[^1].Seconds < elapsed.TotalSeconds - 0.01)
            points.Add((elapsed.TotalSeconds, bytes));
        if (upload)
            points = Confirmed(points.Select(p => p.Seconds)).ToList();
        var samples = SpeedMath.Samples(points);
        // A failed transfer after the server refused us is "server busy", not a fault of the user's line.
        SpeedReading Busy(SpeedReading reading) => busy == 1 ? reading with { ServerBusy = true } : reading;

        if (userToken.IsCancellationRequested)
            return new SpeedReading(StageOutcome.Stopped, null, bytes, elapsed, samples, streams, SpeedEnd.Stopped, problem);
        if (bytes == 0)
            return Busy(new SpeedReading(StageOutcome.Failed, null, 0, elapsed, samples, streams, SpeedEnd.Failed,
                problem ?? "No data was transferred."));
        // The data limit only counts as reached when the bytes actually arrived. Reservations alone can pass the
        // limit while the server is refusing requests (HTTP 429), which once turned a 0.5 s fragment into a "result".
        var reachedCap = capHit == 1 && bytes >= cap * 0.9;
        if (problem is not null && !reachedCap && elapsed < duration * 0.5)
            return Busy(new SpeedReading(StageOutcome.Failed, null, bytes, elapsed, samples, streams, SpeedEnd.Failed, problem));

        // Real case 2026-11-16: 49 MB arrived in ~1 s, then the server stopped sending and one request hung until
        // time ran out. Every 1-second window after the ramp-up was empty, so the speed came out as "0 Mbps" and was
        // rated red. Speed is now taken only up to the moment data stopped arriving.
        var activeEnd = SpeedMath.ActiveEnd(points);
        var idleTail = elapsed.TotalSeconds - activeEnd;
        // Upload bytes only count when a request is confirmed, so an in-flight request at the end looks idle for
        // up to ~0.5 s (longer on very slow links): give uploads more slack before calling it a stall.
        var stalled = !reachedCap && idleTail >= (upload ? StallUpload : StallDownload);
        if (stalled && activeEnd < duration.TotalSeconds * 0.5)
            return Busy(new SpeedReading(StageOutcome.Failed, null, bytes, elapsed, samples, streams, SpeedEnd.Failed,
                problem ?? Stalled));
        var active = reachedCap || stalled ? points.Where(p => p.Seconds <= activeEnd).ToList() : points;
        var mbps = SpeedMath.Summarize(active);
        if (mbps is not > 0)
            return Busy(new SpeedReading(StageOutcome.Failed, null, bytes, elapsed, samples, streams, SpeedEnd.Failed,
                problem ?? "Too little data arrived to work out a speed."));
        if (stalled)
            problem ??= Stalled + " The speed is from the part that ran.";
        var end = reachedCap && activeEnd < duration.TotalSeconds ? SpeedEnd.ByteCap : SpeedEnd.Duration;
        return new SpeedReading(StageOutcome.Complete, mbps, bytes, elapsed, samples, streams, end, problem);
    }

    private const double StallDownload = 1.0, StallUpload = 2.5;
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan LiveSettled = TimeSpan.FromSeconds(2.5);
    private const string Stalled = "The speed server stopped sending data part-way through.";

    /// <summary>Aim for ~0.5 s per upload request: big enough to keep the link busy, small enough for fine timing.</summary>
    private static long NextUploadSize(long size, double seconds)
    {
        var target = seconds > 0 ? size / seconds * 0.5 : size * 4;
        return (long)Math.Clamp(target, FirstUploadSize, Math.Min(size * 4d, 25_000_000));
    }

    private static string Describe(Exception error) => error switch
    {
        HttpRequestException { StatusCode: HttpStatusCode.TooManyRequests } => "The speed server asked us to slow down (HTTP 429).",
        HttpRequestException { StatusCode: { } code } => $"The speed server answered HTTP {(int)code}.",
        HttpRequestException => "Couldn't connect to the speed server.",
        _ => "The connection to the speed server dropped.",
    };

    /// <summary>Upload body of a fixed length that reports bytes as they are handed to the connection.</summary>
    private sealed class CountingContent(long length, Action<int> sent) : HttpContent
    {
        private static readonly byte[] Chunk = RandomNumberGenerator.GetBytes(64 * 1024);

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context,
            CancellationToken cancellationToken)
        {
            var remaining = length;
            while (remaining > 0)
            {
                var n = (int)Math.Min(Chunk.Length, remaining);
                await stream.WriteAsync(Chunk.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
                remaining -= n;
                sent(n);
            }
        }

        protected override bool TryComputeLength(out long length2)
        {
            length2 = length;
            return true;
        }
    }
}

/// <summary>Pure throughput math, kept separate so it can be checked without a network.</summary>
public static class SpeedMath
{
    /// <summary>
    /// The reported speed: the 90th percentile of 1-second windows after the ramp-up period
    /// (the first 1.5 s, or the first quarter of a short transfer). Falls back to the average
    /// after ramp-up, then the overall average, when there are too few windows.
    /// </summary>
    public static double? Summarize(IReadOnlyList<(double Seconds, long Bytes)> points)
    {
        if (points.Count < 2 || points[^1].Bytes <= 0 || points[^1].Seconds <= 0)
            return null;
        var total = points[^1].Seconds;
        var ramp = Math.Min(1.5, total * 0.25);
        var windows = new List<double>();
        for (var i = 1; i < points.Count; i++)
        {
            var (t, b) = points[i];
            if (t < ramp + 1.0)
                continue;
            var j = i - 1;
            while (j > 0 && points[j].Seconds > t - 1.0)
                j--;
            var span = t - points[j].Seconds;
            if (span >= 0.75)
                windows.Add((b - points[j].Bytes) * 8e-6 / span);
        }
        if (windows.Count >= 2)
        {
            windows.Sort();
            return windows[(int)Math.Ceiling(0.9 * windows.Count) - 1];
        }
        var start = points.LastOrDefault(p => p.Seconds <= ramp);
        var afterRamp = total - start.Seconds;
        if (afterRamp >= 0.5 && points[^1].Bytes > start.Bytes)
            return (points[^1].Bytes - start.Bytes) * 8e-6 / afterRamp;
        return points[^1].Bytes * 8e-6 / total;
    }

    /// <summary>When the last new byte arrived (the first point that already holds the final total).</summary>
    public static double ActiveEnd(IReadOnlyList<(double Seconds, long Bytes)> points)
    {
        if (points.Count == 0)
            return 0;
        var final = points[^1].Bytes;
        foreach (var p in points)
            if (p.Bytes >= final)
                return p.Seconds;
        return points[^1].Seconds;
    }

    /// <summary>Live rate over roughly the last second, for gauges only.</summary>
    public static double? Recent(IReadOnlyList<(double Seconds, long Bytes)> points)
    {
        if (points.Count < 2)
            return null;
        var last = points[^1];
        var j = points.Count - 2;
        while (j > 0 && points[j].Seconds > last.Seconds - 1.0)
            j--;
        var span = last.Seconds - points[j].Seconds;
        return span > 0 ? (last.Bytes - points[j].Bytes) * 8e-6 / span : null;
    }

    /// <summary>
    /// Cumulative bytes at each time, where every completed request's bytes are spread evenly between its start and end.
    /// </summary>
    public static IReadOnlyList<(double Seconds, long Bytes)> Spread(
        IReadOnlyCollection<(double Start, double End, long Bytes)> requests, IEnumerable<double> times) =>
        times.Select(t => (t, (long)requests.Sum(r =>
            r.End <= r.Start ? (t >= r.End ? r.Bytes : 0)
            : r.Bytes * Math.Clamp((t - r.Start) / (r.End - r.Start), 0, 1)))).ToArray();

    public static IReadOnlyList<ThroughputSample> Samples(IReadOnlyList<(double Seconds, long Bytes)> points) =>
        points.Zip(points.Skip(1), (a, b) => b.Seconds > a.Seconds
                ? new ThroughputSample(b.Seconds, (b.Bytes - a.Bytes) * 8e-6 / (b.Seconds - a.Seconds))
                : null)
            .OfType<ThroughputSample>().ToArray();
}
