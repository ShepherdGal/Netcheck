using System.Diagnostics;
using System.Globalization;
using System.Net;
using Netcheck.Core;

namespace Netcheck.Measurements;

public sealed partial class HttpsSpeedTestProvider
{
    private const int WindowMilliseconds = 1_000;
    private const int RequestLimit = 384;
    private const int InitialChunkBytes = 128 * 1024;

    private static async Task<TransferMeasurement> Sustain(HttpClient client, MeasurementStage stage,
        long allowance, EndpointCapabilities endpoint, TimeSpan duration, Action<int> count, Action<double> report,
        Func<bool> routeChanged, CancellationToken token)
    {
        using var phase = CancellationTokenSource.CreateLinkedTokenSource(token);
        var stageStart = Stopwatch.GetTimestamp();
        phase.CancelAfter(duration);
        var download = stage == MeasurementStage.Download;
        var windowCount = (int)Math.Ceiling(duration.TotalMilliseconds / WindowMilliseconds);
        var measured = new long[windowCount];
        var probes = new Probes();
        var peakStreams = 0;
        var activeStreams = 0;
        var requests = 0;
        var reserved = 0L;
        var transferred = 0L;
        var verified = 0L;
        var lastCompleted = stageStart;
        var stop = (int)TransferEnd.TargetDuration;
        var maxStreams = endpoint.MaxSustainedStreams;
        var allocationLock = new object();

        var workers = Enumerable.Range(0, maxStreams).Select(TransferWorker).ToArray();
        var monitoring = Monitor();
        try { await Task.WhenAll(workers).ConfigureAwait(false); }
        finally
        {
            await phase.CancelAsync().ConfigureAwait(false);
            await monitoring.ConfigureAwait(false);
        }

        var elapsed = Stopwatch.GetElapsedTime(stageStart, lastCompleted);
        var end = token.IsCancellationRequested ? TransferEnd.Interrupted : (TransferEnd)stop;
        if (end == TransferEnd.TargetDuration)
        {
            if (transferred == allowance)
                end = TransferEnd.ByteLimit;
            else
                elapsed = duration;
        }
        var samples = Windows(measured, elapsed);
        var rate = samples.Length >= 2 && samples.Count(sample => sample.MegabitsPerSecond > 0) >= 2
            ? MeasurementStatistics.Median(samples.Select(sample => sample.MegabitsPerSecond))
            : null;
        return new TransferMeasurement(transferred, elapsed, end, verified > 0, samples,
            probes.Result(), rate > 0 ? rate : null, IsSustained: true, PeakBulkStreams: peakStreams,
            VerifiedBytes: download ? transferred : verified);

        async Task TransferWorker(int index)
        {
            // Start with one stream and ramp to the advertised concurrency during calibration.
            var chunk = (long)InitialChunkBytes;
            var buffer = download ? new byte[64 * 1024] : null;
            var uploadWindows = download ? null : new long[windowCount];
            try
            {
                if (index > 0)
                    await Task.Delay(250 * index, phase.Token).ConfigureAwait(false);
                while (!phase.IsCancellationRequested)
                {
                    long size;
                    lock (allocationLock)
                    {
                        if (reserved == allowance)
                            return;
                        if (requests >= RequestLimit)
                        {
                            Interlocked.CompareExchange(ref stop, (int)TransferEnd.RequestLimit, (int)TransferEnd.TargetDuration);
                            return;
                        }
                        size = Math.Min(Math.Min(chunk, endpoint.MaxTransferBytes), allowance - reserved);
                        requests++;
                        reserved += size;
                        peakStreams = Math.Max(peakStreams, ++activeStreams);
                    }

                    using var requestDeadline = CancellationTokenSource.CreateLinkedTokenSource(phase.Token);
                    requestDeadline.CancelAfter(TimeSpan.FromSeconds(6));
                    var started = Stopwatch.GetTimestamp();
                    if (uploadWindows is not null)
                        Array.Clear(uploadWindows);
                    try
                    {
                        var outcome = download
                            ? await ReadChunk(size, buffer!, requestDeadline.Token).ConfigureAwait(false)
                            : await WriteChunk(size, requestDeadline.Token).ConfigureAwait(false);
                        if (outcome != TransferEnd.ByteLimit)
                        {
                            await Stop(outcome).ConfigureAwait(false);
                            return;
                        }
                        Interlocked.Add(ref verified, size);
                        if (uploadWindows is not null)
                        {
                            for (var window = 0; window < windowCount; window++)
                                Interlocked.Add(ref measured[window], uploadWindows[window]);
                        }

                        // Aim for subsecond chunks so a deadline discards little in-flight upload data.
                        var seconds = Stopwatch.GetElapsedTime(started).TotalSeconds;
                        chunk = (long)Math.Clamp(size * 0.5 / Math.Max(seconds, 0.001),
                            InitialChunkBytes, Math.Clamp(2d * size, InitialChunkBytes, 32 * MeasurementProtocol.MiB));
                    }
                    catch (OperationCanceledException) when (phase.IsCancellationRequested) { return; }
                    catch (OperationCanceledException) { await Stop(TransferEnd.TimeLimit).ConfigureAwait(false); }
                    catch (Exception error) when (error is HttpRequestException or IOException)
                    {
                        if (!phase.IsCancellationRequested)
                            await Stop(requestDeadline.IsCancellationRequested ? TransferEnd.TimeLimit : TransferEnd.Interrupted)
                                .ConfigureAwait(false);
                    }
                    finally
                    {
                        lock (allocationLock)
                        {
                            activeStreams--;
                            lastCompleted = Math.Max(lastCompleted, Stopwatch.GetTimestamp());
                        }
                    }
                }
            }
            catch (OperationCanceledException) when (phase.IsCancellationRequested) { }

            void Meter(int bytes)
            {
                Interlocked.Add(ref transferred, bytes);
                count(bytes);
                var index = (int)(Stopwatch.GetElapsedTime(stageStart).TotalMilliseconds / WindowMilliseconds);
                if ((uint)index >= (uint)windowCount)
                    return;
                if (uploadWindows is not null)
                    uploadWindows[index] += bytes;
                else
                    Interlocked.Add(ref measured[index], bytes);
            }

            async Task<TransferEnd> ReadChunk(long size, byte[] scratch, CancellationToken requestToken)
            {
                using var response = await client.GetAsync(PathFor($"/download?bytes={size}"),
                    HttpCompletionOption.ResponseHeadersRead, requestToken).ConfigureAwait(false);
                if (response.StatusCode == HttpStatusCode.TooManyRequests)
                    return TransferEnd.ServerBusy;
                if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentLength != size ||
                    response.Content.Headers.ContentEncoding.Count != 0 ||
                    response.Content.Headers.ContentType?.MediaType != "application/octet-stream")
                    return TransferEnd.InvalidResponse;

                await using var stream = await response.Content.ReadAsStreamAsync(requestToken).ConfigureAwait(false);
                for (var remaining = size; remaining > 0;)
                {
                    var bytes = await stream.ReadAsync(scratch.AsMemory(0, (int)Math.Min(scratch.Length, remaining)),
                        requestToken).ConfigureAwait(false);
                    if (bytes == 0)
                        return TransferEnd.Interrupted;
                    Meter(bytes);
                    remaining -= bytes;
                }
                return TransferEnd.ByteLimit;
            }

            async Task<TransferEnd> WriteChunk(long size, CancellationToken requestToken)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, PathFor("/upload"))
                    { Content = new UploadContent(size, static () => { }, Meter) };
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, requestToken)
                    .ConfigureAwait(false);
                if (response.StatusCode == HttpStatusCode.TooManyRequests)
                    return TransferEnd.ServerBusy;
                return response.StatusCode == HttpStatusCode.NoContent &&
                    response.Headers.TryGetValues(MeasurementProtocol.AcknowledgedBytes, out var values) &&
                    long.TryParse(values.FirstOrDefault(), NumberStyles.None, CultureInfo.InvariantCulture, out var received) &&
                    received == size ? TransferEnd.ByteLimit : TransferEnd.InvalidResponse;
            }
        }

        async Task Stop(TransferEnd reason)
        {
            Interlocked.CompareExchange(ref stop, (int)reason, (int)TransferEnd.TargetDuration);
            await phase.CancelAsync().ConfigureAwait(false);
        }

        async Task Monitor()
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500));
            var lastReported = 0;
            try
            {
                while (await timer.WaitForNextTickAsync(phase.Token).ConfigureAwait(false))
                {
                    if (routeChanged())
                    {
                        await Stop(TransferEnd.RouteChanged).ConfigureAwait(false);
                        return;
                    }
                    var window = (int)(Stopwatch.GetElapsedTime(stageStart).TotalMilliseconds / WindowMilliseconds) - 1;
                    if (window < 0)
                        continue;
                    if (window > lastReported && window < windowCount)
                    {
                        lastReported = window;
                        report(Interlocked.Read(ref measured[window]) * 8e-6);
                    }
                    if (Volatile.Read(ref activeStreams) > 0 &&
                        Interlocked.Read(ref measured[Math.Min(window, windowCount - 1)]) > 0)
                        await Probe(client, probes, phase.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (phase.IsCancellationRequested) { }
        }
    }

    private static ThroughputSample[] Windows(long[] measured, TimeSpan elapsed)
    {
        // The first second is calibration. Incomplete trailing windows are excluded.
        var completed = Math.Min(measured.Length, (int)(elapsed.TotalMilliseconds / WindowMilliseconds));
        return measured.Take(completed).Select((bytes, index) =>
            new ThroughputSample((index + 1) * WindowMilliseconds / 1000d, bytes * 8e-6))
            .Skip(1).ToArray();
    }
}
