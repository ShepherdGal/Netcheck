using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Netcheck.Core;

namespace Netcheck.Measurements;

public sealed partial class HttpsSpeedTestProvider(Func<IPAddress, Guid?> identifyAdapter, byte[]? localCertificateHash = null,
    Func<IPAddress, RouteObservation?>? readRoute = null, Action<Guid>? observeAdapter = null)
    : ISpeedTestProvider
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly byte[] UploadBuffer = RandomNumberGenerator.GetBytes(64 * 1024);
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan TransferTimeout = TimeSpan.FromSeconds(12);

    internal static bool SupportsSustained(EndpointCapabilities? endpoint) => endpoint?.MaxSustainedStreams > 0;

    public async Task<MeasurementResult> RunAsync(MeasurementOptions options, IProgress<MeasurementProgress>? progress,
        CancellationToken cancellationToken)
    {
        if (!options.Endpoint.IsAbsoluteUri || !MeasurementProtocol.TryOrigin(options.Endpoint.AbsoluteUri, out _) ||
            options.Mode is not (MeasurementMode.Quick or MeasurementMode.Standard) ||
            options.Duration <= TimeSpan.Zero || options.Duration > TimeSpan.FromMinutes(2) ||
            options.PayloadBudget is < 0 or > MeasurementProtocol.SustainedBudgetLimit ||
            options.SustainedDuration is { } target && (options.Mode != MeasurementMode.Standard ||
                target < TimeSpan.FromSeconds(2) || target > TimeSpan.FromSeconds(25)) ||
            options.SustainedDuration is null && options.PayloadBudget > 2 * MeasurementProtocol.TransferLimit ||
            options.Mode == MeasurementMode.Quick && options.PayloadBudget != 0 ||
            options.Mode == MeasurementMode.Standard && options.PayloadBudget < 2 * MeasurementProtocol.MiB)
            throw new ArgumentException("Invalid HTTPS origin, duration, or payload allowance.", nameof(options));
        if (localCertificateHash is not null && (localCertificateHash.Length != 32 ||
            options.Endpoint.IdnHost != IPAddress.Loopback.ToString()))
            throw new ArgumentException("The temporary certificate is only valid for the built-in IPv4 loopback endpoint.");

        var started = DateTimeOffset.UtcNow;
        using var run = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        run.CancelAfter(options.Duration);
        var token = run.Token;
        var paths = new ConcurrentDictionary<ObservedPath, byte>();
        var routes = new ConcurrentDictionary<IPAddress, RouteObservation>();
        var notes = new List<string>();
        var routeMismatch = 0;
        var routeChanged = 0;
        var total = 0L;
        EndpointCapabilities? endpoint = null;
        ProbeMeasurement? idle = null;
        TransferMeasurement? download = null;
        TransferMeasurement? upload = null;
        var dns = new List<DnsMeasurement>();
        var state = MeasurementState.Failed;

        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            UseProxy = localCertificateHash is null,
            MaxConnectionsPerServer = MeasurementProtocol.SustainedStreams + 1,
            MaxResponseDrainSize = 0,
            MaxResponseHeadersLength = 16,
            ConnectTimeout = TimeSpan.FromSeconds(4),
            ConnectCallback = Connect
        };
        if (localCertificateHash is { } pin)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                certificate is not null && CryptographicOperations.FixedTimeEquals(
                    certificate.GetCertHash(HashAlgorithmName.SHA256), pin);
        }
        using var client = new HttpClient(handler, disposeHandler: false)
        {
            BaseAddress = options.Endpoint, Timeout = Timeout.InfiniteTimeSpan,
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact
        };
        client.DefaultRequestHeaders.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
        client.DefaultRequestHeaders.AcceptEncoding.ParseAdd("identity");

        try
        {
            Report(MeasurementStage.Endpoint);
            endpoint = await ReadCapabilities(client, token).ConfigureAwait(false);
            if (paths.Keys.Any(path => path.ViaProxy))
                notes.Add("Windows used a proxy. The observed peer is the proxy's next hop.");
            if (paths.Keys.Any(path => path.Adapter is null && !IPAddress.IsLoopback(path.LocalAddress)))
                notes.Add("Windows adapter identity could not be established for the observed socket.");
            if (endpoint.BytesPerSecond is > 0)
                notes.Add("The endpoint reports an explicit server-side rate limit.");

            Report(MeasurementStage.Idle);
            idle = await MeasureIdle(client, token).ConfigureAwait(false);
            if (idle.Milliseconds.Count < 2)
                notes.Add("Too few valid idle probes for a jitter result.");

            if (options.Mode == MeasurementMode.Standard)
            {
                if (options.SustainedDuration is { } duration)
                {
                    if (SupportsSustained(endpoint))
                    {
                        download = await SustainDirection(MeasurementStage.Download, options.PayloadBudget / 2, duration)
                            .ConfigureAwait(false);
                        if (!RouteChanged() && Volatile.Read(ref routeMismatch) == 0)
                            upload = await SustainDirection(MeasurementStage.Upload, options.PayloadBudget - options.PayloadBudget / 2,
                                duration).ConfigureAwait(false);
                    }
                    else
                        notes.Add("This server supports Quick checks. Sustained testing requires a compatible endpoint.");
                }
                else
                {
                    var allowance = Math.Min(options.PayloadBudget / 2, endpoint.MaxTransferBytes);
                    if (allowance < options.PayloadBudget / 2)
                        notes.Add("The server reduced the per-direction payload allowance.");
                    download = await Direction(MeasurementStage.Download, allowance).ConfigureAwait(false);
                    upload = await Direction(MeasurementStage.Upload, allowance).ConfigureAwait(false);
                }
            }
            token.ThrowIfCancellationRequested();

            if (options.IncludeSystemDns)
            {
                Report(MeasurementStage.Dns);
                dns.Add(await SystemDnsMeasurement.MeasureAsync(AddressFamily.InterNetwork, "A", token).ConfigureAwait(false));
                Report(MeasurementStage.Dns);
                dns.Add(await SystemDnsMeasurement.MeasureAsync(AddressFamily.InterNetworkV6, "AAAA", token).ConfigureAwait(false));
            }

            Report(MeasurementStage.Validation);
            using var validationDeadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            validationDeadline.CancelAfter(ProbeTimeout);
            using var validationBody = new StringContent(JsonSerializer.Serialize(
                new PayloadValidation(download?.Bytes ?? 0, upload?.VerifiedBytes ?? (upload?.Acknowledged == true ? upload.Bytes : 0)),
                JsonOptions), Encoding.UTF8, "application/json");
            using var validationRequest = new HttpRequestMessage(HttpMethod.Post, PathFor("/validate"))
                { Content = validationBody };
            using var validation = await client.SendAsync(validationRequest, HttpCompletionOption.ResponseHeadersRead,
                validationDeadline.Token).ConfigureAwait(false);
            if (validation.StatusCode != HttpStatusCode.NoContent)
                notes.Add("The endpoint did not accept the payload summary.");
            var complete = idle.Milliseconds.Count >= 2 &&
                (options.Mode == MeasurementMode.Quick || (IsComplete(download) && IsComplete(upload))) &&
                (!options.IncludeSystemDns || dns.Any(result => result.Milliseconds.Count != 0)) &&
                validation.StatusCode == HttpStatusCode.NoContent;
            state = complete ? MeasurementState.Complete : MeasurementState.Partial;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            state = MeasurementState.Stopped;
        }
        catch (OperationCanceledException)
        {
            state = MeasurementState.TimedOut;
            notes.Add(token.IsCancellationRequested ? "The overall test time limit elapsed." : "An endpoint request timed out.");
        }
        catch (Exception error) when (error is HttpRequestException or IOException or JsonException or SocketException)
        {
            state = idle is not null || download is not null || upload is not null || dns.Count > 0
                ? MeasurementState.Partial : MeasurementState.Failed;
            if (Volatile.Read(ref routeMismatch) == 0)
                notes.Add(error switch
                {
                    ProtocolException protocol => protocol.Message,
                    HttpRequestException { HttpRequestError: HttpRequestError.SecureConnectionError } =>
                        "TLS validation or handshake failed.",
                    HttpRequestException { HttpRequestError: HttpRequestError.NameResolutionError } =>
                        "Windows could not resolve the endpoint name.",
                    _ => "The HTTPS endpoint could not be reached or verified."
                });
        }

        if (Volatile.Read(ref routeMismatch) != 0)
        {
            notes.Add("Windows did not use the selected adapter. Choose the Windows-selected route or change the active connection.");
            if (state == MeasurementState.Complete)
                state = MeasurementState.Partial;
        }
        var observed = paths.Keys.ToArray();
        if (RouteChanged())
        {
            notes.Add("The endpoint route changed or became unavailable. Treat comparisons as inconclusive.");
            if (state == MeasurementState.Complete)
                state = MeasurementState.Partial;
        }

        return new MeasurementResult(options, started, DateTimeOffset.UtcNow, state, endpoint, observed,
            Interlocked.Read(ref total), idle, download, upload, dns.ToArray(), notes.ToArray(),
            ProviderVersion: options.SustainedDuration is null ? "HTTPS v1" : "HTTPS v1 sustained")
        {
            Route = observed.Length == 1 ? routes.GetValueOrDefault(observed[0].PeerAddress) : null
        };

        void Report(MeasurementStage stage, double? rate = null) =>
            progress?.Report(new MeasurementProgress(stage, Interlocked.Read(ref total), rate)
            {
                Readings = new MeasurementReadings(download?.MegabitsPerSecond, upload?.MegabitsPerSecond,
                    idle?.MedianMs, idle?.JitterMs, idle?.TimeoutPercent, dns.FirstOrDefault(family => family.MedianMs.HasValue))
            });

        async Task<TransferMeasurement?> Direction(MeasurementStage stage, long allowance)
        {
            Report(stage);
            var warmupBytes = Math.Min(MeasurementProtocol.WarmupBytes, allowance / 8);
            var warmup = await Transfer(client, stage, warmupBytes, new PayloadMeter(CountBytes), false, token)
                .ConfigureAwait(false);
            if (!IsComplete(warmup))
            {
                notes.Add($"{stage} warmup ended with {Describe(warmup.End)}.");
                return null;
            }
            var result = await Transfer(client, stage, allowance - warmupBytes, new PayloadMeter(CountBytes), true, token)
                .ConfigureAwait(false);
            if (result.End != TransferEnd.ByteLimit)
                notes.Add($"{stage} ended with {Describe(result.End)}.");
            return result;

            void CountBytes(int count, double? rate)
            {
                Interlocked.Add(ref total, count);
                if (rate is not null)
                    Report(stage, rate);
            }
        }

        async Task<TransferMeasurement?> SustainDirection(MeasurementStage stage, long allowance, TimeSpan duration)
        {
            token.ThrowIfCancellationRequested();
            Report(stage);
            token.ThrowIfCancellationRequested();
            var result = await Sustain(client, stage, allowance, endpoint!, duration,
                count => Interlocked.Add(ref total, count), rate => Report(stage, rate), RouteChanged, token)
                .ConfigureAwait(false);
            if (!IsComplete(result))
                notes.Add($"{stage} did not complete its sustained workload. It ended with {Describe(result.End)}.");
            return result;
        }

        async ValueTask<Stream> Connect(SocketsHttpConnectionContext context, CancellationToken connectToken)
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(context.DnsEndPoint, connectToken).ConfigureAwait(false);
                if (socket.LocalEndPoint is not IPEndPoint local || socket.RemoteEndPoint is not IPEndPoint peer)
                    throw new IOException("Socket endpoints unavailable.");
                var address = Normalize(local.Address);
                var adapter = identifyAdapter(address);
                var proxy = !string.Equals(context.DnsEndPoint.Host.Trim('[', ']'),
                    options.Endpoint.IdnHost.Trim('[', ']'), StringComparison.OrdinalIgnoreCase) ||
                    context.DnsEndPoint.Port != options.Endpoint.Port;
                var peerAddress = Normalize(peer.Address);
                if (paths.TryAdd(new ObservedPath(address, peerAddress, adapter, proxy), 0))
                {
                    if (adapter is { } adapterId)
                        observeAdapter?.Invoke(adapterId);
                    if (readRoute?.Invoke(peerAddress) is { } route)
                        routes.TryAdd(peerAddress, route);
                }
                if (options.SelectedAdapter is { } selected && adapter != selected)
                {
                    Interlocked.Exchange(ref routeMismatch, 1);
                    throw new IOException("The observed socket does not belong to the selected adapter.");
                }
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        bool RouteChanged()
        {
            if (Volatile.Read(ref routeChanged) != 0)
                return true;
            if (paths.Count > 1 || (readRoute is not null &&
                routes.Any(entry => readRoute(entry.Key) != entry.Value)))
                Interlocked.Exchange(ref routeChanged, 1);
            return Volatile.Read(ref routeChanged) != 0;
        }
    }

    private static async Task<EndpointCapabilities> ReadCapabilities(HttpClient client, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(6));
        using var response = await client.GetAsync(PathFor("/capabilities"), HttpCompletionOption.ResponseHeadersRead,
            deadline.Token).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new ProtocolException($"The HTTPS endpoint returned HTTP {(int)response.StatusCode} during the capability check.");
        await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
        var buffer = new byte[4097];
        var read = await stream.ReadAtLeastAsync(buffer, buffer.Length, false, deadline.Token)
            .ConfigureAwait(false);
        if (read == buffer.Length)
            throw new ProtocolException("The endpoint sent an oversized capability response.");
        var capabilities = JsonSerializer.Deserialize<EndpointCapabilities>(buffer.AsSpan(0, read), JsonOptions);
        if (capabilities is not { Version: MeasurementProtocol.Version, MaxTransferBytes: >= 65536 and <= MeasurementProtocol.TransferLimit,
            Region.Length: > 0 and <= 120, MaxSustainedStreams: >= 0 and <= MeasurementProtocol.SustainedStreams })
            throw new ProtocolException("This endpoint does not advertise a compatible Netcheck protocol.");
        return capabilities;
    }

    private static async Task<ProbeMeasurement> MeasureIdle(HttpClient client, CancellationToken token)
    {
        var warmup = new Probes();
        await Probe(client, warmup, token).ConfigureAwait(false);
        var probes = new Probes();
        for (var index = 0; index < 6; index++)
        {
            token.ThrowIfCancellationRequested();
            await Probe(client, probes, token).ConfigureAwait(false);
            if (index < 5)
                await Task.Delay(150, token).ConfigureAwait(false);
        }
        token.ThrowIfCancellationRequested();
        return probes.Result();
    }

    private static async Task Probe(HttpClient client, Probes probes, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(ProbeTimeout);
        var started = Stopwatch.GetTimestamp();
        try
        {
            using var response = await client.GetAsync(PathFor("/latency"), HttpCompletionOption.ResponseHeadersRead,
                deadline.Token).ConfigureAwait(false);
            if (token.IsCancellationRequested)
                probes.Canceled++;
            else if (response.StatusCode == HttpStatusCode.NoContent)
                probes.Valid.Add(Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            else
                probes.Failed++;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { probes.Canceled++; }
        catch (OperationCanceledException) { probes.Unanswered++; }
        catch (Exception error) when (error is HttpRequestException or IOException) { probes.Failed++; }
    }

    private static async Task<TransferMeasurement> Transfer(HttpClient client, MeasurementStage stage, long bytes,
        PayloadMeter meter, bool probeUnderLoad, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TransferTimeout);
        using var stopProbes = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        var probes = new Probes();
        var loaded = probeUnderLoad ? SampleLoad() : Task.CompletedTask;
        var end = TransferEnd.Interrupted;
        var acknowledged = false;
        var responseAccepted = false;
        TimeSpan elapsed;
        try
        {
            if (stage == MeasurementStage.Download)
            {
                using var response = await client.GetAsync(PathFor($"/download?bytes={bytes}"),
                    HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
                if (response.StatusCode == HttpStatusCode.TooManyRequests)
                    end = TransferEnd.ServerBusy;
                else if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentLength != bytes ||
                    response.Content.Headers.ContentEncoding.Count != 0 ||
                    response.Content.Headers.ContentType?.MediaType != "application/octet-stream")
                    end = TransferEnd.InvalidResponse;
                else
                {
                    responseAccepted = true;
                    await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
                    var buffer = new byte[64 * 1024];
                    meter.Start();
                    while (meter.Bytes < bytes)
                    {
                        var count = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, bytes - meter.Bytes)),
                            deadline.Token).ConfigureAwait(false);
                        if (count == 0)
                            break;
                        meter.Add(count);
                    }
                    acknowledged = meter.Bytes > 0;
                    end = meter.Bytes == bytes ? TransferEnd.ByteLimit : TransferEnd.Interrupted;
                }
            }
            else
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, PathFor("/upload"))
                    { Content = new UploadContent(bytes, meter.Start, meter.Add) };
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token)
                    .ConfigureAwait(false);
                acknowledged = response.StatusCode == HttpStatusCode.NoContent &&
                    response.Headers.TryGetValues(MeasurementProtocol.AcknowledgedBytes, out var values) &&
                    long.TryParse(values.FirstOrDefault(), NumberStyles.None, CultureInfo.InvariantCulture, out var received) &&
                    received == bytes && meter.Bytes == bytes;
                end = response.StatusCode == HttpStatusCode.TooManyRequests ? TransferEnd.ServerBusy :
                    acknowledged ? TransferEnd.ByteLimit : TransferEnd.InvalidResponse;
            }
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            end = TransferEnd.TimeLimit;
            acknowledged = responseAccepted && meter.Bytes > 0;
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            end = deadline.IsCancellationRequested ? TransferEnd.TimeLimit : TransferEnd.Interrupted;
            acknowledged = responseAccepted && meter.Bytes > 0;
        }
        finally
        {
            elapsed = meter.Elapsed;
            await stopProbes.CancelAsync().ConfigureAwait(false);
            await loaded.ConfigureAwait(false);
        }
        token.ThrowIfCancellationRequested();
        return new TransferMeasurement(meter.Bytes, elapsed, end, acknowledged, meter.Samples, probes.Result());

        async Task SampleLoad()
        {
            try
            {
                var warmed = false;
                while (!stopProbes.IsCancellationRequested)
                {
                    await Task.Delay(250, stopProbes.Token).ConfigureAwait(false);
                    if (!meter.Started)
                        continue;
                    if (!warmed)
                    {
                        var warmup = new Probes();
                        await Probe(client, warmup, stopProbes.Token).ConfigureAwait(false);
                        warmed = warmup.Valid.Count != 0;
                        if (!warmed)
                        {
                            probes.Unanswered += warmup.Unanswered;
                            probes.Failed += warmup.Failed;
                            probes.Canceled += warmup.Canceled;
                        }
                        continue;
                    }
                    await Probe(client, probes, stopProbes.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (stopProbes.IsCancellationRequested) { }
        }
    }

    private static bool IsComplete(TransferMeasurement? transfer) =>
        transfer is { IsSustained: false, End: TransferEnd.ByteLimit, Acknowledged: true } or
            { IsSustained: true, End: TransferEnd.TargetDuration, Acknowledged: true,
              MegabitsPerSecond: not null, Loaded.MedianMs: not null };

    private static string Describe(TransferEnd end) => end switch
    {
        TransferEnd.TimeLimit => "the time limit",
        TransferEnd.ServerBusy => "a busy server",
        TransferEnd.InvalidResponse => "an invalid endpoint response",
        TransferEnd.ByteLimit => "the payload cap",
        TransferEnd.RequestLimit => "the request cap",
        TransferEnd.RouteChanged => "a route change",
        TransferEnd.TargetDuration => "the target duration with insufficient samples",
        _ => "a connection interruption"
    };

    private static string PathFor(string route) => MeasurementProtocol.Prefix + route;
    private static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private sealed class Probes
    {
        internal List<double> Valid { get; } = [];
        internal int Unanswered;
        internal int Failed;
        internal int Canceled;
        internal ProbeMeasurement Result() => new(Valid.ToArray(), Unanswered, Failed, Canceled);
    }

    private sealed class ProtocolException(string message) : IOException(message);

    private sealed class UploadContent : HttpContent
    {
        private readonly long _length;
        private readonly Action _start;
        private readonly Action<int> _add;
        private int _serialized;

        internal UploadContent(long length, Action start, Action<int> add)
        {
            _length = length;
            _start = start;
            _add = add;
            Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _length;
            return true;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context,
            CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _serialized, 1) != 0)
                throw new IOException("The upload cannot be replayed within its payload budget.");
            _start();
            for (var sent = 0L; sent < _length;)
            {
                var size = (int)Math.Min(UploadBuffer.Length, _length - sent);
                await stream.WriteAsync(UploadBuffer.AsMemory(0, size), cancellationToken).ConfigureAwait(false);
                _add(size);
                sent += size;
            }
        }
    }
}
