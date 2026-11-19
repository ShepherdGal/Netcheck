using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;

namespace Netcheck.TestServer;

/// <summary>
/// Loopback HTTPS server with the same shape as Cloudflare's speed endpoints
/// (<c>GET /__down?bytes=N</c>, <c>POST /__up</c>), an optional shared rate limit and an optional
/// per-request delay, so the internet check can be measured against known answers offline.
/// </summary>
public sealed class SpeedFixture : IAsyncDisposable
{
    public const int MaxRequestBytes = 50_000_000;
    private readonly WebApplication app;
    private readonly X509Certificate2 certificate;
    private long downloaded, uploaded;

    private SpeedFixture(WebApplication app, X509Certificate2 certificate)
    {
        this.app = app;
        this.certificate = certificate;
        Address = new Uri(app.Urls.Single().TrimEnd('/') + "/");
        CertificateHash = certificate.GetCertHash(HashAlgorithmName.SHA256);
    }

    public Uri Address { get; }
    public byte[] CertificateHash { get; }
    public long DownloadedBytes => Interlocked.Read(ref downloaded);
    public long UploadedBytes => Interlocked.Read(ref uploaded);

    /// <param name="bytesPerSecond">Shared limit across all connections and both directions; null = unlimited.</param>
    /// <param name="requestDelay">Added before every response, to simulate distance.</param>
    /// <param name="refuseTransfersAfter">After this many data requests, answer HTTP 429 like a rate-limited server
    /// (tiny ping requests are still served).</param>
    /// <param name="stallAfterBytes">Once this many bytes went each way, stop sending (downloads) or stop answering
    /// (uploads) without closing the connection, like a server that hangs part-way.</param>
    public static async Task<SpeedFixture> StartAsync(int? bytesPerSecond, TimeSpan? requestDelay,
        CancellationToken cancellationToken, int? refuseTransfersAfter = null, long? stallAfterBytes = null,
        int? refuseFor = null)
    {
        // refuseFor: refuse only this many requests after the limit, then serve again (a short "slow down" burst).
        var transfers = 0;
        bool Refuse() => refuseTransfersAfter is { } limit && Interlocked.Increment(ref transfers) is var n && n > limit &&
                          (refuseFor is not { } burst || n <= limit + burst);
        var certificate = LocalTestEndpoint.CreateCertificate();
        var builder = WebApplication.CreateSlimBuilder();
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.ConfigureKestrel(server =>
        {
            server.AddServerHeader = false;
            server.Limits.MaxConcurrentConnections = 16;
            server.Limits.MaxRequestBodySize = MaxRequestBytes;
            server.Listen(IPAddress.Loopback, 0, listen =>
            {
                listen.Protocols = HttpProtocols.Http1;
                listen.UseHttps(certificate);
            });
        });
        var app = builder.Build();
        SpeedFixture? fixture = null;
        var pace = bytesPerSecond is { } rate ? new Pace(rate) : null;

        app.MapGet("/__down", (RequestDelegate)(async context =>
        {
            if (!long.TryParse(context.Request.Query["bytes"], out var bytes) || bytes is < 0 or > MaxRequestBytes)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            if (bytes > 0 && Refuse())
            {
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                if (refuseFor is not null)
                    context.Response.Headers["Retry-After"] = "1";
                return;
            }
            if (requestDelay is { } delay)
                await Task.Delay(delay, context.RequestAborted);
            context.Response.Headers["Server-Timing"] = "cfRequestDuration;dur=0.4";
            context.Response.Headers["cf-ray"] = "0000000000000000-TST";
            context.Response.ContentType = "application/octet-stream";
            context.Response.ContentLength = bytes;
            var chunk = new byte[16 * 1024];
            for (var left = bytes; left > 0;)
            {
                var n = (int)Math.Min(chunk.Length, left);
                if (stallAfterBytes is { } stall && Interlocked.Read(ref fixture!.downloaded) >= stall)
                    await Task.Delay(Timeout.Infinite, context.RequestAborted);
                if (pace is not null)
                    await pace.WaitAsync(n, context.RequestAborted);
                await context.Response.Body.WriteAsync(chunk.AsMemory(0, n), context.RequestAborted);
                left -= n;
                Interlocked.Add(ref fixture!.downloaded, n);
            }
        }));

        app.MapPost("/__up", (RequestDelegate)(async context =>
        {
            if (Refuse())
            {
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                return;
            }
            if (requestDelay is { } delay)
                await Task.Delay(delay, context.RequestAborted);
            var buffer = new byte[16 * 1024];
            int read;
            while ((read = await context.Request.Body.ReadAsync(buffer, context.RequestAborted)) > 0)
            {
                if (pace is not null)
                    await pace.WaitAsync(read, context.RequestAborted);
                Interlocked.Add(ref fixture!.uploaded, read);
            }
            if (stallAfterBytes is { } limit && Interlocked.Read(ref fixture!.uploaded) >= limit)
                await Task.Delay(Timeout.Infinite, context.RequestAborted);
            context.Response.Headers["Server-Timing"] = "cfRequestDuration;dur=0.4";
            context.Response.StatusCode = StatusCodes.Status200OK;
        }));

        try
        {
            await app.StartAsync(cancellationToken).ConfigureAwait(false);
            fixture = new SpeedFixture(app, certificate);
            return fixture;
        }
        catch
        {
            await app.DisposeAsync().ConfigureAwait(false);
            certificate.Dispose();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try { await app.StopAsync(deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
        finally
        {
            await app.DisposeAsync().ConfigureAwait(false);
            certificate.Dispose();
        }
    }

    /// <summary>Simple shared pacer: each chunk is scheduled after the previous one at the given rate.</summary>
    private sealed class Pace(int bytesPerSecond)
    {
        private readonly Stopwatch clock = Stopwatch.StartNew();
        private readonly Lock gate = new();
        private double nextSeconds;

        public Task WaitAsync(int bytes, CancellationToken cancellationToken)
        {
            double wait;
            lock (gate)
            {
                var now = clock.Elapsed.TotalSeconds;
                nextSeconds = Math.Max(nextSeconds, now - 0.05) + (double)bytes / bytesPerSecond;
                wait = nextSeconds - now;
            }
            return wait > 0.001 ? Task.Delay(TimeSpan.FromSeconds(wait), cancellationToken) : Task.CompletedTask;
        }
    }
}
