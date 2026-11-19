using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Netcheck.Core;

namespace Netcheck.TestServer;

public static class TestEndpoint
{
    public static WebApplication Build(string[] args, X509Certificate2? loopbackCertificate = null,
        int? validationBytesPerSecond = null, TimeSpan? validationProbeDelay = null,
        Func<bool>? interruptTransfers = null)
    {
        var builder = loopbackCertificate is null
            ? WebApplication.CreateBuilder(args)
            : WebApplication.CreateSlimBuilder(args);
        if (loopbackCertificate is not null)
        {
            builder.Configuration.Sources.Clear();
            builder.Logging.ClearProviders();
            builder.WebHost.UseKestrelHttpsConfiguration();
        }
        else if (string.IsNullOrWhiteSpace(builder.Configuration["urls"]))
            builder.WebHost.UseUrls("https://localhost:7443");

        builder.WebHost.ConfigureKestrel(server =>
        {
            server.AddServerHeader = false;
            server.Limits.MaxConcurrentConnections = 32;
            server.Limits.MaxRequestBodySize = MeasurementProtocol.TransferLimit;
            server.Limits.MaxRequestHeadersTotalSize = 8 * 1024;
            server.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(15);
            server.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(5);
            if (loopbackCertificate is not null)
                server.Listen(IPAddress.Loopback, 0, listen =>
                {
                    listen.Protocols = HttpProtocols.Http1;
                    listen.UseHttps(loopbackCertificate);
                });
        });
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ =>
                RateLimitPartition.GetFixedWindowLimiter("netcheck", _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 1024, Window = TimeSpan.FromMinutes(1), QueueLimit = 0
                }));
        });
        var app = builder.Build();
        var capabilities = new EndpointCapabilities(MeasurementProtocol.Version, MeasurementProtocol.TransferLimit,
            loopbackCertificate is null ? builder.Configuration["Netcheck:Region"] ?? "Unspecified" : "Local validation",
            validationBytesPerSecond, MeasurementProtocol.SustainedStreams);
        var transfers = new SemaphoreSlim(4);
        var payload = RandomNumberGenerator.GetBytes(64 * 1024);

        app.Use(async (context, next) =>
        {
            if (!context.Request.IsHttps)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            context.Response.Headers.CacheControl = "no-store";
            await next(context);
        });
        app.UseRateLimiter();
        var routes = app.MapGroup(MeasurementProtocol.Prefix);
        routes.MapGet("/capabilities", () => capabilities);
        routes.MapGet("/latency", async (HttpContext context) =>
        {
            if (validationProbeDelay is { } delay)
                await Task.Delay(delay, context.RequestAborted);
            return Results.NoContent();
        });
        routes.MapGet("/download", Download);
        routes.MapPost("/upload", Upload);
        routes.MapPost("/validate", Validate);
        return app;

        async Task Download(HttpContext context)
        {
            if (!long.TryParse(context.Request.Query["bytes"], NumberStyles.None, CultureInfo.InvariantCulture, out var length) ||
                length is <= 0 or > MeasurementProtocol.TransferLimit)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            if (!transfers.Wait(0))
            {
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                return;
            }
            try
            {
                using var deadline = TransferDeadline(context);
                context.Response.ContentType = "application/octet-stream";
                context.Response.ContentLength = length;
                var started = Stopwatch.GetTimestamp();
                for (var sent = 0L; sent < length;)
                {
                    if (interruptTransfers?.Invoke() == true)
                    {
                        context.Abort();
                        return;
                    }
                    var size = (int)Math.Min(payload.Length, length - sent);
                    await Pace(started, sent + size, deadline.Token);
                    await context.Response.Body.WriteAsync(payload.AsMemory(0, size), deadline.Token);
                    sent += size;
                }
            }
            catch (OperationCanceledException) { context.Abort(); }
            catch (IOException) { context.Abort(); }
            finally { transfers.Release(); }
        }

        async Task Upload(HttpContext context)
        {
            if (context.Request.ContentLength is not ( > 0 and <= MeasurementProtocol.TransferLimit) ||
                context.Request.ContentType != "application/octet-stream")
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            if (!transfers.Wait(0))
            {
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                return;
            }
            try
            {
                using var deadline = TransferDeadline(context);
                var buffer = new byte[64 * 1024];
                var started = Stopwatch.GetTimestamp();
                long received = 0;
                int read;
                while ((read = await context.Request.Body.ReadAsync(buffer, deadline.Token)) > 0)
                {
                    if (interruptTransfers?.Invoke() == true)
                    {
                        context.Abort();
                        return;
                    }
                    received += read;
                    await Pace(started, received, deadline.Token);
                }
                if (received != context.Request.ContentLength)
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    return;
                }
                context.Response.Headers[MeasurementProtocol.AcknowledgedBytes] = received.ToString(CultureInfo.InvariantCulture);
                context.Response.StatusCode = StatusCodes.Status204NoContent;
            }
            catch (OperationCanceledException) { context.Abort(); }
            catch (IOException) { context.Abort(); }
            finally { transfers.Release(); }
        }

        async Task Validate(HttpContext context)
        {
            if (context.Request.ContentLength is not (> 0 and <= 256) || !context.Request.HasJsonContentType())
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            try
            {
                using var deadline = TransferDeadline(context);
                var values = await context.Request.ReadFromJsonAsync<PayloadValidation>(deadline.Token);
                context.Response.StatusCode = values is { Downloaded: >= 0 and <= MeasurementProtocol.SustainedBudgetLimit,
                    Uploaded: >= 0 and <= MeasurementProtocol.SustainedBudgetLimit } &&
                    values.Downloaded + values.Uploaded <= MeasurementProtocol.SustainedBudgetLimit
                    ? StatusCodes.Status204NoContent : StatusCodes.Status400BadRequest;
            }
            catch (System.Text.Json.JsonException) { context.Response.StatusCode = StatusCodes.Status400BadRequest; }
            catch (OperationCanceledException) { context.Abort(); }
        }

        async ValueTask Pace(long started, long bytes, CancellationToken token)
        {
            if (validationBytesPerSecond is > 0)
            {
                var wait = TimeSpan.FromSeconds((double)bytes / validationBytesPerSecond.Value) - Stopwatch.GetElapsedTime(started);
                if (wait > TimeSpan.Zero)
                    await Task.Delay(wait, token);
            }
        }
    }

    private static CancellationTokenSource TransferDeadline(HttpContext context)
    {
        var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        timeout.CancelAfter(TimeSpan.FromSeconds(18));
        return timeout;
    }
}
