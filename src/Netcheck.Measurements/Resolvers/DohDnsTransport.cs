using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;

namespace Netcheck.Measurements.Resolvers;

/// <summary>Sends one DNS query over HTTPS (RFC 8484) to a server address. Swappable for tests.</summary>
public interface IDohTransport
{
    /// <param name="connection">Which of this server's connections to use: each number is its own kept-open HTTPS
    /// connection. Some providers send each connection to a different server site (OpenDNS, 2026-11-17: about 1 in 8 lands
    /// on a far one, ~64 ms on every lookup), so one connection can be lucky or unlucky; several show the real picture.</param>
    Task<DnsReply> QueryAsync(IPEndPoint server, string template, string name, TimeSpan timeout, CancellationToken cancellationToken,
        int connection = 0);
}

/// <summary>
/// Private DNS timed the way Windows uses it (P12b): one kept-open HTTPS connection per server, opened to the server's
/// own address (the template's host name is used only for the certificate), warmed up once untimed. Windows' DNS client
/// keeps its connection open too, so counting the TCP + TLS handshake on every lookup would make private DNS look slower
/// than it is. Idle connections close themselves after 15 s.
/// </summary>
public sealed class DohDnsTransport : IDohTransport
{
    private static readonly MediaTypeHeaderValue DnsMessage = new("application/dns-message");
    private readonly ConcurrentDictionary<(IPAddress Address, string Template, int Connection), Lazy<HttpClient>> clients = new();
    private readonly ConcurrentDictionary<(IPAddress Address, string Template, int Connection), Lazy<Task>> warm = new();

    public async Task<DnsReply> QueryAsync(IPEndPoint server, string template, string name, TimeSpan timeout,
        CancellationToken cancellationToken, int connection = 0)
    {
        if (!Uri.TryCreate(template, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            return new DnsReply(null, -1, 0);
        var key = (server.Address, template, connection);
        var client = clients.GetOrAdd(key, k => new Lazy<HttpClient>(() => Create(k.Address))).Value;
        // Untimed warm-up: opens the connection (TCP + TLS) the way Windows already has it open.
        await warm.GetOrAdd(key, _ => new Lazy<Task>(() => SendAsync(client, uri, "example.com", TimeSpan.FromSeconds(3), CancellationToken.None)))
            .Value.ConfigureAwait(false);
        return await SendAsync(client, uri, name, timeout, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<DnsReply> SendAsync(HttpClient client, Uri uri, string name, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        // RFC 8484 §4.1: id 0 keeps the request cache-friendly; the reply is matched by the HTTP exchange itself.
        using var content = new ByteArrayContent(DnsWire.Query(0, name));
        content.Headers.ContentType = DnsMessage;
        // HTTP/2 like Windows' DNS client (Quad9 refuses HTTP/1.1 with 505). Set on the request itself: the client's
        // DefaultRequestVersion only applies to requests HttpClient builds, not to a hand-made HttpRequestMessage.
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = content, Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
        var clock = Stopwatch.StartNew();
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, deadline.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                return new DnsReply(null, -1, 0);
            var body = await response.Content.ReadAsByteArrayAsync(deadline.Token).ConfigureAwait(false);
            var ms = clock.Elapsed.TotalMilliseconds;
            return DnsWire.Parse(body) is { IsResponse: true } reply
                ? new DnsReply(ms, reply.Rcode, reply.Addresses.Count, reply.Addresses)
                : new DnsReply(null, -1, 0);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new DnsReply(null, -1, 0);   // timed out
        }
        catch (Exception error) when (error is HttpRequestException or IOException or SocketException or
            System.Security.Authentication.AuthenticationException)
        {
            return new DnsReply(null, -1, 0);   // unreachable, refused or a bad certificate
        }
    }

    private static HttpClient Create(IPAddress address)
    {
        var handler = new SocketsHttpHandler
        {
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(15),
            ConnectTimeout = TimeSpan.FromSeconds(3),
            UseProxy = false,   // Windows' DNS client talks to the server directly
            ConnectCallback = async (context, token) =>
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), token).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
        return new HttpClient(handler)
        {
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
            Timeout = Timeout.InfiniteTimeSpan,
        };
    }
}
