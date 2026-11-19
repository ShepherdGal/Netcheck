using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Netcheck.Windows;

public sealed record RouterAdvertisement(string? Manufacturer, string? Model, string? ModelNumber, string? Firmware);

[SupportedOSPlatform("windows")]
public static class RouterIdentity
{
    public static async Task<RouterAdvertisement?> ReadAsync(Guid adapter, IPAddress gateway, CancellationToken token = default)
    {
        if (gateway.AddressFamily != AddressFamily.InterNetwork)
            return null;
        var route = RouteDiscovery.Read(gateway);
        if (route.AdapterId != adapter || route.Source is not { } source || IPAddress.IsLoopback(gateway) ||
            gateway.Equals(IPAddress.Any) || gateway.Equals(IPAddress.Broadcast) || gateway.GetAddressBytes()[0] >= 224)
            return null;

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(4));
        try
        {
            using var udp = new UdpClient(new IPEndPoint(source, 0));
            var multicast = IPAddress.Parse("239.255.255.250");
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, source.GetAddressBytes());
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 1);
            const string query = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
            await udp.SendAsync(Encoding.ASCII.GetBytes(query), new IPEndPoint(multicast, 1900), deadline.Token);
            using var discovery = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            discovery.CancelAfter(TimeSpan.FromSeconds(2));
            for (var i = 0; i < 32; i++)
            {
                var reply = await udp.ReceiveAsync(discovery.Token);
                if (!reply.RemoteEndPoint.Address.Equals(gateway) ||
                    ParseLocation(reply.Buffer, gateway) is not { } location)
                    continue;
                return await ReadDescriptionAsync(location, gateway, source, deadline.Token);
            }
        }
        catch (Exception error) when (error is SocketException or HttpRequestException or IOException or XmlException ||
            error is OperationCanceledException && !token.IsCancellationRequested)
        {
            return null;
        }
        return null;
    }

    internal static Uri? ParseLocation(byte[] reply, IPAddress gateway)
    {
        if (reply.Length > 4096)
            return null;
        var lines = Encoding.ASCII.GetString(reply).Split("\r\n");
        if (!lines[0].StartsWith("HTTP/1.1 200 ", StringComparison.Ordinal))
            return null;
        var locations = lines.Skip(1).TakeWhile(line => line.Length > 0)
            .Where(line => line.StartsWith("LOCATION:", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (locations.Length != 1 || !Uri.TryCreate(locations[0][9..].Trim(), UriKind.Absolute, out var uri))
            return null;
        return uri.Scheme is "http" or "https" && uri.HostNameType == UriHostNameType.IPv4 &&
            IPAddress.TryParse(uri.Host, out var host) && host.Equals(gateway) &&
            uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 ? uri : null;
    }

    private static async Task<RouterAdvertisement?> ReadDescriptionAsync(Uri location, IPAddress gateway,
        IPAddress source, CancellationToken token)
    {
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseProxy = false, UseCookies = false, MaxResponseHeadersLength = 8,
            ConnectCallback = async (_, cancellation) =>
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.Bind(new IPEndPoint(source, 0));
                    await socket.ConnectAsync(new IPEndPoint(gateway, location.Port), cancellation);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            }
        };
        using var http = new HttpClient(handler);
        using var response = await http.GetAsync(location, HttpCompletionOption.ResponseHeadersRead, token);
        const int maxBytes = 64 * 1024;
        if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > maxBytes)
            return null;
        using var stream = await response.Content.ReadAsStreamAsync(token);
        var data = new byte[maxBytes + 1];
        var count = await stream.ReadAtLeastAsync(data, data.Length, false, token);
        if (count > maxBytes)
            return null;
        using var description = new MemoryStream(data, 0, count);
        return ParseDescription(description);
    }

    internal static RouterAdvertisement? ParseDescription(Stream description)
    {
        using var reader = XmlReader.Create(description, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 64 * 1024
        });
        var root = XDocument.Load(reader).Root;
        XNamespace ns = "urn:schemas-upnp-org:device-1-0";
        if (root?.Name != ns + "root" || root.Element(ns + "device") is not { } device ||
            !((string?)device.Element(ns + "deviceType") ?? "").StartsWith(
                "urn:schemas-upnp-org:device:InternetGatewayDevice:", StringComparison.Ordinal))
            return null;

        var advertised = new RouterAdvertisement(Field("manufacturer"), Field("modelName"), Field("modelNumber"),
            Field("firmwareVersion") ?? Field("softwareVersion"));
        return advertised.Model is not null || advertised.ModelNumber is not null ? advertised : null;

        string? Field(string name)
        {
            var value = device.Elements().FirstOrDefault(element => element.Name.LocalName == name)?.Value.Trim();
            return value is { Length: > 0 and <= 120 } &&
                !value.Any(character => char.IsControl(character) ||
                    char.GetUnicodeCategory(character) == System.Globalization.UnicodeCategory.Format) ? value : null;
        }
    }
}
