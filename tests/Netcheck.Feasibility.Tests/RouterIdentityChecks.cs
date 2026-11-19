using System.Net;
using System.Runtime.Versioning;
using System.Text;
using System.Xml;
using Netcheck.Windows;

[SupportedOSPlatform("windows")]
internal static class RouterIdentityChecks
{
    internal static async Task<int> RunLiveAsync()
    {
        var candidate = ConnectionDiscovery.Read().Connections
            .Where(detail => detail.Adapter.Status == System.Net.NetworkInformation.OperationalStatus.Up)
            .SelectMany(detail => detail.Gateways.Select(gateway => (detail.Adapter, Gateway: gateway)))
            .FirstOrDefault(item => item.Gateway.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                RouteDiscovery.Read(item.Gateway).AdapterId == item.Adapter.Id);
        if (candidate.Adapter is null)
        {
            Console.WriteLine("Windows did not report an IPv4 gateway on an active adapter.");
            return 0;
        }

        var identity = await RouterIdentity.ReadAsync(candidate.Adapter.Id, candidate.Gateway);
        Console.WriteLine(identity is null ? $"No usable advertisement on {candidate.Adapter.Name}." :
            $"Advertised on {candidate.Adapter.Name}: {identity.Manufacturer} {identity.Model} {identity.ModelNumber}. Firmware: {identity.Firmware ?? "unavailable"}.");
        return 0;
    }

    internal static int Run()
    {
        var gateway = IPAddress.Parse("192.0.2.1");
        Require(Location("http://192.0.2.1:12345/description.xml")?.Port == 12345);
        Require(Location("http://192.0.2.2/description.xml") is null);
        Require(Location("http://router.example/description.xml") is null);
        Require(Location("http://user@192.0.2.1/description.xml") is null);
        Require(Location("http://192.0.2.1/one\r\nLOCATION: http://192.0.2.1/two") is null);
        const string description = """
            <root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>
              <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
              <modelName>Fixture router</modelName><modelNumber>123</modelNumber>
              </device>
            </root>
            """;
        Require(Parse(description) is { Model: "Fixture router", ModelNumber: "123", Firmware: null });
        Require(Parse(description.Replace("</device>", "<vendor:firmwareVersion xmlns:vendor='urn:fixture'>2.3.4</vendor:firmwareVersion></device>"))
            is { Firmware: "2.3.4" });
        Require(Parse(description.Replace("InternetGatewayDevice", "MediaServer")) is null);
        try
        {
            Parse("<!DOCTYPE root [<!ENTITY unexpected 'fixture'>]>" + description);
            throw new InvalidOperationException("DTD was accepted.");
        }
        catch (XmlException) { }
        Console.WriteLine("PASS router identity: gateway-only URLs, device type, advertised and missing firmware, DTD rejection");
        return 0;

        Uri? Location(string location) => RouterIdentity.ParseLocation(
            Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nLOCATION: {location}\r\n\r\n"), gateway);
    }

    private static RouterAdvertisement? Parse(string description)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(description));
        return RouterIdentity.ParseDescription(stream);
    }

    private static void Require(bool condition)
    {
        if (!condition)
            throw new InvalidOperationException("Router identity fixture failed.");
    }
}
