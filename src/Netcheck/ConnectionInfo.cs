using System.Net;
using System.Net.NetworkInformation;
using Netcheck.Windows;

namespace Netcheck;

/// <summary>What the user is connected through and which DNS server Windows uses, in plain words.</summary>
internal sealed record ConnectionInfo(string Kind, bool Connected, string DnsName, string DnsAddress)
{
    private static readonly Dictionary<string, string> KnownDns = new()
    {
        ["1.1.1.1"] = "Cloudflare", ["1.0.0.1"] = "Cloudflare", ["8.8.8.8"] = "Google", ["8.8.4.4"] = "Google",
        ["9.9.9.9"] = "Quad9", ["149.112.112.112"] = "Quad9", ["94.140.14.14"] = "AdGuard", ["94.140.15.15"] = "AdGuard",
        ["208.67.222.222"] = "OpenDNS", ["208.67.220.220"] = "OpenDNS", ["76.76.2.0"] = "Control D", ["86.54.11.100"] = "DNS4EU",
    };

    public static ConnectionInfo Unknown { get; } = new("", false, "", "");

    /// <summary>Plain name of a well-known DNS address, or null.</summary>
    public static string? NameOf(string address) => KnownDns.TryGetValue(address, out var name) ? name : null;

    /// <summary>Reads the Windows route to the internet (no Wi-Fi name, so no location prompt). Never throws.</summary>
    public static Task<ConnectionInfo> ReadAsync() => Task.Run(() =>
    {
        try
        {
            var route = RouteDiscovery.Read(IPAddress.Parse("1.1.1.1"));
            if (route.State != RouteReadState.Found || route.AdapterId is not { } id)
                return new ConnectionInfo("", false, "", "");
            var adapter = AdapterDiscovery.Read().FirstOrDefault(a => a.Id == id);
            var kind = adapter?.Type switch
            {
                NetworkInterfaceType.Wireless80211 => "Wi-Fi",
                NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.FastEthernetT
                    or NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.Ethernet3Megabit => "Ethernet",
                NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2 => "Mobile data",
                NetworkInterfaceType.Ppp or NetworkInterfaceType.Tunnel => "VPN",
                _ => "Network",
            };
            var resolver = ConnectionDiscovery.ReadDns(id, ipv6: false).ReportedResolvers.FirstOrDefault();
            var name = resolver is null ? ""
                : route.NextHop is { } gateway && resolver.Equals(gateway) ? "Your router"
                : KnownDns.TryGetValue(resolver.ToString(), out var known) ? known
                : "Other DNS";
            return new ConnectionInfo(kind, adapter?.Status == OperationalStatus.Up, name, resolver?.ToString() ?? "");
        }
        catch (Exception)
        {
            return Unknown;
        }
    });
}
