using System.Net;
using System.Net.NetworkInformation;

namespace Netcheck.Windows;

public sealed record AdapterInfo(Guid Id, string Name, string Description,
    NetworkInterfaceType Type, OperationalStatus Status, bool SupportsIpv4, bool SupportsIpv6);

public static class AdapterDiscovery
{
    public static IReadOnlyList<AdapterInfo> Read() => Enumerate()
        .Select(entry => entry.Adapter).ToArray();

    public static Guid? IdentifyAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
            return null;
        try
        {
            Guid? match = null;
            foreach (var (network, adapter) in Enumerate())
            {
                IPInterfaceProperties properties;
                try { properties = network.GetIPProperties(); }
                catch (NetworkInformationException) { continue; }
                if (!properties.UnicastAddresses.Any(entry => entry.Address.Equals(address)))
                    continue;
                if (match is not null)
                    return null;
                match = adapter.Id;
            }
            return match;
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }

    internal static IEnumerable<(NetworkInterface Interface, AdapterInfo Adapter)> Enumerate()
    {
        var adapters = new List<(NetworkInterface Interface, AdapterInfo Adapter)>();
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.NetworkInterfaceType is NetworkInterfaceType.Loopback ||
                !Guid.TryParse(networkInterface.Id, out var id))
            {
                continue;
            }

            adapters.Add((networkInterface, new AdapterInfo(id, networkInterface.Name, networkInterface.Description,
                networkInterface.NetworkInterfaceType, networkInterface.OperationalStatus,
                networkInterface.Supports(NetworkInterfaceComponent.IPv4),
                networkInterface.Supports(NetworkInterfaceComponent.IPv6))));
        }

        return adapters.OrderByDescending(entry => entry.Adapter.Status == OperationalStatus.Up)
            .ThenBy(entry => entry.Adapter.Name, StringComparer.CurrentCultureIgnoreCase);
    }
}
