using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using Netcheck.Windows;

internal interface ILabDnsAdapter
{
    // Validate the target adapter and return whether it also supports the other address family.
    bool ValidateTarget(Guid adapterId, bool ipv6);
    DnsFamilyConfiguration Read(Guid adapterId, bool ipv6);
    void Write(Guid adapterId, bool ipv6, string servers, IReadOnlyList<DohProperty> properties, bool updateDoh);
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsLabDnsAdapter : ILabDnsAdapter
{
    public bool ValidateTarget(Guid adapterId, bool ipv6)
    {
        var adapter = NetworkInterface.GetAllNetworkInterfaces()
            .SingleOrDefault(item => Guid.TryParse(item.Id, out var id) && id == adapterId);
        if (adapter is null || adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback or
            NetworkInterfaceType.Tunnel || !adapter.Supports(ipv6 ? NetworkInterfaceComponent.IPv6 :
            NetworkInterfaceComponent.IPv4))
        {
            throw new InvalidOperationException("Select a lab adapter that supports the requested address family.");
        }

        if (adapter.GetIPProperties().GatewayAddresses.Any(gateway =>
            !gateway.Address.Equals(IPAddress.Any) && !gateway.Address.Equals(IPAddress.IPv6Any)))
        {
            throw new InvalidOperationException("Select a dedicated lab adapter with no configured default gateway.");
        }

        return adapter.Supports(ipv6 ? NetworkInterfaceComponent.IPv4 : NetworkInterfaceComponent.IPv6);
    }

    public DnsFamilyConfiguration Read(Guid adapterId, bool ipv6) => InterfaceDns.Read(adapterId, ipv6);

    public void Write(Guid adapterId, bool ipv6, string servers, IReadOnlyList<DohProperty> properties, bool updateDoh) =>
        InterfaceDns.WriteSettings(adapterId, ipv6, servers, properties, updateDoh);
}
