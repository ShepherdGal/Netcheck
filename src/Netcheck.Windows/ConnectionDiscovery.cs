using System.ComponentModel;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using Microsoft.Win32;

namespace Netcheck.Windows;

public enum DiscoveryState { Available, PermissionNeeded, Unavailable, Unsupported }
public enum DnsAssignment { Unknown, Automatic, Manual, ProfileOverride }

public sealed record DnsDiscovery(DiscoveryState State, DnsAssignment Assignment,
    IReadOnlyList<IPAddress> ReportedResolvers, DnsFamilyConfiguration? Configuration);

public sealed record DriverDetails(string? Provider, string? Version, string? Date,
    bool? Virtual, bool? AdminLocked, uint? Duplex, ulong? TransmitBits, ulong? ReceiveBits);

public sealed record ConnectionDetails(AdapterInfo Adapter, long? LinkBits, bool AddressDetailsAvailable,
    IReadOnlyList<string> Addresses, IReadOnlyList<IPAddress> Gateways, string? DnsSuffix,
    DnsDiscovery IPv4Dns, DnsDiscovery IPv6Dns, DriverDetails? Driver, uint? IPv4Metric, uint? IPv6Metric);

public sealed record DnsPolicyIndicators(DiscoveryState State, IReadOnlyList<string> Signals);
public sealed record ConnectionSnapshot(IReadOnlyList<ConnectionDetails> Connections, DnsPolicyIndicators DnsPolicy);

[SupportedOSPlatform("windows")]
public static partial class ConnectionDiscovery
{
    private const string CimNamespace = @"root\StandardCimv2";
    private const string DnsPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

    public static ConnectionSnapshot Read()
    {
        var adapters = AdapterDiscovery.Enumerate().ToArray();
        var drivers = ReadDrivers();
        var metrics = ReadMetrics();
        var details = adapters.Select(entry => ReadAdapter(entry.Interface, entry.Adapter, drivers, metrics)).ToArray();
        return new ConnectionSnapshot(details, ReadDnsPolicy());
    }

    public static DnsDiscovery ReadDns(Guid adapterId, bool ipv6)
    {
        foreach (var (network, adapter) in AdapterDiscovery.Enumerate())
        {
            if (adapter.Id != adapterId)
                continue;

            var resolvers = TryRead(() => network.GetIPProperties().DnsAddresses.ToArray()) ?? [];
            return ReadDns(adapter, resolvers, ipv6);
        }

        return new DnsDiscovery(DiscoveryState.Unavailable, DnsAssignment.Unknown, [], null);
    }

    private static ConnectionDetails ReadAdapter(NetworkInterface network, AdapterInfo adapter,
        Dictionary<Guid, DriverDetails> drivers, Dictionary<(uint Index, ushort Family), uint> metrics)
    {
        var properties = TryRead(network.GetIPProperties);
        var addresses = TryRead(() => properties?.UnicastAddresses
            .Select(entry => $"{entry.Address}/{entry.PrefixLength}").ToArray());
        var gateways = TryRead(() => properties?.GatewayAddresses.Select(entry => entry.Address).ToArray());
        var dns = TryRead(() => properties?.DnsAddresses.ToArray()) ?? [];
        var ipv4 = TryRead(() => properties?.GetIPv4Properties());
        var ipv6 = TryRead(() => properties?.GetIPv6Properties());
        var speed = adapter.Status == OperationalStatus.Up ? TryRead(() => network.Speed) : -1;
        drivers.TryGetValue(adapter.Id, out var driver);
        return new ConnectionDetails(adapter, speed > 0 ? speed : null, addresses is not null, addresses ?? [], gateways ?? [],
            TryRead(() => properties?.DnsSuffix), ReadDns(adapter, dns, ipv6: false), ReadDns(adapter, dns, ipv6: true),
            driver, GetMetric(ipv4?.Index, AddressFamily.InterNetwork), GetMetric(ipv6?.Index, AddressFamily.InterNetworkV6));

        uint? GetMetric(int? index, AddressFamily family) => index is >= 0 &&
            metrics.TryGetValue(((uint)index.Value, (ushort)family), out var metric) ? metric : null;
    }

    private static DnsDiscovery ReadDns(AdapterInfo adapter, IPAddress[] resolvers, bool ipv6)
    {
        if (!(ipv6 ? adapter.SupportsIpv6 : adapter.SupportsIpv4))
            return new DnsDiscovery(DiscoveryState.Unsupported, DnsAssignment.Unknown, [], null);

        var family = ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        var reported = resolvers.Where(address => address.AddressFamily == family).ToArray();
        try
        {
            var configuration = InterfaceDns.Read(adapter.Id, ipv6);
            return new DnsDiscovery(DiscoveryState.Available, ClassifyAssignment(configuration), reported, configuration);
        }
        catch (Win32Exception error)
        {
            var state = error.NativeErrorCode switch
            {
                5 or 1260 => DiscoveryState.PermissionNeeded,
                50 or 120 => DiscoveryState.Unsupported,
                _ => DiscoveryState.Unavailable
            };
            return new DnsDiscovery(state, DnsAssignment.Unknown, reported, null);
        }
        catch (Exception error) when (error is NotSupportedException or EntryPointNotFoundException)
        {
            return new DnsDiscovery(DiscoveryState.Unsupported, DnsAssignment.Unknown, reported, null);
        }
    }

    internal static DnsAssignment ClassifyAssignment(DnsFamilyConfiguration configuration) =>
        !string.IsNullOrWhiteSpace(configuration.ProfileServers) ? DnsAssignment.ProfileOverride :
        !string.IsNullOrWhiteSpace(configuration.ConfiguredServers) ? DnsAssignment.Manual : DnsAssignment.Automatic;

    internal static Dictionary<Guid, DriverDetails> ReadDrivers()
    {
        var drivers = new Dictionary<Guid, DriverDetails>();
        ReadCim("""
            SELECT InterfaceGuid, DriverProvider, DriverVersionString, DriverDate, Virtual,
                   AdminLocked, MediaDuplexState, TransmitLinkSpeed, ReceiveLinkSpeed FROM MSFT_NetAdapter
            """, row =>
        {
            if (Guid.TryParse(row["InterfaceGuid"] as string, out var id))
                drivers[id] = new DriverDetails(row["DriverProvider"] as string, row["DriverVersionString"] as string,
                    row["DriverDate"] as string, row["Virtual"] as bool?, row["AdminLocked"] as bool?,
                    row["MediaDuplexState"] as uint?, row["TransmitLinkSpeed"] as ulong?, row["ReceiveLinkSpeed"] as ulong?);
        });
        return drivers;
    }

    private static Dictionary<(uint Index, ushort Family), uint> ReadMetrics()
    {
        var metrics = new Dictionary<(uint, ushort), uint>();
        ReadCim("SELECT InterfaceIndex, AddressFamily, InterfaceMetric FROM MSFT_NetIPInterface", row =>
        {
            if (row["InterfaceIndex"] is uint index && row["AddressFamily"] is ushort family &&
                row["InterfaceMetric"] is uint metric)
                metrics[(index, family)] = metric;
        });
        return metrics;
    }

    private static void ReadCim(string query, Action<ManagementBaseObject> read)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(new ManagementScope(CimNamespace), new ObjectQuery(query),
                new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(4), Rewindable = false });
            using var rows = searcher.Get();
            foreach (ManagementBaseObject row in rows)
            {
                using (row)
                    read(row);
            }
        }
        catch (Exception error) when (error is ManagementException or COMException or UnauthorizedAccessException)
        {
            // CIM can be restricted. The independent IP Helper results are still usable.
        }
    }

    internal static DnsPolicyIndicators ReadDnsPolicy()
    {
        try
        {
            using var policy = Registry.LocalMachine.OpenSubKey(DnsPolicyPath, writable: false);
            using var rules = policy?.OpenSubKey("DnsPolicyConfig", writable: false);
            using var localRules = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig", writable: false);
            var signals = new List<string>();
            if (rules?.SubKeyCount > 0)
                signals.Add("Group Policy DNS namespace rules");
            if (localRules?.SubKeyCount > 0)
                signals.Add("Local DNS namespace rules");
            foreach (var (name, label) in new[]
                     {
                         ("NameServer", "DNS server policy"),
                         ("SearchList", "DNS suffix search policy"),
                         ("DoHPolicy", "DNS over HTTPS policy"),
                         ("EnableMulticast", "Multicast name resolution policy")
                     })
            {
                if (policy?.GetValue(name) is { } value && (value is not string text || !string.IsNullOrWhiteSpace(text)))
                    signals.Add(label);
            }
            return new DnsPolicyIndicators(DiscoveryState.Available, signals);
        }
        catch (Exception error) when (error is SecurityException or UnauthorizedAccessException or IOException)
        {
            return new DnsPolicyIndicators(DiscoveryState.Unavailable, []);
        }
    }

    private static T? TryRead<T>(Func<T> read)
    {
        try { return read(); }
        catch (Exception error) when (error is NetworkInformationException or PlatformNotSupportedException)
        {
            return default;
        }
    }
}
