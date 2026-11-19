using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using Netcheck.Windows;

namespace Netcheck.Elevation;

[SupportedOSPlatform("windows")]
internal sealed class WindowsDnsTransactionPlatform : IDnsTransactionPlatform
{
    public DnsSnapshot Read(Guid adapterId, DnsTargetFamily family)
    {
        var adapter = AdapterDiscovery.Read().SingleOrDefault(item => item.Id == adapterId);
        var ipv6 = family == DnsTargetFamily.Ipv6;
        if (adapter is null || !(ipv6 ? adapter.SupportsIpv6 : adapter.SupportsIpv4))
            throw new NotSupportedException("The selected adapter or address family is unavailable.");

        var target = InterfaceDns.Read(adapterId, ipv6);
        var other = (ipv6 ? adapter.SupportsIpv4 : adapter.SupportsIpv6) ? InterfaceDns.Read(adapterId, !ipv6) : null;
        var targetChange = Decode(adapterId, family, target);
        var otherChange = other is null ? null :
            Decode(adapterId, ipv6 ? DnsTargetFamily.Ipv4 : DnsTargetFamily.Ipv6, other);

        // These fields are outside the write operation. Include them in the comparison so an unrelated
        // change cannot be mistaken for the proposal and overwritten during recovery.
        var unaffected = target with { Flags = target.Flags & ~(2UL | 0x1000UL),
            ConfiguredServers = null, ServerProperties = [] };
        var evidence = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { unaffected, other })));
        return new DnsSnapshot(targetChange, otherChange, evidence);
    }

    public bool Permits(DnsChange change)
    {
        if (DnsChangeValidation.Validate(change) is not null)
            return false;
        var adapters = AdapterDiscovery.Read();
        var selected = adapters.SingleOrDefault(adapter => adapter.Id == change.AdapterId);
        if (selected?.Type is not (NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or
                NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.FastEthernetT or NetworkInterfaceType.Wireless80211) ||
            adapters.Any(adapter => adapter.Status == OperationalStatus.Up &&
                adapter.Type is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp))
            return false;

        var policy = ConnectionDiscovery.ReadDnsPolicy();
        return policy is { State: DiscoveryState.Available, Signals.Count: 0 } &&
            ConnectionDiscovery.ReadMdm() == false && IsUnmanaged() &&
            ConnectionDiscovery.ReadDrivers().GetValueOrDefault(change.AdapterId)
                is { AdminLocked: false, Virtual: false };
    }

    public void Write(DnsChange change)
    {
        var ipv6 = change.Family == DnsTargetFamily.Ipv6;
        var current = InterfaceDns.Read(change.AdapterId, ipv6);
        _ = Decode(change.AdapterId, change.Family, current);
        var properties = change.Resolvers.Select((resolver, index) => (resolver, index))
            .Where(entry => entry.resolver.Encryption != DnsEncryption.Plaintext)
            .Select(entry => new DohProperty((uint)entry.index, entry.resolver.HttpsTemplate,
                entry.resolver.Encryption == DnsEncryption.PreferHttps ? 6UL : 2UL)).ToArray();
        InterfaceDns.WriteSettings(change.AdapterId, ipv6, string.Join(",", change.Resolvers.Select(resolver => resolver.Address)),
            properties, properties.Length != 0 || current.ServerProperties.Count != 0);
    }

    internal static DnsChange Decode(Guid adapterId, DnsTargetFamily family, DnsFamilyConfiguration settings)
    {
        if (!string.IsNullOrEmpty(settings.ProfileServers) || settings.ProfileServerProperties.Count != 0 ||
            settings.DisableUnconstrainedQueries != 0)
            throw new NotSupportedException("Windows reports a DNS profile or restrictions outside this operation.");

        var servers = string.IsNullOrEmpty(settings.ConfiguredServers)
            ? [] : settings.ConfiguredServers.Split(',', StringSplitOptions.TrimEntries);
        var resolvers = servers.Select(address => new DnsResolver(
            IPAddress.TryParse(address, out var parsed) ? parsed.ToString() : address, DnsEncryption.Plaintext)).ToArray();
        var indices = new HashSet<uint>();
        foreach (var property in settings.ServerProperties)
        {
            if (property.ServerIndex >= resolvers.Length || !indices.Add(property.ServerIndex) ||
                property.Flags is not (2 or 6))
                throw new NotSupportedException("The existing DNS encryption settings cannot be restored exactly.");

            var resolver = resolvers[property.ServerIndex];
            resolvers[property.ServerIndex] = resolver with
            {
                Encryption = property.Flags == 6 ? DnsEncryption.PreferHttps : DnsEncryption.RequireHttps,
                HttpsTemplate = property.Template
            };
        }

        var change = new DnsChange(adapterId, family,
            resolvers.Length == 0 ? DnsTargetAssignment.Automatic : DnsTargetAssignment.Manual,
            Array.AsReadOnly(resolvers), resolvers.Any(resolver => resolver.Encryption == DnsEncryption.PreferHttps));
        if (DnsChangeValidation.Validate(change) is { } error)
            throw new NotSupportedException(error);
        return change;
    }

    internal static bool IsUnmanaged()
    {
        var status = NetGetJoinInformation(null, out var name, out var join);
        if (name != 0)
            NetApiBufferFree(name);
        if (status != 0 || join != 2) // NetSetupWorkgroupName
            return false;

        var aadStatus = NetGetAadJoinInformation(null, out var information);
        if (information != 0)
            NetFreeAadJoinInformation(information);
        // S_OK or S_FALSE (seen on an unjoined home PC) with no join information = not work/school managed.
        // Any failure HRESULT or any returned join information still blocks the change.
        return aadStatus >= 0 && information == 0;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint NetGetJoinInformation(string? server, out nint name, out int joinStatus);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint NetApiBufferFree(nint buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NetGetAadJoinInformation(string? tenant, out nint joinInformation);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void NetFreeAadJoinInformation(nint joinInformation);
}
