using System.Net;
using System.Net.NetworkInformation;
using Netcheck.Windows;

internal static class Phase4Checks
{
    internal static int RunFixtures()
    {
        if (!OperatingSystem.IsWindows())
            return 1;
        var empty = new DnsFamilyConfiguration(0, null, null, null, null, null, [], [], 0, 0, 0, 0);
        Require(ConnectionDiscovery.ClassifyAssignment(empty) == DnsAssignment.Automatic,
            "Automatic assignment");
        Require(ConnectionDiscovery.ClassifyAssignment(empty with { ConfiguredServers = "192.0.2.1" }) == DnsAssignment.Manual,
            "Explicit server assignment");
        Require(ConnectionDiscovery.ClassifyAssignment(empty with { ProfileServers = "192.0.2.1" }) == DnsAssignment.ProfileOverride,
            "Profile resolver override");
        Require(RouteDiscovery.Failed(IPAddress.Loopback, 1231).State == RouteReadState.NoRoute,
            "Offline route result");
        Require(RouteDiscovery.Failed(IPAddress.Loopback, 5).State == RouteReadState.Unavailable,
            "Denied route result");
        Require(WifiDiscovery.Failed(5).State == WifiReadState.PermissionNeeded, "Denied Wi-Fi details");
        Require(WifiDiscovery.Failed(5023).State == WifiReadState.Disconnected, "Disconnected Wi-Fi");
        Console.WriteLine("PASS discovery fixtures (7 assertions)");
        return 0;
    }

    internal static int RunWindows()
    {
        if (!OperatingSystem.IsWindows())
            return 1;

        var snapshot = ConnectionDiscovery.Read();
        Require(snapshot.Connections.Select(item => item.Adapter.Id).Distinct().Count() == snapshot.Connections.Count,
            "Unique adapter identities");

        var loopback = RouteDiscovery.Read(IPAddress.Loopback);
        Require(loopback.State == RouteReadState.Found, $"IPv4 loopback lookup ({loopback.WindowsError})");
        Require(loopback.AdapterId is not null && Equals(loopback.Source, IPAddress.Loopback) &&
            loopback.Prefix is not null && loopback.PrefixLength is <= 32, "IPv4 route marshalling and identity");
        var mapped = RouteDiscovery.Read(IPAddress.Loopback.MapToIPv6());
        Require(mapped.State == RouteReadState.Found && mapped.AdapterId == loopback.AdapterId,
            "IPv4-mapped route identity");

        var ipv6 = RouteDiscovery.Read(IPAddress.IPv6Loopback);
        if (ipv6.State == RouteReadState.Found)
        {
            Require(ipv6.AdapterId is not null && Equals(ipv6.Source, IPAddress.IPv6Loopback) && ipv6.PrefixLength == 128,
                "IPv6 route marshalling and identity");
        }
        var remote = RouteDiscovery.Read(IPAddress.Parse("192.0.2.1"));
        if (remote.State == RouteReadState.Found)
        {
            Require(remote.AdapterId is not null &&
                snapshot.Connections.Any(item => item.Adapter.Id == remote.AdapterId), "Destination route maps to an enumerated adapter");
        }

        Console.WriteLine($"Adapters={snapshot.Connections.Count}, Wi-Fi={snapshot.Connections.Count(x => x.Adapter.Type == NetworkInterfaceType.Wireless80211)}, " +
            $"drivers={snapshot.Connections.Count(x => x.Driver?.Version is not null)}, " +
            $"interface metrics={snapshot.Connections.Count(x => x.IPv4Metric is not null || x.IPv6Metric is not null)}");
        Console.WriteLine($"IPv4 DNS assignments={snapshot.Connections.Count(x => x.IPv4Dns.Assignment != DnsAssignment.Unknown)}, " +
            $"IPv6 DNS assignments={snapshot.Connections.Count(x => x.IPv6Dns.Assignment != DnsAssignment.Unknown)}, " +
            $"DNS policy read={snapshot.DnsPolicy.State}");
        Console.WriteLine($"Route lookup: IPv4 loopback={loopback.State}, IPv6 loopback={ipv6.State}, example destination={remote.State}");
        var tuning = ConnectionDiscovery.ReadTuning(remote.AdapterId);
        Require(tuning.WindowsBuild > 0 && (tuning.AdapterName is null || snapshot.Connections.Any(item =>
            item.Adapter.Id == remote.AdapterId && item.Adapter.Name == tuning.AdapterName)), "tuning evidence identifies the routed adapter");
        Console.WriteLine($"Tuning evidence: TCP templates={tuning.TcpTemplates.Count}, driver reported={tuning.Driver is not null}, " +
            $"RSS reported={tuning.RssEnabled.HasValue}, power reported={tuning.PowerSetting is not null}, " +
            $"MDM read={tuning.MdmRegistered.HasValue}");
        return 0;
    }

    private static void Require(bool condition, string description)
    {
        if (!condition)
            throw new InvalidOperationException($"Discovery check failed: {description}");
    }
}
