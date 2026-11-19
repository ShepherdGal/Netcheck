using System.Net;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using Netcheck.Windows;

internal sealed record LabDnsBaseline(int Version, Guid AdapterId, bool Ipv6, string Mode, bool Automatic,
    DnsFamilyConfiguration Target, DnsFamilyConfiguration? Other);

internal sealed class LabDnsRoundTrip(ILabDnsAdapter dns)
{
    private const ulong DnsChangeFlags = 0x0002 | 0x1000;

    [SupportedOSPlatform("windows")]
    internal static void Run(Guid adapterId, bool ipv6, string mode)
    {
        RequireAdministrator();
        var transaction = new LabDnsRoundTrip(new WindowsLabDnsAdapter());
        var baseline = transaction.Capture(adapterId, ipv6, mode, automatic: false);
        Console.WriteLine(JsonSerializer.Serialize(baseline));
        try
        {
            transaction.Apply(baseline);
        }
        finally
        {
            transaction.Restore(baseline);
            Console.WriteLine("Native DNS read-back matched the original configuration after restoration.");
        }
    }

    [SupportedOSPlatform("windows")]
    internal static void RequireAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw new InvalidOperationException("The VM write probe requires an elevated token.");
        }
    }

    internal LabDnsBaseline Capture(Guid adapterId, bool ipv6, string mode, bool automatic)
    {
        var otherSupported = dns.ValidateTarget(adapterId, ipv6);
        var before = dns.Read(adapterId, ipv6);
        if (automatic != string.IsNullOrWhiteSpace(before.ConfiguredServers) ||
            !string.IsNullOrEmpty(before.ProfileServers) ||
            before.ProfileServerProperties.Count != 0 || before.ServerProperties.Count > 16 ||
            (automatic && before.ServerProperties.Count != 0))
        {
            throw new InvalidOperationException("The native DNS baseline did not match the requested assignment mode and lab prerequisites.");
        }

        if (ServersMatch(before.ConfiguredServers, Candidate(ipv6)))
        {
            throw new InvalidOperationException("Choose a different resolver for the manual lab baseline.");
        }

        var other = otherSupported ? dns.Read(adapterId, !ipv6) : null;
        return new LabDnsBaseline(1, adapterId, ipv6, mode, automatic, before, other);
    }

    private static string Candidate(bool ipv6) => ipv6 ? "2606:4700:4700::1111" : "1.1.1.1";

    private static DohProperty[] RequestedProperties(string mode)
    {
        const ulong EnableExplicitTemplate = 2;
        const ulong AllowPlaintextFallback = 4;
        return mode switch
        {
            "required" => [new(0, "https://cloudflare-dns.com/dns-query", EnableExplicitTemplate)],
            "preferred" => [new(0, "https://cloudflare-dns.com/dns-query",
                EnableExplicitTemplate | AllowPlaintextFallback)],
            _ => []
        };
    }

    internal void Apply(LabDnsBaseline baseline)
    {
        var adapterId = baseline.AdapterId;
        var ipv6 = baseline.Ipv6;
        var otherSupported = dns.ValidateTarget(adapterId, ipv6);
        if (!Equivalent(dns.Read(adapterId, ipv6), baseline.Target) || !OtherFamilyMatches(baseline, otherSupported))
        {
            throw new InvalidOperationException("The adapter changed since the DNS baseline was captured.");
        }

        var candidate = Candidate(ipv6);
        var properties = RequestedProperties(baseline.Mode);
        var updateDoh = properties.Length != 0 || baseline.Target.ServerProperties.Count != 0;
        dns.Write(adapterId, ipv6, candidate, properties, updateDoh);
        var applied = dns.Read(adapterId, ipv6);
        if (!MatchesCandidate(baseline, applied) || !OtherFamilyMatches(baseline, otherSupported))
        {
            throw new InvalidOperationException("Applied DNS did not match the requested configuration and address family.");
        }
    }

    internal void Restore(LabDnsBaseline baseline)
    {
        var adapterId = baseline.AdapterId;
        var ipv6 = baseline.Ipv6;
        var otherSupported = dns.ValidateTarget(adapterId, ipv6);
        var current = dns.Read(adapterId, ipv6);
        if (!Equivalent(current, baseline.Target))
        {
            if (!MatchesCandidate(baseline, current))
            {
                throw new InvalidOperationException("DNS differs from both the baseline and the proposed configuration. Review the VM checkpoint.");
            }

            // An empty static list is the Automatic reset candidate under test.
            // Read-back must match the captured state before the journal can be cleared.
            var original = baseline.Target.ConfiguredServers ?? string.Empty;
            var updateDoh = !baseline.Automatic &&
                (current.ServerProperties.Count != 0 || baseline.Target.ServerProperties.Count != 0);
            dns.Write(adapterId, ipv6, original, baseline.Target.ServerProperties, updateDoh);
        }

        if (!Equivalent(dns.Read(adapterId, ipv6), baseline.Target) || !OtherFamilyMatches(baseline, otherSupported))
        {
            throw new InvalidOperationException("Exact read-back restoration failed. Review the VM checkpoint.");
        }

    }

    private static bool MatchesCandidate(LabDnsBaseline baseline, DnsFamilyConfiguration current) =>
        ServersMatch(current.ConfiguredServers, Candidate(baseline.Ipv6)) &&
        current.ServerProperties.SequenceEqual(RequestedProperties(baseline.Mode)) &&
        Equivalent(current with
        {
            Flags = (current.Flags & ~DnsChangeFlags) | (baseline.Target.Flags & DnsChangeFlags),
            ConfiguredServers = baseline.Target.ConfiguredServers,
            ServerProperties = baseline.Target.ServerProperties
        }, baseline.Target);

    private bool OtherFamilyMatches(LabDnsBaseline baseline, bool supported) =>
        supported == (baseline.Other is not null) &&
        (baseline.Other is null || Equivalent(dns.Read(baseline.AdapterId, !baseline.Ipv6), baseline.Other));

    private static bool Equivalent(DnsFamilyConfiguration left, DnsFamilyConfiguration right) =>
        JsonSerializer.Serialize(left) == JsonSerializer.Serialize(right);

    private static bool ServersMatch(string? configured, string candidate) =>
        IPAddress.TryParse(configured?.Trim(), out var address) && address.Equals(IPAddress.Parse(candidate));
}
