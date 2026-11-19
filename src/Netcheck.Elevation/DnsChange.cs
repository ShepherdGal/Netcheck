using System.Net;
using System.Net.Sockets;

namespace Netcheck.Elevation;

public enum DnsTargetFamily { Ipv4, Ipv6 }
public enum DnsTargetAssignment { Automatic, Manual }
public enum DnsEncryption { Plaintext, RequireHttps, PreferHttps }

public sealed record DnsResolver(string Address, DnsEncryption Encryption, string? HttpsTemplate = null);

public sealed record DnsChange(Guid AdapterId, DnsTargetFamily Family, DnsTargetAssignment Assignment,
    IReadOnlyList<DnsResolver> Resolvers, bool AllowPlaintextFallback);

public static class DnsChangeValidation
{
    public static string? Validate(DnsChange change)
    {
        if (change.AdapterId == Guid.Empty || !Enum.IsDefined(change.Family) || !Enum.IsDefined(change.Assignment))
            return "Select a valid adapter and address family.";
        if (change.Resolvers is null)
            return "Resolver list is required.";
        if (change.Assignment == DnsTargetAssignment.Automatic)
            return change.Resolvers.Count == 0 && !change.AllowPlaintextFallback ? null :
                "Automatic assignment cannot specify resolvers or fallback.";
        if (change.Resolvers.Count is < 1 or > 16)
            return "Provide one to sixteen ordered resolvers.";

        var expected = change.Family == DnsTargetFamily.Ipv4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
        var seen = new HashSet<IPAddress>();
        foreach (var resolver in change.Resolvers)
        {
            if (resolver is null || !Enum.IsDefined(resolver.Encryption) ||
                !IPAddress.TryParse(resolver.Address, out var address) || address.ToString() != resolver.Address ||
                address.AddressFamily != expected || address.IsIPv4MappedToIPv6 ||
                address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast) ||
                address.IsIPv6Multicast || (expected == AddressFamily.InterNetwork && address.GetAddressBytes()[0] is >= 224 and <= 239) ||
                !seen.Add(address))
                return "Use unique, canonical unicast resolver addresses from the selected family.";
            if (resolver.Encryption == DnsEncryption.Plaintext)
            {
                if (resolver.HttpsTemplate is not null)
                    return "A plaintext resolver cannot specify an HTTPS template.";
            }
            else
            {
                if (resolver.Encryption == DnsEncryption.PreferHttps && !change.AllowPlaintextFallback)
                    return "Plaintext fallback requires explicit approval.";
                if (!ValidTemplate(resolver.HttpsTemplate))
                    return "Use an HTTPS resolver URL without credentials or a fragment.";
                var templateHost = new Uri(resolver.HttpsTemplate!).DnsSafeHost;
                if (IPAddress.TryParse(templateHost, out var templateAddress) && !templateAddress.Equals(address))
                    return "An IP address in the HTTPS URL must match its resolver address.";
            }
        }
        if (change.AllowPlaintextFallback && !change.Resolvers.Any(resolver => resolver.Encryption == DnsEncryption.PreferHttps))
            return "Fallback approval requires a resolver configured to prefer HTTPS.";
        return null;
    }

    private static bool ValidTemplate(string? text) =>
        text is { Length: > 0 and <= 2048 } && !text.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)) &&
        !text.Contains('\\') && !text.Contains('{') && !text.Contains('}') &&
        Uri.TryCreate(text, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
        uri.HostNameType is UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0;
}
