namespace Netcheck.Core;

// Models for the DNS benchmark (design plan §6). Raw timings only; ratings and wording live in CheckAssessment / the UI.

public enum DnsGoal { Fastest, BlocksMalware, FamilySafe }

/// <summary>
/// A DNS server to test. <see cref="DohTemplate"/> is set only where the provider publishes one we rely on.
/// <see cref="ViaHttps"/>: time it over HTTPS with that template, because that is how it is (current DNS, private on)
/// or would be (switching turns private lookups on) really used (P12b).
/// </summary>
public sealed record DnsCandidate(string Name, string Address, string? Secondary = null, string? DohTemplate = null,
    bool IsCurrent = false, int Port = 53, bool ViaHttps = false)
{
    public bool SupportsEncryption => DohTemplate is not null;
}

/// <summary>Curated, maintained list. Addresses are the providers' published IPv4 resolvers.</summary>
public static class DnsCandidates
{
    public static IReadOnlyList<DnsCandidate> For(DnsGoal goal) => goal switch
    {
        DnsGoal.BlocksMalware => Malware,
        DnsGoal.FamilySafe => Family,
        _ => Fast,
    };

    public static IReadOnlyList<DnsCandidate> Fast { get; } =
    [
        new("Cloudflare", "1.1.1.1", "1.0.0.1", "https://cloudflare-dns.com/dns-query"),
        new("Google", "8.8.8.8", "8.8.4.4", "https://dns.google/dns-query"),
        new("Quad9 (no filter)", "9.9.9.10", "149.112.112.10", "https://dns10.quad9.net/dns-query"),
        new("AdGuard (no filter)", "94.140.14.140", "94.140.14.141", "https://unfiltered.adguard-dns.com/dns-query"),
        new("OpenDNS", "208.67.222.222", "208.67.220.220", "https://doh.opendns.com/dns-query"),
        new("Control D", "76.76.2.0", "76.76.10.0"),
        new("DNS4EU", "86.54.11.100", "86.54.11.200"),
        // Added P8 (each answered from the test PC on 2026-11-16). No DoH template until verified, so "Private" shows Not offered.
        new("CIRA Canadian Shield", "149.112.121.10", "149.112.122.10"),
        new("UltraDNS Public", "64.6.64.6", "64.6.65.6"),
        new("Hurricane Electric", "74.82.42.42"),
    ];

    public static IReadOnlyList<DnsCandidate> Malware { get; } =
    [
        new("Cloudflare Security", "1.1.1.2", "1.0.0.2", "https://security.cloudflare-dns.com/dns-query"),
        new("Quad9", "9.9.9.9", "149.112.112.112", "https://dns.quad9.net/dns-query"),
        new("AdGuard", "94.140.14.14", "94.140.15.15", "https://dns.adguard-dns.com/dns-query"),
        new("Control D Malware", "76.76.2.1", "76.76.10.1"),
        new("DNS4EU Protective", "86.54.11.1", "86.54.11.201"),
        new("CleanBrowsing Security", "185.228.168.9", "185.228.169.9"),
        new("CIRA Canadian Shield Protected", "149.112.121.20", "149.112.122.20"),
        new("UltraDNS Threat Protection", "156.154.70.2", "156.154.71.2"),
        new("Comodo Secure", "8.26.56.26"),   // its listed second address (8.20.247.20) didn't answer on 2026-11-16
    ];

    public static IReadOnlyList<DnsCandidate> Family { get; } =
    [
        new("Cloudflare Family", "1.1.1.3", "1.0.0.3", "https://family.cloudflare-dns.com/dns-query"),
        new("AdGuard Family", "94.140.14.15", "94.140.15.16", "https://family.adguard-dns.com/dns-query"),
        new("CleanBrowsing Family", "185.228.168.168", "185.228.169.168"),
        new("OpenDNS FamilyShield", "208.67.222.123", "208.67.220.123"),
        new("DNS4EU Child", "86.54.11.12", "86.54.11.212"),
        new("CIRA Canadian Shield Family", "149.112.121.30", "149.112.122.30"),
        new("UltraDNS Family", "156.154.70.3", "156.154.71.3"),
        new("Control D Family", "76.76.2.4", "76.76.10.4"),
    ];
}

/// <summary>
/// Which of a provider's two addresses goes first. Windows asks the first DNS server and only falls back to the
/// second when the first doesn't answer, so the first one sets everyday lookup speed. The provider's order is kept
/// unless the second address is clearly quicker from this PC: at least 10 % and more than 2 ms (the switching bar),
/// or the first didn't answer at all.
/// </summary>
public static class DnsAddressOrder
{
    public static DnsCandidate FasterFirst(DnsCandidate candidate, double? primaryMs, double? secondaryMs) =>
        candidate.Secondary is { } second && secondaryMs is { } s &&
        (primaryMs is not { } p || (p / Math.Max(s, 0.1) >= 1.1 && p - s > 2))
            ? candidate with { Address = second, Secondary = candidate.Address }
            : candidate;
}

public sealed record DnsBenchmarkOptions
{
    public int QuickQueries { get; init; } = 10;
    public int Finalists { get; init; } = 5;
    /// <summary>Popular and new-name lookups per finalist in each pass.</summary>
    public int CachedQueries { get; init; } = 15;
    public int FreshQueries { get; init; } = 15;
    /// <summary>
    /// Round 2 runs in passes spread over time (P8, user review: ~3 s was too short to trust). One slow moment on the
    /// line or at a server then can't decide the winner, and the spread between passes shows each server's wobble.
    /// GRC's DNS Benchmark found ~50 lookups per resolver the minimum for repeatable results; 3 × 30 = 90.
    /// </summary>
    public int Passes { get; init; } = 3;
    public TimeSpan PassGap { get; init; } = TimeSpan.FromSeconds(6);
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(1.5);
    public int Concurrency { get; init; } = 4;

    /// <summary>Popular names most resolvers already hold: measures the server's reply speed.</summary>
    public IReadOnlyList<string> PopularNames { get; init; } =
        ["google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com", "microsoft.com", "apple.com",
         "netflix.com", "instagram.com", "whatsapp.com"];

    /// <summary>
    /// Fresh lookups ask for a random name under these zones. They are not DNSSEC-signed, so a resolver cannot answer
    /// "does not exist" from aggressive NSEC caching and must ask the zone's servers: that measures real resolving.
    /// </summary>
    public IReadOnlyList<string> FreshZones { get; init; } = ["google.com", "microsoft.com", "amazon.com"];

    /// <summary>
    /// Safety checks (P9), one lookup each per finalist; they never change the ranking.
    /// A name whose DNSSEC signature is deliberately broken (kept up by Comcast for exactly this test): a server that
    /// checks signatures refuses it (SERVFAIL); one that doesn't hands out the address.
    /// </summary>
    public string FakeAnswerTestName { get; init; } = "dnssec-failed.org";

    /// <summary>A public name that points at a home-network address (192.168.0.1). A server that guards home devices
    /// (DNS rebinding protection) won't hand out a private address for a public name.</summary>
    public string HomeDeviceTestName { get; init; } = "192.168.0.1.nip.io";

    /// <summary>Signature checking can make the refusal slow, so safety lookups get longer than speed lookups.</summary>
    public TimeSpan SafetyTimeout { get; init; } = TimeSpan.FromSeconds(3);
}

public enum DnsRound { Quick = 1, Finalists = 2 }

/// <summary>Result for one server. Fresh = uncached lookups; Slowest = 90th percentile of all round-2 replies.</summary>
public sealed record DnsServerResult(DnsCandidate Server, double? QuickMs, int QuickFailed, int QuickSent,
    bool Finalist, double? CachedMs = null, double? FreshMs = null, double? SlowestMs = null,
    int Failed = 0, int Sent = 0, int Redirects = 0, double? TypicalMs = null, IReadOnlyList<double>? PassTypicalMs = null,
    bool? BlocksFakeAnswers = null, bool? GuardsHomeDevices = null)
{
    /// <summary>Half the spread of the per-pass typical times: how much this server's speed moved during the test.</summary>
    public double Wobble => PassTypicalMs is { Count: > 1 } p ? (p.Max() - p.Min()) / 2 : 0;

    public double? FailurePercent => Sent > 0 ? 100d * Failed / Sent : null;

    /// <summary>
    /// Lower is better. Ranked on the typical lookup (popular and new names weighted equally, like real browsing)
    /// and the slow tail. Fresh-only times can mislead: a resolver may answer "does not exist" quickly yet be slow on
    /// real sites (seen live: 14 ms fresh, 69 ms popular). Every 1 % of failures costs 40 ms; redirecting missing
    /// names to ads disqualifies a server.
    /// </summary>
    // Ranked on the typical lookup only, so the number shown on the podium always matches the order;
    // the slow tail is shown in the comparison but is not mixed into the rank.
    public double Score => !Finalist || TypicalMs is null
        ? double.MaxValue
        : TypicalMs.Value + (FailurePercent ?? 0) * 40 + (Redirects > 0 ? 10_000 : 0);
}

public sealed record DnsBenchmarkResult(DnsGoal Goal, DateTimeOffset Started, DateTimeOffset Ended, bool Stopped,
    IReadOnlyList<DnsServerResult> Servers)
{
    public const string Method = "netcheck-dns-v3";   // v3 (P12b): private servers timed over HTTPS

    /// <summary>Finalists, best first.</summary>
    public IReadOnlyList<DnsServerResult> Ranked => Servers.Where(s => s.Finalist && s.TypicalMs is not null)
        .OrderBy(s => s.Score).ToArray();

    public DnsServerResult? Current => Servers.FirstOrDefault(s => s.Server.IsCurrent);

    /// <summary>The best server that is not the one already in use.</summary>
    public DnsServerResult? Winner => Ranked.FirstOrDefault(s => !s.Server.IsCurrent && s.Redirects == 0);

    /// <summary>True when the current DNS ranked first (nothing faster was found).</summary>
    public bool CurrentIsBest => Ranked.FirstOrDefault()?.Server.IsCurrent == true;

    /// <summary>
    /// The winner is only "faster" when it beats the current DNS by at least 10 % and by more than normal wobble:
    /// 2 ms, or the larger of the two servers' pass-to-pass wobble. Otherwise the current DNS is already a great choice.
    /// Without a current result (not measurable) any winner counts.
    /// </summary>
    public bool WinnerIsMeaningfullyFaster =>
        Winner is { TypicalMs: { } w } winner && !CurrentIsBest && (Current is not { TypicalMs: { } c } current ||
            (c / Math.Max(w, 0.1) >= 1.1 && c - w > Math.Max(2, Math.Max(winner.Wobble, current.Wobble))));
}

/// <summary>Live progress for the race view: one server's latest numbers.</summary>
public sealed record DnsBenchmarkProgress(DnsRound Round, DnsCandidate Server, double? Ms, bool Done, bool Out = false,
    double Fraction = 0);
