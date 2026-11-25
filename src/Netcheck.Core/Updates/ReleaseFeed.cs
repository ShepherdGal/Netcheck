using System.Net.Http.Headers;
using System.Text.Json;

namespace Netcheck.Core.Updates;

/// <summary>One release Netcheck may offer: a newer version whose Windows package has a published SHA-256.</summary>
public sealed record ReleaseOffer(AppVersion Version, string Tag, string Notes, Uri Page, string AssetName,
    Uri AssetUrl, long Size, string Sha256);

/// <summary>
/// Reads GitHub Releases for ShepherdGal/Netcheck. Only a release that is newer than the running version, is not a
/// draft, has the one-file <c>Netcheck.exe</c> and a GitHub "sha256:" digest for it is offered.
/// Pre-releases are offered only to someone already running a pre-release.
/// </summary>
public static class ReleaseFeed
{
#if NETCHECK_TEST_FEED
    // Test builds only (built with -p:NetcheckTestFeed=true): a local fixture feed for upgrade/rollback tests.
    public static readonly Uri Address = new("http://127.0.0.1:47613/repos/ShepherdGal/Netcheck/releases");
    public const bool IsTestFeed = true;
#else
    public static readonly Uri Address = new("https://api.github.com/repos/ShepherdGal/Netcheck/releases?per_page=20");
    public const bool IsTestFeed = false;
#endif
    public const long MaxPackageBytes = 200L * 1024 * 1024;
    private const int MaxFeedBytes = 2 * 1024 * 1024;

    public static string PackageName(AppVersion version) => "Netcheck.exe";   // one file per release (user, 2026-11-25)

    public static HttpClient CreateClient()
    {
        var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 5 })
        {
            Timeout = TimeSpan.FromSeconds(20),
        };
        // A generic client name: no personal details in requests.
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("Netcheck", "1"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        return client;
    }

    /// <summary>All valid offers in the feed (any version), newest first.</summary>
    public static async Task<IReadOnlyList<ReleaseOffer>> FetchAsync(HttpClient client, CancellationToken token)
    {
        using var response = await client.GetAsync(Address, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return [];   // no repository or no releases yet
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > MaxFeedBytes)
            throw new InvalidDataException("The release list is unexpectedly large.");
        await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
        using var limited = new MemoryStream();
        var buffer = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(buffer, token).ConfigureAwait(false)) > 0)
        {
            if (limited.Length + read > MaxFeedBytes)
                throw new InvalidDataException("The release list is unexpectedly large.");
            limited.Write(buffer, 0, read);
        }
        return Parse(limited.ToArray());
    }

    /// <summary>Parses a GitHub "list releases" reply. Invalid or incomplete releases are skipped, never guessed.</summary>
    public static IReadOnlyList<ReleaseOffer> Parse(ReadOnlySpan<byte> json)
    {
        var offers = new List<ReleaseOffer>();
        using var document = JsonDocument.Parse(json.ToArray());
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            return offers;
        foreach (var release in document.RootElement.EnumerateArray())
        {
            if (Bool(release, "draft") || Str(release, "tag_name") is not { } tag || !AppVersion.TryParse(tag, out var version))
                continue;
            if (Bool(release, "prerelease") != version.IsPreRelease)
                continue;   // the label and the version must agree
            if (!Uri.TryCreate(Str(release, "html_url"), UriKind.Absolute, out var page) || !Allowed(page))
                continue;
            var expected = PackageName(version);
            if (!release.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
                continue;
            foreach (var asset in assets.EnumerateArray())
            {
                if (Str(asset, "name") != expected ||
                    !Uri.TryCreate(Str(asset, "browser_download_url"), UriKind.Absolute, out var url) || !Allowed(url) ||
                    !asset.TryGetProperty("size", out var sizeElement) || !sizeElement.TryGetInt64(out var size) ||
                    size <= 0 || size > MaxPackageBytes || Sha(Str(asset, "digest")) is not { } sha)
                    continue;
                var notes = Str(release, "body") ?? "";
                offers.Add(new ReleaseOffer(version, tag, notes.Length > 4000 ? notes[..4000] : notes, page, expected, url, size, sha));
                break;
            }
        }
        offers.Sort((a, b) => b.Version.CompareTo(a.Version));
        return offers;
    }

    /// <summary>The newest offer worth showing to someone running <paramref name="current"/>, or null.</summary>
    public static ReleaseOffer? Newest(IEnumerable<ReleaseOffer> offers, AppVersion current) =>
        offers.Where(o => o.Version > current && (!o.Version.IsPreRelease || current.IsPreRelease))
            .OrderByDescending(o => o.Version).FirstOrDefault();

    private static bool Allowed(Uri uri) =>
        IsTestFeed ? uri.Scheme is "http" or "https" : uri.Scheme == Uri.UriSchemeHttps &&
            uri.Host is "github.com" or "api.github.com";

    private static string? Sha(string? digest) =>
        digest is { Length: 71 } d && d.StartsWith("sha256:", StringComparison.Ordinal) && d[7..].All(char.IsAsciiHexDigit)
            ? d[7..].ToUpperInvariant() : null;

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool Bool(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
}
