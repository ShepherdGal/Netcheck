using System.Text;
using Netcheck.Core.Updates;

/// <summary>Version ordering and release-feed rules (no network).</summary>
internal static class UpdateChecks
{
    internal static void Run()
    {
        string[] ordered = ["0.9.9", "1.0.0-alpha", "1.0.0-dev.1", "1.0.0-dev.2", "1.0.0-dev.10", "1.0.0-rc.1", "1.0.0", "v1.0.1", "1.10.0"];
        for (var i = 1; i < ordered.Length; i++)
            Require(AppVersion.Parse(ordered[i - 1]) < AppVersion.Parse(ordered[i]), $"{ordered[i - 1]} < {ordered[i]}");
        Require(AppVersion.Parse("1.0.0-dev.2+abc123").Equals(AppVersion.Parse("v1.0.0-dev.2")), "build metadata and 'v' ignored");
        foreach (var bad in new[] { "", "1.0", "1.0.0.0", "01.0.0", "1.0.0-", "1.0.0-dev..1", "x.y.z", "1.0.0-dev_1" })
            Require(!AppVersion.TryParse(bad, out _), $"rejects '{bad}'");
        Console.WriteLine("PASS version ordering and parsing");

        var sha = new string('a', 64);
        var json = Encoding.UTF8.GetBytes($$"""
        [
          {"tag_name":"v1.0.0-dev.3","draft":false,"prerelease":true,"html_url":"https://github.com/ShepherdGal/Netcheck/releases/tag/v1.0.0-dev.3","body":"Fixes",
           "assets":[{"name":"Netcheck-1.0.0-dev.3-win-x64.zip","size":52000000,"browser_download_url":"https://github.com/ShepherdGal/Netcheck/releases/download/v1.0.0-dev.3/Netcheck-1.0.0-dev.3-win-x64.zip","digest":"sha256:{{sha}}"}]},
          {"tag_name":"v1.0.0-dev.4","draft":true,"prerelease":true,"html_url":"https://github.com/ShepherdGal/Netcheck/releases/tag/v1.0.0-dev.4",
           "assets":[{"name":"Netcheck-1.0.0-dev.4-win-x64.zip","size":1,"browser_download_url":"https://github.com/x.zip","digest":"sha256:{{sha}}"}]},
          {"tag_name":"v1.0.0-dev.5","draft":false,"prerelease":true,"html_url":"https://github.com/ShepherdGal/Netcheck/releases/tag/v1.0.0-dev.5",
           "assets":[{"name":"Netcheck-1.0.0-dev.5-win-x64.zip","size":10,"browser_download_url":"https://github.com/a.zip"}]},
          {"tag_name":"v1.0.0-dev.6","draft":false,"prerelease":true,"html_url":"https://github.com/ShepherdGal/Netcheck/releases/tag/v1.0.0-dev.6",
           "assets":[{"name":"Netcheck-1.0.0-dev.6-win-x64.zip","size":10,"browser_download_url":"https://evil.example/a.zip","digest":"sha256:{{sha}}"}]},
          {"tag_name":"v1.0.0-dev.7","draft":false,"prerelease":true,"html_url":"https://github.com/ShepherdGal/Netcheck/releases/tag/v1.0.0-dev.7",
           "assets":[{"name":"Other.zip","size":10,"browser_download_url":"https://github.com/a.zip","digest":"sha256:{{sha}}"}]},
          {"tag_name":"v1.0.0","draft":false,"prerelease":false,"html_url":"https://github.com/ShepherdGal/Netcheck/releases/tag/v1.0.0",
           "assets":[{"name":"Netcheck-1.0.0-win-x64.zip","size":52000000,"browser_download_url":"https://github.com/ShepherdGal/Netcheck/releases/download/v1.0.0/Netcheck-1.0.0-win-x64.zip","digest":"sha256:{{sha}}"}]}
        ]
        """);
        var offers = ReleaseFeed.Parse(json);
        if (!ReleaseFeed.IsTestFeed)
        {
            Require(offers.Count == 2 && offers[0].Version.ToString() == "1.0.0" && offers[1].Version.ToString() == "1.0.0-dev.3",
                $"draft, no digest, foreign host and wrong file name skipped ({string.Join(", ", offers.Select(o => o.Version))})");
            Require(offers[1].Sha256 == sha.ToUpperInvariant() && offers[1].Notes == "Fixes", "digest and notes read");
        }
        Require(ReleaseFeed.Newest(offers, AppVersion.Parse("1.0.0-dev.2"))?.Version.ToString() == "1.0.0", "pre-release user gets newest");
        Require(ReleaseFeed.Newest(offers.Where(o => o.Version.IsPreRelease), AppVersion.Parse("0.9.0")) is null,
            "stable user is not offered pre-releases");
        Require(ReleaseFeed.Newest(offers, AppVersion.Parse("1.0.0")) is null, "nothing newer, nothing offered");
        Require(ReleaseFeed.Parse("{\"message\":\"Not Found\"}"u8).Count == 0, "non-list reply gives no offers");
        Console.WriteLine("PASS release feed rules (draft, digest, host, file name, pre-release)");

        // Version read from metadata (never the Windows loader): this test assembly and, when present, a published build.
        var own = AppVersion.ReadFromAssembly(typeof(UpdateChecks).Assembly.Location);
        Require(own is not null, "version read from this test assembly's metadata");
        var published = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "artifacts", "p7-test", "Netcheck-1.0.0-dev.4", "Netcheck.dll");
        if (File.Exists(published))
            Require(AppVersion.ReadFromAssembly(published)?.ToString() == "1.0.0-dev.4", "version read from a published Netcheck.dll");
        Require(AppVersion.ReadFromAssembly(Path.Combine(AppContext.BaseDirectory, "missing.dll")) is null, "missing file gives no version");
        Console.WriteLine($"PASS version from assembly metadata ({own}{(File.Exists(published) ? ", published 1.0.0-dev.4" : "")})");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException("FAIL " + message);
    }
}
