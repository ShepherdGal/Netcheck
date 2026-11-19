using System.Net;
using Netcheck.Core;
using Netcheck.Measurements.Resolvers;
using Netcheck.TestServer;

/// <summary>P4 DNS benchmark checks: wire format, ranking against fake servers with known delays, and a live run.</summary>
internal static class DnsBenchmarkChecks
{
    internal static async Task RunAsync()
    {
        WireChecks();
        await RankingAsync();
        await RedirectAndDeadAsync();
        await StopAsync();
        await SecondAddressAsync();
        await SafetyAsync();
        await HttpsRoutingAsync();
        Console.WriteLine("PASS all DNS benchmark checks");
    }

    private static void WireChecks()
    {
        var query = DnsWire.Query(0xBEEF, "www.example.com");
        Require(query.Length == 12 + 17 + 4 && query[0] == 0xBE && query[1] == 0xEF && query[2] == 0x01, "query header and RD flag");
        // Response: header + question + one compressed A answer (pointer 0xC00C)
        byte[] response = [.. query[..2], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, .. query[12..],
            0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34];
        Require(DnsWire.Parse(response) is { Id: 0xBEEF, IsResponse: true, Rcode: 0, Addresses: [var ip] } &&
            ip.Equals(IPAddress.Parse("93.184.216.34")), "parses a compressed A answer");
        Require(DnsWire.Parse(response.AsSpan(0, 20)) is null && DnsWire.Parse([1, 2]) is null, "malformed packets are rejected");
        Require(new DnsServerResult(new("A", "1.1.1.1"), 5, 0, 6, true, 5, 10, 20, 0, 30, TypicalMs: 8).Score <
                new DnsServerResult(new("B", "1.1.1.2"), 5, 0, 6, true, 5, 10, 20, 3, 30, TypicalMs: 8).Score,
            "failures make a server rank lower");
        // Meaningful-win rule (P8): at least 10 % and beyond 2 ms / pass-to-pass wobble.
        static DnsBenchmarkResult Race(double current, double winner, double[] currentPasses, double[] winnerPasses) =>
            new(DnsGoal.Fastest, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, false,
            [
                new DnsServerResult(new("Now", "10.0.0.1", IsCurrent: true), current, 0, 10, true, Sent: 90, TypicalMs: current, PassTypicalMs: currentPasses),
                new DnsServerResult(new("Other", "10.0.0.2"), winner, 0, 10, true, Sent: 90, TypicalMs: winner, PassTypicalMs: winnerPasses),
            ]);
        Require(Race(36, 12, [35, 36, 37], [12, 12, 13]).WinnerIsMeaningfullyFaster, "3× quicker counts as faster");
        Require(!Race(35, 34, [35, 35, 35], [34, 34, 34]).WinnerIsMeaningfullyFaster, "1 ms ahead is not faster");
        Require(!Race(36, 31, [30, 36, 42], [31, 31, 31]).WinnerIsMeaningfullyFaster, "5 ms ahead within 6 ms wobble is not faster");
        Require(Race(60, 40, [59, 60, 61], [40, 40, 41]).WinnerIsMeaningfullyFaster, "20 ms ahead beyond wobble is faster");
        Require(!Race(30, 35, [30, 30, 30], [35, 35, 35]).WinnerIsMeaningfullyFaster, "the current DNS ranked first: nothing to switch to");
        Console.WriteLine("PASS DNS wire format and scoring rules");
    }

    private static DnsBenchmarkOptions Fast => new()
    {
        QuickQueries = 6, CachedQueries = 10, FreshQueries = 10, Timeout = TimeSpan.FromMilliseconds(400),
        Passes = 3, PassGap = TimeSpan.FromMilliseconds(150),
    };

    private static async Task RankingAsync()
    {
        await using var quick = new FakeDnsServer(TimeSpan.FromMilliseconds(5), TimeSpan.FromMilliseconds(25));
        await using var slow = new FakeDnsServer(TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(70));
        await using var lossy = new FakeDnsServer(TimeSpan.FromMilliseconds(5), TimeSpan.FromMilliseconds(20), dropEvery: 4);
        DnsCandidate[] candidates =
        [
            new("Slow", "127.0.0.1", Port: slow.Port, IsCurrent: true),
            new("Quick", "127.0.0.1", Port: quick.Port),
            new("Lossy", "127.0.0.1", Port: lossy.Port),
        ];
        var updates = 0;
        var result = await new DnsBenchmarkEngine().RunAsync(DnsGoal.Fastest, candidates, Fast,
            new InlineProgress<DnsBenchmarkProgress>(_ => Interlocked.Increment(ref updates)), CancellationToken.None);
        var q = result.Servers.Single(s => s.Server.Name == "Quick");
        var s = result.Servers.Single(s => s.Server.Name == "Slow");
        var l = result.Servers.Single(s => s.Server.Name == "Lossy");
        Require(q.FreshMs is >= 23 and <= 60 && q.CachedMs is >= 4 and <= 30, $"quick server timings match its delays ({q.CachedMs:0.0}/{q.FreshMs:0.0} ms)");
        Require(s.FreshMs is >= 68 and <= 110, $"slow server fresh ≈ 70 ms ({s.FreshMs:0.0})");
        Require(l.Failed > 0 && l.Score > q.Score, $"lossy server is penalised ({l.Failed}/{l.Sent} failed)");
        Require(result.Winner?.Server.Name == "Quick" && result.Current?.Server.Name == "Slow" && !result.CurrentIsBest,
            "the quick server wins and the current DNS is kept for comparison");
        Require(updates > 10, "progress is reported for the live race");
        Require(q.PassTypicalMs is { Count: 3 } && q.Sent == 3 * 20, $"three passes of 20 lookups ({q.PassTypicalMs?.Count} passes, {q.Sent} sent)");
        Require(result.WinnerIsMeaningfullyFaster, "a clearly quicker server counts as faster");
        Console.WriteLine($"PASS ranking: Quick {q.FreshMs:0.0} ms fresh, Slow {s.FreshMs:0.0} ms, Lossy {l.Failed}/{l.Sent} failed");
    }

    private static async Task RedirectAndDeadAsync()
    {
        await using var redirect = new FakeDnsServer(TimeSpan.FromMilliseconds(2), TimeSpan.FromMilliseconds(2), redirectMissing: true);
        await using var honest = new FakeDnsServer(TimeSpan.FromMilliseconds(8), TimeSpan.FromMilliseconds(30));
        DnsCandidate[] candidates =
        [
            new("Redirects", "127.0.0.1", Port: redirect.Port),
            new("Honest", "127.0.0.1", Port: honest.Port),
            new("Dead", "127.0.0.1", Port: 9),   // nothing listens
        ];
        var result = await new DnsBenchmarkEngine().RunAsync(DnsGoal.Fastest, candidates, Fast, null, CancellationToken.None);
        Require(result.Servers.Single(s => s.Server.Name == "Redirects").Redirects > 0, "redirecting missing names is detected");
        Require(result.Winner?.Server.Name == "Honest", "a faster server that redirects never wins");
        Require(result.Servers.Single(s => s.Server.Name == "Dead") is { Finalist: false, QuickMs: null }, "a dead server drops out in round 1");
        Console.WriteLine("PASS redirect detection and dead-server elimination");
    }

    private static async Task StopAsync()
    {
        await using var server = new FakeDnsServer(TimeSpan.FromMilliseconds(30), TimeSpan.FromMilliseconds(60));
        using var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        var result = await new DnsBenchmarkEngine().RunAsync(DnsGoal.Fastest, [new("Only", "127.0.0.1", Port: server.Port)],
            Fast, null, stop.Token);
        Require(result.Stopped && result.Winner is null, "stopping returns a partial result with no winner");
        Console.WriteLine("PASS stop returns a partial result");
    }

    /// <summary>The winner's second address is timed too; the quicker one goes first only when clearly quicker.</summary>
    private static async Task SecondAddressAsync()
    {
        var pair = new DnsCandidate("Pair", "10.0.0.1", "10.0.0.2");
        Require(DnsAddressOrder.FasterFirst(pair, 30, 12) is { Address: "10.0.0.2", Secondary: "10.0.0.1" }, "second 2.5× quicker goes first");
        Require(DnsAddressOrder.FasterFirst(pair, 16, 15) == pair, "1 ms quicker keeps the provider's order");
        Require(DnsAddressOrder.FasterFirst(pair, 3, 1.5) == pair, "under 2 ms apart keeps the order even at 2×");
        Require(DnsAddressOrder.FasterFirst(pair, 12, null) == pair, "a second address that doesn't answer stays second");
        Require(DnsAddressOrder.FasterFirst(pair, null, 20).Address == "10.0.0.2", "a first address that doesn't answer moves back");
        Require(DnsAddressOrder.FasterFirst(new("One", "10.0.0.1"), 30, 10).Secondary is null, "a single address is left alone");

        var engine = new DnsBenchmarkEngine(new DelayTransport(new() { ["10.0.0.1"] = 40, ["10.0.0.2"] = 8 }));
        var swapped = await engine.FasterFirstAsync(pair, CancellationToken.None);
        Require(swapped is { Address: "10.0.0.2", Secondary: "10.0.0.1" }, "timed: the quicker second address goes first");
        var even = new DnsBenchmarkEngine(new DelayTransport(new() { ["10.0.0.1"] = 10, ["10.0.0.2"] = 10 }));
        Require(await even.FasterFirstAsync(pair, CancellationToken.None) == pair, "timed: equal addresses keep the provider's order");
        var silent = new DnsBenchmarkEngine(new DelayTransport(new() { ["10.0.0.1"] = 10 }));
        Require(await silent.FasterFirstAsync(pair, CancellationToken.None) == pair, "timed: a silent second address stays second");
        Console.WriteLine("PASS second address timed, quicker one first");
    }

    /// <summary>P9 safety rows: rules on single replies, then a full run where each fake server behaves differently.</summary>
    private static async Task SafetyAsync()
    {
        IPAddress[] home = [IPAddress.Parse("192.168.0.1")], web = [IPAddress.Parse("93.184.216.34")];
        Require(DnsSafety.BlocksFakeAnswers(new(40, DnsSafety.RcodeServerFailure, 0), true) == true, "broken signature refused → blocks fake answers");
        Require(DnsSafety.BlocksFakeAnswers(new(20, 0, 1, web), true) == false, "broken signature answered → doesn't block");
        Require(DnsSafety.BlocksFakeAnswers(new(null, -1, 0), true) is null, "no reply → couldn't check");
        Require(DnsSafety.BlocksFakeAnswers(new(40, DnsSafety.RcodeServerFailure, 0), false) is null, "server failing everything → couldn't check, not yes");
        Require(DnsSafety.GuardsHomeDevices(new(20, 0, 1, home)) == false, "home address handed out → doesn't guard");
        Require(DnsSafety.GuardsHomeDevices(new(20, 0, 0, [])) == true, "home address withheld → guards");
        Require(DnsSafety.GuardsHomeDevices(new(20, DnsWire.RcodeNameError, 0, [])) == true, "answered 'no such name' → guards");
        Require(DnsSafety.GuardsHomeDevices(new(20, DnsSafety.RcodeServerFailure, 0)) is null, "server failure → couldn't check");
        Require(DnsSafety.GuardsHomeDevices(new(null, -1, 0)) is null, "no reply → couldn't check");
        Require(DnsSafety.IsHomeAddress(IPAddress.Parse("172.20.1.1")) && !DnsSafety.IsHomeAddress(IPAddress.Parse("172.32.0.1")) &&
                DnsSafety.IsHomeAddress(IPAddress.Parse("10.1.2.3")) && !DnsSafety.IsHomeAddress(IPAddress.Parse("8.8.8.8")), "home address ranges");

        DnsCandidate careful = new("Careful", "10.0.0.1"), open = new("Open", "10.0.0.2", IsCurrent: true), mute = new("Mute", "10.0.0.3");
        var options = Fast with { PassGap = TimeSpan.Zero, SafetyTimeout = TimeSpan.FromMilliseconds(200) };
        var result = await new DnsBenchmarkEngine(new SafetyTransport(options)).RunAsync(DnsGoal.Fastest, [careful, open, mute], options, null, CancellationToken.None);
        var c = result.Servers.Single(s => s.Server == careful);
        var o = result.Servers.Single(s => s.Server == open);
        var m = result.Servers.Single(s => s.Server == mute);
        Require(c is { BlocksFakeAnswers: true, GuardsHomeDevices: true }, $"careful server: yes / yes ({c.BlocksFakeAnswers}/{c.GuardsHomeDevices})");
        Require(o is { BlocksFakeAnswers: false, GuardsHomeDevices: false }, $"open server: no / no ({o.BlocksFakeAnswers}/{o.GuardsHomeDevices})");
        Require(m is { BlocksFakeAnswers: null, GuardsHomeDevices: null }, $"silent on test names: couldn't check ({m.BlocksFakeAnswers}/{m.GuardsHomeDevices})");
        Require(result.Winner?.Server == careful, "safety doesn't change the ranking (careful is also quickest here)");
        Console.WriteLine("PASS safety checks: fake answers and home devices");
    }

    /// <summary>10.0.0.1 checks signatures and withholds home addresses; 10.0.0.2 does neither; 10.0.0.3 ignores the test names.</summary>
    private sealed class SafetyTransport(DnsBenchmarkOptions options) : IDnsTransport
    {
        public async Task<DnsReply> QueryAsync(IPEndPoint server, string name, TimeSpan timeout, CancellationToken cancellationToken)
        {
            var who = server.Address.ToString();
            var ms = who == "10.0.0.1" ? 5.0 : 12.0;
            await Task.Delay(TimeSpan.FromMilliseconds(ms), cancellationToken);
            if (name == options.FakeAnswerTestName)
                return who switch
                {
                    "10.0.0.1" => new DnsReply(30, DnsSafety.RcodeServerFailure, 0),
                    "10.0.0.2" => new DnsReply(10, 0, 1, [IPAddress.Parse("69.252.80.75")]),
                    _ => new DnsReply(null, -1, 0),
                };
            if (name == options.HomeDeviceTestName)
                return who switch
                {
                    "10.0.0.1" => new DnsReply(10, 0, 0, []),
                    "10.0.0.2" => new DnsReply(10, 0, 1, [IPAddress.Parse("192.168.0.1")]),
                    _ => new DnsReply(null, -1, 0),
                };
            return name.StartsWith("nc", StringComparison.Ordinal) ? new DnsReply(ms, DnsWire.RcodeNameError, 0, []) : new DnsReply(ms, 0, 1, [IPAddress.Parse("93.184.216.34")]);
        }
    }

    /// <summary>P12b: private servers are timed over HTTPS, plain ones over UDP; the Check page's lookup follows the template.</summary>
    private static async Task HttpsRoutingAsync()
    {
        var udp = new DelayTransport(new() { ["10.0.0.1"] = 6, ["10.0.0.2"] = 30 });
        var https = new RecordingDoh(4);
        var engine = new DnsBenchmarkEngine(udp, https);
        DnsCandidate plain = new("Plain", "10.0.0.1"),
            secure = new("Private", "10.0.0.2", DohTemplate: "https://dns.example/dns-query", ViaHttps: true),
            offered = new("Offered", "10.0.0.3", DohTemplate: "https://other.example/dns-query");   // template, but timed plain
        var result = await engine.RunAsync(DnsGoal.Fastest, [plain, secure, offered], Fast, null, CancellationToken.None);
        Require(https.Servers.All(s => s == "10.0.0.2:443") && https.Servers.Count > 0, "only the private server goes over HTTPS");
        Require(https.Templates.All(t => t == "https://dns.example/dns-query"), "HTTPS lookups use the server's own template");
        Require(result.Ranked.FirstOrDefault()?.Server.Name == "Private", "the HTTPS time (4 ms), not the plain one (30 ms), ranks it");
        Require(result.Servers.Single(s => s.Server.Name == "Offered").QuickMs is null, "a template alone doesn't switch to HTTPS");
        Require(https.ConnectionsBag.Distinct().Order().SequenceEqual([0, 1, 2, 3, 4, 5]), "each of the 3 passes uses its own two HTTPS connections");

        var before = https.Servers.Count;
        Require(await engine.QuickLookupAsync("10.0.0.2", CancellationToken.None, httpsTemplate: "https://dns.example/dns-query") is { } q && q < 10,
            "Check's lookup with a template is timed over HTTPS");
        Require(https.Servers.Count > before, "Check's lookup with a template went over HTTPS");
        var quick = new RecordingDoh(4);
        await new DnsBenchmarkEngine(udp, quick).QuickLookupAsync("10.0.0.2", CancellationToken.None, httpsTemplate: "https://dns.example/dns-query");
        Require(quick.ConnectionsBag.Distinct().Count() == DnsBenchmarkEngine.QuickConnections, "Check's lookup spreads over 6 HTTPS connections");
        Require(await engine.QuickLookupAsync("10.0.0.2", CancellationToken.None) is { } p && p >= 25, "without a template it stays plain");
        Console.WriteLine("PASS private servers timed over HTTPS, others plain");
    }

    /// <summary>Fake DNS over HTTPS: answers every query after a fixed delay and records where it was sent. No network.</summary>
    private sealed class RecordingDoh(double ms) : IDohTransport
    {
        public System.Collections.Concurrent.ConcurrentBag<string> ServersBag { get; } = [];
        public System.Collections.Concurrent.ConcurrentBag<string> TemplatesBag { get; } = [];
        public List<string> Servers => [.. ServersBag];
        public List<string> Templates => [.. TemplatesBag];

        public System.Collections.Concurrent.ConcurrentBag<int> ConnectionsBag { get; } = [];

        public async Task<DnsReply> QueryAsync(IPEndPoint server, string template, string name, TimeSpan timeout, CancellationToken cancellationToken,
            int connection = 0)
        {
            ConnectionsBag.Add(connection);
            ServersBag.Add(server.ToString());
            TemplatesBag.Add(template);
            await Task.Delay(TimeSpan.FromMilliseconds(ms), cancellationToken);
            return name.StartsWith("nc", StringComparison.Ordinal) ? new DnsReply(ms, DnsWire.RcodeNameError, 0) : new DnsReply(ms, 0, 1);
        }
    }

    /// <summary>Read-only, tiny traffic: one provider timed plain and over HTTPS from this PC, the two ways Windows can reach it.</summary>
    internal static async Task LiveHttpsAsync()
    {
        var engine = new DnsBenchmarkEngine();
        foreach (var c in DnsCandidates.Fast.Where(c => c.DohTemplate is not null))
        {
            var plain = await engine.QuickLookupAsync(c.Address, CancellationToken.None);
            var https = await engine.QuickLookupAsync(c.Address, CancellationToken.None, httpsTemplate: c.DohTemplate);
            Console.WriteLine($"  {c.Name,-22} {c.Address,-15} plain {plain,6:0.0}  https {https,6:0.0}");
        }
    }

    /// <summary>Answers each address after a fixed delay (ms); addresses not listed never answer. No network.</summary>
    private sealed class DelayTransport(Dictionary<string, double> delays) : IDnsTransport
    {
        public async Task<DnsReply> QueryAsync(IPEndPoint server, string name, TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (!delays.TryGetValue(server.Address.ToString(), out var ms))
                return new DnsReply(null, -1, 0);
            await Task.Delay(TimeSpan.FromMilliseconds(ms), cancellationToken);
            // Made-up names don't exist (NXDOMAIN); popular names get one address.
            return name.StartsWith("nc", StringComparison.Ordinal) ? new DnsReply(ms, DnsWire.RcodeNameError, 0) : new DnsReply(ms, 0, 1);
        }
    }

    /// <summary>Read-only: times both addresses of each Fast-list provider from this PC and shows which goes first.</summary>
    internal static async Task LivePairsAsync()
    {
        var engine = new DnsBenchmarkEngine();
        foreach (var c in DnsCandidates.Fast.Where(c => c.Secondary is not null))
        {
            var first = await engine.QuickLookupAsync(c.Address, CancellationToken.None);
            var second = await engine.QuickLookupAsync(c.Secondary!, CancellationToken.None);
            var ordered = DnsAddressOrder.FasterFirst(c, first, second);
            Console.WriteLine($"  {c.Name,-22} {c.Address,-15} {first,6:0.0}  {c.Secondary,-15} {second,6:0.0}  first: {ordered.Address}");
        }
    }

    /// <summary>Real servers from the curated list plus the DNS this PC uses. Tiny traffic (a few hundred small UDP packets).</summary>
    internal static async Task LiveAsync(string? current)
    {
        var list = DnsCandidates.Fast.ToList();
        if (current is not null)
            list.Insert(0, new DnsCandidate("Your current DNS", current, IsCurrent: true));
        var result = await new DnsBenchmarkEngine().RunAsync(DnsGoal.Fastest, list, new DnsBenchmarkOptions(), null, CancellationToken.None);
        Console.WriteLine($"Live DNS benchmark ({(result.Ended - result.Started).TotalSeconds:0.0} s):");
        foreach (var s in result.Servers)
            Console.WriteLine($"  {s.Server.Name,-22} {s.Server.Address,-15} quick {s.QuickMs,6:0.0}  " +
                (s.Finalist ? $"typical {s.TypicalMs,6:0.0}  cached {s.CachedMs,6:0.0}  fresh {s.FreshMs,6:0.0}  slowest {s.SlowestMs,6:0.0}  failed {s.Failed}/{s.Sent}  redirects {s.Redirects}  fake-answers {s.BlocksFakeAnswers?.ToString() ?? "?"}  home {s.GuardsHomeDevices?.ToString() ?? "?"}" : "(not a finalist)"));
        Console.WriteLine($"Winner: {result.Winner?.Server.Name ?? "none"}; current is best: {result.CurrentIsBest}");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException("FAIL " + message);
    }

    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }
}
