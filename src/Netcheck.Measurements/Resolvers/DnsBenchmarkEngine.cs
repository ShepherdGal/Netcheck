using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Netcheck.Core;

namespace Netcheck.Measurements.Resolvers;

/// <summary>One DNS reply: time in ms (null = no reply in time), response code and A answers.</summary>
public sealed record DnsReply(double? Ms, int Rcode, int Answers, IReadOnlyList<IPAddress>? Addresses = null);

/// <summary>
/// Reads the two safety checks from single replies. Null = couldn't check (no reply, or the test name itself
/// failed), never a guess.
/// </summary>
public static class DnsSafety
{
    public const int RcodeServerFailure = 2;

    /// <summary>
    /// Reply for the broken-signature name. Refused (SERVFAIL) = checks signatures = yes; an address = no.
    /// Only meaningful when the same server answers ordinary names (<paramref name="answersNormally"/>).
    /// </summary>
    public static bool? BlocksFakeAnswers(DnsReply reply, bool answersNormally) =>
        !answersNormally || reply.Ms is null ? null
        : reply.Rcode == RcodeServerFailure ? true
        : reply.Rcode == DnsWire.RcodeNoError && reply.Answers > 0 ? false
        : null;

    /// <summary>Reply for the public name that points home. A private address handed out = no; withheld = yes.</summary>
    public static bool? GuardsHomeDevices(DnsReply reply) =>
        reply.Ms is null || reply.Rcode == RcodeServerFailure ? null
        : reply.Addresses?.Any(IsHomeAddress) == true ? false
        : reply.Rcode == DnsWire.RcodeNoError && reply.Answers > 0 && reply.Addresses is null ? null   // can't see addresses
        : true;

    /// <summary>Private (10/8, 172.16/12, 192.168/16), loopback and link-local IPv4 addresses.</summary>
    public static bool IsHomeAddress(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
            return false;
        var b = address.GetAddressBytes();
        return b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1] is >= 16 and <= 31) ||
               (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
    }
}

/// <summary>Sends one query and waits for the matching reply. Swappable for tests.</summary>
public interface IDnsTransport
{
    Task<DnsReply> QueryAsync(IPEndPoint server, string name, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Plain DNS over UDP straight to the server (bypasses the Windows DNS cache). A fresh socket per query.</summary>
public sealed class UdpDnsTransport : IDnsTransport
{
    public async Task<DnsReply> QueryAsync(IPEndPoint server, string name, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var id = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);
        var query = DnsWire.Query(id, name);
        using var socket = new UdpClient(server.AddressFamily);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var clock = Stopwatch.StartNew();
        try
        {
            socket.Connect(server);
            await socket.SendAsync(query, deadline.Token).ConfigureAwait(false);
            while (true)
            {
                var packet = await socket.ReceiveAsync(deadline.Token).ConfigureAwait(false);
                var reply = DnsWire.Parse(packet.Buffer);
                // Ignore anything that isn't the answer to this exact question.
                if (reply is { IsResponse: true } && reply.Id == id)
                    return new DnsReply(clock.Elapsed.TotalMilliseconds, reply.Rcode, reply.Addresses.Count, reply.Addresses);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new DnsReply(null, -1, 0);   // timed out
        }
        catch (SocketException)
        {
            return new DnsReply(null, -1, 0);   // unreachable (e.g. ICMP port unreachable)
        }
    }
}

/// <summary>
/// Two-round DNS benchmark (design plan §6). Round 1 asks every candidate a few popular names and drops failures and
/// the slow tail. Round 2 gives the finalists cached and fresh (uncached) lookups in a shuffled, interleaved order,
/// so no server benefits from going first. Also detects servers that redirect non-existent names (ads/hijacking).
/// </summary>
public sealed class DnsBenchmarkEngine(IDnsTransport? transport = null, IDohTransport? https = null)
{
    private readonly IDnsTransport transport = transport ?? new UdpDnsTransport();
    private readonly IDohTransport https = https ?? new DohDnsTransport();

    public async Task<DnsBenchmarkResult> RunAsync(DnsGoal goal, IReadOnlyList<DnsCandidate> candidates, DnsBenchmarkOptions options,
        IProgress<DnsBenchmarkProgress>? progress, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var results = new Dictionary<DnsCandidate, DnsServerResult>();
        var stopped = false;
        try
        {
            // ---- Round 1: quick test of everyone ----
            using var gate = new SemaphoreSlim(options.Concurrency);
            var total = candidates.Count;
            var finished = 0;
            await Task.WhenAll(candidates.Select(async candidate =>
            {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    var times = new List<double>();
                    var failed = 0;
                    foreach (var name in Shuffle(options.PopularNames).Take(options.QuickQueries))
                    {
                        var reply = await Ask(candidate, name, options, cancellationToken).ConfigureAwait(false);
                        if (reply.Ms is { } ms && reply.Rcode == DnsWire.RcodeNoError) times.Add(ms); else failed++;
                        progress?.Report(new DnsBenchmarkProgress(DnsRound.Quick, candidate, MeasurementStatistics.Median(times), false));
                    }
                    var quick = new DnsServerResult(candidate, MeasurementStatistics.Median(times), failed, options.QuickQueries, false);
                    lock (results)
                        results[candidate] = quick;
                    progress?.Report(new DnsBenchmarkProgress(DnsRound.Quick, candidate, quick.QuickMs, true,
                        Fraction: Interlocked.Increment(ref finished) / (double)total));
                }
                finally
                {
                    gate.Release();
                }
            })).ConfigureAwait(false);

            // Finalists: answered at least two thirds of the quick questions; fastest first; current DNS always kept.
            var healthy = results.Values.Where(r => r.QuickMs is not null && r.QuickFailed * 3 <= r.QuickSent)
                .OrderBy(r => r.QuickMs).ToList();
            var finalists = healthy.Take(options.Finalists).Select(r => r.Server).ToList();
            if (healthy.FirstOrDefault(r => r.Server.IsCurrent) is { } current && !finalists.Contains(current.Server))
                finalists.Add(current.Server);
            foreach (var r in results.Values.Where(r => !finalists.Contains(r.Server)).ToArray())
                progress?.Report(new DnsBenchmarkProgress(DnsRound.Quick, r.Server, r.QuickMs, true, Out: true, Fraction: 1));

            // ---- Round 2: cached + fresh lookups for the finalists, in passes spread over time ----
            // Within a pass the questions are shuffled and interleaved, so no server benefits from going first.
            var samples = finalists.ToDictionary(s => s, _ => (Cached: new List<double>(), Fresh: new List<double>(),
                Failed: 0, Sent: 0, Redirects: 0));
            var passTypical = finalists.ToDictionary(s => s, _ => new List<double>());
            var connectionTypical = finalists.ToDictionary(s => s, _ => new List<double>());
            var passes = Math.Max(1, options.Passes);
            var perServer = options.CachedQueries + options.FreshQueries;
            var totalJobs = finalists.Count * perServer * passes;
            var done = 0;
            for (var pass = 0; pass < passes; pass++)
            {
                if (pass > 0 && options.PassGap > TimeSpan.Zero)
                    await Task.Delay(options.PassGap, cancellationToken).ConfigureAwait(false);
                // Each pass uses new HTTPS connections, two per server (P12b): some providers send each connection to a
                // near or a far site (OpenDNS 2026-11-17: ~8 ms or ~65 ms on every lookup), so one connection is luck.
                // Alternate jobs share the two; the typical time is the average over all connections (below).
                var jobs = new List<(DnsCandidate Server, string Name, bool Fresh, int Connection)>();
                foreach (var server in finalists)
                {
                    jobs.AddRange(Shuffle(options.PopularNames).Take(Math.Min(options.CachedQueries, options.PopularNames.Count))
                        .Concat(Enumerable.Range(0, Math.Max(0, options.CachedQueries - options.PopularNames.Count))
                            .Select(i => options.PopularNames[i % options.PopularNames.Count]))
                        .Select((name, i) => (server, name, false, pass * ConnectionsPerPass + i % ConnectionsPerPass)));
                    jobs.AddRange(Enumerable.Range(0, options.FreshQueries)
                        .Select(i => (server, $"nc{RandomLabel()}.{options.FreshZones[i % options.FreshZones.Count]}", true,
                            pass * ConnectionsPerPass + i % ConnectionsPerPass)));
                }
                var thisPass = new Dictionary<(DnsCandidate Server, int Connection), (List<double> Cached, List<double> Fresh)>();
                foreach (var job in jobs)
                    thisPass.TryAdd((job.Server, job.Connection), (new List<double>(), new List<double>()));
                await Task.WhenAll(Shuffle(jobs).Select(async job =>
                {
                    await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                    try
                    {
                        var reply = await Ask(job.Server, job.Name, options, cancellationToken, job.Connection).ConfigureAwait(false);
                        double? live;
                        lock (samples)
                        {
                            var s = samples[job.Server];
                            s.Sent++;
                            if (reply.Ms is not { } ms || reply.Rcode is not (DnsWire.RcodeNoError or DnsWire.RcodeNameError))
                                s.Failed++;
                            else if (job.Fresh)
                            {
                                s.Fresh.Add(ms);
                                thisPass[(job.Server, job.Connection)].Fresh.Add(ms);
                                // A made-up name must not resolve; an address here means redirects (ads/hijacking).
                                if (reply.Rcode == DnsWire.RcodeNoError && reply.Answers > 0)
                                    s.Redirects++;
                            }
                            else
                            {
                                s.Cached.Add(ms);
                                thisPass[(job.Server, job.Connection)].Cached.Add(ms);
                            }
                            samples[job.Server] = s;
                            live = MeasurementStatistics.Median(s.Cached) is { } lc && MeasurementStatistics.Median(s.Fresh) is { } lf ? (lc + lf) / 2 : MeasurementStatistics.Median(s.Cached.Concat(s.Fresh));
                        }
                        progress?.Report(new DnsBenchmarkProgress(DnsRound.Finalists, job.Server, live, false,
                            Fraction: Interlocked.Increment(ref done) / (double)totalJobs));
                    }
                    finally
                    {
                        gate.Release();
                    }
                })).ConfigureAwait(false);
                foreach (var server in finalists)
                {
                    var perConnection = thisPass.Where(e => e.Key.Server == server)
                        .Select(e => Typical(e.Value.Cached, e.Value.Fresh)).OfType<double>().ToArray();
                    connectionTypical[server].AddRange(perConnection);
                    if (perConnection.Length > 0)
                        passTypical[server].Add(perConnection.Average());
                }
            }

            foreach (var (server, s) in samples)
            {
                var all = s.Cached.Concat(s.Fresh).Order().ToArray();
                results[server] = results[server] with
                {
                    Finalist = true,
                    CachedMs = MeasurementStatistics.Median(s.Cached),
                    FreshMs = MeasurementStatistics.Median(s.Fresh),
                    // Typical = popular and new sites weighted equally, per connection, averaged over every connection
                    // (P12b): what this PC gets over time as Windows reconnects, near site or far. (A plain median of
                    // the two clusters jumps between them and once made a slow resolver look fast.)
                    TypicalMs = connectionTypical[server].Count > 0 ? connectionTypical[server].Average()
                        : Typical(s.Cached, s.Fresh),
                    SlowestMs = all.Length == 0 ? null : all[(int)Math.Ceiling(0.9 * all.Length) - 1],
                    Failed = s.Failed, Sent = s.Sent, Redirects = s.Redirects,
                    PassTypicalMs = passTypical[server].ToArray(),
                };
                progress?.Report(new DnsBenchmarkProgress(DnsRound.Finalists, server, results[server].TypicalMs, true, Fraction: 1));
            }

            // ---- Safety checks for the finalists (information only; the ranking above is already final) ----
            await Task.WhenAll(finalists.Select(async server =>
            {
                var fake = await AskSafety(server, options.FakeAnswerTestName, options, cancellationToken).ConfigureAwait(false);
                var home = await AskSafety(server, options.HomeDeviceTestName, options, cancellationToken).ConfigureAwait(false);
                lock (results)
                    results[server] = results[server] with
                    {
                        BlocksFakeAnswers = DnsSafety.BlocksFakeAnswers(fake, answersNormally: results[server].CachedMs is not null),
                        GuardsHomeDevices = DnsSafety.GuardsHomeDevices(home),
                    };
            })).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            stopped = true;
        }

        var ordered = results.Values.OrderBy(r => r.Score).ThenBy(r => r.QuickMs ?? double.MaxValue).ToArray();
        return new DnsBenchmarkResult(goal, started, DateTimeOffset.UtcNow, stopped, ordered);
    }

    /// <summary>
    /// Typical lookup time of one server for the Check page's DNS box, with the same rule as the benchmark (popular and
    /// new names weighted equally per connection, averaged over connections) so both pages agree. Null when it doesn't
    /// answer. Over HTTPS it uses six separate connections side by side (P12b, the benchmark's 3 passes × 2): one
    /// connection can land on a far server site and make a quick provider look slow (seen live with OpenDNS).
    /// </summary>
    /// <param name="httpsTemplate">Set when the server is reached over HTTPS (private DNS): it is timed that way.</param>
    public async Task<double?> QuickLookupAsync(string address, CancellationToken cancellationToken, int each = 10,
        string? httpsTemplate = null)
    {
        if (!IPAddress.TryParse(address, out _))
            return null;
        var options = new DnsBenchmarkOptions();
        var candidate = new DnsCandidate("Current", address, DohTemplate: httpsTemplate, ViaHttps: httpsTemplate is not null);
        // Plain UDP already uses a fresh socket per lookup, so one group is enough there.
        var connections = httpsTemplate is null ? 1 : QuickConnections;
        var freshEach = connections == 1 ? each : Math.Max(3, (int)Math.Ceiling(each * 2.0 / connections));
        var groups = await Task.WhenAll(Enumerable.Range(0, connections)
            .Select(c => QuickSamplesAsync(candidate, options, each, freshEach, c, cancellationToken))).ConfigureAwait(false);
        var typical = groups.Where(g => g.Cached.Count * 2 >= each && g.Fresh.Count * 2 >= g.FreshSent)
            .Select(g => Typical(g.Cached, g.Fresh)).OfType<double>().ToArray();
        return typical.Length * 2 > connections ? typical.Average() : null;
    }

    /// <summary>HTTPS connections the Check page's DNS lookup spreads over (the benchmark's 3 passes × 2).</summary>
    public const int QuickConnections = 6;

    /// <summary>New HTTPS connections per server in each benchmark pass.</summary>
    public const int ConnectionsPerPass = 2;

    /// <summary>Popular and new names weighted equally; null without both.</summary>
    private static double? Typical(List<double> cached, List<double> fresh) =>
        MeasurementStatistics.Median(cached) is { } c && MeasurementStatistics.Median(fresh) is { } f ? (c + f) / 2 : null;

    private async Task<(List<double> Cached, List<double> Fresh, int FreshSent)> QuickSamplesAsync(DnsCandidate candidate,
        DnsBenchmarkOptions options, int each, int freshCount, int connection, CancellationToken cancellationToken)
    {
        var cached = new List<double>();
        var fresh = new List<double>();
        // All popular names, like the benchmark: per-name times differ a lot (8 vs 52 ms on one resolver), so a small
        // random subset made the median flip between runs.
        var popular = Shuffle(options.PopularNames).Take(each).ToArray();
        // Untimed warm-up, as the benchmark's quick round does: anycast resolvers keep separate caches per server,
        // so a first "popular" lookup can be a cold one (seen live: 59 ms here vs 33 ms in the DNS tab).
        foreach (var name in popular)
            await Ask(candidate, name, options, cancellationToken, connection).ConfigureAwait(false);
        foreach (var name in popular)
            if (await Ask(candidate, name, options, cancellationToken, connection).ConfigureAwait(false) is { Ms: { } ms, Rcode: DnsWire.RcodeNoError })
                cached.Add(ms);
        for (var i = 0; i < freshCount; i++)
            if (await Ask(candidate, $"nc{RandomLabel()}.{options.FreshZones[(i + connection) % options.FreshZones.Count]}", options,
                    cancellationToken, connection).ConfigureAwait(false) is { Ms: { } ms, Rcode: DnsWire.RcodeNoError or DnsWire.RcodeNameError })
                fresh.Add(ms);
        return (cached, fresh, freshCount);
    }

    /// <summary>
    /// Times the winner's two addresses side by side (same typical-lookup rule as the Check page) and returns the
    /// candidate with the quicker one first. Runs in the background after the result shows; the benchmark itself
    /// only timed the first address.
    /// </summary>
    public async Task<DnsCandidate> FasterFirstAsync(DnsCandidate candidate, CancellationToken cancellationToken)
    {
        if (candidate.Secondary is not { } second)
            return candidate;
        var template = candidate.ViaHttps ? candidate.DohTemplate : null;
        var primary = QuickLookupAsync(candidate.Address, cancellationToken, httpsTemplate: template);
        var secondary = QuickLookupAsync(second, cancellationToken, httpsTemplate: template);
        await Task.WhenAll(primary, secondary).ConfigureAwait(false);
        return DnsAddressOrder.FasterFirst(candidate, primary.Result, secondary.Result);
    }

    /// <summary>One safety lookup with a longer wait, asked once more if the first gets no reply (a lost UDP packet).</summary>
    private async Task<DnsReply> AskSafety(DnsCandidate server, string name, DnsBenchmarkOptions options, CancellationToken token)
    {
        var endpoint = new IPEndPoint(IPAddress.Parse(server.Address), server.Port);
        var reply = await transport.QueryAsync(endpoint, name, options.SafetyTimeout, token).ConfigureAwait(false);
        return reply.Ms is null ? await transport.QueryAsync(endpoint, name, options.SafetyTimeout, token).ConfigureAwait(false) : reply;
    }

    /// <summary>One timed lookup, sent the way the server is really used: HTTPS for private servers, plain UDP otherwise.</summary>
    private Task<DnsReply> Ask(DnsCandidate server, string name, DnsBenchmarkOptions options, CancellationToken token, int connection = 0) =>
        server is { ViaHttps: true, DohTemplate: { } template }
            ? https.QueryAsync(new IPEndPoint(IPAddress.Parse(server.Address), 443), template, name, options.Timeout, token, connection)
            : transport.QueryAsync(new IPEndPoint(IPAddress.Parse(server.Address), server.Port), name, options.Timeout, token);

    private static string RandomLabel() => Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();

    private static List<T> Shuffle<T>(IEnumerable<T> items)
    {
        var list = items.ToList();
        for (var i = list.Count - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
        return list;
    }
}
