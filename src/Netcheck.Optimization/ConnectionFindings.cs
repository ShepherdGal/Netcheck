using Netcheck.Core;

namespace Netcheck.Optimization;

public sealed record ConnectionFinding(string Title, string Scope, string Confidence, string Evidence,
    string Explanation, string Check, string Tradeoff);

public static class ConnectionFindings
{
    public static ConnectionFinding? Recommend(IReadOnlyList<ConnectionFinding> findings, MeasurementResult result, Guid? activeAdapter)
    {
        if (result.State != MeasurementState.Complete)
            return null;
        var runs = result.Repeats ?? [result];
        var matchesActive = activeAdapter is { } id && runs.Count > 0 &&
            runs.All(run => run.Paths is [{ ViaProxy: false, Adapter: { } observed }] && observed == id);
        return findings.Where(finding => finding.Scope is not ("Cable or port" or "Local traffic") || matchesActive)
            .OrderBy(finding => finding.Scope switch
            {
                "Cable or port" => 0,
                "Local traffic" => 1,
                "Test path" => 2,
                _ => 3
            })
            .FirstOrDefault();
    }

    public static IReadOnlyList<ConnectionFinding> Evaluate(MeasurementResult result)
    {
        var findings = new List<ConnectionFinding>();
        var runs = result.Repeats?.ToArray() ?? [result];
        if (result.State != MeasurementState.Complete || runs.Length == 0 ||
            runs.Any(run => run.State != MeasurementState.Complete))
            return [new("Incomplete measurement", "Test", "Inconclusive", $"Result: {result.State}",
                "A stopped or partial test can miss the conditions needed to identify a bottleneck.",
                "Repeat the same check when the connection is available and review any stop reason.", "A repeat uses its selected traffic allowance.")];

        Loaded("download", run => run.Download);
        Loaded("upload", run => run.Upload);
        foreach (var family in new[] { "A", "AAAA" })
        {
            var dns = runs.Select(run => run.SystemDns.FirstOrDefault(item => item.RecordType == family)).ToArray();
            if (dns.All(item => item is { Milliseconds.Count: >= 3, MedianMs: >= 100 }))
                findings.Add(new($"Slow Windows DNS lookups ({family})", "Windows resolver", "Limited",
                    $"Median {MeasurementStatistics.Median(dns.Select(item => item!.MedianMs!.Value)):0.#} ms across {runs.Length} run(s).",
                    "Slow lookups can delay the start of a connection. Windows DNS timings can include cached responses.",
                    "Repeat the same DNS check and review DNS assignment and policy in Connections. For managed DNS, share the result with your administrator.",
                    "Faster lookups can improve connection setup. Bulk transfer speed is measured separately."));
        }
        if (runs.All(run => run.Paths is [{ Adapter: not null, ViaProxy: false }] &&
            run.Connection is { AdapterType: "Ethernet" or "FastEthernetFx" or "FastEthernetT" or "GigabitEthernet",
                LinkBitsPerSecond: 100_000_000 }) &&
            runs.All(run => (run.Download?.MegabitsPerSecond ?? 0) >= 80))
            findings.Add(new("Ethernet link may limit download speed", "Cable or port", "Moderate",
                "Windows reported a 100 Mbps link and measured download reached at least 80 Mbps.",
                "The measured download approached the negotiated link rate. A port limited to 100 Mbps can produce the same evidence as a cable or negotiation issue.",
                "If both ports support gigabit, try a known-good cable or another gigabit port, then check the link rate and repeat the same test.",
                "Unplugging briefly interrupts connectivity. Reconnect the original cable or port to undo the check."));
        if (runs.All(run => run.Paths is [{ Adapter: not null, ViaProxy: false }] &&
            run.Options.SustainedDuration.HasValue && run.PayloadBytes >= MeasurementProtocol.MiB &&
            run.Connection is { AdapterReceivedBytes: { } received, AdapterSentBytes: { } sent } &&
            (double)received + sent - run.PayloadBytes > Math.Max(8L * MeasurementProtocol.MiB, run.PayloadBytes * 0.25)))
            findings.Add(new("Other adapter traffic may have affected the test", "Local traffic", "Limited",
                "Adapter counters exceeded measured payload by more than 25% and at least 8 MiB.",
                "Adapter totals include protocol overhead, retries and activity from other apps.",
                "Repeat while known downloads, sync or streaming are paused and compare the results.",
                "Pausing transfers delays their completion. Resume them after the retest."));
        return findings;

        void Loaded(string direction, Func<MeasurementResult, TransferMeasurement?> select)
        {
            var changes = new List<double>();
            foreach (var run in runs)
            {
                if (run.Idle is not { Milliseconds.Count: >= 5, MedianMs: { } idle } ||
                    select(run)?.Loaded is not { Milliseconds.Count: >= 5, MedianMs: { } loaded } ||
                    loaded - idle < Math.Max(30, idle * 0.5))
                    return;
                changes.Add(loaded - idle);
            }
            findings.Add(new($"Response time rose during {direction}", "Test path", runs.Length >= 3 ? "Moderate" : "Limited",
                $"HTTPS median increased by {MeasurementStatistics.Median(changes):0.#} ms across {runs.Length} run(s), with at least five idle and five loaded samples per run.",
                "Traffic queues can make calls and games less responsive during transfers. The test cannot locate the queue along the path.",
                "Repeat on the same endpoint and adapter with other traffic paused. Compare idle latency and latency during the same transfer direction.",
                "A repeat uses its selected traffic allowance. Pausing other transfers can delay their completion."));
        }
    }
}
