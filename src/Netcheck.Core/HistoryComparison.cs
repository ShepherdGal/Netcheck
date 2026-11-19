namespace Netcheck.Core;

public sealed record MetricComparison(string Metric, string Unit, double? Baseline, double? Retest,
    double? BaselineSpread, double? RetestSpread, int BaselineCount, int RetestCount, double? Delta, double? Percent,
    string Outcome, IReadOnlyList<double> BaselineValues, IReadOnlyList<double> RetestValues);

public sealed record HistoryComparison(string? Limitation, IReadOnlyList<MetricComparison> Metrics)
{
    public static HistoryComparison Compare(MeasurementResult baseline, MeasurementResult retest)
    {
        var before = baseline.Repeats?.ToArray() ?? [baseline];
        var after = retest.Repeats?.ToArray() ?? [retest];
        var limitation = Limit();
        var metrics = new[]
        {
            Measure("Download", "Mbps", run => run.Download?.MegabitsPerSecond, true, 1),
            Measure("Upload", "Mbps", run => run.Upload?.MegabitsPerSecond, true, 1),
            Measure("Idle latency", "ms", run => run.Idle?.MedianMs, false, 1),
            Measure("Idle jitter", "ms", run => run.Idle?.JitterMs, false, 1),
            Measure("Download loaded latency", "ms", run => run.Download?.Loaded.MedianMs, false, 1),
            Measure("Upload loaded latency", "ms", run => run.Upload?.Loaded.MedianMs, false, 1),
            Measure("Windows DNS A", "ms", run => run.SystemDns.FirstOrDefault(x => x.RecordType == "A")?.MedianMs, false, 1),
            Measure("Windows DNS AAAA", "ms", run => run.SystemDns.FirstOrDefault(x => x.RecordType == "AAAA")?.MedianMs, false, 1)
        };
        return new(limitation, metrics);

        string? Limit()
        {
            if (baseline.State != MeasurementState.Complete || retest.State != MeasurementState.Complete ||
                before.Any(x => x.State != MeasurementState.Complete) || after.Any(x => x.State != MeasurementState.Complete))
                return "One or both tests are incomplete.";
            if (baseline.Options != retest.Options || baseline.Provider != retest.Provider ||
                baseline.ProviderVersion is null || baseline.ProviderVersion != retest.ProviderVersion ||
                baseline.Endpoint != retest.Endpoint || baseline.MetricDefinition is null || baseline.MetricDefinition != retest.MetricDefinition)
                return "The provider, endpoint, workload or measurement definition differs.";
            if (before.Length != 3 || after.Length != 3)
                return "Three completed runs on each side are needed for a directional verdict.";
            var paths = baseline.Paths;
            if (paths is not [{ Adapter: not null, ViaProxy: false }] || !paths.SequenceEqual(retest.Paths) ||
                before.Concat(after).Any(run => !paths.SequenceEqual(run.Paths)))
                return "The same direct adapter and endpoint path could not be verified.";
            var first = before[0];
            if (first.Route is not { Adapter: not null, NextHop: not null } ||
                before.Concat(after).Any(run => run.Route != first.Route))
                return "The same route and gateway could not be verified.";
            if (baseline.ConnectionCost is null || baseline.ConnectionCost != retest.ConnectionCost ||
                before.Concat(after).Any(run => run.Connection?.LinkBitsPerSecond is null ||
                    run.Connection.LinkBitsPerSecond != first.Connection?.LinkBitsPerSecond ||
                    run.Connection.AdapterType != first.Connection?.AdapterType ||
                    run.Connection.AdapterType is null or "Wireless80211" ||
                    run.Connection.TunnelAdapterObserved == true || run.Connection.AdapterReceivedBytes is null ||
                    run.Connection.AdapterSentBytes is null))
                return "Link or connection conditions differ or cannot be verified.";
            if (before.Concat(after).Any(run => run.Connection!.AdapterReceivedBytes + run.Connection.AdapterSentBytes -
                run.PayloadBytes > Math.Max(2 * MeasurementProtocol.MiB, run.PayloadBytes / 5)))
                return "Adapter traffic was substantially higher than the test payload.";
            return null;
        }

        MetricComparison Measure(string name, string unit, Func<MeasurementResult, double?> read, bool higherIsBetter, double floor)
        {
            var a = before.Select(read).OfType<double>().Where(double.IsFinite).ToArray();
            var b = after.Select(read).OfType<double>().Where(double.IsFinite).ToArray();
            var oldValue = MeasurementStatistics.Median(a);
            var newValue = MeasurementStatistics.Median(b);
            var delta = newValue - oldValue;
            var percent = oldValue > 0 ? delta / oldValue * 100 : null;
            var outcome = "Inconclusive";
            if (limitation is null && !name.StartsWith("Windows DNS", StringComparison.Ordinal) &&
                a.Length == before.Length && b.Length == after.Length && delta is { } change)
            {
                var tolerance = Math.Max(floor, oldValue!.Value * 0.05);
                if (Math.Abs(change) <= tolerance)
                    outcome = "Unchanged";
                else if (b.Min() > a.Max() || b.Max() < a.Min())
                    outcome = change > 0 == higherIsBetter ? "Better" : "Worse";
            }
            return new(name, unit, oldValue, newValue, Spread(a), Spread(b), a.Length, b.Length, delta, percent, outcome, a, b);
        }
    }

    private static double? Spread(double[] values) => values.Length < 2 ? null : values.Max() - values.Min();
}
