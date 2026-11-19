using System.Net;
using Netcheck.Core;

internal static class AssessmentChecks
{
    internal static void Run()
    {
        var options = new MeasurementOptions(new Uri("https://example.test"), MeasurementMode.Standard, 1024,
            TimeSpan.FromSeconds(20), IncludeSystemDns: true);
        var adapter = Guid.NewGuid();
        var path = new ObservedPath(IPAddress.Loopback, IPAddress.Parse("192.0.2.2"), adapter, false);
        var result = new MeasurementResult(options, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch,
            MeasurementState.Complete, new EndpointCapabilities(1, 1024, "fixture", null), [path], 1024,
            null, null, null, [], [], ProviderVersion: "HTTPS v1")
        {
            Route = new RouteObservation(adapter, IPAddress.Loopback, IPAddress.Parse("192.0.2.1"))
        };

        foreach (var (sample, quality) in new[]
        {
            (49.9, MetricQuality.Good), (50.0, MetricQuality.Fair),
            (99.9, MetricQuality.Fair), (100.0, MetricQuality.Poor)
        })
            Require(Read(WithProbes(sample), CheckMetric.ResponseTime).Quality == quality, $"latency {sample} ms");
        foreach (var (sample, quality) in new[]
        {
            (9.9, MetricQuality.Good), (10.0, MetricQuality.Fair),
            (29.9, MetricQuality.Fair), (30.0, MetricQuality.Poor)
        })
        {
            var variation = result with { Idle = new ProbeMeasurement([0, sample, 0, sample, 0, sample], 0, 0, 0) };
            Require(Read(variation, CheckMetric.ResponseVariation).Quality == quality, $"variation {sample} ms");
        }

        var stopped = WithProbes(40) with
        {
            State = MeasurementState.Stopped,
            Idle = new ProbeMeasurement([40, 40, 40, 40, 40], 1, 0, 0),
            Download = new TransferMeasurement(100, TimeSpan.FromSeconds(1), TransferEnd.ByteLimit, true, [],
                new ProbeMeasurement([], 0, 0, 0))
        };
        Require(Read(stopped, CheckMetric.ResponseTime).Quality == MetricQuality.Good, "completed idle survives cancellation");
        Require(Read(stopped, CheckMetric.ResponseVariation).Quality == MetricQuality.Neutral, "missing position prevents variation grade");
        Require(Read(stopped, CheckMetric.Download).Meaning == "No speed target set", "completed download stays visible");
        Require(Read(stopped, CheckMetric.Upload).Meaning == "Check stopped", "missing upload keeps stop reason");
        Require(Read(stopped, CheckMetric.PacketLoss).Value is null, "HTTPS timeout does not become packet loss");
        var canceled = stopped with { Idle = new ProbeMeasurement([40, 40, 40, 40, 40], 0, 0, 1) };
        Require(Read(canceled, CheckMetric.ResponseTime).Quality == MetricQuality.Neutral, "canceled probe does not count");
        var unknown = WithProbes(40) with { Provider = MeasurementProvider.Cloudflare };
        Require(Read(unknown, CheckMetric.ResponseTime).Meaning == "Not rated", "Cloudflare timing stays descriptive");
        var failed = WithProbes(40) with { State = MeasurementState.Failed };
        Require(Read(failed, CheckMetric.ResponseTime).Quality == MetricQuality.Neutral, "failed check stays neutral");
        var invalid = result with { Idle = new ProbeMeasurement([40, 40, 40, 40, double.NaN, -1], 0, 0, 0) };
        Require(Read(invalid, CheckMetric.ResponseTime).Quality == MetricQuality.Neutral, "invalid observations do not count");
        var dns = result with { SystemDns = [new DnsMeasurement("A", [], 3), new DnsMeasurement("AAAA", [7, 8], 1)] };
        Require(Read(dns, CheckMetric.NameLookup) is { Value: 7.5, Meaning: "Not enough data" }, "sparse DNS falls back to first available family");
        var cached = dns with { SystemDns = [new DnsMeasurement("A", [7, 8, 9], 0)] };
        Require(Read(cached, CheckMetric.NameLookup) is { Quality: MetricQuality.Neutral, Meaning: "May include cached replies" },
            "complete system DNS remains neutral");

        var repeated = result with { Repeats = [WithProbes(40), WithProbes(70), WithProbes(120)], PlannedRuns = 3 };
        Require(Read(repeated, CheckMetric.ResponseTime) is { Value: 70, Quality: MetricQuality.Fair }, "comparable median");
        var change = repeated with { Repeats = [WithProbes(40), WithProbes(70), WithProbes(120) with { Route = null }] };
        Require(Read(change, CheckMetric.ResponseTime) is { Value: 70, Quality: MetricQuality.Neutral }, "unverified route stays neutral");
        var interrupted = repeated with { State = MeasurementState.Stopped, Repeats = [WithProbes(40), stopped] };
        Require(Read(interrupted, CheckMetric.ResponseTime).Value is null, "incomplete runs do not form an aggregate");
        Require(Read(interrupted.Repeats![0], CheckMetric.ResponseTime).Quality == MetricQuality.Good, "individual run remains assessable");
        Console.WriteLine("PASS metric assessment boundaries, evidence, partial checks, DNS, loss and Thorough runs");

        MeasurementResult WithProbes(double sample) => result with
        {
            Idle = new ProbeMeasurement(Enumerable.Repeat(sample, 6).ToArray(), 0, 0, 0)
        };
    }

    private static MetricAssessment Read(MeasurementResult result, CheckMetric metric) =>
        MetricAssessment.For(result).Single(item => item.Metric == metric);

    private static void Require(bool condition, string description)
    {
        if (!condition)
            throw new InvalidOperationException($"Assessment failed: {description}");
    }
}
