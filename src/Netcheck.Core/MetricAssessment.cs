namespace Netcheck.Core;

public enum CheckMetric { Download, Upload, ResponseTime, ResponseVariation, PacketLoss, NameLookup }
public enum MetricQuality { Neutral, Good, Fair, Poor }

public sealed record MetricAssessment(CheckMetric Metric, double? Value, string Unit, string Meaning,
    MetricQuality Quality = MetricQuality.Neutral, int SampleCount = 0)
{
    public const string PolicyVersion = "v1";

    public string Name => Metric switch
    {
        CheckMetric.Download => "Download",
        CheckMetric.Upload => "Upload",
        CheckMetric.ResponseTime => "Response time",
        CheckMetric.ResponseVariation => "Response variation",
        CheckMetric.PacketLoss => "Packet loss",
        _ => "Name lookup (DNS)"
    };

    public static MetricAssessment[] For(MeasurementResult result)
    {
        if (result.Repeats is not { } runs)
            return ForRun(result);

        var complete = result.State == MeasurementState.Complete && runs.Count == 3 && result.PlannedRuns == runs.Count;
        var comparable = complete && Comparable(runs);
        var readings = runs.Select(ForRun).ToArray();
        var summary = ForRun(result);
        for (var index = 0; index < summary.Length; index++)
        {
            var metric = summary[index];
            if (metric.Metric == CheckMetric.PacketLoss || !complete)
                continue;
            var measures = readings.Select(run => run[index]).ToArray();
            var values = measures.Select(item => item.Value).OfType<double>().ToArray();
            if (values.Length != runs.Count)
                continue;
            var median = MeasurementStatistics.Median(values)!.Value;
            var count = measures.Sum(item => item.SampleCount);
            summary[index] = comparable && measures.All(item => item.Quality != MetricQuality.Neutral)
                ? Grade(metric.Metric, median, count)
                : metric with
                {
                    Value = median, SampleCount = count,
                    Meaning = measures.All(item => item.Meaning == measures[0].Meaning) &&
                        measures[0].Quality == MetricQuality.Neutral ? measures[0].Meaning : "Not rated"
                };
        }
        return summary;
    }

    private static MetricAssessment[] ForRun(MeasurementResult result)
    {
        var idle = result.Idle;
        var samples = idle?.Milliseconds.Where(Valid).ToArray() ?? [];
        var native = result.Provider == MeasurementProvider.NetcheckHttps && idle is { AttemptsKnown: true };
        var usable = native && idle is { Sent: 6, Canceled: 0 } && samples.Length == idle.Milliseconds.Count;
        var variation = samples.Length > 1 && samples.Length == idle?.Milliseconds.Count ? idle.JitterMs : null;
        var dns = result.SystemDns.Select(family => family.Milliseconds.Where(Valid).ToArray())
            .FirstOrDefault(values => values.Length > 0) ?? [];
        return
        [
            Rate(CheckMetric.Download, result.Download),
            Rate(CheckMetric.Upload, result.Upload),
            Probe(CheckMetric.ResponseTime, MeasurementStatistics.Median(samples), 5),
            Probe(CheckMetric.ResponseVariation, variation, 6),
            new(CheckMetric.PacketLoss, null, "%", "Not measured"),
            new(CheckMetric.NameLookup, MeasurementStatistics.Median(dns), "ms",
                dns.Length >= 3 ? "May include cached replies" :
                dns.Length > 0 || result.SystemDns.Count > 0 ? "Not enough data" :
                result.Options.IncludeSystemDns ? Missing() : "Not measured", SampleCount: dns.Length)
        ];

        MetricAssessment Rate(CheckMetric metric, TransferMeasurement? transfer)
        {
            if (result.Options.Mode == MeasurementMode.Quick)
                return new(metric, null, "Mbps", "Not measured in Quick");
            var value = transfer?.MegabitsPerSecond;
            if (value is not > 0 || !Valid(value.Value))
                return new(metric, null, "Mbps", Missing());

            var finished = result.Provider == MeasurementProvider.Cloudflare
                ? result.State == MeasurementState.Complete
                : transfer is { Acknowledged: true, IsSustained: true, End: TransferEnd.TargetDuration } or
                    { Acknowledged: true, IsSustained: false, End: TransferEnd.ByteLimit };
            return new(metric, value, "Mbps", finished ? "No speed target set" : "Partial measurement");
        }

        MetricAssessment Probe(CheckMetric metric, double? value, int minimum)
        {
            if (value is not { } reading || !Valid(reading))
                return new(metric, null, "ms", idle is null ? Missing() : "Not enough data", SampleCount: samples.Length);
            if (usable && samples.Length >= minimum && result.State != MeasurementState.Failed)
                return Grade(metric, reading, samples.Length);
            var meaning = result.State == MeasurementState.Failed ? "Check failed" :
                native ? "Not enough data" : "Not rated";
            return new(metric, reading, "ms", meaning, SampleCount: samples.Length);
        }

        string Missing() => result.State switch
        {
            MeasurementState.Stopped => "Check stopped",
            MeasurementState.TimedOut => "Time limit reached",
            MeasurementState.Failed => "Could not measure",
            _ => "Not measured"
        };
    }

    private static MetricAssessment Grade(CheckMetric metric, double value, int count)
    {
        var (meaning, quality) = (metric, value) switch
        {
            (CheckMetric.ResponseTime, < 50) => ("Quick replies", MetricQuality.Good),
            (CheckMetric.ResponseTime, < 100) => ("Moderate delay", MetricQuality.Fair),
            (CheckMetric.ResponseTime, _) => ("Slow replies", MetricQuality.Poor),
            (_, < 10) => ("Steady replies", MetricQuality.Good),
            (_, < 30) => ("Variable replies", MetricQuality.Fair),
            _ => ("Large swings", MetricQuality.Poor)
        };
        return new(metric, value, "ms", meaning, quality, count);
    }

    private static bool Comparable(IReadOnlyList<MeasurementResult> runs)
    {
        var first = runs[0];
        return first.Provider == MeasurementProvider.NetcheckHttps &&
            first.ProviderVersion is not null && first.Endpoint is not null &&
            first.Paths is [{ Adapter: not null, ViaProxy: false }] &&
            first.Route is { Adapter: not null, NextHop: not null } &&
            runs.All(run => run.State == MeasurementState.Complete && run.Provider == first.Provider &&
                run.ProviderVersion == first.ProviderVersion && run.Endpoint == first.Endpoint &&
                (run.Options with { PayloadBudget = first.Options.PayloadBudget }) == first.Options &&
                Math.Abs((decimal)run.Options.PayloadBudget - first.Options.PayloadBudget) <= 1 &&
                run.Paths.SequenceEqual(first.Paths) && run.Route == first.Route);
    }

    private static bool Valid(double value) => double.IsFinite(value) && value >= 0;
}
