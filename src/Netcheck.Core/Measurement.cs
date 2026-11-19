using System.Net;

namespace Netcheck.Core;

public static class MeasurementProtocol
{
    public const string Prefix = "/netcheck/v1";
    public const int Version = 1;
    public const int MiB = 1024 * 1024;
    public const long TransferLimit = 64L * MiB;
    public const long SustainedBudgetLimit = 6L * 1024 * MiB;
    public const int SustainedStreams = 3;
    public const int WarmupBytes = 32 * 1024;
    public const int SampleMilliseconds = 250;
    public const string AcknowledgedBytes = "X-Netcheck-Bytes";
    public static IReadOnlyList<string> DnsNames { get; } = Array.AsReadOnly(new[] { "example.com", "example.net", "example.org" });

    public static bool TryOrigin(string text, out Uri? origin)
    {
        if (Uri.TryCreate(text.Trim(), UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
            uri.HostNameType is UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6 &&
            uri.AbsolutePath == "/" && uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0)
        {
            origin = uri;
            return true;
        }
        origin = null;
        return false;
    }
}

public enum MeasurementMode { Quick, Standard, Thorough }
public enum MeasurementState { Complete, Partial, Stopped, Failed, TimedOut }
public enum MeasurementStage { Endpoint, Idle, Download, Upload, Dns, Validation }
public enum TransferEnd { ByteLimit, TimeLimit, ServerBusy, Interrupted, InvalidResponse, Sampled, TargetDuration, RequestLimit, RouteChanged }
public enum MeasurementProvider { NetcheckHttps, Cloudflare }

public sealed record EndpointCapabilities(int Version, long MaxTransferBytes, string Region, int? BytesPerSecond,
    int MaxSustainedStreams = 0);
public sealed record PayloadValidation(long Downloaded, long Uploaded);
public sealed record MeasurementOptions(Uri Endpoint, MeasurementMode Mode, long PayloadBudget,
    TimeSpan Duration, bool IncludeSystemDns, Guid? SelectedAdapter = null, TimeSpan? SustainedDuration = null);
public sealed record ObservedPath(IPAddress LocalAddress, IPAddress PeerAddress, Guid? Adapter, bool ViaProxy);
public sealed record RouteObservation(Guid? Adapter, IPAddress? Source, IPAddress? NextHop);
public sealed record ConnectionEvidence(string? AdapterType, long? LinkBitsPerSecond, uint? PriorWifiSignalPercent,
    long? AdapterReceivedBytes, long? AdapterSentBytes, bool? TunnelAdapterObserved);
public sealed record MeasurementProgress(MeasurementStage Stage, long PayloadBytes, double? CurrentMbps = null)
{
    public MeasurementReadings? Readings { get; init; }
}

public sealed record MeasurementReadings(double? DownloadMbps, double? UploadMbps, double? LatencyMs,
    double? JitterMs, double? ProbeTimeoutPercent, DnsMeasurement? Dns);
public sealed record ThroughputSample(double Seconds, double MegabitsPerSecond);
public sealed record TransferMeasurement(long Bytes, TimeSpan Elapsed, TransferEnd End, bool Acknowledged,
    IReadOnlyList<ThroughputSample> Samples, ProbeMeasurement Loaded, double? SampledMbps = null,
    bool IsSustained = false, int? PeakBulkStreams = null, long? VerifiedBytes = null)
{
    public double? MegabitsPerSecond => SampledMbps ?? (!IsSustained && Acknowledged && Bytes > 0 && Elapsed.TotalSeconds > 0
        ? Bytes * 8e-6 / Elapsed.TotalSeconds : null);
    public double? PeakMbps => Samples.Count == 0 ? null : Samples.Max(sample => sample.MegabitsPerSecond);
}

public sealed record ProbeMeasurement(IReadOnlyList<double> Milliseconds, int Unanswered, int Failed, int Canceled,
    bool AttemptsKnown = true)
{
    public int Sent => Milliseconds.Count + Unanswered + Failed + Canceled;
    public double? MedianMs => MeasurementStatistics.Median(Milliseconds);
    public double? JitterMs => Milliseconds.Count < 2 ? null :
        Milliseconds.Zip(Milliseconds.Skip(1), (first, second) => Math.Abs(second - first)).Average();
    public double? TimeoutPercent => !AttemptsKnown || Sent == Canceled ? null : 100d * Unanswered / (Sent - Canceled);
}

public sealed record DnsMeasurement(string RecordType, IReadOnlyList<double> Milliseconds, int Failed)
{
    public double? MedianMs => MeasurementStatistics.Median(Milliseconds);
}

public sealed record MeasurementResult(MeasurementOptions Options, DateTimeOffset Started, DateTimeOffset Ended,
    MeasurementState State, EndpointCapabilities? Endpoint, IReadOnlyList<ObservedPath> Paths, long PayloadBytes,
    ProbeMeasurement? Idle, TransferMeasurement? Download, TransferMeasurement? Upload,
    IReadOnlyList<DnsMeasurement> SystemDns, IReadOnlyList<string> Notes,
    MeasurementProvider Provider = MeasurementProvider.NetcheckHttps,
    string? ProviderVersion = null,
    ConnectionEvidence? Connection = null,
    Guid? InspectedAdapter = null)
{
    public IReadOnlyList<MeasurementResult>? Repeats { get; init; }
    public int PlannedRuns { get; init; } = 1;
    public string? ConnectionCost { get; init; }
    public string? MetricDefinition { get; init; }
    public RouteObservation? Route { get; init; }
}

public static class MeasurementStatistics
{
    public static double? Median(IEnumerable<double> values)
    {
        var sorted = values.Order().ToArray();
        if (sorted.Length == 0)
            return null;
        var center = sorted.Length / 2;
        return sorted.Length % 2 == 0 ? (sorted[center - 1] + sorted[center]) / 2 : sorted[center];
    }
}

public interface ISpeedTestProvider
{
    Task<MeasurementResult> RunAsync(MeasurementOptions options, IProgress<MeasurementProgress>? progress,
        CancellationToken cancellationToken);
}
