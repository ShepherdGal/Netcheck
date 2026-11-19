using System.Diagnostics;
using Netcheck.Core;

namespace Netcheck.Measurements;

internal sealed class PayloadMeter(Action<int, double?> report)
{
    private readonly List<ThroughputSample> _samples = [];
    private long _started;
    private long _lastWindowBytes;
    private int _window;

    internal long Bytes { get; private set; }
    internal TimeSpan Elapsed => _started == 0 ? TimeSpan.Zero : Stopwatch.GetElapsedTime(_started);
    internal bool Started => Interlocked.Read(ref _started) != 0;
    internal IReadOnlyList<ThroughputSample> Samples => _samples.ToArray();

    internal void Start() => Interlocked.CompareExchange(ref _started, Stopwatch.GetTimestamp(), 0);

    internal void Add(int length)
    {
        Bytes += length;
        double? sample = null;
        var elapsed = Elapsed;
        var window = (int)(elapsed.TotalMilliseconds / MeasurementProtocol.SampleMilliseconds);
        if (window > _window)
        {
            // Assign completed I/O to its observed window. A zero window is meaningful only after data has started.
            for (var skipped = _window + 1; skipped < window; skipped++)
            {
                var bytes = skipped == _window + 1 ? Bytes - length - _lastWindowBytes : 0;
                Append(skipped, bytes);
            }
            var previousBytes = window == _window + 1 ? Bytes - length - _lastWindowBytes : 0;
            sample = Append(window, previousBytes);
            _lastWindowBytes = Bytes - length;
            _window = window;
        }
        report(length, sample);
    }

    private double Append(int window, long bytes)
    {
        var seconds = MeasurementProtocol.SampleMilliseconds / 1000d;
        var rate = bytes * 8e-6 / seconds;
        _samples.Add(new ThroughputSample(window * seconds, rate));
        return rate;
    }
}
