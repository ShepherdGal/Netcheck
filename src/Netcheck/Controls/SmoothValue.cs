using System.Diagnostics;
using Avalonia.Threading;

namespace Netcheck.Controls;

/// <summary>
/// Eases a displayed number toward its latest target (critically damped, ~180 ms time constant).
/// The timer runs only while the value is moving and is capped at ~60 updates per second, so a settled
/// gauge costs nothing. Raw measurements are never changed; this is presentation only.
/// </summary>
internal sealed class SmoothValue
{
    private readonly Action<double> apply;
    private readonly DispatcherTimer timer;
    private readonly Stopwatch clock = new();
    private double shown, target;

    public SmoothValue(Action<double> apply)
    {
        this.apply = apply;
        timer = new DispatcherTimer(TimeSpan.FromMilliseconds(16), DispatcherPriority.Render, (_, _) => Step());
    }

    public void Set(double value)
    {
        if (!double.IsFinite(value))
            return;
        target = value;
        if (Motion.Reduced)
        {
            shown = value;
            apply(value);
            return;
        }
        if (!timer.IsEnabled)
        {
            clock.Restart();
            timer.Start();
        }
    }

    public void Reset(double value = 0)
    {
        timer.Stop();
        shown = target = value;
        apply(value);
    }

    private void Step()
    {
        var dt = Math.Min(0.05, clock.Elapsed.TotalSeconds);
        clock.Restart();
        shown += (target - shown) * (1 - Math.Exp(-dt / 0.18));
        if (Math.Abs(target - shown) <= Math.Max(0.01, Math.Abs(target) * 0.002))
        {
            shown = target;
            timer.Stop();
        }
        apply(shown);
    }
}
