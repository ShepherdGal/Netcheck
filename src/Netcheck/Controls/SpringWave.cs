using System.Diagnostics;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace Netcheck.Controls;

/// <summary>
/// A reading that isn't done yet (user, 2026-11-17, replaces the breathing dot in the Check strip): three small dots
/// that rise and settle one after another on a damped spring, y = −A·e^(−4t)·sin(7t), so each kick peaks after ~0.15 s,
/// dips ~1 px below rest and is still by ~1 s; one wave every 1.6 s. Every unfinished reading moves, whether it is
/// being measured now or waits for a later stage (user, 2026-11-17, approved mockup). Draws only while attached and
/// visible; reduced motion = still dots.
/// </summary>
internal sealed class SpringWave : Control
{
    private const double Dot = 6, Gap = 5, Rise = 7, Period = 1.6, Stagger = 0.16;
    // Peak of e^(−4t)·sin(7t) is ≈ 0.476 (at t ≈ 0.15 s); scale so the highest point is Rise px.
    private const double Amplitude = Rise / 0.476;

    private readonly IBrush brush;
    // One clock for every wave: the strip is rebuilt at each stage change, and the waves must carry on in step.
    private static readonly Stopwatch clock = Stopwatch.StartNew();
    private bool attached;

    public SpringWave(string label)
    {
        brush = (IBrush)Application.Current!.FindResource("AccentBrush")!;
        Width = 3 * Dot + 2 * Gap;
        Height = Dot + Rise + 2;
        HorizontalAlignment = HorizontalAlignment.Center;
        VerticalAlignment = VerticalAlignment.Center;
        AutomationProperties.SetName(this, label);
    }

    private static bool Moving => !Motion.Reduced;

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        attached = true;
        if (Moving)
            NextFrame();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        attached = false;
        base.OnDetachedFromVisualTree(e);
    }

    private void NextFrame() => TopLevel.GetTopLevel(this)?.RequestAnimationFrame(_ =>
    {
        if (!attached || !IsEffectivelyVisible)
            return;   // stops when the reading is replaced, the page changes or the strip is hidden
        InvalidateVisual();
        NextFrame();
    });

    public override void Render(DrawingContext context)
    {
        var now = clock.Elapsed.TotalSeconds;
        var rest = Bounds.Height - Dot / 2 - 1;
        for (var i = 0; i < 3; i++)
        {
            double lift = 0, glow = 0;
            if (Moving)
            {
                var t = ((now - i * Stagger) % Period + Period) % Period;
                var spring = Math.Exp(-4 * t) * Math.Sin(7 * t);   // damped spring after a kick
                lift = Amplitude * spring;
                glow = Math.Clamp(spring / 0.476, 0, 1);
            }
            using (context.PushOpacity(Moving ? 0.45 + 0.5 * glow : 0.6))
                context.DrawEllipse(brush, null, new Point(Dot / 2 + i * (Dot + Gap), rest - lift), Dot / 2, Dot / 2);
        }
    }
}
