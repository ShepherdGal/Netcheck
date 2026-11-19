using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace Netcheck.Controls;

/// <summary>
/// Dusk gauge: a thick 240° arc with a soft track, a gradient value stroke, a faint inner tick ring that
/// brightens up to the value, and a small light at the tip. Draws only when Value or size changes
/// (no per-frame work); callers animate Value themselves.
/// </summary>
public sealed class ArcGauge : Control
{
    public static readonly StyledProperty<double> ValueProperty =
        AvaloniaProperty.Register<ArcGauge, double>(nameof(Value));
    public static readonly StyledProperty<IBrush?> AccentProperty =
        AvaloniaProperty.Register<ArcGauge, IBrush?>(nameof(Accent));
    public static readonly StyledProperty<IBrush?> TrackProperty =
        AvaloniaProperty.Register<ArcGauge, IBrush?>(nameof(Track));
    public static readonly StyledProperty<IBrush?> TickProperty =
        AvaloniaProperty.Register<ArcGauge, IBrush?>(nameof(Tick));
    public static readonly StyledProperty<double> ThicknessProperty =
        AvaloniaProperty.Register<ArcGauge, double>(nameof(Thickness), 16);
    public static readonly StyledProperty<double> DiameterProperty =
        AvaloniaProperty.Register<ArcGauge, double>(nameof(Diameter), 330);

    static ArcGauge()
    {
        AffectsRender<ArcGauge>(ValueProperty, AccentProperty, TrackProperty, TickProperty, ThicknessProperty);
        AffectsMeasure<ArcGauge>(DiameterProperty, ThicknessProperty);
    }

    /// <summary>Fill fraction, 0 to 1.</summary>
    public double Value { get => GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public IBrush? Accent { get => GetValue(AccentProperty); set => SetValue(AccentProperty, value); }
    public IBrush? Track { get => GetValue(TrackProperty); set => SetValue(TrackProperty, value); }
    public IBrush? Tick { get => GetValue(TickProperty); set => SetValue(TickProperty, value); }
    public double Thickness { get => GetValue(ThicknessProperty); set => SetValue(ThicknessProperty, value); }
    /// <summary>Largest width the gauge grows to.</summary>
    public double Diameter { get => GetValue(DiameterProperty); set => SetValue(DiameterProperty, value); }

    private const double StartDegrees = 150, SweepDegrees = 240;
    private const int Ticks = 48;

    protected override Size MeasureOverride(Size available)
    {
        var w = double.IsInfinity(available.Width) ? Diameter : Math.Min(available.Width, Diameter);
        return new Size(w, (w - Thickness) * 0.75 + Thickness);
    }

    public override void Render(DrawingContext context)
    {
        // The 240° arc spans 2r wide and 1.5r tall (top to the ends at ±30° below centre), plus the stroke.
        var t = Thickness;
        var radius = Math.Min((Bounds.Width - t) / 2, (Bounds.Height - t) / 1.5);
        if (radius <= 0)
            return;
        var center = new Point(Bounds.Width / 2, radius + t / 2);
        var v = Math.Clamp(double.IsFinite(Value) ? Value : 0, 0, 1);

        if (Track is { } track)
            context.DrawGeometry(null, new Pen(track, t, lineCap: PenLineCap.Round), Arc(center, radius, 0, 1));

        if (Tick is { } tick)
        {
            var lit = new Pen(tick, 1.2, lineCap: PenLineCap.Round);
            var dim = new Pen(tick, 1.2, lineCap: PenLineCap.Round);
            var inner = radius - t / 2 - 8;
            for (var i = 0; i <= Ticks; i++)
            {
                var g = (double)i / Ticks;
                var length = i % 8 == 0 ? 8 : 4;
                using (context.PushOpacity(g <= v && v > 0.002 ? 0.55 : 0.14))
                    context.DrawLine(g <= v ? lit : dim, On(center, inner, Angle(g)), On(center, inner - length, Angle(g)));
            }
        }

        if (v > 0.002 && Accent is { } accent)
        {
            context.DrawGeometry(null, new Pen(accent, t, lineCap: PenLineCap.Round), Arc(center, radius, 0, v));
            var tip = On(center, radius, Angle(v));
            using (context.PushOpacity(0.9))
                context.DrawEllipse(Brushes.White, null, tip, 3.5, 3.5);
        }
    }

    private static double Angle(double fraction) => StartDegrees + SweepDegrees * fraction;

    private static Point On(Point c, double r, double deg)
    {
        var rad = deg * Math.PI / 180;
        return new Point(c.X + r * Math.Cos(rad), c.Y + r * Math.Sin(rad));
    }

    private static StreamGeometry Arc(Point center, double radius, double from, double to)
    {
        var sweep = SweepDegrees * (to - from);
        var geometry = new StreamGeometry();
        using var ctx = geometry.Open();
        ctx.BeginFigure(On(center, radius, Angle(from)), false);
        ctx.ArcTo(On(center, radius, Angle(to)), new Size(radius, radius), 0, sweep > 180, SweepDirection.Clockwise);
        ctx.EndFigure(false);
        return geometry;
    }
}
