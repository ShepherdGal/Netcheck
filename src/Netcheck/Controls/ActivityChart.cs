using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Immutable;
using Netcheck.Windows;

namespace Netcheck.Controls;

/// <summary>
/// Reads the internet adapter's byte counters once a second on a background timer and keeps the last ~70 seconds.
/// Shared by every chart, so returning to the Check tab shows the full minute straight away. Read-only; never throws.
/// </summary>
internal static class TrafficMonitor
{
    internal readonly record struct Sample(double Time, double DownMbps, double UpMbps);

    internal static readonly Stopwatch Clock = Stopwatch.StartNew();
    private static readonly object Gate = new();
    private static readonly List<Sample> Samples = [];
    private static Timer? timer;
    private static NetworkInterface? adapter;
    private static double routeReadAt = double.NegativeInfinity, lastTime;
    private static long lastRx = -1, lastTx = -1;

    internal static void Start()
    {
        lock (Gate)
            timer ??= new Timer(_ => Tick(), null, 0, 1000);
    }

    internal static Sample[] Snapshot()
    {
        lock (Gate)
            return [.. Samples];
    }

    private static void Tick()
    {
        try
        {
            var now = Clock.Elapsed.TotalSeconds;
            // Follow the route to the internet (it changes when Wi-Fi/Ethernet/VPN changes); re-check every 10 s.
            if (now - routeReadAt > 10)
            {
                routeReadAt = now;
                var id = RouteDiscovery.Read(IPAddress.Parse("1.1.1.1")).AdapterId;
                var found = id is { } guid
                    ? NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => Guid.TryParse(n.Id, out var g) && g == guid)
                    : null;
                if (found?.Id != adapter?.Id)
                    lastRx = lastTx = -1;   // new adapter: its counters aren't comparable with the old ones
                adapter = found;
            }

            double down = 0, up = 0;
            if (adapter is not null)
            {
                var stats = adapter.GetIPStatistics();
                long rx = stats.BytesReceived, tx = stats.BytesSent;
                var seconds = now - lastTime;
                if (lastRx >= 0 && rx >= lastRx && tx >= lastTx && seconds > 0.2)
                {
                    down = (rx - lastRx) * 8 / 1e6 / seconds;
                    up = (tx - lastTx) * 8 / 1e6 / seconds;
                }
                lastRx = rx;
                lastTx = tx;
            }
            lastTime = now;

            lock (Gate)
            {
                Samples.Add(new Sample(now, down, up));
                if (Samples.Count > 72)
                    Samples.RemoveAt(0);
            }
        }
        catch (Exception error) when (error is NetworkInformationException or InvalidOperationException or PlatformNotSupportedException)
        {
            adapter = null;
        }
    }
}

/// <summary>
/// "Network activity": download and upload over the last 60 seconds, drawn one sample behind real time so each new
/// reading glides in from the right instead of jumping. Monotone curves (no overshoot), a scale that eases, a faded
/// left edge. Redraws at most 30 times a second while visible; stops when detached, hidden or minimised.
/// With reduced motion it redraws once per new sample.
/// Speeds aren't shown as a constantly changing number (design rules "no jittery numbers", 2026-11-16): when a line makes a
/// clear bump, the bump's speed appears once above its top as a compact number that pops in on a slow spring, rides
/// left with the graph and fades out. Only the number: no dot, ring, box or scale label.
/// </summary>
internal sealed class ActivityChart : Control
{
    // The chart drifts ~17 px a second, so 30 frames a second already moves it about half a pixel per frame:
    // it looks as smooth as 60 at half the cost (measured: ~27 % → ~14 % of one core at 175 % scaling).
    private const double Span = 60, Delay = 1.25, FrameSeconds = 1.0 / 30 - 0.002;

    private static readonly ImmutablePen GridPen = new(new ImmutableSolidColorBrush(Color.FromArgb(13, 255, 255, 255)), 1);

    private readonly Series down, up;
    private bool attached;
    private (double Down, double Up, double Top)? legend;
    private readonly List<Bubble> bubbles = [];
    private double lastChecked = double.NegativeInfinity, lastDownBubble = double.NegativeInfinity, lastUpBubble = double.NegativeInfinity;

    /// <summary>One bump's speed: anchored to its sample, so it moves with the curve.</summary>
    private sealed record Bubble(bool Down, double Time, double Mbps, double Born);

    /// <summary>Formats a bump's speed in the user's units (set by the page).</summary>
    public Func<double, string> Format { get; set; } = mbps => $"{mbps:0.#} Mbps";
    private double yMax = 0.5, lastRender = double.NegativeInfinity, lastLegend = double.NegativeInfinity, lastSampleSeen;

    /// <summary>Raised up to four times a second: download Mbps, upload Mbps, top of the scale in Mbps.</summary>
    public event Action<double, double, double>? Changed;

    public ActivityChart()
    {
        down = new Series(Color.Parse("#D6E7FC"), 0.11, 1.7);
        up = new Series(Color.Parse("#5E8CCB"), 0.10, 1.4);
        // Old readings fade out on the left instead of being cut off.
        OpacityMask = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(1, 0, RelativeUnit.Relative),
            GradientStops = { new GradientStop(Color.FromArgb(0, 0, 0, 0), 0), new GradientStop(Colors.Black, 0.09) },
        };
        ClipToBounds = true;
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        TrafficMonitor.Start();
        attached = true;
        RequestFrame();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        attached = false;
        base.OnDetachedFromVisualTree(e);
    }

    private void RequestFrame() => TopLevel.GetTopLevel(this)?.RequestAnimationFrame(_ => OnFrame());

    private void OnFrame()
    {
        if (!attached)
            return;
        if (legend is { } readings)
        {
            legend = null;
            Changed?.Invoke(readings.Down, readings.Up, readings.Top);
        }
        var minimised = TopLevel.GetTopLevel(this) is Window { WindowState: WindowState.Minimized };
        if (IsEffectivelyVisible && !minimised)
        {
            var now = TrafficMonitor.Clock.Elapsed.TotalSeconds;
            if (Motion.Reduced)
            {
                var samples = TrafficMonitor.Snapshot();
                if (samples.Length > 0 && samples[^1].Time != lastSampleSeen)
                {
                    lastSampleSeen = samples[^1].Time;
                    InvalidateVisual();
                }
            }
            else if (now - lastRender >= FrameSeconds)
            {
                InvalidateVisual();
            }
        }
        RequestFrame();
    }

    public override void Render(DrawingContext context)
    {
        var w = Bounds.Width;
        var h = Bounds.Height;
        if (w <= 0 || h <= 0)
            return;
        var now = TrafficMonitor.Clock.Elapsed.TotalSeconds;
        var dt = Math.Clamp(now - lastRender, 0, 0.1);
        lastRender = now;

        var samples = TrafficMonitor.Snapshot();
        // Reduced motion: step once per sample instead of gliding.
        var viewEnd = Motion.Reduced && samples.Length > 0 ? samples[^1].Time : now - Delay;

        var peak = 0.0;
        foreach (var s in samples)
            if (s.Time > viewEnd - Span)
                peak = Math.Max(peak, Math.Max(s.DownMbps, s.UpMbps));
        var target = Nice(Math.Max(0.05, peak * 1.15));
        yMax += (target - yMax) * (Motion.Reduced ? 1 : 1 - Math.Exp(-dt / 0.45));   // the scale eases, never snaps

        // Headroom (user, 2026-11-17: a bump's number looked squeezed against the top): the plot starts 30 px down,
        // so a number always fits above its bump. The chart's former 16 px top margin became this space.
        var top = Math.Min(Headroom, h * 0.4);
        foreach (var f in new[] { 0, 0.5, 1 })
        {
            var y = Math.Round(top + (h - 3 - top) * f) + 0.5;
            context.DrawLine(GridPen, new Point(0, y), new Point(w, y));
        }

        if (samples.Length >= 2)
        {
            Point Map(double time, double mbps) => new(w * (1 - (viewEnd - time) / Span), top + (h - 3 - top) * (1 - Math.Min(1, mbps / yMax)));
            up.Draw(context, samples.Select(s => Map(s.Time, s.UpMbps)).Where(p => p.X > -60 && p.X < w + 60).ToArray(), h);
            down.Draw(context, samples.Select(s => Map(s.Time, s.DownMbps)).Where(p => p.X > -60 && p.X < w + 60).ToArray(), h);
            FindBumps(samples, target, now);
            DrawBubbles(context, w, now, Map);
        }

        // Text can't change inside the render pass; hand the readings to the next frame callback.
        if (now - lastLegend >= 0.25 && samples.Length > 0)
        {
            lastLegend = now;
            legend = (ValueAt(samples, viewEnd, s => s.DownMbps), ValueAt(samples, viewEnd, s => s.UpMbps), target);
        }
    }

    /// <summary>
    /// A bump = a sample (two seconds back, so both neighbours are known) at least as high as both neighbours that rises
    /// a quarter of the scale above the lowest of the six readings before it and at least doubles it. At most one number
    /// per line every 6 s, so small wiggles and busy periods stay quiet.
    /// </summary>
    private void FindBumps(TrafficMonitor.Sample[] samples, double top, double now)
    {
        var n = samples.Length;
        if (n < 9 || samples[^1].Time == lastChecked)
            return;
        lastChecked = samples[^1].Time;
        var s = samples[n - 3];
        foreach (var isDown in new[] { true, false })
        {
            double V(TrafficMonitor.Sample x) => isDown ? x.DownMbps : x.UpMbps;
            var value = V(s);
            var floor = samples.Skip(n - 9).Take(6).Min(V);
            var last = isDown ? lastDownBubble : lastUpBubble;
            if (value >= V(samples[n - 4]) && value >= V(samples[n - 2]) && value - floor > 0.25 * top && value > 2 * floor &&
                s.Time - last > 6)
            {
                if (isDown) lastDownBubble = s.Time; else lastUpBubble = s.Time;
                bubbles.Add(new Bubble(isDown, s.Time, value, now));
            }
        }
    }

    private static readonly ImmutableSolidColorBrush DownText = new(Color.Parse("#D6E7FC"));
    private static readonly ImmutableSolidColorBrush UpText = new(Color.Parse("#8DB8F2"));

    /// <summary>
    /// Space above the plot for a bump's number: 15 px SemiBold is ~19.5 px tall + 5 px gap, with room to spare because
    /// a bump can touch the top while the scale is still easing up (24 px was seen to fall back beside the bump).
    /// </summary>
    private const double Headroom = 30;

    private void DrawBubbles(DrawingContext context, double w, double now, Func<double, double, Point> map)
    {
        if (bubbles.Count == 0)
            return;
        var font = Application.Current?.FindResource("UiFont") as FontFamily ?? FontFamily.Default;
        var typeface = new Typeface(font, FontStyle.Normal, FontWeight.SemiBold);
        foreach (var b in bubbles.ToArray())
        {
            var age = now - b.Born;
            var point = map(b.Time, b.Mbps);
            // Fades out after ~8 s, or as it reaches the faded left edge.
            var edge = Math.Clamp((point.X / w - 0.12) / 0.08, 0, 1);
            var life = Math.Clamp((9 - age) / 0.9, 0, 1);
            if (life <= 0 || point.X < w * 0.12)
            {
                bubbles.Remove(b);
                continue;
            }
            // Slow spring: from 60 % size, a gentle ~5 % overshoot at ~0.45 s, settled by ~1 s; fades in over 0.35 s.
            var scale = Motion.Reduced ? 1 : 1 - 0.4 * Math.Exp(-4.5 * age) * Math.Cos(7 * age);
            var opacity = (Motion.Reduced ? 1 : Math.Min(1, age / 0.35)) * Math.Min(edge, life);
            var brush = b.Down ? DownText : UpText;

            // Just the number: no dot, ring or box (user, 2026-11-16: "simple yet beautiful").
            var text = new FormattedText((b.Down ? "↓ " : "↑ ") + Format(b.Mbps), CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight, typeface, 15, brush);
            // Above the top of the bump; beside it when there is no room above.
            Point at;
            if (point.Y - 5 - text.Height >= 0)
                at = new Point(Math.Clamp(point.X - text.Width / 2, 0, Math.Max(0, w - text.Width)), point.Y - 5 - text.Height);
            else
                at = new Point(point.X + 9 + text.Width <= w ? point.X + 9 : point.X - 9 - text.Width,
                    Math.Max(0, point.Y - text.Height / 2));
            var transform = Matrix.CreateTranslation(-point.X, -point.Y) * Matrix.CreateScale(scale, scale) *
                            Matrix.CreateTranslation(point.X, point.Y);
            using (context.PushTransform(transform))
            using (context.PushOpacity(opacity))
                context.DrawText(text, at);
        }
    }

    /// <summary>The reading at the right edge, eased between the two samples around it.</summary>
    private static double ValueAt(TrafficMonitor.Sample[] samples, double time, Func<TrafficMonitor.Sample, double> pick)
    {
        for (var i = samples.Length - 1; i > 0; i--)
        {
            var (a, b) = (samples[i - 1], samples[i]);
            if (time >= a.Time && time <= b.Time)
            {
                var f = (time - a.Time) / (b.Time - a.Time);
                return pick(a) + (pick(b) - pick(a)) * f * f * (3 - 2 * f);
            }
        }
        return pick(samples[^1]);
    }

    /// <summary>1, 2, 2.5, 5 × 10ⁿ: a round top for the scale.</summary>
    private static double Nice(double v)
    {
        var p = Math.Pow(10, Math.Floor(Math.Log10(v)));
        foreach (var m in new[] { 1, 2, 2.5, 5 })
            if (m * p >= v)
                return m * p;
        return 10 * p;
    }

    private sealed class Series(Color color, double fillAlpha, double width)
    {
        private readonly ImmutablePen pen = new(new ImmutableSolidColorBrush(color), width, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round);
        private readonly IImmutableBrush fill = new ImmutableLinearGradientBrush(
            [new ImmutableGradientStop(0, Color.FromArgb((byte)(fillAlpha * 255), color.R, color.G, color.B)),
             new ImmutableGradientStop(1, Color.FromArgb(0, color.R, color.G, color.B))],
            startPoint: new RelativePoint(0, 0, RelativeUnit.Relative), endPoint: new RelativePoint(0, 1, RelativeUnit.Relative));

        public void Draw(DrawingContext context, Point[] points, double height)
        {
            if (points.Length < 2)
                return;
            context.DrawGeometry(fill, null, Curve(points, height));
            context.DrawGeometry(null, pen, Curve(points, null));
        }

        /// <summary>Monotone cubic (Fritsch–Carlson): smooth, and never dips below zero or overshoots a peak.</summary>
        private static StreamGeometry Curve(Point[] p, double? closeAt)
        {
            var n = p.Length;
            var m = new double[n - 1];
            var t = new double[n];
            for (var i = 0; i < n - 1; i++)
                m[i] = (p[i + 1].Y - p[i].Y) / Math.Max(1e-6, p[i + 1].X - p[i].X);
            t[0] = m[0];
            t[n - 1] = m[n - 2];
            for (var i = 1; i < n - 1; i++)
                t[i] = m[i - 1] * m[i] <= 0 ? 0 : (m[i - 1] + m[i]) / 2;
            for (var i = 0; i < n - 1; i++)
            {
                if (m[i] == 0)
                {
                    t[i] = t[i + 1] = 0;
                    continue;
                }
                double a = t[i] / m[i], b = t[i + 1] / m[i], s = a * a + b * b;
                if (s > 9)
                {
                    var k = 3 / Math.Sqrt(s);
                    t[i] = k * a * m[i];
                    t[i + 1] = k * b * m[i];
                }
            }

            var geometry = new StreamGeometry();
            using var g = geometry.Open();
            g.BeginFigure(p[0], closeAt is not null);
            for (var i = 0; i < n - 1; i++)
            {
                var dx = (p[i + 1].X - p[i].X) / 3;
                g.CubicBezierTo(new Point(p[i].X + dx, p[i].Y + t[i] * dx), new Point(p[i + 1].X - dx, p[i + 1].Y - t[i + 1] * dx), p[i + 1]);
            }
            if (closeAt is { } bottom)
            {
                g.LineTo(new Point(p[n - 1].X, bottom));
                g.LineTo(new Point(p[0].X, bottom));
            }
            g.EndFigure(closeAt is not null);
            return geometry;
        }
    }
}
