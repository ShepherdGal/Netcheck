using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Threading;

namespace Netcheck.Controls;

/// <summary>
/// The Dusk background: night blue with one soft glow at the top.
/// <para>
/// The glow colour is only ~10–34 shades away from the base, so a normal 8-bit gradient shows wide flat stripes
/// (measured: 39 shades, flat runs up to 777 px at 175 %). This control renders the glow once per size, at device
/// resolution, with a bell-shaped falloff (no linear "Mach band" edges) and ordered dithering of at most one shade
/// per pixel (1/255). That is not a visible texture, unlike the rejected grain; it only removes the steps.
/// </para>
/// Redraws only when the size settles after a resize; nothing runs while idle.
/// </summary>
public sealed class GlowBackdrop : Control
{
    private static readonly Color Base = Color.Parse("#0E1828");
    private static readonly Color Glow = Color.Parse("#18294A");
    private const double RadiusX = 0.70, RadiusY = 0.60;   // of width / height, centred on the top edge

    private WriteableBitmap? bitmap;
    private PixelSize rendered;
    private readonly DispatcherTimer settle;

    public GlowBackdrop()
    {
        IsHitTestVisible = false;
        settle = new DispatcherTimer(TimeSpan.FromMilliseconds(120), DispatcherPriority.Background, (_, _) => Rebuild());
    }

    protected override void OnSizeChanged(SizeChangedEventArgs e)
    {
        base.OnSizeChanged(e);
        settle.Stop();
        if (bitmap is null)
            Rebuild();          // first paint immediately
        else
            settle.Start();     // while resizing, stretch the last image; rebuild when the size settles
    }

    private void Rebuild()
    {
        settle.Stop();
        var scale = TopLevel.GetTopLevel(this)?.RenderScaling ?? 1;
        var size = new PixelSize(Math.Max(1, (int)Math.Ceiling(Bounds.Width * scale)), Math.Max(1, (int)Math.Ceiling(Bounds.Height * scale)));
        if (size == rendered && bitmap is not null)
            return;
        // Plain 96 DPI bitmap, scaled down explicitly in Render (still 1 image pixel per screen pixel). A bitmap tagged
        // with the screen DPI was drawn 1.75× too large at 175 %, which cropped it and pushed the glow off to the right.
        var next = new WriteableBitmap(size, new Vector(96, 96), PixelFormat.Bgra8888, AlphaFormat.Opaque);
        using (var frame = next.Lock())
            Paint(frame, size);
        bitmap?.Dispose();
        bitmap = next;
        rendered = size;
        InvalidateVisual();
    }

    private static void Paint(ILockedFramebuffer frame, PixelSize size)
    {
        var row = new int[size.Width];
        var cx = size.Width / 2.0;
        var rx = size.Width * RadiusX;
        var ry = size.Height * RadiusY;
        var floor = Math.Exp(-2.6);
        for (var y = 0; y < size.Height; y++)
        {
            var dy = y / ry;
            for (var x = 0; x < size.Width; x++)
            {
                var dx = (x - cx) / rx;
                var d2 = dx * dx + dy * dy;
                // Bell-shaped falloff that reaches exactly zero at the edge of the ellipse.
                var f = d2 >= 1 ? 0 : (Math.Exp(-2.6 * d2) - floor) / (1 - floor);
                // Interleaved gradient noise: an even, fine pattern in [-0.5, 0.5); shifts a pixel by at most one shade.
                var n = Fraction(52.9829189 * Fraction(0.06711056 * x + 0.00583715 * y)) - 0.5;
                var r = Channel(Base.R, Glow.R, f, n);
                var g = Channel(Base.G, Glow.G, f, n);
                var b = Channel(Base.B, Glow.B, f, n);
                row[x] = unchecked((int)(0xFF000000u | (uint)(r << 16) | (uint)(g << 8) | (uint)b));
            }
            Marshal.Copy(row, 0, frame.Address + y * frame.RowBytes, size.Width);
        }
    }

    private static double Fraction(double v) => v - Math.Floor(v);

    private static int Channel(byte from, byte to, double f, double noise) =>
        Math.Clamp((int)Math.Round(from + (to - from) * f + noise), 0, 255);

    public override void Render(DrawingContext context)
    {
        if (bitmap is null)
            context.FillRectangle(new SolidColorBrush(Base), new Rect(Bounds.Size));
        else
            context.DrawImage(bitmap, new Rect(0, 0, rendered.Width, rendered.Height), new Rect(Bounds.Size));
    }
}
