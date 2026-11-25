using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace Netcheck.Controls;

/// <summary>
/// A card cell or row with hairline dividers that float and fade (user, 2026-11-25, mockup docs/mockups/divider-fade.html):
/// a divider never touches the card's edge and thins out to nothing at both ends. Vertical lines start 16 px from the
/// top and bottom, horizontal ones 24 px from the sides; then the line is made 5 % longer, each end staying at least
/// 8 px from the edge. Exactly 1 px, today's Line colour in the middle (never stronger), fading to a zero-alpha copy of
/// the same colour so the ends never turn grey. Use instead of a Border with a one-sided BorderThickness, which always
/// runs edge to edge. <see cref="Lines"/> says which sides get a divider (any value above 0).
/// </summary>
internal sealed class Divided : Decorator
{
    public static readonly StyledProperty<Thickness> LinesProperty =
        AvaloniaProperty.Register<Divided, Thickness>(nameof(Lines));

    public Thickness Lines
    {
        get => GetValue(LinesProperty);
        set => SetValue(LinesProperty, value);
    }

    private const double VerticalInset = 16, HorizontalInset = 24, Longer = 1.05, MinInset = 8;

    static Divided() => AffectsRender<Divided>(LinesProperty);

    public Divided()
    {
        ActualThemeVariantChanged += (_, _) => InvalidateVisual();
    }

    public override void Render(DrawingContext context)
    {
        var size = Bounds.Size;
        var lines = Lines;
        if (lines == default || ThemeManager.Resource("LineColor") is not Color color)
            return;
        if (lines.Left > 0)
            Vertical(context, 0, size.Height, color);
        if (lines.Right > 0)
            Vertical(context, size.Width - 1, size.Height, color);
        if (lines.Top > 0)
            Horizontal(context, 0, size.Width, color);
        if (lines.Bottom > 0)
            Horizontal(context, size.Height - 1, size.Width, color);
    }

    /// <summary>Start and length of a line along <paramref name="total"/>: base inset, 5 % longer, never closer than 8 px.</summary>
    internal static (double Start, double Length) Span(double total, double inset)
    {
        var length = Math.Min(Math.Max(0, total - 2 * inset) * Longer, Math.Max(0, total - 2 * MinInset));
        return ((total - length) / 2, length);
    }

    private static void Vertical(DrawingContext context, double x, double height, Color color)
    {
        var (start, length) = Span(height, VerticalInset);
        if (length > 0)
            context.FillRectangle(Fade(color, vertical: true), new Rect(x, start, 1, length));
    }

    private static void Horizontal(DrawingContext context, double y, double width, Color color)
    {
        var (start, length) = Span(width, HorizontalInset);
        if (length > 0)
            context.FillRectangle(Fade(color, vertical: false), new Rect(start, y, length, 1));
    }

    // Full colour from 35 % to 65 % of a vertical line (30–70 % of a horizontal one), clear at both ends.
    private static LinearGradientBrush Fade(Color color, bool vertical)
    {
        var clear = Color.FromArgb(0, color.R, color.G, color.B);
        var (from, to) = vertical ? (0.35, 0.65) : (0.30, 0.70);
        return new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = vertical ? new RelativePoint(0, 1, RelativeUnit.Relative) : new RelativePoint(1, 0, RelativeUnit.Relative),
            GradientStops = { new GradientStop(clear, 0), new GradientStop(color, from), new GradientStop(color, to), new GradientStop(clear, 1) },
        };
    }
}
