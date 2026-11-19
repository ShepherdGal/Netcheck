using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media.Transformation;

namespace Netcheck.Controls;

/// <summary>
/// The one selection motion (design rules §4): a pill behind the chosen item that glides to the new choice
/// (300 ms ease-out on position and width), placed without motion the first time and never animated with reduced
/// motion. Used by the tab bar and by every "pick one of these" row (App size, Speed units).
/// The pill is a Border declared in XAML behind the items, so each place keeps its own look.
/// </summary>
internal sealed class SelectionSlider
{
    private static readonly TimeSpan Glide = TimeSpan.FromMilliseconds(300);
    private readonly Border pill;
    private readonly Panel items;
    private bool placed;

    private SelectionSlider(Border pill, Panel items)
    {
        this.pill = pill;
        this.items = items;
        pill.HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Left;
        pill.Width = 0;
        pill.Opacity = 0;
        items.LayoutUpdated += (_, _) => Place();
        items.Children.CollectionChanged += (_, _) => Hook();
        Hook();
    }

    /// <summary>Attach to a pill Border and the panel holding the toggle buttons (RadioButtons) it follows.</summary>
    internal static SelectionSlider Attach(Border pill, Panel items) => new(pill, items);

    /// <summary>Forget the current position so the next placement jumps (e.g. after the items were rebuilt).</summary>
    internal void Reset()
    {
        placed = false;
        pill.Transitions = null;
    }

    private void Hook()
    {
        foreach (var item in items.Children.OfType<ToggleButton>())
        {
            item.IsCheckedChanged -= OnChecked;
            item.IsCheckedChanged += OnChecked;
        }
    }

    private void OnChecked(object? sender, Avalonia.Interactivity.RoutedEventArgs e) => Place();

    private void Place()
    {
        var chosen = items.Children.OfType<ToggleButton>().FirstOrDefault(t => t.IsChecked == true);
        if (chosen is null)
        {
            pill.Opacity = 0;
            return;
        }
        var width = chosen.Bounds.Width;
        var x = chosen.Bounds.X;
        if (width <= 0)
            return;
        if (Math.Abs(pill.Width - width) < 0.5 && pill.RenderTransform is TransformOperations t &&
            Math.Abs(t.Value.M31 - x) < 0.5 && pill.Opacity == 1)
            return;

        pill.Width = width;
        pill.RenderTransform = TransformOperations.Parse(FormattableString.Invariant($"translateX({x:0.##}px)"));
        pill.Opacity = 1;
        if (placed || Motion.Reduced)
            return;
        placed = true;
        // From now on every change glides; the first placement above happened without motion.
        pill.Transitions =
        [
            new DoubleTransition { Property = Layoutable.WidthProperty, Duration = Glide, Easing = Motion.EaseOut },
            new TransformOperationsTransition { Property = Visual.RenderTransformProperty, Duration = Glide, Easing = Motion.EaseOut },
            new DoubleTransition { Property = Visual.OpacityProperty, Duration = TimeSpan.FromMilliseconds(180), Easing = Motion.EaseOut },
        ];
    }
}
