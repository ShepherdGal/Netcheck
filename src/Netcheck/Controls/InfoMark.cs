using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace Netcheck.Controls;

/// <summary>
/// A small circled "i" next to a label (design rules "equal rows, explanations behind ⓘ", 2026-11-16). The explanation
/// shows as a tooltip on hover and on click or Enter/Space, so rows keep one line and the same height.
/// </summary>
internal sealed class InfoMark : Button
{
    private readonly Border circle;

    public InfoMark(string text)
    {
        Theme = (Avalonia.Styling.ControlTheme)Application.Current!.FindResource("NcLinkButton")!;
        Padding = new Thickness(4, 2);
        Margin = new Thickness(4, 0, 0, 0);
        VerticalAlignment = VerticalAlignment.Center;
        circle = new Border
        {
            Width = 18, Height = 18, CornerRadius = new CornerRadius(9), BorderThickness = new Thickness(1.3),
            BorderBrush = Brush("Ink3Brush"),
            Child = new TextBlock
            {
                Text = "i", FontSize = 12.5, FontWeight = FontWeight.Bold, Foreground = Brush("Ink3Brush"),
                HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
            },
        };
        Content = circle;
        ToolTip.SetTip(this, text);
        ToolTip.SetShowDelay(this, 150);
        AutomationProperties.SetName(this, text);
        Click += (_, _) => ToolTip.SetIsOpen(this, !ToolTip.GetIsOpen(this));
        PointerEntered += (_, _) => Tint("AccentBrush");
        PointerExited += (_, _) => Tint("Ink3Brush");
        GotFocus += (_, _) => Tint("AccentBrush");
        LostFocus += (_, _) => { Tint("Ink3Brush"); ToolTip.SetIsOpen(this, false); };
    }

    private void Tint(string key)
    {
        circle.BorderBrush = Brush(key);
        ((TextBlock)circle.Child!).Foreground = Brush(key);
    }

    private static IBrush Brush(string key) => ThemeManager.Brush(key);
}
