using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Animation;
using Avalonia.Animation.Easings;
using Avalonia.Controls;
using Avalonia.Media.Transformation;
using Avalonia.Threading;

namespace Netcheck;

/// <summary>Shared motion rules (design plan §4): short ease-out, nothing when Windows or the user asks for reduced motion.</summary>
internal static class Motion
{
    internal static readonly Easing EaseOut = new SplineEasing(0.22, 0.8, 0.24, 1);
    internal static readonly TimeSpan Enter = TimeSpan.FromMilliseconds(260);

    /// <summary>True when Windows "Animation effects" is off or the user chose reduced motion in Netcheck.</summary>
    internal static bool Reduced { get; set; } = !WindowsAnimationsEnabled();

    /// <summary>
    /// Fades a newly shown page in, in place. (Until P8 it also rose 10 px; text passing between pixels and then
    /// snapping sharp at the end read as titles "adjusting" — user review 2026-11-16.) Interrupting it simply restarts.
    /// </summary>
    internal static void EnterPage(Control page)
    {
        page.Transitions = null;
        page.RenderTransform = null;
        if (Reduced)
        {
            page.Opacity = 1;
            return;
        }

        page.Opacity = 0;
        Dispatcher.UIThread.Post(() =>
        {
            page.Transitions = [new DoubleTransition { Property = Visual.OpacityProperty, Duration = Enter, Easing = EaseOut }];
            page.Opacity = 1;
        }, DispatcherPriority.Render);
    }

    private const uint SpiGetClientAreaAnimation = 0x1042;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(uint action, uint param, out int value, uint winIni);

    private static bool WindowsAnimationsEnabled()
    {
        if (!OperatingSystem.IsWindows())
            return true;
        try { return !SystemParametersInfo(SpiGetClientAreaAnimation, 0, out var enabled, 0) || enabled != 0; }
        catch (DllNotFoundException) { return true; }
    }
}
