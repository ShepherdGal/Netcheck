using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Controls.Primitives;
using Avalonia.Diagnostics;
using Avalonia.Markup.Xaml.Styling;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.VisualTree;

namespace Netcheck;

/// <summary>
/// Dark ("Dusk") and Light ("Dawn"), one design with the lightness flipped (user, 2026-11-25).
/// <para>
/// XAML reads every themed colour with DynamicResource, so changing <see cref="Application.RequestedThemeVariant"/>
/// restyles it by itself. Pages also build rows in code and hand them a resource brush as a local value; those would keep
/// the old theme's brush, so after a switch every such local value is swapped for the same-named brush of the new theme.
/// Values that came from a style or a binding are left alone (they follow the theme already).
/// </para>
/// </summary>
internal static class ThemeManager
{
    internal const string DarkName = "Dark", LightName = "Light";

    /// <summary>Pages kept alive off screen (the main window caches them); they hold code-built rows too.</summary>
    internal static Func<IEnumerable<Visual>>? ExtraRoots { get; set; }

    internal static ThemeVariant VariantOf(string? name) => name == LightName ? ThemeVariant.Light : ThemeVariant.Dark;

    /// <summary>A themed resource of the theme in use now. (Looking a key up without the variant misses the theme dictionaries.)</summary>
    internal static object? Resource(string key) =>
        Application.Current is { } app && app.TryGetResource(key, app.ActualThemeVariant, out var value) ? value : null;

    internal static IBrush Brush(string key) => Resource(key) as IBrush ?? Brushes.Gray;

    /// <summary>Before any window exists: use the saved choice.</summary>
    internal static void ApplySaved(Application app) => app.RequestedThemeVariant = VariantOf(UiPreferences.Current.Theme);

    /// <summary>Switches the running app (and saves the choice).</summary>
    internal static void Choose(string name)
    {
        var app = Application.Current;
        if (app is null)
            return;
        var next = VariantOf(name);
        var old = app.ActualThemeVariant;
        if (old != next)
        {
            var swaps = BrushSwaps(app, old, next);
            app.RequestedThemeVariant = next;
            if (app.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
                foreach (var window in desktop.Windows)
                    SwapLocalBrushes(window, swaps);
            foreach (var page in ExtraRoots?.Invoke() ?? [])
                SwapLocalBrushes(page, swaps);
        }
        if (UiPreferences.Current.Theme != name)
            UiPreferences.Change(p => p with { Theme = name });
    }

    private static Dictionary<IBrush, IBrush> BrushSwaps(Application app, ThemeVariant from, ThemeVariant to)
    {
        var swaps = new Dictionary<IBrush, IBrush>(ReferenceEqualityComparer.Instance as IEqualityComparer<IBrush>);
        foreach (var key in BrushKeys(app, from))
            if (app.TryGetResource(key, from, out var oldValue) && oldValue is IBrush oldBrush
                && app.TryGetResource(key, to, out var newValue) && newValue is IBrush newBrush)
                swaps[oldBrush] = newBrush;
        return swaps;
    }

    private static IEnumerable<object> BrushKeys(Application app, ThemeVariant variant)
    {
        foreach (var merged in app.Resources.MergedDictionaries)
        {
            var dictionary = (merged as ResourceInclude)?.Loaded as ResourceDictionary ?? merged as ResourceDictionary;
            if (dictionary?.ThemeDictionaries.TryGetValue(variant, out var themed) == true && themed is ResourceDictionary entries)
                foreach (var pair in entries)
                    if (pair.Value is IBrush)
                        yield return pair.Key;
        }
    }

    private static void SwapLocalBrushes(Visual root, Dictionary<IBrush, IBrush> swaps)
    {
        foreach (var visual in root.GetSelfAndVisualDescendants())
        {
            if (visual is not AvaloniaObject target)
                continue;
            foreach (var property in AvaloniaPropertyRegistry.Instance.GetRegistered(target))
            {
                if (!typeof(IBrush).IsAssignableFrom(property.PropertyType))
                    continue;
                var current = target.GetDiagnostic(property);
                if (current.Priority == Avalonia.Data.BindingPriority.LocalValue && current.Value is IBrush brush
                    && swaps.TryGetValue(brush, out var replacement))
                    target.SetValue(property, replacement, Avalonia.Data.BindingPriority.LocalValue);
            }
        }
    }
}
