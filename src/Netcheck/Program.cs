using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Netcheck.Windows;

namespace Netcheck;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (OperatingSystem.IsWindows() && args.FirstOrDefault() == Elevation.WindowsDnsBroker.Switch)
            return Elevation.WindowsDnsBroker.RunAsync(args).GetAwaiter().GetResult();
        if (OperatingSystem.IsWindows() && args.FirstOrDefault() == Elevation.WindowsTweakBroker.Switch)
        {
            // The Boost helper needs Windows management (CIM) only; graphics are never loaded elevated by a helper.
            NativeLibraries.Prepare(Elevation.WindowsInstaller.IsElevated, NativeLibraries.Management);
            return Elevation.WindowsTweakBroker.RunAsync(args).GetAwaiter().GetResult();
        }
        if (OperatingSystem.IsWindows() && args.FirstOrDefault() == Elevation.WindowsInstaller.BrokerSwitch)
            return Elevation.WindowsInstaller.RunBrokerAsync(args).GetAwaiter().GetResult();
        if (OperatingSystem.IsWindows() && args.FirstOrDefault() == Elevation.WindowsInstaller.SetupSwitch)
            return Elevation.WindowsInstaller.RunSetup(args);
        if (OperatingSystem.IsWindows() && args.FirstOrDefault() == Elevation.WindowsInstaller.UninstallSwitch)
        {
            // Before asking Windows for permission: offer to undo a DNS switch or Boost change still in place.
            if (!Elevation.WindowsInstaller.IsElevated && Elevation.WindowsInstaller.CanUpdate && UninstallWindow.HasChanges)
            {
                NativeLibraries.Prepare(elevated: false);
                App.ShowUninstall = true;
                BuildApp().StartWithClassicDesktopLifetime(args);
                if (!App.UninstallConfirmed)
                    return 1;
            }
            return Elevation.WindowsInstaller.RunUninstall(args);
        }

        using var instance = OperatingSystem.IsWindows() ? NetcheckInstance.TryAcquire(
            args.Contains(Updater.WaitSwitch) ? TimeSpan.FromSeconds(20) : TimeSpan.Zero) : null;
        if (OperatingSystem.IsWindows() && instance is null)
            return 0;

        // One-file build: graphics libraries checked and loaded from a folder that fits who runs this (P14).
        if (OperatingSystem.IsWindows())
            NativeLibraries.Prepare(Elevation.WindowsInstaller.IsElevated);
        try
        {
            return BuildApp().StartWithClassicDesktopLifetime(args);
        }
        finally { instance?.ReleaseMutex(); }
    }

    private static AppBuilder BuildApp() => AppBuilder.Configure<App>()
        .UseWin32().UseSkia().UseHarfBuzz()
        .With(new FontManagerOptions { DefaultFamilyName = "avares://Netcheck/Assets/Fonts#Inter 18pt" });
}

public sealed class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    /// <summary>Uninstall mode: show only the "undo first?" window instead of the app.</summary>
    internal static bool ShowUninstall { get; set; }
    internal static bool UninstallConfirmed { get; private set; }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            if (ShowUninstall)
            {
                var prompt = new UninstallWindow();
                prompt.Closed += (_, _) => UninstallConfirmed = prompt.Proceed;
                desktop.MainWindow = prompt;
            }
            else
                desktop.MainWindow = new MainWindow();
        }
        base.OnFrameworkInitializationCompleted();
    }
}


