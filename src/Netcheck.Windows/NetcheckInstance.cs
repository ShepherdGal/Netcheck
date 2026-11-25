using System.Runtime.InteropServices;
using System.Text;

namespace Netcheck.Windows;

public static class NetcheckInstance
{
    // Keep this Windows-wide identity stable across application upgrades.
    private const string MutexName = @"Global\Netcheck.Desktop.14D6E4D7-2443-46C8-85BB-73D87D073305";

    public static Mutex? TryAcquire(TimeSpan wait = default)
    {
        Mutex mutex;
        try { mutex = new Mutex(false, MutexName); }
        catch (UnauthorizedAccessException)
        {
            // The running instance may belong to a different Windows account.
            return null;
        }

        try
        {
            if (mutex.WaitOne(wait))
                return mutex;
        }
        catch (AbandonedMutexException)
        {
            // Windows granted ownership after the previous process exited unexpectedly.
            return mutex;
        }

        mutex.Dispose();
        return null;
    }

    /// <summary>
    /// Netcheck is already open: bring its window forward (restored if minimised), so opening it again from Start or
    /// the desktop shows it instead of doing nothing. The window is matched by its exact title and Avalonia's window
    /// class, so a folder window named "Netcheck" is never picked. False when no such window is found.
    /// </summary>
    public static bool ShowRunning()
    {
        var found = IntPtr.Zero;
        var title = new StringBuilder(64);
        var type = new StringBuilder(64);
        EnumWindows((window, _) =>
        {
            title.Clear();
            type.Clear();
            if (GetWindowText(window, title, title.Capacity) > 0 && title.ToString() == "Netcheck" &&
                GetClassName(window, type, type.Capacity) > 0 && type.ToString().StartsWith("Avalonia", StringComparison.Ordinal))
            {
                found = window;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        if (found == IntPtr.Zero)
            return false;
        if (IsIconic(found))
            ShowWindow(found, RestoreWindow);
        SetForegroundWindow(found);
        return true;
    }

    private const int RestoreWindow = 9;   // SW_RESTORE

    private delegate bool EnumWindowsProc(IntPtr window, IntPtr parameter);

    [DllImport("user32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetWindowTextW", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GetWindowText(IntPtr window, StringBuilder text, int capacity);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetClassNameW", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int GetClassName(IntPtr window, StringBuilder text, int capacity);

    [DllImport("user32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool IsIconic(IntPtr window);

    [DllImport("user32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool ShowWindow(IntPtr window, int command);

    [DllImport("user32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool SetForegroundWindow(IntPtr window);
}
