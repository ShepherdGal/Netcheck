using System.Reflection;
using Netcheck.Core.Updates;

namespace Netcheck;

internal enum AppEdition { Installed, Portable, Development }

/// <summary>
/// Where this copy of Netcheck runs from and where it keeps its data (design plan D9, P14):
/// installed (Program Files\Netcheck) → %LOCALAPPDATA%\Netcheck; any other release build is portable → a
/// <c>Netcheck Data</c> folder beside the exe (a 1.0 portable copy's <c>Data</c> folder keeps working); a development
/// build → %LOCALAPPDATA%\Netcheck as before. NETCHECK_DATA_DIR overrides the data folder for tests on copies.
/// </summary>
internal static class AppPaths
{
    /// <summary>The 1.0 portable marker file; no longer needed (any release copy outside Program Files is portable).</summary>
    internal const string PortableMarker = "Netcheck.portable";

    /// <summary>The portable copy's data folder beside the exe (1.0 used plain <c>Data</c>).</summary>
    internal const string PortableDataName = "Netcheck Data";

    internal static readonly string InstallDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Netcheck");

    internal static readonly string PreviousDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Netcheck Previous");

    internal static readonly string InstalledExe = Path.Combine(InstallDirectory, "Netcheck.exe");

    internal static readonly string ProfileData = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Netcheck");

    internal static readonly AppEdition Edition =
        string.Equals(Environment.ProcessPath, InstalledExe, StringComparison.OrdinalIgnoreCase) ? AppEdition.Installed
        : IsReleaseBuild() || File.Exists(Path.Combine(AppContext.BaseDirectory, PortableMarker)) ? AppEdition.Portable
        : AppEdition.Development;

    internal static readonly string DataDirectory =
        Environment.GetEnvironmentVariable("NETCHECK_DATA_DIR") is { Length: > 0 } dir ? dir
        : Edition == AppEdition.Portable ? PortableData()
        : ProfileData;

    /// <summary>A published build (the Windows publish profile stamps it); development builds from bin\ are not.</summary>
    private static bool IsReleaseBuild() =>
        typeof(AppPaths).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Any(m => m.Key == "Netcheck.ProtectedDeployment" && m.Value == "Windows");

    /// <summary>
    /// "Netcheck Data" beside the exe. A 1.0 portable copy's "Data" folder is used where it is (never moved), but only
    /// when it really is Netcheck's: an unrelated "Data" folder in Downloads is left alone.
    /// </summary>
    private static string PortableData()
    {
        var current = Path.Combine(AppContext.BaseDirectory, PortableDataName);
        var older = Path.Combine(AppContext.BaseDirectory, "Data");
        return !Directory.Exists(current) &&
               (File.Exists(Path.Combine(older, "history.db")) || File.Exists(Path.Combine(older, "appearance.json")))
            ? older : current;
    }

    internal static string Data(string name) => Path.Combine(DataDirectory, name);

    /// <summary>This copy's version, from the assembly's informational version.</summary>
    internal static readonly AppVersion Version =
        AppVersion.TryParse(typeof(AppPaths).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
            out var v) ? v : AppVersion.Parse("0.0.0");

    /// <summary>The version kept for "Go back" (installed copy only), read from the protected Previous folder.</summary>
    internal static AppVersion? PreviousVersion()
    {
        try
        {
            // A 1.0 folder has Netcheck.dll beside the exe; a one-file Netcheck.exe (P14) carries it inside.
            var dll = Path.Combine(PreviousDirectory, "Netcheck.dll");
            if (File.Exists(dll))
                return AppVersion.ReadFromAssembly(dll);
            var exe = Path.Combine(PreviousDirectory, "Netcheck.exe");
            return File.Exists(exe) && OneFileBundle.ReadFile(exe, "Netcheck.dll") is { } bytes
                ? AppVersion.ReadFromAssembly(new MemoryStream(bytes)) : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
