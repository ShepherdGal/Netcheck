using System.Reflection;
using Netcheck.Core.Updates;

namespace Netcheck;

internal enum AppEdition { Installed, Portable, Development }

/// <summary>
/// Where this copy of Netcheck runs from and where it keeps its data (design plan D9):
/// installed (Program Files\Netcheck) → %LOCALAPPDATA%\Netcheck; portable (a <c>Netcheck.portable</c> marker beside the
/// exe) → <c>Data\</c> beside the exe; a development build → %LOCALAPPDATA%\Netcheck as before.
/// NETCHECK_DATA_DIR overrides the data folder for tests on copies.
/// </summary>
internal static class AppPaths
{
    internal const string PortableMarker = "Netcheck.portable";

    internal static readonly string InstallDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Netcheck");

    internal static readonly string PreviousDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Netcheck Previous");

    internal static readonly string InstalledExe = Path.Combine(InstallDirectory, "Netcheck.exe");

    internal static readonly string ProfileData = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Netcheck");

    internal static readonly AppEdition Edition =
        string.Equals(Environment.ProcessPath, InstalledExe, StringComparison.OrdinalIgnoreCase) ? AppEdition.Installed
        : File.Exists(Path.Combine(AppContext.BaseDirectory, PortableMarker)) ? AppEdition.Portable
        : AppEdition.Development;

    internal static readonly string DataDirectory =
        Environment.GetEnvironmentVariable("NETCHECK_DATA_DIR") is { Length: > 0 } dir ? dir
        : Edition == AppEdition.Portable ? Path.Combine(AppContext.BaseDirectory, "Data")
        : ProfileData;

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
            var dll = Path.Combine(PreviousDirectory, "Netcheck.dll");
            return File.Exists(dll) ? AppVersion.ReadFromAssembly(dll) : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
