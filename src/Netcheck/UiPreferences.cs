using System.Text.Json;

namespace Netcheck;

/// <summary>Per-user preferences (appearance.json in the data folder). Missing fields keep their defaults.</summary>
internal sealed record UiPreferences(string Theme, bool ReduceMotion, SpeedUnit SpeedUnit = SpeedUnit.Automatic,
    bool KeepTemporaryFiles = false, double AppScale = 0,   // AppScale 0 = automatic (largest size that fits)
    bool AutoUpdateCheck = true, DateTimeOffset? LastUpdateCheck = null, string? SkippedVersion = null)
{
    private static readonly string PathToSettings = AppPaths.Data("appearance.json");
    private static UiPreferences? current;

    /// <summary>The preferences in use; read from disk once, then kept in step with every Change.</summary>
    internal static UiPreferences Current => current ??= Load();

    /// <summary>Applies a change, saves it and raises Changed.</summary>
    internal static void Change(Func<UiPreferences, UiPreferences> edit)
    {
        current = edit(Current);
        current.Save();
        Changed?.Invoke();
    }

    internal static event Action? Changed;

    internal static UiPreferences Load()
    {
        try
        {
            // Read the former location once so the application rename preserves preferences (not for portable copies).
            var former = Path.Combine(AppPaths.ProfileData, "Avalonia", "appearance.json");
            var path = File.Exists(PathToSettings) || AppPaths.Edition == AppEdition.Portable ? PathToSettings : former;
            if (File.Exists(path) && new FileInfo(path).Length <= 4096)
            {
                var preferences = JsonSerializer.Deserialize<UiPreferences>(File.ReadAllText(path)) ?? new("Dark", false);
                if (path != PathToSettings)
                    preferences.Save();
                return preferences;
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
        }
        return new("Dark", false);
    }

    internal void Save()
    {
        try
        {
            var directory = Path.GetDirectoryName(PathToSettings)!;
            Directory.CreateDirectory(directory);
            var temporary = Path.Combine(directory, $"{Guid.NewGuid():N}.tmp");
            try
            {
                File.WriteAllText(temporary, JsonSerializer.Serialize(this));
                File.Move(temporary, PathToSettings, overwrite: true);
            }
            finally
            {
                File.Delete(temporary);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // The selected preferences still apply to this session.
        }
    }
}
