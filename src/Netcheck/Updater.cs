using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;
using Netcheck.Core.Updates;
using Netcheck.Elevation;

namespace Netcheck;

internal enum UpdateStage { Unknown, Checking, UpToDate, Available, CheckFailed, Downloading, Installing, Failed }

/// <summary>
/// Update check (at most once a day when on, or "Check Now"), download with progress, then the installed copy's
/// elevated broker swaps versions and Netcheck restarts. Also: go back to the kept version and install from portable.
/// Nothing downloads without a click. Changed is raised on the UI thread.
/// </summary>
internal static class Updater
{
    /// <summary>Passed to the restarted copy so it waits for this one to close instead of exiting.</summary>
    internal const string WaitSwitch = "--wait-for-previous";

    private static CancellationTokenSource? download;

    internal static UpdateStage Stage { get; private set; }
    internal static ReleaseOffer? Offer { get; private set; }
    internal static string Problem { get; private set; } = "";
    internal static long Received { get; private set; }
    internal static event Action? Changed;

    /// <summary>An offer the user hasn't turned down by going back from it.</summary>
    internal static bool HasOffer => Offer is { } o && o.Version.ToString() != UiPreferences.Current.SkippedVersion;

    internal static Task CheckIfDueAsync()
    {
        var p = UiPreferences.Current;
        return p.AutoUpdateCheck && (p.LastUpdateCheck is not { } last || DateTimeOffset.UtcNow - last > TimeSpan.FromHours(24))
            ? CheckAsync() : Task.CompletedTask;
    }

    internal static async Task CheckAsync()
    {
        if (Stage is UpdateStage.Checking or UpdateStage.Downloading or UpdateStage.Installing)
            return;
        Set(UpdateStage.Checking);
        try
        {
            using var client = ReleaseFeed.CreateClient();
            var offers = await ReleaseFeed.FetchAsync(client, CancellationToken.None);
            Offer = ReleaseFeed.Newest(offers, AppPaths.Version);
            UiPreferences.Change(p => p with { LastUpdateCheck = DateTimeOffset.UtcNow });
            Set(HasOffer ? UpdateStage.Available : UpdateStage.UpToDate);
        }
        catch (Exception error) when (error is HttpRequestException or IOException or InvalidDataException or
            System.Text.Json.JsonException or TaskCanceledException)
        {
            Problem = "Couldn't reach GitHub.";
            Set(UpdateStage.CheckFailed);
        }
    }

    /// <summary>Installed copy: download the offer, check its fingerprint, then swap and restart.</summary>
    internal static async Task UpdateAsync()
    {
        if (Offer is not { } offer || Stage is UpdateStage.Downloading or UpdateStage.Installing || !WindowsInstaller.CanUpdate)
            return;
        download = new CancellationTokenSource();
        Received = 0;
        Set(UpdateStage.Downloading);
        var folder = Path.Combine(Path.GetTempPath(), "Netcheck-update");
        var file = Path.Combine(folder, offer.AssetName);
        try
        {
            Directory.CreateDirectory(folder);
            await DownloadAsync(offer, file, download.Token);
            Set(UpdateStage.Installing);
            var result = await WindowsInstaller.UpdateAsync(offer.Version, file, CancellationToken.None);
            if (result.Outcome == InstallOutcome.Done)
            {
                Restart();
                return;
            }
            Fail(result);
        }
        catch (OperationCanceledException) when (download.IsCancellationRequested)
        {
            Set(HasOffer ? UpdateStage.Available : UpdateStage.UpToDate);
        }
        catch (Exception error) when (error is HttpRequestException or IOException or InvalidDataException or
            UnauthorizedAccessException or OperationCanceledException)
        {
            Problem = error is InvalidDataException ? error.Message : "The download didn't finish.";
            Set(UpdateStage.Failed);
        }
        finally
        {
            download.Dispose();
            download = null;
            try { File.Delete(file); } catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        }
    }

    internal static void StopDownload() => download?.Cancel();

    private static async Task DownloadAsync(ReleaseOffer offer, string file, CancellationToken token)
    {
        using var client = ReleaseFeed.CreateClient();
        client.Timeout = Timeout.InfiniteTimeSpan;
        using var request = new HttpRequestMessage(HttpMethod.Get, offer.AssetUrl);
        request.Headers.Accept.Clear();
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
        response.EnsureSuccessStatusCode();
        await using var input = await response.Content.ReadAsStreamAsync(token);
        await using var output = new FileStream(file, FileMode.Create, FileAccess.Write, FileShare.None);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        var lastReport = Stopwatch.StartNew();
        int read;
        while ((read = await ReadWithIdleLimitAsync(input, buffer, token)) > 0)
        {
            if (Received + read > offer.Size)
                throw new InvalidDataException("The download was larger than the release says.");
            await output.WriteAsync(buffer.AsMemory(0, read), token);
            sha.AppendData(buffer, 0, read);
            Received += read;
            if (lastReport.ElapsedMilliseconds >= 250)
            {
                lastReport.Restart();
                Set(UpdateStage.Downloading);
            }
        }
        if (Received != offer.Size || Convert.ToHexString(sha.GetHashAndReset()) != offer.Sha256)
            throw new InvalidDataException("The download didn't match the release fingerprint.");
    }

    /// <summary>A read that gives up after 30 s without any data (a stalled connection), not after a fixed total time.</summary>
    private static async Task<int> ReadWithIdleLimitAsync(Stream input, byte[] buffer, CancellationToken token)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(token);
        idle.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            return await input.ReadAsync(buffer, idle.Token);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            throw new IOException("The download stalled.");
        }
    }

    /// <summary>Installed copy: swap with the kept earlier version, then restart. The version left is not offered again.</summary>
    internal static async Task<InstallResult> GoBackAsync()
    {
        var leaving = AppPaths.Version.ToString();
        var previous = AppPaths.PreviousVersion();
        var result = await WindowsInstaller.SwitchToPreviousAsync(CancellationToken.None);
        if (result.Outcome == InstallOutcome.Done)
        {
            // Going back from a newer version: don't offer it again until something newer appears.
            if (previous is not null && previous < AppPaths.Version)
                UiPreferences.Change(p => p with { SkippedVersion = leaving });
            else
                UiPreferences.Change(p => p with { SkippedVersion = null });
            Restart();
        }
        return result;
    }

    internal static Task<InstallResult> RecoverAsync() => WindowsInstaller.RecoverAsync(CancellationToken.None);

    /// <summary>Portable copy: one-time install, copy the portable checks to the installed app, open it, close this one.</summary>
    internal static async Task<InstallResult> InstallFromPortableAsync()
    {
        var result = await WindowsInstaller.SetupAsync(CancellationToken.None);
        if (result.Outcome is InstallOutcome.Done)
        {
            CopyPortableData();
            Restart();
        }
        return result;
    }

    /// <summary>Copies (never moves) portable data into the installed app's folder; existing files there win.</summary>
    private static void CopyPortableData()
    {
        try
        {
            var from = new DirectoryInfo(AppPaths.DataDirectory);
            // Test runs (NETCHECK_DATA_DIR) never write into the real profile folder.
            if (!from.Exists || string.Equals(from.FullName, AppPaths.ProfileData, StringComparison.OrdinalIgnoreCase) ||
                Environment.GetEnvironmentVariable("NETCHECK_DATA_DIR") is { Length: > 0 })
                return;
            Directory.CreateDirectory(AppPaths.ProfileData);
            foreach (var file in from.EnumerateFiles())
            {
                if (file.Extension.Equals(".tmp", StringComparison.OrdinalIgnoreCase))
                    continue;
                var target = Path.Combine(AppPaths.ProfileData, file.Name);
                if (!File.Exists(target))
                    file.CopyTo(target);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // The portable folder keeps everything; nothing is lost.
        }
    }

    internal static void OpenReleasePage()
    {
        if (Offer is { } offer)
            Open(offer.Page.ToString());
    }

    internal static void Open(string target)
    {
        try
        {
            Process.Start(new ProcessStartInfo { FileName = target, UseShellExecute = true })?.Dispose();
        }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
        }
    }

    /// <summary>Starts the installed copy (which waits for this one) and closes this one.</summary>
    internal static void Restart()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = AppPaths.InstalledExe, Arguments = WaitSwitch, UseShellExecute = true,
                WorkingDirectory = AppPaths.InstallDirectory,
            })?.Dispose();
        }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
        }
        Dispatcher.UIThread.Post(() =>
            (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown());
    }

    private static void Fail(InstallResult result)
    {
        Problem = result.Outcome switch
        {
            InstallOutcome.Cancelled => "Windows asked for permission and it wasn't given.",
            InstallOutcome.RecoveryRequired => "The update stopped halfway.",
            _ => result.Reason.Length > 0 ? char.ToUpperInvariant(result.Reason[0]) + result.Reason[1..].TrimEnd('.') + "." : "",
        };
        Set(UpdateStage.Failed);
    }

    private static void Set(UpdateStage stage)
    {
        Stage = stage;
        Dispatcher.UIThread.Post(() => Changed?.Invoke());
    }
}
