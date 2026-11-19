using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Netcheck.Core;
using Netcheck.Elevation;
using Netcheck.Measurements;
using Netcheck.Windows;

namespace Netcheck;

/// <summary>Result of a switch, in the three outcomes the DNS page shows (plus a reason for the details).</summary>
internal enum SwitchResult { Done, NothingChanged, NeedsFix }

internal sealed record SwitchOutcome(SwitchResult Result, string Reason);

/// <summary>Private (encrypted) DNS on the connection now. Partly = some addresses plain or allowed to fall back.</summary>
internal enum PrivateState { Unknown, Off, Partly, On }

/// <summary>
/// Switches the connection's IPv4 DNS through the elevated broker (Detect → Validate → Snapshot → Apply →
/// Read back → Verify → Commit or Restore all happen in <see cref="DnsTransaction"/>). Remembers the settings
/// from before the first switch so "Switch back" restores exactly those, even after several switches.
/// </summary>
internal static class DnsSwitcher
{
    private static readonly string OriginalPath = AppPaths.Data("dns-original.json");

    /// <summary>True only in the protected Program Files install (the broker refuses everywhere else).</summary>
    public static bool IsAvailable => OperatingSystem.IsWindows() && WindowsDnsBroker.IsEnabled;

    /// <summary>The servers this PC used before Netcheck's first switch, or null when nothing is switched.</summary>
    public static DnsChange? Original
    {
        get
        {
            try
            {
                return File.Exists(OriginalPath) && new FileInfo(OriginalPath).Length <= 8192
                    ? JsonSerializer.Deserialize<DnsChange>(File.ReadAllText(OriginalPath)) : null;
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Switches to <paramref name="target"/>. Private DNS (P11, user choice 2026-11-16: encrypted only): when the provider
    /// publishes an HTTPS template, every address is set to "require HTTPS" with no plain fallback, so the Verify step
    /// (websites open through Windows) can only pass if encrypted lookups really work on this network.
    /// </summary>
    public static Task<SwitchOutcome> SwitchToAsync(DnsCandidate target, CancellationToken token = default) =>
        RunAsync(adapter =>
        {
            DnsResolver For(string address) => target.DohTemplate is { } template
                ? new(address, DnsEncryption.RequireHttps, template)
                : new(address, DnsEncryption.Plaintext);
            IReadOnlyList<DnsResolver> resolvers = target.Secondary is { } second ? [For(target.Address), For(second)] : [For(target.Address)];
            return new DnsChange(adapter, DnsTargetFamily.Ipv4, DnsTargetAssignment.Manual, resolvers, false);
        }, rememberOriginal: true, token);

    /// <summary>
    /// Whether the connection's IPv4 lookups are encrypted now, read from Windows' per-adapter settings
    /// (Unknown when it can't be read, e.g. a DNS profile or no route).
    /// </summary>
    public static PrivateState ReadPrivateState()
    {
        if (!OperatingSystem.IsWindows())
            return PrivateState.Unknown;
        try
        {
            var route = RouteDiscovery.Read(IPAddress.Parse("1.1.1.1"));
            if (route.State != RouteReadState.Found || route.AdapterId is not { } adapter || ReadCurrent(adapter) is not { } now)
                return PrivateState.Unknown;
            // Automatic DNS (P12b): Windows' per-adapter settings list no servers, but encrypted entries for the router's
            // servers can be left over (seen 2026-11-16 after a cable reconnect). Whether Windows uses them for DHCP servers
            // isn't shown anywhere, so it reads "Partly" (user choice), never "Off" and never "On".
            if (now.Assignment == DnsTargetAssignment.Automatic)
                return LeftoverEncrypted(adapter) ? PrivateState.Partly : PrivateState.Off;
            var encrypted = now.Resolvers.Count(r => r.Encryption != DnsEncryption.Plaintext);
            return encrypted == 0 ? PrivateState.Off
                : encrypted == now.Resolvers.Count && now.Resolvers.All(r => r.Encryption == DnsEncryption.RequireHttps) ? PrivateState.On
                : PrivateState.Partly;
        }
        catch (Exception error) when (error is NotSupportedException or System.Net.NetworkInformation.NetworkInformationException or
            UnauthorizedAccessException or Win32Exception or InvalidOperationException)
        {
            return PrivateState.Unknown;
        }
    }

    /// <summary>
    /// The HTTPS template Windows uses for <paramref name="address"/> on the internet connection now (set by hand with
    /// private lookups on), or null when lookups to it go plain or it can't be read. The benchmark and the Check page
    /// time the current DNS this way, so "Now" is what this PC really gets (P12b).
    /// </summary>
    public static string? HttpsTemplateFor(string address)
    {
        if (!OperatingSystem.IsWindows() || address.Length == 0)
            return null;
        try
        {
            var route = RouteDiscovery.Read(IPAddress.Parse("1.1.1.1"));
            return route.State == RouteReadState.Found && route.AdapterId is { } adapter && ReadCurrent(adapter) is { } now
                ? now.Resolvers.FirstOrDefault(r => r.Address == address && r.Encryption != DnsEncryption.Plaintext)?.HttpsTemplate
                : null;
        }
        catch (Exception error) when (error is NotSupportedException or System.Net.NetworkInformation.NetworkInformationException or
            UnauthorizedAccessException or Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>True when Windows keeps an encrypted entry for one of the router-given (DHCP) DNS servers of this adapter.</summary>
    private static bool LeftoverEncrypted(Guid adapter)
    {
        var servers = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => Guid.TryParse(n.Id, out var id) && id == adapter)?.GetIPProperties().DnsAddresses
            .Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()).ToArray() ?? [];
        using var doh = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\{adapter:B}\DohInterfaceSettings\Doh");
        if (doh is null)
            return false;
        foreach (var server in servers)
        {
            using var entry = doh.OpenSubKey(server);
            if (entry?.GetValue("DohFlags") is int flags && flags != 0)
                return true;
        }
        return false;
    }

    public static Task<SwitchOutcome> SwitchBackAsync(CancellationToken token = default) =>
        Original is { } original
            ? RunAsync(adapter => original.AdapterId == adapter ? original : null, rememberOriginal: false, token)
            : Task.FromResult(new SwitchOutcome(SwitchResult.NothingChanged, "No earlier DNS settings were saved."));

    /// <summary>Finishes an interrupted change by putting the recorded settings back.</summary>
    public static async Task<SwitchOutcome> FixAsync(CancellationToken token = default)
    {
        if (!IsAvailable)
            return new(SwitchResult.NeedsFix, "Fixing needs the installed app.");
        try
        {
            var outcome = await WindowsDnsBroker.RecoverAsync(token);
            return outcome is DnsTransactionOutcome.Restored or DnsTransactionOutcome.NoChange
                ? new(SwitchResult.NothingChanged, "The earlier DNS settings are back.")
                : new(SwitchResult.NeedsFix, $"Recovery ended as {outcome}.");
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            return new(SwitchResult.NeedsFix, "Permission was declined.");
        }
        catch (Exception error) when (error is OperationCanceledException or IOException or Win32Exception or JsonException or InvalidOperationException)
        {
            return new(SwitchResult.NeedsFix, error.Message);
        }
    }

    private static async Task<SwitchOutcome> RunAsync(Func<Guid, DnsChange?> propose, bool rememberOriginal, CancellationToken token)
    {
        if (!IsAvailable)
            return new(SwitchResult.NothingChanged, "Switching works in the installed app.");

        ReviewedDnsChange review;
        try
        {
            var snapshot = await Task.Run(() =>
            {
                var route = RouteDiscovery.Read(IPAddress.Parse("1.1.1.1"));
                if (route.State != RouteReadState.Found || route.AdapterId is not { } adapter)
                    return null;
                var proposed = propose(adapter);
                return proposed is null ? null
                    : new ReviewedDnsChange(WindowsDnsBroker.ReadForReview(adapter, DnsTargetFamily.Ipv4), proposed);
            }, token);
            if (snapshot is null)
                return new(SwitchResult.NothingChanged, "The connection changed since the DNS was saved.");
            review = snapshot;
        }
        catch (Exception error) when (error is NotSupportedException or System.Net.NetworkInformation.NetworkInformationException or
            UnauthorizedAccessException or Win32Exception or InvalidOperationException)
        {
            // Covers DNS set by a profile/policy and settings Netcheck could not restore exactly.
            return new(SwitchResult.NothingChanged, $"Windows DNS settings can't be changed safely here: {error.Message}");
        }

        if (rememberOriginal && Original is null)
            Save(review.Before.Target);

        DnsTransactionOutcome outcome;
        try
        {
            outcome = await WindowsDnsBroker.ApplyAsync(review, WebsitesOpenAsync, token);
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            ForgetIfUnchanged(rememberOriginal);
            return new(SwitchResult.NothingChanged, "Permission was declined.");
        }
        catch (Exception error) when (error is OperationCanceledException or IOException or Win32Exception or
            JsonException or InvalidOperationException or UnauthorizedAccessException)
        {
            // The helper stopped without a final answer (e.g. it refused to start). Only call it broken when the
            // settings actually differ from before; unchanged settings mean nothing happened (seen 2026-11-16).
            if (ReadCurrent(review.Before.Target.AdapterId) is { } now && now.Assignment == review.Before.Target.Assignment &&
                now.Resolvers.SequenceEqual(review.Before.Target.Resolvers))
            {
                ForgetIfUnchanged(rememberOriginal);
                return new(SwitchResult.NothingChanged, $"Netcheck's helper stopped before changing anything ({error.Message}).");
            }
            return new(SwitchResult.NeedsFix, $"The change ended without a confirmed result: {error.Message}");
        }

        switch (outcome)
        {
            case DnsTransactionOutcome.Committed or DnsTransactionOutcome.NoChange:
                if (!rememberOriginal)
                    Forget();
                return new(SwitchResult.Done, outcome.ToString());
            case DnsTransactionOutcome.Rejected or DnsTransactionOutcome.Restored:
                ForgetIfUnchanged(rememberOriginal);
                return new(SwitchResult.NothingChanged, outcome == DnsTransactionOutcome.Restored
                    ? review.Proposed.Resolvers.Any(r => r.Encryption != DnsEncryption.Plaintext)
                        ? "Private DNS didn't work on this network, so the earlier settings were put back."
                        : "Websites didn't open with the new DNS, so the earlier settings were put back."
                    : "Windows didn't allow the change (VPN, work policy, or the settings changed meanwhile).");
            default:
                return new(SwitchResult.NeedsFix, $"The change ended as {outcome}.");
        }
    }

    /// <summary>Verify step: with the new settings in place, ordinary lookups through Windows must all work.</summary>
    private static async Task<bool> WebsitesOpenAsync(CancellationToken token)
    {
        // Warm-up: right after a change Windows may need a moment (with private DNS, its first encrypted connection).
        // Wait up to ~10 s for one answer, then every name must work as before. Plain DNS answers on the first try.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(2));
            try
            {
                if ((await Dns.GetHostAddressesAsync(MeasurementProtocol.DnsNames[0], AddressFamily.InterNetwork, deadline.Token)).Length > 0)
                    break;
            }
            catch (System.Net.Sockets.SocketException) { await Task.Delay(500, token); }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
        }
        var check = await SystemDnsMeasurement.MeasureAsync(AddressFamily.InterNetwork, "A", token);
        return check.Failed == 0 && check.Milliseconds.Count == MeasurementProtocol.DnsNames.Count;
    }

    /// <summary>After a first switch that didn't happen, the saved "original" is just the current setting: drop it.</summary>
    private static void ForgetIfUnchanged(bool firstSwitch)
    {
        if (firstSwitch && Original is { } saved && ReadCurrent(saved.AdapterId) is { } now &&
            now.Resolvers.SequenceEqual(saved.Resolvers) && now.Assignment == saved.Assignment)
            Forget();
    }

    private static DnsChange? ReadCurrent(Guid adapter)
    {
        try { return WindowsDnsBroker.ReadForReview(adapter, DnsTargetFamily.Ipv4).Target; }
        catch (Exception) { return null; }
    }

    private static void Save(DnsChange original)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(OriginalPath)!);
            var temporary = OriginalPath + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(original));
            File.Move(temporary, OriginalPath, overwrite: true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void Forget()
    {
        try { File.Delete(OriginalPath); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }
}
