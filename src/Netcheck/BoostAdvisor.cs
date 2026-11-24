using System.Net;
using System.Text.Json;
using Netcheck.Elevation;
using Netcheck.Windows;

namespace Netcheck;

internal enum BoostKind { Recommended, Optional, AlreadyGood }

/// <summary>One Boost line: plain words for the default view plus the typed value to apply.</summary>
internal sealed record BoostItem(TweakId Id, string Name, string Reason, BoostKind Kind, TweakValue Target, TweakValue Current,
    string GoodName = "")
{
    /// <summary>Plain state wording for "Already good" rows ("Cable power saving is off"), not the action.</summary>
    public string Label => Kind == BoostKind.AlreadyGood && GoodName.Length > 0 ? GoodName : Name;
}

/// <summary>What carries the internet now; Boost offers only the tweaks for it (P8, user request).</summary>
internal enum BoostLink { Unknown, Cable, WiFi }

internal sealed record BoostScan(Guid Adapter, IReadOnlyList<BoostItem> Items, BoostLink Link = BoostLink.Unknown,
    string AdapterName = "", bool Usb = false, bool Battery = false)
{
    /// <summary>The quiet line under the title: "Tuned for your cable connection · (the network card's name)".</summary>
    public string TunedFor => Link switch
    {
        BoostLink.Cable => $"Tuned for your cable connection · {AdapterName}",
        BoostLink.WiFi => $"Tuned for your Wi-Fi · {AdapterName}",
        _ => "",
    };

    public IEnumerable<BoostItem> Recommended => Items.Where(i => i.Kind == BoostKind.Recommended);
    public IEnumerable<BoostItem> Optional => Items.Where(i => i.Kind == BoostKind.Optional);
    public IEnumerable<BoostItem> Good => Items.Where(i => i.Kind == BoostKind.AlreadyGood);
}

/// <summary>Myths: things Boost deliberately never changes (design plan §7), one plain line each.</summary>
internal static class BoostMyths
{
    public static IReadOnlyList<(string Name, string Why)> All { get; } =
    [
        ("Freeing the \"reserved 20%\" of bandwidth", "Windows doesn't hold it back. Apps can already use all of it."),
        ("Turning off Nagle (TCPNoDelay)", "Games that need it already switch it off themselves."),
        ("Changing the MTU size", "A wrong value breaks websites. Windows finds the right one."),
        ("Turning off IPv6", "It can break Windows features and makes nothing faster."),
        ("Turning off the firewall", "It removes protection and adds no speed."),
        ("Turning off Wi-Fi auto-configuration", "It hides background scans but stops Wi-Fi reconnecting by itself."),
        ("Wi-Fi \"Throughput Booster\"", "It grabs airtime from every other device on your Wi-Fi."),
        ("Turning off Large Send / checksum offload", "It makes the CPU do the card's work, with no measured gain on modern cards."),
        ("Registry TTL, MaxUserPort, IRPStackSize, DNS cache size", "Old tips with no effect on today's Windows."),
        ("Changing TCP congestion control", "Windows picks it per connection; the built-in templates can't be changed safely."),
    ];
}

/// <summary>
/// Detects each tweak on the active connection (read-only, no elevation) and decides what to offer.
/// Never offers a change that would make an existing stricter or custom setting weaker.
/// </summary>
internal static class BoostAdvisor
{
    private static readonly string UndoPath = AppPaths.Data("boost-original.json");

    private enum Fit { Any, Cable, WiFi, Usb }

    // Order = order shown. "{plugged}" becomes " when plugged in" on PCs with a battery and disappears on desktops.
    private static readonly (TweakId Id, string Name, string Reason, string Good, bool Optional, Fit Fit)[] Catalog =
    [
        (TweakId.WifiPowerSaving, "Keep Wi-Fi at full power{plugged}", "Stops Wi-Fi napping between packets, a common cause of lag spikes.", "Wi-Fi runs at full power{plugged}", false, Fit.WiFi),
        (TweakId.EnergyEfficientEthernet, "Turn off cable power saving", "Stops the cable link slowing down to save power.", "Cable power saving is off", false, Fit.Cable),
        (TweakId.GreenEthernet, "Turn off Green Ethernet", "The card's own cable power saving. It can cause short drops.", "Green Ethernet is off", false, Fit.Cable),
        (TweakId.PowerSavingMode, "Turn off the card's power saving mode", "Keeps the cable link at full speed.", "The card's power saving mode is off", false, Fit.Cable),
        (TweakId.AdvancedEee, "Turn off Advanced EEE", "Another cable power saver that can add delay.", "Advanced EEE is off", false, Fit.Cable),
        (TweakId.SelectiveSuspend, "Don't let the USB network adapter sleep", "USB adapters that nap often drop the connection.", "The USB adapter stays awake", false, Fit.Usb),
        (TweakId.NicPowerSaving, "Keep the network card awake", "Stops Windows turning it off to save power.", "Network card stays awake", false, Fit.Any),
        (TweakId.PcieLinkPower, "Keep the network card's connection awake{plugged}", "The PC's internal link to the card doesn't sleep. Waking it adds delay.", "The card's connection stays awake{plugged}", false, Fit.Any),
        (TweakId.SpeedDuplex, "Let the cable pick its full speed", "The cable speed was fixed by hand, which can cap you below your plan. Auto lets the card and router agree on the fastest speed.", "The cable picks its own speed", false, Fit.Cable),
        (TweakId.ReceiveSideScaling, "Spread network work across the CPU", "Receive Side Scaling was off, so one CPU core handles all traffic. Windows turns it on by default.", "Network work is spread across the CPU", false, Fit.Any),
        (TweakId.RoamingAggressiveness, "Wi-Fi roaming back to normal", "Someone changed how eagerly Wi-Fi hops between access points. Medium is Intel's advice.", "Wi-Fi roaming is normal", false, Fit.WiFi),
        (TweakId.BackgroundUpdates, "Keep Windows updates in the background", "Big updates won't slow your games or calls.", "Updates already have a speed limit", false, Fit.Any),
        (TweakId.AutoTuning, "Normal download tuning", "Lets Windows size downloads to your speed.", "Download tuning is normal", false, Fit.Any),
        (TweakId.UpdateSharing, "Stop sharing updates over the internet", "Your upload stays free for you.", "Updates aren't shared over the internet", false, Fit.Any),
        (TweakId.PreferredBand, "Prefer the faster Wi-Fi band", "Connects on 5 GHz when your router offers it. Range is shorter than 2.4 GHz.", "Wi-Fi already prefers 5 GHz", true, Fit.WiFi),
        (TweakId.MimoPowerSave, "Use all Wi-Fi antennas", "Keeps every antenna on instead of switching some off to save power.", "All Wi-Fi antennas stay on", true, Fit.WiFi),
        (TweakId.PacketCoalescing, "Don't hold packets back", "The card collects packets in batches to save power. Off hands them over at once; uses a little more power.", "Packets aren't held back", true, Fit.Any),
        (TweakId.InterruptModeration, "Lowest-latency network card mode", "Hands each packet to Windows straight away. For competitive games; uses a little more CPU.", "Lowest-latency mode is on", true, Fit.Any),
        (TweakId.Ecn, "Smoother busy networks (ECN)", "Can help on busy networks. Some routers ignore it.", "Busy-network signals are on", true, Fit.Any),
        (TweakId.MediaThrottling, "Remove the media network limit", "Very small effect on most PCs.", "Media network limit is off", true, Fit.Any),
    ];

    public static Task<BoostScan> ScanAsync() => Task.Run(() =>
    {
        var adapter = Guid.Empty;
        try
        {
            var route = RouteDiscovery.Read(IPAddress.Parse("1.1.1.1"));
            if (route.State == RouteReadState.Found && route.AdapterId is { } id)
                adapter = id;
        }
        catch (Exception) { }

        // What carries the internet: cable or Wi-Fi (and whether it's a USB adapter), and whether there's a battery.
        var info = adapter == Guid.Empty ? null : Safe(() => AdapterDiscovery.Read().FirstOrDefault(a => a.Id == adapter));
        var link = info?.Type switch
        {
            System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211 => BoostLink.WiFi,
            null => BoostLink.Unknown,
            _ => BoostLink.Cable,
        };
        var usb = adapter != Guid.Empty && Safe(() => IsUsb(adapter));
        var battery = Safe(HasBattery);
        var plugged = battery ? " when plugged in" : "";
        var scheme = Safe(() => (Guid?)WindowsTweakBroker.ActivePowerScheme()) ?? Guid.Empty;

        var items = new List<BoostItem>();
        foreach (var (id, nameText, reason, goodText, optional, fit) in Catalog)
        {
            if (fit == Fit.Cable && link != BoostLink.Cable || fit == Fit.WiFi && link != BoostLink.WiFi || fit == Fit.Usb && !usb)
                continue;
            var scope = TweakRules.PowerPlan(id) ? scheme : TweakRules.AdapterScoped(id) ? adapter : Guid.Empty;
            if (TweakRules.AdapterScoped(id) && scope == Guid.Empty)
                continue;
            TweakValue current;
            long? targetValue;
            try
            {
                current = WindowsTweakBroker.Read(id, scope);
                targetValue = TweakRules.DriverMapped(id) ? WindowsTweakBroker.DriverTarget(id, scope) : TweakRules.Target(id);
            }
            catch (Exception) { continue; } // not on this PC/driver: don't show it at all
            if (TweakRules.DriverMapped(id) && targetValue is null)
                continue;                      // the driver has no matching choice
            var target = new TweakValue(id, scope, targetValue);
            var needed = id switch
            {
                TweakId.NicPowerSaving => current.Value == 1,
                TweakId.BackgroundUpdates => current.Value is null,          // any existing limit is respected
                TweakId.AutoTuning => current.Value != 3,
                TweakId.EnergyEfficientEthernet => current.Value != 0,
                TweakId.UpdateSharing => current.Value == 3,                  // only internet uploads; never loosen 0/99/100
                TweakId.Ecn => current.Value == 0,
                TweakId.MediaThrottling => current.Value != TweakRules.ThrottlingOff,
                TweakId.WifiPowerSaving or TweakId.PcieLinkPower => current.Value != 0,
                TweakId.GreenEthernet or TweakId.PowerSavingMode or TweakId.AdvancedEee or TweakId.SelectiveSuspend or
                    TweakId.InterruptModeration or TweakId.PacketCoalescing => current.Value == 1,
                TweakId.ReceiveSideScaling => current.Value == 0,
                TweakId.PreferredBand or TweakId.MimoPowerSave or TweakId.RoamingAggressiveness or TweakId.SpeedDuplex =>
                    current.Value != targetValue,
                _ => false,
            };
            items.Add(new BoostItem(id, nameText.Replace("{plugged}", plugged, StringComparison.Ordinal), reason,
                !needed ? BoostKind.AlreadyGood : optional ? BoostKind.Optional : BoostKind.Recommended, target, current,
                goodText.Replace("{plugged}", plugged, StringComparison.Ordinal)));
        }
        var name = (info?.Description ?? "").Replace("(R)", "", StringComparison.Ordinal).Replace("(TM)", "", StringComparison.Ordinal)
            .Replace("  ", " ", StringComparison.Ordinal).Trim();
        return Last = new BoostScan(adapter, items, link, name, usb, battery);
    });

    /// <summary>
    /// The latest scan, so the Boost tab can show its list the moment it opens (user, 2026-11-16) and refresh it
    /// quietly in place. The main window runs a first scan in the background shortly after start.
    /// </summary>
    public static BoostScan? Last { get; private set; }

    private static T Safe<T>(Func<T> read)
    {
        try { return read(); }
        catch (Exception) { return default!; }
    }

    private static bool IsUsb(Guid adapter)
    {
        using var searcher = new System.Management.ManagementObjectSearcher("root/cimv2",
            $"SELECT PNPDeviceID FROM Win32_NetworkAdapter WHERE GUID = '{adapter.ToString("B").ToUpperInvariant()}'");
        return searcher.Get().Cast<System.Management.ManagementObject>()
            .Any(o => o["PNPDeviceID"] is string device && device.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase));
    }

    private static bool HasBattery()
    {
        using var searcher = new System.Management.ManagementObjectSearcher("root/cimv2", "SELECT Name FROM Win32_Battery");
        return searcher.Get().Count > 0;
    }

    // ---------- undo ("Undo My Boost Changes") ----------

    /// <summary>The values from before Netcheck's Boost changes, or null when nothing is applied.</summary>
    public static TweakValue[]? Originals
    {
        get
        {
            try
            {
                return File.Exists(UndoPath) && new FileInfo(UndoPath).Length <= 16384
                    ? JsonSerializer.Deserialize<TweakValue[]>(File.ReadAllText(UndoPath)) : null;
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
            {
                return null;
            }
        }
    }

    /// <summary>Adds the originals of newly applied tweaks; keeps the earliest original for tweaks applied before.</summary>
    public static void RememberOriginals(IEnumerable<TweakValue> before)
    {
        var all = (Originals ?? []).ToList();
        foreach (var value in before)
            if (!all.Any(v => v.Id == value.Id && v.Adapter == value.Adapter))
                all.Add(value);
        Save(all);
    }

    /// <summary>Keeps the last Boost result and its step reason (for the details view and troubleshooting).</summary>
    public static void LogLast(string action, TweakOutcome outcome, string reason)
    {
        try
        {
            var path = Path.Combine(Path.GetDirectoryName(UndoPath)!, "boost-last.json");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(new { At = DateTimeOffset.Now, Action = action, Outcome = outcome.ToString(), Reason = reason }));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }

    public static void ForgetOriginals()
    {
        try { File.Delete(UndoPath); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }

    private static void Save(List<TweakValue> values)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(UndoPath)!);
            var temporary = UndoPath + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(values));
            File.Move(temporary, UndoPath, overwrite: true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }
}
