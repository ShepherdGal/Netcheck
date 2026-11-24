namespace Netcheck.Elevation;

// Boost tweaks (design plan §7). Each tweak is one typed, allowlisted value; the platform maps the id to one
// fixed registry value or CIM property in code, so a caller can never name a path, key or command.

public enum TweakId
{
    NicPowerSaving,          // "Allow the computer to turn off this device" on the active adapter: 1 on, 0 off
    BackgroundUpdates,       // Delivery Optimization background bandwidth policy, percent (null = not set)
    Ecn,                     // TCP "Internet" template ECN: 0 off, 1 on
    MediaThrottling,         // Multimedia NetworkThrottlingIndex (null = Windows default 10, 0xFFFFFFFF = off)
    AutoTuning,              // TCP "Internet" template receive-window auto-tuning level: 0..4, 3 = normal
    EnergyEfficientEthernet, // Adapter *EEE advanced property: 0 off, other = driver's "on" values
    UpdateSharing,           // Delivery Optimization download-mode policy (null = not set, 3 = internet uploads)
    // ---- added P8 (research: Microsoft NIC tuning, Intel, Dell); scope = power scheme or adapter ----
    WifiPowerSaving,         // Power plan "Wireless Adapter Settings → Power Saving Mode", plugged-in index: 0 max performance … 3 max saving
    PcieLinkPower,           // Power plan "PCI Express → Link State Power Management", plugged-in index: 0 off, 1 moderate, 2 maximum
    GreenEthernet,           // Adapter "EnableGreenEthernet" (Realtek): 0 off, 1 on
    PowerSavingMode,         // Adapter "PowerSavingMode" (Realtek): 0 off, 1 on
    AdvancedEee,             // Adapter "AdvancedEEE" (Realtek): 0 off, 1 on
    SelectiveSuspend,        // Adapter *SelectiveSuspend (USB adapters): 0 off, 1 on
    InterruptModeration,     // Adapter *InterruptModeration: 0 off, 1 on
    PreferredBand,           // Wi-Fi adapter preferred band: one of the driver's own registry values
    MimoPowerSave,           // Wi-Fi adapter MIMO power save mode: one of the driver's own registry values
    RoamingAggressiveness,   // Wi-Fi adapter roaming aggressiveness: one of the driver's own registry values
    // ---- added P15 (2026-11-24): real faults found on PCs, each a standard NDIS keyword ----
    ReceiveSideScaling,      // Adapter *RSS: 0 off, 1 on (Microsoft: on by default; off puts all traffic on one CPU core)
    SpeedDuplex,             // Adapter *SpeedDuplex: one of the driver's values; the target is its "Auto Negotiation"
    PacketCoalescing,        // Adapter *PacketCoalescing: 0 off, 1 on (batches packets to save power; adds delay)
}

/// <summary>One setting: the tweak, its adapter (empty for system-wide tweaks) and its value (null = not set).</summary>
public sealed record TweakValue(TweakId Id, Guid Adapter, long? Value);

public sealed record TweakRecoveryRecord(IReadOnlyList<TweakValue> Before, IReadOnlyList<TweakValue> Proposed);

public enum TweakOutcome { Committed, NoChange, Rejected, Restored, RecoveryRequired, Conflict }

public enum RestorePointResult { NotRequested, Made, Skipped, Off, Failed }

public static class TweakRules
{
    public const long ThrottlingOff = 0xFFFFFFFF;
    public const int MaxBatch = 20;

    /// <summary>Tweaks whose <see cref="TweakValue.Adapter"/> names something: an adapter, or (power plan) a power scheme.</summary>
    public static bool AdapterScoped(TweakId id) => id is TweakId.NicPowerSaving or TweakId.EnergyEfficientEthernet ||
        AdvancedProperty(id) || PowerPlan(id);

    /// <summary>Power-plan tweaks: the scope GUID is the power scheme, so Undo always returns to the plan it changed.</summary>
    public static bool PowerPlan(TweakId id) => id is TweakId.WifiPowerSaving or TweakId.PcieLinkPower;

    /// <summary>Adapter advanced properties (read/written through the driver's own advanced-property list).</summary>
    public static bool AdvancedProperty(TweakId id) => id is TweakId.GreenEthernet or TweakId.PowerSavingMode or
        TweakId.AdvancedEee or TweakId.SelectiveSuspend or TweakId.InterruptModeration or TweakId.ReceiveSideScaling or
        TweakId.PacketCoalescing || DriverMapped(id);

    /// <summary>Values that differ per driver: the target is the driver value whose label matches (e.g. "Prefer 5GHz band").</summary>
    public static bool DriverMapped(TweakId id) => id is TweakId.PreferredBand or TweakId.MimoPowerSave or TweakId.RoamingAggressiveness or
        TweakId.SpeedDuplex;

    /// <summary>The value Netcheck proposes for each tweak.</summary>
    public static long? Target(TweakId id) => id switch
    {
        TweakId.NicPowerSaving => 0,
        TweakId.BackgroundUpdates => 20,
        TweakId.Ecn => 1,
        TweakId.MediaThrottling => ThrottlingOff,
        TweakId.AutoTuning => 3,
        TweakId.EnergyEfficientEthernet => 0,
        TweakId.UpdateSharing => 1,
        TweakId.WifiPowerSaving or TweakId.PcieLinkPower => 0,
        TweakId.GreenEthernet or TweakId.PowerSavingMode or TweakId.AdvancedEee or TweakId.SelectiveSuspend or
            TweakId.InterruptModeration or TweakId.PacketCoalescing => 0,
        TweakId.ReceiveSideScaling => 1,
        _ => throw new ArgumentOutOfRangeException(nameof(id), "This tweak's target comes from the driver."),
    };

    /// <summary>Allowlist: known id, adapter present exactly when needed, value inside the documented range.</summary>
    public static bool Valid(TweakValue? value) => value is { } v && Enum.IsDefined(v.Id) &&
        (AdapterScoped(v.Id) ? v.Adapter != Guid.Empty : v.Adapter == Guid.Empty) && v.Id switch
        {
            TweakId.NicPowerSaving or TweakId.Ecn => v.Value is 0 or 1,
            TweakId.BackgroundUpdates => v.Value is null or (>= 0 and <= 100),
            TweakId.MediaThrottling => v.Value is null or (>= 1 and <= 70) or ThrottlingOff,
            TweakId.AutoTuning => v.Value is >= 0 and <= 4,
            TweakId.EnergyEfficientEthernet => v.Value is >= 0 and <= 16,
            TweakId.UpdateSharing => v.Value is null or (>= 0 and <= 3) or 99 or 100,
            TweakId.WifiPowerSaving => v.Value is >= 0 and <= 3,
            TweakId.PcieLinkPower => v.Value is >= 0 and <= 2,
            TweakId.GreenEthernet or TweakId.PowerSavingMode or TweakId.AdvancedEee or TweakId.SelectiveSuspend or
                TweakId.InterruptModeration or TweakId.ReceiveSideScaling or TweakId.PacketCoalescing => v.Value is 0 or 1,
            // Speed values are enumerations (0 = auto, 1..10 standard); some drivers use larger codes such as 2500.
            TweakId.SpeedDuplex => v.Value is >= 0 and <= 100_000,
            // The platform additionally requires the value to be one the driver itself lists (Permits).
            TweakId.PreferredBand or TweakId.MimoPowerSave or TweakId.RoamingAggressiveness => v.Value is >= 0 and <= 255,
            _ => false,
        };
}

// The platform must reject values it cannot read back or restore exactly.
public interface ITweakPlatform
{
    TweakValue Read(TweakId id, Guid adapter);
    bool Permits(TweakValue value);
    void Write(TweakValue value);
}

// Same contract as the DNS journal: exclusive cross-process lease, integrity-checked record.
public interface ITweakRecoveryStore
{
    IDisposable AcquireExclusive();
    TweakRecoveryRecord? Read();
    void Persist(TweakRecoveryRecord record);
    void Clear();
}

/// <summary>
/// Detect → Validate → Snapshot → Apply → Read back → Verify → Commit or Restore for a batch of tweaks.
/// The "before" values are always read here (never taken from the caller); the journal is written before
/// the first change, so a crash at any point leaves enough to restore.
/// </summary>
public sealed class TweakTransaction(ITweakPlatform platform, ITweakRecoveryStore recovery)
{
    /// <summary>Which step decided the last outcome, in plain technical words (for the details view and logs).</summary>
    public string Reason { get; private set; } = "";

    private TweakOutcome Because(TweakOutcome outcome, string reason)
    {
        Reason = reason;
        return outcome;
    }

    public TweakOutcome Apply(IReadOnlyList<TweakValue> proposed, Func<CancellationToken, bool> verify,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(verify);
        if (proposed is not { Count: > 0 and <= TweakRules.MaxBatch } || !proposed.All(TweakRules.Valid) ||
            proposed.Select(p => (p.Id, p.Adapter)).Distinct().Count() != proposed.Count)
            return Because(TweakOutcome.Rejected, "validate: the batch is empty, too big, duplicated or outside the allowlist");
        var wanted = proposed.ToArray();

        using var lease = recovery.AcquireExclusive();
        try
        {
            if (recovery.Read() is not null)
                return Because(TweakOutcome.RecoveryRequired, "journal: an earlier change was not finished");
        }
        catch (InvalidDataException) { return Because(TweakOutcome.RecoveryRequired, "journal: unreadable"); }

        // Detect + snapshot.
        TweakValue[] before;
        try { before = wanted.Select(p => platform.Read(p.Id, p.Adapter)).ToArray(); }
        catch (Exception error) when (error is NotSupportedException or UnauthorizedAccessException or
            InvalidOperationException or System.ComponentModel.Win32Exception or IOException)
        {
            return Because(TweakOutcome.Rejected, $"detect: {error.GetType().Name}: {error.Message}");
        }
        var changes = Enumerable.Range(0, wanted.Length).Where(i => before[i].Value != wanted[i].Value).ToArray();
        if (changes.Length == 0)
            return Because(TweakOutcome.NoChange, "detect: already at the proposed values");

        // Validate: both directions must be writable, or the change could not be undone exactly.
        var record = new TweakRecoveryRecord(changes.Select(i => before[i]).ToArray(), changes.Select(i => wanted[i]).ToArray());
        if (token.IsCancellationRequested)
            return Because(TweakOutcome.Rejected, "validate: cancelled");
        if (record.Before.FirstOrDefault(v => !TweakRules.Valid(v)) is { } odd)
            return Because(TweakOutcome.Rejected, $"validate: current {odd.Id} = {odd.Value} can't be restored exactly");
        if (record.Proposed.Concat(record.Before).FirstOrDefault(v => !platform.Permits(v)) is { } refused)
            return Because(TweakOutcome.Rejected, $"validate: not permitted here: {refused.Id} = {refused.Value} (managed PC, policy or adapter)");

        recovery.Persist(record);
        TweakId? writing = null;
        try
        {
            foreach (var value in record.Proposed)
            {
                token.ThrowIfCancellationRequested();
                writing = value.Id;
                platform.Write(value);
            }
            writing = null;
            if (Mismatch(record.Proposed) is { } stuck)
                Reason = $"read back: {stuck.Id} is {platform.Read(stuck.Id, stuck.Adapter).Value} after writing {stuck.Value}";
            else if (!verify(token) || token.IsCancellationRequested)
                Reason = "verify: not kept (Undo, no answer in time, or closed)";
            else if (Mismatch(record.Proposed) is { } drifted)
                Reason = $"read back after keep: {drifted.Id} changed to {platform.Read(drifted.Id, drifted.Adapter).Value}";
            else
                return Clear(TweakOutcome.Committed, "committed");
        }
        catch (Exception error)
        {
            // A write can fail after changing state. Restore classifies every value by reading it back.
            // Name the tweak whose write failed, so a live failure points straight at it (2026-11-17).
            Reason = $"apply{(writing is { } id ? $" {id}" : "")}: {error.GetType().Name}: {error.Message}";
        }
        var why = Reason;
        var restored = Restore(record);
        Reason = $"{why}; restore: {Reason}";
        return restored;
    }

    public TweakOutcome Recover()
    {
        using var lease = recovery.AcquireExclusive();
        TweakRecoveryRecord? record;
        try { record = recovery.Read(); }
        catch (InvalidDataException) { return Because(TweakOutcome.RecoveryRequired, "journal: unreadable"); }
        if (record is null)
            return Because(TweakOutcome.NoChange, "journal: nothing to recover");
        return record.Before.Count == record.Proposed.Count && record.Before.All(TweakRules.Valid) &&
               record.Proposed.All(TweakRules.Valid) ? Restore(record) : TweakOutcome.RecoveryRequired;
    }

    private TweakOutcome Restore(TweakRecoveryRecord record)
    {
        var conflict = false;
        try
        {
            for (var i = 0; i < record.Before.Count; i++)
            {
                var original = record.Before[i];
                var current = platform.Read(original.Id, original.Adapter);
                if (current.Value == original.Value)
                    continue;
                // Only undo our own value; anything else was changed by someone else meanwhile.
                if (current.Value != record.Proposed[i].Value)
                {
                    conflict = true;
                    continue;
                }
                platform.Write(original);
            }
            if (conflict)
                return Because(TweakOutcome.Conflict, "a value was changed by something else; journal kept");
            return AllAt(record.Before) ? Clear(TweakOutcome.Restored, "all values back")
                : Because(TweakOutcome.RecoveryRequired, "a value did not return to its original");
        }
        catch (Exception error)
        {
            return Because(TweakOutcome.RecoveryRequired, $"{error.GetType().Name}: {error.Message}");
        }
    }

    private bool AllAt(IEnumerable<TweakValue> values) => Mismatch(values) is null;

    private TweakValue? Mismatch(IEnumerable<TweakValue> values) =>
        values.FirstOrDefault(v => platform.Read(v.Id, v.Adapter).Value != v.Value);

    private TweakOutcome Clear(TweakOutcome outcome, string reason)
    {
        try { recovery.Clear(); }
        catch (Exception error) { return Because(TweakOutcome.RecoveryRequired, $"journal clear failed: {error.Message}"); }
        return Because(outcome, reason);
    }
}
