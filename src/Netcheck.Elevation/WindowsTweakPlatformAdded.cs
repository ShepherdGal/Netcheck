using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Netcheck.Windows;

namespace Netcheck.Elevation;

/// <summary>
/// P8 tweaks. Power-plan values go through powrprof (PowerRead/WriteACValueIndex on the named scheme, plugged-in
/// value only; battery behaviour is untouched). Adapter values go through the driver's own advanced-property list
/// (MSFT_NetAdapterAdvancedPropertySettingData), and only values that list offers can be written.
/// </summary>
internal sealed partial class WindowsTweakPlatform
{
    // Power setting GUIDs (Windows-defined; seen on the test PC with powercfg /q, 2026-11-16).
    private static readonly Guid WirelessSubgroup = new("19cbb8fa-5279-450e-9fac-8a3d5fedd0c1");
    private static readonly Guid WirelessPowerSaving = new("12bbebe6-58d6-4636-95bb-3217ef867c1a");
    private static readonly Guid PcieSubgroup = new("501a4d13-42af-4429-9fd1-a8218c268e20");
    private static readonly Guid PcieAspm = new("ee12f906-d277-404b-b6da-e5fa1a576df5");

    /// <summary>Driver keywords per tweak, in the order tried (vendors name some settings differently).</summary>
    internal static IReadOnlyList<string> Keywords(TweakId id) => id switch
    {
        TweakId.GreenEthernet => ["EnableGreenEthernet", "GreenEthernet"],
        TweakId.PowerSavingMode => ["PowerSavingMode"],
        TweakId.AdvancedEee => ["AdvancedEEE"],
        TweakId.SelectiveSuspend => ["*SelectiveSuspend"],
        TweakId.InterruptModeration => ["*InterruptModeration"],
        TweakId.PreferredBand => ["RoamingPreferredBandType", "PreferredBand", "BandPreference"],
        TweakId.MimoPowerSave => ["MIMOPowerSaveMode", "MimoPowerSaveMode"],
        TweakId.RoamingAggressiveness => ["RoamAggressiveness", "RoamingAggressiveness"],
        _ => [],
    };

    /// <summary>Which driver label is the target for a driver-mapped tweak.</summary>
    internal static bool IsTargetLabel(TweakId id, string label)
    {
        var l = label.ToUpperInvariant();
        return id switch
        {
            // "Prefer 5GHz band", "5 GHz preferred", "Prefer 5.2GHz" — but never a 2.4 or 6 GHz preference.
            TweakId.PreferredBand => l.Contains('5') && (l.Contains("PREFER", StringComparison.Ordinal) || l.Contains("PREFERRED", StringComparison.Ordinal)) &&
                                     !l.Contains("2.4", StringComparison.Ordinal) && !l.Contains("6G", StringComparison.Ordinal) && !l.Contains("6 G", StringComparison.Ordinal),
            TweakId.MimoPowerSave => l.Contains("NO SMPS", StringComparison.Ordinal),
            TweakId.RoamingAggressiveness => l.Contains("MEDIUM", StringComparison.Ordinal) && !l.Contains("-", StringComparison.Ordinal),
            _ => false,
        };
    }

    /// <summary>
    /// The value to propose for a driver-mapped tweak on this adapter, or null when the driver offers no matching
    /// choice (then the tweak isn't offered). Read-only; used by the Boost page to detect.
    /// </summary>
    internal static long? DriverTarget(TweakId id, Guid adapter)
    {
        using var property = AdvancedPropertyObject(id, adapter);
        var labels = property["ValidDisplayValues"] as string[] ?? [];
        var values = property["ValidRegistryValues"] as string[] ?? [];
        if (labels.Length != values.Length)
            return null;
        for (var i = 0; i < labels.Length; i++)
            if (IsTargetLabel(id, labels[i]) && long.TryParse(values[i], NumberStyles.Integer, CultureInfo.InvariantCulture, out var v))
                return v;
        return null;
    }

    private static long ReadAdded(TweakId id, Guid scope)
    {
        if (TweakRules.PowerPlan(id))
            return ReadPower(id, scope);
        if (TweakRules.AdvancedProperty(id))
        {
            using var property = AdvancedPropertyObject(id, scope);
            return RegistryNumber(property);
        }
        throw new NotSupportedException();
    }

    private static bool PermitsAdded(TweakValue value)
    {
        if (TweakRules.PowerPlan(value.Id))
            return value.Adapter == ActiveScheme();   // only the plan in use, which is the one we read and show
        if (!TweakRules.AdvancedProperty(value.Id))
            return true;
        // Only values the driver itself lists for this property.
        using var property = AdvancedPropertyObject(value.Id, value.Adapter);
        var values = property["ValidRegistryValues"] as string[];
        return values is null or { Length: 0 }
            ? value.Value is 0 or 1 && !TweakRules.DriverMapped(value.Id)
            : values.Contains(value.Value!.Value.ToString(CultureInfo.InvariantCulture), StringComparer.Ordinal);
    }

    private static void WriteAdded(TweakValue value)
    {
        if (TweakRules.PowerPlan(value.Id))
        {
            WritePower(value.Id, value.Adapter, (uint)value.Value!.Value);
            return;
        }
        if (TweakRules.AdvancedProperty(value.Id))
        {
            // The driver restarts the adapter to apply this; the connection drops for a few seconds.
            using var property = AdvancedPropertyObject(value.Id, value.Adapter);
            PutAdvancedValue(property, value.Value!.Value);
            return;
        }
        throw new NotSupportedException();
    }

    // ---------- adapter advanced properties ----------

    /// <summary>
    /// Writes a driver setting exactly as Set-NetAdapterAdvancedProperty -RegistryValue does: a CIM ModifyInstance
    /// that sends only the changed RegistryValue. System.Management's Put sends the whole instance (also the writable
    /// RegistryKeyword, RegistryDataType and DisplayValue) and the NetAdapterCim provider rejected it as "Invalid
    /// parameter" every time (live on a 2.5 GbE Intel card, 2026-11-17: stale label, matching label, null label and a WMI
    /// partial put all failed). The value must be one the driver lists; the driver restarts the adapter to apply it.
    /// </summary>
    internal static void PutAdvancedValue(ManagementObject property, long value)
    {
        var text = value.ToString(CultureInfo.InvariantCulture);
        _ = MatchingLabel(property["ValidRegistryValues"] as string[], property["ValidDisplayValues"] as string[], text);
        var id = property["InstanceID"] as string ?? throw new NotSupportedException("The setting has no instance ID.");
        using var session = Microsoft.Management.Infrastructure.CimSession.Create(null);
        // Find the same instance by its key (InstanceID is "{adapter GUID}::keyword", read from Windows, never typed in).
        var all = session.QueryInstances(Tcp, "WQL", "SELECT * FROM MSFT_NetAdapterAdvancedPropertySettingData").ToList();
        try
        {
            var instance = all.SingleOrDefault(i =>
                    string.Equals(i.CimInstanceProperties["InstanceID"]?.Value as string, id, StringComparison.Ordinal))
                ?? throw new NotSupportedException("The driver setting disappeared.");
            instance.CimInstanceProperties["RegistryValue"].Value = new[] { text };   // marks only this property as changed
            using var updated = session.ModifyInstance(Tcp, instance);
        }
        finally
        {
            foreach (var item in all)
                item.Dispose();
        }
    }

    /// <summary>The label the driver lists for <paramref name="value"/>; the value itself for free-number settings.</summary>
    internal static string MatchingLabel(string[]? values, string[]? labels, string value)
    {
        if (values is not { Length: > 0 })
            return value;
        var index = Array.IndexOf(values, value);
        if (index < 0)
            throw new NotSupportedException("The driver doesn't offer this value.");
        return labels is { } names && names.Length == values.Length ? names[index]
            : throw new NotSupportedException("The driver's list of choices is incomplete.");
    }

    private static ManagementObject AdvancedPropertyObject(TweakId id, Guid adapter)
    {
        var info = AdapterDiscovery.Read().SingleOrDefault(a => a.Id == adapter)
                   ?? throw new NotSupportedException("The adapter is unavailable.");
        foreach (var keyword in Keywords(id))
        {
            // Keywords are fixed constants above, never caller input.
            using var searcher = new ManagementObjectSearcher(Tcp,
                $"SELECT * FROM MSFT_NetAdapterAdvancedPropertySettingData WHERE RegistryKeyword = '{keyword}'");
            var matches = searcher.Get().Cast<ManagementObject>()
                .Where(o => string.Equals(o["Name"] as string, info.Name, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(o["InterfaceDescription"] as string, info.Description, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (matches.Length == 1)
                return matches[0];
        }
        throw new NotSupportedException("The driver doesn't offer this setting.");
    }

    private static long RegistryNumber(ManagementObject property) =>
        property["RegistryValue"] is string[] { Length: 1 } values &&
        long.TryParse(values[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var v)
            ? v : throw new NotSupportedException("The setting has an unexpected value.");

    // ---------- power plan (plugged-in value of a named scheme) ----------

    /// <summary>The power plan in use. Boost reads and changes only this plan's plugged-in value.</summary>
    internal static Guid ActiveScheme()
    {
        if (PowerGetActiveScheme(IntPtr.Zero, out var pointer) != 0 || pointer == IntPtr.Zero)
            throw new NotSupportedException("Windows didn't report the power plan in use.");
        try { return Marshal.PtrToStructure<Guid>(pointer); }
        finally { LocalFree(pointer); }
    }

    private static (Guid Subgroup, Guid Setting) PowerSetting(TweakId id) => id switch
    {
        TweakId.WifiPowerSaving => (WirelessSubgroup, WirelessPowerSaving),
        TweakId.PcieLinkPower => (PcieSubgroup, PcieAspm),
        _ => throw new NotSupportedException(),
    };

    private static long ReadPower(TweakId id, Guid scheme)
    {
        var (subgroup, setting) = PowerSetting(id);
        var code = PowerReadACValueIndex(IntPtr.Zero, ref scheme, ref subgroup, ref setting, out var index);
        return code == 0 ? index : throw new NotSupportedException($"The power plan has no such setting ({code}).");
    }

    private static void WritePower(TweakId id, Guid scheme, uint index)
    {
        var (subgroup, setting) = PowerSetting(id);
        var code = PowerWriteACValueIndex(IntPtr.Zero, ref scheme, ref subgroup, ref setting, index);
        if (code != 0)
            throw new IOException($"Windows refused the power setting ({code}).");
        // Re-apply the plan so the new value takes effect now.
        if (PowerSetActiveScheme(IntPtr.Zero, ref scheme) != 0)
            throw new IOException("Windows didn't re-apply the power plan.");
    }

    [DllImport("powrprof.dll")]
    private static extern uint PowerGetActiveScheme(IntPtr userRootPowerKey, out IntPtr activePolicyGuid);

    [DllImport("powrprof.dll")]
    private static extern uint PowerReadACValueIndex(IntPtr rootPowerKey, ref Guid schemeGuid, ref Guid subGroupGuid,
        ref Guid powerSettingGuid, out uint acValueIndex);

    [DllImport("powrprof.dll")]
    private static extern uint PowerWriteACValueIndex(IntPtr rootPowerKey, ref Guid schemeGuid, ref Guid subGroupGuid,
        ref Guid powerSettingGuid, uint acValueIndex);

    [DllImport("powrprof.dll")]
    private static extern uint PowerSetActiveScheme(IntPtr userRootPowerKey, ref Guid schemeGuid);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
