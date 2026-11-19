using System.Globalization;
using System.Management;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Netcheck.Windows;

namespace Netcheck.Elevation;

/// <summary>
/// Maps each <see cref="TweakId"/> to one fixed registry value or CIM property. Reading works without
/// elevation (used by the Boost page to detect); writing happens only inside the elevated broker.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed partial class WindowsTweakPlatform : ITweakPlatform
{
    private const string DeliveryPolicy = @"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";
    private const string Multimedia = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile";
    private const string Tcp = "root/StandardCimv2";

    public TweakValue Read(TweakId id, Guid adapter) => new(id, TweakRules.AdapterScoped(id) ? adapter : Guid.Empty, id switch
    {
        // A driver/OEM "PnPCapabilities" lock (0x18) means Windows never powers the card off, whatever the
        // WMI flag says; writing the flag then fails with "Not supported". Treat it as already kept awake.
        TweakId.NicPowerSaving => PowerLocked(adapter) ? 0 : PowerObject(adapter)["Enable"] is true ? 1 : 0,
        TweakId.BackgroundUpdates => ReadDword(DeliveryPolicy, "DOPercentageMaxBackgroundBandwidth"),
        TweakId.Ecn => Convert.ToInt64(TcpInternet()["EcnCapability"] ?? throw new NotSupportedException("ECN is not reported."), CultureInfo.InvariantCulture),
        TweakId.MediaThrottling => ReadDword(Multimedia, "NetworkThrottlingIndex"),
        TweakId.AutoTuning => Convert.ToInt64(TcpInternet()["AutoTuningLevelLocal"] ?? throw new NotSupportedException("Auto-tuning is not reported."), CultureInfo.InvariantCulture),
        TweakId.EnergyEfficientEthernet => EeeValue(EeeObject(adapter)),
        TweakId.UpdateSharing => ReadDword(DeliveryPolicy, "DODownloadMode"),
        _ => ReadAdded(id, adapter),
    });

    public bool Permits(TweakValue value)
    {
        if (!TweakRules.Valid(value) || !WindowsDnsTransactionPlatform.IsUnmanaged() || ConnectionDiscovery.ReadMdm() != false)
            return false;
        if (TweakRules.AdapterScoped(value.Id) && !TweakRules.PowerPlan(value.Id) &&
            ConnectionDiscovery.ReadDrivers().GetValueOrDefault(value.Adapter) is not { Virtual: false, AdminLocked: false })
            return false;
        if (!PermitsAdded(value))
            return false;
        // TCP template values set by Group Policy are not ours to change.
        if (value.Id is TweakId.AutoTuning or TweakId.Ecn && TcpInternet()["AutoTuningLevelEffective"] is byte source && source != 0)
            return false;
        return true;
    }

    public void Write(TweakValue value)
    {
        if (!TweakRules.Valid(value))
            throw new ArgumentException("Tweak value is outside its allowlist.");
        switch (value.Id)
        {
            case TweakId.NicPowerSaving:
                using (var power = PowerObject(value.Adapter))
                {
                    power["Enable"] = value.Value == 1;
                    power.Put();
                }
                break;
            case TweakId.BackgroundUpdates:
                WriteDword(DeliveryPolicy, "DOPercentageMaxBackgroundBandwidth", value.Value);
                break;
            case TweakId.UpdateSharing:
                WriteDword(DeliveryPolicy, "DODownloadMode", value.Value);
                break;
            case TweakId.MediaThrottling:
                WriteDword(Multimedia, "NetworkThrottlingIndex", value.Value);
                break;
            case TweakId.Ecn or TweakId.AutoTuning:
                using (var tcp = TcpInternet())
                {
                    tcp[value.Id == TweakId.Ecn ? "EcnCapability" : "AutoTuningLevelLocal"] = (byte)value.Value!.Value;
                    tcp.Put(new PutOptions { Type = PutType.UpdateOnly });
                }
                break;
            case TweakId.EnergyEfficientEthernet:
                using (var eee = EeeObject(value.Adapter))
                {
                    PutAdvancedValue(eee, value.Value!.Value);
                }
                break;
            default:
                WriteAdded(value);
                break;
        }
    }

    // ---------- registry (64-bit view, DWORD only) ----------

    private static long? ReadDword(string path, string name)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(path);
        return key?.GetValue(name) switch
        {
            null => null,
            int dword when key.GetValueKind(name) == RegistryValueKind.DWord => unchecked((uint)dword),
            _ => throw new NotSupportedException($"{name} is not a DWORD."),
        };
    }

    private static void WriteDword(string path, string name, long? value)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        if (value is null)
        {
            using var existing = root.OpenSubKey(path, writable: true);
            existing?.DeleteValue(name, throwOnMissingValue: false);
            return;
        }
        using var key = root.CreateSubKey(path, writable: true);
        key.SetValue(name, unchecked((int)(uint)value.Value), RegistryValueKind.DWord);
    }

    // ---------- CIM ----------

    private static ManagementObject TcpInternet() =>
        Single(Tcp, "SELECT * FROM MSFT_NetTCPSetting WHERE SettingName = 'Internet'", "the Internet TCP template");

    /// <summary>The "allow the computer to turn off this device" object of the adapter's PnP device.</summary>
    private static ManagementObject PowerObject(Guid adapter)
    {
        using var nic = Single("root/cimv2",
            $"SELECT PNPDeviceID FROM Win32_NetworkAdapter WHERE GUID = '{adapter.ToString("B").ToUpperInvariant()}'", "the network adapter");
        var device = nic["PNPDeviceID"] as string ?? throw new NotSupportedException("The adapter has no device id.");
        using var searcher = new ManagementObjectSearcher("root/wmi", "SELECT * FROM MSPower_DeviceEnable");
        var matches = searcher.Get().Cast<ManagementObject>()
            .Where(o => o["InstanceName"] is string name && name.StartsWith(device + "_", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        return matches.Length == 1 ? matches[0] : throw new NotSupportedException("The adapter's power setting is not available.");
    }

    /// <summary>True when the adapter's driver key sets PnPCapabilities bits 0x18 ("don't allow power-off").</summary>
    private static bool PowerLocked(Guid adapter)
    {
        using var nic = Single("root/cimv2",
            $"SELECT PNPDeviceID FROM Win32_NetworkAdapter WHERE GUID = '{adapter.ToString("B").ToUpperInvariant()}'", "the network adapter");
        if (nic["PNPDeviceID"] is not string device || device.Contains("..", StringComparison.Ordinal))
            return false;
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var enumKey = root.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + device);
        if (enumKey?.GetValue("Driver") is not string driver || driver.Contains("..", StringComparison.Ordinal))
            return false;
        using var classKey = root.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\" + driver);
        return classKey?.GetValue("PnPCapabilities") is int caps && (caps & 0x18) == 0x18;
    }

    private static ManagementObject EeeObject(Guid adapter)
    {
        var info = AdapterDiscovery.Read().SingleOrDefault(a => a.Id == adapter)
                   ?? throw new NotSupportedException("The adapter is unavailable.");
        using var searcher = new ManagementObjectSearcher(Tcp,
            "SELECT * FROM MSFT_NetAdapterAdvancedPropertySettingData WHERE RegistryKeyword = '*EEE'");
        var matches = searcher.Get().Cast<ManagementObject>()
            .Where(o => string.Equals(o["Name"] as string, info.Name, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(o["InterfaceDescription"] as string, info.Description, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        return matches.Length == 1 ? matches[0] : throw new NotSupportedException("The driver has no Energy-Efficient Ethernet setting.");
    }

    private static long EeeValue(ManagementObject eee) =>
        eee["RegistryValue"] is string[] { Length: 1 } values && values[0] is var text && long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v)
            ? v : throw new NotSupportedException("Energy-Efficient Ethernet has an unexpected value.");

    private static ManagementObject Single(string scope, string query, string what)
    {
        using var searcher = new ManagementObjectSearcher(scope, query);
        var items = searcher.Get().Cast<ManagementObject>().ToArray();
        return items.Length == 1 ? items[0] : throw new NotSupportedException($"Windows did not report {what}.");
    }
}

/// <summary>System Restore point before a Boost change. Windows may skip it (frequency limit) or have it off.</summary>
[SupportedOSPlatform("windows")]
internal static class RestorePoints
{
    public static RestorePointResult Create(string description)
    {
        try
        {
            var before = Count();
            using var restore = new ManagementClass("root/default", "SystemRestore", null);
            var result = restore.InvokeMethod("CreateRestorePoint", [description, 12u /* MODIFY_SETTINGS */, 100u /* BEGIN_SYSTEM_CHANGE */]);
            var code = Convert.ToUInt32(result, CultureInfo.InvariantCulture);
            if (code == 1058) // ERROR_SERVICE_DISABLED: System Protection is off
                return RestorePointResult.Off;
            if (code != 0)
                return RestorePointResult.Failed;
            return Count() > before ? RestorePointResult.Made : RestorePointResult.Skipped;
        }
        catch (Exception error) when (error is ManagementException or UnauthorizedAccessException or InvalidCastException)
        {
            return RestorePointResult.Failed;
        }
    }

    private static int Count()
    {
        using var searcher = new ManagementObjectSearcher("root/default", "SELECT SequenceNumber FROM SystemRestore");
        return searcher.Get().Count;
    }
}
