using System.Management;
using System.Runtime.InteropServices;

namespace Netcheck.Windows;

public sealed record TcpTemplate(string Name, string AutoTuning, string Source);
public sealed record TuningSnapshot(int WindowsBuild, string? AdapterName, DriverDetails? Driver,
    bool? RssEnabled, string? PowerSetting, bool? MdmRegistered, DnsPolicyIndicators DnsPolicy,
    IReadOnlyList<TcpTemplate> TcpTemplates);

public static partial class ConnectionDiscovery
{
    public static TuningSnapshot ReadTuning(Guid? observedAdapter)
    {
        var adapter = observedAdapter is { } id ? AdapterDiscovery.Read().SingleOrDefault(item => item.Id == id) : null;
        var driver = adapter is null ? null : ReadDrivers().GetValueOrDefault(adapter.Id);
        var templates = new List<TcpTemplate>();
        ReadCim("""
            SELECT SettingName, AutoTuningLevelEffective, AutoTuningLevelLocal, AutoTuningLevelGroupPolicy
            FROM MSFT_NetTCPSetting
            """, row =>
        {
            if (row["SettingName"] is not string name)
                return;
            var source = row["AutoTuningLevelEffective"] as byte?;
            var level = source switch
            {
                0 => row["AutoTuningLevelLocal"] as byte?,
                1 => row["AutoTuningLevelGroupPolicy"] as byte?,
                _ => null
            };
            templates.Add(new TcpTemplate(name, level switch
            {
                0 => "Disabled", 1 => "Highly restricted", 2 => "Restricted",
                3 => "Normal", 4 => "Experimental", _ => "Unavailable"
            }, source switch { 0 => "Local", 1 => "Group Policy", _ => "Unavailable" }));
        });

        var rss = ReadAdapterSetting("SELECT Name, InterfaceDescription, Enabled FROM MSFT_NetAdapterRssSettingData",
            "Enabled") as bool?;
        var power = ReadAdapterSetting("""
            SELECT Name, InterfaceDescription, AllowComputerToTurnOffDevice
            FROM MSFT_NetAdapterPowerManagementSettingData
            """, "AllowComputerToTurnOffDevice") as uint?;
        return new TuningSnapshot(Environment.OSVersion.Version.Build, adapter?.Name, driver, rss,
            power switch { 0 => "Unsupported", 1 => "Disabled", 2 => "Enabled", _ => null },
            ReadMdm(), ReadDnsPolicy(), templates.OrderBy(item => item.Name, StringComparer.Ordinal).ToArray());

        object? ReadAdapterSetting(string query, string property)
        {
            if (adapter is null)
                return null;
            object? value = null;
            var matches = 0;
            ReadCim(query, row =>
            {
                if (string.Equals(row["Name"] as string, adapter.Name, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(row["InterfaceDescription"] as string, adapter.Description, StringComparison.OrdinalIgnoreCase))
                {
                    matches++;
                    value = row[property];
                }
            });
            // Reject ambiguous matches and results for an adapter that changed during discovery.
            return matches == 1 && AdapterDiscovery.Read().Contains(adapter) ? value : null;
        }
    }

    internal static bool? ReadMdm()
    {
        try { return IsDeviceRegisteredWithManagement(out var registered, 0, nint.Zero) == 0 ? registered != 0 : null; }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException) { return null; }
    }

    [DllImport("MDMRegistration.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int IsDeviceRegisteredWithManagement(out int registered, uint upnLength, nint upn);
}
