using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace Netcheck.Windows;

public enum WifiReadState { Connected, Disconnected, PermissionNeeded, Unavailable }

public sealed record WifiDetails(WifiReadState State, string? NetworkName = null, uint? SignalPercent = null,
    string? Standard = null, uint? Channel = null, uint? ReceiveKilobits = null, uint? TransmitKilobits = null,
    uint? WindowsError = null);

[SupportedOSPlatform("windows")]
public static partial class WifiDiscovery
{
    private const int CurrentConnection = 7;
    private const int ChannelNumber = 8;
    private const int AssociationOffset = 520;
    private const uint AssociationEnd = AssociationOffset + 68;

    // The UI calls this only on request because Windows can prompt for location consent.
    public static WifiDetails Read(Guid adapter)
    {
        var error = WlanOpenHandle(2, 0, out _, out var client);
        if (error != 0)
            return Failed(error);
        try
        {
            error = WlanQueryInterface(client, in adapter, CurrentConnection, 0, out var size, out var data, 0);
            if (error != 0)
                return Failed(error);
            try
            {
                if (size < AssociationEnd || data == 0)
                    return new WifiDetails(WifiReadState.Unavailable);
                if (Marshal.ReadInt32(data) != 1)
                    return new WifiDetails(WifiReadState.Disconnected);

                var association = data + AssociationOffset;
                var length = Marshal.ReadInt32(association);
                string? name = null;
                if (length is > 0 and <= 32)
                {
                    var bytes = new byte[length];
                    Marshal.Copy(association + 4, bytes, 0, bytes.Length);
                    name = Encoding.UTF8.GetString(bytes);
                    name = new string(name.Select(character => char.IsControl(character) ? '\uFFFD' : character).ToArray());
                }
                return new WifiDetails(WifiReadState.Connected, name,
                    (uint)Math.Clamp(Marshal.ReadInt32(association, 56), 0, 100),
                    PhyName(Marshal.ReadInt32(association, 48)), ReadChannel(client, adapter),
                    (uint)Marshal.ReadInt32(association, 60), (uint)Marshal.ReadInt32(association, 64));
            }
            finally
            {
                WlanFreeMemory(data);
            }
        }
        finally
        {
            WlanCloseHandle(client, 0);
        }
    }

    private static uint? ReadChannel(nint client, Guid adapter)
    {
        var error = WlanQueryInterface(client, in adapter, ChannelNumber, 0, out var size, out var data, 0);
        if (error != 0)
            return null;
        try { return size >= sizeof(uint) && data != 0 && Marshal.ReadInt32(data) > 0 ? (uint)Marshal.ReadInt32(data) : null; }
        finally { WlanFreeMemory(data); }
    }

    private static string? PhyName(int phy) => phy switch
    {
        4 => "802.11a", 5 => "802.11b", 6 => "802.11g", 7 => "Wi-Fi 4 (802.11n)",
        8 => "Wi-Fi 5 (802.11ac)", 9 => "802.11ad", 10 => "Wi-Fi 6 (802.11ax)", 11 => "Wi-Fi 7 (802.11be)",
        _ => null
    };

    internal static WifiDetails Failed(uint error) => new(error switch
    {
        5 or 1260 => WifiReadState.PermissionNeeded,
        5023 => WifiReadState.Disconnected,
        _ => WifiReadState.Unavailable
    }, WindowsError: error);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanOpenHandle(uint clientVersion, nint reserved, out uint version, out nint client);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanCloseHandle(nint client, nint reserved);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanQueryInterface(nint client, in Guid adapter, int opcode, nint reserved,
        out uint size, out nint data, nint valueType);

    [LibraryImport("wlanapi.dll")]
    private static partial void WlanFreeMemory(nint memory);
}
