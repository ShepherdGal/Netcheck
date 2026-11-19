using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Netcheck.Windows;

public sealed record DohProperty(uint ServerIndex, string? Template, ulong Flags);

public sealed record DnsFamilyConfiguration(ulong Flags, string? ConfiguredServers,
    string? ProfileServers, string? Domain, string? SearchList, string? SupplementalSearchList,
    IReadOnlyList<DohProperty> ServerProperties, IReadOnlyList<DohProperty> ProfileServerProperties,
    uint RegistrationEnabled, uint RegisterAdapterName, uint EnableLlmnr, uint QueryAdapterName,
    uint DisableUnconstrainedQueries = 0);

[SupportedOSPlatform("windows")]
public static partial class InterfaceDns
{
    private const ulong Ipv6Flag = 1;
    private const ulong NameServerFlag = 2;
    private const ulong DohFlag = 0x1000;

    public static DnsFamilyConfiguration Read(Guid adapterId, bool ipv6)
    {
        var settings = new NativeSettings { Version = 3, Flags = ipv6 ? Ipv6Flag : 0 };
        var error = GetInterfaceDnsSettings(adapterId, ref settings);
        if (error != 0)
        {
            throw new Win32Exception((int)error);
        }

        try
        {
            return new DnsFamilyConfiguration(settings.Flags, ReadString(settings.NameServer),
                ReadString(settings.ProfileNameServer), ReadString(settings.Domain),
                ReadString(settings.SearchList), ReadString(settings.SupplementalSearchList),
                ReadProperties(settings.ServerProperties, settings.ServerPropertyCount),
                ReadProperties(settings.ProfileServerProperties, settings.ProfileServerPropertyCount),
                settings.RegistrationEnabled, settings.RegisterAdapterName,
                settings.EnableLlmnr, settings.QueryAdapterName, settings.DisableUnconstrainedQueries);
        }
        finally
        {
            FreeInterfaceDnsSettings(ref settings);
        }
    }

    internal static unsafe void WriteSettings(Guid adapterId, bool ipv6, string servers,
        IReadOnlyList<DohProperty> properties, bool updateDoh)
    {
        var nativeProperties = stackalloc NativeServerProperty[properties.Count];
        var nativeDoh = stackalloc NativeDohSettings[properties.Count];
        var templates = new nint[properties.Count];
        try
        {
            for (var index = 0; index < properties.Count; index++)
            {
                var property = properties[index];
                templates[index] = Marshal.StringToCoTaskMemUni(property.Template);
                nativeDoh[index] = new NativeDohSettings { Template = templates[index], Flags = property.Flags };
                nativeProperties[index] = new NativeServerProperty
                {
                    Version = 1,
                    Type = 1,
                    ServerIndex = property.ServerIndex,
                    DohSettings = (nint)(nativeDoh + index)
                };
            }

            fixed (char* serverText = servers)
            {
                var settings = new NativeSettings
                {
                    Version = 3,
                    Flags = NameServerFlag | (ipv6 ? Ipv6Flag : 0) | (updateDoh ? DohFlag : 0),
                    NameServer = (nint)serverText,
                    ServerPropertyCount = (uint)properties.Count,
                    ServerProperties = properties.Count == 0 ? 0 : (nint)nativeProperties
                };
                var error = SetInterfaceDnsSettings(adapterId, in settings);
                if (error != 0)
                {
                    throw new Win32Exception((int)error);
                }
            }
        }
        finally
        {
            foreach (var template in templates)
            {
                Marshal.FreeCoTaskMem(template);
            }
        }
    }

    private static string? ReadString(nint pointer) => Marshal.PtrToStringUni(pointer);

    private static IReadOnlyList<DohProperty> ReadProperties(nint pointer, uint count)
    {
        if (pointer == 0 && count != 0)
        {
            throw new NotSupportedException("Windows returned DNS server properties without data.");
        }

        var properties = new DohProperty[count];
        for (var index = 0; index < properties.Length; index++)
        {
            var property = Marshal.PtrToStructure<NativeServerProperty>(
                pointer + index * Marshal.SizeOf<NativeServerProperty>());
            if (property.Version != 1 || property.Type != 1 || property.DohSettings == 0)
            {
                throw new NotSupportedException("Windows returned an unsupported DNS server property.");
            }

            var doh = Marshal.PtrToStructure<NativeDohSettings>(property.DohSettings);
            properties[index] = new DohProperty(property.ServerIndex, ReadString(doh.Template), doh.Flags);
        }

        return properties;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeSettings
    {
        public uint Version;
        public ulong Flags;
        public nint Domain;
        public nint NameServer;
        public nint SearchList;
        public uint RegistrationEnabled;
        public uint RegisterAdapterName;
        public uint EnableLlmnr;
        public uint QueryAdapterName;
        public nint ProfileNameServer;
        public uint DisableUnconstrainedQueries;
        public nint SupplementalSearchList;
        public uint ServerPropertyCount;
        public nint ServerProperties;
        public uint ProfileServerPropertyCount;
        public nint ProfileServerProperties;
    }

    // DNS_SERVER_PROPERTY (netioapi.h, SDK 10.0.26100): Version, ServerIndex, Type, Property. ServerIndex comes
    // before Type; swapping them (fixed 2026-11-16) made Windows store an invalid property, so DoH never applied.
    [StructLayout(LayoutKind.Sequential)]
    internal struct NativeServerProperty
    {
        public uint Version;
        public uint ServerIndex;
        public uint Type;
        public nint DohSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeDohSettings
    {
        public nint Template;
        public ulong Flags;
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetInterfaceDnsSettings(Guid adapterId, ref NativeSettings settings);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint SetInterfaceDnsSettings(Guid adapterId, in NativeSettings settings);

    [LibraryImport("iphlpapi.dll")]
    private static partial void FreeInterfaceDnsSettings(ref NativeSettings settings);
}
