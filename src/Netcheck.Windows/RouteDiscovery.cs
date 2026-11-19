using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Netcheck.Windows;

public enum RouteReadState { Found, NoRoute, Unavailable }

public sealed record RouteLookup(IPAddress Destination, RouteReadState State, Guid? AdapterId = null,
    IPAddress? Source = null, IPAddress? NextHop = null, IPAddress? Prefix = null, byte? PrefixLength = null,
    uint? RouteMetric = null, uint? WindowsError = null);

[SupportedOSPlatform("windows")]
public static partial class RouteDiscovery
{
    public static RouteLookup Read(IPAddress destination)
    {
        if (destination.IsIPv4MappedToIPv6)
            destination = destination.MapToIPv4();
        if (destination.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            throw new ArgumentException("Use an IPv4 or IPv6 destination.", nameof(destination));

        var address = SocketAddress.From(destination);
        var error = GetBestInterfaceEx(in address, out var index);
        if (error != 0)
            return Failed(destination, error);

        error = GetBestRoute2(0, index, 0, in address, 0, out var route, out var source);
        if (error != 0)
            return Failed(destination, error);

        // Resolve the LUID immediately. An interface index is not a durable adapter identity.
        Guid? adapter = ConvertInterfaceLuidToGuid(in route.InterfaceLuid, out var id) == 0 ? id : null;
        return new RouteLookup(destination, RouteReadState.Found, adapter, source.ToAddress(), route.NextHop.ToAddress(),
            route.Prefix.ToAddress(), route.PrefixLength, route.Metric);
    }

    internal static RouteLookup Failed(IPAddress destination, uint error) => new(destination,
        error is 1168 or 1228 or 1231 or 1232 or 10051 or 10065 ? RouteReadState.NoRoute : RouteReadState.Unavailable,
        WindowsError: error);

    [StructLayout(LayoutKind.Explicit, Size = 28)]
    private unsafe struct SocketAddress
    {
        [FieldOffset(0)] private ushort _family;
        [FieldOffset(4)] private fixed byte _ipv4[4];
        [FieldOffset(8)] private fixed byte _ipv6[16];
        [FieldOffset(24)] private uint _scope;

        internal static SocketAddress From(IPAddress address)
        {
            var value = new SocketAddress { _family = (ushort)address.AddressFamily };
            if (address.AddressFamily == AddressFamily.InterNetwork)
                address.TryWriteBytes(new Span<byte>(value._ipv4, 4), out _);
            else
            {
                address.TryWriteBytes(new Span<byte>(value._ipv6, 16), out _);
                value._scope = (uint)address.ScopeId;
            }
            return value;
        }

        internal IPAddress? ToAddress()
        {
            fixed (byte* ipv4 = _ipv4, ipv6 = _ipv6)
            {
                return (AddressFamily)_family switch
                {
                    AddressFamily.InterNetwork => new IPAddress(new ReadOnlySpan<byte>(ipv4, 4)),
                    AddressFamily.InterNetworkV6 => new IPAddress(new ReadOnlySpan<byte>(ipv6, 16), _scope),
                    _ => null
                };
            }
        }
    }

    // MIB_IPFORWARD_ROW2 from netioapi.h. Unused fields still occupy their native space.
    [StructLayout(LayoutKind.Explicit, Size = 104)]
    private struct ForwardRow
    {
        [FieldOffset(0)] internal ulong InterfaceLuid;
        [FieldOffset(12)] internal SocketAddress Prefix;
        [FieldOffset(40)] internal byte PrefixLength;
        [FieldOffset(44)] internal SocketAddress NextHop;
        [FieldOffset(84)] internal uint Metric;
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetBestInterfaceEx(in SocketAddress destination, out uint interfaceIndex);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetBestRoute2(nint interfaceLuid, uint interfaceIndex, nint source,
        in SocketAddress destination, uint sortOptions, out ForwardRow route, out SocketAddress bestSource);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint ConvertInterfaceLuidToGuid(in ulong interfaceLuid, out Guid interfaceGuid);
}
