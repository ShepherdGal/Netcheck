using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace Netcheck.Elevation;

[SupportedOSPlatform("windows")]
internal static class DnsBrokerPipe
{
    private const int MaxMessageBytes = 96 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        MaxDepth = 12,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal static NamedPipeServerStream Listen(string name)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(identity.User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 4096, 4096, security);
    }

    internal static NamedPipeClientStream ConnectToLocal(string name) => new(".", name,
        PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);

    internal static bool IsPeer(PipeStream pipe, Process expected, bool server)
    {
        uint pid;
        var identified = server
            ? GetNamedPipeServerProcessId(pipe.SafePipeHandle, out pid)
            : GetNamedPipeClientProcessId(pipe.SafePipeHandle, out pid);
        // Hold the process handle to pin its identity for the entire exchange.
        return identified && pid == (uint)expected.Id && !expected.HasExited;
    }

    internal static async Task SendAsync<T>(Stream pipe, T message, CancellationToken token)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions);
        if (body.Length is < 1 or > MaxMessageBytes)
            throw new InvalidDataException("DNS broker message exceeds its size limit.");
        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, body.Length);
        await pipe.WriteAsync(header, token).ConfigureAwait(false);
        await pipe.WriteAsync(body, token).ConfigureAwait(false);
    }

    internal static async Task<T> ReceiveAsync<T>(Stream pipe, CancellationToken token)
    {
        var header = new byte[sizeof(int)];
        await pipe.ReadExactlyAsync(header, token).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is < 1 or > MaxMessageBytes)
            throw new InvalidDataException("Invalid DNS broker message size.");
        var body = new byte[length];
        await pipe.ReadExactlyAsync(body, token).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(body, JsonOptions) ??
            throw new InvalidDataException("Invalid DNS broker message.");
    }

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);
}
