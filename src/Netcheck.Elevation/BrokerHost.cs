using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace Netcheck.Elevation;

/// <summary>
/// Shared plumbing for the elevated brokers (DNS, Boost): the protected-install trust check, the
/// elevated relaunch with a nonce-named pipe, the peer identity checks on both ends and the protected
/// recovery directory. Each broker only supplies its typed request/reply exchange.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class BrokerHost
{
    internal const string RecoveryDirectoryName = "Netcheck Recovery";
    internal static readonly TimeSpan ExchangeTimeout = TimeSpan.FromMinutes(2);
    private static readonly Lazy<bool> ProtectedInstall = new(CheckInstallation);

    internal static bool IsEnabled => ProtectedInstall.Value;

    /// <summary>Client side: start the elevated broker, authenticate it, then run the typed exchange.</summary>
    internal static async Task<T?> ExchangeAsync<T>(string switchName, string pipePrefix,
        Func<Stream, CancellationToken, Task<T>> talk, CancellationToken token) where T : struct
    {
        if (!IsEnabled || token.IsCancellationRequested)
            return null;
        var nonce = Guid.NewGuid().ToString("N");
        using var pipe = DnsBrokerPipe.Listen($"{pipePrefix}.{nonce}");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(ExchangeTimeout);
        using var process = await Task.Run(() => Process.Start(new ProcessStartInfo
        {
            FileName = Environment.ProcessPath ?? throw new InvalidOperationException("Netcheck executable is unavailable."),
            WorkingDirectory = AppContext.BaseDirectory,
            Arguments = FormattableString.Invariant($"{switchName} {nonce} {Environment.ProcessId}"),
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden
        }), CancellationToken.None).ConfigureAwait(false);
        if (process is null)
            return null;
        _ = process.SafeHandle;

        await pipe.WaitForConnectionAsync(deadline.Token).ConfigureAwait(false);
        if (!DnsBrokerPipe.IsPeer(pipe, process, server: false))
            return null;
        return await talk(pipe, deadline.Token).ConfigureAwait(false);
    }

    /// <summary>Broker side: verify elevation, the caller's identity and the pipe peer, then serve one exchange.</summary>
    internal static async Task<int> ServeAsync(string[] args, string switchName, string pipePrefix,
        Func<Stream, CancellationToken, Task> serve)
    {
        if (!IsEnabled || args is not [var name, var nonce, var parent] || name != switchName ||
            !Guid.TryParseExact(nonce, "N", out _) || !int.TryParse(parent, out var pid) || pid <= 0)
            return 1;

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                return 1;
            using var caller = Process.GetProcessById(pid);
            _ = caller.SafeHandle;
            using var broker = Process.GetCurrentProcess();
            if (caller.SessionId != broker.SessionId ||
                !string.Equals(caller.MainModule?.FileName, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
                return 1;
            using var deadline = new CancellationTokenSource(ExchangeTimeout);
            using var pipe = DnsBrokerPipe.ConnectToLocal($"{pipePrefix}.{nonce}");
            await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);
            if (!DnsBrokerPipe.IsPeer(pipe, caller, server: true))
                return 1;

            await serve(pipe, deadline.Token).ConfigureAwait(false);
            return 0;
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException or
            Win32Exception or ArgumentException or InvalidOperationException or NotSupportedException or
            OperationCanceledException or System.Net.NetworkInformation.NetworkInformationException or
            System.Management.ManagementException)
        {
            return 1;
        }
    }

    /// <summary>The broker-owned recovery directory under Program Files, created with its final ACL in one call.</summary>
    internal static DirectoryInfo OpenRecoveryDirectory(out SecurityIdentifier owner)
    {
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var acl = new DirectorySecurity();
        acl.SetOwner(administrators);
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { administrators, system })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));

        var root = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrEmpty(root) || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("The Windows recovery storage parent is unavailable.");
        var directory = new DirectoryInfo(Path.Combine(root, RecoveryDirectoryName));
        directory.Create(acl);
        if ((File.GetAttributes(directory.FullName) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("The Windows recovery storage cannot be a reparse point.");
        // Clicking "Continue" on this folder in File Explorer silently adds the signed-in user with Full control
        // (seen 2026-11-16), and the recovery store then rightly refuses the folder, so every DNS/Boost change failed.
        // The broker is elevated and Administrators own the folder: put the exact protected ACL back before use.
        // This restores the protection; every journal and lock file inside is still checked on its own (owner,
        // protected ACL, digest), so nothing a user could have placed there is trusted.
        if (!HasExactAcl(directory, administrators, system))
            directory.SetAccessControl(acl);
        owner = administrators;
        return directory;
    }

    /// <summary>Owner Administrators, inheritance off, and only Administrators/SYSTEM allowed (no deny or other entries).</summary>
    private static bool HasExactAcl(DirectoryInfo directory, SecurityIdentifier administrators, SecurityIdentifier system)
    {
        var security = directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        if (!security.AreAccessRulesProtected || security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
            !owner.Equals(administrators))
            return false;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow || rule.IdentityReference is not SecurityIdentifier sid ||
                !(sid.Equals(administrators) || sid.Equals(system)))
                return false;
        }
        return true;
    }

    /// <summary>True when the journal is known to be absent; any doubt means "maybe a recovery is pending".</summary>
    internal static bool JournalAbsent(string journalName)
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrEmpty(root))
            return false;
        try
        {
            File.GetAttributes(Path.Combine(root, RecoveryDirectoryName, journalName));
            return false;
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
        {
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static bool CheckInstallation()
    {
        try
        {
            if (Assembly.GetEntryAssembly()?.GetCustomAttributes<AssemblyMetadataAttribute>()
                .Any(metadata => metadata.Key == "Netcheck.ProtectedDeployment" && metadata.Value == "Windows") != true)
                return false;
            var root = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (string.IsNullOrEmpty(root))
                return false;
            var install = new DirectoryInfo(Path.Combine(root, "Netcheck"));
            if (!string.Equals(Environment.ProcessPath, Path.Combine(install.FullName, "Netcheck.exe"),
                    StringComparison.OrdinalIgnoreCase))
                return false;

            for (var directory = install; directory is not null; directory = directory.Parent)
            {
                if (!ProtectedPath(directory))
                    return false;
                // Windows controls the Program Files location. Check the installation and Program Files
                // ACLs for writable code and path components.
                if (string.Equals(directory.FullName, root, StringComparison.OrdinalIgnoreCase))
                    break;
            }
            return ProtectedContents(install);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            Win32Exception or System.Security.SecurityException)
        {
            return false;
        }
    }

    internal static bool ProtectedContents(DirectoryInfo directory)
    {
        foreach (var entry in directory.EnumerateFileSystemInfos())
        {
            if (!ProtectedPath(entry) || entry is DirectoryInfo child && !ProtectedContents(child))
                return false;
        }
        return true;
    }

    internal static bool ProtectedPath(FileSystemInfo entry)
    {
        if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            return false;
        const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
        FileSystemSecurity security = entry is DirectoryInfo directory
            ? directory.GetAccessControl(sections) : ((FileInfo)entry).GetAccessControl(sections);
        var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        if (descriptor.Owner is not { } owner || !Trusted(owner) || descriptor.DiscretionaryAcl is not { } acl)
            return false;

        const int mutation = (int)(FileSystemRights.WriteData | FileSystemRights.AppendData |
            FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes | FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership) |
            0x50000000; // GENERIC_WRITE and GENERIC_ALL
        foreach (var entryAce in acl)
        {
            if ((entryAce.AceFlags & AceFlags.InheritOnly) != 0)
                continue;
            if (entryAce is not CommonAce ace ||
                ace.AceQualifier == AceQualifier.AccessAllowed && (ace.AccessMask & mutation) != 0 && !Trusted(ace.SecurityIdentifier))
                return false;
        }
        return true;
    }

    private static bool Trusted(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
        sid.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; // TrustedInstaller
}
