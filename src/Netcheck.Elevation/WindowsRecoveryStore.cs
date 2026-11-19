using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

namespace Netcheck.Elevation;

[SupportedOSPlatform("windows")]
internal class WindowsRecoveryStore<TRecord>(string protectedDirectory, SecurityIdentifier brokerOwner,
    string journalName, Func<TRecord, bool> complete) where TRecord : class
{
    private const int MaxBytes = 128 * 1024;
    private readonly string _directory = Path.GetFullPath(protectedDirectory);
    private FileStream? _lease;

    private string Journal => Path.Combine(_directory, journalName);
    private string Pending => Journal + ".pending";
    private string Retired => Journal + ".retired";

    // The future broker must provision a fixed, trustworthy parent and supply its configured owner.
    // Never resolve either input from a client's request or from the journal itself.
    public IDisposable AcquireExclusive()
    {
        lock (this)
        {
            if (_lease is not null)
                throw new InvalidOperationException("The recovery store already has an active lease.");
            for (DirectoryInfo? path = new(_directory); path is not null; path = path.Parent)
                RejectReparse(path);
            VerifyAcl(new DirectoryInfo(_directory));
            var lockFile = new FileInfo(Path.Combine(_directory, Path.ChangeExtension(journalName, ".lock")));
            var existing = Exists(lockFile);
            if (existing)
                VerifyAcl(lockFile);
            var stream = existing ? lockFile.Open(FileMode.Open, FileAccess.ReadWrite, FileShare.None) : Create(lockFile);
            try
            {
                VerifyAcl(lockFile);
                _lease = stream;
                return new Lease(this);
            }
            catch { stream.Dispose(); throw; }
        }
    }

    public TRecord? Read()
    {
        RequireLease();
        var file = new FileInfo(Journal);
        if (!Exists(file))
            return null;
        VerifyAcl(file);
        using var stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > MaxBytes)
            throw new InvalidDataException("Invalid recovery journal size.");
        try
        {
            var envelope = JsonSerializer.Deserialize<Envelope>(stream);
            if (envelope is not { Version: 1, Digest.Length: 32, Payload.Length: > 0 } ||
                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(envelope.Payload), envelope.Digest))
                throw new InvalidDataException("recovery journal integrity check failed.");
            return JsonSerializer.Deserialize<TRecord>(envelope.Payload) is { } record && complete(record) ? record :
                throw new InvalidDataException("recovery journal is incomplete.");
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("recovery journal could not be decoded.", error);
        }
    }

    public void Persist(TRecord record)
    {
        RequireLease();
        if (Exists(new FileInfo(Journal)))
            throw new IOException("A recovery journal already exists.");
        RemoveStagingFile(Pending);
        RemoveStagingFile(Retired);
        var payload = JsonSerializer.SerializeToUtf8Bytes(record);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new Envelope(1, payload, SHA256.HashData(payload)));
        if (bytes.Length > MaxBytes)
            throw new InvalidDataException("recovery journal exceeds its size limit.");
        var file = new FileInfo(Pending);
        using (var stream = Create(file))
        {
            VerifyAcl(file);
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        MoveDurably(Pending, Journal);
    }

    public void Clear()
    {
        RequireLease();
        var file = new FileInfo(Journal);
        if (!Exists(file))
            return;
        VerifyAcl(file);
        RemoveStagingFile(Retired);
        // Rename is the commit point. Ignore retired files on recovery.
        MoveDurably(Journal, Retired);
    }

    private void RemoveStagingFile(string path)
    {
        var file = new FileInfo(path);
        if (Exists(file))
        {
            VerifyAcl(file);
            file.Delete();
        }
    }

    private FileStream Create(FileInfo file)
    {
        var security = new FileSecurity();
        security.SetOwner(brokerOwner);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { brokerOwner,
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) }.Distinct())
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        return file.Create(FileMode.CreateNew, FileSystemRights.ReadData | FileSystemRights.WriteData |
            FileSystemRights.ReadAttributes | FileSystemRights.ReadPermissions | FileSystemRights.Synchronize,
            FileShare.None, 4096, FileOptions.None, security);
    }

    private void VerifyAcl(FileSystemInfo file)
    {
        RejectReparse(file);
        const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
        FileSystemSecurity security = file is DirectoryInfo directory
            ? directory.GetAccessControl(sections) : ((FileInfo)file).GetAccessControl(sections);
        var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        if (descriptor.Owner is not { } owner || !Trusted(owner) || descriptor.DiscretionaryAcl is not { } acl ||
            (file is DirectoryInfo && !security.AreAccessRulesProtected))
            throw new UnauthorizedAccessException("recovery storage requires an explicit, protected ACL and trusted owner.");
        foreach (GenericAce entry in acl)
        {
            if (entry is not CommonAce ace ||
                ace.AceQualifier == AceQualifier.AccessAllowed && !Trusted(ace.SecurityIdentifier))
                throw new UnauthorizedAccessException("The recovery ACL grants access outside the broker identities.");
        }
    }

    private bool Trusted(SecurityIdentifier sid) => sid.Equals(brokerOwner) ||
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);

    private static bool Exists(FileInfo file)
    {
        // Read attributes so access denial cannot masquerade as an absent journal.
        try
        {
            var attributes = File.GetAttributes(file.FullName);
            if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
                throw new IOException("recovery path is not a regular file.");
            return true;
        }
        catch (FileNotFoundException) { return false; }
    }

    private static void RejectReparse(FileSystemInfo file)
    {
        if ((File.GetAttributes(file.FullName) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("recovery storage cannot use a reparse point.");
    }

    private static void MoveDurably(string source, string destination)
    {
        const uint writeThrough = 8;
        if (!RecoveryNative.MoveFileEx(source, destination, writeThrough))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not move the recovery journal.");
    }

    private void RequireLease()
    {
        if (_lease is null)
            throw new InvalidOperationException("recovery storage must be opened exclusively.");
    }


    private sealed record Envelope(int Version, byte[] Payload, byte[] Digest);

    private sealed class Lease(WindowsRecoveryStore<TRecord> store) : IDisposable
    {
        private bool _released;
        public void Dispose()
        {
            lock (store)
            {
                if (_released)
                    return;
                store._lease!.Dispose();
                store._lease = null;
                _released = true;
            }
        }
    }
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsDnsRecoveryStore(string protectedDirectory, SecurityIdentifier brokerOwner)
    : WindowsRecoveryStore<DnsRecoveryRecord>(protectedDirectory, brokerOwner, JournalName,
        record => record is { Proposed: not null, Before.Target: not null }), IDnsRecoveryStore
{
    internal const string JournalName = "dns-recovery.json";
}

internal static class RecoveryNative
{
    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool MoveFileEx(string source, string destination, uint flags);
}
