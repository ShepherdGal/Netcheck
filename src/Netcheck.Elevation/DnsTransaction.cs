namespace Netcheck.Elevation;

public sealed record DnsSnapshot(DnsChange Target, DnsChange? OtherFamily, string? NativeEvidence = null);
public sealed record ReviewedDnsChange(DnsSnapshot Before, DnsChange Proposed);
public sealed record DnsRecoveryRecord(DnsSnapshot Before, DnsChange Proposed);

public enum DnsTransactionOutcome
{
    Committed, NoChange, Rejected, Restored, RecoveryRequired, Conflict
}

// The platform must reject baselines it cannot represent and restore losslessly.
public interface IDnsTransactionPlatform
{
    DnsSnapshot Read(Guid adapterId, DnsTargetFamily family);
    bool Permits(DnsChange change);
    void Write(DnsChange change);
}

// A broker implementation must hold an exclusive, cross-process lease and
// verify the provenance and integrity of any record before handing it back.
public interface IDnsRecoveryStore
{
    IDisposable AcquireExclusive();
    DnsRecoveryRecord? Read();
    void Persist(DnsRecoveryRecord record);
    void Clear();
}

public sealed class DnsTransaction(IDnsTransactionPlatform platform, IDnsRecoveryStore recovery)
{
    public DnsTransactionOutcome Apply(ReviewedDnsChange review, Func<CancellationToken, bool> verify,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(verify);
        var record = new DnsRecoveryRecord(Copy(review.Before), Copy(review.Proposed));
        if (!Valid(record))
            return DnsTransactionOutcome.Rejected;

        using var lease = recovery.AcquireExclusive();
        try
        {
            if (recovery.Read() is not null)
                return DnsTransactionOutcome.RecoveryRequired;
        }
        catch (InvalidDataException) { return DnsTransactionOutcome.RecoveryRequired; }
        if (token.IsCancellationRequested || !platform.Permits(record.Proposed) || !BaselineMatches(record))
            return DnsTransactionOutcome.Rejected;
        if (Same(record.Before.Target, record.Proposed))
            return DnsTransactionOutcome.NoChange;
        if (!platform.Permits(record.Before.Target))
            return DnsTransactionOutcome.Rejected;

        // Persist and flush before crossing the write boundary.
        recovery.Persist(record);
        try
        {
            if (token.IsCancellationRequested || !platform.Permits(record.Proposed) ||
                !platform.Permits(record.Before.Target) ||
                !BaselineMatches(record))
                return Clear(DnsTransactionOutcome.Rejected);

            platform.Write(record.Proposed);
            if (!token.IsCancellationRequested &&
                Matches(Read(record), record.Proposed, record.Before) &&
                verify(token) && !token.IsCancellationRequested &&
                Matches(Read(record), record.Proposed, record.Before))
                return Clear(DnsTransactionOutcome.Committed);
        }
        catch (Exception)
        {
            // The platform can fail after changing state. Always classify read-back before restoring.
        }
        return Restore(record);
    }

    public DnsTransactionOutcome Recover()
    {
        using var lease = recovery.AcquireExclusive();
        DnsRecoveryRecord? record;
        try { record = recovery.Read(); }
        catch (InvalidDataException) { return DnsTransactionOutcome.RecoveryRequired; }
        if (record is null)
            return DnsTransactionOutcome.NoChange;
        return Valid(record) ? Restore(record) : DnsTransactionOutcome.RecoveryRequired;
    }

    private DnsTransactionOutcome Restore(DnsRecoveryRecord record)
    {
        try
        {
            var current = Read(record);
            if (Matches(current, record.Before.Target, record.Before))
                return Clear(DnsTransactionOutcome.Restored);
            if (!Matches(current, record.Proposed, record.Before))
                return DnsTransactionOutcome.Conflict;
            if (!platform.Permits(record.Before.Target))
                return DnsTransactionOutcome.RecoveryRequired;
            if (!Matches(Read(record), record.Proposed, record.Before))
                return DnsTransactionOutcome.Conflict;

            platform.Write(record.Before.Target);
            return Matches(Read(record), record.Before.Target, record.Before)
                ? Clear(DnsTransactionOutcome.Restored) : DnsTransactionOutcome.RecoveryRequired;
        }
        catch (Exception)
        {
            return DnsTransactionOutcome.RecoveryRequired;
        }
    }

    private DnsSnapshot Read(DnsRecoveryRecord record) =>
        platform.Read(record.Proposed.AdapterId, record.Proposed.Family);

    private bool BaselineMatches(DnsRecoveryRecord record)
    {
        try { return Matches(Read(record), record.Before.Target, record.Before); }
        catch (Exception error) when (error is NotSupportedException or UnauthorizedAccessException or
            System.ComponentModel.Win32Exception or System.Net.NetworkInformation.NetworkInformationException)
        {
            return false;
        }
    }

    private DnsTransactionOutcome Clear(DnsTransactionOutcome outcome)
    {
        // A failed clear leaves an undecided operation for recovery.
        try { recovery.Clear(); }
        catch (Exception) { return DnsTransactionOutcome.RecoveryRequired; }
        return outcome;
    }

    private static bool Valid(DnsRecoveryRecord record) =>
        DnsChangeValidation.Validate(record.Proposed) is null &&
        DnsChangeValidation.Validate(record.Before.Target) is null &&
        record.Proposed.AdapterId == record.Before.Target.AdapterId && record.Proposed.Family == record.Before.Target.Family &&
        (record.Before.OtherFamily is not { } other ||
            DnsChangeValidation.Validate(other) is null && other.AdapterId == record.Proposed.AdapterId &&
            other.Family != record.Proposed.Family);

    internal static bool Matches(DnsSnapshot snapshot, DnsChange target, DnsSnapshot baseline) =>
        Same(snapshot.Target, target) && Same(snapshot.OtherFamily, baseline.OtherFamily) &&
        string.Equals(snapshot.NativeEvidence, baseline.NativeEvidence, StringComparison.Ordinal);

    private static bool Same(DnsChange? a, DnsChange? b) =>
        a is null || b is null ? a is null && b is null :
            a.AdapterId == b.AdapterId && a.Family == b.Family && a.Assignment == b.Assignment &&
            a.AllowPlaintextFallback == b.AllowPlaintextFallback && a.Resolvers.SequenceEqual(b.Resolvers);

    private static DnsChange Copy(DnsChange change) =>
        change.Resolvers is null ? change : change with { Resolvers = Array.AsReadOnly(change.Resolvers.ToArray()) };

    private static DnsSnapshot Copy(DnsSnapshot snapshot) =>
        new(Copy(snapshot.Target), snapshot.OtherFamily is { } other ? Copy(other) : null, snapshot.NativeEvidence);
}
