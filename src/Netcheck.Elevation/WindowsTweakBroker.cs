using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace Netcheck.Elevation;

[StructLayout(LayoutKind.Auto)]
public readonly record struct TweakApplyResult(TweakOutcome Outcome, RestorePointResult RestorePoint, string Reason = "");

/// <summary>Elevated broker for Boost: same trust checks, pipe and journal rules as the DNS broker.</summary>
[SupportedOSPlatform("windows")]
public static class WindowsTweakBroker
{
    public const string Switch = "--netcheck-tweak-broker";
    private const string PipePrefix = "Netcheck.Boost";
    internal const string JournalName = "tweak-recovery.json";

    public static bool IsEnabled => BrokerHost.IsEnabled;
    public static bool CanRuleOutRecovery => BrokerHost.JournalAbsent(JournalName);

    /// <summary>Detect: read one tweak's current value without elevation. Throws NotSupportedException when unavailable.</summary>
    public static TweakValue Read(TweakId id, Guid adapter) => new WindowsTweakPlatform().Read(id, adapter);

    /// <summary>Detect: for driver-mapped tweaks, the driver's own value whose label is the target, or null.</summary>
    public static long? DriverTarget(TweakId id, Guid adapter) => WindowsTweakPlatform.DriverTarget(id, adapter);

    /// <summary>The power plan in use; power-plan tweaks are scoped to it.</summary>
    public static Guid ActivePowerScheme() => WindowsTweakPlatform.ActiveScheme();

    /// <summary>
    /// Applies a batch. <paramref name="keep"/> runs after the values are written and read back; returning
    /// false (or timing out) restores everything.
    /// </summary>
    public static async Task<TweakApplyResult> ApplyAsync(IReadOnlyList<TweakValue> proposed, bool restorePoint,
        Func<CancellationToken, Task<bool>> keep, CancellationToken token = default) =>
        await RequestAsync(new Request(1, proposed.ToArray(), restorePoint, Recover: false), keep, token).ConfigureAwait(false);

    public static async Task<TweakOutcome> RecoverAsync(CancellationToken token = default) =>
        (await RequestAsync(new Request(1, null, false, Recover: true), null, token).ConfigureAwait(false)).Outcome;

    private static async Task<TweakApplyResult> RequestAsync(Request request,
        Func<CancellationToken, Task<bool>>? keep, CancellationToken token)
    {
        var result = await BrokerHost.ExchangeAsync<TweakApplyResult>(Switch, PipePrefix, async (pipe, deadline) =>
        {
            await DnsBrokerPipe.SendAsync(pipe, request, deadline).ConfigureAwait(false);
            var reply = await DnsBrokerPipe.ReceiveAsync<Reply>(pipe, deadline).ConfigureAwait(false);
            if (reply is { NeedsVerification: true, Outcome: null } && keep is not null)
            {
                var decision = await keep(deadline).ConfigureAwait(false);
                await DnsBrokerPipe.SendAsync(pipe, decision, deadline).ConfigureAwait(false);
                reply = await DnsBrokerPipe.ReceiveAsync<Reply>(pipe, deadline).ConfigureAwait(false);
            }
            var outcome = !reply.NeedsVerification && reply.Outcome is { } o && Enum.IsDefined(o) ? o : TweakOutcome.RecoveryRequired;
            return new TweakApplyResult(outcome, Enum.IsDefined(reply.RestorePoint) ? reply.RestorePoint : RestorePointResult.Failed,
                reply.Reason is { Length: <= 600 } reason ? reason : "");
        }, token).ConfigureAwait(false);
        return result ?? new TweakApplyResult(TweakOutcome.Rejected, RestorePointResult.NotRequested, "broker: not started or not trusted");
    }

    public static Task<int> RunAsync(string[] args) =>
        BrokerHost.ServeAsync(args, Switch, PipePrefix,
            (pipe, token) => ExecuteAsync(pipe, OpenTransaction, () => RestorePoints.Create("Netcheck Boost"), token));

    internal static async Task ExecuteAsync(Stream pipe, Func<TweakTransaction> openTransaction,
        Func<RestorePointResult> createRestorePoint, CancellationToken token)
    {
        var request = await DnsBrokerPipe.ReceiveAsync<Request>(pipe, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var outcome = TweakOutcome.Rejected;
        var point = RestorePointResult.NotRequested;
        var reason = "broker: request rejected (version, shape or allowlist)";
        if (request is { Version: 1, Recover: true, Proposed: null, RestorePoint: false })
        {
            var transaction = openTransaction();
            outcome = transaction.Recover();
            reason = transaction.Reason;
        }
        else if (request is { Version: 1, Recover: false, Proposed: { Length: > 0 and <= TweakRules.MaxBatch } proposed } &&
                 proposed.All(TweakRules.Valid))
        {
            if (request.RestorePoint)
                point = createRestorePoint();
            var transaction = openTransaction();
            outcome = transaction.Apply(proposed, verificationToken =>
            {
                DnsBrokerPipe.SendAsync(pipe, new Reply(true, null, point), verificationToken).GetAwaiter().GetResult();
                return DnsBrokerPipe.ReceiveAsync<bool>(pipe, verificationToken).GetAwaiter().GetResult();
            }, token);
            reason = transaction.Reason;
        }
        using var replyDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await DnsBrokerPipe.SendAsync(pipe, new Reply(false, outcome, point, reason.Length > 600 ? reason[..600] : reason),
            replyDeadline.Token).ConfigureAwait(false);
    }

    private static TweakTransaction OpenTransaction()
    {
        var directory = BrokerHost.OpenRecoveryDirectory(out var owner);
        return new TweakTransaction(new WindowsTweakPlatform(), new WindowsTweakRecoveryStore(directory.FullName, owner));
    }

    internal sealed record Request(int Version, TweakValue[]? Proposed, bool RestorePoint, bool Recover);
    internal sealed record Reply(bool NeedsVerification, TweakOutcome? Outcome, RestorePointResult RestorePoint, string? Reason = null);
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsTweakRecoveryStore(string protectedDirectory, SecurityIdentifier brokerOwner)
    : WindowsRecoveryStore<TweakRecoveryRecord>(protectedDirectory, brokerOwner, WindowsTweakBroker.JournalName,
        record => record is { Before.Count: > 0, Proposed.Count: > 0 } && record.Before.Count == record.Proposed.Count),
      ITweakRecoveryStore;
