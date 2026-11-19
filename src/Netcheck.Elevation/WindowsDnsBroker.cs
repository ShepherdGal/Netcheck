using System.Runtime.Versioning;

namespace Netcheck.Elevation;

[SupportedOSPlatform("windows")]
public static class WindowsDnsBroker
{
    public static bool IsEnabled => BrokerHost.IsEnabled;

    // The desktop only uses this hint to surface the recovery action. An unreadable
    // journal is still a reason to offer recovery through the authenticated broker.
    public static bool CanRuleOutRecovery => BrokerHost.JournalAbsent(WindowsDnsRecoveryStore.JournalName);

    public const string Switch = "--netcheck-dns-broker";
    private const string PipePrefix = "Netcheck.Dns";

    public static DnsSnapshot ReadForReview(Guid adapter, DnsTargetFamily family) =>
        new WindowsDnsTransactionPlatform().Read(adapter, family);

    public static Task<DnsTransactionOutcome> ApplyAsync(ReviewedDnsChange review,
        Func<CancellationToken, Task<bool>> verify, CancellationToken token = default) =>
        RequestAsync(new Request(1, review, Recover: false), verify, token);

    public static Task<DnsTransactionOutcome> RecoverAsync(CancellationToken token = default) =>
        RequestAsync(new Request(1, null, Recover: true), null, token);

    private static async Task<DnsTransactionOutcome> RequestAsync(Request request,
        Func<CancellationToken, Task<bool>>? verify, CancellationToken token)
    {
        var outcome = await BrokerHost.ExchangeAsync<DnsTransactionOutcome>(Switch, PipePrefix, async (pipe, deadline) =>
        {
            await DnsBrokerPipe.SendAsync(pipe, request, deadline).ConfigureAwait(false);
            var reply = await DnsBrokerPipe.ReceiveAsync<Reply>(pipe, deadline).ConfigureAwait(false);
            if (reply is { NeedsVerification: true, Outcome: null } && verify is not null)
            {
                var keep = await verify(deadline).ConfigureAwait(false);
                await DnsBrokerPipe.SendAsync(pipe, keep, deadline).ConfigureAwait(false);
                reply = await DnsBrokerPipe.ReceiveAsync<Reply>(pipe, deadline).ConfigureAwait(false);
            }
            return !reply.NeedsVerification && reply.Outcome is { } result && Enum.IsDefined(result)
                ? result : DnsTransactionOutcome.RecoveryRequired;
        }, token).ConfigureAwait(false);
        return outcome ?? DnsTransactionOutcome.Rejected;
    }

    public static Task<int> RunAsync(string[] args) =>
        BrokerHost.ServeAsync(args, Switch, PipePrefix, (pipe, token) => ExecuteAsync(pipe, OpenTransaction, token));

    internal static async Task ExecuteAsync(Stream pipe, Func<DnsTransaction> openTransaction, CancellationToken token)
    {
        var request = await DnsBrokerPipe.ReceiveAsync<Request>(pipe, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var outcome = DnsTransactionOutcome.Rejected;
        if (request is { Version: 1, Recover: true, Review: null })
            outcome = openTransaction().Recover();
        else if (request is { Version: 1, Recover: false, Review: { Before.Target: not null, Proposed: not null } review })
            outcome = openTransaction().Apply(review, verificationToken =>
            {
                DnsBrokerPipe.SendAsync(pipe, new Reply(true, null), verificationToken).GetAwaiter().GetResult();
                return DnsBrokerPipe.ReceiveAsync<bool>(pipe, verificationToken).GetAwaiter().GetResult();
            }, token);
        using var replyDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await DnsBrokerPipe.SendAsync(pipe, new Reply(false, outcome), replyDeadline.Token).ConfigureAwait(false);
    }

    private static DnsTransaction OpenTransaction()
    {
        var directory = BrokerHost.OpenRecoveryDirectory(out var owner);
        return new DnsTransaction(new WindowsDnsTransactionPlatform(),
            new WindowsDnsRecoveryStore(directory.FullName, owner));
    }

    internal static bool ProtectedPath(FileSystemInfo entry) => BrokerHost.ProtectedPath(entry);

    internal sealed record Request(int Version, ReviewedDnsChange? Review, bool Recover);
    internal sealed record Reply(bool NeedsVerification, DnsTransactionOutcome? Outcome);
}
