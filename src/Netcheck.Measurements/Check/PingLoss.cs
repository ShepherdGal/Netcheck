using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using Netcheck.Core;

namespace Netcheck.Measurements.Check;

/// <summary>Sends one echo request. Returns the round trip in ms, or null when no reply arrived in time.</summary>
public interface IPinger
{
    Task<double?> SendAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Unprivileged ICMP echo through Windows' IcmpSendEcho2 (System.Net.NetworkInformation.Ping).</summary>
public sealed class IcmpPinger : IPinger
{
    private static readonly byte[] Payload = new byte[32];

    public async Task<double?> SendAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var ping = new Ping();
        try
        {
            var reply = await ping.SendPingAsync(address, timeout, Payload, new PingOptions(64, true), cancellationToken)
                .ConfigureAwait(false);
            return reply.Status == IPStatus.Success ? reply.RoundtripTime : null;
        }
        catch (PingException)
        {
            return null;
        }
    }
}

internal static class PingLossRunner
{
    private static readonly TimeSpan ReplyTimeout = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Sends evenly spaced echoes to every target in parallel. Each echo is its own task so a slow or lost
    /// reply never delays the schedule. Echoes not sent before cancellation are not counted.
    /// </summary>
    internal static async Task<PingLossReading> RunAsync(IPinger pinger, CheckOptions options,
        Action<double>? reportFraction, CancellationToken cancellationToken)
    {
        var targets = options.LossTargets
            .Select(target => (target, address: IPAddress.TryParse(target.Address, out var ip) ? ip : null))
            .ToArray();
        var interval = options.EffectiveLossInterval;
        var count = options.LossPingsPerTarget;
        var sent = new int[targets.Length];
        var replies = targets.Select(_ => new List<(int Index, double Ms)>()).ToArray();
        var pending = new List<Task>();
        var clock = Stopwatch.StartNew();
        var stopped = false;

        try
        {
            for (var i = 0; i < count; i++)
            {
                var due = interval * i;
                var wait = due - clock.Elapsed;
                if (wait > TimeSpan.Zero)
                    await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                for (var t = 0; t < targets.Length; t++)
                {
                    if (targets[t].address is not { } address)
                        continue;
                    sent[t]++;
                    var slot = t;
                    var index = i;
                    pending.Add(Task.Run(async () =>
                    {
                        var rtt = await pinger.SendAsync(address, ReplyTimeout, CancellationToken.None).ConfigureAwait(false);
                        if (rtt is { } ms)
                            lock (replies[slot])
                                replies[slot].Add((index, ms));
                    }, CancellationToken.None));
                }
                reportFraction?.Invoke((i + 1d) / count);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            stopped = true;
        }

        // Echoes already sent get their full reply window, so a stop never turns into fake loss.
        await Task.WhenAll(pending).ConfigureAwait(false);
        var readings = targets.Select((entry, t) =>
        {
            // Replies can finish out of order; jitter compares them in the order they were sent.
            var ordered = replies[t].OrderBy(r => r.Index).Select(r => r.Ms).ToArray();
            return new PingTargetReading(entry.target.Name, entry.target.Address, sent[t], ordered.Length,
                MeasurementStatistics.Median(ordered), PingTargetReading.Jitter(ordered));
        }).ToArray();
        return new PingLossReading(stopped ? StageOutcome.Stopped : StageOutcome.Complete, readings);
    }
}
