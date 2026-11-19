using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Netcheck.Core;

namespace Netcheck.Measurements;

public static class SystemDnsMeasurement
{
    public static async Task<DnsMeasurement> MeasureAsync(AddressFamily family, string type, CancellationToken token)
    {
        var samples = new List<double>();
        var failures = 0;
        foreach (var host in MeasurementProtocol.DnsNames)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(2));
            var start = Stopwatch.GetTimestamp();
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host, family, deadline.Token).ConfigureAwait(false);
                if (addresses.Length > 0)
                    samples.Add(Stopwatch.GetElapsedTime(start).TotalMilliseconds);
                else
                    failures++;
            }
            catch (SocketException) { failures++; }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { failures++; }
        }
        token.ThrowIfCancellationRequested();
        return new DnsMeasurement(type, samples.ToArray(), failures);
    }
}
