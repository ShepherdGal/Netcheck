using System.Text.Json;
using Netcheck.Core;

namespace Netcheck.Storage;

public static class HistoryExport
{
    public static async Task WriteFileAsync(string path, IReadOnlyList<HistoryEntry> history)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                bufferSize: 4096, useAsync: true))
                await WriteAsync(stream, history);
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    public static Task WriteAsync(Stream output, IReadOnlyList<HistoryEntry> history) =>
        JsonSerializer.SerializeAsync(output, new
        {
            Version = 1,
            Runs = history.Select(entry => Redact(entry.Result))
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true });

    private static object Redact(MeasurementResult run) => new
    {
        Day = run.Ended.UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
        Provider = run.Provider.ToString(),
        Mode = run.Options.Mode.ToString(),
        State = run.State.ToString(),
        run.Options.PayloadBudget,
        run.PayloadBytes,
        Idle = Probe(run.Idle),
        Download = Transfer(run.Download),
        Upload = Transfer(run.Upload),
        Dns = run.SystemDns.Select(result => new { result.RecordType, result.MedianMs, Count = result.Milliseconds.Count }),
        Repeats = run.Repeats?.Select(Redact)
    };

    private static object? Transfer(TransferMeasurement? transfer) => transfer is null ? null : new
    {
        transfer.MegabitsPerSecond,
        transfer.Bytes,
        Seconds = transfer.Elapsed.TotalSeconds,
        End = transfer.End.ToString(),
        Loaded = Probe(transfer.Loaded)
    };

    private static object? Probe(ProbeMeasurement? probe) => probe is null ? null : new
    {
        probe.MedianMs,
        probe.JitterMs,
        ValidSamples = probe.Milliseconds.Count
    };
}
