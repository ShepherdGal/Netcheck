using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Netcheck.Core;
using Netcheck.Measurements;
using Netcheck.TestServer;

internal static class CurlComparison
{
    private const int Streams = 3;
    private const int BytesPerStream = 4 * MeasurementProtocol.MiB;
    private const double ExpectedMbps = Streams * MeasurementProtocol.MiB * 8e-6;
    private const double Tolerance = 0.15;

    internal static async Task RunAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        await using var endpoint = await LocalTestEndpoint.StartAsync(deadline.Token, MeasurementProtocol.MiB);
        var provider = new HttpsSpeedTestProvider(_ => null, endpoint.CertificateHash);
        var options = new MeasurementOptions(endpoint.Address, MeasurementMode.Standard,
            2L * Streams * BytesPerStream, TimeSpan.FromSeconds(16), IncludeSystemDns: false,
            SustainedDuration: TimeSpan.FromSeconds(4));
        var result = await provider.RunAsync(options, null, deadline.Token);
        if (result.State != MeasurementState.Complete || result.Download?.MegabitsPerSecond is not { } download ||
            result.Upload?.MegabitsPerSecond is not { } upload)
            throw new InvalidOperationException($"Netcheck returned {result.State}. {string.Join(" ", result.Notes)}");

        if (!endpoint.Address.IsLoopback)
            throw new InvalidOperationException("The curl comparison only uses the private loopback fixture.");
        var payloadFile = Path.GetTempFileName();
        try
        {
            await using (var payload = File.OpenWrite(payloadFile))
                payload.SetLength(BytesPerStream);

            var referenceDownload = await MeasureCurl(endpoint, uploadFile: null, deadline.Token);
            var referenceUpload = await MeasureCurl(endpoint, payloadFile, deadline.Token);
            Verify("download", download, referenceDownload);
            Verify("upload", upload, referenceUpload);
        }
        finally
        {
            File.Delete(payloadFile);
        }
    }

    private static void Verify(string direction, double netcheck, double curl)
    {
        if (Math.Abs(netcheck - curl) / curl > Tolerance || Math.Abs(curl - ExpectedMbps) / ExpectedMbps > Tolerance)
            throw new InvalidOperationException($"{direction} differs from the paced fixture. Netcheck {netcheck:F2} Mbps, curl {curl:F2} Mbps.");
        Console.WriteLine($"PASS {direction}: Netcheck {netcheck:F2} Mbps, curl {curl:F2} Mbps, nominal {ExpectedMbps:F2} Mbps");
    }

    private static async Task<double> MeasureCurl(LocalTestEndpoint endpoint, string? uploadFile, CancellationToken token)
    {
        var start = new ProcessStartInfo
        {
            FileName = OperatingSystem.IsWindows() ? "curl.exe" : "curl",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        string[] common = ["--disable", "--silent", "--show-error", "--fail", "--noproxy", "*", "--http1.1",
            "--parallel", "--parallel-immediate", "--parallel-max", "3", "--max-time", "8", "--connect-timeout", "2",
            // Only the ephemeral loopback certificate is accepted by the public-key pin.
            "--insecure", "--pinnedpubkey", endpoint.PublicKeyPin, "--write-out", "%{json}\n"];
        foreach (var argument in common)
            start.ArgumentList.Add(argument);

        var bytes = BytesPerStream.ToString(CultureInfo.InvariantCulture);
        var path = MeasurementProtocol.Prefix + (uploadFile is null ? $"/download?bytes={bytes}" : "/upload");
        if (uploadFile is not null)
        {
            foreach (var argument in new[] { "--header", "Content-Type: application/octet-stream", "--header", "Expect:",
                "--data-binary", $"@{uploadFile}" })
                start.ArgumentList.Add(argument);
        }
        for (var index = 0; index < Streams; index++)
        {
            start.ArgumentList.Add("--output");
            start.ArgumentList.Add(OperatingSystem.IsWindows() ? "NUL" : "/dev/null");
            start.ArgumentList.Add(new Uri(endpoint.Address, path).AbsoluteUri);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start curl.");
        var output = process.StandardOutput.ReadToEndAsync(token);
        var errors = process.StandardError.ReadToEndAsync(token);
        try { await process.WaitForExitAsync(token); }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
            throw;
        }
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"curl exited with {process.ExitCode}. {await errors}");

        var rows = (await output).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (rows.Length != Streams)
            throw new InvalidOperationException($"Expected {Streams} curl transfers, received {rows.Length}.");

        var longestSeconds = 0d;
        foreach (var row in rows)
        {
            using var parsed = JsonDocument.Parse(row);
            var transfer = parsed.RootElement;
            var expectedStatus = uploadFile is null ? 200 : 204;
            var sizeField = uploadFile is null ? "size_download" : "size_upload";
            if (transfer.GetProperty("response_code").GetInt32() != expectedStatus ||
                transfer.GetProperty(sizeField).GetInt64() != BytesPerStream)
                throw new InvalidOperationException($"curl did not complete one {BytesPerStream}-byte transfer.");
            var seconds = transfer.GetProperty("time_total").GetDouble() -
                transfer.GetProperty("time_pretransfer").GetDouble();
            if (seconds <= 0)
                throw new InvalidOperationException("curl reported an invalid transfer duration.");
            longestSeconds = Math.Max(longestSeconds, seconds);
        }
        // The three requests start together. Use their longest elapsed transfer time for the aggregate.
        return Streams * BytesPerStream * 8e-6 / longestSeconds;
    }
}
