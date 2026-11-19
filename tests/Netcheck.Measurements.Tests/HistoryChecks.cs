using System.Diagnostics;
using System.Net;
using System.Text;
using Microsoft.Data.Sqlite;
using Netcheck.Core;
using Netcheck.Storage;
using Netcheck.Optimization;

internal static class HistoryChecks
{
    internal static async Task RunAsync()
    {
        var folder = Directory.CreateTempSubdirectory("Netcheck-history-");
        try
        {
            var file = Path.Combine(folder.FullName, "history.db");
            var store = new HistoryStore(file);
            Require(store.Load().Entries.Count == 0, "new database");
            var run = Sample(100, DateTimeOffset.UtcNow);
            var entry = new HistoryEntry(Guid.NewGuid(), run);
            store.Save(entry);
            var loaded = new HistoryStore(file).Load().Entries.Single();
            Require(loaded.Id == entry.Id && loaded.Result.Paths.Single() == run.Paths.Single() &&
                loaded.Result.Download?.Samples.Count == 1 && loaded.Result.Download.MegabitsPerSecond == 100,
                "result and IPv4/IPv6 round-trip across reopen");
            Execute(file, "DROP INDEX runs_ended; PRAGMA user_version=1");
            Require(new HistoryStore(file).Load().Entries.Count == 1, "v1 database migrates with original row intact");
            Execute(file, "PRAGMA user_version=99");
            try { _ = store.Load(); throw new Exception("Opened a future schema."); }
            catch (InvalidDataException) { }
            Execute(file, "PRAGMA user_version=2");

            using (var process = StartInterruptedWriter(file))
            {
                Require(process.WaitForExit(10_000) && process.ExitCode == 41, "writer exits inside an open transaction");
                Require(store.Load().Entries.Single().Id == entry.Id, "SQLite rolls back interrupted delete");
            }
            Console.WriteLine("PASS history reopen, schema migration, future schema protection, interrupted transaction");

            var stopped = new HistoryEntry(Guid.NewGuid(), run with { State = MeasurementState.Stopped, Upload = null });
            store.Save(stopped);
            Require(store.Load().Entries.Any(x => x.Id == stopped.Id && x.Result.Upload is null), "partial results survive");
            using var export = new MemoryStream();
            await HistoryExport.WriteAsync(export, store.Load().Entries);
            var redacted = Encoding.UTF8.GetString(export.ToArray());
            Require(redacted.Contains("100") && !redacted.Contains("measure.example") &&
                !redacted.Contains("2001:db8") && !redacted.Contains("10.0.0.5") &&
                !redacted.Contains("private detail") && !redacted.Contains(entry.Id.ToString()), "export allowlist removes identifiers");
            store.Delete(stopped.Id);
            Require(store.Load().Entries.Single().Id == entry.Id, "delete one persists");
            Execute(file, "UPDATE runs SET payload=x'2020';");
            var skipped = store.Load();
            Require(skipped.Entries.Count == 0 && skipped.Notice is not null, "malformed row is reported");
            store.Clear();
            for (var i = 0; i <= HistoryStore.Retention; i++)
                store.Save(new HistoryEntry(Guid.NewGuid(), run with { Ended = run.Ended.AddSeconds(i) }));
            var retained = new HistoryStore(file).Load().Entries;
            Require(retained.Count == HistoryStore.Retention && retained.Last().Result.Ended == run.Ended.AddSeconds(1), "newest-first retention");
            store.Clear();
            Require(new HistoryStore(file).Load().Entries.Count == 0, "delete all persists");
            File.WriteAllText(file, "damaged");
            var recovered = new HistoryStore(file).Load();
            Require(recovered.Notice is not null && File.ReadAllText(file + ".damaged") == "damaged", "preserve damaged original");
            Console.WriteLine("PASS partial results, redaction, delete one/all, retention and corruption recovery");

            var baseline = Thorough(100, 20, run.Ended);
            var retest = Thorough(115, 30, run.Ended.AddHours(1));
            var comparison = HistoryComparison.Compare(baseline, retest);
            Require(comparison.Limitation is null && comparison.Metrics[0] is { Outcome: "Better", Delta: 15 } &&
                comparison.Metrics[2].Outcome == "Worse", "throughput/latency tradeoff");
            Require(HistoryComparison.Compare(baseline, retest with { State = MeasurementState.Partial })
                .Metrics.All(x => x.Outcome == "Inconclusive"), "partial tests remain inconclusive");
            Require(HistoryComparison.Compare(baseline, retest with { Options = retest.Options with { PayloadBudget = 1 } })
                .Limitation is not null, "different workload remains inconclusive");
            Require(HistoryComparison.Compare(run, Sample(200, run.Ended.AddHours(1))).Metrics[0].Outcome == "Inconclusive",
                "single-run comparison remains inconclusive");
            Require(HistoryComparison.Compare(baseline, Thorough(101, 20, run.Ended.AddHours(1))).Metrics[0].Outcome == "Unchanged",
                "small difference falls within uncertainty threshold");
            Require(HistoryComparison.Compare(Thorough(0, 20, run.Ended), retest).Metrics[0].Percent is null,
                "zero baseline has no percent change");
            Console.WriteLine("PASS better, worse, unchanged, inconclusive and undefined percentage comparisons");

            var fiveIdle = new ProbeMeasurement([20, 20, 20, 20, 20], 0, 0, 0);
            var fiveLoaded = new ProbeMeasurement([65, 65, 65, 65, 65], 0, 0, 0);
            var observed = run with
            {
                Idle = fiveIdle, Download = run.Download! with { Loaded = fiveLoaded },
                PayloadBytes = 10 * MeasurementProtocol.MiB,
                SystemDns = [new DnsMeasurement("A", [100, 110, 120], 0)],
                Connection = run.Connection! with { LinkBitsPerSecond = 100_000_000, AdapterReceivedBytes = 30 * MeasurementProtocol.MiB }
            };
            var findings = ConnectionFindings.Evaluate(observed);
            Require(findings.Count == 4, "loaded latency, DNS, Ethernet and traffic rules");
            Require(ConnectionFindings.Recommend(findings, observed, observed.Paths.Single().Adapter)?.Scope == "Cable or port",
                "matching wired adapter automatically selects the cable check");
            Require(ConnectionFindings.Recommend(findings, observed, Guid.NewGuid())?.Scope == "Test path",
                "changed adapter suppresses cable and local traffic advice");
            Require(ConnectionFindings.Recommend(findings, observed with { State = MeasurementState.Partial }, null) is null,
                "partial evidence never selects a change");
            Require(ConnectionFindings.Evaluate(observed with { State = MeasurementState.Partial }).Single().Confidence == "Inconclusive",
                "partial run cannot trigger diagnostic recommendations");
            Require(ConnectionFindings.Evaluate(run).Count == 0, "sparse and ordinary evidence does not trigger findings");
            Console.WriteLine("PASS evidence-based findings and incomplete/sparse evidence handling");

            CheckHistory(folder.FullName, run);
        }
        finally { folder.Delete(recursive: true); }
    }

    /// <summary>P6: new checks are stored beside earlier-version runs; a v2 database upgrades without losing a row.</summary>
    private static void CheckHistory(string folder, MeasurementResult run)
    {
        var file = Path.Combine(folder, "history-v2.db");
        var store = new HistoryStore(file);
        var old = new HistoryEntry(Guid.NewGuid(), run);
        store.Save(old);
        Execute(file, "DROP INDEX checks_ended; DROP TABLE checks; PRAGMA user_version=2");   // as the earlier version left it
        var check = NewCheck(run.Ended.AddDays(2), 480, 7);
        new HistoryStore(file).SaveCheck(check);
        var reopened = new HistoryStore(file);
        Require(reopened.Load().Entries.Single().Id == old.Id, "a v2 database upgrades and its earlier-version run still opens");
        var loaded = reopened.LoadChecks().Checks.Single();
        Require(loaded.Id == check.Id && loaded.Result.Download?.Mbps == 480 && loaded.DnsName == "Google" &&
            loaded.DnsLookupMs == 33 && loaded.Result.Loss?.LossPercent == 0 && loaded.Result.Ping?.Milliseconds.Count == 10,
            "a new check round-trips with its readings, DNS and ping loss");
        for (var i = 0; i <= HistoryStore.Retention; i++)
            reopened.SaveCheck(NewCheck(run.Ended.AddDays(3).AddSeconds(i), 100, 7));
        Require(reopened.LoadChecks().Checks.Count == HistoryStore.Retention && reopened.Load().Entries.Count == 1,
            "checks keep the newest 100 without touching earlier-version runs");
        Execute(file, "UPDATE checks SET payload=x'2020' WHERE rowid = (SELECT max(rowid) FROM checks)");
        Require(reopened.LoadChecks() is { Notice: not null, Checks.Count: HistoryStore.Retention - 1 }, "a damaged check is skipped and reported");
        Console.WriteLine("PASS checks saved beside earlier-version runs, v2 upgrade, retention, damaged row");

        CheckSummary S(double down, double up, double ping, double jitter) =>
            CheckAssessment.Summarize(NewCheck(run.Ended, down, ping, up, jitter).Result);
        var same = CheckComparison.Compare(S(100, 50, 7, 1), 30, S(105, 52, 9, 2), 33);
        Require(same.All(r => r.Meaning is "About the same" or "Same" && r.Tone == Tone.Neutral),
            "small differences (speed ±10 %, ping ±3 ms, DNS ±5 ms) read 'About the same'");
        var changed = CheckComparison.Compare(S(100, 50, 20, 1), 36, S(130, 40, 40, 1), 13);
        Require(changed[0] is { Meaning: "Faster", Tone: Tone.Good, Change: 30 } && changed[1] is { Meaning: "Slower", Tone: Tone.Poor } &&
            changed[2] is { Meaning: "Slower", Tone: Tone.Poor } && changed[5] is { Meaning: "Faster", Tone: Tone.Good },
            "real changes are named, better green and worse red");
        Require(CheckComparison.Compare(S(100, 50, 7, 1), null, S(100, 50, 7, 1), 20)[5] is { Meaning: "Can't compare", Change: null },
            "a missing side can't be compared");
        Require(CheckComparison.Compare(S(100, 50, 7, 1), 30, S(100, 50, 30, 9), 90, earlierVersion: true)
                .Skip(2).Where(r => r.Name != "Ping loss").All(r => r.Meaning == "Measured differently" && r.Tone == Tone.Neutral),
            "ping, jitter and DNS against the earlier version are shown but not judged");
        // Number colours (user, 2026-11-17): better green, worse red; within normal variation the worse one is yellow.
        Require(CheckComparison.SideTones(changed[5]) == (Tone.Poor, Tone.Good), "DNS 36 → 13 ms: before red, after green");
        Require(CheckComparison.SideTones(changed[0]) == (Tone.Poor, Tone.Good), "download 100 → 130 Mbps: higher is better");
        Require(CheckComparison.SideTones(same[2]) == (Tone.Good, Tone.Fair), "ping 7 → 9 ms (about the same): before green, after yellow");
        Require(CheckComparison.SideTones(CheckComparison.Compare(S(100, 50, 7, 1), 30, S(100, 50, 7, 1), 30)[2]) == (null, null),
            "equal values stay plain");
        var shown = CheckComparison.FromEarlierVersion(run);
        Require(shown.Download?.Mbps == run.Download!.MegabitsPerSecond && shown.Loss is null &&
            CheckAssessment.Summarize(shown).Loss.Tone == Tone.Neutral, "an earlier-version run shows in the new layout, ping loss neutral");
        Console.WriteLine("PASS before/after comparison rules and earlier-version display");
    }

    private static CheckRecord NewCheck(DateTimeOffset ended, double down, double ping, double up = 50, double jitter = 1)
    {
        var pings = Enumerable.Range(0, 10).Select(i => ping + (i % 2 == 0 ? 0 : jitter)).ToArray();
        SpeedReading Speed(double mbps) => new(StageOutcome.Complete, mbps, 10_000_000, TimeSpan.FromSeconds(8),
            [new ThroughputSample(1, mbps)], 6, SpeedEnd.Duration);
        var loss = new PingLossReading(StageOutcome.Complete,
            [new PingTargetReading("Cloudflare", "1.1.1.1", 100, 100, ping, jitter)]);
        var result = new InternetCheckResult(ended.AddSeconds(-30), ended, false,
            new LatencyReading(StageOutcome.Complete, pings, 0), Speed(down), Speed(up), loss, "TLV", []);
        return new CheckRecord(Guid.NewGuid(), result, "Ethernet", "Google", "8.8.4.4", 33);
    }

    /// <summary>Opens a COPY of a real history file (never the original) and reports what loads.</summary>
    internal static void OpenCopy(string original)
    {
        var folder = Directory.CreateTempSubdirectory("Netcheck-history-copy-");
        try
        {
            var copy = Path.Combine(folder.FullName, "history.db");
            File.Copy(original, copy);
            var store = new HistoryStore(copy);
            var runs = store.Load();
            var checks = store.LoadChecks();
            var notice = runs.Notice ?? checks.Notice;
            Console.WriteLine($"Copy of {original}: {runs.Entries.Count} earlier-version runs, {checks.Checks.Count} checks" +
                (notice is null ? "" : $" ({notice})"));
            foreach (var entry in runs.Entries)
            {
                var s = CheckAssessment.Summarize(CheckComparison.FromEarlierVersion(entry.Result));
                Console.WriteLine($"  {entry.Result.Ended.ToLocalTime():ddd d MMM HH:mm}  down {s.Download.Value:0} · up {s.Upload.Value:0} Mbps · " +
                    $"ping {s.Ping.Value:0.#} · jitter {s.Jitter.Value:0.#} ms · {s.Verdict.Headline}");
            }
            Require(runs.Notice is null && runs.Entries.Count > 0, "every stored run opens");
            Console.WriteLine("PASS existing history opens (copy; original untouched)");
        }
        finally { folder.Delete(recursive: true); }
    }

    internal static void Interrupt(string file)
    {
        _ = new HistoryStore(file).Load();
        using var db = new SqliteConnection($"Data Source={file};Pooling=False");
        db.Open();
        using var command = db.CreateCommand();
        command.CommandText = "BEGIN IMMEDIATE; DELETE FROM runs;";
        command.ExecuteNonQuery();
        Environment.Exit(41);
    }

    private static Process StartInterruptedWriter(string file)
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
        if (string.Equals(Path.GetFileNameWithoutExtension(start.FileName), "dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(typeof(HistoryChecks).Assembly.Location);
        start.ArgumentList.Add("--interrupt-history");
        start.ArgumentList.Add(file);
        return Process.Start(start)!;
    }

    private static void Execute(string file, string sql)
    {
        using var db = new SqliteConnection($"Data Source={file};Pooling=False");
        db.Open();
        using var command = db.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static MeasurementResult Thorough(double speed, double latency, DateTimeOffset at)
    {
        var first = Sample(speed, at, latency);
        return first with
        {
            Options = first.Options with { Mode = MeasurementMode.Thorough },
            Repeats = [Sample(speed - 0.5 < 0 ? 0 : speed - 0.5, at, latency), first,
                Sample(speed + 0.5, at, latency)],
            PlannedRuns = 3
        };
    }

    private static MeasurementResult Sample(double speed, DateTimeOffset at, double latency = 20)
    {
        var probes = new ProbeMeasurement([latency, latency], 0, 0, 0);
        var transfer = new TransferMeasurement(100, TimeSpan.FromSeconds(20), TransferEnd.TargetDuration,
            true, [new ThroughputSample(2, speed)], probes, speed, true, 3);
        var adapter = Guid.Parse("AAAAAAAA-0000-0000-0000-000000000000");
        return new MeasurementResult(new MeasurementOptions(new Uri("https://measure.example"), MeasurementMode.Standard,
            512L * MeasurementProtocol.MiB, TimeSpan.FromSeconds(55), false, adapter, TimeSpan.FromSeconds(20)),
            at.AddSeconds(-42), at, MeasurementState.Complete, new EndpointCapabilities(1, MeasurementProtocol.TransferLimit,
                "Fixture", null, 3), [new ObservedPath(IPAddress.Parse("10.0.0.5"), IPAddress.Parse("2001:db8::1"), adapter, false)],
            200, probes, transfer, transfer, [], ["private detail"], ProviderVersion: "1",
            Connection: new ConnectionEvidence("Ethernet", 1_000_000_000, null, 300, 300, null))
        {
            ConnectionCost = "Regular", MetricDefinition = "https-window-median-v1",
            Route = new RouteObservation(adapter, IPAddress.Parse("10.0.0.5"), IPAddress.Parse("10.0.0.1"))
        };
    }

    private static void Require(bool condition, string description)
    {
        if (!condition)
            throw new InvalidOperationException(description);
    }
}
