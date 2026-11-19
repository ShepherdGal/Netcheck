using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Netcheck.Core;

namespace Netcheck.Storage;

public sealed record HistoryEntry(Guid Id, MeasurementResult Result);
public sealed record HistoryLoad(IReadOnlyList<HistoryEntry> Entries, string? Notice);

/// <summary>A finished check from the rebuilt Check page, with what Windows reported around it.</summary>
public sealed record CheckRecord(Guid Id, InternetCheckResult Result, string? ConnectionKind, string? DnsName,
    string? DnsAddress, double? DnsLookupMs);
public sealed record CheckLoad(IReadOnlyList<CheckRecord> Checks, string? Notice);

public sealed class HistoryStore(string filename)
{
    public const int Retention = 100;
    // v3 (P6, 2026-11-16) adds the "checks" table for the rebuilt Check page; the older "runs" table is kept
    // untouched so checks from earlier versions still open.
    private const int SchemaVersion = 3;
    private const int MaximumPayloadBytes = 256 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new AddressConverter(), new JsonStringEnumConverter(allowIntegerValues: false) }
    };
    private static readonly Lazy<bool> Provider = new(() =>
    {
        SQLitePCL.raw.SetProvider(new SQLitePCL.SQLite3Provider_winsqlite3());
        return true;
    });
    private readonly object _lock = new();

    public HistoryLoad Load()
    {
        lock (_lock)
        {
            try { return Read(); }
            catch (SqliteException error) when (error.SqliteErrorCode is 11 or 26)
            {
                var preserved = filename + ".damaged";
                if (File.Exists(preserved) || File.Exists(filename + "-journal") || File.Exists(filename + "-wal"))
                    throw new IOException("History is damaged. Its files were preserved for recovery.", error);
                File.Move(filename, preserved);
                return Read() with { Notice = "History was damaged. Netcheck preserved the original database as history.db.damaged." };
            }
        }
    }

    public void Save(HistoryEntry entry)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(entry.Result, Json);
        if (payload.Length > MaximumPayloadBytes)
            throw new InvalidDataException("The history entry exceeds its storage limit.");
        lock (_lock)
        {
            using var db = Open();
            using var transaction = db.BeginTransaction();
            using var insert = db.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = "INSERT OR REPLACE INTO runs(id, ended, payload) VALUES ($id, $ended, $payload)";
            insert.Parameters.AddWithValue("$id", entry.Id.ToString("D"));
            insert.Parameters.AddWithValue("$ended", entry.Result.Ended.ToUnixTimeMilliseconds());
            insert.Parameters.AddWithValue("$payload", payload);
            insert.ExecuteNonQuery();
            using var prune = db.CreateCommand();
            prune.Transaction = transaction;
            prune.CommandText = $"DELETE FROM runs WHERE id IN (SELECT id FROM runs ORDER BY ended DESC, rowid DESC LIMIT -1 OFFSET {Retention})";
            prune.ExecuteNonQuery();
            transaction.Commit();
        }
    }

    /// <summary>Saves (or replaces) a check; keeps the newest <see cref="Retention"/> checks.</summary>
    public void SaveCheck(CheckRecord check)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(check, Json);
        if (payload.Length > MaximumPayloadBytes)
            throw new InvalidDataException("The history entry exceeds its storage limit.");
        lock (_lock)
        {
            using var db = Open();
            using var transaction = db.BeginTransaction();
            using var insert = db.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = "INSERT OR REPLACE INTO checks(id, ended, payload) VALUES ($id, $ended, $payload)";
            insert.Parameters.AddWithValue("$id", check.Id.ToString("D"));
            insert.Parameters.AddWithValue("$ended", check.Result.Ended.ToUnixTimeMilliseconds());
            insert.Parameters.AddWithValue("$payload", payload);
            insert.ExecuteNonQuery();
            using var prune = db.CreateCommand();
            prune.Transaction = transaction;
            prune.CommandText = $"DELETE FROM checks WHERE id IN (SELECT id FROM checks ORDER BY ended DESC, rowid DESC LIMIT -1 OFFSET {Retention})";
            prune.ExecuteNonQuery();
            transaction.Commit();
        }
    }

    /// <summary>Checks from the rebuilt Check page, newest first. Damaged rows are skipped and counted.</summary>
    public CheckLoad LoadChecks()
    {
        lock (_lock)
        {
            using var db = Open();
            using var command = db.CreateCommand();
            command.CommandText = $"SELECT id, CASE WHEN length(payload) <= {MaximumPayloadBytes} THEN payload END FROM checks ORDER BY ended DESC, rowid DESC LIMIT {Retention}";
            using var reader = command.ExecuteReader();
            var checks = new List<CheckRecord>();
            var skipped = 0;
            while (reader.Read())
            {
                try
                {
                    if (Guid.TryParse(reader.GetString(0), out var id) && !reader.IsDBNull(1) &&
                        JsonSerializer.Deserialize<CheckRecord>(reader.GetFieldValue<byte[]>(1), Json) is { Result.Notes: not null } check &&
                        check.Id == id)
                        checks.Add(check);
                    else
                        skipped++;
                }
                catch (JsonException) { skipped++; }
            }
            return new CheckLoad(checks, skipped == 0 ? null : $"{skipped} damaged checks could not be loaded.");
        }
    }

    public void Delete(Guid id) => Delete("DELETE FROM runs WHERE id = $id", id);
    public void Clear() => Delete("DELETE FROM runs; DELETE FROM checks", null);

    private void Delete(string sql, Guid? id)
    {
        lock (_lock)
        {
            using var db = Open();
            using var command = db.CreateCommand();
            command.CommandText = sql;
            if (id is { } key)
                command.Parameters.AddWithValue("$id", key.ToString("D"));
            command.ExecuteNonQuery();
        }
    }

    private HistoryLoad Read()
    {
        using var db = Open();
        using var command = db.CreateCommand();
        command.CommandText = "PRAGMA quick_check(1)";
        if (!string.Equals(command.ExecuteScalar() as string, "ok", StringComparison.Ordinal))
            throw new SqliteException("History integrity check failed.", 11);
        command.CommandText = $"SELECT id, CASE WHEN length(payload) <= {MaximumPayloadBytes} THEN payload END FROM runs ORDER BY ended DESC, rowid DESC LIMIT {Retention}";
        using var reader = command.ExecuteReader();
        var entries = new List<HistoryEntry>();
        var skipped = 0;
        while (reader.Read())
        {
            try
            {
                if (Guid.TryParse(reader.GetString(0), out var id) && !reader.IsDBNull(1) &&
                    JsonSerializer.Deserialize<MeasurementResult>(reader.GetFieldValue<byte[]>(1), Json) is { } run &&
                    Valid(run))
                    entries.Add(new HistoryEntry(id, run));
                else
                    skipped++;
            }
            catch (JsonException) { skipped++; }
        }
        return new HistoryLoad(entries, skipped == 0 ? null : $"{skipped} damaged history entries could not be loaded.");
    }

    private static bool Valid(MeasurementResult run) =>
        run.Options?.Endpoint is { IsAbsoluteUri: true } origin &&
        MeasurementProtocol.TryOrigin(origin.AbsoluteUri, out _) && run.Paths is not null &&
        run.SystemDns is not null && run.Notes is not null &&
        (run.Idle is null || run.Idle.Milliseconds is not null) &&
        ValidTransfer(run.Download) && ValidTransfer(run.Upload) &&
        (run.Repeats is null || (run.Repeats.Count <= 3 && run.Repeats.All(child =>
            child is { Repeats: null } && Valid(child))));

    private static bool ValidTransfer(TransferMeasurement? transfer) => transfer is null ||
        (transfer.Samples is not null && transfer.Loaded?.Milliseconds is not null);

    private SqliteConnection Open()
    {
        _ = Provider.Value;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(filename))!);
        var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = filename,
            Pooling = false,
            DefaultTimeout = 3
        }.ToString());
        try
        {
            db.Open();
            using var command = db.CreateCommand();
            command.CommandText = "PRAGMA user_version";
            var version = Convert.ToInt32(command.ExecuteScalar());
            if (version is < 0 or > SchemaVersion)
                throw new InvalidDataException("This history database requires a newer version of Netcheck.");
            command.CommandText = "PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;";
            command.ExecuteNonQuery();
            if (version < SchemaVersion)
            {
                // Keep one untouched copy of history from before the upgrade (e.g. history.db.before-v3).
                var backup = $"{filename}.before-v{SchemaVersion}";
                if (version > 0 && !File.Exists(backup))
                {
                    db.Close();
                    File.Copy(filename, backup);
                    db.Open();
                }
                Migrate(db);
            }
            return db;
        }
        catch
        {
            db.Dispose();
            throw;
        }
    }

    private static void Migrate(SqliteConnection db)
    {
        using var transaction = db.BeginTransaction();
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA user_version";
        var version = Convert.ToInt32(command.ExecuteScalar());
        if (version == 0)
        {
            command.CommandText = "CREATE TABLE runs(id TEXT NOT NULL PRIMARY KEY, ended INTEGER NOT NULL, payload BLOB NOT NULL); PRAGMA user_version=1;";
            command.ExecuteNonQuery();
            version = 1;
        }
        if (version == 1)
        {
            command.CommandText = "CREATE INDEX runs_ended ON runs(ended DESC); PRAGMA user_version=2;";
            command.ExecuteNonQuery();
            version = 2;
        }
        if (version == 2)
        {
            command.CommandText = "CREATE TABLE IF NOT EXISTS checks(id TEXT NOT NULL PRIMARY KEY, ended INTEGER NOT NULL, payload BLOB NOT NULL); " +
                "CREATE INDEX IF NOT EXISTS checks_ended ON checks(ended DESC); PRAGMA user_version=3;";
            command.ExecuteNonQuery();
            version = 3;
        }
        if (version != SchemaVersion)
            throw new InvalidDataException("Unsupported history schema.");
        transaction.Commit();
    }

    private sealed class AddressConverter : JsonConverter<IPAddress>
    {
        public override IPAddress Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            reader.TokenType == JsonTokenType.String && IPAddress.TryParse(reader.GetString(), out var address)
                ? address : throw new JsonException("Invalid stored IP address.");

        public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value.ToString());
    }
}
