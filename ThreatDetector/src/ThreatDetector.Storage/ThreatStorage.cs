using Microsoft.Data.Sqlite;
using Dapper;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using ThreatDetector.Models;

namespace ThreatDetector.Storage;

/// <summary>
/// Member-document source link for one concept (dashboard "documents" field).
/// Accumulates across periods: INSERT OR IGNORE, rows are never deleted.
/// </summary>
public sealed record ConceptDocumentRow(string ConceptId, string DocId, string Url, string Source);

public class ThreatStorage : IDisposable
{
    // SQLite connections are not thread-safe. The API is a singleton and is
    // hit concurrently by the batching service, SignalR pushes and request
    // handlers, so every operation opens its own short-lived connection
    // instead of sharing one long-lived connection.
    private readonly string _connectionString;

    public ThreatStorage(string? dbPath = null)
    {
        var path = dbPath
            ?? Environment.GetEnvironmentVariable("THREAT_DB_PATH")
            ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "ThreatDetector",
                "threats.db");

        path = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            // Wait for a competing writer instead of throwing "database is
            // locked" on the first contention.
            DefaultTimeout = 10,
        }.ToString();
        InitializeDatabase();
    }

    private SqliteConnection CreateConnection() => new(_connectionString);

    private static void ConfigureConnection(SqliteConnection connection)
    {
        // journal_mode lives in the database header, but synchronous is a
        // per-connection setting: without this every short-lived connection
        // would silently fall back to FULL.
        connection.Execute("PRAGMA synchronous=NORMAL;");
    }

    private async Task<SqliteConnection> OpenConnectionAsync()
    {
        var connection = CreateConnection();
        await connection.OpenAsync();
        ConfigureConnection(connection);
        return connection;
    }

    private void InitializeDatabase()
    {
        using var connection = CreateConnection();
        connection.Open();
        // WAL lets readers proceed during a write; NORMAL is the standard
        // durability/throughput trade-off for a WAL database.
        connection.Execute("PRAGMA journal_mode=WAL;");
        ConfigureConnection(connection);
        connection.Execute(@"
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                text TEXT NOT NULL,
                source TEXT,
                timestamp DATETIME,
                metadata TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS concepts (
                id TEXT PRIMARY KEY,
                label TEXT,
                summary TEXT,
                first_seen DATETIME,
                last_seen DATETIME,
                document_count INTEGER DEFAULT 0,
                strength REAL DEFAULT 0.0,
                coordinates TEXT,
                source TEXT,
                sentences TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS concept_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                concept_id TEXT,
                event_type TEXT,
                payload TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (concept_id) REFERENCES concepts(id)
            );

            CREATE INDEX IF NOT EXISTS idx_documents_source ON documents(source);
            CREATE INDEX IF NOT EXISTS idx_documents_timestamp ON documents(timestamp);
            CREATE INDEX IF NOT EXISTS idx_concepts_first_seen ON concepts(first_seen);
            CREATE INDEX IF NOT EXISTS idx_concepts_created ON concepts(created_at);
            CREATE INDEX IF NOT EXISTS idx_concept_events_concept
                ON concept_events(concept_id, created_at);

            CREATE TABLE IF NOT EXISTS periods (
                period_id TEXT PRIMARY KEY,
                drift REAL DEFAULT 0.0,
                drift_alert INTEGER DEFAULT 0,
                max_diff REAL DEFAULT 0.0,
                mean_diff REAL DEFAULT 0.0,
                novel_concepts INTEGER DEFAULT 0,
                total_concepts INTEGER DEFAULT 0,
                total_documents INTEGER DEFAULT 0,
                cluster_mode TEXT,
                summary TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_periods_created ON periods(created_at);

            CREATE TABLE IF NOT EXISTS concept_documents (
                concept_id TEXT NOT NULL,
                doc_id TEXT NOT NULL,
                doc_url TEXT,
                doc_source TEXT,
                PRIMARY KEY (concept_id, doc_id)
            );

            CREATE INDEX IF NOT EXISTS idx_concept_documents_concept ON concept_documents(concept_id);
        ");

        // Migration: add the emerging column to DBs created before it existed
        // (CREATE TABLE IF NOT EXISTS above leaves old tables untouched).
        try
        {
            connection.Execute("ALTER TABLE concepts ADD COLUMN emerging INTEGER DEFAULT 0");
        }
        catch (SqliteException)
        {
            // duplicate column — already migrated
        }

        // Migration: MSRC publishes a non-permalink <guid>CVE-...</guid>
        // before the real <link>. Older parser builds stored that bare CVE id,
        // which the dashboard then resolved against localhost. Repair legacy
        // rows to the canonical MSRC advisory URL.
        connection.Execute(@"
            UPDATE concept_documents
            SET doc_url = 'https://msrc.microsoft.com/update-guide/vulnerability/' || doc_url
            WHERE doc_source = 'rss:api.msrc.microsoft.com'
              AND doc_url LIKE 'CVE-%'
              AND doc_url NOT LIKE 'http://%'
              AND doc_url NOT LIKE 'https://%';
        ");
    }

    public async Task SaveDocumentAsync(ParsedDocument doc)
    {
        await using var connection = await OpenConnectionAsync();
        await connection.ExecuteAsync(
            "INSERT OR REPLACE INTO documents (id, text, source, timestamp, metadata) VALUES (@Id, @Text, @Source, @Timestamp, @Metadata)",
            new { doc.Id, doc.Text, doc.Source, doc.Timestamp, Metadata = JsonConvert.SerializeObject(doc.Metadata) });
    }

    public async Task SaveConceptAsync(DetectedConcept concept)
    {
        await using var connection = await OpenConnectionAsync();
        await connection.ExecuteAsync(
            "INSERT OR REPLACE INTO concepts (id, label, summary, first_seen, last_seen, document_count, strength, coordinates, source, sentences, emerging) " +
            "VALUES (@ConceptId, @Label, @Summary, @FirstSeen, @LastSeen, @DocumentCount, @Strength, @Coordinates, @Source, @Sentences, @Emerging)",
            new
            {
                concept.ConceptId,
                concept.Label,
                concept.Summary,
                concept.FirstSeen,
                concept.LastSeen,
                concept.DocumentCount,
                concept.Strength,
                Coordinates = JsonConvert.SerializeObject(concept.Coordinates),
                concept.Source,
                Sentences = JsonConvert.SerializeObject(concept.Sentences),
                Emerging = concept.Emerging ? 1 : 0,
            });
    }

    /// <summary>
    /// Record a per-period snapshot of a concept (used for temporal history/sparklines).
    /// </summary>
    public async Task SaveConceptEventAsync(DetectedConcept concept, string eventType, string? periodId = null)
    {
        var payload = new
        {
            // The event period is the detection batch, not the feed name.
            periodId = string.IsNullOrWhiteSpace(periodId) ? concept.Source : periodId,
            strength = concept.Strength,
            coordinates = concept.Coordinates,
            label = concept.Label,
            documentCount = concept.DocumentCount,
        };
        await using var connection = await OpenConnectionAsync();
        await connection.ExecuteAsync(
            "INSERT INTO concept_events (concept_id, event_type, payload) VALUES (@ConceptId, @EventType, @Payload)",
            new { ConceptId = concept.ConceptId, EventType = eventType, Payload = JsonConvert.SerializeObject(payload) });
    }

    public async Task<List<Dictionary<string, object>>> GetConceptHistoryAsync(string conceptId, int limit = 200)
    {
        await using var connection = await OpenConnectionAsync();
        var rows = await connection.QueryAsync(
            "SELECT event_type, payload, created_at FROM concept_events WHERE concept_id = @Id ORDER BY created_at DESC LIMIT @Limit",
            new { Id = conceptId, Limit = limit });

        var history = new List<Dictionary<string, object>>();
        foreach (var row in rows)
        {
            var payload = JsonConvert.DeserializeObject<Dictionary<string, object>>(((string?)row.payload) ?? "{}") ?? new();
            payload["eventType"] = (string)row.event_type;
            payload["createdAt"] = ParseDate(row.created_at).ToString("o");
            history.Add(payload);
        }
        return history;
    }

    public async Task SaveConceptDocumentsAsync(IReadOnlyList<ConceptDocumentRow> rows)
    {
        if (rows.Count == 0) return;
        await using var connection = await OpenConnectionAsync();
        await using var tx = await connection.BeginTransactionAsync();
        try
        {
            await connection.ExecuteAsync(
                "INSERT OR IGNORE INTO concept_documents (concept_id, doc_id, doc_url, doc_source) VALUES (@ConceptId, @DocId, @Url, @Source)",
                rows.Select(r => new { r.ConceptId, r.DocId, r.Url, r.Source }), tx);
            await tx.CommitAsync();
        }
        catch
        {
            await tx.RollbackAsync();
            throw;
        }
    }

    public async Task<Dictionary<string, List<(string Url, string Source)>>> GetConceptDocumentsAsync(
        IEnumerable<string> conceptIds)
    {
        var ids = conceptIds.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var map = new Dictionary<string, List<(string Url, string Source)>>(StringComparer.OrdinalIgnoreCase);
        if (ids.Count == 0) return map;

        await using var connection = await OpenConnectionAsync();
        var rows = await connection.QueryAsync(
            "SELECT concept_id, doc_url, doc_source FROM concept_documents WHERE concept_id IN @Ids",
            new { Ids = ids });

        foreach (var row in rows)
        {
            var conceptId = (string)row.concept_id;
            if (!map.TryGetValue(conceptId, out var list))
            {
                list = new List<(string Url, string Source)>();
                map[conceptId] = list;
            }
            list.Add((((string?)row.doc_url) ?? "", ((string?)row.doc_source) ?? ""));
        }
        return map;
    }

    public async Task<List<DetectedConcept>> GetRecentConceptsAsync(int limit = 50)
    {
        await using var connection = await OpenConnectionAsync();
        var rows = await connection.QueryAsync(
            "SELECT * FROM concepts ORDER BY created_at DESC LIMIT @Limit",
            new { Limit = limit });

        return rows.Select(r => (DetectedConcept)MapConcept(r)).ToList();
    }

    public async Task<DetectedConcept?> GetConceptAsync(string id)
    {
        await using var connection = await OpenConnectionAsync();
        var row = await connection.QuerySingleOrDefaultAsync(
            "SELECT * FROM concepts WHERE id = @Id COLLATE NOCASE", new { Id = id });
        return row is null ? null : MapConcept(row);
    }

    private static DetectedConcept MapConcept(dynamic r)
    {
        var coordinates = JsonConvert.DeserializeObject<List<double>>(((string?)r.coordinates) ?? "[]") ?? new List<double>();
        var sentences = JsonConvert.DeserializeObject<List<string>>(((string?)r.sentences) ?? "[]") ?? new List<string>();
        return new DetectedConcept
        {
            ConceptId = (string)r.id,
            Label = ((string?)r.label) ?? "",
            Summary = ((string?)r.summary) ?? "",
            FirstSeen = ParseDate(r.first_seen),
            LastSeen = ParseDate(r.last_seen),
            DocumentCount = (int)Convert.ToInt64(r.document_count),
            Strength = (double)Convert.ToDouble(r.strength),
            Coordinates = coordinates,
            Source = ((string?)r.source) ?? "",
            Sentences = sentences,
            Emerging = Convert.ToInt64((object?)r.emerging ?? 0) == 1,
        };
    }

    private static DateTime ParseDate(object? value)
    {
        if (value is DateTime dt) return dt;
        if (value is string s && DateTime.TryParse(s, out var parsed)) return parsed.ToUniversalTime();
        if (value is IConvertible) return Convert.ToDateTime(value).ToUniversalTime();
        return DateTime.MinValue;
    }

    /// <summary>
    /// Persist a per-period snapshot (drift + detection summary) for the timeline (Feature E/F).
    /// </summary>
    public async Task SavePeriodAsync(DetectionResult result)
    {
        var h = result.HeatmapDiffSummary;
        await using var connection = await OpenConnectionAsync();
        await connection.ExecuteAsync(
            "INSERT OR REPLACE INTO periods (period_id, drift, drift_alert, max_diff, mean_diff, novel_concepts, total_concepts, total_documents, cluster_mode, summary, created_at) " +
            "VALUES (@PeriodId, @Drift, @DriftAlert, @MaxDiff, @MeanDiff, @NovelConcepts, @TotalConcepts, @TotalDocuments, @ClusterMode, @Summary, CURRENT_TIMESTAMP)",
            new
            {
                result.PeriodId,
                Drift = h?.Drift ?? 0.0,
                DriftAlert = h?.DriftAlert == true ? 1 : 0,
                MaxDiff = h?.MaxDiff ?? 0.0,
                MeanDiff = h?.MeanDiff ?? 0.0,
                NovelConcepts = h?.NovelConcepts ?? 0,
                TotalConcepts = result.Concepts?.Count ?? 0,
                TotalDocuments = result.TotalDocuments,
                ClusterMode = h?.ClusterMode ?? "",
                Summary = JsonConvert.SerializeObject(new
                {
                    periodId = result.PeriodId,
                    concepts = result.Concepts == null
                        ? Array.Empty<object>()
                        : result.Concepts.Select(c => new
                        {
                            c.ConceptId, c.Label, c.Summary, c.Strength, c.Coordinates, c.DocumentCount, emerging = c.Emerging,
                        }).ToArray(),
                }),
            });
    }

    /// <summary>
    /// Ordered per-period snapshots for the global timeline.
    /// </summary>
    public async Task<List<Dictionary<string, object>>> GetPeriodsAsync(int limit = 1000)
    {
        await using var connection = await OpenConnectionAsync();
        var rows = await connection.QueryAsync(
            "SELECT period_id, drift, drift_alert, max_diff, mean_diff, novel_concepts, total_concepts, total_documents, cluster_mode, summary, created_at " +
            "FROM periods ORDER BY created_at ASC LIMIT @Limit",
            new { Limit = limit });

        var periods = new List<Dictionary<string, object>>();
        foreach (var row in rows)
        {
            var summaryText = ((string?)row.summary) ?? "{}";
            var summary = JsonConvert.DeserializeObject<Dictionary<string, object>>(summaryText) ?? new();
            periods.Add(new Dictionary<string, object>
            {
                ["periodId"] = (string)row.period_id,
                ["drift"] = (double)Convert.ToDouble(row.drift),
                ["driftAlert"] = Convert.ToInt64(row.drift_alert) == 1,
                ["maxDiff"] = (double)Convert.ToDouble(row.max_diff),
                ["meanDiff"] = (double)Convert.ToDouble(row.mean_diff),
                ["novelConcepts"] = Convert.ToInt64(row.novel_concepts),
                ["totalConcepts"] = Convert.ToInt64(row.total_concepts),
                ["totalDocuments"] = Convert.ToInt64(row.total_documents),
                ["clusterMode"] = ((string?)row.cluster_mode) ?? "",
                ["concepts"] = NormalizePeriodConcepts(summary),
                ["createdAt"] = ParseDate(row.created_at).ToString("o"),
            });
        }
        return periods;
    }

    // Stored period concepts carry PascalCase keys (the anonymous object in
    // SavePeriodAsync bypasses the API's camelCase policy). Normalize them to the
    // same camelCase shape as the live analyze response and return plain CLR data
    // (System.Text.Json cannot serialize Newtonsoft JToken types cleanly).
    private static List<Dictionary<string, object?>> NormalizePeriodConcepts(Dictionary<string, object> summary)
    {
        if (!summary.TryGetValue("concepts", out var concepts) || concepts is not JArray arr)
            return new();

        var normalized = new List<Dictionary<string, object?>>();
        foreach (var item in arr)
        {
            if (item is not JObject jo)
                continue;
            var no = new Dictionary<string, object?>();
            foreach (var (pascal, camel) in new[]
            {
                ("ConceptId", "conceptId"), ("Label", "label"), ("Summary", "summary"),
                ("Strength", "strength"), ("Coordinates", "coordinates"),
                ("DocumentCount", "documentCount"), ("emerging", "emerging"),
            })
            {
                if (jo.TryGetValue(pascal, out var tok))
                    no[camel] = ToClrValue(tok);
            }
            foreach (var prop in jo.Properties())
            {
                if (!no.ContainsKey(prop.Name))
                    no[prop.Name] = ToClrValue(prop.Value);
            }
            normalized.Add(no);
        }
        return normalized;
    }

    private static object? ToClrValue(JToken tok)
    {
        switch (tok)
        {
            case JArray ja:
                return ja.Select(ToClrValue).ToList();
            case JValue jv:
                return jv.Value;
            default:
                return tok.ToString();
        }
    }

    public async Task<int> GetDocumentCountAsync()
    {
        await using var connection = await OpenConnectionAsync();
        return await connection.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM documents");
    }

    public async Task<int> GetConceptCountAsync()
    {
        await using var connection = await OpenConnectionAsync();
        return await connection.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM concepts");
    }

    public void Dispose()
    {
        // Connections are scoped per operation; nothing long-lived to release.
        GC.SuppressFinalize(this);
    }
}
