using Microsoft.Data.Sqlite;
using Dapper;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using ThreatDetector.Models;

namespace ThreatDetector.Storage;

public class ThreatStorage : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly string _dbPath;

    public ThreatStorage(string? dbPath = null)
    {
        _dbPath = dbPath
            ?? Environment.GetEnvironmentVariable("THREAT_DB_PATH")
            ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "ThreatDetector",
                "threats.db");

        Directory.CreateDirectory(Path.GetDirectoryName(_dbPath)!);
        _connection = new SqliteConnection($"Data Source={_dbPath}");
        _connection.Open();
        InitializeDatabase();
    }

    private void InitializeDatabase()
    {
        _connection.Execute(@"
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
        ");
    }

    public async Task SaveDocumentAsync(ParsedDocument doc)
    {
        await _connection.ExecuteAsync(
            "INSERT OR REPLACE INTO documents (id, text, source, timestamp, metadata) VALUES (@Id, @Text, @Source, @Timestamp, @Metadata)",
            new { doc.Id, doc.Text, doc.Source, doc.Timestamp, Metadata = JsonConvert.SerializeObject(doc.Metadata) });
    }

    public async Task SaveConceptAsync(DetectedConcept concept)
    {
        await _connection.ExecuteAsync(
            "INSERT OR REPLACE INTO concepts (id, label, summary, first_seen, last_seen, document_count, strength, coordinates, source, sentences) " +
            "VALUES (@ConceptId, @Label, @Summary, @FirstSeen, @LastSeen, @DocumentCount, @Strength, @Coordinates, @Source, @Sentences)",
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
            });
    }

    /// <summary>
    /// Record a per-period snapshot of a concept (used for temporal history/sparklines).
    /// </summary>
    public async Task SaveConceptEventAsync(DetectedConcept concept, string eventType)
    {
        var payload = new
        {
            periodId = concept.Source,
            strength = concept.Strength,
            coordinates = concept.Coordinates,
            label = concept.Label,
            documentCount = concept.DocumentCount,
        };
        await _connection.ExecuteAsync(
            "INSERT INTO concept_events (concept_id, event_type, payload) VALUES (@ConceptId, @EventType, @Payload)",
            new { ConceptId = concept.ConceptId, EventType = eventType, Payload = JsonConvert.SerializeObject(payload) });
    }

    public async Task<List<Dictionary<string, object>>> GetConceptHistoryAsync(string conceptId, int limit = 200)
    {
        var rows = await _connection.QueryAsync(
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

    public async Task<List<DetectedConcept>> GetRecentConceptsAsync(int limit = 50)
    {
        var rows = await _connection.QueryAsync(
            "SELECT * FROM concepts ORDER BY created_at DESC LIMIT @Limit",
            new { Limit = limit });

        return rows.Select(r =>
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
            };
        }).ToList();
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
        await _connection.ExecuteAsync(
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
                            c.ConceptId, c.Label, c.Summary, c.Strength, c.Coordinates, c.DocumentCount, emerging = true,
                        }).ToArray(),
                }),
            });
    }

    /// <summary>
    /// Ordered per-period snapshots for the global timeline.
    /// </summary>
    public async Task<List<Dictionary<string, object>>> GetPeriodsAsync(int limit = 1000)
    {
        var rows = await _connection.QueryAsync(
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
        return await _connection.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM documents");
    }

    public async Task<int> GetConceptCountAsync()
    {
        return await _connection.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM concepts");
    }

    public void Dispose()
    {
        _connection?.Dispose();
        GC.SuppressFinalize(this);
    }
}
