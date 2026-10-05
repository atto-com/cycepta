namespace ThreatDetector.Models;

public class ParsedDocument
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Text { get; set; } = string.Empty;
    public string Source { get; set; } = "unknown";
    public DateTime? Timestamp { get; set; } = DateTime.UtcNow;
    public Dictionary<string, string> Metadata { get; set; } = new();
}

public class DocumentBatch
{
    public List<ParsedDocument> Documents { get; set; } = new();
    public string? PeriodId { get; set; }
}

public class DetectedConcept
{
    public string ConceptId { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public List<string> Sentences { get; set; } = new();
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;
    public int DocumentCount { get; set; } = 0;
    public double Strength { get; set; } = 0.0;
    public List<double> Coordinates { get; set; } = new();
    public string Source { get; set; } = string.Empty;
}

public class DetectionResult
{
    public string PeriodId { get; set; } = string.Empty;
    public int ConceptsFound { get; set; }
    public List<DetectedConcept> Concepts { get; set; } = new();
    public double ProcessingTimeMs { get; set; }
    public int TotalDocuments { get; set; }
    public HeatmapDiffSummary? HeatmapDiffSummary { get; set; }
}

public class HeatmapDiffSummary
{
    public double MaxDiff { get; set; }
    public double MeanDiff { get; set; }
    public int NonzeroBins { get; set; }
    public int Units { get; set; }
    public int NovelConcepts { get; set; }
    public double Drift { get; set; }
    public bool DriftAlert { get; set; }
    public string ClusterMode { get; set; } = "";
}

public class HealthResponse
{
    public string Status { get; set; } = "ok";
    public bool ModelLoaded { get; set; }
    public string ModelName { get; set; } = "";
    public string Device { get; set; } = "";
    public int PeriodsProcessed { get; set; }
    public double UptimeSeconds { get; set; }
}

public class ThreatAlert
{
    public string ConceptId { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public List<string> SampleSentences { get; set; } = new();
    public double Strength { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public string Source { get; set; } = string.Empty;
}

public class ConceptUpdate
{
    public string EventType { get; set; } = string.Empty; // new_concept, concept_evolved
    public ThreatAlert Alert { get; set; } = new();
}

public class DashboardMetrics
{
    public int DocumentsProcessed { get; set; }
    public int ConceptsDetected { get; set; }
    public int ActiveSources { get; set; }
    public double ProcessingRate { get; set; } // docs per second
    public TimeSpan Uptime { get; set; }
}
