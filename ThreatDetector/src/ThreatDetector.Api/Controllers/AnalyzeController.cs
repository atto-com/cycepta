using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;
using ThreatDetector.Api.Hubs;
using ThreatDetector.Api.Services;
using ThreatDetector.Models;
using ThreatDetector.Parsing.Feeds;

namespace ThreatDetector.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class AnalyzeController : ControllerBase
{
    private readonly RssFeedParser _rssParser;
    private readonly CveFeedParser _cveParser;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ConceptPersistenceService _persistence;
    private readonly IHubContext<ThreatHub> _hub;
    private readonly IConfiguration _config;
    private readonly ILogger<AnalyzeController> _logger;

    public AnalyzeController(
        RssFeedParser rssParser,
        CveFeedParser cveParser,
        IHttpClientFactory httpClientFactory,
        ConceptPersistenceService persistence,
        IHubContext<ThreatHub> hub,
        IConfiguration config,
        ILogger<AnalyzeController> logger)
    {
        _rssParser = rssParser;
        _cveParser = cveParser;
        _httpClientFactory = httpClientFactory;
        _persistence = persistence;
        _hub = hub;
        _config = config;
        _logger = logger;
    }

    private string NcdUrl => _config["NcdService:Url"] ?? "http://localhost:5000";

    private int NcdTimeoutSeconds =>
        Math.Max(30, _config.GetValue("NcdService:TimeoutSeconds", 300));

    private int AnalysisChunkSize =>
        Math.Clamp(_config.GetValue("Ingest:AnalysisChunkSize", 250), 25, 1000);

    private FeedFetchOptions FeedFetch => new()
    {
        TimeoutSeconds = Math.Clamp(_config.GetValue("Ingest:FeedTimeoutSeconds", 15), 5, 60),
        BudgetSeconds = Math.Clamp(_config.GetValue("Ingest:FeedBudgetSeconds", 120), 15, 600),
        Concurrency = Math.Clamp(_config.GetValue("Ingest:FeedConcurrency", 12), 1, 32),
    };

    // One full fetch+analyze at a time: the NCD engine serializes batches
    // anyway, and overlapping runs would hammer the external feeds.
    private static readonly SemaphoreSlim AnalysisGate = new(1, 1);

    [HttpPost("fetch-and-analyze")]
    public async Task<IActionResult> FetchAndAnalyze([FromQuery] string source = "all")
    {
        if (!await AnalysisGate.WaitAsync(0))
        {
            return Conflict(new { error = "An analysis is already running" });
        }

        try
        {
            return await FetchAndAnalyzeCore(source);
        }
        finally
        {
            AnalysisGate.Release();
        }
    }

    [HttpPost("from-date")]
    public async Task<IActionResult> AnalyzeFromDate([FromQuery] string date)
    {
        if (string.IsNullOrEmpty(date))
        {
            return BadRequest(new { error = "Date parameter is required" });
        }

        // Start analysis from the specified date
        return Ok(new { status = "started", source = "date", date = date });
    }

    private async Task<IActionResult> FetchAndAnalyzeCore(string source)
    {
        var allDocs = new List<ParsedDocument>();
        var perSourceCap = _config.GetValue("Ingest:PerSourceCap", 50);
        var globalCap = _config.GetValue("Ingest:GlobalCap", 1300);

        await ReportProgressAsync(
            "fetching",
            source == "nvd" ? "Fetching CVEs from NVD..." : "Fetching RSS feeds...",
            0, 0, 0);

        // 1. Fetch from RSS feeds
        if (source == "all" || source == "rss")
        {
            _logger.LogInformation("Fetching RSS feeds...");
            var rssDocs = await _rssParser.ParseAllFeedsAsync(
                perSourceCap,
                globalCap,
                options: FeedFetch,
                onProgress: progress => ReportProgressAsync(
                    "fetching",
                    $"Fetching feeds: {progress.Completed}/{progress.Total} sources, " +
                    $"{progress.Documents} documents",
                    progress.Completed,
                    progress.Total,
                    0));
            allDocs.AddRange(rssDocs);
            var rssSources = rssDocs
                .Select(d => d.Source)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            _logger.LogInformation(
                "Fetched {Count} documents from RSS across {Sources} sources",
                rssDocs.Count, rssSources);
            await ReportProgressAsync(
                "fetching",
                $"Fetched {rssDocs.Count} documents from {rssSources} RSS sources",
                0, 0, 0);
            if (source == "all")
            {
                await ReportProgressAsync("fetching", "Fetching CVEs from NVD...", 0, 0, 0);
            }
        }

        // 2. Fetch from NVD
        if (source == "all" || source == "nvd")
        {
            _logger.LogInformation("Fetching CVEs from NVD...");
            var cveDocs = (await _cveParser.FetchRecentCvesAsync(lastModDays: 7)).Take(perSourceCap).ToList();
            allDocs.AddRange(cveDocs);
            _logger.LogInformation("Fetched {Count} CVEs from NVD", cveDocs.Count);
        }

        if (allDocs.Count == 0)
        {
            await ReportProgressAsync("done", "No new documents were fetched.", 0, 0, 0);
            return Ok(new DetectionResult
            {
                PeriodId = "empty",
                ConceptsFound = 0,
                Concepts = new List<DetectedConcept>(),
                TotalDocuments = 0,
            });
        }

        // Hard cap per the NCD detect schema (text max_length=10000); guards
        // every source, not just the RSS parser.
        foreach (var d in allDocs)
        {
            if (d.Text.Length > 10000)
            {
                d.Text = d.Text[..10000];
            }
        }

        // 3. Send to Python NCD service in batches. Concepts from each finished
        //    batch are persisted immediately and pushed over SignalR, so the
        //    dashboard can draw them while the remaining batches are running.
        var client = _httpClientFactory.CreateClient();
        client.BaseAddress = new Uri(NcdUrl);
        client.Timeout = TimeSpan.FromSeconds(NcdTimeoutSeconds);

        var chunkSize = AnalysisChunkSize;
        var chunks = new List<List<ParsedDocument>>();
        for (var offset = 0; offset < allDocs.Count; offset += chunkSize)
        {
            chunks.Add(allDocs.GetRange(offset, Math.Min(chunkSize, allDocs.Count - offset)));
        }

        var periodBase = $"web_{DateTime.UtcNow:yyyyMMdd_HHmmss}";
        var conceptsById = new Dictionary<string, DetectedConcept>(StringComparer.OrdinalIgnoreCase);
        var elapsed = Stopwatch.StartNew();

        _logger.LogInformation(
            "Sending {Count} documents to NCD engine in {Batches} batches of up to {ChunkSize}...",
            allDocs.Count, chunks.Count, chunkSize);
        await ReportProgressAsync(
            "analyzing",
            $"Analyzing {allDocs.Count} documents in {chunks.Count} batches...",
            0, chunks.Count, 0);

        for (var part = 0; part < chunks.Count; part++)
        {
            var chunk = chunks[part];
            var periodId = $"{periodBase}_b{part + 1}";
            var batch = new DocumentBatch
            {
                Documents = chunk,
                PeriodId = periodId,
            };

            _logger.LogInformation(
                "Sending batch {Part}/{Total} ({Count} documents) to NCD engine...",
                part + 1, chunks.Count, chunk.Count);

            DetectionResult result;
            try
            {
                using var response = await client.PostAsJsonAsync("/api/v1/detect", batch);
                if (!response.IsSuccessStatusCode)
                {
                    var error = await response.Content.ReadAsStringAsync();
                    _logger.LogError("NCD service error on batch {Part}: {Error}", part + 1, error);
                    return StatusCode(502, new { error = "NCD service error", details = error });
                }

                result = await response.Content.ReadFromJsonAsync<DetectionResult>()
                    ?? new DetectionResult { PeriodId = periodId };
            }
            catch (TaskCanceledException ex)
            {
                _logger.LogError(ex, "NCD batch {Part}/{Total} timed out after {Seconds}s",
                    part + 1, chunks.Count, NcdTimeoutSeconds);
                return StatusCode(504, new
                {
                    error = "NCD analysis timed out",
                    details = $"Batch {part + 1}/{chunks.Count} exceeded {NcdTimeoutSeconds}s. " +
                              "Concepts from finished batches are already on the map.",
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reach NCD service at {Url}", NcdUrl);
                return StatusCode(502, new
                {
                    error = "Cannot reach NCD service",
                    details = $"NCD at {NcdUrl}: {ex.Message}",
                });
            }

            result.PeriodId = periodId;
            result.Concepts ??= new List<DetectedConcept>();

            // 4. Persist this batch before moving on: PersistAsync also pushes
            //    one ConceptUpdate per concept, which refreshes the heatmap.
            await _persistence.PersistAsync(chunk, result.Concepts, result);

            foreach (var concept in result.Concepts)
            {
                if (!string.IsNullOrWhiteSpace(concept.ConceptId))
                {
                    conceptsById[concept.ConceptId] = concept;
                }
            }

            _logger.LogInformation(
                "Batch {Part}/{Total}: {BatchConcepts} concepts, {TotalConcepts} total",
                part + 1, chunks.Count, result.Concepts.Count, conceptsById.Count);

            await ReportProgressAsync(
                "analyzing",
                $"Batch {part + 1}/{chunks.Count}: {conceptsById.Count} concepts on the map",
                part + 1, chunks.Count, conceptsById.Count);
        }

        elapsed.Stop();
        var aggregate = new DetectionResult
        {
            PeriodId = periodBase,
            ConceptsFound = conceptsById.Count,
            Concepts = conceptsById.Values.ToList(),
            ProcessingTimeMs = elapsed.Elapsed.TotalMilliseconds,
            TotalDocuments = allDocs.Count,
        };

        _logger.LogInformation(
            "NCD returned {Count} concepts across {Batches} batches",
            aggregate.ConceptsFound, chunks.Count);
        await ReportProgressAsync(
            "done",
            $"Analysis complete: {aggregate.ConceptsFound} concepts",
            chunks.Count, chunks.Count, aggregate.ConceptsFound);

        return Ok(aggregate);
    }

    private async Task ReportProgressAsync(string stage, string message, int current, int total, int concepts)
    {
        try
        {
            await _hub.Clients.All.SendAsync("AnalysisProgress", new AnalysisProgress
            {
                Stage = stage,
                Message = message,
                Current = current,
                Total = total,
                Concepts = concepts,
            });
        }
        catch (Exception ex)
        {
            // Progress is best-effort; a dropped SignalR client must never
            // abort an analysis that is already running.
            _logger.LogDebug(ex, "Analysis progress push failed");
        }
    }

    [HttpGet("sources")]
    public IActionResult GetSources()
    {
        return Ok(new
        {
            rss = _rssParser.GetFeedUrls().Select(u => new { url = u }),
        });
    }

    [HttpPost("summarize")]
    public async Task<IActionResult> Summarize([FromBody] JsonElement payload)
    {
        try
        {
            var client = _httpClientFactory.CreateClient();
            client.BaseAddress = new Uri(NcdUrl);
            // The NCD report may take minutes on CPU/small GPUs while the
            // local model writes item summaries in memory-safe batches.
            client.Timeout = TimeSpan.FromSeconds(600);
            var response = await client.PostAsJsonAsync("/api/v1/summarize", payload, CancellationToken.None);
            var content = await response.Content.ReadAsStringAsync();
            if (response.IsSuccessStatusCode)
            {
                return Ok(JsonSerializer.Deserialize<JsonElement>(content));
            }
            return StatusCode(502, new { error = "LLM summarization service error", details = content });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to reach LLM summarization service");
            return StatusCode(502, new { error = "Cannot reach NCD service", details = ex.Message });
        }
    }

    [HttpGet("llm-providers")]
    public async Task<IActionResult> GetLlmProviders()
    {
        try
        {
            var client = _httpClientFactory.CreateClient();
            client.BaseAddress = new Uri(NcdUrl);
            var response = await client.GetAsync("/api/v1/llm/providers");
            var content = await response.Content.ReadAsStringAsync();
            if (response.IsSuccessStatusCode)
            {
                return Ok(JsonSerializer.Deserialize<JsonElement>(content));
            }
            return StatusCode(502, new { error = "LLM provider registry error", details = content });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to reach LLM provider registry");
            return StatusCode(502, new { error = "Cannot reach NCD service", details = ex.Message });
        }
    }
}