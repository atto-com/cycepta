using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Json;
using System.Text.Json;
using ThreatDetector.Api.Services;
using ThreatDetector.Models;
using ThreatDetector.Parsing.Feeds;
using ThreatDetector.Parsing.Feeds.CveFeedParser;

namespace ThreatDetector.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class AnalyzeController : ControllerBase
{
    private readonly RssFeedParser _rssParser;
    private readonly CveFeedParser _cveParser;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ConceptPersistenceService _persistence;
    private readonly IConfiguration _config;
    private readonly ILogger<AnalyzeController> _logger;

    public AnalyzeController(
        RssFeedParser rssParser,
        CveFeedParser cveParser,
        IHttpClientFactory httpClientFactory,
        ConceptPersistenceService persistence,
        IConfiguration config,
        ILogger<AnalyzeController> logger)
    {
        _rssParser = rssParser;
        _cveParser = cveParser;
        _httpClientFactory = httpClientFactory;
        _persistence = persistence;
        _config = config;
        _logger = logger;
    }

    private string NcdUrl => _config["NcdService:Url"] ?? "http://localhost:5000";

    [HttpPost("fetch-and-analyze")]
    public async Task<IActionResult> FetchAndAnalyze([FromQuery] string source = "all")
    {
        var allDocs = new List<ParsedDocument>();

        // 1. Fetch from RSS feeds
        if (source == "all" || source == "rss")
        {
            _logger.LogInformation("Fetching RSS feeds...");
            var rssDocs = await _rssParser.ParseAllFeedsAsync();
            allDocs.AddRange(rssDocs);
            _logger.LogInformation("Fetched {Count} documents from RSS", rssDocs.Count);
        }

        // 2. Fetch from NVD
        if (source == "all" || source == "nvd")
        {
            _logger.LogInformation("Fetching CVEs from NVD...");
            var cveDocs = await _cveParser.FetchRecentCvesAsyncParse(lastModDays: 7, ct: HttpContext.RequestAborted);
            allDocs.AddRange(cveDocs);
            _logger.LogInformation("Fetched {Count} CVEs from NVD", cveDocs.Count);
        }

        if (allDocs.Count == 0)
        {
            return Ok(new DetectionResult
            {
                PeriodId = "empty",
                ConceptsFound = 0,
                Concepts = new List<DetectedConcept>(),
                TotalDocuments = 0,
            });
        }

        // 3. Send to Python NCD service
        try
        {
            var client = _httpClientFactory.CreateClient();
            client.BaseAddress = new Uri(NcdUrl);

            var periodId = $"web_{DateTime.UtcNow:yyyyMMdd_HHmmss}";
            var batch = new DocumentBatch
            {
                Documents = allDocs,
                PeriodId = periodId,
            };

            _logger.LogInformation("Sending {Count} documents to NCD engine...", allDocs.Count);
            var response = await client.PostAsJsonAsync("/api/v1/detect", batch);

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                _logger.LogError("NCD service error: {Error}", error);
                return StatusCode(502, new { error = "NCD service error", details = error });
            }

            var result = await response.Content.ReadFromJsonAsync<DetectionResult>()
                ?? new DetectionResult { PeriodId = periodId, Concepts = new List<DetectedConcept>() };

            _logger.LogInformation("NCD returned {Count} concepts", result.Concepts?.Count ?? 0);

            // 4. Persist documents + concepts + per-period events
            await _persistence.PersistAsync(allDocs, result.Concepts ?? new List<DetectedConcept>(), result);

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to reach NCD service");
            return StatusCode(502, new { error = "Cannot reach NCD service", details = ex.Message });
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
}