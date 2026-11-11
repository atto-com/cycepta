using Microsoft.AspNetCore.Mvc;
using ThreatDetector.Models;
using ThreatDetector.Storage;

namespace ThreatDetector.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class ConceptsController : ControllerBase
{
    private readonly ThreatStorage _storage;
    private readonly ILogger<ConceptsController> _logger;

    public ConceptsController(ThreatStorage storage, ILogger<ConceptsController> logger)
    {
        _storage = storage;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> GetConcepts([FromQuery] int limit = 50)
    {
        // Bound caller-controlled paging: an unbounded limit lets one request
        // serialize the whole concept table.
        var concepts = await _storage.GetRecentConceptsAsync(Math.Clamp(limit, 1, 1000));
        var links = await _storage.GetConceptDocumentsAsync(concepts.Select(c => c.ConceptId));

        var items = concepts.Select(c =>
        {
            List<object> documents = new();
            if (links.TryGetValue(c.ConceptId, out var linkList))
            {
                documents = linkList
                    .Where(l => !string.IsNullOrWhiteSpace(l.Url))
                    .GroupBy(l => l.Url)
                    .Select(g => new { url = g.Key, source = g.First().Source })
                    .Take(12)
                    .Cast<object>()
                    .ToList();
            }

            return new
            {
                ConceptId = c.ConceptId,
                Label = c.Label,
                Summary = c.Summary,
                Sentences = c.Sentences,
                FirstSeen = c.FirstSeen,
                LastSeen = c.LastSeen,
                DocumentCount = c.DocumentCount,
                Strength = c.Strength,
                Coordinates = c.Coordinates,
                Source = c.Source,
                Emerging = c.Emerging,
                Documents = documents,
            };
        });

        return Ok(new { concepts = items, total = concepts.Count });
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetConcept(string id)
    {
        var concept = await _storage.GetConceptAsync(id);
        if (concept is null)
        {
            return NotFound(new { error = "Concept not found", conceptId = id });
        }

        var history = await _storage.GetConceptHistoryAsync(id);
        return Ok(new { concept, history });
    }

    [HttpGet("{id}/history")]
    public async Task<IActionResult> GetConceptHistory(string id)
    {
        var history = await _storage.GetConceptHistoryAsync(id);
        return Ok(new { conceptId = id, history });
    }

    [HttpGet("periods")]
    public async Task<IActionResult> GetPeriods([FromQuery] int limit = 1000)
    {
        var periods = await _storage.GetPeriodsAsync(Math.Clamp(limit, 1, 1000));
        return Ok(new { periods, total = periods.Count });
    }
}