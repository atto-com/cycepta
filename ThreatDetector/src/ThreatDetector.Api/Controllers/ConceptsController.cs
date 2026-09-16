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
        var concepts = await _storage.GetRecentConceptsAsync(limit);
        return Ok(new { concepts, total = concepts.Count });
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetConcept(string id)
    {
        var recent = await _storage.GetRecentConceptsAsync(limit: 5000);
        var concept = recent.FirstOrDefault(c =>
            string.Equals(c.ConceptId, id, StringComparison.OrdinalIgnoreCase));
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
        var periods = await _storage.GetPeriodsAsync(limit);
        return Ok(new { periods, total = periods.Count });
    }
}