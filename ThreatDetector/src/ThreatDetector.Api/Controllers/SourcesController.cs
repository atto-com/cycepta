using Microsoft.AspNetCore.Mvc;
using ThreatDetector.Api.Services;
using ThreatDetector.Parsing.Channels;

namespace ThreatDetector.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class SourcesController : ControllerBase
{
    private readonly DataIngestionChannel _ingestionChannel;
    private readonly ILogger<SourcesController> _logger;

    public SourcesController(DataIngestionChannel ingestionChannel, ILogger<SourcesController> logger)
    {
        _ingestionChannel = ingestionChannel;
        _logger = logger;
    }

    [HttpPost("rss")]
    public async Task<IActionResult> AddRssFeed([FromBody] RssFeedRequest request)
    {
        _logger.LogInformation("Adding RSS feed: {Url}", request.Url);
        return Ok(new { status = "added", url = request.Url });
    }

    [HttpGet]
    public IActionResult ListSources()
    {
        return Ok(new
        {
            sources = new[]
            {
                new { type = "rss", name = "Krebs on Security", status = "active" },
                new { type = "rss", name = "The Hacker News", status = "active" },
                new { type = "nvd", name = "NVD CVE Feed", status = "active" },
            }
        });
    }
}

public class RssFeedRequest
{
    public string Url { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}
