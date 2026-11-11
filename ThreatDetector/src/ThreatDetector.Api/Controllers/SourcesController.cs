using Microsoft.AspNetCore.Mvc;
using ThreatDetector.Parsing.Feeds;

namespace ThreatDetector.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class SourcesController : ControllerBase
{
    private readonly RssFeedParser _rssParser;
    private readonly ILogger<SourcesController> _logger;

    public SourcesController(RssFeedParser rssParser, ILogger<SourcesController> logger)
    {
        _rssParser = rssParser;
        _logger = logger;
    }

    [HttpPost("rss")]
    public IActionResult AddRssFeed([FromBody] RssFeedRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Url))
        {
            return BadRequest(new { error = "url is required" });
        }

        try
        {
            var added = _rssParser.AddFeed(request.Url.Trim());
            _logger.LogInformation("RSS feed {Status}: {Url}", added ? "added" : "already present", request.Url);
            return Ok(new { status = added ? "added" : "exists", url = request.Url });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpGet]
    public IActionResult ListSources()
    {
        var health = _rssParser.GetFeedStatuses()
            .ToDictionary(s => s.Url, StringComparer.OrdinalIgnoreCase);

        var sources = _rssParser.GetFeedUrls()
            .Select(u =>
            {
                health.TryGetValue(u, out var status);
                return (object)new
                {
                    type = "rss",
                    name = new Uri(u).Host,
                    url = u,
                    status = status?.Status ?? "pending",
                    documents = status?.Documents ?? 0,
                    lastChecked = status?.CheckedAt,
                    error = status?.Error,
                };
            })
            .Append(new
            {
                type = "nvd",
                name = "NVD CVE Feed",
                url = (string?)null,
                status = "active",
                documents = (int?)null,
                lastChecked = (DateTime?)null,
                error = (string?)null,
            })
            .ToList();

        return Ok(new { count = sources.Count, sources });
    }
}

public class RssFeedRequest
{
    public string Url { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}
