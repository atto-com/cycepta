using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using ThreatDetector.Models;

namespace ThreatDetector.Parsing.Feeds;

public class RssFeedParser
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<RssFeedParser> _logger;

    private static readonly string[] SecurityFeeds = new[]
    {
        "https://krebsonsecurity.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.securityweek.com/feed",
        "https://www.bleepingcomputer.com/feed/",
        "https://threatpost.com/feed/",
    };

    public RssFeedParser(HttpClient httpClient, ILogger<RssFeedParser> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<List<ParsedDocument>> ParseFeedAsync(string feedUrl, CancellationToken ct = default)
    {
        var documents = new List<ParsedDocument>();

        try
        {
            var response = await _httpClient.GetStringAsync(feedUrl, ct);
            var doc = XDocument.Parse(response);

            var items = doc.Descendants("item");
            foreach (var item in items)
            {
                var title = item.Element("title")?.Value ?? "";
                var description = item.Element("description")?.Value ?? "";
                var link = item.Element("link")?.Value ?? "";
                var pubDate = item.Element("pubDate")?.Value ?? "";

                // Strip HTML tags from description
                var cleanDesc = System.Text.RegularExpressions.Regex.Replace(description, "<.*?>", "");

                if (!string.IsNullOrWhiteSpace(title) || !string.IsNullOrWhiteSpace(cleanDesc))
                {
                    documents.Add(new ParsedDocument
                    {
                        Text = $"{title}. {cleanDesc}".Trim(),
                        Source = $"rss:{new Uri(feedUrl).Host}",
                        Timestamp = DateTime.TryParse(pubDate, out var dt) ? dt : DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["url"] = link,
                            ["feed"] = feedUrl,
                        },
                    });
                }
            }

            _logger.LogDebug("Parsed {Count} items from {Feed}", documents.Count, feedUrl);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse RSS feed {Feed}", feedUrl);
        }

        return documents;
    }

    public async Task<List<ParsedDocument>> ParseAllFeedsAsync(CancellationToken ct = default)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(25));

        var tasks = SecurityFeeds.Select(feed => ParseFeedAsync(feed, timeoutCts.Token));
        var results = await Task.WhenAll(tasks);

        var allDocs = new List<ParsedDocument>();
        foreach (var docs in results)
        {
            allDocs.AddRange(docs);
        }

        return allDocs;
    }

    public IEnumerable<string> GetFeedUrls() => SecurityFeeds;
}
