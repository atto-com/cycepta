using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using ThreatDetector.Models;
using ThreatDetector.Parsing.Feeds.RssFeedParser.RssFeedClient;

namespace ThreatDetector.Parsing.Feeds.RssFeedParser;

public class RssFeedParser
{
    private readonly ILogger<RssFeedParser> _logger;
    private readonly System.Text.RegularExpressions.Regex _htmlRegex = 
        new System.Text.RegularExpressions.Regex("<.*?>", System.Text.RegularExpressions.RegexOptions.Compiled);
    private readonly IHttpClientFactory _httpClientFactory;
    private static readonly string[] SecurityFeeds = new[]
    {
        "https://krebsonsecurity.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.securityweek.com/feed",
        "https://www.bleepingcomputer.com/feed/",
        "https://threatpost.com/feed/",
    };

    public RssFeedParser(ILogger<RssFeedParser> logger, IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<List<ParsedDocument>> ParseFeedAsync(string feedUrl, CancellationToken ct = default)
    {
        var documents = new List<ParsedDocument>();
        try
        {
            using var client = _httpClientFactory.CreateClient(RssClientClass.HttpClientName);
            var response = await client.GetStringAsync(feedUrl, ct).ConfigureAwait(false);

            if (response == null)
                return new List<ParsedDocument>();

            var host = Uri.TryCreate(feedUrl, UriKind.Absolute, out var uri) 
                ? uri.Host
                : string.Empty;

            var source = $"rss:{host}";

            // настройка ридера для игнорирования DTD и отключения XmlResolver для безопасности
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Ignore,
                XmlResolver = null
            };
            using var reader = XmlReader.Create(new StringReader(response), settings);
            var doc = XDocument.Load(reader);

            var items = doc.Descendants("item");
            foreach (var item in items)
            {
                var title = item.Element("title")?.Value ?? "";
                var description = item.Element("description")?.Value ?? "";
                var link = item.Element("link")?.Value ?? "";
                var pubDate = item.Element("pubDate")?.Value ?? "";

                // Strip HTML tags from description
                var cleanDesc = _htmlRegex.Replace(description, "");

                if (!string.IsNullOrWhiteSpace(title) || !string.IsNullOrWhiteSpace(cleanDesc))
                {
                    documents.Add(new ParsedDocument
                    {
                        Text = $"{title}. {cleanDesc}".Trim(),
                        Source = $"rss:{new Uri(feedUrl).Host}",
                        Timestamp = DateTimeOffset.TryParse(pubDate, CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out var dt) ? dt.UtcDateTime : null,
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
        catch (OperationCanceledException ex)
        {
            _logger.LogWarning(ex, "Operation canceled while parsing RSS feed {Feed}", feedUrl);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse RSS feed {Feed}", feedUrl);
            throw;
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
