using Microsoft.Extensions.Logging;
using System.Collections;
using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Xml;
using System.Xml.Linq;
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

    public async Task<string> ParseFeedAsyncRequest(string feedUrl, CancellationToken ct = default)
    {
        var documents = new List<ParsedDocument>();
        using var cts = new CancellationTokenSource();
        try
        {
            using var client = _httpClientFactory.CreateClient(RssClientClass.HttpClientName);
            var response = await client.GetStringAsync(feedUrl, ct).ConfigureAwait(false);

            if (response == null)
                return string.Empty;

            //var host = Uri.TryCreate(feedUrl, UriKind.Absolute, out var uri) 
            //    ? uri.Host
            //    : string.Empty;

            //var source = $"rss:{host}";
            return response;
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
    }

    public async IAsyncEnumerable<ParsedDocument> ParseFeedAsync(string feedUrl, [EnumeratorCancellation] CancellationToken ct = default)
    {
            using var cts = new CancellationTokenSource();

            // настройка ридера для игнорирования DTD и отключения XmlResolver для безопасности
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Ignore,
                XmlResolver = null
            };

            var response = await ParseFeedAsyncRequest(feedUrl, ct).ConfigureAwait(false);

            ConcurrentBag<ParsedDocument> parsedDocuments = new ConcurrentBag<ParsedDocument>();
            using var reader = XmlReader.Create(new StringReader(response), settings);
            var doc = XDocument.Load(reader);

            var items = doc.Descendants("item");
            await Parallel.ForEachAsync(items, new ParallelOptions
            {
                MaxDegreeOfParallelism = 10,
                CancellationToken = ct
            },
            async (item, itemCt) =>
            {
                var title = item.Element("title")?.Value ?? "";
                var description = item.Element("description")?.Value ?? "";
                var link = item.Element("link")?.Value ?? "";
                var pubDate = item.Element("pubDate")?.Value ?? "";

                var cleanDesc = _htmlRegex.Replace(description, "");

                if (!string.IsNullOrWhiteSpace(title) || !string.IsNullOrWhiteSpace(cleanDesc))
                {
                    parsedDocuments.Add(new ParsedDocument
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
            });

            foreach (var docs in parsedDocuments)
            {
                yield return docs;
            }
    }


    public async Task<List<ParsedDocument>> ParseAllFeedsAsync(CancellationToken ct = default)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(25));

        var tasks = SecurityFeeds.Select(async feed =>
        {
            var list = new List<ParsedDocument>();
            try
            {
                await foreach (var doc in ParseFeedAsync(feed, timeoutCts.Token).WithCancellation(timeoutCts.Token))
                {
                    list.Add(doc);
                }
            }
            catch (OperationCanceledException ex)
            {
                _logger.LogWarning(ex, "Фид {Feed} отменён", feed);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex.Message, "Фид {Feed} отменён", feed);
            }

            return list;
        });
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
