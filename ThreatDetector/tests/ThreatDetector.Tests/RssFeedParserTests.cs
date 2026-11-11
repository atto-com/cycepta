using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using ThreatDetector.Models;
using ThreatDetector.Parsing.Feeds;

namespace ThreatDetector.Tests;

public class RssFeedParserTests
{
    private const string FeedXml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <item>
              <title>Alpha advisory</title>
              <description>First body.</description>
              <link>https://example.test/a</link>
              <pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate>
            </item>
            <item>
              <title>Beta advisory</title>
              <description>Second body.</description>
              <link>https://example.test/b</link>
              <pubDate>Tue, 02 Jan 2024 00:00:00 GMT</pubDate>
            </item>
          </channel>
        </rss>
        """;

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly string _body;

        public StubHandler(string body) => _body = body;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/rss+xml"),
            });
    }

    private static RssFeedParser CreateParser(string body = FeedXml) =>
        new(new HttpClient(new StubHandler(body)), NullLogger<RssFeedParser>.Instance);

    [Fact]
    public async Task ParseFeed_AssignsStableIdsAcrossFetches()
    {
        var parser = CreateParser();

        var first = await parser.ParseFeedAsync("https://example.test/feed.xml");
        var second = await parser.ParseFeedAsync("https://example.test/feed.xml");

        Assert.Equal(2, first.Count);
        Assert.Equal(first.Select(d => d.Id), second.Select(d => d.Id));
        Assert.Equal(2, first.Select(d => d.Id).Distinct().Count());
    }

    [Fact]
    public async Task ParseFeed_ChangesIdWhenItemContentChanges()
    {
        var parser = CreateParser();
        var original = await parser.ParseFeedAsync("https://example.test/feed.xml");

        var changed = CreateParser(FeedXml.Replace("First body.", "Corrected body."));
        var updated = await changed.ParseFeedAsync("https://example.test/feed.xml");

        Assert.NotEqual(original[0].Id, updated[0].Id);
        // The untouched item keeps its identity.
        Assert.Equal(original[1].Id, updated[1].Id);
    }

    [Fact]
    public async Task ParseFeed_ResolvesHtmlEntities()
    {
        const string cdataFeed = """
            <?xml version="1.0" encoding="UTF-8"?>
            <rss version="2.0">
              <channel>
                <item>
                  <title>Alert: can&#39;t trust &quot;normal&quot;</title>
                  <description><![CDATA[&quot;create_issue&quot; &amp; <b>bold</b> markers]]></description>
                  <link>https://example.test/c</link>
                </item>
              </channel>
            </rss>
            """;

        var docs = await CreateParser(cdataFeed).ParseFeedAsync("https://example.test/feed.xml");

        var text = Assert.Single(docs).Text;
        Assert.Contains("can't trust \"normal\"", text);
        Assert.Contains("\"create_issue\" & bold markers", text);
        Assert.DoesNotContain("&quot;", text);
        Assert.DoesNotContain("<b>", text);
    }

    [Fact]
    public async Task ParseFeed_PrefersLinkOverGuidWhenGuidComesFirst()
    {
        const string msrcLikeFeed = """
            <?xml version="1.0" encoding="UTF-8"?>
            <rss version="2.0">
              <channel>
                <item>
                  <guid isPermaLink="false">CVE-2026-119264</guid>
                  <link>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-119264</link>
                  <title>CVE-2026-119264 Example</title>
                  <description>Example advisory.</description>
                  <pubDate>Mon, 09 Nov 2026 00:00:00 GMT</pubDate>
                </item>
              </channel>
            </rss>
            """;

        var docs = await CreateParser(msrcLikeFeed)
            .ParseFeedAsync("https://api.msrc.microsoft.com/update-guide/rss");

        var doc = Assert.Single(docs);
        Assert.Equal(
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-119264",
            doc.Metadata["url"]);
    }

    [Fact]
    public async Task ParseFeed_FallsBackToGuidWhenLinkIsMissing()
    {
        const string guidOnlyFeed = """
            <?xml version="1.0" encoding="UTF-8"?>
            <rss version="2.0">
              <channel>
                <item>
                  <guid>https://example.test/guid-only</guid>
                  <title>Guid-only item</title>
                  <description>No link element here.</description>
                  <pubDate>Mon, 09 Nov 2026 00:00:00 GMT</pubDate>
                </item>
              </channel>
            </rss>
            """;

        var docs = await CreateParser(guidOnlyFeed)
            .ParseFeedAsync("https://example.test/feed.xml");

        Assert.Equal("https://example.test/guid-only", Assert.Single(docs).Metadata["url"]);
    }

    [Fact]
    public void AddFeed_RejectsNonHttpUrls()
    {
        var parser = CreateParser();

        Assert.Throws<ArgumentException>(() => parser.AddFeed("file:///etc/passwd"));
        Assert.Throws<ArgumentException>(() => parser.AddFeed("not a url"));
    }

    [Theory]
    [InlineData("http://127.0.0.1/feed")]
    [InlineData("http://localhost/feed")]
    [InlineData("http://169.254.169.254/latest/meta-data")]
    [InlineData("http://10.0.0.1/feed")]
    [InlineData("http://172.16.0.1/feed")]
    [InlineData("http://192.168.1.1/feed")]
    [InlineData("http://[::1]/feed")]
    public void AddFeed_RejectsPrivateTargets(string url)
    {
        var parser = CreateParser();

        Assert.Throws<ArgumentException>(() => parser.AddFeed(url));
    }

    [Fact]
    public void AddFeed_IsIdempotent()
    {
        var parser = CreateParser();
        var url = $"https://example.test/feed-{Guid.NewGuid():N}.xml";

        Assert.True(parser.AddFeed(url));
        Assert.False(parser.AddFeed(url));
        Assert.Contains(url, parser.GetFeedUrls());
    }

    [Fact]
    public void SelectDiverse_GivesEveryWorkingFeedAFairShare()
    {
        var feeds = Enumerable.Range(0, 10)
            .Select(feed => Enumerable.Range(0, 20)
                .Select(i => Doc($"feed{feed:00}", i))
                .ToList())
            .ToList();

        var selected = RssFeedParser.SelectDiverse(feeds, perSourceCap: 50, globalCap: 100);

        Assert.Equal(100, selected.Count);
        var perFeed = selected.GroupBy(d => d.Source).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(10, perFeed.Count);
        Assert.All(perFeed.Values, count => Assert.Equal(10, count));
    }

    [Fact]
    public void SelectDiverse_KeepsSmallFeedsAndFillsTheTailFromLargeFeeds()
    {
        var feeds = Enumerable.Range(0, 4)
            .Select(feed => Enumerable.Range(0, 2)
                .Select(i => Doc($"small{feed}", i))
                .ToList())
            .ToList();
        feeds.Add(Enumerable.Range(0, 100).Select(i => Doc("big", i)).ToList());

        var selected = RssFeedParser.SelectDiverse(feeds, perSourceCap: 50, globalCap: 20);

        Assert.Equal(20, selected.Count);
        var perFeed = selected.GroupBy(d => d.Source).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(5, perFeed.Count);
        Assert.All(Enumerable.Range(0, 4), i => Assert.Equal(2, perFeed[$"small{i}"]));
        Assert.Equal(12, perFeed["big"]);
    }

    [Fact]
    public void SelectDiverse_DeduplicatesTheSameArticleAcrossFeeds()
    {
        var feeds = new List<List<ParsedDocument>>
        {
            new()
            {
                Doc("one", 0, "https://example.test/story?utm_source=one"),
                Doc("one", 1, "https://example.test/other"),
            },
            new()
            {
                Doc("two", 0, "https://www.example.test/story/"),
                Doc("two", 1, "https://example.test/third"),
            },
        };

        var selected = RssFeedParser.SelectDiverse(feeds, perSourceCap: 50, globalCap: 10);

        Assert.Equal(3, selected.Count);
        Assert.Single(selected, d => d.Id == "one-0");
        Assert.Contains(selected, d => d.Id == "one-1");
        Assert.Contains(selected, d => d.Id == "two-1");
    }

    [Fact]
    public void SelectDiverse_RespectsPerSourceCap()
    {
        var feeds = new List<List<ParsedDocument>>
        {
            Enumerable.Range(0, 100).Select(i => Doc("only", i)).ToList(),
        };

        var selected = RssFeedParser.SelectDiverse(feeds, perSourceCap: 10, globalCap: 100);

        Assert.Equal(10, selected.Count);
    }

    [Fact]
    public async Task ParseFeed_RecordsSuccessfulHealth()
    {
        var parser = CreateParser();
        var url = $"https://example.test/feed-{Guid.NewGuid():N}.xml";

        var docs = await parser.ParseFeedAsync(url);

        Assert.Equal(2, docs.Count);
        var status = Assert.Single(parser.GetFeedStatuses(), s => s.Url == url);
        Assert.Equal("ok", status.Status);
        Assert.Equal(2, status.Documents);
        Assert.Null(status.Error);
    }

    [Fact]
    public async Task ParseFeed_RecordsTimeoutHealth()
    {
        var parser = new RssFeedParser(
            new HttpClient(new SlowHandler()), NullLogger<RssFeedParser>.Instance);
        var url = $"https://example.test/slow-{Guid.NewGuid():N}.xml";
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        var docs = await parser.ParseFeedAsync(url, cts.Token);

        Assert.Empty(docs);
        var status = Assert.Single(parser.GetFeedStatuses(), s => s.Url == url);
        Assert.Equal("timeout", status.Status);
        Assert.Equal(0, status.Documents);
    }

    [Fact]
    public async Task ParseFeed_AcceptsLeadingCommentDoctypeAndNamedEntities()
    {
        const string messyFeed = """
            <!-- generated by the feed builder -->
            <!DOCTYPE rss>
            <rss version="2.0">
              <channel>
                <item>
                  <title>Messy&nbsp;feed</title>
                  <description>Dash &mdash; and an entity.</description>
                  <link>https://example.test/m</link>
                </item>
              </channel>
            </rss>
            """;

        var docs = await CreateParser(messyFeed).ParseFeedAsync("https://example.test/messy.xml");

        var text = Assert.Single(docs).Text;
        Assert.Contains("Messy feed", text.Replace('\u00A0', ' '));
        Assert.Contains("Dash — and an entity.", text);
    }

    [Fact]
    public async Task ParseFeed_FlagsHtmlChallengeAsBlocked()
    {
        const string challenge = """
            <!DOCTYPE html>
            <html><head><title>Just a moment...</title></head><body>checking</body></html>
            """;
        var parser = CreateParser(challenge);
        var url = "https://example.test/blocked.xml";

        var docs = await parser.ParseFeedAsync(url);

        Assert.Empty(docs);
        var status = Assert.Single(parser.GetFeedStatuses(), s => s.Url == url);
        Assert.Equal("blocked", status.Status);
        Assert.Equal(0, status.Documents);
    }

    private static ParsedDocument Doc(string source, int index, string? url = null) => new()
    {
        Id = $"{source}-{index}",
        Text = $"{source} story {index}. Body text for the item.",
        Source = source,
        Metadata = new Dictionary<string, string>
        {
            ["url"] = url ?? $"https://{source}.example.test/story-{index}",
        },
    };

    private sealed class SlowHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }
}
