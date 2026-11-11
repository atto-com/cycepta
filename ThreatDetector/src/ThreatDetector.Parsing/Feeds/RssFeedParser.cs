using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using ThreatDetector.Models;

namespace ThreatDetector.Parsing.Feeds;

/// <summary>
/// Per-fetch limits. The old implementation shared one 25s cancellation token
/// across every feed; slow hosts starved the queue and only the few fastest
/// feeds (GitLab, arXiv) ever finished. Every feed now gets its own timeout
/// inside a wider wall-clock budget, so a dead host cannot take the whole
/// source list down with it.
/// </summary>
public sealed record FeedFetchOptions
{
    public int TimeoutSeconds { get; init; } = 15;
    public int BudgetSeconds { get; init; } = 120;
    public int Concurrency { get; init; } = 12;
}

/// <summary>Progress snapshot emitted after each feed finishes.</summary>
public sealed record FeedFetchProgress(
    int Completed,
    int Total,
    int Documents,
    int SourcesWithDocuments);

/// <summary>Last observed health for one configured feed.</summary>
public sealed record FeedFetchStatus(
    string Url,
    string Status,
    int Documents,
    DateTime CheckedAt,
    string? Error);

public class RssFeedParser
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<RssFeedParser> _logger;

    // Shared across parser instances so /api/v1/sources can show what the
    // latest run actually fetched, not just which URLs are configured.
    private static readonly ConcurrentDictionary<string, FeedFetchStatus> FeedStatuses =
        new(StringComparer.OrdinalIgnoreCase);

    // Curated security feeds, verified from the operator network on
    // 2026-11-07. The previous list was dominated by dead links and bot walls
    // (41/97 unreachable); the old 25s shared timeout then cancelled most of
    // the queue, so a run could surface only the two fastest hosts (GitLab
    // and arXiv). The list below keeps the working, security-focused sources
    // and adds independent research, government, academic, AppSec and DFIR
    // feeds so no single host can define a run. Intermittent bot walls
    // (Dark Reading, Wired, Reddit) are kept because they do serve feeds when
    // the wall is not active; their health is reported by /api/v1/sources.
    // Deliberately excluded: general tech feeds (GitLab all-posts, DigiCert,
    // Kaspersky blog, Palo Alto blog, Check Point blog) that duplicated a
    // vendor's security-research feed, and dead/bot-walled URLs verified on
    // 2026-11-07 (The Record, SecurityWeek, Talos, CrowdStrike, Mandiant,
    // SANS ISC, Packet Storm, Help Net Security, The Register, EFF).
    private static readonly object FeedsLock = new();
    private static readonly List<string> SecurityFeeds = new()
    {
        // --- Government, standards and vendor advisories ---
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://www.cisa.gov/news.xml",
        "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml",
        "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        "https://www.nist.gov/news-events/news/rss.xml",
        "https://api.msrc.microsoft.com/update-guide/rss",

        // --- News and independent reporting ---
        "https://www.bleepingcomputer.com/feed/",
        "https://krebsonsecurity.com/feed/",
        "https://arstechnica.com/security/feed/",
        "https://www.darkreading.com/rss.xml",
        "https://www.wired.com/feed/category/security/latest/rss",
        "https://www.cyberscoop.com/feed/",
        "https://www.csoonline.com/feed/",
        "https://www.zdnet.com/topic/security/rss.xml",
        "https://techcrunch.com/category/security/feed/",
        "https://www.infosecurity-magazine.com/rss/news/",
        "https://securityaffairs.com/feed/",
        "https://www.hackread.com/feed/",
        "https://www.grahamcluley.com/feed/",
        "https://latesthackingnews.com/feed/",
        "https://www.techrepublic.com/rssfeeds/topic/security/",
        "https://www.informationsecuritybuzz.com/feed/",

        // --- Vendor research, threat intelligence and AppSec ---
        "https://unit42.paloaltonetworks.com/feed/",
        "https://research.checkpoint.com/feed/",
        "https://securelist.com/feed/",
        "https://www.welivesecurity.com/feed/",
        "https://www.microsoft.com/en-us/security/blog/feed/",
        "https://github.blog/security/feed/",
        "https://blog.cloudflare.com/rss/",
        "https://blog.malwarebytes.com/feed/",
        "https://www.sentinelone.com/labs/feed/",
        "https://redcanary.com/blog/feed/",
        "https://www.proofpoint.com/us/rss.xml",
        "https://blogs.cisco.com/security/feed",
        "https://blogs.vmware.com/security/feed/",
        "https://www.imperva.com/blog/feed/",
        "https://www.horizon3.ai/feed/",
        "https://bishopfox.com/blog/feed",
        "https://blog.assetnote.io/feed.xml",
        "https://blog.detectify.com/feed/",
        "https://blog.sublimesecurity.com/rss/",
        "https://www.wordfence.com/blog/feed/",
        "https://labs.nettitude.com/feed/",
        "https://www.pentestpartners.com/feed/",
        "https://blog.trailofbits.com/feed/",
        "https://www.greynoise.io/blog/rss.xml",
        "https://www.mend.io/feed/",
        "https://www.sonatype.com/blog/rss.xml",
        "https://googleprojectzero.blogspot.com/rss.xml",
        "https://blog.0patch.com/feeds/posts/default",

        // --- Independent researchers, community and DFIR ---
        "https://www.schneier.com/feed/",
        "https://www.troyhunt.com/rss/",
        "https://freedom-to-tinker.com/feed/",
        "https://www.reddit.com/r/netsec/.rss",
        "https://infosecwriteups.com/feed",
        "https://www.secjuice.com/rss/",
        "https://stateofsecurity.com/feed/",
        "https://www.exploit-db.com/rss.xml",
        "https://thedfirreport.com/feed/",

        // --- Academic and conference research ---
        "https://rss.arxiv.org/rss/cs.CR",
        "https://eprint.iacr.org/rss/rss.xml",
        "https://www.ndss-symposium.org/feed/",
    };

    // Rotation cursor for ParseAllFeedsAsync; static because the parser may be
    // re-instantiated per DI scope while fairness must persist across calls.
    // It rotates both the fetch queue and the aggregation order.
    private static int _startOffset;

    public RssFeedParser(HttpClient httpClient, ILogger<RssFeedParser> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        if (_httpClient.DefaultRequestHeaders.UserAgent.Count == 0)
        {
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (compatible; ThreatDetector/1.0)");
        }
    }

    public async Task<List<ParsedDocument>> ParseFeedAsync(string feedUrl, CancellationToken ct = default)
    {
        var documents = new List<ParsedDocument>();

        try
        {
            var response = await GetFeedBodyAsync(feedUrl, ct);

            XDocument doc;
            try
            {
                doc = XDocument.Parse(SanitizeFeedXml(response));
            }
            catch (System.Xml.XmlException) when (LooksLikeHtml(response))
            {
                // Bot walls and SPA shells answer 200 with HTML. Parsing that
                // as XML produced noisy "multiple root elements" errors and
                // hid the real cause; report it as blocked instead.
                _logger.LogDebug("Feed returned non-XML content: {Feed}", feedUrl);
                RecordStatus(feedUrl, "blocked", 0,
                    "response was not an XML feed (HTML page or bot challenge)");
                return documents;
            }

            // Valid XML with an <html> root is an XHTML challenge page, not a
            // feed. Checking the parsed root (rather than a string prefix)
            // keeps feeds with comments or a DOCTYPE before <rss> working.
            if (doc.Root?.Name.LocalName is not ("rss" or "feed" or "RDF"))
            {
                _logger.LogDebug("Feed root element is not RSS/Atom: {Feed}", feedUrl);
                RecordStatus(feedUrl, "blocked", 0,
                    $"response root <{doc.Root?.Name.LocalName}> is not an RSS/Atom feed");
                return documents;
            }

            // Namespace-agnostic item extraction: RSS <item>, Atom <entry>,
            // RDF <item> (feeds may declare their own xmlns).
            var items = doc.Descendants().Where(e => e.Name.LocalName is "item" or "entry");
            foreach (var item in items)
            {
                var title = El(item, "title") ?? "";
                var description = El(item, "description", "summary", "content") ?? "";
                var link = ElOrHref(item, "link", "guid") ?? "";
                var pubDate = El(item, "pubDate", "published", "updated") ?? "";

                // Strip HTML tags, then resolve HTML entities: feeds from
                // CDATA-wrapped HTML routinely carry pre-escaped fragments
                // (literal &quot;/&amp;) that would otherwise leak into the
                // embedding text, concept labels and the dashboard.
                var cleanDesc = System.Text.RegularExpressions.Regex.Replace(description, "<.*?>", "");
                cleanDesc = System.Net.WebUtility.HtmlDecode(cleanDesc);
                title = System.Net.WebUtility.HtmlDecode(title);

                var text = $"{title}. {cleanDesc}".Trim();
                // Feed hygiene: advisory feeds (e.g. CISA all.xml) emit full-text
                // advisories tens of KB long. Cap early so the DB and NCD payload stay lean.
                if (text.Length > 4000)
                {
                    text = text[..4000];
                }

                if (!string.IsNullOrWhiteSpace(title) || !string.IsNullOrWhiteSpace(cleanDesc))
                {
                    documents.Add(new ParsedDocument
                    {
                        // Content-addressed identity: the same feed item must
                        // keep one id across fetches. A random Guid per fetch
                        // created duplicate documents and duplicate concepts.
                        Id = StableId(feedUrl, link, pubDate, text),
                        Text = text,
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
            RecordStatus(feedUrl, documents.Count > 0 ? "ok" : "empty", documents.Count, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Per-feed timeout or the overall fetch budget expired. This is
            // expected for slow/dead hosts and must not look like a parser bug.
            _logger.LogDebug("Feed fetch cancelled or timed out: {Feed}", feedUrl);
            RecordStatus(feedUrl, "timeout", 0, "feed did not finish before its timeout");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse RSS feed {Feed}", feedUrl);
            RecordStatus(feedUrl, "error", 0, ex.Message);
        }

        return documents;
    }

    private static readonly Regex InvalidXmlChars =
        new("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]", RegexOptions.Compiled);
    private static readonly Regex NamedHtmlEntity =
        new("&([a-zA-Z][a-zA-Z0-9]+);", RegexOptions.Compiled);

    private static bool LooksLikeHtml(string payload)
    {
        var trimmed = payload.TrimStart('\uFEFF', ' ', '\t', '\r', '\n');
        return trimmed.StartsWith("<!doctype html", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("<html", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Feeds regularly contain named HTML entities (&amp;nbsp;, &amp;mdash;)
    /// that are invalid XML, plus stray control characters. Decode only the
    /// non-XML names so the well-formed entities used by real markup keep
    /// working.
    /// </summary>
    private static string SanitizeFeedXml(string xml)
    {
        var cleaned = InvalidXmlChars.Replace(xml, string.Empty);
        return NamedHtmlEntity.Replace(cleaned, match =>
        {
            var name = match.Groups[1].Value;
            if (name is "amp" or "lt" or "gt" or "quot" or "apos")
            {
                return match.Value;
            }

            var decoded = WebUtility.HtmlDecode(match.Value);
            return decoded == match.Value ? match.Value : decoded;
        });
    }

    private static void RecordStatus(string feedUrl, string status, int documents, string? error)
    {
        FeedStatuses[feedUrl] = new FeedFetchStatus(
            feedUrl, status, documents, DateTime.UtcNow, error);
    }

    /// <summary>Latest per-feed result from this process, for the sources API.</summary>
    public IReadOnlyList<FeedFetchStatus> GetFeedStatuses() =>
        FeedStatuses.Values.OrderBy(s => s.Url, StringComparer.OrdinalIgnoreCase).ToArray();

    /// <summary>
    /// Fetch a feed with manual redirects so every hop is checked against the
    /// same private-host policy as AddFeed (auto-redirect would let a public
    /// feed bounce the request into the metadata service).
    /// </summary>
    private async Task<string> GetFeedBodyAsync(string feedUrl, CancellationToken ct)
    {
        var current = new Uri(feedUrl);
        var retried429 = false;
        for (var hop = 0; hop < 4; hop++)
        {
            if (!AllowPrivateFeeds && IsBlockedHost(current.Host))
            {
                throw new InvalidOperationException($"Refusing redirect to private host {current.Host}");
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            using var response = await _httpClient.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, ct);

            if ((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
            {
                var location = response.Headers.Location;
                if (location is null)
                {
                    throw new InvalidOperationException($"Redirect from {current} has no Location header");
                }
                current = location.IsAbsoluteUri ? location : new Uri(current, location);
                continue;
            }

            // Respect 429 Too Many Requests: back off per Retry-After, retry once.
            if ((int)response.StatusCode == 429 && !retried429)
            {
                retried429 = true;
                var retryAfter = response.Headers.RetryAfter;
                var delay = retryAfter?.Delta ?? TimeSpan.FromSeconds(5);
                if (delay > TimeSpan.FromSeconds(30)) delay = TimeSpan.FromSeconds(30);
                await Task.Delay(delay, ct);
                hop--; // retry the same URL without consuming a redirect hop
                continue;
            }

            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync(ct);
        }

        throw new InvalidOperationException($"Too many redirects for feed {feedUrl}");
    }

    public async Task<List<ParsedDocument>> ParseAllFeedsAsync(
        int perSourceCap = 50,
        int globalCap = 1300,
        CancellationToken ct = default,
        FeedFetchOptions? options = null,
        Func<FeedFetchProgress, Task>? onProgress = null)
    {
        options ??= new FeedFetchOptions();
        var feeds = GetFeedUrls().ToArray();
        if (feeds.Length == 0 || perSourceCap <= 0 || globalCap <= 0)
        {
            return new List<ParsedDocument>();
        }

        // Rotate the fetch order as well as the aggregation order. With a
        // fixed order, the same feeds were always last in the queue and the
        // first slow host could starve everything behind it.
        var offset = Math.Abs(Interlocked.Increment(ref _startOffset) - 1) % feeds.Length;
        var rotatedFeeds = feeds.Skip(offset).Concat(feeds.Take(offset)).ToArray();

        var results = new List<ParsedDocument>?[rotatedFeeds.Length];
        var completed = 0;
        var withDocuments = 0;
        var totalDocuments = 0;
        var progressLock = new object();

        using var budgetCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budgetCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(5, options.BudgetSeconds)));
        using var semaphore = new SemaphoreSlim(Math.Clamp(options.Concurrency, 1, 32));
        var elapsed = Stopwatch.StartNew();

        var tasks = rotatedFeeds.Select(async (feed, index) =>
        {
            try
            {
                await semaphore.WaitAsync(budgetCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            try
            {
                using var feedCts = CancellationTokenSource.CreateLinkedTokenSource(budgetCts.Token);
                feedCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, options.TimeoutSeconds)));
                var docs = await ParseFeedAsync(feed, feedCts.Token).ConfigureAwait(false);
                results[index] = docs;

                FeedFetchProgress? snapshot = null;
                lock (progressLock)
                {
                    completed++;
                    if (docs.Count > 0)
                    {
                        withDocuments++;
                    }
                    totalDocuments += docs.Count;
                    snapshot = new FeedFetchProgress(
                        completed, rotatedFeeds.Length, totalDocuments, withDocuments);
                }

                if (onProgress is not null)
                {
                    try
                    {
                        await onProgress(snapshot).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        // A dashboard progress push must never abort ingestion.
                        _logger.LogDebug(ex, "Feed fetch progress callback failed");
                    }
                }
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        elapsed.Stop();

        var completedFeeds = results
            .Where(r => r is not null)
            .Select(r => r!)
            .ToArray();
        var selected = SelectDiverse(completedFeeds, perSourceCap, globalCap);

        _logger.LogInformation(
            "RSS fetch finished in {Elapsed:F1}s: {WithDocs}/{Total} feeds returned documents, " +
            "{Parsed} parsed, {Selected} selected across {Sources} sources",
            elapsed.Elapsed.TotalSeconds, withDocuments, rotatedFeeds.Length,
            totalDocuments, selected.Count,
            selected.Select(d => d.Source).Distinct(StringComparer.OrdinalIgnoreCase).Count());

        if (withDocuments == 0)
        {
            _logger.LogWarning(
                "No RSS feed returned documents; check network access and /api/v1/sources status");
        }

        return selected;
    }

    /// <summary>
    /// Fair-share selection: every working feed contributes a baseline number
    /// of documents before any one feed can use up the remaining global cap.
    /// The old round-robin started with perSourceCap (50), so a handful of
    /// giant feeds could fill the whole batch and crowd the rest out.
    /// </summary>
    internal static List<ParsedDocument> SelectDiverse(
        IReadOnlyList<List<ParsedDocument>> perFeed,
        int perSourceCap,
        int globalCap)
    {
        var selected = new List<ParsedDocument>();
        if (perSourceCap <= 0 || globalCap <= 0)
        {
            return selected;
        }

        var feeds = perFeed.Where(f => f.Count > 0).ToArray();
        if (feeds.Length == 0)
        {
            return selected;
        }

        var cursors = new int[feeds.Length];
        var taken = new int[feeds.Length];
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var remaining = globalCap;
        var quota = Math.Clamp(globalCap / feeds.Length, 1, perSourceCap);
        var madeProgress = true;

        while (remaining > 0 && madeProgress)
        {
            madeProgress = false;
            for (var i = 0; i < feeds.Length && remaining > 0; i++)
            {
                var docs = feeds[i];
                var limit = Math.Min(quota, perSourceCap - taken[i]);
                var addedHere = 0;

                while (addedHere < limit && cursors[i] < docs.Count && remaining > 0)
                {
                    var doc = docs[cursors[i]++];
                    if (string.IsNullOrWhiteSpace(doc.Text) || !seen.Add(DedupeKey(doc)))
                    {
                        continue;
                    }

                    selected.Add(doc);
                    taken[i]++;
                    addedHere++;
                    remaining--;
                }

                if (addedHere > 0)
                {
                    madeProgress = true;
                }
            }

            if (remaining > 0 && !madeProgress && quota < perSourceCap)
            {
                // Every feed either hit the fair-share quota or ran out of
                // unique items. Raise the ceiling once so large feeds can
                // fill the tail without ever exceeding perSourceCap.
                quota = perSourceCap;
                madeProgress = true;
            }
        }

        return selected;
    }

    private static string DedupeKey(ParsedDocument doc)
    {
        if (doc.Metadata.TryGetValue("url", out var rawUrl)
            && !string.IsNullOrWhiteSpace(rawUrl)
            && Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            var host = uri.Host.StartsWith("www.", StringComparison.OrdinalIgnoreCase)
                ? uri.Host[4..]
                : uri.Host;
            var path = uri.AbsolutePath.TrimEnd('/');
            if (path.Length == 0)
            {
                path = "/";
            }

            var keptQuery = uri.Query.TrimStart('?')
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Where(p => !IsTrackingParam(p))
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase);
            var query = string.Join("&", keptQuery);

            return $"{host.ToLowerInvariant()}{path.ToLowerInvariant()}"
                   + (query.Length > 0 ? "?" + query : "");
        }

        var text = string.Join(' ', doc.Text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return (text.Length <= 160 ? text : text[..160]).ToLowerInvariant();
    }

    private static bool IsTrackingParam(string pair)
    {
        var name = pair.Split('=', 2)[0];
        return name.Equals("fbclid", StringComparison.OrdinalIgnoreCase)
            || name.Equals("gclid", StringComparison.OrdinalIgnoreCase)
            || name.Equals("mc_cid", StringComparison.OrdinalIgnoreCase)
            || name.Equals("mc_eid", StringComparison.OrdinalIgnoreCase)
            || name.Equals("ref", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("utm_", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Register an additional feed at runtime. Returns false when the URL is
    /// already present. In-memory by design for this pass; a durable registry
    /// belongs in the source service (DB/config), not in the parser.
    /// </summary>
    public bool AddFeed(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException("Feed URL must be an absolute http(s) URL.", nameof(url));
        }

        // SSRF guard: the feed registry is operator-editable, so a typo or an
        // exposed dashboard must not turn into a request to cloud metadata or
        // an internal service. DNS names are not resolved here (that would
        // block); literal private/loopback addresses are rejected. Set
        // THREAT_ALLOW_PRIVATE_FEEDS=1 for an intentional intranet feed.
        if (!AllowPrivateFeeds && IsBlockedHost(uri.Host))
        {
            throw new ArgumentException("Feed URL must point to a public host.", nameof(url));
        }

        var normalized = uri.ToString();
        lock (FeedsLock)
        {
            if (SecurityFeeds.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            {
                return false;
            }
            SecurityFeeds.Add(normalized);
            return true;
        }
    }

    public IEnumerable<string> GetFeedUrls()
    {
        lock (FeedsLock)
        {
            return SecurityFeeds.ToArray();
        }
    }

    private static readonly bool AllowPrivateFeeds =
        (Environment.GetEnvironmentVariable("THREAT_ALLOW_PRIVATE_FEEDS") ?? "0")
            .ToLowerInvariant() is "1" or "true" or "yes";

    private static bool IsBlockedHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!IPAddress.TryParse(host, out var address))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal
                || address.IsIPv6SiteLocal
                || address.IsIPv6UniqueLocal
                || address.Equals(IPAddress.IPv6Any);
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 0
            || bytes[0] == 10
            || bytes[0] == 127
            || (bytes[0] == 169 && bytes[1] == 254)
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || (bytes[0] == 192 && bytes[1] == 168);
    }

    private static string StableId(string feedUrl, string link, string pubDate, string text)
    {
        var raw = $"{feedUrl}\n{link}\n{pubDate}\n{text}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }

    private static string? El(XElement parent, params string[] localNames) =>
        parent.Elements().FirstOrDefault(e => localNames.Contains(e.Name.LocalName))?.Value;

    /// <summary>
    /// Resolve an item link with explicit name priority. XML order is not the
    /// same as preference order: MSRC publishes a non-permalink
    /// &lt;guid&gt;CVE-...&lt;/guid&gt; before the real &lt;link&gt;, so the old
    /// first-match implementation stored the bare GUID instead of the URL.
    /// </summary>
    private static string? ElOrHref(XElement parent, params string[] localNames)
    {
        foreach (var localName in localNames)
        {
            foreach (var element in parent.Elements().Where(e => e.Name.LocalName == localName))
            {
                var value = string.IsNullOrWhiteSpace(element.Value)
                    ? element.Attribute("href")?.Value
                    : element.Value;
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }
        }

        return null;
    }
}
