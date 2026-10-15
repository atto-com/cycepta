using System.Collections.Concurrent;
using System.Globalization;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using ThreatDetector.Models;
using ThreatDetector.Parsing.Feeds.CveFeedParser.CveFeeParserModels;

namespace ThreatDetector.Parsing.Feeds.CveFeedParser;

public class CveFeedParser
{
    private readonly ILogger<CveFeedParser> _logger;
    private const int PageSize = 100;
    private const int MaxPages = 50;
    private readonly IHttpClientFactory _httpClientFactory;

    public CveFeedParser(IHttpClientFactory httpClientFactory, ILogger<CveFeedParser> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    private static string GiveUrl(DateTime lastStart, DateTime lastEnd, int startIndex)
    {
        return 
            $"?lastModStartDate={lastStart.ToUniversalTime():yyyy-MM-ddTHH:mm:ss.fff}Z&lastModEndDate={lastEnd.ToUniversalTime():yyyy-MM-ddTHH:mm:ss.fff}Z&startIndex={startIndex}&resultsPerPage={PageSize}";
    }

    private async IAsyncEnumerable<NvdResponse> FetchRecentCvesAsync(int lastModDays = 1, CancellationToken ct = default)
    {
        using HttpClient httpClient = _httpClientFactory.CreateClient("ClientCveFeed");
        var cves = new List<NvdCve>();

        DateTime lastStart = DateTime.UtcNow.AddDays(-lastModDays);
        DateTime lastEnd = DateTime.UtcNow;

        int startIndex = 0;
        int totalResults = int.MaxValue;

        while (startIndex < totalResults && startIndex / PageSize < MaxPages)
        {
            ct.ThrowIfCancellationRequested();

            string url = GiveUrl(lastStart, lastEnd, startIndex);

            var response = await httpClient.GetFromJsonAsync<NvdResponse>(url, ct).ConfigureAwait(false);
            if (response == null || response.Vulnerabilities.Count == 0) break;

            totalResults = response.TotalResults;
            cves.AddRange(response.Vulnerabilities.Select(v => v.Cve));

            startIndex += PageSize;
            _logger.LogDebug("Fetched CVE page {Start}/{Total}", startIndex, totalResults);

            yield return response;
        }
    }

    public async IAsyncEnumerable<ParsedDocument> FetchRecentCvesAsyncParse(int lastModDays = 1, CancellationToken ct = default)
    {
        using var cts = new CancellationTokenSource();
        await foreach (var response in FetchRecentCvesAsync(lastModDays, ct).WithCancellation(ct))
        {
            ConcurrentBag<ParsedDocument> nvdVulnerabilities = new ConcurrentBag<ParsedDocument>();

            await Parallel.ForEachAsync(response.Vulnerabilities,
                new ParallelOptions
            {
                MaxDegreeOfParallelism = 10,
                CancellationToken = cts.Token
            },
            async (vuln, token) =>
            {
                var cve = vuln.Cve;
                if (string.IsNullOrEmpty(cve?.Id)) return;

                var desc = cve.Descriptions?.FirstOrDefault(d => d.Lang == "en")?.Value ?? "";

                nvdVulnerabilities.Add(new ParsedDocument
                {
                    Id = cve.Id,
                    Text = $"CVE {cve.Id}: {desc}",
                    Source = "nvd",
                    Timestamp = cve.Published ?? DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["cve_id"] = cve.Id,
                        ["severity"] = cve.Metrics?.Values
                        .SelectMany(m => m)
                        .Select(m => m?.CvssData?.BaseSeverity)
                        .FirstOrDefault(s => !string.IsNullOrEmpty(s)) ?? "Unknow"
                    },
                });
            });

            foreach (var doc in nvdVulnerabilities)
            {
                yield return doc;
            }
        }
    }
}
