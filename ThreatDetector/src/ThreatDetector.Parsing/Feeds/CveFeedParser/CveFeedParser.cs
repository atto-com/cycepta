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
        return $"?lastModStartDate={lastStart.ToUniversalTime():yyyy-MM-ddTHH:mm:ss.fff}Z&lastModEndDate={lastEnd.ToUniversalTime():yyyy-MM-ddTHH:mm:ss.fff}Z&startIndex={startIndex}&resultsPerPage={PageSize}";
    }

    private async Task<List<NvdCve>> FetchRecentCvesAsync(int lastModDays = 1, CancellationToken ct = default)
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
        }

        return cves;
    }

    public async Task<List<ParsedDocument>> FetchRecentCvesAsyncParse(int lastModDays = 1, CancellationToken ct = default)
    {
        var documents = new List<ParsedDocument>();

        try
        {
            List<NvdCve> cves = await FetchRecentCvesAsync(lastModDays, ct).ConfigureAwait(false);

            foreach (var cve in cves)
            {
                if (string.IsNullOrEmpty(cve.Id)) continue;

                string id = cve.Id;
                var desc = cve.Descriptions
                                .FirstOrDefault(d => string.Equals(d.Lang, "en", StringComparison.OrdinalIgnoreCase))?.Value
                            ?? cve.Descriptions.FirstOrDefault()?.Value
                            ?? "";
                var metric = GetPrimaryMetric(cve);

                documents.Add(new ParsedDocument
                {
                    Id = id,
                    Text = $"CVE {id}: {desc}",
                    Source = "nvd",
                    Timestamp = cve.Published ?? DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["cve_id"] = id,
                        ["severity"] = metric?.CvssData?.BaseSeverity ?? "UNKNOWN",
                        ["cvss_score"] = metric?.CvssData?.BaseScore?.ToString("0.0", CultureInfo.InvariantCulture) ?? "",
                    },
                });
            }

            _logger.LogInformation("Fetched {Count} CVEs from NVD", documents.Count);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to fetch CVEs from NVD");
        }

        return documents;
    }

    private static NvdMetric? GetPrimaryMetric(NvdCve cve)
    {
        if (cve.Metrics == null) return null;

        var metrics = cve.Metrics.Values
            .Where(m => m != null)
            .SelectMany(m => m)
            .ToList();

        return metrics.FirstOrDefault(m => string.Equals(m.Type, "Primary", StringComparison.OrdinalIgnoreCase))
            ?? metrics.FirstOrDefault();
    }
}
