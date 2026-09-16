using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using ThreatDetector.Models;

namespace ThreatDetector.Parsing.Feeds;

public class CveFeedParser
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<CveFeedParser> _logger;
    private const int PageSize = 100;

    public CveFeedParser(HttpClient httpClient, ILogger<CveFeedParser> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<List<ParsedDocument>> FetchRecentCvesAsync(
        int lastModDays = 1,
        CancellationToken ct = default)
    {
        var documents = new List<ParsedDocument>();

        try
        {
            var startIndex = 0;
            var totalResults = int.MaxValue;

            while (startIndex < totalResults && startIndex < 500)
            {
                var url = $"https://services.nvd.nist.gov/rest/json/cves/2.0"
                         + $"?lastModStartDate={DateTime.UtcNow.AddDays(-lastModDays):O}"
                         + $"&lastModEndDate={DateTime.UtcNow:O}"
                         + $"&startIndex={startIndex}"
                         + $"&resultsPerPage={PageSize}";

                var response = await _httpClient.GetFromJsonAsync<NvdResponse>(url, ct);
                if (response?.Vulnerabilities == null) break;

                totalResults = response.TotalResults;

                foreach (var vuln in response.Vulnerabilities)
                {
                    var cve = vuln.Cve;
                    if (cve == null) continue;

                    var desc = cve.Descriptions?.FirstOrDefault(d => d.Language == "en")?.Value ?? "";
                    var id = cve.Id ?? "";

                    documents.Add(new ParsedDocument
                    {
                        Id = id,
                        Text = $"CVE {id}: {desc}",
                        Source = "nvd",
                        Timestamp = cve.Published ?? DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["cve_id"] = id,
                            ["severity"] = cve.Metrics?.FirstOrDefault().Value?.FirstOrDefault()?.Severity ?? "UNKNOWN",
                        },
                    });
                }

                startIndex += PageSize;
                _logger.LogDebug("Fetched CVE page {Start}/{Total}", startIndex, totalResults);
            }

            _logger.LogInformation("Fetched {Count} CVEs from NVD", documents.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to fetch CVEs from NVD");
        }

        return documents;
    }
}

#region NVD API Models

public class NvdResponse
{
    public int TotalResults { get; set; }
    public List<NvdVulnerability>? Vulnerabilities { get; set; }
}

public class NvdVulnerability
{
    public NvdCve? Cve { get; set; }
}

public class NvdCve
{
    public string? Id { get; set; }
    public DateTime? Published { get; set; }
    public List<NvdDescription>? Descriptions { get; set; }
    public Dictionary<string, List<NvdMetric>>? Metrics { get; set; }
}

public class NvdDescription
{
    public string? Language { get; set; }
    public string? Value { get; set; }
}

public class NvdMetric
{
    public string? Severity { get; set; }
}

#endregion
