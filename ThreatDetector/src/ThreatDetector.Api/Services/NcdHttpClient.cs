using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using ThreatDetector.Models;

namespace ThreatDetector.Api.Services;

public class NcdHttpClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<NcdHttpClient> _logger;

    public NcdHttpClient(string ncdServiceUrl, ILogger<NcdHttpClient> logger)
    {
        _logger = logger;
        _httpClient = new HttpClient { BaseAddress = new Uri(ncdServiceUrl) };
    }

    public async Task<DetectionResult?> DetectConceptsAsync(
        List<ParsedDocument> documents,
        string periodId = "",
        CancellationToken ct = default)
    {
        var batch = new DocumentBatch
        {
            Documents = documents,
            PeriodId = periodId,
        };

        try
        {
            var response = await _httpClient.PostAsJsonAsync("/api/v1/detect", batch, ct);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<DetectionResult>(cancellationToken: ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to detect concepts");
            return null;
        }
    }

    public async Task<HealthResponse?> GetHealthAsync(CancellationToken ct = default)
    {
        try
        {
            var response = await _httpClient.GetAsync("/api/v1/health", ct);
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<HealthResponse>(cancellationToken: ct);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to get health status");
        }
        return null;
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
        GC.SuppressFinalize(this);
    }
}
