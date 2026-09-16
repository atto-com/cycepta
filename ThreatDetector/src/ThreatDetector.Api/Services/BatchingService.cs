using Microsoft.Extensions.Logging;
using ThreatDetector.Models;
using ThreatDetector.Parsing.Channels;

namespace ThreatDetector.Api.Services;

public class BatchingService : BackgroundService
{
    private readonly DataIngestionChannel _ingestionChannel;
    private readonly NcdHttpClient _ncdClient;
    private readonly ConceptPersistenceService _persistence;
    private readonly ILogger<BatchingService> _logger;

    public BatchingService(
        DataIngestionChannel ingestionChannel,
        NcdHttpClient ncdClient,
        ConceptPersistenceService persistence,
        ILogger<BatchingService> logger)
    {
        _ingestionChannel = ingestionChannel;
        _ncdClient = ncdClient;
        _persistence = persistence;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Batching service starting");

        // Start batch producer
        var batchingTask = _ingestionChannel.StartBatchingAsync(stoppingToken);

        var periodCount = 0;

        // Consumer: process batches
        await foreach (var batch in _ingestionChannel.BatchReader.ReadAllAsync(stoppingToken))
        {
            periodCount++;
            var periodId = $"period_{periodCount}_{DateTime.UtcNow:yyyyMMdd_HHmmss}";

            _logger.LogInformation("Processing batch {Period} with {Count} documents",
                periodId, batch.Count);

            try
            {
                var result = await _ncdClient.DetectConceptsAsync(batch, periodId, stoppingToken);

                if (result != null)
                {
                    if (result.ConceptsFound > 0)
                    {
                        _logger.LogWarning("DETECTED {Count} NEW CONCEPTS in period {Period}!",
                            result.ConceptsFound, periodId);
                    }

                    await _persistence.PersistAsync(batch, result.Concepts ?? new(), result);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process batch {Period}", periodId);
            }
        }

        _logger.LogInformation("Batching service stopped");
    }
}