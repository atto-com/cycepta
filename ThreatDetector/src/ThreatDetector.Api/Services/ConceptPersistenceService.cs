using Microsoft.AspNetCore.SignalR;
using ThreatDetector.Api.Hubs;
using ThreatDetector.Models;
using ThreatDetector.Storage;

namespace ThreatDetector.Api.Services;

/// <summary>
/// Shared persistence + real-time push for detected concepts.
/// Used by both the interactive AnalyzeController and the background BatchingService.
/// </summary>
public class ConceptPersistenceService
{
    private readonly ThreatStorage _storage;
    private readonly IHubContext<ThreatHub> _hub;
    private readonly ILogger<ConceptPersistenceService> _logger;

    public ConceptPersistenceService(
        ThreatStorage storage,
        IHubContext<ThreatHub> hub,
        ILogger<ConceptPersistenceService> logger)
    {
        _storage = storage;
        _hub = hub;
        _logger = logger;
    }

    public async Task PersistAsync(List<ParsedDocument> docs, List<DetectedConcept> concepts,
        DetectionResult? result = null)
    {
        try
        {
            if (result is not null && !string.IsNullOrWhiteSpace(result.PeriodId))
            {
                await _storage.SavePeriodAsync(result);
            }

            foreach (var doc in docs)
            {
                await _storage.SaveDocumentAsync(doc);
            }

            var recent = await _storage.GetRecentConceptsAsync(limit: 5000);
            var knownIds = new HashSet<string>(recent.Select(c => c.ConceptId), StringComparer.OrdinalIgnoreCase);

            foreach (var concept in concepts)
            {
                await _storage.SaveConceptAsync(concept);
                var eventType = knownIds.Contains(concept.ConceptId) ? "concept_evolved" : "new_concept";
                await _storage.SaveConceptEventAsync(concept, eventType);

                var update = new ConceptUpdate
                {
                    EventType = eventType,
                    Alert = new ThreatAlert
                    {
                        ConceptId = concept.ConceptId,
                        Summary = concept.Summary,
                        SampleSentences = concept.Sentences,
                        Strength = concept.Strength,
                        DetectedAt = DateTime.UtcNow,
                        Source = concept.Source,
                    },
                };
                await _hub.Clients.All.SendAsync("ConceptUpdate", update);
            }

            _logger.LogInformation("Persisted {DocCount} documents and {ConceptCount} concepts", docs.Count, concepts.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Persistence or SignalR push failed (non-fatal)");
        }
    }
}