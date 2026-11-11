using ThreatDetector.Models;
using ThreatDetector.Storage;

namespace ThreatDetector.Tests;

public sealed class ThreatStorageTests : IDisposable
{
    private readonly string _directory;
    private readonly ThreatStorage _storage;

    public ThreatStorageTests()
    {
        _directory = Path.Combine(Path.GetTempPath(), "threatdetector-tests", Guid.NewGuid().ToString("N"));
        _storage = new ThreatStorage(Path.Combine(_directory, "threats.db"));
    }

    public void Dispose()
    {
        _storage.Dispose();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup; SQLite may still hold the file briefly.
        }
    }

    [Fact]
    public async Task SaveDocument_HandlesConcurrentWrites()
    {
        var writes = Enumerable.Range(0, 24)
            .Select(i => _storage.SaveDocumentAsync(new ParsedDocument
            {
                Id = $"doc-{i}",
                Text = $"document {i}",
                Source = "test",
            }));

        await Task.WhenAll(writes);

        Assert.Equal(24, await _storage.GetDocumentCountAsync());
    }

    [Fact]
    public async Task Constructor_RepairsLegacyMsrcGuidDocumentUrls()
    {
        var dbPath = Path.Combine(_directory, "legacy.db");
        using (var storage = new ThreatStorage(dbPath))
        {
            await storage.SaveConceptDocumentsAsync(new[]
            {
                new ConceptDocumentRow(
                    "concept-1", "doc-1", "CVE-2026-119264",
                    "rss:api.msrc.microsoft.com"),
                new ConceptDocumentRow(
                    "concept-1", "doc-2", "https://example.test/advisory",
                    "rss:example.test"),
            });
        }

        using var reopened = new ThreatStorage(dbPath);
        var docs = await reopened.GetConceptDocumentsAsync(new[] { "concept-1" });

        Assert.Contains(
            docs["concept-1"],
            d => d.Url == "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-119264");
        Assert.DoesNotContain(docs["concept-1"], d => d.Url == "CVE-2026-119264");
    }

    [Fact]
    public async Task ConceptEvent_UsesProvidedPeriodId()
    {
        var concept = new DetectedConcept
        {
            ConceptId = "concept-1",
            Label = "Test concept",
            Source = "rss:example.test",
            Strength = 0.5,
            Coordinates = new List<double> { 1, 2 },
        };

        await _storage.SaveConceptAsync(concept);
        await _storage.SaveConceptEventAsync(concept, "new_concept", "period-7");

        var loaded = await _storage.GetConceptAsync(concept.ConceptId);
        Assert.NotNull(loaded);
        Assert.Equal(concept.Label, loaded!.Label);

        var history = await _storage.GetConceptHistoryAsync(concept.ConceptId);

        var snapshot = Assert.Single(history);
        Assert.Equal("period-7", snapshot["periodId"]?.ToString());
        Assert.Equal("new_concept", snapshot["eventType"]?.ToString());
    }
}
