using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ThreatDetector.Parsing.Feeds.CveFeedParser.CveFeeParserModels
{
    #region NVD API Models

    public sealed class NvdResponse
    {
        [JsonPropertyName("totalResults")]
        public int TotalResults { get; set; }

        [JsonPropertyName("startIndex")]
        public int StartIndex { get; set; }

        [JsonPropertyName("resultsPerPage")]
        public int ResultsPerPage { get; set; }

        [JsonPropertyName("vulnerabilities")]
        public List<NvdVulnerability> Vulnerabilities { get; set; } = new();
    }

    public sealed class NvdVulnerability
    {
        [JsonPropertyName("cve")]
        public NvdCve Cve { get; set; } = new();
    }

    public sealed class NvdCve
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("published")]
        public DateTime? Published { get; set; }

        [JsonPropertyName("lastModified")]
        public DateTime? LastModified { get; set; }

        [JsonPropertyName("descriptions")]
        public List<NvdDescription> Descriptions { get; set; } = new();

        [JsonPropertyName("metrics")]
        public Dictionary<string, List<NvdMetric>>? Metrics { get; set; }
    }

    public sealed class NvdDescription
    {
        [JsonPropertyName("lang")]
        public string? Lang { get; set; }

        [JsonPropertyName("value")]
        public string? Value { get; set; }
    }

    public sealed class NvdMetric
    {
        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("cvssData")]
        public NvdCvssData? CvssData { get; set; }
    }

    public sealed class NvdCvssData
    {
        [JsonPropertyName("baseScore")]
        public double? BaseScore { get; set; }

        [JsonPropertyName("baseSeverity")]
        public string? BaseSeverity { get; set; }
    }

    #endregion

}
