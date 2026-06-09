using System.Text.Json.Serialization;

namespace NineSTriage.Engine.Evidence;

public sealed class EvidencePackage
{
    public const string SchemaVersion = "1.4.0";
    public const string ScannerVersion = "1.6.0";

    [JsonPropertyName("schema_version")]
    public string SchemaVersionValue { get; set; } = SchemaVersion;

    [JsonPropertyName("scanner_version")]
    public string ScannerVersionValue { get; set; } = ScannerVersion;

    [JsonPropertyName("collection_time_utc")]
    public string CollectionTimeUtc { get; set; } = "";

    [JsonPropertyName("host")]
    public HostInfo Host { get; set; } = new();

    [JsonPropertyName("evidence")]
    public List<EvidenceItem> Evidence { get; set; } = new();

    [JsonPropertyName("collection_metadata")]
    public CollectionMetadata CollectionMetadata { get; set; } = new();
}

public sealed class HostInfo
{
    [JsonPropertyName("hostname")]
    public string Hostname { get; set; } = "";

    [JsonPropertyName("os")]
    public string Os { get; set; } = "";

    [JsonPropertyName("os_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? OsVersion { get; set; }

    [JsonPropertyName("architecture")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Architecture { get; set; }
}

public sealed class CollectionMetadata
{
    [JsonPropertyName("scan_duration_ms")]
    public long ScanDurationMs { get; set; }

    [JsonPropertyName("partial_scan")]
    public bool PartialScan { get; set; }

    [JsonPropertyName("interference_suspected")]
    public bool InterferenceSuspected { get; set; }

    [JsonPropertyName("collection_end_time_utc")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CollectionEndTimeUtc { get; set; }

    [JsonPropertyName("privilege_level")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PrivilegeLevel { get; set; }

    [JsonPropertyName("diagnostics")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? Diagnostics { get; set; }

    [JsonPropertyName("network_activity_present")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? NetworkActivityPresent { get; set; }

    [JsonPropertyName("connection_churn_score")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ConnectionChurnScore { get; set; }

    [JsonPropertyName("failure_reason_class")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? FailureReasonClass { get; set; }

    [JsonPropertyName("observation_window_sec")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ObservationWindowSec { get; set; }

    [JsonPropertyName("observation_interval_sec")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ObservationIntervalSec { get; set; }

    [JsonPropertyName("observation_rounds")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ObservationRounds { get; set; }

    [JsonPropertyName("process_observation_unique_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ProcessObservationUniqueCount { get; set; }

    [JsonPropertyName("process_observation_peak_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ProcessObservationPeakCount { get; set; }

    [JsonPropertyName("process_observation_churn")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ProcessObservationChurn { get; set; }

    [JsonPropertyName("tcp_observation_peak_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int TcpObservationPeakCount { get; set; }

    [JsonPropertyName("tcp_observation_delta_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int TcpObservationDeltaCount { get; set; }

    [JsonPropertyName("short_lived_process_suspected")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool ShortLivedProcessSuspected { get; set; }

    [JsonPropertyName("short_lived_network_suspected")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool ShortLivedNetworkSuspected { get; set; }

    [JsonPropertyName("collection_profile")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CollectionProfile { get; set; }

    [JsonPropertyName("duration_budget_sec_max")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int DurationBudgetSecMax { get; set; }

    [JsonPropertyName("duration_budget_sec_consumed")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int DurationBudgetSecConsumed { get; set; }

    [JsonPropertyName("collector_execution")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<CollectorExecutionEntry>? CollectorExecution { get; set; }

    [JsonPropertyName("observation_only_entity_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ObservationOnlyEntityCount { get; set; }
}

public sealed class CollectorExecutionEntry
{
    [JsonPropertyName("collector")]
    public string Collector { get; set; } = "";

    [JsonPropertyName("status")]
    public string Status { get; set; } = "";

    [JsonPropertyName("failure_reason_class")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FailureReasonClass { get; set; }

    [JsonPropertyName("duration_ms")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int DurationMs { get; set; }

    [JsonPropertyName("evidence_emitted_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int EvidenceEmittedCount { get; set; }
}
