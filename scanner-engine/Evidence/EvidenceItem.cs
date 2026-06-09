using System.Text.Json.Serialization;

namespace NineSTriage.Engine.Evidence;

public sealed class EvidenceItem
{
    [JsonPropertyName("evidence_id")]
    public string EvidenceId { get; set; } = "";

    [JsonPropertyName("category")]
    public string Category { get; set; } = "";

    [JsonPropertyName("target")]
    public EvidenceTarget Target { get; set; } = new();

    [JsonPropertyName("signal")]
    public string Signal { get; set; } = "";

    [JsonPropertyName("details")]
    public Dictionary<string, object?> Details { get; set; } = new();

    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }

    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "low";

    [JsonPropertyName("source")]
    public string Source { get; set; } = "veris_triage";

    [JsonPropertyName("explanation")]
    public string Explanation { get; set; } = "";

    [JsonPropertyName("network_visibility_class")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NetworkVisibilityClass { get; set; }
}

public sealed class EvidenceTarget
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "process";

    [JsonPropertyName("pid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Pid { get; set; }

    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; set; }

    [JsonPropertyName("path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Path { get; set; }
}
