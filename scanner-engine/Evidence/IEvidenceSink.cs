namespace NineSTriage.Engine.Evidence;

/// <summary>Collectors push evidence through this sink; implementation builds the in-memory package.</summary>
public interface IEvidenceSink
{
    void AddEvidence(
        string evidenceId,
        string category,
        string targetType,
        int? targetPid,
        string? targetName,
        string? targetPath,
        string signal,
        IReadOnlyDictionary<string, object?> details,
        double confidence,
        string severity,
        string explanation,
        string? networkVisibilityClass = null);
}
