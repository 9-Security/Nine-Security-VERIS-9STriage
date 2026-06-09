namespace NineSTriage.Engine.Evidence;

/// <summary>Builds schema-aligned evidence package; implements IEvidenceSink.</summary>
public sealed class EvidenceEmitter : IEvidenceSink
{
    private readonly List<EvidenceItem> _evidence = new();

    public IReadOnlyList<EvidenceItem> Evidence => _evidence;

    public void SetHost(string hostname, string os, string? osVersion = null, string? architecture = null)
    {
        Hostname = hostname;
        HostOs = os;
        HostOsVersion = osVersion;
        HostArchitecture = architecture;
    }

    public void SetCollectionTimeUtc(string collectionTimeUtc) => CollectionTimeUtc = collectionTimeUtc;
    public void SetCollectionEndTimeUtc(string? collectionEndTimeUtc) => CollectionEndTimeUtc = collectionEndTimeUtc;
    public void SetCollectionMetadata(long scanDurationMs, bool partialScan, bool interferenceSuspected)
    {
        ScanDurationMs = scanDurationMs;
        PartialScan = partialScan;
        InterferenceSuspected = interferenceSuspected;
    }
    public void SetDiagnostics(List<string> diagnostics) => Diagnostics = diagnostics;
    public void SetNetworkActivityPresent(bool? present) => NetworkActivityPresent = present;
    public void SetConnectionChurnScore(string? score) => ConnectionChurnScore = score;
    public void SetFailureReasonClass(Dictionary<string, string>? map) => FailureReasonClass = map;
    public void SetPrivilegeLevel(string? level) => PrivilegeLevel = level;

    public string CollectionTimeUtc { get; private set; } = "";
    public string? CollectionEndTimeUtc { get; private set; }
    public string Hostname { get; private set; } = "";
    public string HostOs { get; private set; } = "";
    public string? HostOsVersion { get; private set; }
    public string? HostArchitecture { get; private set; }
    public long ScanDurationMs { get; private set; }
    public bool PartialScan { get; private set; }
    public bool InterferenceSuspected { get; private set; }
    public List<string>? Diagnostics { get; private set; }
    public bool? NetworkActivityPresent { get; private set; }
    public string? ConnectionChurnScore { get; private set; }
    public Dictionary<string, string>? FailureReasonClass { get; private set; }
    public string? PrivilegeLevel { get; private set; }

    public void SetObservationMachineMetadata(
        int observationWindowSec,
        int observationIntervalSec,
        int observationRounds,
        int processObservationUniqueCount,
        int processObservationPeakCount,
        int processObservationChurn,
        int tcpObservationPeakCount,
        int tcpObservationDeltaCount,
        bool shortLivedProcessSuspected,
        bool shortLivedNetworkSuspected)
    {
        ObservationWindowSec = observationWindowSec;
        ObservationIntervalSec = observationIntervalSec;
        ObservationRounds = observationRounds;
        ProcessObservationUniqueCount = processObservationUniqueCount;
        ProcessObservationPeakCount = processObservationPeakCount;
        ProcessObservationChurn = processObservationChurn;
        TcpObservationPeakCount = tcpObservationPeakCount;
        TcpObservationDeltaCount = tcpObservationDeltaCount;
        ShortLivedProcessSuspected = shortLivedProcessSuspected;
        ShortLivedNetworkSuspected = shortLivedNetworkSuspected;
    }

    public int ObservationWindowSec { get; private set; }
    public int ObservationIntervalSec { get; private set; }
    public int ObservationRounds { get; private set; }
    public int ProcessObservationUniqueCount { get; private set; }
    public int ProcessObservationPeakCount { get; private set; }
    public int ProcessObservationChurn { get; private set; }
    public int TcpObservationPeakCount { get; private set; }
    public int TcpObservationDeltaCount { get; private set; }
    public bool ShortLivedProcessSuspected { get; private set; }
    public bool ShortLivedNetworkSuspected { get; private set; }

    public string CollectionProfileStored { get; private set; } = "fast";
    private List<CollectorExecutionEntry>? _collectorExecution;
    private int _durationBudgetSecMax = 600;

    public void SetCollectionProfile(string? profile)
    {
        var p = (profile ?? "fast").Trim().ToLowerInvariant();
        CollectionProfileStored = p is "observe" or "escalated" or "fast" ? p : "fast";
    }

    public void SetCollectorExecutionRecords(List<CollectorExecutionEntry>? rows) => _collectorExecution = rows;

    public void SetDurationBudgetConsumedSec(int consumedSec)
    {
        if (consumedSec < 0)
            consumedSec = 0;
        ScanDurationSecsForBudget = consumedSec;
    }

    public int ScanDurationSecsForBudget { get; private set; }

    public void AddEvidence(
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
        string? networkVisibilityClass = null)
    {
        var item = new EvidenceItem
        {
            EvidenceId = evidenceId,
            Category = category,
            Target = new EvidenceTarget
            {
                Type = targetType,
                Pid = targetPid,
                Name = targetName,
                Path = targetPath
            },
            Signal = signal,
            Details = details is Dictionary<string, object?> d ? new Dictionary<string, object?>(d) : details.ToDictionary(x => x.Key, x => x.Value),
            Confidence = Math.Clamp(confidence, 0.0, 1.0),
            Severity = severity,
            Source = "veris_triage",
            Explanation = explanation,
            NetworkVisibilityClass = string.IsNullOrEmpty(networkVisibilityClass) ? null : networkVisibilityClass
        };
        _evidence.Add(item);
    }

    public EvidencePackage BuildPackage()
    {
        var meta = new CollectionMetadata
        {
            ScanDurationMs = ScanDurationMs,
            PartialScan = PartialScan,
            InterferenceSuspected = InterferenceSuspected,
            CollectionEndTimeUtc = CollectionEndTimeUtc,
            PrivilegeLevel = PrivilegeLevel,
            Diagnostics = Diagnostics,
            NetworkActivityPresent = NetworkActivityPresent,
            ConnectionChurnScore = ConnectionChurnScore,
            FailureReasonClass = FailureReasonClass,
            ObservationWindowSec = ObservationWindowSec,
            ObservationIntervalSec = ObservationIntervalSec,
            ObservationRounds = ObservationRounds,
            ProcessObservationUniqueCount = ProcessObservationUniqueCount,
            ProcessObservationPeakCount = ProcessObservationPeakCount,
            ProcessObservationChurn = ProcessObservationChurn,
            TcpObservationPeakCount = TcpObservationPeakCount,
            TcpObservationDeltaCount = TcpObservationDeltaCount,
            ShortLivedProcessSuspected = ShortLivedProcessSuspected,
            ShortLivedNetworkSuspected = ShortLivedNetworkSuspected,
            CollectionProfile = string.IsNullOrWhiteSpace(CollectionProfileStored) ? "fast" : CollectionProfileStored,
            DurationBudgetSecMax = _durationBudgetSecMax,
            DurationBudgetSecConsumed = ScanDurationSecsForBudget > 0 ? ScanDurationSecsForBudget : (int)Math.Max(0L, ScanDurationMs / 1000L),
            CollectorExecution = _collectorExecution,
            ObservationOnlyEntityCount = CountObservationOnly()
        };
        return new EvidencePackage
        {
            SchemaVersionValue = EvidencePackage.SchemaVersion,
            ScannerVersionValue = EvidencePackage.ScannerVersion,
            CollectionTimeUtc = CollectionTimeUtc,
            Host = new HostInfo
            {
                Hostname = Hostname,
                Os = HostOs,
                OsVersion = HostOsVersion,
                Architecture = HostArchitecture
            },
            Evidence = _evidence.OrderBy(e => e.EvidenceId).ToList(),
            CollectionMetadata = meta
        };
    }

    private int CountObservationOnly()
    {
        var n = 0;
        foreach (var e in _evidence)
        {
            if (!e.Details.TryGetValue("observation_only", out var o))
                continue;
            if (o is bool b && b)
                n++;
        }
        return n;
    }
}
