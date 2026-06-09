using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text.Json;
using NineSTriage.Engine.Probes;
using NineSTriage.Engine.Evidence;
using NineSTriage.Engine.License;

namespace NineSTriage.Engine;

public sealed class ScanRunnerOptions
{
    public string OutputDir { get; set; } = "";
    public string? ZipPath { get; set; }
    public bool CreateZip { get; set; }
    public bool ZipOnlyOutput { get; set; }
    public long? TimeBudgetMsPerModule { get; set; }
    public string? LicensePath { get; set; }
    /// <summary>Bounded triage profile: fast, observe, or escalated.</summary>
    public string CollectionProfile { get; set; } = "fast";
    public int ObservationWindowSeconds { get; set; }
    public int ObservationIntervalSeconds { get; set; } = 15;
}

public sealed class ScanRunnerResult
{
    public int ExitCode { get; init; }
    public int EvidenceCount { get; init; }
    public List<string> Diagnostics { get; init; } = new();
    public string? ErrorMessage { get; init; }
    public string? EvidencePath { get; init; }
    public string? ManifestPath { get; init; }
    public string? ReportPath { get; init; }
    public string? ZipPath { get; init; }
}

public static class ScanRunner
{
    private const int MaxObservationWindowSeconds = 600;
    private const int MinObservationIntervalSeconds = 5;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static async Task<ScanRunnerResult> RunAsync(ScanRunnerOptions options, CancellationToken cancellationToken = default)
    {
        var startUtc = DateTime.UtcNow;
        var emitter = new EvidenceEmitter();
        var diagnostics = new List<string>();
        var failureReasons = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var partialScan = false;

        try
        {
            Directory.CreateDirectory(options.OutputDir);
            emitter.SetCollectionTimeUtc(startUtc.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            emitter.SetHost(
                Environment.MachineName ?? "unknown",
                Environment.OSVersion.Platform.ToString(),
                Environment.OSVersion.Version.ToString(),
                Environment.Is64BitOperatingSystem ? "x64" : "x86");
            emitter.SetPrivilegeLevel(GetPrivilegeLevel());

            var collectors = new ICollector[]
            {
                new ProcessCollector(),
                new NetworkCollector(),
                new MemoryCollector(),
                new PersistenceCollector(),
                new DriverCollector(),
                new ConsistencyCollector(),
                new ArtefactCollector(),
                new IntegrityCollector()
            };
            var budgetPerCollectorMs = options.TimeBudgetMsPerModule ?? -1L;
            var overallBudgetMs = budgetPerCollectorMs > 0 ? budgetPerCollectorMs * collectors.Length : -1L;
            var runSw = Stopwatch.StartNew();
            var execRows = new List<CollectorExecutionEntry>();

            foreach (var collector in collectors)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var remainingMs = overallBudgetMs > 0 ? Math.Max(0, overallBudgetMs - runSw.ElapsedMilliseconds) : -1L;
                if (overallBudgetMs > 0 && remainingMs <= 0)
                {
                    diagnostics.Add($"{collector.Name}: timeout (global budget exhausted)");
                    execRows.Add(new CollectorExecutionEntry
                    {
                        Collector = collector.Name,
                        Status = "error",
                        FailureReasonClass = "timeout",
                    });
                    failureReasons[collector.Name] = "timeout";
                    partialScan = true;
                    break;
                }
                try
                {
                    var collectorStartMs = runSw.ElapsedMilliseconds;
                    var evidenceCountBefore = emitter.Evidence.Count;
                    var result = default(CollectResult);
                    if (remainingMs > 0)
                    {
                        var collectorTimeoutMs = budgetPerCollectorMs > 0 ? Math.Min(remainingMs, budgetPerCollectorMs) : remainingMs;
                        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        linkedCts.CancelAfter(TimeSpan.FromMilliseconds(collectorTimeoutMs));
                        result = await Task.Run(
                            () => collector.Collect(emitter, collectorTimeoutMs, linkedCts.Token),
                            linkedCts.Token
                        ).ConfigureAwait(false);
                    }
                    else
                    {
                        result = collector.Collect(emitter, remainingMs, cancellationToken);
                    }
                    var statusText = result.Status == CollectStatus.Ok ? "ok" : result.Status == CollectStatus.Partial ? "partial" : "error";
                    diagnostics.Add(string.IsNullOrWhiteSpace(result.Message)
                        ? $"{collector.Name}: {statusText}"
                        : $"{collector.Name}: {statusText} ({result.Message})");

                    var stExec = result.Status switch
                    {
                        CollectStatus.Ok => "ok",
                        CollectStatus.Partial => "partial",
                        _ => "error"
                    };
                    execRows.Add(new CollectorExecutionEntry
                    {
                        Collector = collector.Name,
                        Status = stExec,
                        FailureReasonClass = result.Status == CollectStatus.Ok ? null : (result.FailureReasonClass ?? "unknown"),
                        DurationMs = (int)Math.Max(0L, runSw.ElapsedMilliseconds - collectorStartMs),
                        EvidenceEmittedCount = Math.Max(0, emitter.Evidence.Count - evidenceCountBefore),
                    });

                    if (result.Status != CollectStatus.Ok)
                        partialScan = true;
                    if (result.Status != CollectStatus.Ok && result.FailureReasonClass != null)
                        failureReasons[collector.Name] = result.FailureReasonClass;
                }
                catch (OperationCanceledException)
                {
                    diagnostics.Add($"{collector.Name}: cancelled");
                    failureReasons[collector.Name] = "timeout";
                    partialScan = true;
                    execRows.Add(new CollectorExecutionEntry
                    {
                        Collector = collector.Name,
                        Status = "error",
                        FailureReasonClass = "timeout",
                        DurationMs = 0,
                        EvidenceEmittedCount = 0,
                    });
                }
            }

            emitter.SetCollectorExecutionRecords(execRows);
            emitter.SetCollectionProfile(options.CollectionProfile);
            if (string.Equals(options.CollectionProfile, "escalated", StringComparison.OrdinalIgnoreCase))
            {
                emitter.AddEvidence(
                    "EV-ESC-TX-1",
                    "artefact",
                    "scanner",
                    null,
                    "veris",
                    null,
                    "extended_triage_context",
                    new Dictionary<string, object?>
                    {
                        ["escalated_profile_marker"] = true,
                        ["note"] = "Escalated triage profile: enriched bounded linkage context (facts still evidence-bound).",
                    },
                    0.45,
                    "low",
                    "Escalated profile emitted extra bounded artefact linkage marker.",
                    null);
            }

            var baselinePids = CollectBaselinePids(emitter);
            var normalizedWindow = Math.Clamp(options.ObservationWindowSeconds, 0, MaxObservationWindowSeconds);
            var normalizedInterval = Math.Max(MinObservationIntervalSeconds, options.ObservationIntervalSeconds);
            var observedNetworkActivity = emitter.Evidence.Any(e => e.Category == "network");
            var obsResult = await RunBoundedObservationAsync(
                normalizedWindow, normalizedInterval, startUtc, baselinePids, diagnostics, cancellationToken).ConfigureAwait(false);

            if (normalizedWindow > 0)
            {
                if (!string.IsNullOrWhiteSpace(obsResult.ChurnScore))
                    emitter.SetConnectionChurnScore(obsResult.ChurnScore);
                observedNetworkActivity = observedNetworkActivity || obsResult.TcpPeak > 0;
                emitter.SetObservationMachineMetadata(
                    normalizedWindow,
                    normalizedInterval,
                    obsResult.Rounds,
                    obsResult.ProcessUnionCount,
                    obsResult.ProcessPeakSample,
                    obsResult.ProcessChurn,
                    obsResult.TcpPeak,
                    obsResult.TcpDelta,
                    obsResult.ShortLivedProcessSuspected,
                    obsResult.ShortLivedNetworkSuspected);
                ApplyObservationEvidenceEnrichment(emitter, obsResult, baselinePids, startUtc, normalizedInterval);
                EmitProcessObservationSummary(emitter, obsResult, baselinePids);
            }

            ApplyProcessContextToMemoryEvidence(emitter);

            var endUtc = DateTime.UtcNow;
            var durationMs = (long)(endUtc - startUtc).TotalMilliseconds;
            emitter.SetCollectionMetadata(durationMs, partialScan, false);
            emitter.SetDurationBudgetConsumedSec((int)Math.Round(durationMs / 1000.0, MidpointRounding.AwayFromZero));
            emitter.SetCollectionEndTimeUtc(endUtc.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            emitter.SetDiagnostics(diagnostics);
            emitter.SetNetworkActivityPresent(observedNetworkActivity);
            if (failureReasons.Count > 0)
                emitter.SetFailureReasonClass(failureReasons);

            var package = emitter.BuildPackage();
            var evidencePath = Path.Combine(options.OutputDir, "evidence.json");
            await File.WriteAllTextAsync(evidencePath, JsonSerializer.Serialize(package, JsonOptions), cancellationToken).ConfigureAwait(false);

            var reportPath = Path.Combine(options.OutputDir, "endpoint_report.md");
            await ReportWriter.WriteReportAsync(
                reportPath,
                package,
                "full report",
                Array.Empty<string>(),
                cancellationToken).ConfigureAwait(false);

            await ManifestWriter.WriteManifestAsync(options.OutputDir, evidencePath, reportPath, cancellationToken).ConfigureAwait(false);
            var manifestPath = Path.Combine(options.OutputDir, "manifest.json");

            if (options.CreateZip && !string.IsNullOrEmpty(options.ZipPath))
            {
                await ZipWriter.CreateEvidenceZipAsync(options.ZipPath, options.OutputDir, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (options.ZipOnlyOutput)
                    CleanupIntermediateFiles(options.OutputDir, evidencePath, reportPath, manifestPath);
            }

            return new ScanRunnerResult
            {
                ExitCode = 0,
                EvidenceCount = package.Evidence.Count,
                Diagnostics = diagnostics,
                EvidencePath = evidencePath,
                ManifestPath = manifestPath,
                ReportPath = reportPath,
                ZipPath = options.CreateZip ? options.ZipPath : null
            };
        }
        catch (Exception ex)
        {
            diagnostics.Add($"fatal: {ex.Message}");
            return new ScanRunnerResult
            {
                ExitCode = 1,
                EvidenceCount = emitter.Evidence.Count,
                Diagnostics = diagnostics,
                ErrorMessage = ex.Message
            };
        }
    }

    private static void ApplyProcessContextToMemoryEvidence(EvidenceEmitter emitter)
    {
        var contextByPid = new Dictionary<int, Dictionary<string, object?>>();
        foreach (var e in emitter.Evidence)
        {
            if (e.Category != "process" || e.Signal != "process_enumerated" || e.Target.Pid is not int pid)
                continue;
            var context = new Dictionary<string, object?>();
            if (e.Details.TryGetValue("process_enrichment", out var enrichmentObj) &&
                enrichmentObj is Dictionary<string, object?> enrichment &&
                enrichment.Count > 0)
            {
                foreach (var kv in enrichment)
                    context[kv.Key] = kv.Value;
            }
            if (e.Details.TryGetValue("process_identity", out var identityObj) &&
                identityObj is Dictionary<string, object?> identity &&
                identity.Count > 0)
            {
                context["identity"] = new Dictionary<string, object?>(identity);
            }
            if (context.Count > 0)
                contextByPid[pid] = context;
        }

        foreach (var e in emitter.Evidence)
        {
            if (e.Category != "memory" || e.Target.Pid is not int pid)
                continue;
            if (!contextByPid.TryGetValue(pid, out var context))
                continue;
            e.Details["process_context"] = new Dictionary<string, object?>(context);
        }
    }

    private static HashSet<int> CollectBaselinePids(EvidenceEmitter emitter)
    {
        var pids = new HashSet<int>();
        foreach (var e in emitter.Evidence)
        {
            if (e.Category == "process" && e.Signal == "process_enumerated" && e.Target.Pid is { } pp)
                pids.Add(pp);
            if (e.Category == "network" && e.Target.Pid is { } np)
                pids.Add(np);
            if (e.Category == "network" && e.Details.TryGetValue("pid", out var po))
            {
                if (po is long l) pids.Add((int)l);
                else if (po is int ii) pids.Add(ii);
            }
        }
        return pids;
    }

    private sealed class ObservationAccumulator
    {
        public Dictionary<int, PidObservation> PerPid { get; } = new();
        public int ProcessPeakSample { get; set; }
        public int ProcessUnionCount { get; set; }
        public int TcpPeak { get; set; }
        public int TcpDelta { get; set; }
        public string ChurnScore { get; set; } = "low";
        public int RoundsExecuted { get; set; }

        public class PidObservation
        {
            public int FirstRound { get; set; }
            public int LastRound { get; set; }
            public int SeenRounds { get; set; }
        }
    }

    private static void ApplyObservationEvidenceEnrichment(
        EvidenceEmitter emitter,
        ObservationResultDto obs,
        HashSet<int> baselinePids,
        DateTime startUtc,
        int intervalSec)
    {
        if (obs.Rounds <= 0) return;

        foreach (var e in emitter.Evidence)
        {
            if (e.Category != "process" || e.Signal != "process_enumerated" || e.Target.Pid is not int pid)
                continue;
            if (!obs.PerPidObservation.TryGetValue(pid, out var ob))
                continue;
            var t0 = startUtc.AddSeconds(ob.FirstRound * intervalSec).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var t1 = startUtc.AddSeconds(ob.LastRound * intervalSec).ToString("yyyy-MM-ddTHH:mm:ssZ");
            e.Details["first_seen_utc"] = t0;
            e.Details["last_seen_utc"] = t1;
            e.Details["seen_count"] = ob.SeenRounds;
            e.Details["seen_in_observation_window"] = true;
            e.Details["seen_in_snapshot"] = true;
        }

        foreach (var e in emitter.Evidence)
        {
            if (e.Category != "network") continue;
            if (e.Details.TryGetValue("local_address", out var _) == false) continue;
            var key = NetworkFingerprintFromDetails(e.Details);
            if (string.IsNullOrEmpty(key)) continue;
            if (obs.TcpKeyObservation.TryGetValue(key, out var rounds))
            {
                e.Details["first_seen_utc"] = startUtc.AddSeconds(Math.Max(0, rounds.FirstRound * intervalSec)).ToString("yyyy-MM-ddTHH:mm:ssZ");
                e.Details["last_seen_utc"] = startUtc.AddSeconds(Math.Max(0, rounds.LastRound * intervalSec)).ToString("yyyy-MM-ddTHH:mm:ssZ");
                e.Details["seen_count"] = rounds.SeenRounds;
                e.Details["seen_in_observation_window"] = true;
                e.Details["seen_in_snapshot"] = true;
                e.Details["observation_transient"] = rounds.SeenRounds < Math.Max(2, obs.Rounds / 2);
            }
        }

        foreach (var pid in obs.OnlyObservationPids)
        {
            if (baselinePids.Contains(pid)) continue;
            string name = "unknown";
            try
            {
                using var p = Process.GetProcessById(pid);
                name = p.ProcessName ?? name;
            }
            catch { }

            var details = new Dictionary<string, object?>
            {
                ["observation_only"] = true,
                ["seen_in_observation_window"] = true,
                ["seen_in_snapshot"] = false
            };
            if (obs.PerPidObservation.TryGetValue(pid, out var ob))
            {
                details["first_seen_utc"] = startUtc.AddSeconds(ob.FirstRound * intervalSec).ToString("yyyy-MM-ddTHH:mm:ssZ");
                details["last_seen_utc"] = startUtc.AddSeconds(ob.LastRound * intervalSec).ToString("yyyy-MM-ddTHH:mm:ssZ");
                details["seen_count"] = ob.SeenRounds;
            }
            emitter.AddEvidence(
                $"process-obs-{pid}",
                "process",
                "process",
                pid,
                name,
                null,
                "process_enumerated",
                details,
                0.5,
                "low",
                "Process observed only during bounded observation window (may be short-lived).",
                null);
        }
    }

    private static string? NetworkFingerprintFromDetails(Dictionary<string, object?> d)
    {
        int pid = -1;
        if (d.TryGetValue("pid", out var v))
        {
            if (v is int i) pid = i;
            else if (v is long l) pid = (int)l;
        }

        if (pid < 0) return null;
        var la = d.TryGetValue("local_address", out var a) ? a?.ToString() : null;
        var ra = d.TryGetValue("remote_address", out var r) ? r?.ToString() : null;
        var lp = d.TryGetValue("local_port", out var lpv) ? lpv : null;
        var rp = d.TryGetValue("remote_port", out var rpv) ? rpv : null;
        if (la == null || ra == null) return null;
        return $"{pid}|{la}:{lp}->{ra}:{rp}";
    }

    private sealed class ObservationResultDto
    {
        public string ChurnScore { get; init; } = "low";
        public int ProcessUnionCount { get; init; }
        public int ProcessChurn { get; init; }
        public int TcpDelta { get; init; }
        public int TcpPeak { get; init; }
        public int Rounds { get; init; }
        public int ProcessPeakSample { get; init; }
        public bool ShortLivedProcessSuspected { get; init; }
        public bool ShortLivedNetworkSuspected { get; init; }
        public Dictionary<int, ObservationAccumulator.PidObservation> PerPidObservation { get; init; } = new();
        public Dictionary<string, TcpObservationStats> TcpKeyObservation { get; init; } = new(StringComparer.Ordinal);
        public HashSet<int> OnlyObservationPids { get; init; } = new();
        public HashSet<int> FinalRoundPids { get; init; } = new();
        public HashSet<int> EarlyExitPids { get; init; } = new();
    }

    private sealed class TcpObservationStats
    {
        public int FirstRound { get; set; }
        public int LastRound { get; set; }
        public int SeenRounds { get; set; }
    }

    private static async Task<ObservationResultDto> RunBoundedObservationAsync(
        int windowSeconds,
        int intervalSeconds,
        DateTime startUtc,
        HashSet<int> baselinePids,
        List<string> diagnostics,
        CancellationToken cancellationToken)
    {
        if (windowSeconds <= 0 || !OperatingSystem.IsWindows())
        {
            return new ObservationResultDto { Rounds = 0 };
        }

        var acc = new ObservationAccumulator();
        var rounds = Math.Max(1, windowSeconds / intervalSeconds);
        var processCounts = new List<int>();
        var tcpCounts = new List<int>();
        var pidUnion = new HashSet<int>();
        var finalRoundPids = new HashSet<int>();
        var tcpGlobalKeys = new Dictionary<string, TcpObservationStats>(StringComparer.Ordinal);

        for (var i = 0; i <= rounds; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sampledCount = 0;
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    var id = p.Id;
                    pidUnion.Add(id);
                    sampledCount++;
                    if (!acc.PerPid.TryGetValue(id, out var obs))
                    {
                        acc.PerPid[id] = new ObservationAccumulator.PidObservation
                        {
                            FirstRound = i,
                            LastRound = i,
                            SeenRounds = 1
                        };
                    }
                    else
                    {
                        obs.LastRound = i;
                        obs.SeenRounds++;
                    }
                }
                finally { p.Dispose(); }
            }
            if (i == rounds)
                finalRoundPids = new HashSet<int>(acc.PerPid.Where(kv => kv.Value.LastRound == i).Select(kv => kv.Key));
            processCounts.Add(sampledCount);
            if (sampledCount > acc.ProcessPeakSample)
                acc.ProcessPeakSample = sampledCount;

            try
            {
                var tcpCount = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Length;
                tcpCounts.Add(tcpCount);
            }
            catch
            {
                tcpCounts.Add(0);
            }

            var keys = TcpObservationSampler.SnapshotEstablishedKeys(cancellationToken);
            foreach (var k in keys)
            {
                if (!tcpGlobalKeys.TryGetValue(k, out var stat))
                {
                    tcpGlobalKeys[k] = new TcpObservationStats
                    {
                        FirstRound = i,
                        LastRound = i,
                        SeenRounds = 1,
                    };
                }
                else
                {
                    stat.LastRound = i;
                    stat.SeenRounds++;
                }
            }

            if (i < rounds)
                await Task.Delay(TimeSpan.FromSeconds(intervalSeconds), cancellationToken).ConfigureAwait(false);
        }

        acc.ProcessUnionCount = pidUnion.Count;
        acc.RoundsExecuted = rounds + 1;
        var processChurn = processCounts.Count > 1 ? Math.Abs(processCounts.Max() - processCounts.Min()) : 0;
        var tcpDelta = tcpCounts.Count > 1 ? Math.Abs(tcpCounts.Max() - tcpCounts.Min()) : 0;
        acc.TcpDelta = tcpDelta;
        acc.TcpPeak = tcpCounts.Count > 0 ? tcpCounts.Max() : 0;
        acc.ChurnScore = tcpDelta >= 80 ? "high" : tcpDelta >= 20 ? "medium" : "low";

        var onlyObs = new HashSet<int>(pidUnion);
        onlyObs.ExceptWith(baselinePids);
        var earlyExitPids = acc.PerPid
            .Where(kv => kv.Value.LastRound < acc.RoundsExecuted - 1)
            .Select(kv => kv.Key)
            .ToHashSet();

        var shortLivedProc = onlyObs.Count > 0;
        var shortLivedNet = tcpDelta >= 20 && tcpGlobalKeys.Values.Any(v => v.SeenRounds < acc.RoundsExecuted);

        diagnostics.Add(
            $"observation_window: ok (bounded={windowSeconds}s, interval={intervalSeconds}s, unique_processes={acc.ProcessUnionCount}, process_churn={processChurn}, tcp_delta={tcpDelta}, tcp_peak={acc.TcpPeak}, churn={acc.ChurnScore})");

        return new ObservationResultDto
        {
            ChurnScore = acc.ChurnScore,
            ProcessUnionCount = acc.ProcessUnionCount,
            ProcessChurn = processChurn,
            TcpDelta = tcpDelta,
            TcpPeak = acc.TcpPeak,
            Rounds = acc.RoundsExecuted,
            ProcessPeakSample = acc.ProcessPeakSample,
            ShortLivedProcessSuspected = shortLivedProc,
            ShortLivedNetworkSuspected = shortLivedNet,
            PerPidObservation = acc.PerPid.ToDictionary(kv => kv.Key, kv => kv.Value),
            TcpKeyObservation = tcpGlobalKeys,
            OnlyObservationPids = onlyObs,
            FinalRoundPids = finalRoundPids,
            EarlyExitPids = earlyExitPids
        };
    }

    private static void EmitProcessObservationSummary(EvidenceEmitter emitter, ObservationResultDto obs, HashSet<int> baselinePids)
    {
        if (obs.Rounds <= 0)
            return;

        const int maxProcessSample = 12;
        var newProcessRows = obs.OnlyObservationPids
            .OrderBy(pid => pid)
            .Take(maxProcessSample)
            .Select(pid => BuildObservationProcessRow(pid, obs))
            .ToList();
        var terminatedRows = obs.EarlyExitPids
            .Where(pid => !obs.FinalRoundPids.Contains(pid) && !baselinePids.Contains(pid))
            .OrderBy(pid => pid)
            .Take(maxProcessSample)
            .Select(pid => BuildObservationProcessRow(pid, obs))
            .ToList();

        emitter.AddEvidence(
            "process-observation-summary-1",
            "artefact",
            "host",
            null,
            "process_observation",
            null,
            "process_observation_summary",
            new Dictionary<string, object?>
            {
                ["rounds"] = obs.Rounds,
                ["process_union_count"] = obs.ProcessUnionCount,
                ["process_peak_count"] = obs.ProcessPeakSample,
                ["process_churn_count"] = obs.ProcessChurn,
                ["new_process_count"] = obs.OnlyObservationPids.Count,
                ["terminated_process_count"] = obs.EarlyExitPids.Count(pid => !obs.FinalRoundPids.Contains(pid) && !baselinePids.Contains(pid)),
                ["new_processes"] = newProcessRows,
                ["terminated_processes"] = terminatedRows,
                ["bounds"] = new Dictionary<string, object?>
                {
                    ["process_sample_max"] = maxProcessSample
                }
            },
            0.85,
            "low",
            "Bounded process observation summary for short-lived lifecycle visibility.",
            null);
    }

    private static Dictionary<string, object?> BuildObservationProcessRow(int pid, ObservationResultDto obs)
    {
        var row = new Dictionary<string, object?>
        {
            ["pid"] = pid
        };
        if (obs.PerPidObservation.TryGetValue(pid, out var ob))
        {
            row["first_round"] = ob.FirstRound;
            row["last_round"] = ob.LastRound;
            row["seen_rounds"] = ob.SeenRounds;
        }
        try
        {
            using var process = Process.GetProcessById(pid);
            row["name"] = ProcessCollector.TruncateForEvidence(process.ProcessName, 80) ?? "unknown";
        }
        catch
        {
            // Best effort only; PID-only sample remains valid evidence.
        }
        return row;
    }

    private static void CleanupIntermediateFiles(string outputDir, string evidencePath, string reportPath, string manifestPath)
    {
        TryDelete(evidencePath);
        TryDelete(reportPath);
        TryDelete(manifestPath);
        TryDelete(Path.Combine(outputDir, "manifest.sig"));
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // Best-effort cleanup only; never fail scan output on local delete errors.
        }
    }

    private static string GetPrivilegeLevel()
    {
        if (!OperatingSystem.IsWindows()) return "unknown";
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator) ? "elevated" : "normal";
        }
        catch { return "unknown"; }
    }
}
