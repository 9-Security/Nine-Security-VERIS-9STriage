using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using NineSTriage.Engine.Evidence;

namespace NineSTriage.Engine.Probes;

/// <summary>Artefact collector: Prefetch snapshot, Amcache observable, event log indicator, recent executables (Prefetch modified in 24h). Aligned with C++ artefact.cpp. No path in evidence per SECURITY_MODEL §9 where applicable.</summary>
public sealed class ArtefactCollector : ICollector
{
    public string Name => "artefact";

    private const int MaxPrefetchEvidence = 50;
    private const int MaxRecentExecutableEvidence = 30;
    private const long RecentExecutableWindowSeconds = 24 * 60 * 60; // 24h

    private const int EventlogSequentialRead = 0x0004;
    private const int EventlogForwardsRead = 0x0008;

    public CollectResult Collect(IEvidenceSink sink, long remainingMs = -1, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return CollectResult.Fail("Artefact collector is Windows-only.", "api_not_supported");

        var start = Stopwatch.StartNew();
        long Remaining() => remainingMs < 0 ? -1 : Math.Max(0, remainingMs - start.ElapsedMilliseconds);

        try
        {
            if (Remaining() == 0) return CollectResult.Partial();
            var r1 = CollectPrefetchSnapshot(sink, Remaining(), cancellationToken);
            if (r1.Status == CollectStatus.Fail) return r1;

            if (Remaining() == 0) return CollectResult.Partial();
            var r2 = CollectAmcacheSnapshot(sink, Remaining(), cancellationToken);
            if (r2.Status == CollectStatus.Fail) return r2;

            if (Remaining() == 0) return CollectResult.Partial();
            var r3 = CollectEventLogIndicator(sink, Remaining(), cancellationToken);
            if (r3.Status == CollectStatus.Fail) return r3;

            if (Remaining() == 0) return CollectResult.Partial();
            var r4 = CollectRecentExecutables(sink, Remaining(), cancellationToken);
            if (r4.Status == CollectStatus.Fail) return r4;

            bool anyPartial = r1.Status == CollectStatus.Partial || r2.Status == CollectStatus.Partial ||
                              r3.Status == CollectStatus.Partial || r4.Status == CollectStatus.Partial;
            return anyPartial ? CollectResult.Partial() : CollectResult.Ok();
        }
        catch (Exception ex)
        {
            return CollectResult.Fail(ex.Message, "unknown");
        }
    }

    private static CollectResult CollectPrefetchSnapshot(IEvidenceSink sink, long remainingMs, CancellationToken ct)
    {
        var sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
        if (string.IsNullOrEmpty(sysRoot)) return CollectResult.Partial();

        var searchDir = Path.Combine(sysRoot, "Prefetch");
        if (!Directory.Exists(searchDir)) return CollectResult.Partial();

        bool partial = false;
        int seq = 0;
        try
        {
            foreach (var path in Directory.EnumerateFiles(searchDir, "*.pf"))
            {
                if (remainingMs >= 0 && remainingMs < 50) { partial = true; break; }
                ct.ThrowIfCancellationRequested();
                if (seq >= MaxPrefetchEvidence) { partial = true; break; }
                var filename = Path.GetFileName(path) ?? "unknown";
                long sizeBytes = 0;
                try
                {
                    sizeBytes = new FileInfo(path).Length;
                }
                catch { }
                seq++;
                var details = new Dictionary<string, object?>
                {
                    ["filename"] = filename,
                    ["size_bytes"] = sizeBytes
                };
                sink.AddEvidence($"EV-A-{seq}", "artefact", "file", null, filename, null,
                    "prefetch_anomaly", details, 0.5, "low", "Prefetch file observed (snapshot)", null);
            }
        }
        catch (UnauthorizedAccessException) { partial = true; }
        return partial ? CollectResult.Partial() : CollectResult.Ok();
    }

    private static CollectResult CollectAmcacheSnapshot(IEvidenceSink sink, long remainingMs, CancellationToken ct)
    {
        var sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
        if (string.IsNullOrEmpty(sysRoot)) return CollectResult.Ok();

        var path = Path.Combine(sysRoot, "AppCompat", "Programs", "Amcache.hve");
        try
        {
            if (!File.Exists(path)) return CollectResult.Ok();
            ct.ThrowIfCancellationRequested();
            long sizeBytes = new FileInfo(path).Length;
            var details = new Dictionary<string, object?>
            {
                ["observable"] = true,
                ["size_bytes"] = sizeBytes
            };
            sink.AddEvidence("EV-A-Amcache-1", "artefact", "amcache", null, "amcache", null,
                "amcache_artifact", details, 0.7, "low",
                "Amcache hive observable (no path in evidence)", null);
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        return CollectResult.Ok();
    }

    private static CollectResult CollectEventLogIndicator(IEvidenceSink sink, long remainingMs, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            var query = new EventLogQuery("System", PathType.LogName, "*") { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            int seq = 0;
            var maxEvidence = 8;
            for (var rev = reader.ReadEvent(); rev != null && seq < maxEvidence; rev = reader.ReadEvent())
            {
                using (rev)
                {
                    ct.ThrowIfCancellationRequested();
                    seq++;
                    long? ridNullable = rev.RecordId;
                    int id = ridNullable.HasValue ? unchecked((ushort)ridNullable.Value) : seq;
                    var time = rev.TimeCreated?.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") ?? "";
                    var provider = rev.ProviderName ?? "";
                    string kind = "operational_indicator";
                    if (id is 104 or 1100 or 1102)
                        kind = "log_clear_reset";
                    else if (provider.Contains("Audit", StringComparison.OrdinalIgnoreCase) ||
                             id == 4719 || id == 1102)
                        kind = "audit_policy_weakness";

                    var details = new Dictionary<string, object?>
                    {
                        ["channel"] = "System",
                        ["provider"] = provider,
                        ["event_id"] = id,
                        ["record_time_utc"] = time,
                        ["indicator_kind"] = kind
                    };
                    sink.AddEvidence($"EV-A-EL-{seq}", "artefact", "event_log", null, "System", null,
                        "event_log_indicator", details, 0.6, "low",
                        "Windows event record metadata sampled (bounded; no rendered message)", null);
                }
            }

            if (seq == 0)
            {
                IntPtr hLog = Native.OpenEventLogW(IntPtr.Zero, "System");
                if (hLog == IntPtr.Zero) return CollectResult.Ok();
                try
                {
                    var buf = new byte[8192];
                    if (!Native.ReadEventLogW(hLog, EventlogSequentialRead | EventlogForwardsRead, 0, buf, (uint)buf.Length, out uint read, out _)
                        || read == 0)
                        return CollectResult.Ok();
                    sink.AddEvidence("EV-A-EventLog-1", "artefact", "event_log", null, "System", null,
                        "event_log_indicator", new Dictionary<string, object?>
                        {
                            ["channel"] = "System",
                            ["readable"] = true,
                            ["indicator_kind"] = "operational_indicator",
                            ["provider"] = "unknown",
                            ["event_id"] = null as object,
                            ["record_time_utc"] = null as object,
                        }, 0.5, "low",
                        "Event log reachable but structured read returned no rows (fallback observable only).", null);
                }
                finally
                {
                    Native.CloseEventLog(hLog);
                }
            }
        }
        catch (Exception ex)
        {
            sink.AddEvidence("EV-A-EventLog-err", "artefact", "event_log", null, "System", null,
                "event_log_indicator", new Dictionary<string, object?>
                {
                    ["channel"] = "System",
                    ["indicator_kind"] = "operational_indicator",
                    ["error"] = ex.Message[..Math.Min(120, ex.Message.Length)]
                }, 0.4, "low",
                "Event log sampling constrained (exceptions are observable fact only)", null);
        }
        return CollectResult.Ok();
    }

    private static CollectResult CollectRecentExecutables(IEvidenceSink sink, long remainingMs, CancellationToken ct)
    {
        var sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
        if (string.IsNullOrEmpty(sysRoot)) return CollectResult.Ok();

        var searchDir = Path.Combine(sysRoot, "Prefetch");
        if (!Directory.Exists(searchDir)) return CollectResult.Ok();

        var cutoffUtc = DateTime.UtcNow.AddSeconds(-RecentExecutableWindowSeconds);
        bool partial = false;
        int seq = 0;
        try
        {
            foreach (var path in Directory.EnumerateFiles(searchDir, "*.pf"))
            {
                if (remainingMs >= 0 && remainingMs < 50) { partial = true; break; }
                ct.ThrowIfCancellationRequested();
                FileInfo? fi = null;
                try { fi = new FileInfo(path); } catch { continue; }
                if (fi.LastWriteTimeUtc < cutoffUtc) continue;
                if (seq >= MaxRecentExecutableEvidence) { partial = true; break; }
                var filename = fi.Name;
                var modifiedUtc = fi.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ");
                seq++;
                var details = new Dictionary<string, object?>
                {
                    ["filename"] = filename,
                    ["size_bytes"] = fi.Length,
                    ["modified_utc"] = modifiedUtc
                };
                sink.AddEvidence($"EV-A-Recent-{seq}", "artefact", "file", null, filename, null,
                    "recent_executable", details, 0.5, "low",
                    "Recently modified executable artefact (Prefetch; basename only, no path)", null);
            }
        }
        catch (UnauthorizedAccessException) { partial = true; }
        return partial ? CollectResult.Partial() : CollectResult.Ok();
    }

    private static class Native
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenEventLogW(IntPtr lpUNCServerName, string lpSourceName);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseEventLog(IntPtr hEventLog);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadEventLogW(IntPtr hEventLog, uint dwReadFlags, uint dwRecordOffset,
            byte[] lpBuffer, uint nNumberOfBytesToRead, out uint pnBytesRead, out uint pnMinNumberOfBytesNeeded);
    }
}
