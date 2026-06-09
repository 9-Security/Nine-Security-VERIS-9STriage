using NineSTriage.Engine.Evidence;

namespace NineSTriage.Engine.Probes;

/// <summary>Integrity collector: binary_tamper_indicator (critical system binary without valid PE MZ header), config_tamper_indicator (HOSTS unusually large or high line count). No paths or sensitive content in evidence (SECURITY_MODEL §9). Aligned with C++ integrity.cpp.</summary>
public sealed class IntegrityCollector : ICollector
{
    public string Name => "integrity";

    private const int HostsUnusuallyLargeThresholdBytes = 32 * 1024;
    private const int HostsHighLineCountThreshold = 200;
    private const int HostsMaxReadBytes = 64 * 1024;

    public CollectResult Collect(IEvidenceSink sink, long remainingMs = -1, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return CollectResult.Fail("Integrity collector is Windows-only.", "api_not_supported");

        var sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
        if (string.IsNullOrEmpty(sysRoot))
            return CollectResult.Ok();

        int evidenceSeq = 0;
        bool partial = false;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Check one critical system binary (winlogon.exe) for valid PE header
            var winlogonPath = Path.Combine(sysRoot, "System32", "winlogon.exe");
            CheckSystemBinaryPeHeader(winlogonPath, sink, ref evidenceSeq);

            cancellationToken.ThrowIfCancellationRequested();

            // HOSTS file heuristic
            CheckHostsFile(sink, sysRoot, ref evidenceSeq);

            return partial ? CollectResult.Partial() : CollectResult.Ok();
        }
        catch (OperationCanceledException)
        {
            return CollectResult.Partial();
        }
        catch (Exception ex)
        {
            return CollectResult.Fail(ex.Message, "unknown");
        }
    }

    /// <summary>If file is readable and does not start with "MZ", emit binary_tamper_indicator. No path in evidence.</summary>
    private static bool CheckSystemBinaryPeHeader(string path, IEvidenceSink sink, ref int evidenceSeq)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var buf = new byte[64];
            int read = fs.Read(buf, 0, buf.Length);
            if (read < 2) return false;
            if (buf[0] == 'M' && buf[1] == 'Z') return false; // valid PE header start

            evidenceSeq++;
            var details = new Dictionary<string, object?> { ["reason"] = "pe_header_invalid" };
            sink.AddEvidence($"EV-Integrity-Bin-{evidenceSeq}", "integrity", "binary", null, "system_binary", null,
                "binary_tamper_indicator", details, 0.7, "medium",
                "Critical system binary did not have valid PE header (MZ)", null);
            return true;
        }
        catch (UnauthorizedAccessException) { return false; }
        catch (IOException) { return false; }
    }

    /// <summary>HOSTS unusually large (>32K) or line count >200 -> config_tamper_indicator. No path or content in evidence.</summary>
    private static void CheckHostsFile(IEvidenceSink sink, string sysRoot, ref int evidenceSeq)
    {
        var path = Path.Combine(sysRoot, "System32", "drivers", "etc", "hosts");
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return;
            long sizeBytes = fi.Length;

            bool emit = false;
            string? reason = null;

            if (sizeBytes > HostsUnusuallyLargeThresholdBytes)
            {
                emit = true;
                reason = "unusually_large";
            }
            else if (sizeBytes > 0 && sizeBytes <= HostsMaxReadBytes)
            {
                var toRead = (int)Math.Min(sizeBytes, HostsMaxReadBytes);
                var buf = new byte[toRead];
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                    fs.Read(buf, 0, toRead);
                int lines = 0;
                for (int i = 0; i < toRead; i++)
                    if (buf[i] == '\n') lines++;
                if (toRead > 0 && buf[toRead - 1] != '\n') lines++;
                if (lines > HostsHighLineCountThreshold)
                {
                    emit = true;
                    reason = "high_line_count";
                }
            }

            if (!emit || reason == null) return;

            evidenceSeq++;
            var details = new Dictionary<string, object?> { ["reason"] = reason };
            if (reason == "unusually_large")
                details["size_bytes"] = sizeBytes;
            sink.AddEvidence($"EV-Integrity-Cfg-{evidenceSeq}", "integrity", "config", null, "hosts", null,
                "config_tamper_indicator", details, 0.6, "medium",
                "HOSTS file heuristic: " + reason, null);
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }
}
