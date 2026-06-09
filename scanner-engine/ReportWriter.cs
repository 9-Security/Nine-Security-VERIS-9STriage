namespace NineSTriage.Engine;

public static class ReportWriter
{
    public static async Task WriteReportAsync(
        string path,
        Evidence.EvidencePackage package,
        string licenseMode,
        IReadOnlyList<string> enabledFeatureFlags,
        CancellationToken cancellationToken = default)
    {
        var sb = new System.Text.StringBuilder();
        var host = package.Host;
        var meta = package.CollectionMetadata;

        sb.AppendLine("# 9STriage — Endpoint Report");
        sb.AppendLine();
        sb.AppendLine("## Host");
        sb.AppendLine($"- **Hostname:** {host.Hostname}");
        sb.AppendLine($"- **OS:** {host.Os}");
        if (!string.IsNullOrWhiteSpace(host.OsVersion))
            sb.AppendLine($"- **OS version:** {host.OsVersion}");
        if (!string.IsNullOrWhiteSpace(host.Architecture))
            sb.AppendLine($"- **Architecture:** {host.Architecture}");
        sb.AppendLine();
        sb.AppendLine("## Scan");
        sb.AppendLine($"- **Collection time (UTC):** {package.CollectionTimeUtc}");
        if (!string.IsNullOrWhiteSpace(meta.CollectionEndTimeUtc))
            sb.AppendLine($"- **Collection end time (UTC):** {meta.CollectionEndTimeUtc}");
        sb.AppendLine($"- **Duration (ms):** {meta.ScanDurationMs}");
        sb.AppendLine($"- **Partial scan:** {(meta.PartialScan ? "yes" : "no")}");
        sb.AppendLine($"- **Interference suspected:** {(meta.InterferenceSuspected ? "yes" : "no")}");
        if (!string.IsNullOrWhiteSpace(meta.PrivilegeLevel))
            sb.AppendLine($"- **Privilege level:** {meta.PrivilegeLevel}");
        sb.AppendLine($"- **Evidence count:** {package.Evidence.Count}");
        sb.AppendLine();

        if (meta.Diagnostics is { Count: > 0 })
        {
            sb.AppendLine("## Scan diagnostics (report-only, non-sensitive)");
            foreach (var diagnostic in meta.Diagnostics)
                sb.AppendLine($"- {diagnostic}");
            sb.AppendLine();
        }

        sb.AppendLine("## License Status (report-only)");
        sb.AppendLine($"- **Mode:** {licenseMode}");
        sb.AppendLine($"- **Enabled feature flags:** {string.Join(", ", enabledFeatureFlags)}");
        sb.AppendLine();
        sb.AppendLine("---");
        sb.AppendLine("*Evidence package: evidence.json (machine-readable). License data is not in evidence.json.*");
        sb.AppendLine("*Privacy: paths and other sensitive fields are not printed in this report.*");
        await File.WriteAllTextAsync(path, sb.ToString(), cancellationToken).ConfigureAwait(false);
    }
}
