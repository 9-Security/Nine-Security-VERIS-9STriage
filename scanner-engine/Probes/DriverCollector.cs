using System.Diagnostics;
using Microsoft.Win32;
using NineSTriage.Engine.Evidence;

namespace NineSTriage.Engine.Probes;

public sealed class DriverCollector : ICollector
{
    public string Name => "driver";

    private const int MaxDriverRows = 256;
    private const int MaxMiniFilterRows = 128;

    public CollectResult Collect(IEvidenceSink sink, long remainingMs = -1, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return CollectResult.Fail("Driver collector is Windows-only.", "api_not_supported");

        var partial = false;
        try
        {
            partial |= !CollectDriverInventory(sink, cancellationToken);
            partial |= !CollectMiniFilterInventory(sink, cancellationToken);
            return partial ? CollectResult.Partial() : CollectResult.Ok();
        }
        catch (Exception ex)
        {
            return CollectResult.Fail(ex.Message, "unknown");
        }
    }

    private static bool CollectDriverInventory(IEvidenceSink sink, CancellationToken cancellationToken)
    {
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
            if (services == null)
                return false;

            var drivers = new List<Dictionary<string, object?>>();
            foreach (var subKeyName in services.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var service = services.OpenSubKey(subKeyName, false);
                if (service == null)
                    continue;

                var typeValue = ProcessCollector.ToInt(service.GetValue("Type"));
                if (!typeValue.HasValue || (typeValue.Value & 0xB) == 0)
                    continue;

                var row = new Dictionary<string, object?>
                {
                    ["service_name"] = ProcessCollector.TruncateForEvidence(subKeyName, 80) ?? "unknown"
                };
                var displayName = ProcessCollector.TruncateForEvidence(service.GetValue("DisplayName")?.ToString(), 120);
                if (!string.IsNullOrWhiteSpace(displayName))
                    row["display_name"] = displayName;
                var imagePath = ProcessCollector.TruncateForEvidence(service.GetValue("ImagePath")?.ToString(), 180);
                if (!string.IsNullOrWhiteSpace(imagePath))
                    row["image_path"] = imagePath;
                row["start_type"] = StartTypeToString(ProcessCollector.ToInt(service.GetValue("Start")));
                row["service_type"] = DriverTypeToString(typeValue.Value);
                var group = ProcessCollector.TruncateForEvidence(service.GetValue("Group")?.ToString(), 80);
                if (!string.IsNullOrWhiteSpace(group))
                    row["group"] = group;
                var errorControl = ErrorControlToString(ProcessCollector.ToInt(service.GetValue("ErrorControl")));
                if (!string.IsNullOrWhiteSpace(errorControl))
                    row["error_control"] = errorControl;
                if (!string.IsNullOrWhiteSpace(imagePath))
                {
                    row["signer"] = GetSigner(imagePath);
                    ProcessEnrichment.AddFileSignatureDetails(row, imagePath);
                }

                drivers.Add(row);
                if (drivers.Count >= MaxDriverRows)
                    break;
            }

            var details = new Dictionary<string, object?>
            {
                ["count"] = drivers.Count,
                ["drivers"] = drivers,
                ["truncated"] = drivers.Count >= MaxDriverRows
            };
            sink.AddEvidence(
                "driver-inventory-1",
                "persistence",
                "driver_inventory",
                null,
                "kernel_drivers",
                null,
                "driver_inventory",
                details,
                1.0,
                "low",
                "Kernel driver inventory observed.",
                null);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool CollectMiniFilterInventory(IEvidenceSink sink, CancellationToken cancellationToken)
    {
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
            if (services == null)
                return false;

            var filters = new List<Dictionary<string, object?>>();
            foreach (var subKeyName in services.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var service = services.OpenSubKey(subKeyName, false);
                if (service == null)
                    continue;
                using var instances = service.OpenSubKey("Instances", false);
                if (instances == null)
                    continue;

                var defaultInstance = instances.GetValue("DefaultInstance")?.ToString();
                foreach (var instanceName in instances.GetSubKeyNames())
                {
                    using var instance = instances.OpenSubKey(instanceName, false);
                    if (instance == null)
                        continue;

                    var altitude = ProcessCollector.TruncateForEvidence(instance.GetValue("Altitude")?.ToString(), 40);
                    var flags = ProcessCollector.ToInt(instance.GetValue("Flags"));
                    var row = new Dictionary<string, object?>
                    {
                        ["name"] = ProcessCollector.TruncateForEvidence(subKeyName, 80) ?? "unknown",
                        ["instance"] = ProcessCollector.TruncateForEvidence(instanceName, 80) ?? "unknown"
                    };
                    if (!string.IsNullOrWhiteSpace(altitude))
                        row["altitude"] = altitude;
                    if (flags.HasValue)
                        row["flags"] = flags.Value;
                    if (!string.IsNullOrWhiteSpace(defaultInstance))
                        row["is_default_instance"] = string.Equals(instanceName, defaultInstance, StringComparison.OrdinalIgnoreCase);
                    var imagePath = ProcessCollector.TruncateForEvidence(service.GetValue("ImagePath")?.ToString(), 180);
                    if (!string.IsNullOrWhiteSpace(imagePath))
                        row["image_path"] = imagePath;
                    var group = ProcessCollector.TruncateForEvidence(service.GetValue("Group")?.ToString(), 80);
                    if (!string.IsNullOrWhiteSpace(group))
                        row["group"] = group;
                    filters.Add(row);
                    if (filters.Count >= MaxMiniFilterRows)
                        break;
                }

                if (filters.Count >= MaxMiniFilterRows)
                    break;
            }

            var details = new Dictionary<string, object?>
            {
                ["count"] = filters.Count,
                ["filters"] = filters,
                ["truncated"] = filters.Count >= MaxMiniFilterRows,
                ["source"] = "services_instances_registry"
            };
            sink.AddEvidence(
                "mini-filter-inventory-1",
                "persistence",
                "mini_filter_inventory",
                null,
                "mini_filters",
                null,
                "mini_filter_inventory",
                details,
                1.0,
                "low",
                "Mini-filter inventory observed.",
                null);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string StartTypeToString(int? startType)
    {
        return startType switch
        {
            0 => "boot",
            1 => "system",
            2 => "auto",
            3 => "demand",
            4 => "disabled",
            _ => "unknown"
        };
    }

    private static string DriverTypeToString(int typeValue)
    {
        return (typeValue & 0x2) != 0 ? "file_system_driver"
            : (typeValue & 0x1) != 0 ? "kernel_driver"
            : "driver";
    }

    private static string? ErrorControlToString(int? errorControl)
    {
        return errorControl switch
        {
            0 => "ignore",
            1 => "normal",
            2 => "severe",
            3 => "critical",
            _ => null
        };
    }

    private static string? GetSigner(string? path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path))
                return null;
            var expanded = Environment.ExpandEnvironmentVariables(path).Trim('"');
            if (!File.Exists(expanded))
                return null;
            return ProcessCollector.TruncateForEvidence(FileVersionInfo.GetVersionInfo(expanded).CompanyName, 80);
        }
        catch
        {
            return null;
        }
    }
}
