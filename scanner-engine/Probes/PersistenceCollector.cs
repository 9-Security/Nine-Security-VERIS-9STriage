using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Management;
using Microsoft.Win32;
using NineSTriage.Engine.Evidence;

namespace NineSTriage.Engine.Probes;

/// <summary>Persistence collector: Run/RunOnce keys, services, scheduled tasks (TaskCache Tree), IFEO, startup folders, WMI event consumers. Aligned with C++ persistence.cpp.</summary>
public sealed class PersistenceCollector : ICollector
{
    public string Name => "persistence";

    private const int MaxWmiConsumers = 50;
    private const int MaxScheduledTaskSamples = 64;
    private const int MaxScheduledTaskFallbackSignals = 5;

    private static readonly string[] BenignRunSubstrings =
    {
        "securityhealth", "security health", "windows defender", "windows security",
        "onedrive", "microsoft onedrive", "realtek", "rtkaud", "rtkbtman", "rtk",
        "cortana", "ctfmon", "windows update", "wuauclt", "systemtray",
        "explorer", "sidebar", "windows sidebar", "program files\\windows apps",
        "\\system32\\", "\\syswow64\\",
        "microsoft teams", "teams.exe", "spotify", "dropbox",
        "google update", "gupdate", "gupdatem",
        "nvidia", "nvcontainer", "nvidia share", "intel", "igfx", "intelcpd",
        "razer", "synapse", "logitech", "logi ",
        "searchapp", "search host", "startmenuexperiencehost", "shellexperiencehost",
        "textinputhost", "lockapp", "gamebar", "game bar", "widgets",
        "securityhealthsystray", "securityhealthservice"
    };

    public CollectResult Collect(IEvidenceSink sink, long remainingMs = -1, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return CollectResult.Fail("Persistence collector is Windows-only.", "api_not_supported");

        var start = Stopwatch.StartNew();
        long Remaining() => remainingMs < 0 ? -1 : Math.Max(0, remainingMs - start.ElapsedMilliseconds);

        try
        {
            if (Remaining() == 0) return CollectResult.Partial();
            var r1 = CollectRunKeys(sink, Remaining(), cancellationToken);
            if (r1.Status == CollectStatus.Fail) return r1;

            if (Remaining() == 0) return CollectResult.Partial();
            var r2 = CollectServices(sink, Remaining(), cancellationToken);
            // Continue even if services fail (e.g. no SCM access)

            if (Remaining() == 0) return CollectResult.Partial();
            var r3 = CollectScheduledTasks(sink, Remaining(), cancellationToken);

            if (Remaining() == 0) return CollectResult.Partial();
            var r4 = CollectStartupFolders(sink, Remaining(), cancellationToken);
            if (r4.Status == CollectStatus.Fail) return r4;

            if (Remaining() == 0) return CollectResult.Partial();
            var r5 = CollectIFEO(sink, Remaining(), cancellationToken);
            if (r5.Status == CollectStatus.Fail) return r5;

            if (Remaining() == 0) return CollectResult.Partial();
            CollectWmiEventConsumers(sink, Remaining(), cancellationToken);

            if (r2.Status == CollectStatus.Fail) return r2;
            if (r3.Status == CollectStatus.Fail) return r3;
            bool anyPartial = r1.Status == CollectStatus.Partial || r2.Status == CollectStatus.Partial ||
                              r3.Status == CollectStatus.Partial || r4.Status == CollectStatus.Partial || r5.Status == CollectStatus.Partial;
            return anyPartial ? CollectResult.Partial() : CollectResult.Ok();
        }
        catch (Exception ex)
        {
            return CollectResult.Fail(ex.Message, "unknown");
        }
    }

    private static bool IsBenignRunEntry(string valueName, string valueData)
    {
        var nameLower = valueName.ToLowerInvariant();
        var dataLower = valueData.ToLowerInvariant();
        foreach (var sub in BenignRunSubstrings)
        {
            if (nameLower.Contains(sub, StringComparison.Ordinal)) return true;
            if (dataLower.Contains(sub, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    private static CollectResult CollectRunKeys(IEvidenceSink sink, long remainingMs, CancellationToken ct)
    {
        var keys = new[]
        {
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce")
        };
        bool partial = false;
        int seq = 0;

        foreach (var (hive, subKey, keyName) in keys)
        {
            if (remainingMs >= 0 && remainingMs < 50) { partial = true; break; }
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = hive.OpenSubKey(subKey, false);
                if (key == null) { partial = true; continue; }
                foreach (var valueName in key.GetValueNames())
                {
                    if (remainingMs >= 0 && remainingMs < 50) { partial = true; break; }
                    ct.ThrowIfCancellationRequested();
                    var name = valueName ?? "unknown";
                    var raw = key.GetValue(valueName);
                    string dataStr;
                    if (raw is string s)
                        dataStr = s;
                    else if (raw is string[] multi)
                        dataStr = string.Join("; ", multi);
                    else
                        dataStr = "(non-string)";
                    if (IsBenignRunEntry(name, dataStr)) continue;
                    seq++;
                    var imagePath = ProcessEnrichment.TryExtractImagePath(dataStr);
                    var details = new Dictionary<string, object?>
                    {
                        ["persistence_type"] = "run_key",
                        ["key"] = keyName,
                        ["value_name"] = name,
                        ["value_data"] = dataStr,
                        ["command_line"] = ProcessCollector.TruncateForEvidence(dataStr, 256),
                    };
                    if (!string.IsNullOrWhiteSpace(imagePath))
                    {
                        details["image_path"] = imagePath;
                        var publisher = ProcessEnrichment.GetPublisher(imagePath);
                        if (!string.IsNullOrWhiteSpace(publisher))
                            details["publisher"] = publisher;
                        ProcessEnrichment.AddFileSignatureDetails(details, imagePath);
                        var hash = ProcessEnrichment.TryComputeSha256(imagePath);
                        if (!string.IsNullOrWhiteSpace(hash))
                            details["hash"] = hash;
                    }
                    sink.AddEvidence($"EV-Run-{seq}", "persistence", "registry", null, name, null,
                        "run_key", details, 0.7, "low", "Run/RunOnce registry entry observed", null);
                }
            }
            catch (UnauthorizedAccessException) { partial = true; }
            catch (System.Security.SecurityException) { partial = true; }
        }
        return partial ? CollectResult.Partial() : CollectResult.Ok();
    }

    private static CollectResult CollectServices(IEvidenceSink sink, long remainingMs, CancellationToken ct)
    {
        IntPtr hScm = Native.OpenSCManagerW(null, null, Native.SC_MANAGER_CONNECT);
        if (hScm == IntPtr.Zero)
            return CollectResult.Fail("OpenSCManager failed", Marshal.GetLastWin32Error() == 5 ? "access_denied" : "unknown");

        try
        {
            uint bytesNeeded = 0, servicesReturned = 0, resume = 0;
            if (!Native.EnumServicesStatusExW(hScm, Native.SC_ENUM_PROCESS_INFO, Native.SERVICE_WIN32, Native.SERVICE_STATE_ALL,
                    null, 0, ref bytesNeeded, ref servicesReturned, ref resume, IntPtr.Zero) && Marshal.GetLastWin32Error() != 122)
            {
                if (bytesNeeded == 0) return CollectResult.Ok();
                return CollectResult.Fail("EnumServicesStatusEx size failed", "unknown");
            }
            if (bytesNeeded == 0) return CollectResult.Ok();

            var buf = new byte[bytesNeeded];
            uint n = 0;
            resume = 0;
            if (!Native.EnumServicesStatusExW(hScm, Native.SC_ENUM_PROCESS_INFO, Native.SERVICE_WIN32, Native.SERVICE_STATE_ALL,
                    buf, (uint)buf.Length, ref bytesNeeded, ref n, ref resume, IntPtr.Zero))
                return CollectResult.Fail("EnumServicesStatusEx failed", "unknown");

            bool partial = false;
            int ptrSize = IntPtr.Size;
            int stride = ptrSize * 2 + 36; // ENUM_SERVICE_STATUS_PROCESSW: 2 pointers + SERVICE_STATUS_PROCESS(36)
            for (uint i = 0; i < n; i++)
            {
                if (remainingMs >= 0 && remainingMs < 100) { partial = true; break; }
                ct.ThrowIfCancellationRequested();
                int baseOff = (int)(i * stride);
                IntPtr pSvcName = ptrSize == 8 ? (IntPtr)BitConverter.ToInt64(buf, baseOff) : (IntPtr)BitConverter.ToInt32(buf, baseOff);
                IntPtr pDispName = ptrSize == 8 ? (IntPtr)BitConverter.ToInt64(buf, baseOff + 8) : (IntPtr)BitConverter.ToInt32(buf, baseOff + 4);
                string svcName = pSvcName != IntPtr.Zero ? Marshal.PtrToStringUni(pSvcName) ?? "unknown" : "unknown";
                string displayName = pDispName != IntPtr.Zero ? Marshal.PtrToStringUni(pDispName) ?? "" : "";
                uint currentState = BitConverter.ToUInt32(buf, baseOff + ptrSize * 2 + 4); // SERVICE_STATUS_PROCESS.dwCurrentState
                string state = currentState switch
                {
                    1 => "stopped",
                    2 => "start_pending",
                    3 => "stop_pending",
                    4 => "running",
                    5 => "continue_pending",
                    6 => "pause_pending",
                    7 => "paused",
                    _ => "unknown"
                };
                GetServiceConfig(hScm, svcName, out string imagePath, out string startTypeStr, out string serviceAccount);
                var details = new Dictionary<string, object?>
                {
                    ["service_name"] = svcName,
                    ["display_name"] = displayName,
                    ["state"] = state,
                    ["start_type"] = startTypeStr
                };
                if (!string.IsNullOrWhiteSpace(serviceAccount))
                    details["service_account"] = serviceAccount;
                if (!string.IsNullOrEmpty(imagePath))
                {
                    details["image_path"] = imagePath;
                    var publisher = ProcessEnrichment.GetPublisher(imagePath);
                    if (!string.IsNullOrWhiteSpace(publisher))
                        details["publisher"] = publisher;
                    ProcessEnrichment.AddFileSignatureDetails(details, imagePath);
                    var hash = ProcessEnrichment.TryComputeSha256(imagePath);
                    if (!string.IsNullOrWhiteSpace(hash))
                        details["hash"] = hash;
                }
                details["persistence_type"] = "service_install";
                sink.AddEvidence($"EV-Svc-{i + 1}", "persistence", "service", null, svcName, null,
                    "service_install", details, 0.7, "low", "Windows service observed (non-driver)", null);
            }
            return partial ? CollectResult.Partial() : CollectResult.Ok();
        }
        finally
        {
            Native.CloseServiceHandle(hScm);
        }
    }

    private static void GetServiceConfig(IntPtr hScm, string serviceName, out string imagePath, out string startTypeStr, out string serviceAccount)
    {
        imagePath = "";
        startTypeStr = "unknown";
        serviceAccount = "";
        IntPtr hSvc = Native.OpenServiceW(hScm, serviceName, Native.SERVICE_QUERY_CONFIG);
        if (hSvc == IntPtr.Zero) return;
        try
        {
            uint cbNeeded = 0;
            Native.QueryServiceConfigW(hSvc, null, 0, ref cbNeeded);
            if (cbNeeded == 0) return;
            var buf = new byte[cbNeeded];
            if (!Native.QueryServiceConfigW(hSvc, buf, (uint)buf.Length, ref cbNeeded))
                return;
            // QUERY_SERVICE_CONFIGW has fixed DWORD fields followed by pointer fields.
            uint startType = BitConverter.ToUInt32(buf, 4);
            startTypeStr = startType switch
            {
                0 => "boot",
                1 => "system",
                2 => "auto",
                3 => "demand",
                4 => "disabled",
                _ => "unknown"
            };
            int pathPtrOffset = IntPtr.Size == 8 ? 16 : 12;
            IntPtr pPath = IntPtr.Size == 8 ? (IntPtr)BitConverter.ToInt64(buf, pathPtrOffset) : (IntPtr)BitConverter.ToInt32(buf, pathPtrOffset);
            if (pPath != IntPtr.Zero)
                imagePath = ProcessCollector.TruncateForEvidence(Marshal.PtrToStringUni(pPath), 256) ?? "";

            int startNamePtrOffset = IntPtr.Size == 8 ? 48 : 28;
            IntPtr pStartName = IntPtr.Size == 8
                ? (IntPtr)BitConverter.ToInt64(buf, startNamePtrOffset)
                : (IntPtr)BitConverter.ToInt32(buf, startNamePtrOffset);
            if (pStartName != IntPtr.Zero)
                serviceAccount = ProcessCollector.TruncateForEvidence(Marshal.PtrToStringUni(pStartName), 128) ?? "";
        }
        finally
        {
            Native.CloseServiceHandle(hSvc);
        }
    }

    private static CollectResult CollectScheduledTasks(IEvidenceSink sink, long remainingMs, CancellationToken ct)
    {
        try
        {
            using var tree = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree", false);
            if (tree == null) return CollectResult.Fail("TaskCache Tree not accessible", "access_denied");
            bool partial = false;
            var taskPaths = new List<string>();
            EnumerateTaskPathsRecurse(tree, "", taskPaths, remainingMs, ref partial, ct);

            var taskMetadata = TryCollectScheduledTaskMetadata(taskPaths, ct, out var metadataPartial);
            partial = partial || metadataPartial;

            var sampledTasks = taskMetadata.Count > 0
                ? taskMetadata
                : taskPaths
                    .Take(MaxScheduledTaskSamples)
                    .Select(path => new Dictionary<string, object?> { ["task_path"] = ProcessCollector.TruncateForEvidence(path, 180) ?? path })
                    .ToList();

            sink.AddEvidence(
                "task-inventory-1",
                "persistence",
                "scheduled_task",
                null,
                "task_inventory",
                null,
                "scheduled_task_inventory",
                new Dictionary<string, object?>
                {
                    ["count"] = taskPaths.Count,
                    ["tasks"] = sampledTasks,
                    ["truncated"] = taskPaths.Count > sampledTasks.Count,
                    ["bounds"] = new Dictionary<string, object?>
                    {
                        ["tasks_max"] = MaxScheduledTaskSamples
                    }
                },
                1.0,
                "low",
                "Scheduled task inventory observed.",
                null);

            var fallbackCount = 0;
            foreach (var task in sampledTasks)
            {
                if (fallbackCount >= MaxScheduledTaskFallbackSignals)
                    break;
                if (!task.TryGetValue("task_path", out var taskPathObj))
                    continue;
                var taskPath = taskPathObj?.ToString();
                if (string.IsNullOrWhiteSpace(taskPath))
                    continue;
                fallbackCount++;
                var fallbackDetails = new Dictionary<string, object?> { ["task_path"] = taskPath, ["persistence_type"] = "scheduled_task" };
                if (task.TryGetValue("hidden", out var hidden))
                    fallbackDetails["hidden"] = hidden;
                if (task.TryGetValue("enabled", out var enabled))
                    fallbackDetails["enabled"] = enabled;
                if (task.TryGetValue("exec_image", out var execImageObj))
                {
                    var execImage = execImageObj?.ToString();
                    if (!string.IsNullOrWhiteSpace(execImage))
                    {
                        fallbackDetails["image_path"] = execImage;
                        task.TryGetValue("exec_args", out var execArgsObj);
                        var execArgs = execArgsObj?.ToString();
                        var commandLine = string.IsNullOrWhiteSpace(execArgs) ? execImage : $"{execImage} {execArgs}";
                        fallbackDetails["command_line"] = ProcessCollector.TruncateForEvidence(commandLine, 256);
                        var publisher = ProcessEnrichment.GetPublisher(execImage);
                        if (!string.IsNullOrWhiteSpace(publisher))
                            fallbackDetails["publisher"] = publisher;
                        ProcessEnrichment.AddFileSignatureDetails(fallbackDetails, execImage);
                        var hash = ProcessEnrichment.TryComputeSha256(execImage);
                        if (!string.IsNullOrWhiteSpace(hash))
                            fallbackDetails["hash"] = hash;
                    }
                }
                sink.AddEvidence($"EV-Task-{fallbackCount}", "persistence", "scheduled_task", null, taskPath, null,
                    "scheduled_task", fallbackDetails, 0.45, "low", "Scheduled task fallback sample observed", null);
            }

            return partial ? CollectResult.Partial() : CollectResult.Ok();
        }
        catch (UnauthorizedAccessException) { return CollectResult.Fail("TaskCache access denied", "access_denied"); }
    }

    private static void EnumerateTaskPathsRecurse(RegistryKey tree, string pathPrefix, List<string> taskPaths, long remainingMs, ref bool partial, CancellationToken ct)
    {
        foreach (var subKeyName in tree.GetSubKeyNames())
        {
            if (remainingMs >= 0 && remainingMs < 50) { partial = true; return; }
            ct.ThrowIfCancellationRequested();
            var path = string.IsNullOrEmpty(pathPrefix) ? subKeyName : pathPrefix + "\\" + subKeyName;
            try
            {
                using var sub = tree.OpenSubKey(subKeyName, false);
                if (sub == null) continue;
                var idVal = sub.GetValue("Id");
                if (idVal is string)
                {
                    taskPaths.Add(path);
                }
                else
                    EnumerateTaskPathsRecurse(sub, path, taskPaths, remainingMs, ref partial, ct);
            }
            catch { }
        }
    }

    private static List<Dictionary<string, object?>> TryCollectScheduledTaskMetadata(List<string> taskPaths, CancellationToken ct, out bool partial)
    {
        partial = false;
        var rows = new List<Dictionary<string, object?>>();
        try
        {
            var schedulerType = Type.GetTypeFromProgID("Schedule.Service");
            if (schedulerType == null)
            {
                partial = true;
                return rows;
            }

            dynamic service = Activator.CreateInstance(schedulerType)!;
            service.Connect();
            foreach (var taskPath in taskPaths.Take(MaxScheduledTaskSamples))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    dynamic task = service.GetFolder(GetFolderPath(taskPath)).GetTask(GetTaskName(taskPath));
                    dynamic definition = task.Definition;
                    var row = new Dictionary<string, object?>();
                    row["task_path"] = ProcessCollector.TruncateForEvidence(taskPath, 180) ?? taskPath;
                    var author = ProcessCollector.TruncateForEvidence(SafeToString(definition?.RegistrationInfo?.Author), 120);
                    if (!string.IsNullOrWhiteSpace(author))
                        row["author"] = author;
                    row["enabled"] = SafeToBool(task.Enabled);
                    row["hidden"] = SafeToBool(definition?.Settings?.Hidden);
                    var runAs = ProcessCollector.TruncateForEvidence(SafeToString(definition?.Principal?.UserId), 120);
                    if (!string.IsNullOrWhiteSpace(runAs))
                        row["run_as"] = runAs;
                    var description = ProcessCollector.TruncateForEvidence(SafeToString(definition?.RegistrationInfo?.Description), 180);
                    if (!string.IsNullOrWhiteSpace(description))
                        row["description"] = description;
                    var runLevel = SafeToRunLevel(definition?.Principal?.RunLevel);
                    if (!string.IsNullOrWhiteSpace(runLevel))
                        row["run_level"] = runLevel;
                    var logonType = SafeToLogonType(definition?.Principal?.LogonType);
                    if (!string.IsNullOrWhiteSpace(logonType))
                        row["logon_type"] = logonType;
                    var lastRunTime = SafeTaskDate(task.LastRunTime);
                    if (!string.IsNullOrWhiteSpace(lastRunTime))
                        row["last_run_time_utc"] = lastRunTime;
                    var nextRunTime = SafeTaskDate(task.NextRunTime);
                    if (!string.IsNullOrWhiteSpace(nextRunTime))
                        row["next_run_time_utc"] = nextRunTime;
                    PopulateExecMetadata(row, definition?.Actions);
                    rows.Add(row);
                }
                catch
                {
                    partial = true;
                }
            }
        }
        catch
        {
            partial = true;
        }
        return rows;
    }

    private static void PopulateExecMetadata(Dictionary<string, object?> row, dynamic? actions)
    {
        try
        {
            if (actions == null)
                return;
            var actionCount = SafeToInt(actions.Count);
            if (!actionCount.HasValue || actionCount.Value <= 0)
                return;
            row["action_count"] = actionCount.Value;
            dynamic action = actions.Item(1);
            var execImage = ProcessCollector.TruncateForEvidence(SafeToString(action?.Path), 180);
            var execArgs = ProcessCollector.TruncateForEvidence(SafeToString(action?.Arguments), 180);
            if (!string.IsNullOrWhiteSpace(execImage))
                row["exec_image"] = execImage;
            if (!string.IsNullOrWhiteSpace(execArgs))
                row["exec_args"] = execArgs;
        }
        catch
        {
            // Keep bounded observable metadata only; action detail is optional.
        }
    }

    private static string GetFolderPath(string taskPath)
    {
        var normalized = taskPath.StartsWith("\\", StringComparison.Ordinal) ? taskPath : "\\" + taskPath;
        var lastSlash = normalized.LastIndexOf('\\');
        if (lastSlash <= 0)
            return "\\";
        return normalized[..lastSlash];
    }

    private static string GetTaskName(string taskPath)
    {
        var normalized = taskPath.StartsWith("\\", StringComparison.Ordinal) ? taskPath : "\\" + taskPath;
        var lastSlash = normalized.LastIndexOf('\\');
        return lastSlash < 0 ? normalized : normalized[(lastSlash + 1)..];
    }

    private static string? SafeToString(dynamic? value)
    {
        try { return value?.ToString(); } catch { return null; }
    }

    private static bool SafeToBool(dynamic? value)
    {
        try
        {
            return value != null && Convert.ToBoolean(value);
        }
        catch
        {
            return false;
        }
    }

    private static int? SafeToInt(dynamic? value)
    {
        try
        {
            return value == null ? null : Convert.ToInt32(value);
        }
        catch
        {
            return null;
        }
    }

    private static string? SafeToRunLevel(dynamic? value)
    {
        return SafeToInt(value) switch
        {
            0 => "limited",
            1 => "highest",
            _ => null
        };
    }

    private static string? SafeToLogonType(dynamic? value)
    {
        return SafeToInt(value) switch
        {
            0 => "none",
            1 => "password",
            2 => "s4u",
            3 => "interactive_token",
            4 => "group",
            5 => "service_account",
            6 => "interactive_token_or_password",
            _ => null
        };
    }

    private static string? SafeTaskDate(dynamic? value)
    {
        try
        {
            if (value == null)
                return null;
            var dt = Convert.ToDateTime(value);
            if (dt.Year < 2000)
                return null;
            return dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        }
        catch
        {
            return null;
        }
    }

    private static CollectResult CollectIFEO(IEvidenceSink sink, long remainingMs, CancellationToken ct)
    {
        try
        {
            using var ifeo = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", false);
            if (ifeo == null) return CollectResult.Ok();
            bool partial = false;
            int seq = 0;
            foreach (var subKeyName in ifeo.GetSubKeyNames())
            {
                if (remainingMs >= 0 && remainingMs < 50) { partial = true; break; }
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var sub = ifeo.OpenSubKey(subKeyName, false);
                    if (sub == null) continue;
                    bool hasDebugger = sub.GetValue("Debugger") != null;
                    bool hasGlobalFlag = sub.GetValue("GlobalFlag") != null;
                    if (!hasDebugger && !hasGlobalFlag) continue;
                    seq++;
                    var overrideStr = hasDebugger && hasGlobalFlag ? "Debugger,GlobalFlag" : hasDebugger ? "Debugger" : "GlobalFlag";
                    var imageName = subKeyName ?? "unknown";
                    var details = new Dictionary<string, object?> { ["override"] = overrideStr };
                    sink.AddEvidence($"EV-Pers-IFEO-{seq}", "persistence", "ifeo_hijack", null, imageName, null,
                        "ifeo_hijack", details, 0.8, "medium",
                        "IFEO override present (Debugger or GlobalFlag); potential hijack vector", null);
                }
                catch { }
            }
            return partial ? CollectResult.Partial() : CollectResult.Ok();
        }
        catch (UnauthorizedAccessException) { return CollectResult.Ok(); }
    }

    private static CollectResult CollectStartupFolders(IEvidenceSink sink, long remainingMs, CancellationToken ct)
    {
        bool partial = false;
        int seq = 0;
        var specs = new[] { (Environment.SpecialFolder.Startup, "user_startup"), (Environment.SpecialFolder.CommonStartup, "common_startup") };
        foreach (var (folder, folderKind) in specs)
        {
            if (remainingMs >= 0 && remainingMs < 50) { partial = true; break; }
            ct.ThrowIfCancellationRequested();
            try
            {
                var basePath = Environment.GetFolderPath(folder);
                if (string.IsNullOrEmpty(basePath) || !Directory.Exists(basePath)) continue;
                foreach (var entry in Directory.GetFileSystemEntries(basePath))
                {
                    if (remainingMs >= 0 && remainingMs < 50) { partial = true; break; }
                    ct.ThrowIfCancellationRequested();
                    var fileName = Path.GetFileName(entry) ?? "unknown";
                    if (fileName.StartsWith('.') && (fileName.Length == 1 || (fileName.Length == 2 && fileName[1] == '.'))) continue;
                    seq++;
                    var details = new Dictionary<string, object?>
                    {
                        ["persistence_type"] = "startup_folder",
                        ["folder_kind"] = folderKind,
                        ["file_name"] = fileName,
                        ["path"] = entry,
                        ["image_path"] = ProcessCollector.TruncateForEvidence(entry, 180),
                    };
                    var publisher = ProcessEnrichment.GetPublisher(entry);
                    if (!string.IsNullOrWhiteSpace(publisher))
                        details["publisher"] = publisher;
                    ProcessEnrichment.AddFileSignatureDetails(details, entry);
                    var hash = ProcessEnrichment.TryComputeSha256(entry);
                    if (!string.IsNullOrWhiteSpace(hash))
                        details["hash"] = hash;
                    sink.AddEvidence($"EV-Startup-{seq}", "persistence", "file", null, fileName, null,
                        "startup_folder", details, 0.7, "low", "Startup folder entry observed", null);
                }
            }
            catch (UnauthorizedAccessException) { partial = true; }
        }
        return partial ? CollectResult.Partial() : CollectResult.Ok();
    }

    private static void CollectWmiEventConsumers(IEvidenceSink sink, long remainingMs, CancellationToken ct)
    {
        if (remainingMs >= 0 && remainingMs < 1000) return;
        int seq = 0;
        var queries = new[] { ("CommandLineEventConsumer", "CommandLine"), ("ActiveScriptEventConsumer", "ActiveScript") };
        try
        {
            var scope = new ManagementScope(@"ROOT\subscription");
            scope.Connect();
            foreach (var (className, consumerType) in queries)
            {
                if (seq >= MaxWmiConsumers) break;
                ct.ThrowIfCancellationRequested();
                using var searcher = new ManagementObjectSearcher(scope, new SelectQuery($"SELECT Name FROM {className}"));
                using var results = searcher.Get();
                foreach (var obj in results.Cast<ManagementBaseObject>())
                {
                    if (seq >= MaxWmiConsumers) break;
                    ct.ThrowIfCancellationRequested();
                    var name = obj["Name"]?.ToString();
                    if (string.IsNullOrEmpty(name)) continue;
                    seq++;
                    var details = new Dictionary<string, object?> { ["consumer_type"] = consumerType, ["name"] = name };
                    sink.AddEvidence($"EV-WMI-{seq}", "persistence", "wmi", null, name, null,
                        "wmi_event_consumer", details, 0.8, "low",
                        "WMI event consumer enumerated (name only, no script content)", null);
                }
            }
        }
        catch (ManagementException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static class Native
    {
        public const uint SC_MANAGER_CONNECT = 0x0001;
        public const uint SC_ENUM_PROCESS_INFO = 1;
        public const uint SERVICE_WIN32 = 0x00000030;
        public const uint SERVICE_STATE_ALL = 0x0003;
        public const uint SERVICE_QUERY_CONFIG = 0x0001;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenSCManagerW(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumServicesStatusExW(IntPtr hSCManager, uint InfoLevel, uint dwServiceType, uint dwServiceState,
            byte[]? lpServices, uint cbBufSize, ref uint pcbBytesNeeded, ref uint lpServicesReturned, ref uint lpResumeIndex, IntPtr pszGroupName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenServiceW(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryServiceConfigW(IntPtr hService, byte[]? lpBuffer, uint cbBufSize, ref uint pcbBytesNeeded);
    }
}
