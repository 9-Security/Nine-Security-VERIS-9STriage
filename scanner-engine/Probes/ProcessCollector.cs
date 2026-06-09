using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Management;
using NineSTriage.Engine.Evidence;

namespace NineSTriage.Engine.Probes;

public sealed class ProcessCollector : ICollector
{
    public string Name => "process";

    public CollectResult Collect(IEvidenceSink sink, long remainingMs = -1, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return CollectResult.Fail("Process collector is Windows-only.", "api_not_supported");

        try
        {
            var processMetadata = BuildProcessMetadataSnapshot();
            var processes = Process.GetProcesses();
            int seq = 0;
            var processRecordsForTimestamp = new List<(int Pid, int ParentPid, string CreationUtc, string Name)>();
            foreach (var proc in processes)
            {
                if (remainingMs >= 0 && seq > 0 && seq % 50 == 0)
                    cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    EmitProcessEnumerated(sink, proc, processMetadata, ref seq, processRecordsForTimestamp);
                }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
                finally
                {
                    proc.Dispose();
                }
            }
            EmitTimestampInconsistencies(sink, processRecordsForTimestamp);
            return CollectResult.Ok();
        }
        catch (Exception ex)
        {
            return CollectResult.Fail(ex.Message, "unknown");
        }
    }

    private static void EmitProcessEnumerated(
        IEvidenceSink sink,
        Process proc,
        Dictionary<int, ProcessMetadata> processMetadata,
        ref int seq,
        List<(int Pid, int ParentPid, string CreationUtc, string Name)> processRecordsForTimestamp)
    {
        var evidenceId = $"process-{proc.Id}-{Interlocked.Increment(ref seq)}";
        var name = proc.ProcessName ?? "";
        string? imagePath = null;
        try { imagePath = proc.MainModule?.FileName; } catch { }

        var details = new Dictionary<string, object?>();
        string? creationUtc = null;
        try
        {
            if (proc.StartTime != default)
            {
                creationUtc = proc.StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
                details["creation_time_utc"] = creationUtc;
            }
        }
        catch { }

        int? parentPid = null;
        if (OperatingSystem.IsWindows())
        {
            parentPid = Win32Helper.GetParentProcessId(proc.Id);
            if (parentPid.HasValue)
                details["parent_pid"] = parentPid.Value;
        }
        if (processMetadata.TryGetValue(proc.Id, out var currentMeta))
        {
            var safeCmd = TruncateForEvidence(currentMeta.CommandLine, 256);
            if (!string.IsNullOrWhiteSpace(safeCmd))
                details["command_line"] = safeCmd;
            if (currentMeta.SessionId.HasValue)
                details["session_id"] = currentMeta.SessionId.Value;
            if (!string.IsNullOrWhiteSpace(currentMeta.Owner))
                details["owner"] = currentMeta.Owner;
            if (!string.IsNullOrWhiteSpace(currentMeta.ExecutableArchitecture))
                details["executable_architecture"] = currentMeta.ExecutableArchitecture;
            if (!string.IsNullOrWhiteSpace(currentMeta.TokenElevation))
                details["token_elevation"] = currentMeta.TokenElevation;

            var processContext = BuildProcessContext(parentPid, processMetadata);
            if (processContext.Count > 0)
                details["process_context"] = processContext;
        }
        details["process_role_hint"] = "unknown";
        details["image_path"] = imagePath ?? "";

        var enrichment = ProcessEnrichment.Build(name, imagePath, details.TryGetValue("command_line", out var cmdObj) ? cmdObj?.ToString() : null);
        details["process_enrichment"] = ProcessEnrichment.ToDetailsDictionary(enrichment);
        var identity = ProcessEnrichment.BuildIdentityDetails(imagePath);
        if (identity.Count > 0)
            details["process_identity"] = identity;

        if (!string.IsNullOrEmpty(creationUtc) && parentPid.HasValue)
            processRecordsForTimestamp.Add((proc.Id, parentPid.Value, creationUtc, name));

        sink.AddEvidence(evidenceId, "process", "process", proc.Id, name, imagePath,
            "process_enumerated", details, 1.0, "low", "Process enumerated.", null);
    }

    private static Dictionary<string, object?> BuildProcessContext(int? parentPid, Dictionary<int, ProcessMetadata> processMetadata)
    {
        var context = new Dictionary<string, object?>();
        if (!parentPid.HasValue || parentPid.Value <= 0)
            return context;

        if (!TryBuildProcessRef(parentPid.Value, processMetadata, out var parentRef))
            return context;

        context["parent"] = parentRef;

        if (parentRef.TryGetValue("pid", out var parentPidValue) &&
            parentPidValue is int parentInt &&
            processMetadata.TryGetValue(parentInt, out var parentMeta) &&
            parentMeta.ParentPid > 0 &&
            TryBuildProcessRef(parentMeta.ParentPid, processMetadata, out var grandparentRef))
        {
            context["grandparent"] = grandparentRef;
        }

        return context;
    }

    private static bool TryBuildProcessRef(int pid, Dictionary<int, ProcessMetadata> processMetadata, out Dictionary<string, object?> processRef)
    {
        processRef = new Dictionary<string, object?>();
        if (!processMetadata.TryGetValue(pid, out var meta))
            return false;

        processRef["pid"] = pid;
        processRef["name"] = meta.Name;

        var safePath = TruncateForEvidence(meta.Path, 180);
        if (!string.IsNullOrWhiteSpace(safePath))
            processRef["path"] = safePath;
        var identity = ProcessEnrichment.BuildIdentityDetails(meta.Path);
        if (identity.Count > 0)
            processRef["identity"] = identity;

        var safeCmd = TruncateForEvidence(meta.CommandLine, 256);
        if (!string.IsNullOrWhiteSpace(safeCmd))
            processRef["command_line"] = safeCmd;
        if (meta.SessionId.HasValue)
            processRef["session_id"] = meta.SessionId.Value;
        if (!string.IsNullOrWhiteSpace(meta.Owner))
            processRef["owner"] = meta.Owner;
        if (!string.IsNullOrWhiteSpace(meta.ExecutableArchitecture))
            processRef["executable_architecture"] = meta.ExecutableArchitecture;
        if (!string.IsNullOrWhiteSpace(meta.TokenElevation))
            processRef["token_elevation"] = meta.TokenElevation;

        return processRef.Count > 1;
    }

    private static Dictionary<int, ProcessMetadata> BuildProcessMetadataSnapshot()
    {
        var snapshot = new Dictionary<int, ProcessMetadata>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,SessionId FROM Win32_Process");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                var pid = ToInt(obj["ProcessId"]);
                if (!pid.HasValue || pid.Value <= 0)
                    continue;

                snapshot[pid.Value] = new ProcessMetadata
                {
                    ParentPid = ToInt(obj["ParentProcessId"]) ?? 0,
                    Name = TruncateForEvidence(obj["Name"]?.ToString(), 80) ?? "unknown",
                    Path = TruncateForEvidence(obj["ExecutablePath"]?.ToString(), 180),
                    CommandLine = TruncateForEvidence(obj["CommandLine"]?.ToString(), 256),
                    SessionId = ToInt(obj["SessionId"]),
                    Owner = TruncateForEvidence(BuildOwner(obj), 96),
                    ExecutableArchitecture = GetProcessArchitecture(pid.Value),
                    TokenElevation = GetTokenElevation(pid.Value)
                };
            }
        }
        catch
        {
            // Graceful degrade: process enumeration remains valid without enrichment.
        }

        return snapshot;
    }

    private static string? BuildOwner(ManagementObject obj)
    {
        try
        {
            var outParams = obj.InvokeMethod("GetOwner", null, null);
            var user = outParams?["User"]?.ToString();
            var domain = outParams?["Domain"]?.ToString();
            if (string.IsNullOrWhiteSpace(user))
                return null;
            return string.IsNullOrWhiteSpace(domain) ? user : $"{domain}\\{user}";
        }
        catch
        {
            return null;
        }
    }

    private static string? GetProcessArchitecture(int pid)
    {
        if (!Environment.Is64BitOperatingSystem)
            return "x86";
        IntPtr hProc = IntPtr.Zero;
        try
        {
            hProc = Win32Helper.OpenProcess(Win32Helper.ProcessQueryLimitedInformation, false, (uint)pid);
            if (hProc == IntPtr.Zero)
                return null;
            if (!Win32Helper.IsWow64Process(hProc, out var wow64))
                return null;
            return wow64 ? "x86" : "x64";
        }
        catch
        {
            return null;
        }
        finally
        {
            if (hProc != IntPtr.Zero)
                Win32Helper.CloseHandle(hProc);
        }
    }

    private static string? GetTokenElevation(int pid)
    {
        IntPtr hProc = IntPtr.Zero;
        IntPtr hToken = IntPtr.Zero;
        IntPtr tokenInfo = IntPtr.Zero;
        try
        {
            hProc = Win32Helper.OpenProcess(Win32Helper.ProcessQueryLimitedInformation, false, (uint)pid);
            if (hProc == IntPtr.Zero)
                return null;
            if (!Win32Helper.OpenProcessToken(hProc, Win32Helper.TokenQuery, out hToken))
                return null;
            tokenInfo = Marshal.AllocHGlobal(sizeof(int));
            if (!Win32Helper.GetTokenInformation(hToken, Win32Helper.TokenElevationType, tokenInfo, sizeof(int), out _))
                return null;
            return Marshal.ReadInt32(tokenInfo) switch
            {
                1 => "default",
                2 => "full",
                3 => "limited",
                _ => null
            };
        }
        catch
        {
            return null;
        }
        finally
        {
            if (tokenInfo != IntPtr.Zero)
                Marshal.FreeHGlobal(tokenInfo);
            if (hToken != IntPtr.Zero)
                Win32Helper.CloseHandle(hToken);
            if (hProc != IntPtr.Zero)
                Win32Helper.CloseHandle(hProc);
        }
    }

    internal static int? ToInt(object? value)
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

    internal static string? TruncateForEvidence(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var normalized = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        if (normalized.Length <= maxLength)
            return normalized;
        return normalized[..Math.Max(0, maxLength - 3)] + "...";
    }

    private sealed class ProcessMetadata
    {
        public int ParentPid { get; init; }
        public string Name { get; init; } = "unknown";
        public string? Path { get; init; }
        public string? CommandLine { get; init; }
        public int? SessionId { get; init; }
        public string? Owner { get; init; }
        public string? ExecutableArchitecture { get; init; }
        public string? TokenElevation { get; init; }
    }

    /// <summary>Emit timestamp_inconsistency (artefact) when child process creation time is before parent. Aligns with C++ process.cpp and SCANNER_COLLECTION_SPEC §5.</summary>
    private static void EmitTimestampInconsistencies(
        IEvidenceSink sink,
        List<(int Pid, int ParentPid, string CreationUtc, string Name)> records)
    {
        var pidToCreationUtc = new Dictionary<int, string>();
        foreach (var r in records)
            pidToCreationUtc[r.Pid] = r.CreationUtc;

        int tsSeq = 0;
        foreach (var r in records)
        {
            if (r.ParentPid == 0 || r.ParentPid == 4)
                continue;
            if (!pidToCreationUtc.TryGetValue(r.ParentPid, out var parentUtc))
                continue;
            if (string.CompareOrdinal(r.CreationUtc, parentUtc) >= 0)
                continue;

            tsSeq++;
            var details = new Dictionary<string, object?>
            {
                ["reason"] = "child_before_parent",
                ["child_pid"] = r.Pid,
                ["parent_pid"] = r.ParentPid,
                ["child_creation_utc"] = r.CreationUtc,
                ["parent_creation_utc"] = parentUtc
            };
            var evidenceId = $"process-ts-{r.Pid}-{tsSeq}";
            sink.AddEvidence(evidenceId, "artefact", "process", r.Pid, r.Name, null,
                "timestamp_inconsistency", details, 0.7, "medium",
                "Process creation time before parent (impossible timestamp).", null);
        }
    }
}

internal static class Win32Helper
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(IntPtr hSnapshot, ref ProcessEntry32 lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(IntPtr hSnapshot, ref ProcessEntry32 lppe);

    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    public const uint ProcessQueryLimitedInformation = 0x1000;
    public const uint TokenQuery = 0x0008;
    public const int TokenElevationType = 18;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    public static int? GetParentProcessId(int processId)
    {
        var hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == IntPtr.Zero || hSnap == new IntPtr(-1))
            return null;
        try
        {
            var pe = new ProcessEntry32 { dwSize = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(hSnap, ref pe))
                return null;
            do
            {
                if (pe.th32ProcessID == (uint)processId)
                    return (int)pe.th32ParentProcessID;
            } while (Process32Next(hSnap, ref pe));
            return null;
        }
        finally
        {
            CloseHandle(hSnap);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
}
