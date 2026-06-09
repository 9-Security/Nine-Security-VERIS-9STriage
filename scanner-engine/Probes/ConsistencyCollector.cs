using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using NineSTriage.Engine.Evidence;

namespace NineSTriage.Engine.Probes;

public sealed class ConsistencyCollector : ICollector
{
    public string Name => "consistency";

    private const int MaxSamplePids = 10;

    public CollectResult Collect(IEvidenceSink sink, long remainingMs = -1, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return CollectResult.Fail("Consistency collector is Windows-only.", "api_not_supported");

        try
        {
            var toolhelp = SnapshotProcessIds();
            var wmi = SnapshotWmiProcessIds();
            var tasklist = SnapshotTasklistProcessIds(cancellationToken);
            var networkOwners = SnapshotNetworkOwnerSets();

            var details = new Dictionary<string, object?>
            {
                ["process_sources"] = new Dictionary<string, object?>
                {
                    ["toolhelp_snapshot"] = toolhelp.Count,
                    ["wmi_win32_process"] = wmi.Count,
                    ["tasklist"] = tasklist.Count
                },
                ["deltas"] = new Dictionary<string, object?>
                {
                    ["toolhelp_only_count"] = CountExcept(toolhelp, wmi),
                    ["wmi_only_count"] = CountExcept(wmi, toolhelp),
                    ["tasklist_only_count"] = CountExcept(tasklist, toolhelp),
                    ["toolhelp_only_sample"] = SampleExcept(toolhelp, wmi),
                    ["wmi_only_sample"] = SampleExcept(wmi, toolhelp),
                    ["tasklist_only_sample"] = SampleExcept(tasklist, toolhelp)
                },
                ["network_sources"] = new Dictionary<string, object?>
                {
                    ["tcp_owner_pid_count"] = networkOwners.TcpOwners.Count,
                    ["udp_owner_pid_count"] = networkOwners.UdpOwners.Count,
                    ["tcp_owner_without_process_count"] = CountExcept(networkOwners.TcpOwners, toolhelp),
                    ["udp_owner_without_process_count"] = CountExcept(networkOwners.UdpOwners, toolhelp),
                    ["tcp_owner_without_process_sample"] = SampleExcept(networkOwners.TcpOwners, toolhelp),
                    ["udp_owner_without_process_sample"] = SampleExcept(networkOwners.UdpOwners, toolhelp)
                },
                ["bounds"] = new Dictionary<string, object?>
                {
                    ["pid_sample_max"] = MaxSamplePids
                }
            };

            sink.AddEvidence(
                "consistency-summary-1",
                "artefact",
                "host",
                null,
                "process_visibility",
                null,
                "consistency_summary",
                details,
                0.9,
                "low",
                "Cross-source process visibility consistency summary.",
                null);

            return CollectResult.Ok();
        }
        catch (Exception ex)
        {
            return CollectResult.Fail(ex.Message, "unknown");
        }
    }

    private static HashSet<int> SnapshotProcessIds()
    {
        var set = new HashSet<int>();
        foreach (var proc in Process.GetProcesses())
        {
            try { set.Add(proc.Id); }
            finally { proc.Dispose(); }
        }
        return set;
    }

    private static HashSet<int> SnapshotWmiProcessIds()
    {
        var set = new HashSet<int>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId FROM Win32_Process");
            using var results = searcher.Get();
            foreach (var obj in results.Cast<ManagementBaseObject>())
            {
                var pid = ProcessCollector.ToInt(obj["ProcessId"]);
                if (pid.HasValue && pid.Value > 0)
                    set.Add(pid.Value);
            }
        }
        catch
        {
            // graceful degrade
        }
        return set;
    }

    private static HashSet<int> SnapshotTasklistProcessIds(CancellationToken cancellationToken)
    {
        var set = new HashSet<int>();
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "tasklist.exe",
                Arguments = "/fo csv /nh",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);
            cancellationToken.ThrowIfCancellationRequested();
            using var reader = new StringReader(output);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                var parts = ParseCsvLine(line);
                if (parts.Count < 2)
                    continue;
                if (int.TryParse(parts[1], out var pid) && pid > 0)
                    set.Add(pid);
            }
        }
        catch
        {
            // graceful degrade
        }
        return set;
    }

    private static List<string> ParseCsvLine(string line)
    {
        var result = new List<string>();
        if (string.IsNullOrEmpty(line))
            return result;
        var current = new StringBuilder();
        var inQuotes = false;
        foreach (var ch in line)
        {
            if (ch == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }
            if (ch == ',' && !inQuotes)
            {
                result.Add(current.ToString());
                current.Clear();
                continue;
            }
            current.Append(ch);
        }
        result.Add(current.ToString());
        return result;
    }

    private static int CountExcept(HashSet<int> left, HashSet<int> right)
    {
        var count = 0;
        foreach (var pid in left)
        {
            if (!right.Contains(pid))
                count++;
        }
        return count;
    }

    private static List<int> SampleExcept(HashSet<int> left, HashSet<int> right)
    {
        var sample = new List<int>();
        foreach (var pid in left.OrderBy(x => x))
        {
            if (right.Contains(pid))
                continue;
            sample.Add(pid);
            if (sample.Count >= MaxSamplePids)
                break;
        }
        return sample;
    }

    private static NetworkOwnerSets SnapshotNetworkOwnerSets()
    {
        return new NetworkOwnerSets
        {
            TcpOwners = SnapshotTcpOwnerPids(),
            UdpOwners = SnapshotUdpOwnerPids()
        };
    }

    private static HashSet<int> SnapshotTcpOwnerPids()
    {
        var owners = new HashSet<int>();
        uint size = 0;
        if (Native.GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 4, 0) != 122)
            return owners;
        var buf = new byte[size];
        unsafe
        {
            fixed (byte* p = buf)
            {
                if (Native.GetExtendedTcpTable((IntPtr)p, ref size, false, 2, 4, 0) != 0)
                    return owners;
                uint numEntries = *(uint*)p;
                var rowSize = (uint)Marshal.SizeOf<MibTcpRowOwnerPid>();
                for (uint i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>((IntPtr)((byte*)p + 4 + (int)(i * rowSize)));
                    owners.Add((int)row.dwOwningPid);
                }
            }
        }
        return owners;
    }

    private static HashSet<int> SnapshotUdpOwnerPids()
    {
        var owners = new HashSet<int>();
        uint size = 0;
        if (Native.GetExtendedUdpTable(IntPtr.Zero, ref size, false, 2, 2, 0) != 122)
            return owners;
        var buf = new byte[size];
        unsafe
        {
            fixed (byte* p = buf)
            {
                if (Native.GetExtendedUdpTable((IntPtr)p, ref size, false, 2, 2, 0) != 0)
                    return owners;
                uint numEntries = *(uint*)p;
                var rowSize = (uint)Marshal.SizeOf<MibUdpRowOwnerPid>();
                for (uint i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>((IntPtr)((byte*)p + 4 + (int)(i * rowSize)));
                    owners.Add((int)row.dwOwningPid);
                }
            }
        }
        return owners;
    }

    private sealed class NetworkOwnerSets
    {
        public HashSet<int> TcpOwners { get; init; } = new();
        public HashSet<int> UdpOwners { get; init; } = new();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    private static class Native
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref uint pdwSize, bool sort, int ipVersion, int tblClass, uint reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetExtendedUdpTable(IntPtr pUdpTable, ref uint pdwSize, bool sort, int ipVersion, int tblClass, uint reserved);
    }
}
