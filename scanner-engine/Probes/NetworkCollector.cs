using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Management;
using NineSTriage.Engine.Evidence;

namespace NineSTriage.Engine.Probes;

/// <summary>Network collector: TCP (connections + listening) and UDP via GetExtendedTcpTable / GetExtendedUdpTable. process_bound only.</summary>
public sealed class NetworkCollector : ICollector
{
    public string Name => "network";

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_CONNECTIONS = 4;
    private const int TCP_TABLE_OWNER_PID_LISTENER = 5;
    private const int UDP_TABLE_OWNER_PID = 2;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int MaxTcpEvidence = 1000;
    private const int MaxUdpEvidence = 2000;

    public CollectResult Collect(IEvidenceSink sink, long remainingMs = -1, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return CollectResult.Fail("Network collector is Windows-only.", "api_not_supported");

        try
        {
            var processSnapshot = BuildProcessSnapshot();
            var r1 = CollectTcpConnections(sink, processSnapshot, remainingMs, cancellationToken);
            if (r1.Status == CollectStatus.Fail) return r1;

            var r2 = CollectTcpListeners(sink, processSnapshot, remainingMs, cancellationToken);
            if (r2.Status == CollectStatus.Fail) return r2;

            var r3 = CollectUdpEndpoints(sink, processSnapshot, remainingMs, cancellationToken);
            if (r3.Status == CollectStatus.Fail) return r3;

            return CollectResult.Ok();
        }
        catch (Exception ex)
        {
            return CollectResult.Fail(ex.Message, "unknown");
        }
    }

    private static string FormatIp4(uint addr)
    {
        return $"{(addr >> 0) & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}";
    }

    private static ushort PortNtohs(uint portNetworkOrder)
    {
        var p = (ushort)(portNetworkOrder & 0xFFFF);
        return (ushort)((p >> 8) | (p << 8));
    }

    private static string TcpStateString(uint state)
    {
        return state switch
        {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RECEIVED",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "UNKNOWN"
        };
    }

    private static bool IsSuspiciousRemotePort(int port)
    {
        return port is 4444 or 5555 or 6666 or 9999 or 1337 or 1234 or 12345 or 31337;
    }

    private static CollectResult CollectTcpConnections(IEvidenceSink sink, Dictionary<int, NetworkProcessInfo> processSnapshot, long remainingMs, CancellationToken ct)
    {
        uint size = 0;
        if (Native.GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != ERROR_INSUFFICIENT_BUFFER)
            return CollectResult.Fail("GetExtendedTcpTable size failed", "api_not_supported");

        using var pin = System.Buffers.MemoryPool<byte>.Shared.Rent((int)size);
        var span = pin.Memory.Span.Slice(0, (int)size);
        unsafe
        {
            fixed (byte* p = span)
            {
                if (Native.GetExtendedTcpTable((IntPtr)p, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != 0)
                    return CollectResult.Fail("GetExtendedTcpTable failed", "unknown");
                uint numEntries = *(uint*)p;
                var rowSize = (uint)Marshal.SizeOf<MibTcpRowOwnerPid>();
                int seq = 0;
                for (uint i = 0; i < numEntries && seq < MaxTcpEvidence; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>((IntPtr)((byte*)p + 4 + (int)(i * rowSize)));
                    var localAddr = FormatIp4(row.dwLocalAddr);
                    var remoteAddr = FormatIp4(row.dwRemoteAddr);
                    var localPort = PortNtohs(row.dwLocalPort);
                    var remotePort = PortNtohs(row.dwRemotePort);
                    var pid = (int)row.dwOwningPid;
                    var stateStr = TcpStateString(row.dwState);
                    seq++;
                    var evidenceId = "EV-C-" + seq;
                    var targetName = $"tcp:{localAddr}:{localPort}-{remoteAddr}:{remotePort}";
                    var details = new Dictionary<string, object?>
                    {
                        ["local_address"] = localAddr,
                        ["local_port"] = (int)localPort,
                        ["remote_address"] = remoteAddr,
                        ["remote_port"] = (int)remotePort,
                        ["state"] = stateStr,
                        ["pid"] = pid
                    };
                    AddProcessDetails(details, pid, processSnapshot);
                    sink.AddEvidence(evidenceId, "network", "connection", pid, targetName, null,
                        "established_connection", details, 0.8, "low",
                        "TCP established/non-listening connection observed", "process_bound");

                    if (row.dwState == 5 && IsSuspiciousRemotePort((int)remotePort))
                    {
                        var unusualId = "EV-CU-" + seq;
                        var unusualDetails = new Dictionary<string, object?>
                        {
                            ["remote_port"] = (int)remotePort,
                            ["remote_address"] = remoteAddr,
                            ["state"] = "ESTABLISHED",
                            ["pid"] = pid
                        };
                        AddProcessDetails(unusualDetails, pid, processSnapshot);
                        sink.AddEvidence(unusualId, "network", "connection", pid, targetName, null,
                            "unusual_connection", unusualDetails, 0.7, "medium",
                            "TCP connection to heuristic suspicious remote port", "process_bound");
                    }
                }
            }
        }
        return CollectResult.Ok();
    }

    private static CollectResult CollectTcpListeners(IEvidenceSink sink, Dictionary<int, NetworkProcessInfo> processSnapshot, long remainingMs, CancellationToken ct)
    {
        uint size = 0;
        if (Native.GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) != ERROR_INSUFFICIENT_BUFFER)
            return CollectResult.Fail("GetExtendedTcpTable listeners size failed", "api_not_supported");

        var buf = new byte[size];
        using var pin = System.Buffers.MemoryPool<byte>.Shared.Rent((int)size);
        var span = pin.Memory.Span.Slice(0, (int)size);
        unsafe
        {
            fixed (byte* p = span)
            {
                var pBuf = (IntPtr)p;
                if (Native.GetExtendedTcpTable((IntPtr)p, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) != 0)
                    return CollectResult.Fail("GetExtendedTcpTable listeners failed", "unknown");
                uint numEntries = *(uint*)p;
                var rowSize = (uint)Marshal.SizeOf<MibTcpRowOwnerPid>();
                int seq = 0;
                for (uint i = 0; i < numEntries; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>((IntPtr)((byte*)p + 4 + (int)(i * rowSize)));
                    var localAddr = FormatIp4(row.dwLocalAddr);
                    var localPort = PortNtohs(row.dwLocalPort);
                    var pid = (int)row.dwOwningPid;
                    seq++;
                    var evidenceId = "EV-N-" + seq;
                    var targetName = $"tcp:{localAddr}:{localPort}";
                    var details = new Dictionary<string, object?>
                    {
                        ["local_address"] = localAddr,
                        ["local_port"] = (int)localPort,
                        ["state"] = "LISTENING",
                        ["pid"] = pid
                    };
                    AddProcessDetails(details, pid, processSnapshot);
                    sink.AddEvidence(evidenceId, "network", "socket", pid, targetName, null,
                        "listening_socket", details, 0.8, "low",
                        "TCP listening socket observed", "process_bound");
                }
            }
        }
        return CollectResult.Ok();
    }

    private static CollectResult CollectUdpEndpoints(IEvidenceSink sink, Dictionary<int, NetworkProcessInfo> processSnapshot, long remainingMs, CancellationToken ct)
    {
        uint size = 0;
        if (Native.GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER)
            return CollectResult.Fail("GetExtendedUdpTable size failed", "api_not_supported");

        using var pin = System.Buffers.MemoryPool<byte>.Shared.Rent((int)size);
        var span = pin.Memory.Span.Slice(0, (int)size);
        unsafe
        {
            fixed (byte* p = span)
            {
                if (Native.GetExtendedUdpTable((IntPtr)p, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0) != 0)
                    return CollectResult.Fail("GetExtendedUdpTable failed", "unknown");
                uint numEntries = *(uint*)p;
                var rowSize = (uint)Marshal.SizeOf<MibUdpRowOwnerPid>();
                int seq = 0;
                for (uint i = 0; i < numEntries && seq < MaxUdpEvidence; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>((IntPtr)((byte*)p + 4 + (int)(i * rowSize)));
                    var localAddr = FormatIp4(row.dwLocalAddr);
                    var localPort = PortNtohs(row.dwLocalPort);
                    var pid = (int)row.dwOwningPid;
                    seq++;
                    var evidenceId = "EV-UDP-" + seq;
                    var targetName = $"udp:{localAddr}:{localPort}";
                    var details = new Dictionary<string, object?>
                    {
                        ["local_address"] = localAddr,
                        ["local_port"] = (int)localPort,
                        ["pid"] = pid
                    };
                    AddProcessDetails(details, pid, processSnapshot);
                    sink.AddEvidence(evidenceId, "network", "socket", pid, targetName, null,
                        "udp_endpoint", details, 0.8, "low",
                        "UDP endpoint observed (GetExtendedUdpTable)", "process_bound");
                }
            }
        }
        return CollectResult.Ok();
    }

    private static void AddProcessDetails(Dictionary<string, object?> details, int pid, Dictionary<int, NetworkProcessInfo> processSnapshot)
    {
        if (!processSnapshot.TryGetValue(pid, out var info))
            return;
        var process = new Dictionary<string, object?>();
        process["name"] = info.Name;
        if (!string.IsNullOrWhiteSpace(info.Path))
            process["path"] = info.Path;
        var identity = ProcessEnrichment.BuildIdentityDetails(info.Path);
        if (identity.Count > 0)
            process["identity"] = identity;
        if (!string.IsNullOrWhiteSpace(info.CommandLine))
            process["command_line"] = info.CommandLine;
        if (info.SessionId.HasValue)
            process["session_id"] = info.SessionId.Value;
        if (!string.IsNullOrWhiteSpace(info.Owner))
            process["owner"] = info.Owner;
        if (!string.IsNullOrWhiteSpace(info.ExecutableArchitecture))
            process["executable_architecture"] = info.ExecutableArchitecture;
        if (!string.IsNullOrWhiteSpace(info.Signer))
            process["signer"] = info.Signer;
        if (!string.IsNullOrWhiteSpace(info.SignatureStatus))
            process["signature_status"] = info.SignatureStatus;
        if (process.Count > 0)
            details["process"] = process;
    }

    private static Dictionary<int, NetworkProcessInfo> BuildProcessSnapshot()
    {
        var snapshot = new Dictionary<int, NetworkProcessInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId,Name,ExecutablePath,CommandLine,SessionId FROM Win32_Process");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                var pid = ProcessCollector.ToInt(obj["ProcessId"]);
                if (!pid.HasValue || pid.Value <= 0)
                    continue;
                var path = ProcessCollector.TruncateForEvidence(obj["ExecutablePath"]?.ToString(), 180);
                snapshot[pid.Value] = new NetworkProcessInfo
                {
                    Name = ProcessCollector.TruncateForEvidence(obj["Name"]?.ToString(), 80) ?? "unknown",
                    Path = path,
                    CommandLine = ProcessCollector.TruncateForEvidence(obj["CommandLine"]?.ToString(), 256),
                    SessionId = ProcessCollector.ToInt(obj["SessionId"]),
                    Owner = ProcessCollector.TruncateForEvidence(BuildOwner(obj), 96),
                    ExecutableArchitecture = GetProcessArchitecture(pid.Value),
                    Signer = GetSigner(path),
                    SignatureStatus = string.IsNullOrWhiteSpace(path) ? null : "unknown"
                };
            }
        }
        catch
        {
            // graceful degrade
        }
        return snapshot;
    }

    private static string? GetSigner(string? path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return null;
            var versionInfo = FileVersionInfo.GetVersionInfo(path);
            return ProcessCollector.TruncateForEvidence(versionInfo.CompanyName, 80);
        }
        catch
        {
            return null;
        }
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

    private sealed class NetworkProcessInfo
    {
        public string Name { get; init; } = "unknown";
        public string? Path { get; init; }
        public string? CommandLine { get; init; }
        public int? SessionId { get; init; }
        public string? Owner { get; init; }
        public string? ExecutableArchitecture { get; init; }
        public string? Signer { get; init; }
        public string? SignatureStatus { get; init; }
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
