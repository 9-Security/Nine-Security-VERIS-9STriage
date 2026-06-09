using System.Runtime.InteropServices;

namespace NineSTriage.Engine.Probes;

/// <summary>Reads TCP owner table for bounded observation merges (reuse semantics with NetworkCollector).</summary>
public static class TcpObservationSampler
{
    private const int AfInet = 2;
    private const int TcpTableOwnerPidConnections = 4;
    private const int ErrorInsufficientBuffer = 122;

    /// <returns>Established TCP connection fingerprints for one sample round.</returns>
    public static HashSet<string> SnapshotEstablishedKeys(CancellationToken ct)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        if (!OperatingSystem.IsWindows())
            return keys;

        uint size = 0;
        if (Native.GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidConnections, 0) != ErrorInsufficientBuffer)
            return keys;

        using var pin = System.Buffers.MemoryPool<byte>.Shared.Rent((int)size);
        var span = pin.Memory.Span.Slice(0, (int)size);
        unsafe
        {
            fixed (byte* p = span)
            {
                if (Native.GetExtendedTcpTable((IntPtr)p, ref size, false, AfInet, TcpTableOwnerPidConnections, 0) != 0)
                    return keys;
                uint numEntries = *(uint*)p;
                var rowSize = (uint)Marshal.SizeOf<MibTcpRowOwnerPid>();
                for (uint i = 0; i < numEntries; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>((IntPtr)((byte*)p + 4 + (int)(i * rowSize)));
                    if (row.dwState != 5)
                        continue;
                    var la = FormatIp4(row.dwLocalAddr);
                    var ra = FormatIp4(row.dwRemoteAddr);
                    var lp = PortNtohs(row.dwLocalPort);
                    var rp = PortNtohs(row.dwRemotePort);
                    var pid = (int)row.dwOwningPid;
                    keys.Add($"{pid}|{la}:{lp}->{ra}:{rp}");
                }
            }
        }

        return keys;
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

    private static class Native
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref uint pdwSize, bool sort, int ipVersion, int tblClass, uint reserved);
    }
}
