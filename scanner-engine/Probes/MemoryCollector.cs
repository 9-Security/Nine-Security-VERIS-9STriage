using System.Diagnostics;
using System.Runtime.InteropServices;
using NineSTriage.Engine.Evidence;

namespace NineSTriage.Engine.Probes;

/// <summary>Memory collector: VirtualQueryEx + ReadProcessMemory. Signals: mapped_rwx_region, private_executable_memory, rwx_region, high_entropy_region, suspicious_executable_region, memory_anomaly_density. Aligned with C++ memory.cpp.</summary>
public sealed class MemoryCollector : ICollector
{
    public string Name => "memory";

    private const int ProcessQueryAndVmRead = 0x0410; // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    private const int EntropySampleBytes = 4096;
    private const int EntropySampleBytesLarge = 8192;
    private const ulong MinRegionSizeForEntropy = 256;
    private const double HighEntropyThreshold = 7.5;
    private const int MaxHighEntropyRegionsPerProcess = 25;
    private const int MaxSuspiciousExecutablePerProcess = 25;
    private const int MaxMappedRwxPerProcess = 30;
    private const int HeaderProbeBytes = 64;
    private const int MaxTopRegionsPerProcess = 8;
    private const int MaxFallbackRegionSignalsPerProcess = 3;

    private const uint MemCommit = 0x1000;
    private const uint MemPrivate = 0x20000;
    private const uint MemMapped = 0x40000;
    private const uint MemImage = 0x1000000;
    private const uint PageExecuteRead = 0x20;
    private const uint PageExecuteReadwrite = 0x40;
    private const uint ListModulesAll = 3;

    public CollectResult Collect(IEvidenceSink sink, long remainingMs = -1, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return CollectResult.Fail("Memory collector is Windows-only.", "api_not_supported");

        var start = Stopwatch.StartNew();
        bool partialData = false;
        bool accessDenied = false;

        try
        {
            var processes = Process.GetProcesses();
            foreach (Process? proc in processes)
            {
                if (proc == null) continue;
                if (remainingMs >= 0 && start.ElapsedMilliseconds >= remainingMs)
                {
                    partialData = true;
                    break;
                }
                cancellationToken.ThrowIfCancellationRequested();

                int pid = proc.Id;
                string name = proc.ProcessName ?? "unknown";
                try
                {
                    CollectMemoryHeuristicsForProcess(sink, pid, name, ref partialData, ref accessDenied, remainingMs >= 0 ? remainingMs - start.ElapsedMilliseconds : -1, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    partialData = true;
                    break;
                }
                finally
                {
                    proc.Dispose();
                }
            }

            if (partialData && accessDenied)
                return CollectResult.Partial("access_denied");
            return partialData ? CollectResult.Partial() : CollectResult.Ok();
        }
        catch (Exception ex)
        {
            return CollectResult.Fail(ex.Message, "unknown");
        }
    }

    private static void CollectMemoryHeuristicsForProcess(
        IEvidenceSink sink,
        int pid,
        string name,
        ref bool partialData,
        ref bool accessDenied,
        long remainingMs,
        CancellationToken ct)
    {
        IntPtr hProc = Native.OpenProcess(ProcessQueryAndVmRead, false, (uint)pid);
        if (hProc == IntPtr.Zero)
        {
            partialData = true;
            if (Marshal.GetLastWin32Error() == 5) accessDenied = true; // ERROR_ACCESS_DENIED
            return;
        }

        try
        {
            int evidenceSeq = 0;
            int highEntropyCount = 0;
            int suspiciousExecCount = 0;
            int mappedRwxCount = 0;
            int privateExecCount = 0;
            int rwxCount = 0;
            var anomalyBases = new HashSet<nint>();
            var topRegions = new List<RegionSummary>();
            int emittedPrivateExec = 0;
            int emittedRwx = 0;
            int emittedHighEntropy = 0;
            int emittedMappedRwx = 0;
            int emittedSuspicious = 0;

            nuint addr = 0;
            var mbi = new MemoryBasicInformation();

            while (true)
            {
                if (remainingMs >= 0) { /* time check could be added per iteration */ }
                ct.ThrowIfCancellationRequested();

                if (Native.VirtualQueryEx(hProc, (IntPtr)addr, out mbi, (uint)Marshal.SizeOf<MemoryBasicInformation>()) == UIntPtr.Zero)
                    break;

                nint baseAddr = mbi.BaseAddress;
                ulong regionSize = mbi.RegionSize;
                string baseHex = BaseAddressToHex(baseAddr);

                // MEM_MAPPED / MEM_IMAGE + RWX
                if (mbi.State == MemCommit && (mbi.Type == MemMapped || mbi.Type == MemImage) &&
                    mbi.Protect == PageExecuteReadwrite && mappedRwxCount < MaxMappedRwxPerProcess)
                {
                    mappedRwxCount++;
                    AddOrUpdateTopRegion(topRegions, baseHex, regionSize, "RWX", mbi.Type == MemImage ? "image" : "mapped", "mapped_rwx");
                    if (emittedMappedRwx < MaxFallbackRegionSignalsPerProcess)
                    {
                        emittedMappedRwx++;
                        evidenceSeq++;
                        var details = new Dictionary<string, object?>
                        {
                            ["base_address"] = baseHex,
                            ["region_size"] = (long)regionSize,
                            ["region_type"] = mbi.Type == MemImage ? "image" : "mapped",
                            ["backed"] = true
                        };
                        sink.AddEvidence($"EV-M-MRWX-{pid}-{evidenceSeq}", "memory", "process", pid, name, null,
                            "mapped_rwx_region", details, 0.7, "medium",
                            "Mapped or image region with RWX protection (fallback sample)", null);
                    }
                    anomalyBases.Add(baseAddr);
                }

                if (mbi.State == MemCommit && mbi.Type == MemPrivate)
                {
                    uint p = mbi.Protect;

                    if (p == PageExecuteRead || p == PageExecuteReadwrite)
                    {
                        privateExecCount++;
                        AddOrUpdateTopRegion(topRegions, baseHex, regionSize, ProtectionToString(p), "private", "private_exec");
                        if (emittedPrivateExec < MaxFallbackRegionSignalsPerProcess)
                        {
                            emittedPrivateExec++;
                            evidenceSeq++;
                            var details = new Dictionary<string, object?>
                            {
                                ["base_address"] = baseHex,
                                ["protection"] = ProtectionToString(p),
                                ["region_size"] = (long)regionSize,
                                ["region_type"] = "private",
                                ["mapped_module"] = false,
                                ["backed"] = false
                            };
                            sink.AddEvidence($"EV-M-{pid}-{evidenceSeq}", "memory", "process", pid, name, null,
                                "private_executable_memory", details, 0.75, "medium",
                                "Executable private memory region without corresponding loaded module (fallback sample)", null);
                        }
                        anomalyBases.Add(baseAddr);
                    }

                    if (p == PageExecuteReadwrite)
                    {
                        rwxCount++;
                        AddOrUpdateTopRegion(topRegions, baseHex, regionSize, "RWX", "private", "rwx");
                        if (emittedRwx < MaxFallbackRegionSignalsPerProcess)
                        {
                            emittedRwx++;
                            evidenceSeq++;
                            var detailsRwx = new Dictionary<string, object?>
                            {
                                ["base_address"] = baseHex,
                                ["protection"] = "RWX",
                                ["region_size"] = (long)regionSize,
                                ["region_type"] = "private",
                                ["backed"] = false
                            };
                            sink.AddEvidence($"EV-M-RWX-{pid}-{evidenceSeq}", "memory", "process", pid, name, null,
                                "rwx_region", detailsRwx, 0.8, "medium",
                                "Private RWX memory region (fallback sample)", null);
                        }
                        anomalyBases.Add(baseAddr);
                    }

                    // High entropy + optional suspicious_executable_region
                    if (highEntropyCount < MaxHighEntropyRegionsPerProcess && regionSize >= MinRegionSizeForEntropy)
                    {
                        int sampleCap = regionSize >= EntropySampleBytesLarge ? EntropySampleBytesLarge : EntropySampleBytes;
                        int toRead = (int)Math.Min(regionSize, (ulong)sampleCap);
                        var sample = new byte[toRead];
                        if (Native.ReadProcessMemory(hProc, baseAddr, sample, (uint)toRead, out uint read) && read >= 256)
                        {
                            double entropy = ComputeEntropy(sample.AsSpan(0, (int)read));
                            if (entropy >= HighEntropyThreshold)
                            {
                                highEntropyCount++;
                                AddOrUpdateTopRegion(topRegions, baseHex, regionSize, ProtectionToString(p), "private", "high_entropy", Math.Round(entropy, 2));
                                if (emittedHighEntropy < MaxFallbackRegionSignalsPerProcess)
                                {
                                    emittedHighEntropy++;
                                    evidenceSeq++;
                                    var detailsHe = new Dictionary<string, object?>
                                    {
                                        ["base_address"] = baseHex,
                                        ["entropy"] = Math.Round(entropy, 2),
                                        ["region_size"] = (long)regionSize,
                                        ["region_type"] = "private",
                                        ["sample_bytes"] = (int)read,
                                        ["backed"] = false
                                    };
                                    sink.AddEvidence($"EV-M-HE-{pid}-{evidenceSeq}", "memory", "process", pid, name, null,
                                        "high_entropy_region", detailsHe, 0.6, "low",
                                        "High-entropy memory region (fallback sample)", null);
                                }
                                anomalyBases.Add(baseAddr);

                                if ((p == PageExecuteRead || p == PageExecuteReadwrite) &&
                                    suspiciousExecCount < MaxSuspiciousExecutablePerProcess)
                                {
                                    suspiciousExecCount++;
                                    AddOrUpdateTopRegion(topRegions, baseHex, regionSize, ProtectionToString(p), "private", "suspicious_exec", Math.Round(entropy, 2));
                                    if (emittedSuspicious < MaxFallbackRegionSignalsPerProcess)
                                    {
                                        emittedSuspicious++;
                                        evidenceSeq++;
                                        var detailsSusp = new Dictionary<string, object?>
                                        {
                                            ["base_address"] = baseHex,
                                            ["protection"] = ProtectionToString(p),
                                            ["region_size"] = (long)regionSize,
                                            ["region_type"] = "private",
                                            ["entropy"] = Math.Round(entropy, 2),
                                            ["sample_bytes"] = (int)read,
                                            ["backed"] = false
                                        };
                                        sink.AddEvidence($"EV-M-SUSP-{pid}-{evidenceSeq}", "memory", "process", pid, name, null,
                                            "suspicious_executable_region", detailsSusp, 0.85, "high",
                                            "Executable private region with high entropy (fallback sample)", null);
                                    }
                                    anomalyBases.Add(baseAddr);
                                }
                            }
                        }
                    }

                    // Practical triage heuristic: executable private region with PE/shell stub bytes.
                    if ((p == PageExecuteRead || p == PageExecuteReadwrite) &&
                        suspiciousExecCount < MaxSuspiciousExecutablePerProcess &&
                        regionSize >= HeaderProbeBytes)
                    {
                        var probe = new byte[HeaderProbeBytes];
                        if (Native.ReadProcessMemory(hProc, baseAddr, probe, HeaderProbeBytes, out uint headerRead) && headerRead >= 16)
                        {
                            bool hasMz = probe[0] == 0x4D && probe[1] == 0x5A; // "MZ"
                            bool hasShellStub =
                                probe[0] == 0xFC && probe[1] == 0x48 && probe[2] == 0x83 && probe[3] == 0xE4;
                            if (hasMz || hasShellStub)
                            {
                                suspiciousExecCount++;
                                AddOrUpdateTopRegion(topRegions, baseHex, regionSize, ProtectionToString(p), "private", hasMz ? "mz_header" : "shell_stub");
                                if (emittedSuspicious < MaxFallbackRegionSignalsPerProcess)
                                {
                                    emittedSuspicious++;
                                    evidenceSeq++;
                                    var detailsStub = new Dictionary<string, object?>
                                    {
                                        ["base_address"] = baseHex,
                                        ["protection"] = ProtectionToString(p),
                                        ["region_size"] = (long)regionSize,
                                        ["region_type"] = "private",
                                        ["backed"] = false,
                                        ["signature_hint"] = hasMz ? "mz_header" : "shell_stub"
                                    };
                                    sink.AddEvidence($"EV-M-SIGHINT-{pid}-{evidenceSeq}", "memory", "process", pid, name, null,
                                        "suspicious_executable_region", detailsStub, 0.8, "high",
                                        "Executable private region with suspicious header bytes (fallback sample)", null);
                                }
                                anomalyBases.Add(baseAddr);
                            }
                        }
                    }
                }

                unchecked
                {
                    addr = (nuint)((ulong)baseAddr + regionSize);
                }
                if (addr == 0) break;
            }

            if (privateExecCount > 0 || rwxCount > 0 || highEntropyCount > 0 || mappedRwxCount > 0 || suspiciousExecCount > 0)
            {
                evidenceSeq++;
                sink.AddEvidence(
                    $"EV-M-SUM-{pid}-{evidenceSeq}",
                    "memory",
                    "process",
                    pid,
                    name,
                    null,
                    "memory_summary",
                    new Dictionary<string, object?>
                    {
                        ["rwx_count"] = rwxCount,
                        ["private_exec_count"] = privateExecCount,
                        ["high_entropy_count"] = highEntropyCount,
                        ["mapped_rwx_count"] = mappedRwxCount,
                        ["suspicious_exec_count"] = suspiciousExecCount,
                        ["top_regions"] = topRegions
                            .OrderByDescending(r => r.Score)
                            .ThenByDescending(r => r.RegionSize)
                            .Take(MaxTopRegionsPerProcess)
                            .Select(r => r.ToEvidenceRow())
                            .ToList(),
                        ["bounds"] = new Dictionary<string, object?>
                        {
                            ["top_regions_max"] = MaxTopRegionsPerProcess,
                            ["fallback_region_signals_max_per_type"] = MaxFallbackRegionSignalsPerProcess
                        }
                    },
                    0.82,
                    "medium",
                    "Aggregated memory anomaly summary for process.",
                    null);
            }

            // memory_anomaly_density (aggregate per process)
            if (anomalyBases.Count > 0)
            {
                double uptimeSec = GetProcessUptimeSeconds(hProc);
                int moduleCount = CountLoadedModules(hProc);
                var density = new Dictionary<string, object?>();
                density["anomaly_region_count"] = anomalyBases.Count;
                if (uptimeSec > 0.0)
                    density["process_uptime_sec"] = Math.Round(uptimeSec, 3);
                if (moduleCount >= 0)
                    density["loaded_module_count"] = moduleCount;
                if (uptimeSec > 0.0)
                    density["per_uptime"] = Math.Round(anomalyBases.Count / uptimeSec, 6);
                if (moduleCount > 0)
                    density["per_module"] = Math.Round((double)anomalyBases.Count / moduleCount, 6);
                if (density.Count > 0)
                {
                    evidenceSeq++;
                    sink.AddEvidence($"EV-M-DENS-{pid}-{evidenceSeq}", "memory", "process", pid, name, null,
                        "memory_anomaly_density", density, 0.0, "low",
                        "Aggregated memory anomaly density (per process)", null);
                }
            }
        }
        finally
        {
            Native.CloseHandle(hProc);
        }
    }

    private static string BaseAddressToHex(nint addr)
    {
        return Environment.Is64BitProcess
            ? $"0x{(ulong)addr:X16}"
            : $"0x{(uint)addr:X8}";
    }

    private static string ProtectionToString(uint protect)
    {
        return protect == PageExecuteRead ? "RX" : protect == PageExecuteReadwrite ? "RWX" : "OTHER";
    }

    private static double ComputeEntropy(ReadOnlySpan<byte> buf)
    {
        if (buf.Length == 0) return 0.0;
        Span<int> counts = stackalloc int[256];
        counts.Clear();
        for (int i = 0; i < buf.Length; i++)
            counts[buf[i]]++;
        double entropy = 0.0;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = (double)counts[i] / buf.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static double GetProcessUptimeSeconds(IntPtr hProc)
    {
        if (!Native.GetProcessTimes(hProc, out var creationFt, out var _, out var _, out var _))
            return 0.0;
        Native.GetSystemTimeAsFileTime(out var nowFt);
        ulong c = ((ulong)creationFt.dwHighDateTime << 32) | creationFt.dwLowDateTime;
        ulong n = ((ulong)nowFt.dwHighDateTime << 32) | nowFt.dwLowDateTime;
        if (n <= c) return 0.0;
        double seconds = (double)(n - c) / 10000000.0;
        return seconds > 0 ? seconds : 0.0;
    }

    private static int CountLoadedModules(IntPtr hProc)
    {
        if (!Native.EnumProcessModulesEx(hProc, null, 0, out uint cbNeeded, ListModulesAll))
            return 0;
        return cbNeeded == 0 ? 0 : (int)(cbNeeded / (uint)IntPtr.Size);
    }

    private static void AddOrUpdateTopRegion(List<RegionSummary> topRegions, string baseAddress, ulong regionSize, string protection, string regionType, string indicator, double? entropy = null)
    {
        var existing = topRegions.FirstOrDefault(r => string.Equals(r.BaseAddress, baseAddress, StringComparison.Ordinal));
        if (existing == null)
        {
            existing = new RegionSummary
            {
                BaseAddress = baseAddress,
                RegionSize = (long)regionSize,
                Protection = protection,
                RegionType = regionType
            };
            topRegions.Add(existing);
        }
        existing.AddIndicator(indicator, entropy);
    }

    private sealed class RegionSummary
    {
        public string BaseAddress { get; init; } = "";
        public long RegionSize { get; init; }
        public string Protection { get; init; } = "OTHER";
        public string RegionType { get; init; } = "unknown";
        public HashSet<string> Indicators { get; } = new(StringComparer.Ordinal);
        public double? Entropy { get; private set; }
        public int Score { get; private set; }

        public void AddIndicator(string indicator, double? entropy = null)
        {
            Indicators.Add(indicator);
            Score++;
            if (entropy.HasValue)
                Entropy = Math.Max(Entropy ?? 0.0, entropy.Value);
        }

        public Dictionary<string, object?> ToEvidenceRow()
        {
            var row = new Dictionary<string, object?>
            {
                ["base_address"] = BaseAddress,
                ["region_size"] = RegionSize,
                ["protection"] = Protection,
                ["region_type"] = RegionType,
                ["indicators"] = Indicators.OrderBy(x => x).ToList()
            };
            if (Entropy.HasValue)
                row["entropy"] = Math.Round(Entropy.Value, 2);
            return row;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        private readonly uint _padding;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Filetime
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    private static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UIntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetProcessTimes(IntPtr hProcess, out Filetime lpCreationTime, out Filetime lpExitTime, out Filetime lpKernelTime, out Filetime lpUserTime);

        [DllImport("kernel32.dll")]
        public static extern void GetSystemTimeAsFileTime(out Filetime lpSystemTimeAsFileTime);

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, IntPtr[]? lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);
    }
}
