using NineSTriage.Engine.License;

namespace NineSTriage.Engine;

internal static class Program
{
    private const string DefaultOutputDir = "veris_output";

    public static async Task<int> Main(string[] args)
    {
        var parsed = ParseArgs(args);
        if (!string.IsNullOrEmpty(parsed.ErrorMessage))
        {
            Console.Error.WriteLine(parsed.ErrorMessage);
            PrintUsage();
            return 1;
        }

        if (parsed.ShowHelp)
        {
            PrintUsage();
            return 0;
        }

        var licensePath = ResolveLicensePath(parsed.LicensePath);
        var licenseStatus = LicenseProvider.GetLicenseStatus(licensePath);
        if (licenseStatus is null)
        {
            Console.Error.WriteLine("Error: a valid VERIS token is required.");
            return 1;
        }
        if (licenseStatus.Value.IsExpired)
        {
            Console.Error.WriteLine("Error: VERIS token has expired.");
            return 1;
        }
        if (parsed.PrintLicenseStatus)
        {
            Console.WriteLine(licenseStatus.Value.RequestId);
            if (licenseStatus.Value.ExpiryUtc is { } expiryUtc && !string.IsNullOrWhiteSpace(expiryUtc))
                Console.WriteLine(expiryUtc);
            return 0;
        }

        var outputDir = Path.GetFullPath(string.IsNullOrWhiteSpace(parsed.OutputDir) ? DefaultOutputDir : parsed.OutputDir);
        var zipPath = ResolveZipPath(outputDir, parsed);

        var tokenProfile = licenseStatus.Value.CollectionProfile;
        var profile = string.IsNullOrWhiteSpace(parsed.CollectionProfile) ? tokenProfile : parsed.CollectionProfile.Trim().ToLowerInvariant();
        if (profile != "fast" && profile != "observe" && profile != "escalated")
            profile = "fast";
        if (!string.IsNullOrWhiteSpace(tokenProfile) && profile != tokenProfile)
        {
            Console.Error.WriteLine($"Error: requested --profile '{profile}' mismatches signed VERIS token profile '{tokenProfile}'.");
            return 1;
        }
        var licObs = licenseStatus.Value.ObservationWindowSec;
        if (parsed.ObservationWindowSeconds > 0 && licObs > 0 && parsed.ObservationWindowSeconds != licObs)
        {
            Console.Error.WriteLine(
                $"Error: requested --observation-window-sec '{parsed.ObservationWindowSeconds}' mismatches signed VERIS token window '{licObs}'.");
            return 1;
        }
        var effObservationSec = ResolveObservationWindow(parsed.ObservationWindowSeconds, profile, licObs);
        var timeBudgetMs = ResolveTimeBudgetMs(profile);

        var result = await ScanRunner.RunAsync(new ScanRunnerOptions
        {
            OutputDir = outputDir,
            CreateZip = parsed.CreateZip,
            ZipPath = zipPath,
            ZipOnlyOutput = parsed.ZipOnlyOutput,
            LicensePath = licensePath,
            CollectionProfile = profile,
            ObservationWindowSeconds = effObservationSec,
            ObservationIntervalSeconds = parsed.ObservationIntervalSeconds,
            TimeBudgetMsPerModule = timeBudgetMs,
        }).ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            if (!string.IsNullOrWhiteSpace(result.ErrorMessage))
                Console.Error.WriteLine(result.ErrorMessage);
            foreach (var diagnostic in result.Diagnostics)
                Console.Error.WriteLine(diagnostic);
            return result.ExitCode;
        }

        Console.WriteLine($"Scan completed. Evidence count: {result.EvidenceCount}");
        if (!string.IsNullOrWhiteSpace(result.EvidencePath))
            Console.WriteLine($"evidence.json: {result.EvidencePath}");
        if (!string.IsNullOrWhiteSpace(result.ManifestPath))
            Console.WriteLine($"manifest.json: {result.ManifestPath}");
        if (!string.IsNullOrWhiteSpace(result.ReportPath))
            Console.WriteLine($"endpoint_report.md: {result.ReportPath}");
        if (!string.IsNullOrWhiteSpace(result.ZipPath))
            Console.WriteLine($"zip: {result.ZipPath}");
        return 0;
    }

    private static CliOptions ParseArgs(string[] args)
    {
        var options = new CliOptions();

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--help":
                case "-h":
                    options.ShowHelp = true;
                    return options;
                case "--output-dir":
                    if (!TryReadValue(args, ref i, out var outputDir))
                        return CliOptions.Fail("Error: --output-dir requires <path>.");
                    options.OutputDir = outputDir;
                    break;
                case "--zip":
                    options.CreateZip = true;
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-", StringComparison.Ordinal))
                        options.ZipPath = args[++i];
                    break;
                case "--zip-only":
                    options.CreateZip = true;
                    options.ZipOnlyOutput = true;
                    break;
                case "--license":
                    if (!TryReadValue(args, ref i, out var licensePath))
                        return CliOptions.Fail("Error: --license requires <path>.");
                    options.LicensePath = licensePath;
                    break;
                case "--license-status":
                    options.PrintLicenseStatus = true;
                    break;
                case "--observation-window-sec":
                    if (!TryReadValue(args, ref i, out var windowSecRaw) || !int.TryParse(windowSecRaw, out var windowSec) || windowSec < 0)
                        return CliOptions.Fail("Error: --observation-window-sec requires non-negative integer seconds.");
                    options.ObservationWindowSeconds = windowSec;
                    break;
                case "--observation-interval-sec":
                    if (!TryReadValue(args, ref i, out var intervalSecRaw) || !int.TryParse(intervalSecRaw, out var intervalSec) || intervalSec < 5)
                        return CliOptions.Fail("Error: --observation-interval-sec requires integer seconds >= 5.");
                    options.ObservationIntervalSeconds = intervalSec;
                    break;
                case "--profile":
                    if (!TryReadValue(args, ref i, out var profRaw))
                        return CliOptions.Fail("Error: --profile requires fast|observe|escalated.");
                    var pl = profRaw.Trim().ToLowerInvariant();
                    if (pl != "fast" && pl != "observe" && pl != "escalated")
                        return CliOptions.Fail("Error: --profile must be fast, observe, or escalated.");
                    options.CollectionProfile = pl;
                    break;
                default:
                    return CliOptions.Fail($"Unknown option: {args[i]}");
            }
        }

        return options;
    }

    private static bool TryReadValue(string[] args, ref int index, out string value)
    {
        value = string.Empty;
        if (index + 1 >= args.Length)
            return false;
        value = args[++index];
        return true;
    }

    private static string? ResolveLicensePath(string? explicitPath)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
            return explicitPath;
        return LicenseProvider.ResolveLicensePath();
    }

    private static int ResolveObservationWindow(int cliOverride, string profile, int licenseObservationSec)
    {
        if (licenseObservationSec > 0)
        {
            // Signed token window is authoritative: scanner must not silently downgrade it.
            return Math.Clamp(licenseObservationSec, 0, 600);
        }

        if (cliOverride > 0)
            return Math.Min(cliOverride, 600);

        profile = profile.Trim().ToLowerInvariant();
        return profile switch
        {
            "observe" => Math.Min(Math.Max(licenseObservationSec, 120), 600),
            "escalated" => Math.Min(Math.Max(licenseObservationSec, 240), 600),
            _ => 0,
        };
    }

    /// <summary>Per-collector approximate wall-clock budget (-1 leaves unlimited).</summary>
    private static long? ResolveTimeBudgetMs(string profile)
    {
        profile = profile.Trim().ToLowerInvariant();
        return profile switch
        {
            "escalated" => 120_000L,
            "observe" => 85_000L,
            _ => 60_000L,
        };
    }

    private static string? ResolveZipPath(string outputDir, CliOptions options)
    {
        if (!options.CreateZip)
            return null;
        if (!string.IsNullOrWhiteSpace(options.ZipPath))
            return Path.GetFullPath(options.ZipPath);
        var host = string.IsNullOrWhiteSpace(Environment.MachineName) ? "unknown" : Environment.MachineName;
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        return Path.Combine(outputDir, $"{host}_{timestamp}.zip");
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: 9STriage [options]");
        Console.WriteLine("  --output-dir <path>     Run headless scan and write evidence to <path>.");
        Console.WriteLine("  --zip [path]            Also create a Central-ingest zip package.");
        Console.WriteLine("  --zip-only              Keep only zip package in output directory.");
        Console.WriteLine("  --license <path>        Required VERIS token file for execution.");
        Console.WriteLine("  --license-status        Print validated license mode and exit.");
        Console.WriteLine("  --observation-window-sec <n>   Optional bounded pseudo-live observation window (0-600 sec, default 0).");
        Console.WriteLine("  --observation-interval-sec <n> Sampling interval for observation window (>=5 sec, default 15).");
        Console.WriteLine("  --profile <fast|observe|escalated> Bounded triage collection profile (default fast). Overrides observation window defaults unless --observation-window-sec set.");
        Console.WriteLine("  --help, -h              Show this message.");
        Console.WriteLine("  Environment: VERIS_LICENSE_PATH");
        Console.WriteLine($"  Default output dir when omitted: .\\{DefaultOutputDir}");
    }

    private sealed class CliOptions
    {
        public string? ErrorMessage { get; private init; }
        public bool ShowHelp { get; set; }
        public string? OutputDir { get; set; }
        public bool CreateZip { get; set; }
        public string? ZipPath { get; set; }
        public bool ZipOnlyOutput { get; set; }
        public string? LicensePath { get; set; }
        public bool PrintLicenseStatus { get; set; }
        public int ObservationWindowSeconds { get; set; }
        public int ObservationIntervalSeconds { get; set; } = 15;
        public string? CollectionProfile { get; set; }

        public static CliOptions Fail(string errorMessage) => new() { ErrorMessage = errorMessage };
    }
}
