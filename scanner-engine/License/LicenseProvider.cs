namespace NineSTriage.Engine.License;

/// <summary>Resolves VERIS token path and returns status. Signed token is required for execution.</summary>
public static class LicenseProvider
{
    /// <summary>Resolve license path: VERIS_LICENSE_PATH env, then %APPDATA%\VERIS\license.lic.</summary>
    public static string? ResolveLicensePath()
    {
        var env = Environment.GetEnvironmentVariable("VERIS_LICENSE_PATH");
        if (!string.IsNullOrWhiteSpace(env) && File.Exists(env)) return env;
        var shared = GetSharedLicensePath();
        return !string.IsNullOrEmpty(shared) && File.Exists(shared) ? shared : null;
    }

    /// <summary>Shared license path for UI import and CLI fallback. Creates directory if missing.</summary>
    public static string GetSharedLicensePath()
    {
        try
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (string.IsNullOrEmpty(appData)) return "";
            var dir = Path.Combine(appData, "VERIS");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "license.lic");
        }
        catch
        {
            return "";
        }
    }

    /// <summary>Get current token status. Path optional; when null uses ResolveLicensePath(). Returns request id, expiry, expired flag, observation_window_sec, and collection_profile from token.</summary>
    public static (string RequestId, string? ExpiryUtc, bool IsExpired, int ObservationWindowSec, string CollectionProfile)? GetLicenseStatus(string? licensePath = null)
    {
        var path = licensePath ?? ResolveLicensePath();
        if (string.IsNullOrEmpty(path)) return null;

        // Signed token is the only accepted format.
        var signed = SignedLicenseProvider.TryParseSignedLicense(path);
        return signed;
    }
}
