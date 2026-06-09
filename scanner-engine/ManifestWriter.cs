using System.Security.Cryptography;
using System.Text.Json;
using System.Text;

namespace NineSTriage.Engine;

public static class ManifestWriter
{
    public static async Task WriteManifestAsync(
        string outputDir,
        string evidenceJsonPath,
        string reportPath,
        CancellationToken cancellationToken = default)
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (File.Exists(evidenceJsonPath))
        {
            files[Path.GetFileName(evidenceJsonPath)] = await ComputeSha256Async(evidenceJsonPath, cancellationToken).ConfigureAwait(false);
        }
        if (File.Exists(reportPath))
        {
            files[Path.GetFileName(reportPath)] = await ComputeSha256Async(reportPath, cancellationToken).ConfigureAwait(false);
        }

        var manifest = new Dictionary<string, object?>
        {
            ["schema_version"] = "1.0",
            ["files"] = files
        };

        var options = new JsonSerializerOptions { WriteIndented = true };
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, options);
        var manifestPath = Path.Combine(outputDir, "manifest.json");
        await File.WriteAllBytesAsync(manifestPath, manifestBytes, cancellationToken).ConfigureAwait(false);
        await WriteManifestSignatureAsync(outputDir, manifestBytes, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        var bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static async Task WriteManifestSignatureAsync(string outputDir, byte[] manifestBytes, CancellationToken cancellationToken)
    {
        var signaturePath = Path.Combine(outputDir, "manifest.sig");
        var secret = Environment.GetEnvironmentVariable("VERIS_MANIFEST_HMAC_SECRET");
        if (string.IsNullOrWhiteSpace(secret))
        {
            if (File.Exists(signaturePath))
                File.Delete(signaturePath);
            return;
        }

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var signature = Convert.ToHexString(hmac.ComputeHash(manifestBytes)).ToLowerInvariant();
        await File.WriteAllTextAsync(signaturePath, signature + Environment.NewLine, cancellationToken).ConfigureAwait(false);
    }
}
