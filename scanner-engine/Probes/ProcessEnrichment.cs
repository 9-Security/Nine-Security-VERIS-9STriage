using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace NineSTriage.Engine.Probes;

/// <summary>Observable process enrichment for Central correlation (no scanner-side scoring).</summary>
internal static class ProcessEnrichment
{
    internal sealed class Enrichment
    {
        public string ProcessFamily { get; init; } = "unknown";
        public string? Publisher { get; init; }
        public bool? Signed { get; init; }
        public SignatureDetails? Signature { get; init; }
        public bool JitExpected { get; init; }
    }

    internal sealed class SignatureDetails
    {
        public bool SignaturePresent { get; init; }
        public string Status { get; init; } = "unknown";
        public string? Subject { get; init; }
        public string? Issuer { get; init; }
        public string? Thumbprint { get; init; }
        public string? NotBeforeUtc { get; init; }
        public string? NotAfterUtc { get; init; }
    }

    internal static Enrichment Build(string? processName, string? imagePath, string? commandLine)
    {
        var name = (processName ?? "").Trim();
        var path = (imagePath ?? "").Trim();
        var cmd = (commandLine ?? "").Trim();
        var family = ClassifyProcessFamily(name, path, cmd);
        var publisher = GetPublisher(path);
        var signature = GetSignatureDetails(path);
        return new Enrichment
        {
            ProcessFamily = family,
            Publisher = publisher,
            Signed = signature?.SignaturePresent,
            Signature = signature,
            JitExpected = IsJitExpectedFamily(family),
        };
    }

    internal static Dictionary<string, object?> ToDetailsDictionary(Enrichment enrichment)
    {
        var details = new Dictionary<string, object?>
        {
            ["process_family"] = enrichment.ProcessFamily,
            ["jit_expected"] = enrichment.JitExpected,
        };
        if (!string.IsNullOrWhiteSpace(enrichment.Publisher))
            details["publisher"] = enrichment.Publisher;
        if (enrichment.Signed.HasValue)
            details["signed"] = enrichment.Signed.Value;
        if (enrichment.Signature is { } signature)
            details["signature"] = ToDetailsDictionary(signature);
        return details;
    }

    internal static Dictionary<string, object?> ToDetailsDictionary(SignatureDetails signature)
    {
        var details = new Dictionary<string, object?>
        {
            ["signature_present"] = signature.SignaturePresent,
            ["signature_status"] = signature.Status,
        };
        if (!string.IsNullOrWhiteSpace(signature.Subject))
            details["subject"] = signature.Subject;
        if (!string.IsNullOrWhiteSpace(signature.Issuer))
            details["issuer"] = signature.Issuer;
        if (!string.IsNullOrWhiteSpace(signature.Thumbprint))
            details["thumbprint"] = signature.Thumbprint;
        if (!string.IsNullOrWhiteSpace(signature.NotBeforeUtc))
            details["not_before_utc"] = signature.NotBeforeUtc;
        if (!string.IsNullOrWhiteSpace(signature.NotAfterUtc))
            details["not_after_utc"] = signature.NotAfterUtc;
        return details;
    }

    internal static void AddFileSignatureDetails(Dictionary<string, object?> details, string? path)
    {
        var signature = GetSignatureDetails(path);
        if (signature is null)
            return;
        details["signed"] = signature.SignaturePresent;
        details["signature_status"] = signature.Status;
        details["signature"] = ToDetailsDictionary(signature);
    }

    internal static Dictionary<string, object?> BuildIdentityDetails(string? imagePath)
    {
        var details = new Dictionary<string, object?>();
        var normalizedPath = NormalizeImagePath(imagePath);
        if (!string.IsNullOrWhiteSpace(normalizedPath))
            details["normalized_image_path"] = normalizedPath;

        var hash = TryComputeSha256(imagePath);
        if (!string.IsNullOrWhiteSpace(hash))
            details["image_sha256"] = hash;

        try
        {
            if (!string.IsNullOrWhiteSpace(imagePath) && File.Exists(imagePath))
            {
                var info = new FileInfo(imagePath);
                details["file_created_utc"] = info.CreationTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ");
                details["file_modified_utc"] = info.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ");
                details["file_size_bytes"] = info.Length;
            }
        }
        catch
        {
            // Identity enrichment is best-effort evidence only.
        }

        return details;
    }

    internal static string? NormalizeImagePath(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
            return null;
        var value = Environment.ExpandEnvironmentVariables(imagePath.Trim().Trim('"'))
            .Replace('/', '\\')
            .Trim();
        while (value.Contains(@"\\", StringComparison.Ordinal))
            value = value.Replace(@"\\", @"\", StringComparison.Ordinal);
        return ProcessCollector.TruncateForEvidence(value.ToLowerInvariant(), 260);
    }

    internal static string ClassifyProcessFamily(string name, string path, string commandLine)
    {
        var hay = $"{name} {path} {commandLine}".ToLowerInvariant();
        if (ContainsAny(hay, "msedge", "chrome", "firefox", "brave", "opera", "iexplore", "msedgewebview"))
            return "browser";
        if (ContainsAny(hay, "electron", "cursor", "code.exe", "\\code\\", "slack", "discord", "teams", "postman", "figma"))
            return "electron";
        if (ContainsAny(hay, "vmware", "vmnat", "vmwaretray", "vmwareuser", "vmware-vmx", "vmware-authd"))
            return "vmware";
        if (ContainsAny(hay, "virtualbox", "vbox", "vboxsvc", "vboxheadless"))
            return "virtualization";
        if (ContainsAny(hay, "powershell", "pwsh", "wscript", "cscript", "mshta"))
            return "script_host";
        return "unknown";
    }

    internal static bool IsJitExpectedFamily(string family) =>
        family is "browser" or "electron" or "vmware" or "virtualization";

    internal static string? GetPublisher(string? path)
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

    internal static SignatureDetails? GetSignatureDetails(string? path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return null;
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            return new SignatureDetails
            {
                SignaturePresent = true,
                Status = "signed_certificate_present",
                Subject = ProcessCollector.TruncateForEvidence(cert.Subject, 240),
                Issuer = ProcessCollector.TruncateForEvidence(cert.Issuer, 240),
                Thumbprint = ProcessCollector.TruncateForEvidence(cert.Thumbprint?.Replace(" ", "").ToLowerInvariant(), 80),
                NotBeforeUtc = cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                NotAfterUtc = cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
            };
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return new SignatureDetails
            {
                SignaturePresent = false,
                Status = "unsigned_or_unreadable_signature",
            };
        }
        catch
        {
            return new SignatureDetails
            {
                SignaturePresent = false,
                Status = "signature_read_error",
            };
        }
    }

    internal static string? TryExtractImagePath(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
            return null;
        var trimmed = commandLine.Trim().Trim('"');
        if (trimmed.Length >= 3 && trimmed[1] == ':' && trimmed[2] == '\\')
        {
            var end = trimmed.IndexOf('"');
            var candidate = end > 0 ? trimmed[..end] : trimmed.Split(' ')[0];
            return ProcessCollector.TruncateForEvidence(candidate, 180);
        }
        if (trimmed.StartsWith("\\", StringComparison.Ordinal))
        {
            var candidate = trimmed.Split(' ')[0].Trim('"');
            return ProcessCollector.TruncateForEvidence(candidate, 180);
        }
        return null;
    }

    internal static string? TryComputeSha256(string? path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return null;
            var info = new FileInfo(path);
            if (info.Length <= 0 || info.Length > 50 * 1024 * 1024)
                return null;
            using var stream = File.OpenRead(path);
            using var sha = System.Security.Cryptography.SHA256.Create();
            var hash = sha.ComputeHash(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    private static bool ContainsAny(string haystack, params string[] needles)
    {
        foreach (var needle in needles)
        {
            if (haystack.Contains(needle, StringComparison.Ordinal))
                return true;
        }
        return false;
    }
}
