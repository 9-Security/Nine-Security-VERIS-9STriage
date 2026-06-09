using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace NineSTriage.Engine.License;

/// <summary>VERIS-TOKEN-1: parse and Ed25519 verify. Spec: docs/LICENSE_AND_AUTH_SPEC.md §5. No path in evidence.</summary>
public static class SignedLicenseProvider
{
    /// <summary>Default test/dev public key (32 bytes). Replace for production via VERIS_PUBLIC_KEY_HEX.</summary>
    private static readonly byte[] DefaultPublicKey =
    {
        0xbd, 0x17, 0x92, 0xf3, 0x15, 0x60, 0x7f, 0xa2,
        0xdd, 0xce, 0xc1, 0x7a, 0xa3, 0x35, 0x41, 0xec,
        0x8a, 0x5b, 0x61, 0xde, 0x37, 0x31, 0x1d, 0xd5,
        0x60, 0x5a, 0x2a, 0x5c, 0x33, 0x08, 0xeb, 0x8b
    };

    /// <summary>Try to parse and verify VERIS-TOKEN-1 file. Returns request id, expiry, expired flag, observation_window_sec, and collection_profile; or null if invalid.</summary>
    public static (string RequestId, string? ExpiryUtc, bool IsExpired, int ObservationWindowSec, string CollectionProfile)? TryParseSignedLicense(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return null;
        string[] lines;
        try
        {
            lines = File.ReadAllLines(filePath);
        }
        catch { return null; }

        if (lines.Length < 3) return null;
        if (lines[0].Trim() != "VERIS-TOKEN-1") return null;
        if (!lines[1].StartsWith("payload=", StringComparison.Ordinal)) return null;
        if (!lines[2].StartsWith("sig=", StringComparison.Ordinal)) return null;

        var payloadB64 = lines[1].AsSpan().Slice(8).Trim().ToString();
        var sigB64 = lines[2].AsSpan().Slice(4).Trim().ToString();
        var payload = Base64UrlDecode(payloadB64);
        var sig = Base64UrlDecode(sigB64);
        if (payload == null || payload.Length == 0 || sig == null || sig.Length != 64) return null;

        var publicKey = GetLicensePublicKey();
        if (!Ed25519Verify(publicKey, payload, sig)) return null;

        string json = Encoding.UTF8.GetString(payload);
        string? requestId = null;
        string? expiryUtc = null;
        string? tokenHash = null;
        string? format = null;
        string? collectionProfile = null;
        int observationWindowSec = 0;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("format", out var f)) format = f.GetString();
            if (root.TryGetProperty("request_id", out var r)) requestId = r.GetString();
            if (root.TryGetProperty("expiry_utc", out var e)) expiryUtc = e.GetString();
            if (string.IsNullOrEmpty(expiryUtc) && root.TryGetProperty("expires_at", out var e2))
                expiryUtc = e2.GetString();
            if (root.TryGetProperty("token_hash", out var h)) tokenHash = h.GetString();
            if (root.TryGetProperty("observation_window_sec", out var o)) observationWindowSec = o.GetInt32();
            if (root.TryGetProperty("collection_profile", out var cp)) collectionProfile = cp.GetString();
        }
        catch { return null; }

        if (!string.Equals(format, "VERIS-TOKEN-1", StringComparison.Ordinal)) return null;
        if (string.IsNullOrWhiteSpace(requestId) || string.IsNullOrWhiteSpace(tokenHash) || observationWindowSec < 0) return null;

        var now = DateTime.UtcNow;
        bool isExpired = false;
        if (!string.IsNullOrEmpty(expiryUtc) && DateTime.TryParse(expiryUtc, null, System.Globalization.DateTimeStyles.RoundtripKind, out var expiry))
        {
            isExpired = now >= expiry;
        }

        var normalizedProfile = (collectionProfile ?? "fast").Trim().ToLowerInvariant();
        if (normalizedProfile != "fast" && normalizedProfile != "observe" && normalizedProfile != "escalated")
            normalizedProfile = "fast";

        return (requestId.Trim(), expiryUtc, isExpired, observationWindowSec, normalizedProfile);
    }

    private static byte[] GetLicensePublicKey()
    {
        var hex = Environment.GetEnvironmentVariable("VERIS_PUBLIC_KEY_HEX");
        if (string.IsNullOrEmpty(hex) || hex.Length != 64) return DefaultPublicKey;
        var key = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            int hi = HexNibble(hex[i * 2]);
            int lo = HexNibble(hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) return DefaultPublicKey;
            key[i] = (byte)((hi << 4) | lo);
        }
        return key;
    }

    private static int HexNibble(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    }

    private static byte[]? Base64UrlDecode(string encoded)
    {
        if (string.IsNullOrEmpty(encoded)) return null;
        var b64 = encoded.Replace('-', '+').Replace('_', '/');
        int pad = b64.Length % 4;
        if (pad > 0) b64 += new string('=', 4 - pad);
        try
        {
            return Convert.FromBase64String(b64);
        }
        catch
        {
            return null;
        }
    }

    private static bool Ed25519Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64) return false;
        try
        {
            var keyParam = new Ed25519PublicKeyParameters(publicKey);
            var signer = new Ed25519Signer();
            signer.Init(false, keyParam);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
    }

}
