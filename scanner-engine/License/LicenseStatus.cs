namespace NineSTriage.Engine.License;

/// <summary>Result of VERIS token resolution: request id and optional expiry.</summary>
public sealed class LicenseStatus
{
    public string RequestId { get; init; } = "";
    public string? ExpiryUtc { get; init; }
    public bool IsExpired { get; init; }
}
