namespace NineSTriage.Engine.License;

/// <summary>License interface. License data never touches evidence.json. Report-only.</summary>
public interface ILicenseProvider
{
    string GetLicenseMode();
    IReadOnlyList<string> GetEnabledFeatureFlags();
}
