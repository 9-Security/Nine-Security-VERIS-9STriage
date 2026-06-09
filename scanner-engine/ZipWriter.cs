using System.IO.Compression;

namespace NineSTriage.Engine;

public static class ZipWriter
{
    public static async Task CreateEvidenceZipAsync(
        string zipPath,
        string outputDir,
        string evidenceJsonName = "evidence.json",
        string manifestName = "manifest.json",
        string reportName = "endpoint_report.md",
        string signatureName = "manifest.sig",
        CancellationToken cancellationToken = default)
    {
        if (File.Exists(zipPath))
            File.Delete(zipPath);
        await Task.Run(() =>
        {
            using var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create);
            AddEntry(archive, outputDir, evidenceJsonName);
            AddEntry(archive, outputDir, manifestName);
            AddEntry(archive, outputDir, reportName);
            var sigFull = Path.Combine(outputDir, signatureName);
            if (File.Exists(sigFull))
                archive.CreateEntryFromFile(sigFull, signatureName, CompressionLevel.Fastest);
        }, cancellationToken).ConfigureAwait(false);
    }

    private static void AddEntry(ZipArchive archive, string outputDir, string fileName)
    {
        var fullPath = Path.Combine(outputDir, fileName);
        if (!File.Exists(fullPath)) return;
        archive.CreateEntryFromFile(fullPath, fileName, CompressionLevel.Fastest);
    }
}
