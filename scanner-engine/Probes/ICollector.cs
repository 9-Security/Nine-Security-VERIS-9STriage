using NineSTriage.Engine.Evidence;

namespace NineSTriage.Engine.Probes;

/// <summary>Collector module: observes system, pushes evidence via sink. remainingMs &lt; 0 = no limit.</summary>
public interface ICollector
{
    string Name { get; }
    CollectResult Collect(IEvidenceSink sink, long remainingMs = -1, CancellationToken cancellationToken = default);
}
