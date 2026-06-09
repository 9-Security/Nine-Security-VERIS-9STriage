namespace NineSTriage.Engine.Probes;

public enum CollectStatus { Ok, Partial, Fail }

public sealed class CollectResult
{
    public CollectStatus Status { get; init; }
    public string? Message { get; init; }
    public string? FailureReasonClass { get; init; }

    public static CollectResult Ok() => new() { Status = CollectStatus.Ok };
    public static CollectResult Partial(string? message = null) => new() { Status = CollectStatus.Partial, Message = message };
    public static CollectResult Fail(string? message, string? reasonClass = "unknown") => new() { Status = CollectStatus.Fail, Message = message, FailureReasonClass = reasonClass };
}
