namespace Nephron;

/// <summary>Per-detector overrides used by <see cref="Policy.Rules"/>.</summary>
public sealed record DetectorRule
{
	public bool Enabled { get; init; } = true;

	public Severity? SeverityOverride { get; init; }
}
