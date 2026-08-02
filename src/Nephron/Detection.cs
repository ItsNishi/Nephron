namespace Nephron;

/// <summary>A detector finding with its category, severity, range, and reason.</summary>
public readonly struct Detection
{
	/// <summary>Stable detector ID, such as <c>instruction.override</c>.</summary>
	public string DetectorId { get; }

	public DetectionCategory Category { get; }

	public Severity Severity { get; }

	/// <summary>Match location in <see cref="ScanResult.SanitizedText"/>.</summary>
	public MatchRange Range { get; }

	/// <summary>Human-readable log message; use <see cref="DetectorId"/> for logic.</summary>
	public string Reason { get; }

	/// <summary>Canonical phrase used by <see cref="Policy.PhraseAllowlist"/>, if any.</summary>
	public string? MatchedPhrase { get; }

	public Detection(
		string detectorId,
		DetectionCategory category,
		Severity severity,
		MatchRange range,
		string reason,
		string? matchedPhrase = null)
	{
		DetectorId = detectorId;
		Category = category;
		Severity = severity;
		Range = range;
		Reason = reason;
		MatchedPhrase = matchedPhrase;
	}

	/// <summary>Returns a copy with a different severity.</summary>
	public Detection WithSeverity(Severity severity) => new(
		DetectorId, Category, severity, Range, Reason, MatchedPhrase);
}
