namespace Nephron;

/// <summary>A scan verdict, its detections, and normalized text.</summary>
/// <remarks>Pass <see cref="SanitizedText"/> onward. Allow means no rule fired, not proven safety.</remarks>
public readonly struct ScanResult
{
	public Verdict Verdict { get; }

	public Severity HighestSeverity { get; }

	public IReadOnlyList<Detection> Detections { get; }

	/// <summary>Normalized text and the coordinate space for <see cref="Detection.Range"/>.</summary>
	public string SanitizedText { get; }

	public ScanResult(
		Verdict verdict,
		Severity highestSeverity,
		IReadOnlyList<Detection> detections,
		string sanitizedText)
	{
		Verdict = verdict;
		HighestSeverity = highestSeverity;
		Detections = detections;
		SanitizedText = sanitizedText;
	}

	public bool IsBlocked => Verdict == Verdict.Block;

	public bool IsAllowed => Verdict == Verdict.Allow;

	public bool HasDetections => Detections.Count > 0;
}
