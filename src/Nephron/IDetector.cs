namespace Nephron;

/// <summary>A stateless detection rule registered by <see cref="FilterOptions"/>.</summary>
/// <remarks>Implementations should not allocate when input produces no findings.</remarks>
public interface IDetector
{
	/// <summary>Stable configuration ID, such as <c>instruction.override</c>.</summary>
	/// <remarks>Renaming an ID is a breaking change because unknown policy IDs are ignored.</remarks>
	string DetectorId { get; }

	DetectionCategory Category { get; }

	Severity Severity { get; }

	/// <summary>Appends findings from normalized text to the supplied collection.</summary>
	void Detect(ReadOnlySpan<char> normalizedText, List<Detection> detections);
}
