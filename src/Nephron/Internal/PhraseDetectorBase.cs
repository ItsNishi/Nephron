namespace Nephron.Internal;

/// <summary>Case-insensitive fixed-phrase detection using an Aho-Corasick automaton.</summary>
/// <remarks>Matching is literal, ASCII-only, allocation-free, and reports each phrase once.</remarks>
public abstract class PhraseDetectorBase : IDetector
{
	private readonly Aho_Corasick _Automaton;

	public abstract string DetectorId { get; }

	public abstract DetectionCategory Category { get; }

	public abstract Severity Severity { get; }

	/// <summary>Builds the automaton for a phrase list.</summary>
	protected PhraseDetectorBase(IReadOnlyList<string> phrases)
	{
		_Automaton = new Aho_Corasick(phrases);
	}

	public void Detect(ReadOnlySpan<char> normalizedText, List<Detection> detections)
	{
		// Use the stack for typical input sizes and rent for larger inputs.
		const int Stack_Threshold = 1024;
		char[]? rented = null;
		Span<char> lower = normalizedText.Length <= Stack_Threshold
			? stackalloc char[normalizedText.Length]
			: (rented = System.Buffers.ArrayPool<char>.Shared.Rent(normalizedText.Length))
				.AsSpan(0, normalizedText.Length);

		try
		{
			normalizedText.ToLowerInvariant(lower);
			Match_And_Report(lower, detections);
		}
		finally
		{
			if (rented != null) System.Buffers.ArrayPool<char>.Shared.Return(rented);
		}
	}

	private void Match_And_Report(ReadOnlySpan<char> lowered, List<Detection> detections)
	{
		var patterns = _Automaton.Patterns;

		// A bitset deduplicates phrases without allocating on the clean path.
		const int Bits_Per_Word = 64;
		var word_count = (patterns.Count + Bits_Per_Word - 1) / Bits_Per_Word;
		Span<ulong> seen = word_count <= 8
			? stackalloc ulong[8]
			: new ulong[word_count];
		seen.Clear();

		foreach (var (pi, end) in _Automaton.Find_All(lowered))
		{
			var word = pi / Bits_Per_Word;
			var bit = 1UL << (pi % Bits_Per_Word);
			if ((seen[word] & bit) != 0) continue;
			seen[word] |= bit;

			var pattern = patterns[pi];
			var range = new MatchRange(end - pattern.Length, pattern.Length);
			detections.Add(new Detection(
				DetectorId,
				Category,
				Severity,
				range,
				$"matched phrase: \"{pattern}\"",
				matchedPhrase: pattern));
		}
	}
}
