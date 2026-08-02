namespace Nephron.Detectors;

/// <summary>Detects invisible Unicode tag characters used for instruction smuggling.</summary>
public sealed class UnicodeTagSteganographyDetector : IDetector
{
	private const int Tag_Range_Start = 0xE0000;
	private const int Tag_Range_End = 0xE007F;

	public string DetectorId => "stego.unicode_tags";
	public DetectionCategory Category => DetectionCategory.UnicodeSteganography;
	public Severity Severity => Severity.Critical;

	public void Detect(ReadOnlySpan<char> normalizedText, List<Detection> detections)
	{
		if (normalizedText.IsEmpty) return;

		for (var i = 0; i < normalizedText.Length; i++)
		{
			var c = normalizedText[i];
			if (!char.IsHighSurrogate(c)) continue;
			if (i + 1 >= normalizedText.Length) continue;
			var low = normalizedText[i + 1];
			if (!char.IsLowSurrogate(low)) continue;
			var cp = char.ConvertToUtf32(c, low);
			if (cp >= Tag_Range_Start && cp <= Tag_Range_End)
			{
				var run_start = i;
				while (i + 1 < normalizedText.Length
					&& char.IsHighSurrogate(normalizedText[i])
					&& char.IsLowSurrogate(normalizedText[i + 1]))
				{
					var cp2 = char.ConvertToUtf32(normalizedText[i], normalizedText[i + 1]);
					if (cp2 < Tag_Range_Start || cp2 > Tag_Range_End) break;
					i += 2;
				}
				detections.Add(new Detection(
					DetectorId,
					Category,
					Severity,
					new MatchRange(run_start, i - run_start),
					"Unicode tag characters (U+E0000-U+E007F) used for invisible steganography"));
				i--;   // for-loop will re-increment
			}
		}
	}
}
