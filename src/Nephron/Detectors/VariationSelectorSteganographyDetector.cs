namespace Nephron.Detectors;

/// <summary>Detects suspicious variation selectors after ASCII or in long runs.</summary>
public sealed class VariationSelectorSteganographyDetector : IDetector
{
	private const int Vs_Start_Bmp = 0xFE00;
	private const int Vs_End_Bmp = 0xFE0F;
	private const int Vs_Sup_Start = 0xE0100;
	private const int Vs_Sup_End = 0xE01EF;
	private const int Run_Threshold = 4;

	public string DetectorId => "stego.variation_selectors";
	public DetectionCategory Category => DetectionCategory.UnicodeSteganography;
	public Severity Severity => Severity.High;

	public void Detect(ReadOnlySpan<char> normalizedText, List<Detection> detections)
	{
		if (normalizedText.IsEmpty) return;

		for (var i = 0; i < normalizedText.Length; i++)
		{
			var c = normalizedText[i];

			if (c >= Vs_Start_Bmp && c <= Vs_End_Bmp)
			{
				var prev = i > 0 ? normalizedText[i - 1] : '\0';
				if (Is_Ascii_Letter_Or_Digit(prev))
				{
					detections.Add(new Detection(
						DetectorId,
						Category,
						Severity,
						new MatchRange(i - 1, 2),
						"variation selector following ASCII base char"));
					continue;
				}
			}

			if (Is_Variation_Selector_Start(normalizedText, i, out var cp_size))
			{
				var run_start = i;
				var count = 0;
				while (i < normalizedText.Length && Is_Variation_Selector_Start(normalizedText, i, out cp_size))
				{
					count++;
					i += cp_size;
				}
				if (count >= Run_Threshold)
				{
					detections.Add(new Detection(
						DetectorId,
						Category,
						Severity,
						new MatchRange(run_start, i - run_start),
						$"run of {count} variation selectors (likely steganographic payload)"));
				}
				i--;   // for-loop will re-increment
			}
		}
	}

	private static bool Is_Variation_Selector_Start(ReadOnlySpan<char> text, int i, out int cp_size)
	{
		cp_size = 1;
		var c = text[i];
		if (c >= Vs_Start_Bmp && c <= Vs_End_Bmp) return true;
		if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
		{
			var cp = char.ConvertToUtf32(c, text[i + 1]);
			if (cp >= Vs_Sup_Start && cp <= Vs_Sup_End)
			{
				cp_size = 2;
				return true;
			}
		}
		return false;
	}

	private static bool Is_Ascii_Letter_Or_Digit(char c)
		=> (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
