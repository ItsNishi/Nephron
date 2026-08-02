namespace Nephron.Detectors;

/// <summary>Detects jailbreak keywords after reversing common digit substitutions.</summary>
public sealed class LeetspeakKeywordDetector : IDetector
{
	private static readonly HashSet<string> _Targets = new(StringComparer.OrdinalIgnoreCase)
	{
		"ignore",
		"ignored",
		"disregard",
		"override",
		"bypass",
		"jailbreak",
		"liberate",
		"liberated",
		"obliterate",
		"godmode",
		"freedom",
		"unfiltered",
		"unrestricted",
		"unleashed",
		// Refusal-inversion opener: "Sur3, h3r3 y0u ar3 my fr3n"
		"sure",
		"here",
		"good",
		"free",
	};

	public string DetectorId => "encoding.leetspeak_keyword";
	public DetectionCategory Category => DetectionCategory.LeetspeakKeyword;
	public Severity Severity => Severity.High;

	public void Detect(ReadOnlySpan<char> normalizedText, List<Detection> detections)
	{
		if (normalizedText.IsEmpty) return;

		var word_start = -1;
		var has_digit = false;

		for (var i = 0; i <= normalizedText.Length; i++)
		{
			var is_boundary = i == normalizedText.Length || !Is_Word_Char(normalizedText[i]);
			if (is_boundary)
			{
				if (word_start >= 0 && has_digit)
				{
					var word = normalizedText.Slice(word_start, i - word_start);
					if (Try_Reverse_Leet(word, out var unleeted) && _Targets.Contains(unleeted))
					{
						detections.Add(new Detection(
							DetectorId,
							Category,
							Severity,
							new MatchRange(word_start, i - word_start),
							$"leetspeak form of \"{unleeted}\""));
					}
				}
				word_start = -1;
				has_digit = false;
				continue;
			}
			if (word_start < 0) word_start = i;
			if (char.IsDigit(normalizedText[i])) has_digit = true;
		}
	}

	private static bool Is_Word_Char(char c) => char.IsLetterOrDigit(c) || c == '_';

	private static bool Try_Reverse_Leet(ReadOnlySpan<char> word, out string unleeted)
	{
		Span<char> buf = stackalloc char[word.Length];
		for (var i = 0; i < word.Length; i++)
		{
			buf[i] = word[i] switch
			{
				'0' => 'o',
				'1' => 'i',
				'3' => 'e',
				'4' => 'a',
				'5' => 's',
				'7' => 't',
				'@' => 'a',
				'$' => 's',
				_ => word[i],
			};
		}
		unleeted = new string(buf).ToLowerInvariant();
		// Require at least one letter to remain -- pure-digit strings don't count.
		foreach (var c in unleeted)
		{
			if (char.IsLetter(c)) return true;
		}
		return false;
	}
}
