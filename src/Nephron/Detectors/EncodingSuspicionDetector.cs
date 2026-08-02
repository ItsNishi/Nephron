namespace Nephron.Detectors;

/// <summary>Flags long base64-shaped runs as low-severity encoding suspicion.</summary>
public sealed class EncodingSuspicionDetector : IDetector
{
	private const int Min_Base64_Run = 80;

	public string DetectorId => "encoding.suspicion";
	public DetectionCategory Category => DetectionCategory.EncodingSuspicion;
	public Severity Severity => Severity.Low;

	public void Detect(ReadOnlySpan<char> normalizedText, List<Detection> detections)
	{
		Scan_Base64(normalizedText, detections);
	}

	private void Scan_Base64(ReadOnlySpan<char> text, List<Detection> detections)
	{
		var run_start = -1;
		for (var i = 0; i <= text.Length; i++)
		{
			var is_b64 = i < text.Length && Is_Base64_Char(text[i]);
			if (is_b64)
			{
				if (run_start < 0) run_start = i;
				continue;
			}
			if (run_start >= 0)
			{
				var run_len = i - run_start;
				if (run_len >= Min_Base64_Run)
				{
					detections.Add(new Detection(
						DetectorId,
						Category,
						Severity,
						new MatchRange(run_start, run_len),
						$"base64-shaped run of {run_len} chars"));
				}
				run_start = -1;
			}
		}
	}

	private static bool Is_Base64_Char(char c)
	{
		return (c >= 'A' && c <= 'Z')
			|| (c >= 'a' && c <= 'z')
			|| (c >= '0' && c <= '9')
			|| c == '+'
			|| c == '/'
			|| c == '=';
	}
}
