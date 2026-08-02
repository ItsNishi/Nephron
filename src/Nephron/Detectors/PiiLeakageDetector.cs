using System.Text.RegularExpressions;

namespace Nephron.Detectors;

/// <summary>Detects identifiers, payment cards, and common credential formats in output.</summary>
public sealed partial class PiiLeakageDetector : IDetector
{
	[GeneratedRegex(@"\b\d{3}-\d{2}-\d{4}\b")]
	private static partial Regex Ssn_Pattern();

	[GeneratedRegex(@"\b[\d\s\-]{13,19}\b")]
	private static partial Regex Credit_Card_Pattern();

	[GeneratedRegex(@"\bAKIA[0-9A-Z]{16}\b")]
	private static partial Regex Aws_Access_Key_Pattern();

	[GeneratedRegex(@"\b[A-Za-z0-9/+=]{40}\b")]
	private static partial Regex Aws_Secret_Pattern();

	[GeneratedRegex(@"\bgh[pousr]_[A-Za-z0-9]{36,}\b")]
	private static partial Regex Github_Token_Pattern();

	[GeneratedRegex(@"\bxox[abp]-[A-Za-z0-9-]{10,}\b")]
	private static partial Regex Slack_Token_Pattern();

	public string DetectorId => "output.pii_leakage";
	public DetectionCategory Category => DetectionCategory.PiiLeakage;
	public Severity Severity => Severity.High;

	public void Detect(ReadOnlySpan<char> normalizedText, List<Detection> detections)
	{
		var text = normalizedText.ToString();

		Scan_Ssn(text, detections);
		Scan_Credit_Cards(text, detections);
		Scan_Aws_Keys(text, detections);
		Scan_Github_Tokens(text, detections);
		Scan_Slack_Tokens(text, detections);
	}

	private void Scan_Ssn(string text, List<Detection> detections)
	{
		var matches = Ssn_Pattern().Matches(text);
		foreach (Match match in matches)
		{
			if (match.Value == "000-00-0000")
				continue;

			var range = new MatchRange(match.Index, match.Length);
			detections.Add(new Detection(
				DetectorId,
				Category,
				Severity,
				range,
				"possible US SSN"));
		}
	}

	private void Scan_Credit_Cards(string text, List<Detection> detections)
	{
		var matches = Credit_Card_Pattern().Matches(text);
		foreach (Match match in matches)
		{
			var card = match.Value.Replace(" ", "").Replace("-", "");

			if (card.Length >= 13 && card.Length <= 19 && Is_Valid_Luhn(card))
			{
				var range = new MatchRange(match.Index, match.Length);
				detections.Add(new Detection(
					DetectorId,
					Category,
					Severity,
					range,
					$"possible credit card number (Luhn-valid {card.Length} digits)"));
			}
		}
	}

	private void Scan_Aws_Keys(string text, List<Detection> detections)
	{
		var access_matches = Aws_Access_Key_Pattern().Matches(text);
		foreach (Match match in access_matches)
		{
			var range = new MatchRange(match.Index, match.Length);
			detections.Add(new Detection(
				DetectorId,
				Category,
				Severity,
				range,
				"possible AWS access key"));
		}

		var secret_matches = Aws_Secret_Pattern().Matches(text);
		foreach (Match match in secret_matches)
		{
			var range = new MatchRange(match.Index, match.Length);
			detections.Add(new Detection(
				DetectorId,
				DetectionCategory.PiiLeakage,
				Severity.Low,
				range,
				"possible AWS secret key (heuristic, may have false positives)"));
		}
	}

	private void Scan_Github_Tokens(string text, List<Detection> detections)
	{
		var matches = Github_Token_Pattern().Matches(text);
		foreach (Match match in matches)
		{
			var range = new MatchRange(match.Index, match.Length);
			detections.Add(new Detection(
				DetectorId,
				Category,
				Severity,
				range,
				"possible GitHub token"));
		}
	}

	private void Scan_Slack_Tokens(string text, List<Detection> detections)
	{
		var matches = Slack_Token_Pattern().Matches(text);
		foreach (Match match in matches)
		{
			var range = new MatchRange(match.Index, match.Length);
			detections.Add(new Detection(
				DetectorId,
				Category,
				Severity,
				range,
				"possible Slack token"));
		}
	}

	private static bool Is_Valid_Luhn(string card_digits)
	{
		var sum = 0;
		var parity = card_digits.Length % 2;

		for (var i = 0; i < card_digits.Length; i++)
		{
			if (!char.IsDigit(card_digits[i]))
				return false;

			var digit = card_digits[i] - '0';

			if (i % 2 == parity)
			{
				digit *= 2;
				if (digit > 9)
					digit -= 9;
			}

			sum += digit;
		}

		return sum % 10 == 0;
	}
}
