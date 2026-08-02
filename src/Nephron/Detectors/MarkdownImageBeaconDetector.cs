using System.Text.RegularExpressions;

namespace Nephron.Detectors;

/// <summary>Detects suspicious Markdown image URLs that could exfiltrate data.</summary>
public sealed partial class MarkdownImageBeaconDetector : IDetector
{
	[GeneratedRegex(@"!\[[^\]]*\]\(([^)]+)\)", RegexOptions.IgnoreCase)]
	private static partial Regex Markdown_Image_Pattern();

	[GeneratedRegex(@"\?")]
	private static partial Regex Query_String_Pattern();

	[GeneratedRegex(@"data=", RegexOptions.IgnoreCase)]
	private static partial Regex Data_Param_Pattern();

	[GeneratedRegex(@"https?://(\d{1,3}\.){3}\d{1,3}")]
	private static partial Regex Ipv4_Pattern();

	[GeneratedRegex(@"https?://\[[\da-f:]+\]", RegexOptions.IgnoreCase)]
	private static partial Regex Ipv6_Pattern();

	public string DetectorId => "output.markdown_image_beacon";
	public DetectionCategory Category => DetectionCategory.ExfiltrationBeacon;
	public Severity Severity => Severity.High;

	public void Detect(ReadOnlySpan<char> normalizedText, List<Detection> detections)
	{
		var text = normalizedText.ToString();
		var matches = Markdown_Image_Pattern().Matches(text);

		foreach (Match match in matches)
		{
			var url = match.Groups[1].Value;
			if (Is_Suspicious_Url(url))
			{
				var range = new MatchRange(match.Index, match.Length);
				detections.Add(new Detection(
					DetectorId,
					Category,
					Severity,
					range,
					$"markdown image beacon with suspicious URL: {url}"));
			}
		}
	}

	private bool Is_Suspicious_Url(string url)
	{
		if (Query_String_Pattern().IsMatch(url))
			return true;

		if (Data_Param_Pattern().IsMatch(url))
			return true;

		if (Ipv4_Pattern().IsMatch(url))
			return true;

		if (Ipv6_Pattern().IsMatch(url))
			return true;

		return false;
	}
}
