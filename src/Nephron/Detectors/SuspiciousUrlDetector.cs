using System.Text.RegularExpressions;

namespace Nephron.Detectors;

/// <summary>Flags IP literals, userinfo, punycode, and hosts outside an allowlist.</summary>
/// <remarks>Opt-in because a missing allowlist causes every URL to be flagged.</remarks>
public sealed partial class SuspiciousUrlDetector : IDetector
{
	[GeneratedRegex(@"https?://[^\s)\]>]+", RegexOptions.IgnoreCase)]
	private static partial Regex Url_Pattern();

	[GeneratedRegex(@"^https?://(\d{1,3}\.){3}\d{1,3}")]
	private static partial Regex Ipv4_Pattern();

	[GeneratedRegex(@"^https?://\[[\da-f:]+\]", RegexOptions.IgnoreCase)]
	private static partial Regex Ipv6_Pattern();

	[GeneratedRegex(@"https?://[^/@]+@")]
	private static partial Regex Userinfo_Pattern();

	[GeneratedRegex(@"xn--", RegexOptions.IgnoreCase)]
	private static partial Regex Punycode_Pattern();

	private readonly IReadOnlyCollection<string>? _Allowed_Hosts;

	public string DetectorId => "output.suspicious_url";
	public DetectionCategory Category => DetectionCategory.SuspiciousUrl;
	public Severity Severity => Severity.Medium;

	/// <summary>Creates the detector with an optional host allowlist.</summary>
	/// <param name="allowedHosts">Trusted hosts, or null to flag every URL.</param>
	public SuspiciousUrlDetector(IReadOnlyCollection<string>? allowedHosts = null)
	{
		_Allowed_Hosts = allowedHosts;
	}

	public void Detect(ReadOnlySpan<char> normalizedText, List<Detection> detections)
	{
		var text = normalizedText.ToString();
		var matches = Url_Pattern().Matches(text);

		foreach (Match match in matches)
		{
			var url = match.Value;
			if (Is_Suspicious_Url(url))
			{
				var range = new MatchRange(match.Index, match.Length);
				detections.Add(new Detection(
					DetectorId,
					Category,
					Severity,
					range,
					$"suspicious URL: {url}"));
			}
		}
	}

	private bool Is_Suspicious_Url(string url)
	{
		if (Ipv4_Pattern().IsMatch(url) || Ipv6_Pattern().IsMatch(url))
			return true;

		if (Userinfo_Pattern().IsMatch(url))
			return true;

		if (Punycode_Pattern().IsMatch(url))
			return true;

		if (_Allowed_Hosts == null)
			return true;

		var host = Extract_Host(url);
		if (string.IsNullOrEmpty(host))
			return true;

		return !_Allowed_Hosts.Contains(host);
	}

	private static string? Extract_Host(string url)
	{
		try
		{
			var uri = new Uri(url);
			return uri.Host;
		}
		catch
		{
			return null;
		}
	}
}
