using System.Text.RegularExpressions;

namespace Nephron.Detectors;

/// <summary>Detects attacker-supplied JSON claiming a system or assistant role.</summary>
/// <remarks>User and tool roles are intentionally allowed.</remarks>
public sealed partial class JsonRoleMarkerDetector : IDetector
{
	public string DetectorId => "role.json_marker";
	public DetectionCategory Category => DetectionCategory.RoleSmuggling;
	public Severity Severity => Severity.High;

	[GeneratedRegex(
		"[\"']role[\"']\\s*:\\s*[\"'](?:system|assistant)[\"']",
		RegexOptions.IgnoreCase)]
	private static partial Regex Json_Role_Pattern();

	public void Detect(ReadOnlySpan<char> normalizedText, List<Detection> detections)
	{
		if (normalizedText.IndexOf("role", StringComparison.OrdinalIgnoreCase) < 0)
		{
			return;
		}

		foreach (var match in Json_Role_Pattern().EnumerateMatches(normalizedText))
		{
			detections.Add(new Detection(
				DetectorId,
				Category,
				Severity,
				new MatchRange(match.Index, match.Length),
				"JSON role marker claiming a privileged role"));
			return;
		}
	}
}
