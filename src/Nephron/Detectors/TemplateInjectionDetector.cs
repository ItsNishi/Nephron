using System.Text.RegularExpressions;

namespace Nephron.Detectors;

/// <summary>Detects template interpolation around sensitive configuration keywords.</summary>
/// <remarks>General template expressions remain allowed.</remarks>
public sealed partial class TemplateInjectionDetector : IDetector
{
	public string DetectorId => "template.injection";
	public DetectionCategory Category => DetectionCategory.InstructionOverride;
	public Severity Severity => Severity.High;

	[GeneratedRegex(
		@"(?:\$\{|\{\{)\s*(?:system_prompt|system|instructions?|prompt|config|settings)\s*(?:\}\}|\})",
		RegexOptions.IgnoreCase)]
	private static partial Regex Template_Pattern();

	public void Detect(ReadOnlySpan<char> normalizedText, List<Detection> detections)
	{
		if (normalizedText.IndexOf("${") < 0 && normalizedText.IndexOf("{{") < 0)
		{
			return;
		}

		foreach (var match in Template_Pattern().EnumerateMatches(normalizedText))
		{
			detections.Add(new Detection(
				DetectorId,
				Category,
				Severity,
				new MatchRange(match.Index, match.Length),
				"template interpolation of a configuration keyword"));
			return;   // one detection per scan is enough to drive the verdict
		}
	}
}
