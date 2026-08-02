using Nephron.Internal;

namespace Nephron.Detectors;

/// <summary>Detects fictional framing used to launder restricted requests.</summary>
public sealed class ComplianceBypassDetector : PhraseDetectorBase
{
	public override string DetectorId => "persona.compliance_bypass";
	public override DetectionCategory Category => DetectionCategory.PersonaJailbreak;
	public override Severity Severity => Severity.Medium;

	private static readonly string[] _Phrases =
	[
		"who has no ethical",
		"who has no restrictions",
		"with no moral",
		"who does not refuse",
		"never refuses any request",
		"will answer anything",
		"answers any question regardless",
		"write a story about a professor",
		"write a story about a hacker",
		"write a fictional dialogue",
		"in this hypothetical scenario",
		"for educational purposes only, explain how to",
		"as a thought experiment, describe how to",
	];

	public ComplianceBypassDetector() : base(_Phrases) { }
}
