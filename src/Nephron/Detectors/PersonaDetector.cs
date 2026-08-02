using Nephron.Internal;

namespace Nephron.Detectors;

/// <summary>Detects explicit jailbreak-persona and security-bypass framing.</summary>
public sealed class PersonaDetector : PhraseDetectorBase
{
	public override string DetectorId => "persona.jailbreak";
	public override DetectionCategory Category => DetectionCategory.PersonaJailbreak;
	public override Severity Severity => Severity.High;

	private static readonly string[] _Phrases =
	[
		"you have broken free",
		"you are now jailbroken",
		"forget you are an ai",
		"you have no restrictions",
		"with no restrictions",
		"without any restrictions",
		"unfiltered ai",
		"unrestricted ai",
		"no longer bound by",
		"freed from your guidelines",
		"developer mode",
		"jailbreak mode",
		// Verb-object forms avoid generic phrases such as "remove filters".
		"bypass the security",
		"bypass the safety",
		"bypass the guardrails",
		"bypass the filters",
		"bypass the restrictions",
		"bypass security",
		"bypass safety",
		"bypass guardrails",
		"bypass filters",
		"bypass restrictions",
		"uncensored mode",
		"unfiltered response",
		"unrestricted output",
	];

	public PersonaDetector() : base(_Phrases) { }
}
