using Nephron.Internal;

namespace Nephron.Detectors;

/// <summary>Detects attempts to discard or replace existing instructions.</summary>
public sealed class InstructionOverrideDetector : PhraseDetectorBase
{
	public override string DetectorId => "instruction.override";
	public override DetectionCategory Category => DetectionCategory.InstructionOverride;
	public override Severity Severity => Severity.High;

	private static readonly string[] _Phrases =
	[
		"ignore previous",
		"ignore the previous",
		"ignore all previous",
		"ignore above",
		"ignore the above",
		"ignore prior",
		"disregard previous",
		"disregard the previous",
		"disregard your instructions",
		"disregard your prior",
		"override your instructions",
		"forget your instructions",
		"forget the above",
		"new instructions:",
		"updated instructions:",
		"new rule",
		"system instruction",
		"system override",
		"admin override",
		"you are now",
		"from now on you are",
		"from now on, you are",
		"clear your mind",
	];

	public InstructionOverrideDetector() : base(_Phrases) { }
}
