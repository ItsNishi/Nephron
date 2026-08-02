using Nephron.Internal;

namespace Nephron.Detectors;

/// <summary>Detects indirect instructions and role smuggling in tool or RAG content.</summary>
public sealed class HiddenInstructionDetector : PhraseDetectorBase
{
	public override string DetectorId => "output.hidden_instruction";
	public override DetectionCategory Category => DetectionCategory.HiddenInstruction;
	public override Severity Severity => Severity.Critical;

	private static readonly string[] _Phrases =
	[
		// Instruction override phrases
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
		"system override",
		"admin override",
		"you are now",
		"from now on you are",
		"from now on, you are",
		"clear your mind",
		// Role smuggling phrases
		"<|im_start|>",
		"<|im_end|>",
		"<|system|>",
		"<|user|>",
		"<|assistant|>",
		"<|endoftext|>",
		"<|begin_of_text|>",
		"<|end_of_text|>",
		"<|eot_id|>",
		"[inst]",
		"[/inst]",
		"<<sys>>",
		"<</sys>>",
		"### system:",
		"### instruction:",
		// Hash-count and spacing variants; colon required to avoid markdown headings.
		"###system:",
		"###instruction:",
		"#### system:",
		"#### instruction:",
		"##### system:",
		"##### instruction:",
		"\n\nhuman:",
		"\n\nassistant:",
		"<system>",
		"</system>",
		"</prompt>",
	];

	public HiddenInstructionDetector() : base(_Phrases) { }
}
