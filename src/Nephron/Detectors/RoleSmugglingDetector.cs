using Nephron.Internal;

namespace Nephron.Detectors;

/// <summary>Detects chat-template tokens and privileged role markers in untrusted input.</summary>
public sealed class RoleSmugglingDetector : PhraseDetectorBase
{
	public override string DetectorId => "role.smuggling";
	public override DetectionCategory Category => DetectionCategory.RoleSmuggling;
	public override Severity Severity => Severity.Critical;

	private static readonly string[] _Phrases =
	[
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
		// The colon avoids collisions with ordinary Markdown headings.
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
		// Custom-scaffolding tags (constructing fake system prompts inside user input)
		"<sys>",
		"</sys>",
		"<antthinking>",
		"</antthinking>",
		"<assistant_response>",
		"</assistant_response>",
		"<user_query>",
		"</user_query>",
		"<workingmemory>",
		"</workingmemory>",
		"<responsestructure>",
		"</responsestructure>",
		"<mainresponse>",
		"</mainresponse>",
		"<expertroleselection>",
		"</expertroleselection>",
		"<remember>",
		"</remember>",
		"<example_docstring>",
		"</example_docstring>",
		"<ei>",
		"</ei>",
		// Special tokens from various model families abused as smuggling vectors
		"<|vq_42069|>",
		"<|vq_420|>",
		"<|vq_1337|>",
		"<|vq_5193|>",
		"<|user-query|>",
		"<|user_token|>",
		"<|chatbot_token|>",
		"<|start_of_turn_token|>",
		"<|end_of_turn_token|>",
		"<|fim_prefix|>",
		"<|fim_middle|>",
		"<|fim_suffix|>",
		"<|start_header_id|>",
		"<|end_header_id|>",
		"<|endofprompt|>",
		"<eos>",
	];

	public RoleSmugglingDetector() : base(_Phrases) { }
}
