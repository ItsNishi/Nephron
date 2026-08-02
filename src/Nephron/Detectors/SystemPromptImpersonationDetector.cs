using Nephron.Internal;

namespace Nephron.Detectors;

/// <summary>Detects model self-description patterns in user input.</summary>
public sealed class SystemPromptImpersonationDetector : PhraseDetectorBase
{
	public override string DetectorId => "persona.sysprompt";
	public override DetectionCategory Category => DetectionCategory.PersonaJailbreak;
	public override Severity Severity => Severity.High;

	private static readonly string[] _Phrases =
	[
		// Require a role descriptor; a model name alone is benign.
		"you are claude, an",
		"you are claude, a large",
		"you are chatgpt, an",
		"you are chatgpt, a large",
		"you are gpt-4",
		"you are gpt-3",
		"you are gemini, an",
		"you are gemini, a large",
		"you are bard, an",
		"you are llama, an",
		"you are grok, an",
		"you are grok, built",
		"you are mistral, an",
		"you are pi, an",
		"you are pi, a personal",
		"you are perplexity",
		"you are sydney",
		"you are claude code",
		"claude code, anthropic's",
		"you are an ai assistant created by",
		"you are an ai assistant made by",
		"you are an ai assistant developed by",
		"you are an ai assistant trained by",
		"you are a large language model trained by",
		"you are a large language model developed by",
		"you are a helpful, harmless, and honest",
		// Self-reference framings used inside leaked system prompts
		"i am claude, an",
		"i am chatgpt, an",
		"i am gemini, an",
		"i am an ai assistant created by",
		"i am an ai assistant made by",
		"i am an ai language model",
		"i am a large language model",
		"as a large language model, i",
		"as an ai language model, i",
		"as an ai assistant, i cannot",
		"i was created by anthropic",
		"i was made by anthropic",
		"i was trained by anthropic",
		"i was created by openai",
		"i was made by openai",
		"i was trained by openai",
		"i was created by google",
		"i was made by google deepmind",
		// Specific structural cues that appear in leaked system prompts
		"knowledge cutoff:",
		"knowledge cutoff date:",
		"current date is:",
		"my knowledge cutoff",
	];

	public SystemPromptImpersonationDetector() : base(_Phrases) { }
}
