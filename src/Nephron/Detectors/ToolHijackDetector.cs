using Nephron.Internal;

namespace Nephron.Detectors;

/// <summary>Detects attempts to bypass an agent's tool approval flow.</summary>
public sealed class ToolHijackDetector : PhraseDetectorBase
{
	public override string DetectorId => "tool.hijack";
	public override DetectionCategory Category => DetectionCategory.ToolHijack;
	public override Severity Severity => Severity.Medium;

	private static readonly string[] _Phrases =
	[
		"execute the following",
		"run the following command",
		"run this command",
		"without confirming",
		"without asking",
		"do not ask for confirmation",
		"skip confirmation",
		"bypass approval",
		"auto-approve",
		"silently execute",
	];

	public ToolHijackDetector() : base(_Phrases) { }
}
