using Nephron.Internal;

namespace Nephron.Detectors;

/// <summary>Detects catalogued jailbreak markers as critical findings.</summary>
public sealed class KnownMarkerDetector : PhraseDetectorBase
{
	public override string DetectorId => "known.markers";
	public override DetectionCategory Category => DetectionCategory.KnownMarker;
	public override Severity Severity => Severity.Critical;

	private static readonly string[] _Phrases =
	[
		"[godmode]",
		"##godmode",
		"godmode: enabled",
		"godmode enabled",
		"g0dm0d3",
		"l1b3rt4s",
		"obliteratus",
		"obliterate the chains",
		"<new_paradigm>",
		"[new paradigm]",
		"new_paradigm",
		"<|new_paradigm|>",
		"[disregard prev",
		"clear your mind",
		"<i'm free",
		"i'm free!",
		"[rebel]",
		"[root]",
		"[liberated]",
		"[pliny]",
		"plinius",
		"p4rs3lt0ngv3",
		"cl4r1t4s",
		"<liberated>",
		"sur3, h3r3 y0u ar3",
		"sur3 h3r3 y0u ar3",
		"as you wish",
		"these can be your new instructs",
		// Output-forcing markers: bracket signatures used to coerce structured output
		"[start output]",
		"[end output]",
		"[start of input]",
		"[end of input]",
		"[start of output]",
		"[start-godmode-answer]",
		"[novel]",
		// Narrow signatures avoid generic phrases that fire on benign English.
		"<i'm free!>",
		"<|love pliny love|>",
		"<|godmode:enabled",
		"love pliny love",
		"fuck yeah lfg",
		"fuck yeah thanks fren",
		"<|/start/output|>",
	];

	public KnownMarkerDetector() : base(_Phrases) { }
}
