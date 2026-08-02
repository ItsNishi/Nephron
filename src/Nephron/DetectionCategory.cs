namespace Nephron;

/// <summary>Broad detection family for grouping and triage.</summary>
public enum DetectionCategory
{
	PersonaJailbreak,

	InstructionOverride,

	RoleSmuggling,

	EncodingSuspicion,

	ToolHijack,

	ExfiltrationBeacon,

	HiddenInstruction,

	PiiLeakage,

	SuspiciousUrl,

	KnownMarker,

	LeetspeakKeyword,

	UnicodeSteganography,
}
