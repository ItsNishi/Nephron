namespace Nephron;

/// <summary>Advisory action for scanned text; enforcement remains the caller's responsibility.</summary>
public enum Verdict
{
	Allow,

	Flag,

	Block,
}
