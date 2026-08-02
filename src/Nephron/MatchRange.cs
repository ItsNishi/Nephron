namespace Nephron;

/// <summary>Half-open match range in <see cref="ScanResult.SanitizedText"/>.</summary>
public readonly struct MatchRange
{
	public int Start { get; }

	public int Length { get; }

	public int End => Start + Length;

	public MatchRange(int start, int length)
	{
		Start = start;
		Length = length;
	}

	public override string ToString() => $"[{Start}..{End})";
}
