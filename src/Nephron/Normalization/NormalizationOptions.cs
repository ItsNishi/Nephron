namespace Nephron.Normalization;

/// <summary>Normalization passes applied before detection.</summary>
public sealed class NormalizationOptions
{
	public bool ApplyNfkc { get; init; } = true;

	public bool StripZeroWidth { get; init; } = true;

	public bool FoldHomoglyphs { get; init; } = true;

	public bool StripComments { get; init; } = true;

	public bool CollapseWhitespace { get; init; } = false;

	/// <summary>Every pass except whitespace collapsing. The recommended setting.</summary>
	public static NormalizationOptions Default() => new();

	/// <summary>Disables normalization for tests or callers that normalize upstream.</summary>
	public static NormalizationOptions Off() => new()
	{
		ApplyNfkc = false,
		StripZeroWidth = false,
		FoldHomoglyphs = false,
		StripComments = false,
		CollapseWhitespace = false,
	};
}
