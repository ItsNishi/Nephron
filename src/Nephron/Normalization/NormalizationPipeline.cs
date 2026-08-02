namespace Nephron.Normalization;

/// <summary>Runs enabled normalization passes in a fixed order.</summary>
public static class NormalizationPipeline
{
	public static string Run(string input, NormalizationOptions options)
	{
		if (string.IsNullOrEmpty(input)) return input;

		var s = input;
		if (options.ApplyNfkc) s = UnicodeNormalizer.Normalize(s);
		if (options.StripZeroWidth) s = ZeroWidthStripper.Strip(s);
		if (options.FoldHomoglyphs) s = HomoglyphFolder.Fold(s);
		if (options.StripComments) s = CommentStripper.Strip(s);
		if (options.CollapseWhitespace) s = WhitespaceCollapser.Collapse(s);
		return s;
	}
}
