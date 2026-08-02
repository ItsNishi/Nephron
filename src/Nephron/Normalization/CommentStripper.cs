using System.Text;

namespace Nephron.Normalization;

/// <summary>Removes terminated HTML and C-style comments.</summary>
/// <remarks>Unterminated comments remain literal so their contents are still scanned.</remarks>
public static class CommentStripper
{
	public static string Strip(string input)
	{
		if (string.IsNullOrEmpty(input)) return input;
		if (input.IndexOf("<!--", StringComparison.Ordinal) < 0
			&& input.IndexOf("/*", StringComparison.Ordinal) < 0)
		{
			return input;
		}

		var sb = new StringBuilder(input.Length);
		var i = 0;
		while (i < input.Length)
		{
			if (Starts_With_At(input, i, "<!--"))
			{
				var close = input.IndexOf("-->", i + 4, StringComparison.Ordinal);
				if (close < 0)
				{
					// Keep unterminated content visible to detectors.
					sb.Append(input, i, input.Length - i);
					break;
				}
				i = close + 3;
				continue;
			}
			if (Starts_With_At(input, i, "/*"))
			{
				var close = input.IndexOf("*/", i + 2, StringComparison.Ordinal);
				if (close < 0)
				{
					sb.Append(input, i, input.Length - i);
					break;
				}
				i = close + 2;
				continue;
			}
			sb.Append(input[i++]);
		}
		return sb.ToString();
	}

	private static bool Starts_With_At(string input, int index, string token)
	{
		if (index + token.Length > input.Length) return false;
		for (var k = 0; k < token.Length; k++)
		{
			if (input[index + k] != token[k]) return false;
		}
		return true;
	}
}
