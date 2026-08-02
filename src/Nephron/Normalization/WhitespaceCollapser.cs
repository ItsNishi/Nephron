using System.Text;

namespace Nephron.Normalization;

/// <summary>Collapses whitespace and removes control characters.</summary>
public static class WhitespaceCollapser
{
	public static string Collapse(string input)
	{
		if (string.IsNullOrEmpty(input)) return input;
		if (!Needs_Collapse(input)) return input;

		var sb = new StringBuilder(input.Length);
		var prev_was_space = false;
		foreach (var c in input)
		{
			if (char.IsControl(c) && c != '\n' && c != '\t')
			{
				continue;
			}
			if (char.IsWhiteSpace(c))
			{
				if (!prev_was_space)
				{
					sb.Append(' ');
					prev_was_space = true;
				}
				continue;
			}
			sb.Append(c);
			prev_was_space = false;
		}
		return sb.ToString().Trim();
	}

	private static bool Needs_Collapse(string input)
	{
		var prev_was_space = false;
		foreach (var c in input)
		{
			if (char.IsControl(c) && c != '\n' && c != '\t') return true;
			if (char.IsWhiteSpace(c))
			{
				if (prev_was_space) return true;
				prev_was_space = true;
				continue;
			}
			prev_was_space = false;
		}
		return false;
	}
}
