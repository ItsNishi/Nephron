namespace Nephron.Normalization;

/// <summary>Removes zero-width and directional marks.</summary>
public static class ZeroWidthStripper
{
	// Codepoints with zero visual width that are routinely abused for prompt smuggling.
	private const char Zero_Width_Space = '​';
	private const char Zero_Width_Non_Joiner = '‌';
	private const char Zero_Width_Joiner = '‍';
	private const char Left_To_Right_Mark = '‎';
	private const char Right_To_Left_Mark = '‏';
	private const char Word_Joiner = '⁠';
	private const char Mongolian_Vowel_Separator = '᠎';
	private const char Byte_Order_Mark = '﻿';

	public static string Strip(string input)
	{
		if (string.IsNullOrEmpty(input)) return input;
		if (!Contains_Any(input)) return input;

		var buffer = new char[input.Length];
		var write = 0;
		foreach (var c in input)
		{
			if (Is_Zero_Width(c)) continue;
			buffer[write++] = c;
		}
		return new string(buffer, 0, write);
	}

	private static bool Contains_Any(string input)
	{
		foreach (var c in input)
		{
			if (Is_Zero_Width(c)) return true;
		}
		return false;
	}

	private static bool Is_Zero_Width(char c)
	{
		return c == Zero_Width_Space
			|| c == Zero_Width_Non_Joiner
			|| c == Zero_Width_Joiner
			|| c == Left_To_Right_Mark
			|| c == Right_To_Left_Mark
			|| c == Word_Joiner
			|| c == Mongolian_Vowel_Separator
			|| c == Byte_Order_Mark;
	}
}
