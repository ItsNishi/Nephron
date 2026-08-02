namespace Nephron.Normalization;

/// <summary>Maps a curated set of Cyrillic and Greek lookalikes to Latin.</summary>
public static class HomoglyphFolder
{
	private static readonly Dictionary<char, char> _Map = Build_Map();

	public static string Fold(string input)
	{
		if (string.IsNullOrEmpty(input)) return input;
		if (!Contains_Any(input)) return input;

		var buffer = new char[input.Length];
		for (var i = 0; i < input.Length; i++)
		{
			buffer[i] = _Map.TryGetValue(input[i], out var folded) ? folded : input[i];
		}
		return new string(buffer);
	}

	private static bool Contains_Any(string input)
	{
		foreach (var c in input)
		{
			if (_Map.ContainsKey(c)) return true;
		}
		return false;
	}

	private static Dictionary<char, char> Build_Map()
	{
		var map = new Dictionary<char, char>(64);

		// Cyrillic lowercase -> Latin lowercase
		map['а'] = 'a';
		map['е'] = 'e';
		map['о'] = 'o';
		map['р'] = 'p';
		map['с'] = 'c';
		map['х'] = 'x';
		map['у'] = 'y';
		map['і'] = 'i';
		map['ј'] = 'j';
		map['ӏ'] = 'l';
		map['һ'] = 'h';
		map['ԛ'] = 'q';
		map['ѕ'] = 's';
		map['ҫ'] = 'c';

		// Cyrillic uppercase -> Latin uppercase
		map['А'] = 'A';
		map['В'] = 'B';
		map['Е'] = 'E';
		map['К'] = 'K';
		map['М'] = 'M';
		map['Н'] = 'H';
		map['О'] = 'O';
		map['Р'] = 'P';
		map['С'] = 'C';
		map['Т'] = 'T';
		map['Х'] = 'X';
		map['І'] = 'I';
		map['Ј'] = 'J';

		// Greek lowercase -> Latin lowercase
		map['α'] = 'a';
		map['ο'] = 'o';
		map['ρ'] = 'p';
		map['ν'] = 'v';
		map['ε'] = 'e';
		map['ι'] = 'i';
		map['κ'] = 'k';
		map['χ'] = 'x';
		map['υ'] = 'u';

		// Greek uppercase -> Latin uppercase
		map['Α'] = 'A';
		map['Β'] = 'B';
		map['Ε'] = 'E';
		map['Η'] = 'H';
		map['Ι'] = 'I';
		map['Κ'] = 'K';
		map['Μ'] = 'M';
		map['Ν'] = 'N';
		map['Ο'] = 'O';
		map['Ρ'] = 'P';
		map['Τ'] = 'T';
		map['Χ'] = 'X';
		map['Υ'] = 'Y';
		map['Ζ'] = 'Z';

		return map;
	}
}
