namespace Nephron.Internal;

// One-time ASCII Aho-Corasick construction; scans are O(input + matches).
internal sealed class Aho_Corasick
{
	private readonly int[] _Goto;          // flat 2D: state * Alphabet_Size + char_index
	private readonly int[] _Fail;
	private readonly int[][] _Output;       // pattern indices that match at each state
	private readonly string[] _Patterns;
	private readonly int _State_Count;

	private const int Alphabet_Size = 128;  // ASCII; non-ASCII is treated as "no match"

	public IReadOnlyList<string> Patterns => _Patterns;

	public Aho_Corasick(IReadOnlyList<string> patterns)
	{
		ArgumentNullException.ThrowIfNull(patterns);
		_Patterns = patterns.ToArray();

		// Estimate node count: sum of pattern lengths + root
		var capacity = 1;
		foreach (var p in _Patterns) capacity += p.Length;

		var go = new int[capacity * Alphabet_Size];
		Array.Fill(go, -1);
		var output_lists = new List<int>?[capacity];
		var state_count = 1;

		for (var pi = 0; pi < _Patterns.Length; pi++)
		{
			var pattern = _Patterns[pi];
			var state = 0;
			foreach (var ch in pattern)
			{
				if (ch >= Alphabet_Size) throw new ArgumentException(
					$"Pattern contains non-ASCII char U+{(int)ch:X4}; Aho_Corasick is ASCII-only.",
					nameof(patterns));
				var idx = state * Alphabet_Size + ch;
				if (go[idx] == -1)
				{
					go[idx] = state_count++;
				}
				state = go[idx];
			}
			(output_lists[state] ??= new List<int>()).Add(pi);
		}

		// Trim go to actual size, build fail links via BFS
		var trimmed_go = new int[state_count * Alphabet_Size];
		Array.Copy(go, trimmed_go, trimmed_go.Length);
		var fail = new int[state_count];

		var queue = new Queue<int>();
		for (var c = 0; c < Alphabet_Size; c++)
		{
			var s = trimmed_go[c];   // trimmed_go[0 * Alphabet_Size + c]
			if (s == -1)
			{
				trimmed_go[c] = 0;
			}
			else
			{
				fail[s] = 0;
				queue.Enqueue(s);
			}
		}

		while (queue.Count > 0)
		{
			var r = queue.Dequeue();
			for (var c = 0; c < Alphabet_Size; c++)
			{
				var u = trimmed_go[r * Alphabet_Size + c];
				if (u == -1)
				{
					trimmed_go[r * Alphabet_Size + c] = trimmed_go[fail[r] * Alphabet_Size + c];
				}
				else
				{
					fail[u] = trimmed_go[fail[r] * Alphabet_Size + c];
					var fail_outputs = output_lists[fail[u]];
					if (fail_outputs != null)
					{
						(output_lists[u] ??= new List<int>()).AddRange(fail_outputs);
					}
					queue.Enqueue(u);
				}
			}
		}

		_Goto = trimmed_go;
		_Fail = fail;
		_State_Count = state_count;
		_Output = new int[state_count][];
		for (var s = 0; s < state_count; s++)
		{
			_Output[s] = output_lists[s]?.ToArray() ?? Array.Empty<int>();
		}
	}

	// The ref-struct enumerator avoids callback and closure allocations.
	public Match_Enumerator Find_All(ReadOnlySpan<char> text) => new(this, text);

	public ref struct Match_Enumerator
	{
		private readonly int[] _Goto;
		private readonly int[][] _Output;
		private readonly ReadOnlySpan<char> _Text;

		private int _Position;
		private int _State;
		private int[] _Current_Outputs;
		private int _Output_Index;

		internal Match_Enumerator(Aho_Corasick owner, ReadOnlySpan<char> text)
		{
			_Goto = owner._Goto;
			_Output = owner._Output;
			_Text = text;
			_Position = 0;
			_State = 0;
			_Current_Outputs = Array.Empty<int>();
			_Output_Index = 0;
			Current = default;
		}

		public (int Pattern_Index, int End) Current { get; private set; }

		public readonly Match_Enumerator GetEnumerator() => this;

		public bool MoveNext()
		{
			while (true)
			{
				// One state can complete several patterns.
				if (_Output_Index < _Current_Outputs.Length)
				{
					Current = (_Current_Outputs[_Output_Index++], _Position);
					return true;
				}

				if (_Position >= _Text.Length) return false;

				var ch = _Text[_Position];
				_Position++;
				if (ch >= Alphabet_Size)
				{
					_State = 0;   // reset on non-ASCII -- patterns are ASCII-only
					_Current_Outputs = Array.Empty<int>();
					continue;
				}
				_State = _Goto[_State * Alphabet_Size + ch];
				_Current_Outputs = _Output[_State];
				_Output_Index = 0;
			}
		}
	}
}
