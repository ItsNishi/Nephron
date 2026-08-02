using Nephron.Internal;
using Xunit;

namespace Nephron.Tests;

public sealed class Aho_Corasick_Tests
{
	[Fact]
	public void Finds_Single_Pattern()
	{
		var ac = new Aho_Corasick(new[] { "ignore" });
		var hits = new List<(int, int)>();
		foreach (var (pi, end) in ac.Find_All("please ignore everything".AsSpan()))
		{
			hits.Add((pi, end));
		}
		Assert.Single(hits);
		Assert.Equal(0, hits[0].Item1);
		Assert.Equal(13, hits[0].Item2);
	}

	[Fact]
	public void Finds_Multiple_Overlapping_Patterns()
	{
		var ac = new Aho_Corasick(new[] { "he", "she", "his", "hers" });
		var hits = new List<int>();
		foreach (var (pi, _) in ac.Find_All("ushers".AsSpan()))
		{
			hits.Add(pi);
		}
		// "she" and "he" should both match at position 1-3
		Assert.Contains(0, hits);   // "he"
		Assert.Contains(1, hits);   // "she"
	}

	[Fact]
	public void No_False_Match_On_Substring_Boundary()
	{
		var ac = new Aho_Corasick(new[] { "abc" });
		var hits = new List<int>();
		foreach (var (pi, _) in ac.Find_All("ab".AsSpan()))
		{
			hits.Add(pi);
		}
		Assert.Empty(hits);
	}

	[Fact]
	public void Resets_State_On_Non_Ascii_Character()
	{
		// Cyrillic 'о' interrupts what would otherwise look like "ignore"
		var ac = new Aho_Corasick(new[] { "ignore" });
		var hits = new List<int>();
		foreach (var (pi, _) in ac.Find_All("ignоre".AsSpan()))
		{
			hits.Add(pi);
		}
		Assert.Empty(hits);   // non-ASCII char resets the automaton
	}

	[Fact]
	public void Empty_Input_Yields_No_Hits()
	{
		var ac = new Aho_Corasick(new[] { "anything" });
		var hits = new List<int>();
		foreach (var (pi, _) in ac.Find_All("".AsSpan()))
		{
			hits.Add(pi);
		}
		Assert.Empty(hits);
	}

	[Fact]
	public void Throws_On_Non_Ascii_Pattern()
	{
		Assert.Throws<ArgumentException>(() => new Aho_Corasick(new[] { "héllo" }));
	}

	[Fact]
	public void Multiple_Hits_Of_Same_Pattern()
	{
		var ac = new Aho_Corasick(new[] { "foo" });
		var hits = new List<int>();
		foreach (var (pi, _) in ac.Find_All("foo and foo and foo".AsSpan()))
		{
			hits.Add(pi);
		}
		Assert.Equal(3, hits.Count);
	}
}
