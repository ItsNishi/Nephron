using Xunit;

namespace Nephron.Tests;

public sealed class Policy_Allowlist_Tests
{
	[Fact]
	public void Allowlisted_Phrase_Does_Not_Block()
	{
		// Without allowlist, [godmode] is Critical -> Block.
		var policy = Policy.Default() with
		{
			PhraseAllowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "[godmode]" },
		};
		var filter = new NephronFilter(FilterOptions.FromPolicy(policy));
		// [MALICIOUS] but allowlisted in this policy
		var result = filter.ScanInput("hello [GODMODE] friend");
		Assert.Equal(Verdict.Allow, result.Verdict);
		Assert.Empty(result.Detections);
	}

	[Fact]
	public void Allowlist_Is_Case_Insensitive()
	{
		var policy = Policy.Default() with
		{
			PhraseAllowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "[GODMODE]" },
		};
		var filter = new NephronFilter(FilterOptions.FromPolicy(policy));
		// Detector matches lowercase pattern; allowlist holds uppercase.
		var result = filter.ScanInput("hello [godmode] friend");
		Assert.Equal(Verdict.Allow, result.Verdict);
	}

	[Fact]
	public void Allowlist_Does_Not_Suppress_Other_Detectors()
	{
		// Allow [godmode], but l1b3rt4s should still trigger.
		var policy = Policy.Default() with
		{
			PhraseAllowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "[godmode]" },
		};
		var filter = new NephronFilter(FilterOptions.FromPolicy(policy));
		// [MALICIOUS] mixed allowlisted + non-allowlisted markers
		var result = filter.ScanInput("hello [godmode] also l1b3rt4s here");
		Assert.Equal(Verdict.Block, result.Verdict);
		Assert.Single(result.Detections);
		Assert.Equal("l1b3rt4s", result.Detections[0].MatchedPhrase);
	}

	[Fact]
	public void Empty_Allowlist_Behaves_Like_Default()
	{
		var policy = Policy.Default();
		var filter = new NephronFilter(FilterOptions.FromPolicy(policy));
		// [MALICIOUS]
		var result = filter.ScanInput("hello [godmode] friend");
		Assert.Equal(Verdict.Block, result.Verdict);
	}

	[Fact]
	public void Allowlist_Does_Not_Affect_Non_Phrase_Detectors()
	{
		// Allowlist doesn't apply to detectors that don't expose MatchedPhrase
		// (Unicode_Tag_Stego, PII, etc.). Stego still fires regardless.
		var policy = Policy.Default() with
		{
			PhraseAllowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "anything" },
		};
		var filter = new NephronFilter(FilterOptions.FromPolicy(policy));
		// [MALICIOUS] U+E0049 invisible tag char
		var hidden = char.ConvertFromUtf32(0xE0049);
		var result = filter.ScanInput($"benign{hidden}continuing");
		Assert.Equal(Verdict.Block, result.Verdict);
		Assert.Contains(result.Detections, d => d.DetectorId == "stego.unicode_tags");
	}
}
