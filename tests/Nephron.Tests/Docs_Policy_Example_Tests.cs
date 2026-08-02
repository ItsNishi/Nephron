using System.Text.RegularExpressions;
using Xunit;

namespace Nephron.Tests;

// docs/Policy.md documents the policy JSON schema by example. Without a test, those
// examples drift the moment a property is renamed and nobody notices until a user
// copies one and it silently does nothing. This parses the documented JSON for real.
public sealed partial class Docs_Policy_Example_Tests
{
	[GeneratedRegex(@"```json\s*\n(.*?)```", RegexOptions.Singleline)]
	private static partial Regex Json_Block();

	private static string Repo_Root()
	{
		var dir = new DirectoryInfo(AppContext.BaseDirectory);
		while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Nephron.slnx")))
		{
			dir = dir.Parent;
		}
		Assert.NotNull(dir);
		return dir!.FullName;
	}

	private static List<string> Documented_Json_Blocks()
	{
		var path = Path.Combine(Repo_Root(), "docs", "Policy.md");
		Assert.True(File.Exists(path), $"missing {path}");

		var blocks = new List<string>();
		foreach (Match m in Json_Block().Matches(File.ReadAllText(path)))
		{
			blocks.Add(m.Groups[1].Value);
		}
		return blocks;
	}

	[Fact]
	public void Every_Documented_Json_Block_Parses()
	{
		var blocks = Documented_Json_Blocks();
		Assert.NotEmpty(blocks);

		foreach (var json in blocks)
		{
			var policy = Policy.FromJson(json);
			Assert.NotNull(policy);
		}
	}

	// Pins the specific values the document claims, so a renamed property or changed
	// enum spelling fails here rather than silently parsing to a default.
	[Fact]
	public void Documented_Example_Round_Trips_With_Its_Stated_Values()
	{
		var json = Documented_Json_Blocks()[0];
		var policy = Policy.FromJson(json);

		Assert.Equal("MyApp_Strict", policy.Name);
		Assert.Equal(Severity.Medium, policy.BlockThreshold);

		Assert.True(policy.Normalization.ApplyNfkc);
		Assert.False(policy.Normalization.CollapseWhitespace);

		// A disabled detector and a severity override, both keyed by current ids.
		Assert.False(policy.Rules["encoding.leetspeak_keyword"].Enabled);
		Assert.Equal(Severity.Critical, policy.Rules["known.markers"].SeverityOverride);

		Assert.Contains("GODMODE", policy.PhraseAllowlist);
		Assert.Equal(Severity.Low, policy.ToolResult.BlockThresholdOverride);

		// And it survives a serialize/parse cycle unchanged.
		var again = Policy.FromJson(policy.ToJson());
		Assert.Equal(policy.Name, again.Name);
		Assert.Equal(policy.BlockThreshold, again.BlockThreshold);
		Assert.Equal(policy.ToolResult.BlockThresholdOverride,
			again.ToolResult.BlockThresholdOverride);
	}

	// Every detector id named in the docs must exist, or the example configures nothing.
	[Fact]
	public void Documented_Detector_Ids_All_Exist()
	{
		var options = FilterOptions.Default();
		var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		foreach (var list in new[]
			{ options.InputDetectors, options.OutputDetectors, options.ToolResultDetectors })
		{
			for (var i = 0; i < list.Count; i++) known.Add(list[i].DetectorId);
		}
		known.Add(new Nephron.Detectors.SuspiciousUrlDetector().DetectorId);   // opt-in

		var policy = Policy.FromJson(Documented_Json_Blocks()[0]);
		foreach (var id in policy.Rules.Keys)
		{
			Assert.True(known.Contains(id), $"docs/Policy.md references unknown detector id '{id}'");
		}
	}
}
