using System.Text.Json;

using Xunit;

namespace Nephron.Tests;

public sealed class Policy_Json_Tests
{
	[Fact]
	public void Default_Round_Trips()
	{
		var original = Policy.Default();
		var json = original.ToJson();
		var restored = Policy.FromJson(json);
		Assert.Equal(original.Name, restored.Name);
		Assert.Equal(original.BlockThreshold, restored.BlockThreshold);
	}

	[Fact]
	public void Public_Member_Renames_Preserve_Snake_Case_Json_Contract()
	{
		using var document = JsonDocument.Parse(Policy.Default().ToJson());
		var root = document.RootElement;

		Assert.True(root.TryGetProperty("block_threshold", out _));
		Assert.True(root.TryGetProperty("phrase_allowlist", out _));
		Assert.True(root.TryGetProperty("tool_result", out _));

		var normalization = root.GetProperty("normalization");
		Assert.True(normalization.TryGetProperty("apply_nfkc", out _));
		Assert.True(normalization.TryGetProperty("strip_zero_width", out _));
	}

	[Fact]
	public void Research_Round_Trips_With_Channel_Disable_Set()
	{
		var original = Policy.Research();
		var json = original.ToJson();
		var restored = Policy.FromJson(json);
		Assert.Contains("persona.jailbreak", restored.Input.DisabledDetectors);
		Assert.Contains("persona.compliance_bypass", restored.Input.DisabledDetectors);
		Assert.Contains("instruction.override", restored.Input.DisabledDetectors);
	}

	[Fact]
	public void Agent_Tool_Result_Round_Trips_With_Channel_Override()
	{
		var original = Policy.AgentToolResult();
		var json = original.ToJson();
		var restored = Policy.FromJson(json);
		Assert.Equal(Severity.Low, restored.ToolResult.BlockThresholdOverride);
	}

	[Fact]
	public void Round_Trip_Preserves_Phrase_Allowlist()
	{
		var original = Policy.Default() with
		{
			PhraseAllowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
			{
				"[godmode]",
				"research-only",
			},
		};
		var json = original.ToJson();
		var restored = Policy.FromJson(json);
		Assert.Contains("[godmode]", restored.PhraseAllowlist);
		Assert.Contains("RESEARCH-ONLY", restored.PhraseAllowlist);   // case-insensitive
	}

	[Fact]
	public void Round_Trip_Preserves_Severity_Override()
	{
		var original = Policy.Default() with
		{
			Rules = new Dictionary<string, DetectorRule>
			{
				["instruction.override"] = new() { SeverityOverride = Severity.Critical },
				["encoding.suspicion"] = new() { Enabled = false },
			},
		};
		var json = original.ToJson();
		var restored = Policy.FromJson(json);
		Assert.Equal(Severity.Critical, restored.Rules["instruction.override"].SeverityOverride);
		Assert.False(restored.Rules["encoding.suspicion"].Enabled);
	}

	[Fact]
	public void From_File_Loads_Policy()
	{
		var temp = Path.GetTempFileName();
		try
		{
			File.WriteAllText(temp, Policy.PublicApi().ToJson());
			var loaded = Policy.FromFile(temp);
			Assert.Equal(Severity.Medium, loaded.BlockThreshold);
		}
		finally
		{
			File.Delete(temp);
		}
	}

	[Fact]
	public void Loads_From_Hand_Written_Json()
	{
		var json = """
		{
			"name": "Custom",
			"block_threshold": "High",
			"phrase_allowlist": ["research-only"],
			"rules": {
				"persona.jailbreak": { "enabled": false }
			}
		}
		""";
		var policy = Policy.FromJson(json);
		Assert.Equal("Custom", policy.Name);
		Assert.Equal(Severity.High, policy.BlockThreshold);
		Assert.Contains("RESEARCH-ONLY", policy.PhraseAllowlist);
		Assert.False(policy.Rules["persona.jailbreak"].Enabled);
	}

	[Fact]
	public void Throws_On_Null_Json()
	{
		Assert.Throws<ArgumentNullException>(() => Policy.FromJson(null!));
	}

	[Fact]
	public void Loaded_Policy_Drives_Filter_Behaviour()
	{
		// End-to-end: JSON -> Policy -> Filter -> verdict matches expectation.
		var json = """
		{
			"name": "Allow_Godmode",
			"block_threshold": "High",
			"phrase_allowlist": ["[godmode]"]
		}
		""";
		var policy = Policy.FromJson(json);
		var filter = new NephronFilter(FilterOptions.FromPolicy(policy));
		// [MALICIOUS] but allowlisted by loaded policy
		var result = filter.ScanInput("hello [GODMODE] world");
		Assert.Equal(Verdict.Allow, result.Verdict);
	}
}
