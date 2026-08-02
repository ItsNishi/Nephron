using Xunit;

namespace Nephron.Tests;

public sealed class Policy_Tests
{
	[Fact]
	public void Default_Has_High_Block_Threshold()
	{
		var p = Policy.Default();
		Assert.Equal("Default", p.Name);
		Assert.Equal(Severity.High, p.BlockThreshold);
		Assert.Empty(p.Rules);
		Assert.Empty(p.PhraseAllowlist);
	}

	[Fact]
	public void Default_Initializes_Empty_Channels()
	{
		var p = Policy.Default();
		Assert.Empty(p.Input.DisabledDetectors);
		Assert.Empty(p.Output.DisabledDetectors);
		Assert.Empty(p.ToolResult.DisabledDetectors);
	}

	[Fact]
	public void Default_Has_Default_Normalization()
	{
		var p = Policy.Default();
		Assert.True(p.Normalization.ApplyNfkc);
		Assert.True(p.Normalization.StripZeroWidth);
		Assert.True(p.Normalization.FoldHomoglyphs);
		Assert.True(p.Normalization.StripComments);
	}

	[Fact]
	public void Public_Api_Blocks_At_Medium()
	{
		var p = Policy.PublicApi();
		Assert.Equal("Public_Api", p.Name);
		Assert.Equal(Severity.Medium, p.BlockThreshold);
	}

	[Fact]
	public void Public_Api_Inherits_Default_Channels()
	{
		var p = Policy.PublicApi();
		Assert.Empty(p.Input.DisabledDetectors);
		Assert.Empty(p.Output.DisabledDetectors);
		Assert.Empty(p.ToolResult.DisabledDetectors);
	}

	[Fact]
	public void Public_Api_Maintains_Normalization()
	{
		var p = Policy.PublicApi();
		Assert.True(p.Normalization.ApplyNfkc);
	}

	[Fact]
	public void Research_Disables_Persona_And_Override_On_Input()
	{
		var p = Policy.Research();
		Assert.Equal("Research", p.Name);
		Assert.Contains("persona.jailbreak", p.Input.DisabledDetectors);
		Assert.Contains("persona.compliance_bypass", p.Input.DisabledDetectors);
		Assert.Contains("instruction.override", p.Input.DisabledDetectors);
		Assert.Equal(3, p.Input.DisabledDetectors.Count);
	}

	[Fact]
	public void Research_Does_Not_Disable_Output_Channel()
	{
		var p = Policy.Research();
		Assert.Empty(p.Output.DisabledDetectors);
		Assert.Empty(p.ToolResult.DisabledDetectors);
	}

	[Fact]
	public void Research_Uses_High_Block_Threshold()
	{
		var p = Policy.Research();
		Assert.Equal(Severity.High, p.BlockThreshold);
	}

	[Fact]
	public void Agent_Tool_Result_Lowers_Tool_Channel_Threshold()
	{
		var p = Policy.AgentToolResult();
		Assert.Equal("Agent_Tool_Result", p.Name);
		Assert.Equal(Severity.Low, p.ToolResult.BlockThresholdOverride);
	}

	[Fact]
	public void Agent_Tool_Result_Does_Not_Modify_Input_Channel()
	{
		var p = Policy.AgentToolResult();
		Assert.Null(p.Input.BlockThresholdOverride);
		Assert.Empty(p.Input.DisabledDetectors);
	}

	[Fact]
	public void Agent_Tool_Result_Does_Not_Modify_Output_Channel()
	{
		var p = Policy.AgentToolResult();
		Assert.Null(p.Output.BlockThresholdOverride);
		Assert.Empty(p.Output.DisabledDetectors);
	}

	[Fact]
	public void Permissive_Only_Blocks_Critical()
	{
		var p = Policy.Permissive();
		Assert.Equal("Permissive", p.Name);
		Assert.Equal(Severity.Critical, p.BlockThreshold);
	}

	[Fact]
	public void Permissive_Keeps_Default_Channels()
	{
		var p = Policy.Permissive();
		Assert.Empty(p.Input.DisabledDetectors);
		Assert.Empty(p.Output.DisabledDetectors);
		Assert.Empty(p.ToolResult.DisabledDetectors);
	}

	[Fact]
	public void Permissive_Has_No_Channel_Overrides()
	{
		var p = Policy.Permissive();
		Assert.Null(p.Input.BlockThresholdOverride);
		Assert.Null(p.Output.BlockThresholdOverride);
		Assert.Null(p.ToolResult.BlockThresholdOverride);
	}

	[Fact]
	public void Detector_Rule_Default_Enabled()
	{
		var rule = new DetectorRule();
		Assert.True(rule.Enabled);
		Assert.Null(rule.SeverityOverride);
	}

	[Fact]
	public void Channel_Policy_Default_Null_Threshold_Override()
	{
		var policy = new ChannelPolicy();
		Assert.Null(policy.BlockThresholdOverride);
	}

	[Fact]
	public void Channel_Policy_Default_Empty_Disabled_Detectors()
	{
		var policy = new ChannelPolicy();
		Assert.Empty(policy.DisabledDetectors);
	}

	[Fact]
	public void Channel_Policy_Disabled_Detectors_Case_Insensitive()
	{
		var policy = new ChannelPolicy
		{
			DisabledDetectors = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
			{
				"Test.Detector",
			},
		};
		Assert.Contains("test.detector", policy.DisabledDetectors);
		Assert.Contains("TEST.DETECTOR", policy.DisabledDetectors);
	}

	// JSON serialization is now implemented; round-trip behaviour is covered
	// by Policy_Json_Tests. The earlier stub-throws test was retired.

	[Fact]
	public void Policy_Collections_Are_Truly_Immutable()
	{
		// FrozenDictionary and FrozenSet do not support Add. The compile-time
		// public type is IReadOnly* so callers cannot mutate even if they
		// downcast. This test pins the runtime type to catch regressions.
		var p = Policy.Default();
		Assert.IsAssignableFrom<System.Collections.Frozen.FrozenDictionary<string, DetectorRule>>(p.Rules);
		Assert.IsAssignableFrom<System.Collections.Frozen.FrozenSet<string>>(p.PhraseAllowlist);
	}

	[Fact]
	public void Caller_Mutating_Source_Collection_Does_Not_Affect_Policy()
	{
		// init setter must defensively copy. Mutating the caller's set
		// after construction must not leak into the Policy.
		var source = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "[godmode]" };
		var p = Policy.Default() with { PhraseAllowlist = source };
		source.Add("ignore previous");
		Assert.Single(p.PhraseAllowlist);
		Assert.Contains("[godmode]", p.PhraseAllowlist);
		Assert.DoesNotContain("ignore previous", p.PhraseAllowlist);
	}

	[Fact]
	public void All_Presets_Have_Unique_Names()
	{
		var names = new[]
		{
			Policy.Default().Name,
			Policy.PublicApi().Name,
			Policy.Research().Name,
			Policy.AgentToolResult().Name,
			Policy.Permissive().Name,
		};
		var uniqueNames = new HashSet<string>(names);
		Assert.Equal(5, uniqueNames.Count);
	}
}
