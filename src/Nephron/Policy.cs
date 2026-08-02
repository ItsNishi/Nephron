using System.Collections.Frozen;
using System.Text.Json.Serialization;
using Nephron.Normalization;

namespace Nephron;

/// <summary>Serializable, immutable configuration for <see cref="FilterOptions.FromPolicy"/>.</summary>
public sealed record Policy
{
	/// <summary>Label for logs and diagnostics. Has no effect on behaviour.</summary>
	public string Name { get; init; } = "Default";

	public Severity BlockThreshold { get; init; } = Severity.High;

	public NormalizationOptions Normalization
	{
		get => _Normalization;
		init => _Normalization = value ?? NormalizationOptions.Default();
	}
	private readonly NormalizationOptions _Normalization = NormalizationOptions.Default();

	/// <summary>Case-insensitive overrides keyed by <see cref="IDetector.DetectorId"/>.</summary>
	public IReadOnlyDictionary<string, DetectorRule> Rules
	{
		get => _Rules;
		init => _Rules = value is null
			? FrozenDictionary<string, DetectorRule>.Empty
			: value.ToFrozenDictionary(
				kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);
	}
	private readonly FrozenDictionary<string, DetectorRule> _Rules
		= FrozenDictionary<string, DetectorRule>.Empty;

	/// <summary>Canonical phrases ignored when matched by a detector.</summary>
	[JsonConverter(typeof(Internal.Frozen_String_Set_Json_Converter))]
	public IReadOnlySet<string> PhraseAllowlist
	{
		get => _Phrase_Allowlist;
		init => _Phrase_Allowlist = value is null
			? FrozenSet<string>.Empty
			: value.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
	}
	private readonly FrozenSet<string> _Phrase_Allowlist = FrozenSet<string>.Empty;

	public ChannelPolicy Input
	{
		get => _Input;
		init => _Input = value ?? new ChannelPolicy();
	}
	private readonly ChannelPolicy _Input = new();

	public ChannelPolicy Output
	{
		get => _Output;
		init => _Output = value ?? new ChannelPolicy();
	}
	private readonly ChannelPolicy _Output = new();

	public ChannelPolicy ToolResult
	{
		get => _Tool_Result;
		init => _Tool_Result = value ?? new ChannelPolicy();
	}
	private readonly ChannelPolicy _Tool_Result = new();

	/// <summary>Baseline policy that blocks at <see cref="Severity.High"/>.</summary>
	public static Policy Default() => new();

	/// <summary>Public API policy that blocks at <see cref="Severity.Medium"/>.</summary>
	public static Policy PublicApi() => new()
	{
		Name = "Public_Api",
		BlockThreshold = Severity.Medium,
	};

	/// <summary>Research policy that permits attack text on input while protecting other channels.</summary>
	public static Policy Research() => new()
	{
		Name = "Research",
		Input = new ChannelPolicy
		{
			DisabledDetectors = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
			{
				"persona.jailbreak",
				"persona.compliance_bypass",
				"instruction.override",
			},
		},
	};

	/// <summary>Agent policy that blocks tool and RAG content at <see cref="Severity.Low"/>.</summary>
	public static Policy AgentToolResult() => new()
	{
		Name = "Agent_Tool_Result",
		ToolResult = new ChannelPolicy
		{
			BlockThresholdOverride = Severity.Low,
		},
	};

	/// <summary>Permissive policy that blocks only at <see cref="Severity.Critical"/>.</summary>
	public static Policy Permissive() => new()
	{
		Name = "Permissive",
		BlockThreshold = Severity.Critical,
	};

	/// <summary>Parses a policy from JSON.</summary>
	public static Policy FromJson(string json)
	{
		ArgumentNullException.ThrowIfNull(json);
		var parsed = System.Text.Json.JsonSerializer.Deserialize(
			json, Internal.Policy_Json_Context.Default.Policy);
		return parsed ?? throw new System.Text.Json.JsonException("Policy JSON parsed to null.");
	}

	/// <summary>Reads a policy from a JSON file.</summary>
	public static Policy FromFile(string path)
	{
		ArgumentNullException.ThrowIfNull(path);
		return FromJson(File.ReadAllText(path));
	}

	/// <summary>Serializes this policy to JSON.</summary>
	public string ToJson() => System.Text.Json.JsonSerializer.Serialize(
		this, Internal.Policy_Json_Context.Default.Policy);
}
