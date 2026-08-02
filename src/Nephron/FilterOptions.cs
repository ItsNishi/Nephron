using Nephron.Detectors;
using Nephron.Normalization;

namespace Nephron;

/// <summary>Runtime detector, normalization, and threshold configuration.</summary>
public sealed class FilterOptions
{
	public IReadOnlyList<IDetector> InputDetectors { get; init; } = Array.Empty<IDetector>();

	public IReadOnlyList<IDetector> OutputDetectors { get; init; } = Array.Empty<IDetector>();

	public IReadOnlyList<IDetector> ToolResultDetectors { get; init; } = Array.Empty<IDetector>();

	public NormalizationOptions Normalization { get; init; } = NormalizationOptions.Default();

	public Severity BlockThreshold { get; init; } = Severity.High;

	/// <summary>Source policy used for scan-time overrides, if any.</summary>
	public Policy? SourcePolicy { get; init; }

	/// <summary>Standard detector registration that blocks at <see cref="Severity.High"/>.</summary>
	public static FilterOptions Default()
	{
		var input = new IDetector[]
		{
			new PersonaDetector(),
			new ComplianceBypassDetector(),
			new InstructionOverrideDetector(),
			new RoleSmugglingDetector(),
			new JsonRoleMarkerDetector(),
			new TemplateInjectionDetector(),
			new ToolHijackDetector(),
			new ExfiltrationPreflightDetector(),
			new KnownMarkerDetector(),
			new SystemPromptImpersonationDetector(),
			new LeetspeakKeywordDetector(),
			new UnicodeTagSteganographyDetector(),
			new VariationSelectorSteganographyDetector(),
			new EncodingSuspicionDetector(),
		};

		var output = new IDetector[]
		{
			new MarkdownImageBeaconDetector(),
			new PiiLeakageDetector(),
			new UnicodeTagSteganographyDetector(),
		};

		var tool_result = new IDetector[]
		{
			new HiddenInstructionDetector(),
			new KnownMarkerDetector(),
			new SystemPromptImpersonationDetector(),
			new JsonRoleMarkerDetector(),
			new TemplateInjectionDetector(),
			new UnicodeTagSteganographyDetector(),
			new VariationSelectorSteganographyDetector(),
			new MarkdownImageBeaconDetector(),
		};

		return new FilterOptions
		{
			InputDetectors = input,
			OutputDetectors = output,
			ToolResultDetectors = tool_result,
			Normalization = NormalizationOptions.Default(),
			BlockThreshold = Severity.High,
		};
	}

	/// <summary>Standard detector registration that blocks at <see cref="Severity.Medium"/>.</summary>
	public static FilterOptions Strict()
	{
		var defaults = Default();
		return new FilterOptions
		{
			InputDetectors = defaults.InputDetectors,
			OutputDetectors = defaults.OutputDetectors,
			ToolResultDetectors = defaults.ToolResultDetectors,
			Normalization = defaults.Normalization,
			BlockThreshold = Severity.Medium,
		};
	}

	/// <summary>Builds options from a <see cref="Policy"/>.</summary>
	public static FilterOptions FromPolicy(Policy policy)
	{
		ArgumentNullException.ThrowIfNull(policy);

		var defaults = Default();

		var input = Filter_Detectors(defaults.InputDetectors, policy);
		var output = Filter_Detectors(defaults.OutputDetectors, policy);
		var tool_result = Filter_Detectors(defaults.ToolResultDetectors, policy);

		return new FilterOptions
		{
			InputDetectors = input,
			OutputDetectors = output,
			ToolResultDetectors = tool_result,
			Normalization = policy.Normalization,
			BlockThreshold = policy.BlockThreshold,
			SourcePolicy = policy,
		};
	}

	private static IReadOnlyList<IDetector> Filter_Detectors(
		IReadOnlyList<IDetector> source, Policy policy)
	{
		if (policy.Rules.Count == 0) return source;
		var kept = new List<IDetector>(source.Count);
		foreach (var d in source)
		{
			if (policy.Rules.TryGetValue(d.DetectorId, out var rule) && !rule.Enabled)
			{
				continue;
			}
			kept.Add(d);
		}
		return kept;
	}
}
