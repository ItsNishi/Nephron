using System.Collections.Frozen;
using System.Text.Json.Serialization;

namespace Nephron;

/// <summary>Detection overrides for one input, output, or tool-result channel.</summary>
public sealed record ChannelPolicy
{
	public Severity? BlockThresholdOverride { get; init; }

	/// <summary>Case-insensitive detector IDs disabled on this channel.</summary>
	[JsonConverter(typeof(Internal.Frozen_String_Set_Json_Converter))]
	public IReadOnlySet<string> DisabledDetectors
	{
		get => _Disabled_Detectors;
		init => _Disabled_Detectors = value is null
			? FrozenSet<string>.Empty
			: value.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
	}
	private readonly FrozenSet<string> _Disabled_Detectors = FrozenSet<string>.Empty;
}
