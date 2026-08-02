using System.Text.Json.Serialization;

namespace Nephron.Internal;

// Source-generated policy serialization keeps Native AOT reflection-free.
[JsonSourceGenerationOptions(
	WriteIndented = true,
	PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
	UseStringEnumConverter = true,
	DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(Policy))]
[JsonSerializable(typeof(ChannelPolicy))]
[JsonSerializable(typeof(DetectorRule))]
[JsonSerializable(typeof(Severity))]
[JsonSerializable(typeof(Nephron.Normalization.NormalizationOptions))]
internal sealed partial class Policy_Json_Context : JsonSerializerContext
{
}
