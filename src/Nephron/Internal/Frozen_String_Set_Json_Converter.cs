using System.Collections.Frozen;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nephron.Internal;

// Converts JSON arrays to case-insensitive frozen sets for policy contracts.
internal sealed class Frozen_String_Set_Json_Converter : JsonConverter<IReadOnlySet<string>>
{
	public override IReadOnlySet<string>? Read(
		ref Utf8JsonReader reader,
		Type typeToConvert,
		JsonSerializerOptions options)
	{
		if (reader.TokenType == JsonTokenType.Null)
		{
			return FrozenSet<string>.Empty;
		}
		if (reader.TokenType != JsonTokenType.StartArray)
		{
			throw new JsonException("Expected JSON array for string set.");
		}

		var items = new List<string>();
		while (reader.Read())
		{
			if (reader.TokenType == JsonTokenType.EndArray) break;
			if (reader.TokenType == JsonTokenType.String)
			{
				items.Add(reader.GetString()!);
			}
		}
		return items.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
	}

	public override void Write(
		Utf8JsonWriter writer,
		IReadOnlySet<string> value,
		JsonSerializerOptions options)
	{
		writer.WriteStartArray();
		foreach (var s in value)
		{
			writer.WriteStringValue(s);
		}
		writer.WriteEndArray();
	}
}
