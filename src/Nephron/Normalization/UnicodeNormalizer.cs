using System.Text;

namespace Nephron.Normalization;

/// <summary>Applies Unicode NFKC normalization.</summary>
public static class UnicodeNormalizer
{
	public static string Normalize(string input)
	{
		if (string.IsNullOrEmpty(input)) return input;
		if (input.IsNormalized(NormalizationForm.FormKC)) return input;
		return input.Normalize(NormalizationForm.FormKC);
	}
}
