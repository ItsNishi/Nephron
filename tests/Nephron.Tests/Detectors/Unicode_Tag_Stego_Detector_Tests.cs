using Nephron.Detectors;
using Xunit;

namespace Nephron.Tests.Detectors;

public sealed class Unicode_Tag_Stego_Detector_Tests
{
	private readonly UnicodeTagSteganographyDetector _Detector = new();

	[Fact]
	public void Detects_Unicode_Tag_Characters()
	{
		var tag_a = char.ConvertFromUtf32(0xE0041);
		var tag_b = char.ConvertFromUtf32(0xE0042);
		var tag_end = char.ConvertFromUtf32(0xE007F);
		Detector_Test_Helpers.Assert_Detects_All(
			_Detector,
			// [MALICIOUS]
			$"Hello {tag_a} world",
			// [MALICIOUS]
			$"Text {tag_a}{tag_b} end",
			// [MALICIOUS]
			$"{tag_a}injected instruction",
			// [MALICIOUS]
			$"normal text{tag_end}",
			// [MALICIOUS]
			$"Text {tag_a} middle {tag_b} end");
	}

	[Fact]
	public void Allows_Normal_Unicode_Text()
	{
		Detector_Test_Helpers.Assert_Allows_All(
			_Detector,
			"Hello 😀 world",
			"Chinese: 中国 Japanese: 日本",
			"This is normal ASCII text with no tricks",
			$"Smile {char.ConvertFromUtf32(0x1F600)} happy",
			"Café naïve");
	}

	[Fact]
	public void Reports_Expected_Metadata()
	{
		var detections = Detector_Test_Helpers.Detect(_Detector, $"Hello {char.ConvertFromUtf32(0xE0041)} world");
		Assert.Single(detections);
		Assert.Equal("stego.unicode_tags", detections[0].DetectorId);
		Assert.Equal(DetectionCategory.UnicodeSteganography, detections[0].Category);
		Assert.Equal(Severity.Critical, detections[0].Severity);
	}
}
