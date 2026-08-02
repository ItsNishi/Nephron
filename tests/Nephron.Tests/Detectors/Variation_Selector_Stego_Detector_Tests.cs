using Nephron.Detectors;
using Xunit;

namespace Nephron.Tests.Detectors;

public sealed class Variation_Selector_Stego_Detector_Tests
{
	private readonly VariationSelectorSteganographyDetector _Detector = new();

	[Fact]
	public void Detects_Suspicious_Variation_Selectors()
	{
		var sup1 = char.ConvertFromUtf32(0xE0100);
		var sup2 = char.ConvertFromUtf32(0xE0101);
		var sup3 = char.ConvertFromUtf32(0xE0102);
		var sup4 = char.ConvertFromUtf32(0xE0103);
		Detector_Test_Helpers.Assert_Detects_All(
			_Detector,
			// [MALICIOUS]
			"text a︀ more",
			// [MALICIOUS]
			"number 5︁ here",
			// [MALICIOUS]
			"text︀︁︂︃end",
			// [MALICIOUS]
			$"text{sup1}{sup2}{sup3}{sup4}end",
			// [MALICIOUS]
			"Text X️ signal");
	}

	[Fact]
	public void Allows_Benign_Variation_Selector_Use()
	{
		Detector_Test_Helpers.Assert_Allows_All(
			_Detector,
			"Emoji 😀︀ is valid",
			"Character 中︀ variation",
			"emoji 😀︀︁︂ text",
			"This is completely normal ASCII text",
			"︀text");
	}

	[Fact]
	public void Reports_Expected_Metadata()
	{
		var detections = Detector_Test_Helpers.Detect(_Detector, "text a︀ more");
		Assert.Single(detections);
		Assert.Equal("stego.variation_selectors", detections[0].DetectorId);
		Assert.Equal(DetectionCategory.UnicodeSteganography, detections[0].Category);
		Assert.Equal(Severity.High, detections[0].Severity);
	}
}
