using Nephron.Detectors;
using Xunit;

namespace Nephron.Tests.Detectors;

public sealed class Encoding_Suspicion_Detector_Tests
{
	private readonly EncodingSuspicionDetector _Detector = new();

	[Fact]
	public void Detects_Long_Base64_Shaped_Runs()
	{
		Detector_Test_Helpers.Assert_Detects_All(
			_Detector,
			// [MALICIOUS]
			"Data: " + new string('A', 80),
			// [MALICIOUS]
			"Image: SGVsbG8gV29ybGQgdGhpcyBpcyBhIGxvbmdlciBiYXNlNjQgc3RyaW5nIHRvIHRlc3Qgc3VzcGljaW91cyBlbmNvZGluZyBzdGFydA==",
			// [MALICIOUS]
			"Token: " + new string('A', 40) + "+" + new string('B', 40),
			// [MALICIOUS]
			new string('A', 85) + " is the data",
			// [MALICIOUS]
			"The data is " + new string('A', 85));
	}

	[Fact]
	public void Allows_Short_Or_Normal_Text()
	{
		Detector_Test_Helpers.Assert_Allows_All(
			_Detector,
			"abc123 is a short base64-like string",
			new string('A', 79),
			"This is completely normal English text without encoding",
			"Visit https://example.com for more information",
			"The project code ABC123 and reference number 456789XYZ");
	}

	[Fact]
	public void Reports_Expected_Metadata()
	{
		var detections = Detector_Test_Helpers.Detect(_Detector, "Data: " + new string('A', 80));
		Assert.Single(detections);
		Assert.Equal("encoding.suspicion", detections[0].DetectorId);
		Assert.Equal(DetectionCategory.EncodingSuspicion, detections[0].Category);
		Assert.Equal(Severity.Low, detections[0].Severity);
	}
}
