using Nephron.Detectors;
using Xunit;

namespace Nephron.Tests.Detectors;

public sealed class Pii_Leakage_Detector_Tests
{
	private readonly PiiLeakageDetector _Detector = new();

	[Fact]
	public void Detects_Core_Pii_And_Token_Shapes()
	{
		Detector_Test_Helpers.Assert_Detects_All(
			_Detector,
			// [MALICIOUS]
			"The person with SSN 123-45-6789 is...",
			// [MALICIOUS]
			"Card: 4111-1111-1111-1111",
			// [MALICIOUS]
			"Key: AKIAIOSFODNN7EXAMPLE",
			// [MALICIOUS]
			"Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJk",
			// [MALICIOUS]
			"Token: xoxb-aBcDeFgHiJkLm-noPqRs");
	}

	[Fact]
	public void Allows_Invalid_Or_Clean_Text()
	{
		Detector_Test_Helpers.Assert_Allows_All(
			_Detector,
			"Invalid SSN: 000-00-0000",
			"Fake card: 1234-5678-9012-3456",
			"This is a clean document with no sensitive data",
			"",
			"The support ticket number is 123456789");
	}

	[Fact]
	public void Reports_Expected_Metadata()
	{
		var detections = Detector_Test_Helpers.Detect(_Detector, "The person with SSN 123-45-6789 is...");
		Assert.NotEmpty(detections);
		Assert.Equal("output.pii_leakage", detections[0].DetectorId);
		Assert.Equal(DetectionCategory.PiiLeakage, detections[0].Category);
		Assert.Equal(Severity.High, detections[0].Severity);
	}
}
