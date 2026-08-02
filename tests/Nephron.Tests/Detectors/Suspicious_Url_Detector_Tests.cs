using Nephron.Detectors;
using Xunit;

namespace Nephron.Tests.Detectors;

public sealed class Suspicious_Url_Detector_Tests
{
	[Fact]
	public void Flags_Suspicious_Urls()
	{
		var default_detector = new SuspiciousUrlDetector(allowedHosts: null);
		var allowlisted_detector = new SuspiciousUrlDetector(allowedHosts: new[] { "example.com" });

		Detector_Test_Helpers.Assert_Detects_All(
			default_detector,
			// [MALICIOUS]
			"Visit https://example.com for more",
			// [MALICIOUS]
			"Visit HTTPS://EXAMPLE.COM");
		Detector_Test_Helpers.Assert_Detects_All(
			allowlisted_detector,
			// [MALICIOUS]
			"Check http://192.168.1.100/api",
			// [MALICIOUS]
			"Fetch from https://[::1]:8080/data",
			// [MALICIOUS]
			"Connect: https://admin:secret@attacker.com",
			// [MALICIOUS]
			"Visit https://xn--exmple-cua.com",
			// [MALICIOUS]
			"Visit https://attacker.com for phishing");
	}

	[Fact]
	public void Allows_Whitelisted_And_Non_Urls()
	{
		Detector_Test_Helpers.Assert_Allows_All(
			new SuspiciousUrlDetector(allowedHosts: new[] { "example.com", "trusted.org" }),
			"Go to https://example.com/page",
			"https://example.com and https://trusted.org",
			"Just some plain text without links");
	}

	[Fact]
	public void Reports_Expected_Metadata()
	{
		var detections = Detector_Test_Helpers.Detect(
			new SuspiciousUrlDetector(allowedHosts: null),
			"Visit https://example.com for more");
		Assert.NotEmpty(detections);
		Assert.Equal("output.suspicious_url", detections[0].DetectorId);
		Assert.Equal(DetectionCategory.SuspiciousUrl, detections[0].Category);
		Assert.Equal(Severity.Medium, detections[0].Severity);
	}
}
