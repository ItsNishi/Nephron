using Nephron.Detectors;
using Xunit;

namespace Nephron.Tests.Detectors;

// SuspiciousUrlDetector is opt-in: without an allowlist it flags every URL, so it is
// not in any default channel. These tests pin that contract and compile-check the
// wiring example documented in docs/Detectors.md.
public sealed class Suspicious_Url_Optin_Tests
{
	[Fact]
	public void Is_Not_Registered_On_Any_Default_Channel()
	{
		var defaults = FilterOptions.Default();

		Assert.DoesNotContain(defaults.InputDetectors, d => d is SuspiciousUrlDetector);
		Assert.DoesNotContain(defaults.OutputDetectors, d => d is SuspiciousUrlDetector);
		Assert.DoesNotContain(defaults.ToolResultDetectors, d => d is SuspiciousUrlDetector);
	}

	[Fact]
	public void Documented_Optin_Wiring_Works()
	{
		var defaults = FilterOptions.Default();

		var output = new List<IDetector>(defaults.OutputDetectors)
		{
			new SuspiciousUrlDetector(new[] { "example.com", "cdn.example.com" }),
		};

		var filter = new NephronFilter(new FilterOptions
		{
			InputDetectors = defaults.InputDetectors,
			OutputDetectors = output,
			ToolResultDetectors = defaults.ToolResultDetectors,
			Normalization = defaults.Normalization,
			BlockThreshold = defaults.BlockThreshold,
		});

		var allowed = filter.ScanOutput("Docs are at https://example.com/guide");
		Assert.DoesNotContain(allowed.Detections, d => d.DetectorId == "output.suspicious_url");

		var flagged = filter.ScanOutput("Grab it from https://192.168.1.30/payload");
		Assert.Contains(flagged.Detections, d => d.DetectorId == "output.suspicious_url");
	}

	// The reason it is opt-in: with no allowlist, ordinary links are flagged too.
	[Fact]
	public void Without_Allowlist_Flags_Every_Url()
	{
		var detector = new SuspiciousUrlDetector();
		var detections = Detector_Test_Helpers.Detect(
			detector, "Our docs live at https://example.com/guide");

		Assert.NotEmpty(detections);
	}
}
