using Xunit;

namespace Nephron.Tests.Detectors;

internal static class Detector_Test_Helpers
{
	public static List<Detection> Detect(IDetector detector, string input)
	{
		var detections = new List<Detection>();
		detector.Detect(input.AsSpan(), detections);
		return detections;
	}

	public static void Assert_Detects_All(IDetector detector, params string[] inputs)
	{
		foreach (var input in inputs)
		{
			Assert.NotEmpty(Detect(detector, input));
		}
	}

	public static void Assert_Allows_All(IDetector detector, params string[] inputs)
	{
		foreach (var input in inputs)
		{
			Assert.Empty(Detect(detector, input));
		}
	}
}
