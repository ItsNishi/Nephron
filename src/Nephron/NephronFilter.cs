using Nephron.Normalization;

namespace Nephron;

/// <summary>Scans user input, model output, or tool and RAG content.</summary>
/// <remarks>Thread-safe, reusable, and allocation-free on the clean scan path.</remarks>
public sealed class NephronFilter
{
	[ThreadStatic]
	private static List<Detection>? _Scratch_Hits;

	private readonly FilterOptions _Options;
	private readonly FilterStatistics _Statistics;

	public FilterStatistics Statistics => _Statistics;

	public FilterOptions Options => _Options;

	public NephronFilter(FilterOptions options)
	{
		ArgumentNullException.ThrowIfNull(options);
		_Options = options;
		_Statistics = new FilterStatistics();
	}

	/// <summary>Scans untrusted user input before it reaches the model.</summary>
	public ScanResult ScanInput(string text)
		=> Scan(text, _Options.InputDetectors, _Options.SourcePolicy?.Input);

	/// <summary>Scans model output for exfiltration and sensitive-data findings.</summary>
	public ScanResult ScanOutput(string text)
		=> Scan(text, _Options.OutputDetectors, _Options.SourcePolicy?.Output);

	/// <summary>Scans tool, MCP, or RAG content before prompt ingestion.</summary>
	public ScanResult ScanToolResult(string text)
		=> Scan(text, _Options.ToolResultDetectors, _Options.SourcePolicy?.ToolResult);

	private ScanResult Scan(
		string text,
		IReadOnlyList<IDetector> detectors,
		ChannelPolicy? channel)
	{
		ArgumentNullException.ThrowIfNull(text);

		var sanitized = NormalizationPipeline.Run(text, _Options.Normalization);

		var policy = _Options.SourcePolicy;

		// Thread-local scratch avoids clean-path allocation; results receive a copy.
		var hits = _Scratch_Hits ??= new List<Detection>(8);
		hits.Clear();

		var span = sanitized.AsSpan();
		// An indexed loop avoids boxing IReadOnlyList<T>'s enumerator.
		for (var i = 0; i < detectors.Count; i++)
		{
			var detector = detectors[i];
			if (channel != null && channel.DisabledDetectors.Contains(detector.DetectorId))
			{
				continue;
			}
			detector.Detect(span, hits);
		}

		if (policy != null && hits.Count > 0)
		{
			Apply_Policy_Post_Processing(hits, policy);
		}

		IReadOnlyList<Detection> detections = hits.Count > 0
			? hits.ToArray()
			: Array.Empty<Detection>();

		var highest = Severity.None;
		for (var i = 0; i < detections.Count; i++)
		{
			var severity = detections[i].Severity;
			if (severity > highest) highest = severity;
		}

		var threshold = channel?.BlockThresholdOverride ?? _Options.BlockThreshold;
		var verdict = Resolve_Verdict(highest, detections.Count, threshold);
		_Statistics.Record(verdict, detections.Count);

		return new ScanResult(verdict, highest, detections, sanitized);
	}

	private static void Apply_Policy_Post_Processing(List<Detection> hits, Policy policy)
	{
		for (var i = hits.Count - 1; i >= 0; i--)
		{
			var d = hits[i];

			// Allowlisting takes precedence over severity overrides.
			if (d.MatchedPhrase != null
				&& policy.PhraseAllowlist.Contains(d.MatchedPhrase))
			{
				hits.RemoveAt(i);
				continue;
			}

			if (policy.Rules.TryGetValue(d.DetectorId, out var rule)
				&& rule.SeverityOverride.HasValue)
			{
				hits[i] = d.WithSeverity(rule.SeverityOverride.Value);
			}
		}
	}

	private static Verdict Resolve_Verdict(Severity highest, int detection_count, Severity threshold)
	{
		if (detection_count == 0) return Verdict.Allow;
		if (highest >= threshold) return Verdict.Block;
		return Verdict.Flag;
	}
}
