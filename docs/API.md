# Nephron API guide

This guide covers the public members used in normal integrations. For detector IDs and signals,
see [Detectors.md](Detectors.md). For policy configuration and JSON fields, see
[Policy.md](Policy.md).

## Create a filter

Use a factory unless you are supplying detector lists yourself:

```csharp
var defaultFilter = new NephronFilter(FilterOptions.Default());
var strictFilter = new NephronFilter(FilterOptions.Strict());
var policyFilter = new NephronFilter(FilterOptions.FromPolicy(Policy.PublicApi()));
```

| Factory | Behavior |
|---|---|
| `FilterOptions.Default()` | Registers the standard detectors and blocks at `Severity.High` |
| `FilterOptions.Strict()` | Uses the standard detectors and blocks at `Severity.Medium` |
| `FilterOptions.FromPolicy(policy)` | Applies a preset or custom policy to the standard detectors |

> `new FilterOptions()` starts with empty detector lists. Use it only when intentionally building a
> custom registration.

`NephronFilter` is reusable and thread-safe. Construct it once for a configuration instead of
creating one for every scan.

## Scan methods

| Method | Use it for |
|---|---|
| `ScanInput(text)` | Untrusted user text before it enters the model prompt |
| `ScanOutput(text)` | Model output before it reaches the caller or another system |
| `ScanToolResult(text)` | Tool, MCP, plugin, or RAG content before it re-enters an agent prompt |

Each method returns a `ScanResult` and throws `ArgumentNullException` for null text. Empty strings
are valid; the standard detector set returns an `Allow` result for them.

Use the method matching the trust boundary. The three channels have different default detector
sets; they are not aliases for the same scan.

## ScanResult

| Member | Meaning |
|---|---|
| `Verdict` | Advisory `Allow`, `Flag`, or `Block` action |
| `HighestSeverity` | Highest severity after allowlisting and policy overrides |
| `Detections` | Remaining findings after policy processing |
| `SanitizedText` | Text after the configured normalization pipeline |
| `IsAllowed` / `IsBlocked` | Convenience checks for the corresponding verdict |
| `HasDetections` | Whether the final result contains findings |

Pass `SanitizedText` to the next component. Detection ranges use this normalized string as their
coordinate space and may not line up with the original input.

`Allow` means no configured detector produced a remaining finding. It is not proof that the text
is safe. Enforcement remains the caller's responsibility.

## Verdicts and severity

Verdicts are resolved from the final detections:

| Condition | Verdict |
|---|---|
| No detections | `Allow` |
| Highest severity is below the active threshold | `Flag` |
| Highest severity meets or exceeds the active threshold | `Block` |

The active threshold is the channel override when one exists; otherwise it is
`FilterOptions.BlockThreshold`.

## Detection

A `Detection` contains:

| Member | Contract |
|---|---|
| `DetectorId` | Stable configuration identifier; use this for rules and program logic |
| `Category` | Broad grouping for reporting |
| `Severity` | Severity after policy overrides |
| `Range` | Half-open `[Start..End)` range in `ScanResult.SanitizedText` |
| `Reason` | Human-readable diagnostic text; do not parse it as a stable contract |
| `MatchedPhrase` | Canonical phrase used by the phrase allowlist, when available |

Keep detailed findings in trusted logs. Returning detector IDs, matched phrases, or reasons to an
untrusted caller provides useful feedback for adaptive bypass attempts.

## Policy entry points

`Policy` provides five built-in factories:

- `Default()` for the baseline High threshold.
- `PublicApi()` for a Medium threshold across all channels.
- `Research()` to disable three common jailbreak checks on input while retaining other checks.
- `AgentToolResult()` for a Low threshold on tool and RAG content.
- `Permissive()` for blocking only Critical findings.

Use `Policy.FromJson`, `Policy.FromFile`, and `Policy.ToJson` for serialized configuration. See
[Policy.md](Policy.md) for precedence, field names, channel overrides, and examples.

## Statistics

`filter.Statistics` exposes thread-safe totals for scans, verdicts, and detections. `Reset()`
zeroes the counters. Statistics are per `NephronFilter` instance and are intended for operational
telemetry, not security auditing.

## Custom detectors

Implement `IDetector` for custom logic or derive from `PhraseDetectorBase` for fixed ASCII phrase
lists. Register the detector on only the channels where its signal is meaningful. Detector IDs are
configuration contracts and should remain stable after release.

See [Adding a detector](Detectors.md#adding-a-detector) for registration, tests, and false-positive
requirements.

## Normalization API

Most callers should configure `NormalizationOptions` through `FilterOptions` and consume
`ScanResult.SanitizedText`. The individual normalization classes are public for callers that need
the same transformations outside a scan.

`NormalizationOptions.Default()` enables every pass except whitespace collapsing.
`NormalizationOptions.Off()` disables every pass and is primarily useful when normalization is
already performed upstream.
