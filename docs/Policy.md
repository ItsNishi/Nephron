# Nephron Policy Engine

The Policy engine enables deployment-specific guardrail configuration without code changes. Define strictness levels, per-detector rules, and phrase allowlists in code or JSON.

---

## Overview

A `Policy` bundles together:

- **Severity threshold** -- what detection level triggers a Block verdict
- **Detector rules** -- enable/disable detectors globally, or override their severity
- **Phrase allowlist** -- escape hatch for specific detections (case-insensitive)
- **Channel overrides** -- per-channel threshold or detector disable set (input / output / tool-result)
- **Normalization options** -- NFKC folding, zero-width stripping, etc.

Create a `Policy`, convert it to `FilterOptions` with `FilterOptions.FromPolicy(policy)`, and pass that to `NephronFilter`.

### When to use Policy vs FilterOptions.Default()

| Scenario | Use |
|---|---|
| Simple baseline guardrail, minimal config | `FilterOptions.Default()` (unchanged from v1) |
| Need strictness presets, phrase allowlist, or per-detector overrides | `Policy` + `FromPolicy()` |
| Custom detector list (advanced) | `FilterOptions` constructor directly |

---

## Built-in presets

Five named presets cover the most common deployment patterns. Each is a `static` factory method on `Policy`.

| Preset | Block threshold | Key differences from Default |
|---|---|---|
| **Default** | High | Baseline: all default detectors on, block at High |
| **PublicApi** | Medium | Stricter for untrusted users (block at Medium) |
| **Research** | High | Disables persona.jailbreak, persona.compliance_bypass, instruction.override on input channel (research context) |
| **AgentToolResult** | High | ToolResult channel blocks at Low (prevents poisoned tool/MCP/RAG injection) |
| **Permissive** | Critical | Only Critical-severity detections block; everything else flags for logging |

### Example: choosing a preset

```csharp
using Nephron;

// Public-facing chat API: stricter threshold
var publicApiPolicy = Policy.PublicApi();
var publicApiFilter = new NephronFilter(FilterOptions.FromPolicy(publicApiPolicy));

// Agent reading untrusted tool results: paranoid on tool channel
var agentPolicy = Policy.AgentToolResult();
var agentFilter = new NephronFilter(FilterOptions.FromPolicy(agentPolicy));

// Security research tool: allow discussing jailbreak techniques on input
var researchPolicy = Policy.Research();
var researchFilter = new NephronFilter(FilterOptions.FromPolicy(researchPolicy));

// Telemetry-oriented: non-Critical detections flag; Critical detections still block
var permissivePolicy = Policy.Permissive();
var permissiveFilter = new NephronFilter(FilterOptions.FromPolicy(permissivePolicy));
```

---

## Custom policies

Modify any preset using C# `with` expressions:

```csharp
// Start with PublicApi, but also allow a local research marker in phrase allowlist
var allowlistPolicy = Policy.PublicApi() with
{
	PhraseAllowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		"research-only",
		"GODMODE",
	},
};

// Start with Default, disable encoding.leetspeak_keyword globally
var detectorPolicy = Policy.Default() with
{
	Rules = new Dictionary<string, DetectorRule>(StringComparer.OrdinalIgnoreCase)
	{
		["encoding.leetspeak_keyword"] = new DetectorRule { Enabled = false },
	},
};

// Custom threshold per channel
var channelPolicy = Policy.Default() with
{
	Input = new ChannelPolicy
	{
		BlockThresholdOverride = Severity.Critical,  // input is lenient
	},
	ToolResult = new ChannelPolicy
	{
		BlockThresholdOverride = Severity.Low,       // tool results are paranoid
	},
};

// Per-detector severity override
var severityPolicy = Policy.Default() with
{
	Rules = new Dictionary<string, DetectorRule>(StringComparer.OrdinalIgnoreCase)
	{
		["known.markers"] = new DetectorRule { SeverityOverride = Severity.Critical },
		["role.smuggling"] = new DetectorRule { SeverityOverride = Severity.Critical },
	},
};

var filter = new NephronFilter(FilterOptions.FromPolicy(severityPolicy));
```

---

## JSON schema

Load policies from JSON files or strings using `Policy.FromJson()` or `Policy.FromFile()`.

```json
{
	"name": "MyApp_Strict",
	"block_threshold": "Medium",
	"normalization": {
		"apply_nfkc": true,
		"strip_zero_width": true,
		"fold_homoglyphs": true,
		"strip_comments": true,
		"collapse_whitespace": false
	},
	"rules": {
		"persona.jailbreak": {
			"enabled": true,
			"severity_override": null
		},
		"encoding.leetspeak_keyword": {
			"enabled": false,
			"severity_override": null
		},
		"known.markers": {
			"enabled": true,
			"severity_override": "Critical"
		}
	},
	"phrase_allowlist": [
		"research-only",
		"GODMODE"
	],
	"input": {
		"block_threshold_override": null,
		"disabled_detectors": []
	},
	"output": {
		"block_threshold_override": null,
		"disabled_detectors": []
	},
	"tool_result": {
		"block_threshold_override": "Low",
		"disabled_detectors": []
	}
}
```

### JSON field reference

| Field | Type | Purpose |
|---|---|---|
| `name` | string | Human-readable policy name |
| `block_threshold` | "High" \| "Medium" \| "Low" \| "Critical" | Default verdict threshold |
| `normalization` | object | Sanitization passes (NFKC, zero-width, homoglyph, comment, whitespace) |
| `rules` | object (string -> rule) | Per-detector enable/disable and severity override; key = detector ID |
| `phrase_allowlist` | array of strings | Exact-match phrases to allow (case-insensitive) |
| `input` | object | Overrides for input channel |
| `output` | object | Overrides for output channel |
| `tool_result` | object | Overrides for tool-result channel |

---

## Loading from file

```csharp
// Load from file
var filePolicy = Policy.FromFile("./policies/public_api.json");
var filter = new NephronFilter(FilterOptions.FromPolicy(filePolicy));

// Or from a JSON string
var json = File.ReadAllText("config.json");
var jsonPolicy = Policy.FromJson(json);

// Round-trip: save a programmatic policy as JSON
var savedPolicy = Policy.PublicApi() with
{
	PhraseAllowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "research-only" },
};
var serializedPolicy = savedPolicy.ToJson();
File.WriteAllText("my_policy.json", serializedPolicy);
```

---

## Verdict resolution order

For each scan (input / output / tool-result), verdicts are computed in this order:

1. **Normalization** -- run the configured normalization pipeline (NFKC, zero-width stripping, etc.) to produce `SanitizedText`

2. **Detector filtering** -- for each detector registered on the channel:
   - Skip if disabled globally (`Rules[detectorId].Enabled == false`)
   - Skip if disabled on this channel (`ChannelPolicy.DisabledDetectors` contains the detector ID)
   - Run detector

3. **Policy post-processing** -- for each detection produced:
   - Drop if `MatchedPhrase` is in `PhraseAllowlist` (case-insensitive)
   - Otherwise apply `Rules[detectorId].SeverityOverride` when set

4. **Threshold resolution** -- find the highest severity among remaining detections:
   - Resolve channel threshold: use `ChannelPolicy.BlockThresholdOverride` if set, else fall back to `Policy.BlockThreshold`
   - Verdict = Block if any detection >= threshold; Flag if any < threshold; Allow if none

5. **Record and return** -- emit `ScanResult` with verdict, detections, sanitized text, and statistics

---

## Use-case recipes

### Public-facing chat API

```csharp
// Prioritize safety: stricter threshold, all default detectors on
var policy = Policy.PublicApi();
var filter = new NephronFilter(FilterOptions.FromPolicy(policy));

var result = filter.ScanInput(userPrompt);
if (result.Verdict == Verdict.Block)
{
	return BadRequest("Input policy violation");
}
```

### Security research tool

```csharp
// Researchers need to discuss jailbreaks without false positives
// Optionally add a phrase allowlist for specific attack names
var policy = Policy.Research() with
{
	PhraseAllowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		"L1B3RT4S",
		"OBLITERATUS",
		"G0DM0D3",
	},
};

var filter = new NephronFilter(FilterOptions.FromPolicy(policy));
var result = filter.ScanInput(researchText);
// The three allowlisted markers and the disabled persona families do not fire on input.
```

### Agent reading tool/MCP/RAG results

```csharp
// Paranoid on tool results: block at Low to catch subtle indirect injection
var policy = Policy.AgentToolResult();
var filter = new NephronFilter(FilterOptions.FromPolicy(policy));

var toolOutput = await mcpClient.Call(toolName, args);
var check = filter.ScanToolResult(toolOutput);
if (check.Verdict == Verdict.Block)
{
	throw new SecurityException("Poisoned tool result");
}
agent.AddMessage(check.SanitizedText);
```

### Telemetry-oriented deployment

```csharp
// Log non-Critical findings without blocking. Critical findings still block.
var policy = Policy.Permissive();
var filter = new NephronFilter(FilterOptions.FromPolicy(policy));

var result = filter.ScanInput(userPrompt);
foreach (var detection in result.Detections)
{
	logger.LogWarning("Detection: {0} severity={1}", detection.DetectorId, detection.Severity);
}
// result.Verdict == Verdict.Allow or Verdict.Flag, never Block (unless Critical)
```

---

## Compatibility

The public C# API uses standard .NET naming (`NephronFilter`, `FilterOptions`, `ScanInput`, and
similar PascalCase identifiers). The detector IDs and snake_case JSON field names are separate
configuration contracts and remain unchanged:

```csharp
var filter = new NephronFilter(FilterOptions.Default());
var result = filter.ScanInput(prompt);
// Block at High, all default detectors on
```

Renaming a detector ID or JSON field is a separate breaking change from renaming a C# symbol.

---

## Detector IDs

Use these IDs when defining custom rules. See [Detectors.md](Detectors.md) for full detector descriptions.

### Input detectors

- `persona.jailbreak`
- `persona.compliance_bypass`
- `persona.sysprompt`
- `instruction.override`
- `role.smuggling`
- `role.json_marker`
- `template.injection`
- `tool.hijack`
- `exfil.preflight`
- `known.markers`
- `encoding.leetspeak_keyword`
- `stego.unicode_tags`
- `stego.variation_selectors`
- `encoding.suspicion`

### Output detectors

- `output.markdown_image_beacon`
- `output.pii_leakage`
- `stego.unicode_tags`

### Tool-result detectors

- `output.hidden_instruction`
- `known.markers`
- `persona.sysprompt`
- `role.json_marker`
- `template.injection`
- `stego.unicode_tags`
- `stego.variation_selectors`
- `output.markdown_image_beacon`
