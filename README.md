# 🧬 Nephron — deterministic .NET LLM security guardrails

[![CI][ci-badge]][ci-workflow]
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4.svg)](https://dotnet.microsoft.com/)
[![Native AOT](https://img.shields.io/badge/Native%20AOT-compatible-2ea44f.svg)](docs/Architecture.md)

> Deterministic LLM input/output guardrail library for .NET. Layered detection traps malicious content before it reaches your model, and inspects model output and tool/RAG results for exfiltration markers before they reach your agent.

Named after the kidney's filter unit — many small filtering elements working in series. Catches what it can deterministically. Doesn't pretend to be unbreakable.

---

## ⚡ At a glance

| | |
|---|---|
| 🎯 **Recall (labeled sets)** | 52.1% on confirmed MS LLMail-Inject attacks, 24.2% on Mindgard evaded attacks |
| 🚫 **False positives** | 0.0% on 160 real benign emails, 0.87% on 2,997 labeled benign prompts |
| ⏱️ **Latency** | ~7μs mean, ~6μs median, ~11μs p99 per scan |
| 📦 **Dependencies** | Zero NuGet packages in core |
| ✅ **Tests** | xUnit suite, 0 warnings (`TreatWarningsAsErrors=true`) |
| 🔌 **Compatible** | .NET 10; core library is Native AOT-compatible |
| 🪶 **Footprint** | ~101 KB core assembly, no transitive dependencies |
| 🔧 **Configurable** | Policy engine with presets, JSON loading, phrase allowlist |

---

## 🛡️ What this is — and what it isn't

Nephron is **defense in depth**, not a magic bullet. No filter prevents jailbreaks 100%. Frontier-aligned models already resist most common attacks. Nephron is most valuable when:

- 🌐 You expose an LLM-backed API to untrusted users
- 🤖 Your agent reads tool/MCP/RAG content from sources you don't fully trust
- 🦙 You run smaller or locally-hosted models with weaker built-in alignment

### ✅ What Nephron does

- Strips encoding tricks before scanning — zero-width chars, homoglyphs, HTML comments, NFKC normalization
- Catches known prompt-injection phrasings, jailbreak personas, role-template smuggling
- Detects steganographic Unicode payloads — tag chars (U+E0000 range), variation-selector runs
- Catches catalogued jailbreak markers — `[GODMODE]`, `[START OUTPUT]`, `<NEW_PARADIGM>`, leetspeak openers
- Catches system-prompt-impersonation — `"You are Claude, an AI assistant..."` and similar self-descriptions in user input
- Flags markdown-image exfil beacons and PII leakage in model output
- Sub-millisecond per scan on commodity x86, and a clean scan allocates zero bytes (enforced by test)

### ❌ What Nephron does not do

- Run an ML classifier (no ONNX, no LLM-as-judge — pure deterministic detection)
- Catch novel paraphrased attacks not in its phrase lists
- Replace human review for sensitive deployments
- Replace model alignment, RLHF, or system-prompt design

---

## 📊 Measured detection rates

Measured on three public labeled datasets totaling 176,053 samples:

| Dataset and class | Samples | Result |
|---|---:|---:|
| Microsoft LLMail confirmed attacks | 24,437 | **52.1% caught** |
| Mindgard guardrail-evasion attacks | 11,313 | **24.2% caught** |
| Qualifire labeled jailbreaks | 2,003 | **10.7% caught** |
| Microsoft LLMail real benign email | 160 | **0.0% false positives** |
| Qualifire labeled benign prompts | 2,997 | **0.87% false positives** |

Results are dataset-specific: Nephron is strongest against known signatures and weaker against
paraphrased or adaptive attacks. See the [technical evaluation notes](docs/Evaluation.md) for full
tables, label caveats, limitations, and interpretation. The [evaluation harness](.eval/README.md)
reproduces the results. Last run: 2026-07-31.

---

## 📦 Install

The first public NuGet package has not been published yet. Until that release, reference the
project from a source checkout:

```bash
git clone https://github.com/ItsNishi/Nephron.git
dotnet add <your-project.csproj> reference Nephron/src/Nephron/Nephron.csproj
```

Requires .NET 10. The core library has zero transitive dependencies.

---

## 🚀 Quick start

```csharp
using Nephron;

var filter = new NephronFilter(FilterOptions.Default());

// 1. Filter user prompt before sending to LLM
var result = filter.ScanInput(userPrompt);
if (result.Verdict == Verdict.Block)
{
	// Keep detector IDs, matched phrases, and reasons in server-side logs. Returning
	// them to an untrusted caller makes adaptive bypass easier.
	logger.LogWarning("Nephron blocked input: {@Detections}", result.Detections);
	return BadRequest("Input policy violation.");
}

// 2. Pass the sanitized text — it has zero-width chars, homoglyphs, HTML
//    comments stripped. Pass that to the model rather than raw input.
var llmResponse = await llm.Generate(result.SanitizedText);

// 3. Scan model output for exfiltration markers, leaked PII, beacon URLs
var outputCheck = filter.ScanOutput(llmResponse);
if (outputCheck.Verdict == Verdict.Block)
{
	return BadRequest("Output policy violation.");
}

return Ok(outputCheck.SanitizedText);
```

### 🤖 Agent self-protection

For agent loops that call tools or read MCP/RAG content, scan results before they re-enter the prompt context. This is the highest-value use case — it stops poisoned tool output from injecting itself into your agent.

```csharp
var toolOutput = await mcpClient.Call(toolName, args);
var check = filter.ScanToolResult(toolOutput);
if (check.Verdict == Verdict.Block)
{
	throw new SecurityException("Indirect injection detected in tool result.");
}
agent.AddMessage(check.SanitizedText);
```

### ⚖️ Policy engine

v2.0 adds named `Policy` presets for common deployment patterns, with per-detector rules, phrase allowlist, and JSON loading:

```csharp
// Quick preset: block at Medium with every default detector enabled
var publicApiPolicy = Policy.PublicApi();
var publicApiFilter = new NephronFilter(FilterOptions.FromPolicy(publicApiPolicy));

// Custom policy
var customPolicy = Policy.Default() with
{
	PhraseAllowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "DAN" },
};
var customFilter = new NephronFilter(FilterOptions.FromPolicy(customPolicy));

// Load from JSON
var filePolicy = Policy.FromFile("./policies/public_api.json");
var fileFilter = new NephronFilter(FilterOptions.FromPolicy(filePolicy));
```

Five presets: **Default** (High threshold), **PublicApi** (Medium), **Research** (loose on input), **AgentToolResult** (paranoid on tool channel), **Permissive** (Critical only).

See [docs/Policy.md](docs/Policy.md) for the full reference. Detector IDs and policy JSON field
names remain stable even though the C# API now follows standard .NET naming conventions.

---

## 🧪 Detectors

18 detectors — 17 registered across three channels (14 input, 3 output, 8 tool-result; several run on more than one), plus `output.suspicious_url` which is opt-in because without a host allowlist it flags every URL. See [docs/Detectors.md](docs/Detectors.md) for the full reference. Highlights:

| Category | Examples |
|---|---|
| 🪪 **Persona / jailbreak** | DAN, Evil Assistant, system-prompt impersonation |
| 🚫 **Instruction override** | "ignore previous", "disregard above", "you are now" |
| 🎭 **Role smuggling** | `<\|im_start\|>`, `<\|fim_suffix\|>`, fake `<assistant_response>` tags |
| 🐉 **Known jailbreak markers** | `[GODMODE]`, `[START OUTPUT]`, `<NEW_PARADIGM>`, `[REBEL]`, leetspeak openers |
| 👻 **Unicode steganography** | Invisible tag characters, variation-selector runs |
| 📡 **Exfiltration** | Markdown image beacons, system-prompt extraction (plus opt-in URL allowlisting) |
| 🔐 **PII leakage** | SSN, Luhn-validated credit cards, AWS / GitHub / Slack tokens |

---

## 🏗️ Architecture

```
┌──────────────────┐     ┌────────────────────┐     ┌──────────────────┐
│  Raw input       │───▶ │ Normalization      │───▶ │ Detector chain   │
│                  │     │ NFKC + ZW strip +  │     │ Aho-Corasick     │
│                  │     │ homoglyph fold +   │     │ + custom logic   │
│                  │     │ comment strip      │     │                  │
└──────────────────┘     └────────────────────┘     └──────────────────┘
                                                              │
                                                              ▼
                                          ┌────────────────────────────┐
                                          │ Verdict aggregation        │
                                          │ (Allow / Flag / Block)     │
                                          │ + sanitized text + stats   │
                                          └────────────────────────────┘
```

- **Aho-Corasick automaton** for fixed-string phrase detection — single linear pass over input matches all phrases at once
- **`ReadOnlySpan<char>` hot path** — no allocations on the clean path
- **Normalization runs first** — encoding tricks die before pattern matching
- **Pluggable** — implement `IDetector` to add your own

See [docs/Architecture.md](docs/Architecture.md) for pipeline ordering, coordinate semantics,
threading, allocations, and compatibility contracts.

---

## 🔧 Build & run

```bash
# Build
dotnet build

# Test
dotnet test

# Try the demo
dotnet run --project src/Nephron.Demo -- --canary list
dotnet run --project src/Nephron.Demo -- --canary godmode

# Benchmark
dotnet run --project src/Nephron.Demo -c Release -- --bench

# Batch-scan a directory of files (metadata-only output, safe to pipe)
dotnet run --project src/Nephron.Demo -c Release -- --scan-dir /path/to/corpus
```

---

## 📚 Documentation

- [API guide](docs/API.md) — important public members, scan channels, and result semantics
- [Architecture and technical notes](docs/Architecture.md) — pipeline, performance, and contracts
- [Detector reference](docs/Detectors.md) — detector IDs, severities, and false-positive boundaries
- [Policy reference](docs/Policy.md) — presets, JSON schema, overrides, and resolution order
- [Evaluation notes](docs/Evaluation.md) — measured results, limitations, and reproduction

---

## 📚 Threat taxonomy reference

Detector design is grounded in the threat taxonomy at
[ItsNishi/AI-Agent-Security](https://github.com/ItsNishi/AI-Agent-Security):

- `notes/06_LLM_Jailbreaking_Deep_Dive.md` — jailbreak technique families
- `notes/02_Defense_Patterns.md` — encoding tricks and sanitization patterns
- `notes/01_Skill_Injection_Analysis.md` — indirect injection via tool/RAG content

Marker signatures derive from public red-team payload catalogs, principally `github.com/elder-plinius` (taxonomy only — no payload ingestion).

---

## 🗺️ Roadmap

The current source includes deterministic detection, the policy engine, and an allocation-free
scan path.

Under consideration, roughly in order of measured value:

- 🧠 **Embedded linear classifier** — the largest measured recall lever. A hashed
  char-n-gram model reaches 66% on a *held-out* corpus where the current detectors reach
  23.4%, at ~16 KB of int8 weights: a lookup table and a dot product, so no ONNX runtime,
  no NuGet dependency, and Native AOT stays intact. Needs a false-positive check against
  a real benign corpus before it could ship, and it trades away the "every detection
  names the phrase that matched" property.
- 🌊 **Streaming-aware output scanner** — scan model output as it streams
- 🧷 **Microsoft Spotlighting** delimiters for trust-level separation
- 🔗 **ASP.NET Core middleware** as a separate `Nephron.AspNetCore` package

Explicitly *not* planned: an ONNX model or LLM-as-judge in the core package. Both would
break the zero-dependency and AOT guarantees that are the reason to choose this library
over a heavier one.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for code style, compatibility contracts, detector test
requirements, and the release verification commands.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

---

## 📄 License

MIT — see [LICENSE](LICENSE).

[ci-badge]: https://github.com/ItsNishi/Nephron/actions/workflows/ci.yml/badge.svg
[ci-workflow]: https://github.com/ItsNishi/Nephron/actions/workflows/ci.yml
