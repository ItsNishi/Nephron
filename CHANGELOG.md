# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added contributor guidance, a private vulnerability-reporting policy, and repository-enforced
  public API naming rules.

### Changed

- Pinned test dependencies, evaluation dataset revisions, and CI actions for reproducible builds
  and evaluation runs.
- Canary commands now validate each fixture's expected verdict, including clean and flag-only
  fixtures, instead of assuming every canary must block.
- Condensed the README evaluation results and moved the methodology, detailed tables, and dataset
  caveats into a dedicated technical note.

### Breaking

- Renamed the public C# API to standard .NET identifiers. Representative changes include
  `Nephron_Filter` to `NephronFilter`, `Filter_Options` to `FilterOptions`, `Scan_Result` to
  `ScanResult`, `Scan_Input` to `ScanInput`, and detector types from `<Name>_Detector` to
  `<Name>Detector`.
- Renamed public properties and enum members to PascalCase without underscores, such as
  `Detector_Id` to `DetectorId`, `Sanitized_Text` to `SanitizedText`, and
  `Detection_Category.Role_Smuggling` to `DetectionCategory.RoleSmuggling`.
- Detector IDs such as `role.smuggling`, snake_case policy JSON fields such as
  `block_threshold`, and existing preset `name` values are unchanged.

## [2.1.0] - 2026-07-31

### ⚠️ Breaking

Three `Detector_Id` values were renamed to remove vendor and brand-specific naming.
**Policy JSON referencing the old ids will silently stop matching** — unknown detector
ids are ignored rather than rejected, so a stale rule fails quietly rather than erroring.

| Old id | New id |
|---|---|
| `pliny.markers` | `known.markers` |
| `persona.dan` | `persona.jailbreak` |
| `persona.evil_assistant` | `persona.compliance_bypass` |

Corresponding type and enum renames:

| Old | New |
|---|---|
| `Pliny_Markers_Detector` | `Known_Marker_Detector` |
| `Evil_Assistant_Detector` | `Compliance_Bypass_Detector` |
| `Detection_Category.Pliny_Marker` | `Detection_Category.Known_Marker` |

`persona.jailbreak` no longer carries DAN-specific phrases (`do anything now`,
`you are dan`, `act as dan`).

### Security

- **Unterminated comment truncation.** An unterminated `<!--` or `/*` caused the
  normalizer to drop all remaining input, so any payload after the delimiter reached
  no detector and the scan returned `Allow` with zero detections. A caller who scanned
  with Nephron but sent the original text to the model got that payload through
  entirely unscanned. Unterminated delimiters are now retained as literal text;
  terminated comments are still stripped.

### Added

- `template.injection` — detects template interpolation of configuration keywords,
  e.g. `${system_prompt}`, `{{instructions}}`. Tolerates internal whitespace.
- `role.json_marker` — detects fake chat-message JSON claiming a privileged role,
  e.g. `"role": "system"`. Deliberately ignores `"role": "user"` and `"role": "tool"`.
- Security-bypass phrasings in `persona.jailbreak` (`bypass the guardrails`,
  `uncensored mode`, `unfiltered response`, ...).
- Hash-count and spacing variants of the `### system:` separator in `role.smuggling`
  and `output.hidden_instruction`.
- `Allocation_Tests` — asserts the clean scan path allocates zero bytes, so the
  performance claim cannot silently regress.

### Changed

- **The clean scan path now allocates zero bytes** (was ~216 bytes plus roughly 27
  objects per scan). `Aho_Corasick.Find_All` returns a ref-struct enumerator instead
  of taking a callback; phrase dedup uses a stack bitset instead of a `HashSet`; the
  scan loops are indexed rather than `foreach` over `IReadOnlyList<T>`; the detection
  list is a reused per-thread scratch copied out only when there are hits.
- Latency improved from ~8.3 µs to ~7.3 µs mean, ~13.3 µs to ~11.0 µs p99.
- `Pii_Leakage_Detector`, `Markdown_Image_Beacon_Detector`, and
  `Suspicious_Url_Detector` migrated from `RegexOptions.Compiled` to
  `[GeneratedRegex]`. `Compiled` is AOT-compatible but falls back to the interpreter
  under Native AOT; source-generated regexes compile at build time.
- Documentation now reports measured recall and false-positive rates against labelled
  corpora with ground truth, and states plainly which figures are not recall.
- `Suspicious_Url_Detector` is documented as opt-in. It was always registered on no
  channel -- without a host allowlist it flags every URL -- but nothing said so.

### Fixed

- Documented figures corrected: the previous per-repo "block rate" table measured the
  share of *all* text files in a repository tree that tripped a detector — including
  application source and tooling that were never attacks — and was presented as recall.

## [2.0.0]

### Added

- Policy engine: named presets (`Default`, `Public_Api`, `Research`,
  `Agent_Tool_Result`, `Permissive`), per-detector severity overrides and
  enable/disable, per-channel rules, phrase allowlist, and JSON loading via
  `Policy.From_Json` / `Policy.From_File`.

## [1.0.0]

### Added

- Initial release: normalization pipeline (NFKC, zero-width stripping, homoglyph
  folding, comment stripping) and deterministic detectors for prompt injection,
  jailbreak personas, role smuggling, known jailbreak markers, Unicode
  steganography, leetspeak obfuscation, PII leakage, and exfiltration beacons.
