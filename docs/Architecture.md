# Nephron architecture and technical notes

Nephron is a deterministic, zero-dependency guardrail. It normalizes text, runs channel-specific
detectors, applies policy, and returns an advisory verdict. It does not call an LLM or attempt to
prove that text is safe.

## Scan pipeline

```text
Raw text
  -> normalization
  -> channel detector list
  -> phrase allowlist and severity overrides
  -> threshold resolution
  -> ScanResult and statistics
```

The order is part of the behavior:

1. Normalize the text using the configured passes.
2. Select the input, output, or tool-result detector list.
3. Skip detectors disabled for that channel.
4. Run each detector against the normalized text.
5. Remove phrase-allowlisted findings, then apply detector severity overrides.
6. Resolve the channel threshold and calculate the verdict.
7. Record statistics and return the result.

Globally disabled detectors are removed when `FilterOptions.FromPolicy` builds the runtime options.
Channel-specific disables are evaluated during a scan. Phrase allowlisting takes precedence over
severity overrides because an allowlisted finding is removed entirely.

## Normalization order

Enabled normalization passes run in this fixed sequence:

1. Unicode NFKC normalization.
2. Zero-width and directional-mark removal.
3. Curated Cyrillic and Greek homoglyph folding.
4. Terminated HTML and C-style comment removal.
5. Optional whitespace collapsing and control-character removal.

Whitespace collapsing is off by default because it changes ordinary formatting more aggressively
than the other passes.

Unterminated comments remain literal, including the opening delimiter. Dropping the remainder of
an unterminated comment would hide it from every detector.

## Text and range coordinates

Detectors inspect normalized text, so `Detection.Range` refers to `ScanResult.SanitizedText`, not
the original input. A `MatchRange` is half-open: `Start` is inclusive and `End` is exclusive.

Normalization may remove characters or replace compatibility forms. Do not apply a detection range
directly to the original string unless the caller maintains its own position mapping.

## Channel boundaries

The channel APIs express different trust boundaries:

- `ScanInput` protects the model from untrusted user instructions.
- `ScanOutput` checks generated text before release or downstream processing.
- `ScanToolResult` protects an agent from indirect injection in MCP, plugin, tool, and RAG data.

A detector can be registered on multiple channels, but the default lists are intentionally
different. Tool results should not be routed through `ScanInput` merely because both are strings.

## Detection engines

Fixed-phrase detectors derive from `PhraseDetectorBase`, which builds an ASCII Aho-Corasick
automaton once when the detector is constructed. A scan then finds all registered phrases in one
linear pass over the input plus emitted matches.

Detectors with structural requirements use direct parsing or source-generated regular expressions.
The core avoids reflection and runtime regular-expression construction so Native AOT remains
supported.

## Threading and allocations

`NephronFilter` is reusable and thread-safe. Statistics use atomic operations, and temporary
detection storage is thread-local.

After thread-local scratch storage is initialized, a clean scan that requires no string
transformation produces no managed allocation. A scan with findings copies them into the returned
result so later scans cannot mutate an earlier result.

Changes to scanning, normalization, detector registration, or collection handling should run the
allocation tests in addition to the full test suite.

## Stable contracts

The following identifiers are external contracts even when their C# representation differs:

- Detector IDs such as `instruction.override`.
- Snake-case policy JSON fields such as `block_threshold`.
- Serialized preset names such as `Public_Api`.

Unknown detector IDs in policy configuration are ignored. Renaming a detector ID can therefore
silently disable an existing policy rule and is a breaking change.

`Detection.Reason` is diagnostic text, not a stable machine-readable identifier. Use `DetectorId`,
`Category`, and `Severity` for logic.

## Security boundaries

Nephron is one control in a layered design. Callers remain responsible for authentication,
authorization, tool approval, output encoding, secret isolation, and least-privilege execution.

Detailed detections should remain in trusted telemetry. Returning exact matching phrases or reasons
to an untrusted user can make iterative evasion easier.

Evaluation datasets are hostile input. Repository tooling reports aggregate metadata and does not
echo corpus payloads. See [Evaluation.md](Evaluation.md) for the measurement and reproduction
methodology.

## Extension points

`IDetector` is the primary extension boundary. A detector must provide a stable ID, category,
default severity, and a synchronous `Detect` implementation that appends findings to the supplied
collection.

Keep detector behavior deterministic, avoid clean-path allocations, and define benign near-misses
as regression tests. See [Detectors.md](Detectors.md) for the detector inventory and contribution
contract.
