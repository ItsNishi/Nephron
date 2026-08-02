# Contributing to Nephron

Thank you for helping improve Nephron. Changes should preserve its core properties: deterministic
behavior, a zero-dependency core library, Native AOT compatibility, and a low-allocation scan path.

## Prerequisites

- .NET 10 SDK
- Python 3 when reproducing the optional evaluation results

## Build and verification

Run these commands from the repository root:

```bash
dotnet restore Nephron.slnx --locked-mode
dotnet format Nephron.slnx --verify-no-changes --no-restore
dotnet build Nephron.slnx -c Release --no-restore
dotnet test Nephron.slnx -c Release --no-build
```

The core project treats warnings as errors. Document public types and non-obvious behavior; do not
add comments that only restate an identifier.

## Code style

- Use tabs and Allman braces in C#.
- Keep lines at or below 120 characters; prefer 100 where practical.
- Use standard .NET naming for the public API: PascalCase types and members, camelCase parameters.
- Prefer guard clauses, focused methods, and existing helpers over new abstraction layers.
- Keep one primary type per file and match its file name to the type name.

The repository's `.editorconfig` enforces the public API and parameter naming rules.

## Compatibility contracts

Detector IDs such as `role.smuggling`, snake_case policy JSON fields such as `block_threshold`,
and serialized preset names are stable configuration contracts. Renaming a C# symbol does not
authorize renaming those contracts. Add or update JSON regression tests for intentional changes.

The core library must remain free of NuGet dependencies. Integrations that require ASP.NET Core,
cloud services, ONNX, or LLM calls belong in separate packages.

## Detector changes

- Implement `IDetector`, or derive fixed-phrase detectors from `PhraseDetectorBase`.
- Add at least five malicious and five benign near-miss cases for a new detector.
- Mark malicious fixture strings with `// [MALICIOUS]`.
- Include metadata assertions for detector ID, category, and severity.
- Document the false-positive boundary, especially intentional omissions.
- Register the detector only on channels where its signal is useful.

Do not add broad keywords solely to improve a benchmark. A detector change must demonstrate useful
separation between malicious and ordinary production-like text.

## Performance

The clean scan path should remain allocation-free. Avoid LINQ, reflection, per-call regular
expression construction, and interface-based `foreach` loops on the hot path. Run the allocation
tests after changing scanning, normalization, collections, or detector registration.

## Evaluation safety

The public evaluation datasets contain live prompt-injection payloads. Follow
[`.eval/README.md`](.eval/README.md), keep corpora out of Git, and consume aggregate metadata rather
than copying payloads into issues, pull requests, or AI conversations.

## Pull requests

Keep pull requests focused. Include:

- The behavior or contract that changed.
- Tests that demonstrate the change.
- Commands used for verification.
- Any known limitations or follow-up work.

Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
