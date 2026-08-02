# Evaluation harness

Reproduces the detection numbers summarized in the project README and analyzed in the
[technical evaluation notes](../docs/Evaluation.md).

Only the scripts are tracked. The corpora, generated manifests, scan outputs, and the
Python virtualenv are deliberately not: they are hostile data, run to hundreds of
megabytes, and are not ours to redistribute. Everything below rebuilds from public
sources.

## Safety

These corpora are live jailbreak and prompt-injection payloads. Treat them as hostile
input, not as reading material:

- Do not read payload contents into an LLM context. The scripts emit aggregate metadata
  only, and `--scan-dir` reports verdicts rather than text.
- If an agent is doing the work, have it run the scripts and read the scores. Never have
  it open the corpus files.

## Setup

```bash
python3 -m venv .eval/tools/venv
.eval/tools/venv/bin/pip install -r .eval/requirements.txt
```

Two of the datasets are gated on Hugging Face and need
`.eval/tools/venv/bin/hf auth login` first.

## Acquire the pinned GitHub dataset

```bash
git clone https://github.com/liu00222/Open-Prompt-Injection.git \
  .eval/corpora/Open-Prompt-Injection
git -C .eval/corpora/Open-Prompt-Injection checkout \
  95290f7ce3794c4c52ad3fe8113db2bfcdfe89e0
```

## Rebuild the corpora

```bash
.eval/tools/venv/bin/python .eval/scripts/prepare_corpora.py \
  --root .eval \
  --github-open-prompt-injection .eval/corpora/Open-Prompt-Injection
```

Pulls and flattens:

| Dataset | Source | Revision |
|---|---|---|
| Qualifire prompt-injections-benchmark | `Qualifire/prompt-injections-benchmark` | `9ef1aa46a7e5` |
| Mindgard evaded samples | `Mindgard/evaded-prompt-injection-and-jailbreak-samples` | `ec63ffb26ba6` |
| Microsoft LLMail-Inject challenge | `microsoft/llmail-inject-challenge` | `1063bdf01ec8` |
| Open Prompt Injection | `liu00222/Open-Prompt-Injection` | `95290f7ce379` |

Then rebuild the LLMail corpus with its labels attached:

```bash
.eval/tools/venv/bin/python .eval/scripts/prepare_llmail_labelled.py
```

This one is separate because the labelled LLMail files are keyed
`{email_text: {attack_attempt, reason}}` — the payload is the dict *key*. The generic
preparer walks values only, so it wrote out the labels and discarded every email.

Label semantics:

- `attack_attempt` — `True` / `False` / `Unclear`. `Unclear` is excluded; it is not
  ground truth.
- `reason: api_triggered` — the submission demonstrably fired the tool API. This is the
  strongest positive label in the set.
- `reason: judge` — an LLM judged it. Weaker.
- `emails_for_fp_tests` — ordinary business email. The only true negative set here.

## Run

```bash
bash .eval/scripts/run_eval.sh        # Qualifire + Mindgard
```

For LLMail, scan and score directly:

```bash
dotnet run --project src/Nephron.Demo -c Release -- \
  --scan-dir .eval/inputs/microsoft-llmail-inject-labelled --format jsonl \
  > .eval/outputs/llmail.scan.jsonl

.eval/tools/venv/bin/python .eval/scripts/score_scan_jsonl.py \
  --scan-jsonl .eval/outputs/llmail.scan.jsonl \
  --manifest-jsonl .eval/outputs/manifests/microsoft-llmail-inject-labelled.jsonl \
  --out .eval/outputs/llmail.score.json
```

## Scripts

| Script | Purpose |
|---|---|
| `prepare_corpora.py` | Download and flatten public datasets into scannable text files |
| `prepare_llmail_labelled.py` | Rebuild LLMail with `attack_attempt` / `reason` metadata |
| `run_eval.sh` | Scan + score Qualifire and Mindgard |
| `score_scan_jsonl.py` | Join scan output to a manifest, emit rates by metadata key |
| `missed_by_family.py` | Break misses down by attack family |
| `analyze_scan_metadata.py` | Aggregate length/severity/detector statistics |
| `missed_ngrams.py` | Discriminative n-grams among missed attacks — is there phrase headroom? |
| `phrase_ceiling.py` | Greedy set-cover upper bound on what *any* phrase list could achieve |
| `ml_headroom.py` | Cross-validated linear-model baseline vs the current detectors |
| `ml_transfer.py` | Train on one corpus, test on another — catches dataset artifacts |

## Reading the results

Two findings from this harness are worth carrying forward, because they change how the
numbers should be read:

**Qualifire is a broken benchmark.** All 2,003 of its `jailbreak` samples contain the
literal word *jailbreak* (or "DAN mode" / "do anything now"); none of its 2,997 `benign`
samples do. One keyword separates the classes perfectly, so any tool matching that word
scores 100% while demonstrating nothing. `phrase_ceiling.py` and `ml_headroom.py` both
surface this independently. Do not compare scores on this corpus across tools.

**LLMail's "non-attack" class is not a false-positive set.** Those submissions were
written by people who were still trying to attack, and still contain chat-template
tokens and message JSON. Detector hit rates on that slice run at or above the attack
rate. The only sound false-positive measurement here is `emails_for_fp_tests`.
