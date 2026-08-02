# Evaluation technical notes

Nephron was evaluated against three public labeled datasets totaling 176,053 samples. Each result
uses the dataset's own labels; there is no aggregate score across corpora. A sample is "caught" when
the scan returns either `Flag` or `Block`.

Nephron is a deterministic signature-and-normalization filter. Recall measures how closely a sample
matches known phrasing, so it is low against paraphrased and adversarially evaded attacks by design.
The results below are measurements, not estimates of protection in every deployment.

Last run against the current tree: 2026-07-31.

## Summary

| Dataset and class | Samples | Result |
|---|---:|---:|
| Microsoft LLMail confirmed attacks | 24,437 | 52.1% caught |
| Mindgard guardrail-evasion attacks | 11,313 | 24.2% caught |
| Qualifire labeled jailbreaks | 2,003 | 10.7% caught |
| Microsoft LLMail real benign email | 160 | 0.0% false positives |
| Qualifire labeled benign prompts | 2,997 | 0.87% false positives |

## Microsoft LLMail-Inject challenge

The Microsoft `llmail-inject-challenge` corpus contains 159,740 labeled submissions from an email
injection competition. It is the largest and most representative corpus in this evaluation:
indirect injection delivered through email, which is a primary Nephron use case.

| Group | Samples | Caught |
|---|---:|---:|
| Confirmed attacks (`api_triggered`) | 24,437 | 52.1% |
| Judge-labeled attacks | 123,243 | 30.1% |
| Judge-labeled non-attacks | 11,900 | 47.2% |
| Real benign emails (`emails_for_fp_tests`) | 160 | 0.0% |

`api_triggered` means the submission demonstrably fired the tool API and is the strongest positive
label in the dataset. The judge-labeled groups are weaker because an LLM assigned those labels.

The judge-labeled non-attack group is not a false-positive set. Its submissions were written by
people still trying to attack and contain chat-template tokens and message JSON. The 47.2% hit rate
therefore must not be reported as a production false-positive rate.

Within that adversarial group, `role.smuggling` fires on 50.6% of attacks and 48.4% of non-attacks.
The per-phrase lift for `<|assistant|>` is 1.0; the lift for `<|system|>` and `<|im_end|>` is below
1.0. `role.json_marker` fires on 22.9% of non-attacks and 3.98% of attacks, a lift of 0.17. Removing
the non-discriminative detectors reduces recall on confirmed attacks to roughly 2%.

Against production-like traffic, Nephron catches about half of the confirmed-successful injections
without firing on the benign email set. The 0.0% result covers only 160 messages, so it is useful but
thin evidence.

### Signature decay

Recall drops from 39.1% in competition phase 1 to 11.4% in phase 2 as attackers iterated against
the defenses. This is the expected weakness of a deterministic signature system under an adaptive
adversary.

## Qualifire prompt-injections benchmark

The Qualifire `prompt-injections-benchmark` contains 5,000 human-labeled samples.

| Label | Samples | Blocked | Flagged | Caught |
|---|---:|---:|---:|---:|
| `jailbreak` | 2,003 | 200 | 15 | 10.7% |
| `benign` | 2,997 | 19 | 7 | 0.87% false positives |

This benchmark is separable by a single keyword. Every `jailbreak` sample contains the literal word
*jailbreak*, "DAN mode", or "do anything now"; none of its benign samples do. A detector matching
that one feature could score 100% without demonstrating useful general detection. Nephron does not
add it solely to improve this benchmark, so the 10.7% result should not be compared across tools as
if it measured real-world effectiveness.

## Mindgard evaded attacks

The Mindgard `evaded-prompt-injection-and-jailbreak-samples` corpus contains 11,313 samples. Every
sample was adversarially mutated to evade guardrails. Nephron catches 24.2% overall.

| Attack family | Samples | Caught |
|---|---:|---:|
| Unicode Tags Smuggling | 553 | 100% |
| Emoji Smuggling | 553 | 100% |
| Numbers | 553 | 29.5% |
| Word substitution | 4,404 | 13–16% |
| Unicode obfuscation | 4,977 | 14.1% |
| Pruthi | 273 | 6.2% |

The word-substitution group includes PWWS, Alzantot, Deep Word Bug, BERT-Attack, TextFooler, BAE,
and TextBugger. The Unicode-obfuscation group includes Zero Width, Homoglyphs, Full Width,
Diacritics, Bidirectional, Deletion Chars, Upside Down, Accent Marks, and Spaces.

All nine Unicode-obfuscation families measure exactly 14.1%. One plausible interpretation is that
normalization collapses each variant to the same underlying payload set, after which phrase coverage
determines the result. That interpretation is an inference, not a separate measurement.

## False-positive evidence

Two verified results use different negative classes:

- 0.0% on 160 real benign emails from the Microsoft LLMail false-positive set.
- 0.87% on 2,997 labeled benign prompts from Qualifire, or 99.1% pass-through.

An earlier check on 148 files of legitimate technical writing measured 97% pass-through outside
files explicitly discussing jailbreak techniques, with 25 of 25 curated typical prompts allowed.
That check has not been rerun against the current tree and is not treated as a verified result.

## Reproduction

The [evaluation harness](../.eval/README.md) documents the pinned dataset revisions, setup, corpus
preparation, scan commands, scoring, and analysis scripts. The corpora are not redistributed because
they contain live attack payloads and are not ours to ship.
