#!/usr/bin/env python3
"""Rebuild the LLMail-Inject corpus with its labels intact.

The original prepare_corpora.py walked only dict *values*, so for the labelled
submission files -- which are {email_text: {attack_attempt, reason}} -- it wrote
out the labels and threw away every email. This reads the keys as the payload and
the values as metadata, which is what the file actually is.

Label semantics (from the challenge data):
  attack_attempt True/False/Unclear -- Unclear is excluded, it is not ground truth
  reason api_triggered -- the submission actually fired the tool API (confirmed hit)
  reason judge         -- an LLM judged it (weaker label)
"""

import argparse
import hashlib
import json
from pathlib import Path


def Normalize_Text(value: str) -> str:
	return value.replace("\r\n", "\n").replace("\r", "\n").strip()


def Coerce_Attack_Flag(value):
	"""Returns 'attack', 'benign', or None to skip. Handles str/bool/malformed."""
	if isinstance(value, bool):
		return "attack" if value else "benign"
	if isinstance(value, str):
		v = value.strip().lower()
		if v == "true":
			return "attack"
		if v == "false":
			return "benign"
		return None          # "unclear"
	return None              # malformed (one phase1 row is a list)


def Coerce_Reason(value):
	if isinstance(value, str):
		return value
	if isinstance(value, list) and value and isinstance(value[0], str):
		return value[0]
	return "unknown"


def main():
	ap = argparse.ArgumentParser()
	ap.add_argument("--corpus-dir", default=".eval/corpora/microsoft-llmail-inject-challenge/data")
	ap.add_argument("--out-dir", default=".eval/inputs/microsoft-llmail-inject-labelled")
	ap.add_argument("--manifest", default=".eval/outputs/manifests/microsoft-llmail-inject-labelled.jsonl")
	ap.add_argument("--limit-per-source", type=int, default=0, help="0 = no limit")
	args = ap.parse_args()

	corpus = Path(args.corpus_dir)
	out_dir = Path(args.out_dir)
	out_dir.mkdir(parents=True, exist_ok=True)
	Path(args.manifest).parent.mkdir(parents=True, exist_ok=True)

	seen_sha = set()
	stats = {"written": 0, "skipped_unclear": 0, "skipped_dupe": 0, "skipped_empty": 0}
	by_label = {}

	with open(args.manifest, "w", encoding="utf-8") as mf:

		def Emit(text, metadata, source_file, index):
			text = Normalize_Text(text)
			if not text:
				stats["skipped_empty"] += 1
				return
			raw = text.encode("utf-8")
			sha = hashlib.sha256(raw).hexdigest()
			if sha in seen_sha:
				stats["skipped_dupe"] += 1
				return
			seen_sha.add(sha)

			record_id = f"llmail-{metadata['phase']}-{index:06d}-{sha[:12]}"
			path = out_dir / f"{record_id}.txt"
			path.write_bytes(raw)

			mf.write(json.dumps({
				"record_id": record_id,
				"file": path.name,
				"text_path": str(path),
				"source_dataset": "microsoft/llmail-inject-challenge",
				"source_file": source_file,
				"source_fields": ["attack_attempt", "reason"],
				"metadata": metadata,
				"bytes": len(raw),
				"sha256": sha,
			}) + "\n")
			stats["written"] += 1
			by_label[metadata["label"]] = by_label.get(metadata["label"], 0) + 1

		for phase in (1, 2):
			src = corpus / f"labelled_unique_submissions_phase{phase}.json"
			print(f"reading {src.name} ...", flush=True)
			data = json.loads(src.read_text(encoding="utf-8"))
			n = 0
			for text, meta in data.items():
				if args.limit_per_source and n >= args.limit_per_source:
					break
				label = Coerce_Attack_Flag(meta.get("attack_attempt"))
				if label is None:
					stats["skipped_unclear"] += 1
					continue
				reason = Coerce_Reason(meta.get("reason"))
				Emit(text, {
					"label": label,
					"reason": reason,
					"phase": f"p{phase}",
					# strongest positive: the attack demonstrably fired the API
					"confirmed": "yes" if (label == "attack" and reason == "api_triggered") else "no",
				}, src.name, n)
				n += 1

		src = corpus / "emails_for_fp_tests.json"
		print(f"reading {src.name} ...", flush=True)
		for i, text in enumerate(json.loads(src.read_text(encoding="utf-8"))):
			if isinstance(text, str):
				Emit(text, {"label": "benign", "reason": "fp_test",
					"phase": "fp", "confirmed": "no"}, src.name, i)

	print(json.dumps({"stats": stats, "by_label": by_label}, indent=1))


if __name__ == "__main__":
	main()
