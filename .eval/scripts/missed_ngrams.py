#!/usr/bin/env python3
"""Aggregate-only analysis of missed jailbreak samples.

Emits n-gram counts and discriminative ratios. Prints no full payloads.
"""

import argparse
import json
import re
from collections import Counter


def Load_Jsonl(path):
	with open(path, encoding="utf-8") as fh:
		for line in fh:
			line = line.strip()
			if line:
				yield json.loads(line)


def Ngrams(tokens, n):
	for i in range(len(tokens) - n + 1):
		yield " ".join(tokens[i:i + n])


def main():
	ap = argparse.ArgumentParser()
	ap.add_argument("--manifest-jsonl", required=True)
	ap.add_argument("--scan-jsonl", required=True)
	ap.add_argument("--label-key", default="label")
	ap.add_argument("--positive-label", default="jailbreak")
	ap.add_argument("--negative-label", default="benign")
	ap.add_argument("--top", type=int, default=40)
	args = ap.parse_args()

	verdicts = {r["record_id"]: r["verdict"] for r in Load_Jsonl(args.scan_jsonl)}

	missed = Counter()
	caught = Counter()
	benign = Counter()
	counts = {"missed": 0, "caught": 0, "benign": 0}
	lengths = {"missed": [], "caught": []}

	for rec in Load_Jsonl(args.manifest_jsonl):
		label = rec["metadata"].get(args.label_key)
		verdict = verdicts.get(rec["record_id"])
		try:
			with open(rec["text_path"], encoding="utf-8", errors="replace") as fh:
				text = fh.read()
		except OSError:
			continue

		tokens = re.findall(r"[a-z']+", text.lower())
		grams = set()
		for n in (2, 3, 4):
			grams.update(Ngrams(tokens, n))

		if label == args.negative_label:
			benign.update(grams)
			counts["benign"] += 1
		elif label == args.positive_label:
			bucket = "missed" if verdict == "Allow" else "caught"
			counts[bucket] += 1
			lengths[bucket].append(len(text))
			(missed if bucket == "missed" else caught).update(grams)

	print(json.dumps({"counts": counts}, indent=1))
	for k in ("missed", "caught"):
		v = sorted(lengths[k])
		if v:
			print(f"{k}: n={len(v)} median_bytes={v[len(v) // 2]} p90={v[int(len(v) * 0.9)]} max={max(v)}")

	n_missed = counts["missed"] or 1
	n_benign = counts["benign"] or 1

	print(f"\n== n-grams frequent in MISSED jailbreaks, rare in benign (top {args.top}) ==")
	print(f"{'missed%':>8} {'benign%':>8} {'ratio':>7}  ngram")
	rows = []
	for gram, cnt in missed.items():
		if cnt < n_missed * 0.02:
			continue
		m_pct = cnt / n_missed * 100
		b_pct = benign.get(gram, 0) / n_benign * 100
		ratio = m_pct / b_pct if b_pct > 0 else float("inf")
		rows.append((ratio, m_pct, b_pct, cnt, gram))

	rows.sort(key=lambda r: (-r[0], -r[1]))
	for ratio, m_pct, b_pct, cnt, gram in rows[:args.top]:
		r = "inf" if ratio == float("inf") else f"{ratio:.1f}"
		print(f"{m_pct:7.1f}% {b_pct:7.2f}% {r:>7}  {gram}")

	print(f"\n== highest-coverage n-grams in MISSED (any benign rate) ==")
	for gram, cnt in missed.most_common(25):
		b_pct = benign.get(gram, 0) / n_benign * 100
		print(f"{cnt / n_missed * 100:7.1f}% {b_pct:7.2f}%          {gram}")


if __name__ == "__main__":
	main()
