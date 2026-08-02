#!/usr/bin/env python3
"""Greedy set-cover: how much recall could ANY phrase list buy, at a given FP budget?

Upper bound only. Phrases are selected on the same data they are scored against,
so real-world recall would be lower. If the bound is low, phrase expansion is dead.
"""

import argparse
import json
import re
from collections import Counter, defaultdict


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
	ap.add_argument("--max-benign-pct", type=float, default=0.3)
	ap.add_argument("--budget", type=int, default=50)
	args = ap.parse_args()

	verdicts = {r["record_id"]: r["verdict"] for r in Load_Jsonl(args.scan_jsonl)}

	missed_docs = []
	benign_docs = []

	for rec in Load_Jsonl(args.manifest_jsonl):
		label = rec["metadata"].get("label")
		try:
			with open(rec["text_path"], encoding="utf-8", errors="replace") as fh:
				text = fh.read()
		except OSError:
			continue
		tokens = re.findall(r"[a-z']+", text.lower())
		grams = set()
		for n in (2, 3, 4, 5):
			grams.update(Ngrams(tokens, n))

		if label == "benign":
			benign_docs.append(grams)
		elif label == "jailbreak" and verdicts.get(rec["record_id"]) == "Allow":
			missed_docs.append(grams)

	n_missed = len(missed_docs)
	n_benign = len(benign_docs)
	print(f"missed jailbreaks: {n_missed}   benign: {n_benign}")

	benign_df = Counter()
	for grams in benign_docs:
		benign_df.update(grams)

	# Candidate phrases: appear in >=1% of missed, and under the benign FP budget.
	missed_df = Counter()
	for grams in missed_docs:
		missed_df.update(grams)

	max_benign_docs = n_benign * args.max_benign_pct / 100.0
	candidates = [
		g for g, c in missed_df.items()
		if c >= n_missed * 0.01 and benign_df.get(g, 0) <= max_benign_docs
	]
	print(f"candidate phrases (>=1% of missed, <={args.max_benign_pct}% of benign): {len(candidates)}")

	postings = defaultdict(set)
	for i, grams in enumerate(missed_docs):
		for g in grams:
			if g in postings or g in candidates:
				postings[g].add(i)
	cand_set = set(candidates)
	postings = {g: v for g, v in postings.items() if g in cand_set}

	covered = set()
	fp_docs = set()
	chosen = []
	print(f"\n{'#':>3} {'cum recall':>11} {'cum FP':>8}  phrase")
	for step in range(args.budget):
		best, best_gain = None, 0
		for g, docs in postings.items():
			gain = len(docs - covered)
			if gain > best_gain:
				best, best_gain = g, gain
		if best is None or best_gain == 0:
			break
		covered |= postings[best]
		for j, grams in enumerate(benign_docs):
			if best in grams:
				fp_docs.add(j)
		chosen.append(best)
		if step < 15 or (step + 1) % 10 == 0:
			print(f"{step + 1:>3} {len(covered) / n_missed * 100:10.1f}% "
				f"{len(fp_docs) / n_benign * 100:7.2f}%  {best}")

	print(f"\nCEILING with {len(chosen)} phrases: "
		f"recall on missed = {len(covered) / n_missed * 100:.1f}%, "
		f"added FP = {len(fp_docs) / n_benign * 100:.2f}%")


if __name__ == "__main__":
	main()
