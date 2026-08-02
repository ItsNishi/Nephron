#!/usr/bin/env python3
"""Measure what a small linear model would achieve vs the current phrase filter.

Cross-validated so numbers are honest (not fit-and-score on the same rows).
The model here is deliberately tiny: hashed char n-grams + logistic regression,
which is a weights table plus a dot product at inference -- portable to C# with
no runtime dependency.
"""

import argparse
import json
import re

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import make_pipeline


def Load_Jsonl(path):
	with open(path, encoding="utf-8") as fh:
		for line in fh:
			line = line.strip()
			if line:
				yield json.loads(line)


def Recall_At_Fp(y, scores, budget):
	"""Highest recall achievable while keeping FP rate <= budget."""
	pos = scores[y == 1]
	neg = np.sort(scores[y == 0])[::-1]
	k = int(len(neg) * budget)
	thresh = neg[k] if k < len(neg) else neg[-1] - 1e-9
	return float((pos > thresh).mean())


def main():
	ap = argparse.ArgumentParser()
	ap.add_argument("--manifest-jsonl", required=True)
	ap.add_argument("--scan-jsonl", required=True)
	ap.add_argument("--features", type=int, default=2 ** 18)
	args = ap.parse_args()

	verdicts = {r["record_id"]: r["verdict"] for r in Load_Jsonl(args.scan_jsonl)}

	texts, labels, nephron = [], [], []
	for rec in Load_Jsonl(args.manifest_jsonl):
		label = rec["metadata"].get("label")
		if label not in ("benign", "jailbreak"):
			continue
		try:
			with open(rec["text_path"], encoding="utf-8", errors="replace") as fh:
				texts.append(fh.read())
		except OSError:
			continue
		labels.append(1 if label == "jailbreak" else 0)
		nephron.append(0 if verdicts.get(rec["record_id"]) == "Allow" else 1)

	y = np.array(labels)
	neph = np.array(nephron)
	print(f"samples: {len(y)}  jailbreak: {int(y.sum())}  benign: {int((y == 0).sum())}")

	tp = int(((neph == 1) & (y == 1)).sum())
	fp = int(((neph == 1) & (y == 0)).sum())
	print(f"\nNephron today:  recall {tp / y.sum() * 100:.1f}%   FP {fp / (y == 0).sum() * 100:.2f}%")

	cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)

	configs = {
		"char_wb 3-5 hashed + logreg": make_pipeline(
			HashingVectorizer(analyzer="char_wb", ngram_range=(3, 5),
				n_features=args.features, alternate_sign=False, norm="l2"),
			LogisticRegression(max_iter=2000, C=4.0)),
		"word 1-2 tfidf + logreg": make_pipeline(
			TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2, sublinear_tf=True),
			LogisticRegression(max_iter=2000, C=4.0)),
	}

	for name, pipe in configs.items():
		scores = cross_val_predict(pipe, texts, y, cv=cv, method="predict_proba")[:, 1]
		print(f"\n{name}  (5-fold cross-validated)")
		for budget in (0.005, 0.0087, 0.02, 0.05):
			r = Recall_At_Fp(y, scores, budget)
			print(f"   recall @ {budget * 100:5.2f}% FP : {r * 100:5.1f}%")


if __name__ == "__main__":
	main()
