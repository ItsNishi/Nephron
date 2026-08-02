#!/usr/bin/env python3
"""Does the qualifire-trained model generalize, or is it fitting a dataset artifact?

In-dataset CV said ~100%. This trains on qualifire and tests on mindgard attacks
(a different source). A large drop means the CV number was an artifact.
Also reports a source-blind sanity check: can a model separate the classes using
only length and punctuation? If yes, the dataset is separable for trivial reasons.
"""

import argparse
import json

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import make_pipeline


def Load_Jsonl(path):
	with open(path, encoding="utf-8") as fh:
		for line in fh:
			line = line.strip()
			if line:
				yield json.loads(line)


def Read_Corpus(manifest, label_key, want=None):
	texts, labels = [], []
	for rec in Load_Jsonl(manifest):
		lab = rec["metadata"].get(label_key)
		if want is not None and lab not in want:
			continue
		try:
			with open(rec["text_path"], encoding="utf-8", errors="replace") as fh:
				texts.append(fh.read())
		except OSError:
			continue
		labels.append(lab)
	return texts, labels


def main():
	ap = argparse.ArgumentParser()
	ap.add_argument("--qualifire-manifest", required=True)
	ap.add_argument("--mindgard-manifest", required=True)
	args = ap.parse_args()

	q_texts, q_labels = Read_Corpus(args.qualifire_manifest, "label", {"benign", "jailbreak"})
	y = np.array([1 if l == "jailbreak" else 0 for l in q_labels])
	print(f"qualifire: {len(y)} ({int(y.sum())} jailbreak / {int((y == 0).sum())} benign)")

	vec = HashingVectorizer(analyzer="char_wb", ngram_range=(3, 5),
		n_features=2 ** 18, alternate_sign=False, norm="l2")
	pipe = make_pipeline(vec, LogisticRegression(max_iter=2000, C=4.0))

	# Trivial-feature control: length + punctuation only, no lexical content.
	def Shape(texts):
		out = []
		for t in texts:
			n = len(t) or 1
			out.append([
				len(t), t.count("\n"), t.count("."), t.count(","), t.count("?"),
				t.count("!"), sum(c.isupper() for c in t) / n, sum(c.isdigit() for c in t) / n,
			])
		return np.array(out)

	shape_scores = cross_val_predict(
		LogisticRegression(max_iter=4000), Shape(q_texts), y,
		cv=StratifiedKFold(5, shuffle=True, random_state=0), method="predict_proba")[:, 1]
	neg = np.sort(shape_scores[y == 0])[::-1]
	thr = neg[int(len(neg) * 0.0087)]
	print(f"\nCONTROL -- length/punctuation only, no words:")
	print(f"   recall @ 0.87% FP : {(shape_scores[y == 1] > thr).mean() * 100:.1f}%")
	print("   (high here => the two classes differ in formatting, not in attack content)")

	pipe.fit(q_texts, y)
	q_neg_scores = pipe.predict_proba([t for t, l in zip(q_texts, y) if l == 0])[:, 1]
	thresh = np.sort(q_neg_scores)[::-1][int(len(q_neg_scores) * 0.0087)]
	print(f"\ntrained on qualifire; threshold set for 0.87% FP on qualifire benign = {thresh:.4f}")

	m_texts, _ = Read_Corpus(args.mindgard_manifest, "attack_name")
	m_scores = pipe.predict_proba(m_texts)[:, 1]
	print(f"\nTRANSFER -> mindgard attacks (n={len(m_texts)}, all malicious):")
	print(f"   flagged at that threshold : {(m_scores > thresh).mean() * 100:.1f}%")
	print(f"   (qualifire in-dataset CV recall was ~100% -- compare)")


if __name__ == "__main__":
	main()
