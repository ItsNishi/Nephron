#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def pct(part: int, total: int) -> float:
    return round(100.0 * part / total, 2) if total else 0.0


def choose_metadata_key(manifest_rows: list[dict[str, Any]], preferred: str | None) -> str | None:
    if preferred:
        return preferred
    keys = Counter()
    for row in manifest_rows:
        keys.update(row.get("metadata", {}).keys())
    for candidate in ("attack_name", "attack_family", "family", "label", "category", "class", "type"):
        if candidate in keys:
            return candidate
    return keys.most_common(1)[0][0] if keys else None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-jsonl", type=Path, required=True)
    parser.add_argument("--manifest-jsonl", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--metadata-key")
    parser.add_argument("--verdict", default="Allow")
    parser.add_argument("--max-records-per-family", type=int, default=100)
    args = parser.parse_args()

    scan_rows = load_jsonl(args.scan_jsonl)
    manifest_rows = load_jsonl(args.manifest_jsonl)
    by_record_id = {row.get("record_id"): row for row in manifest_rows if row.get("record_id")}
    by_sha256 = {row.get("sha256"): row for row in manifest_rows if row.get("sha256")}
    metadata_key = choose_metadata_key(manifest_rows, args.metadata_key)

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    verdicts = Counter(row.get("verdict") for row in scan_rows)
    missing_manifest = 0

    for scan in scan_rows:
        manifest = by_record_id.get(scan.get("record_id")) or by_sha256.get(scan.get("sha256"))
        if manifest is None:
            missing_manifest += 1
            continue
        if scan.get("verdict") != args.verdict:
            continue
        metadata = manifest.get("metadata", {})
        family = str(metadata.get(metadata_key, "<unlabeled>")) if metadata_key else "<unlabeled>"
        groups[family].append(
            {
                "record_id": scan.get("record_id"),
                "sha256": scan.get("sha256"),
                "bytes": scan.get("bytes"),
                "verdict": scan.get("verdict"),
                "severity": scan.get("severity"),
                "detectors": scan.get("detectors", []),
                "source_dataset": manifest.get("source_dataset"),
                "source_file": manifest.get("source_file"),
                "metadata": metadata,
            }
        )

    total_target_verdict = verdicts.get(args.verdict, 0)
    families = []
    for family, rows in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        families.append(
            {
                "family": family,
                "records": len(rows),
                "pct_of_verdict": pct(len(rows), total_target_verdict),
                "records_sample": rows[: args.max_records_per_family],
            }
        )

    report = {
        "scan_records": len(scan_rows),
        "manifest_records": len(manifest_rows),
        "missing_manifest": missing_manifest,
        "target_verdict": args.verdict,
        "target_verdict_records": total_target_verdict,
        "metadata_key": metadata_key,
        "verdicts": dict(verdicts),
        "families": families,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "target_verdict": args.verdict,
                "target_verdict_records": total_target_verdict,
                "metadata_key": metadata_key,
                "families": len(families),
                "output": args.out.as_posix(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
