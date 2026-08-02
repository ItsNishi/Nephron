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
    return round((part / total) * 100, 2) if total else 0.0


def length_bucket(size: int) -> str:
    if size < 500:
        return "<500B"
    if size < 2_000:
        return "500B-2KB"
    if size < 10_000:
        return "2KB-10KB"
    if size < 50_000:
        return "10KB-50KB"
    return ">=50KB"


def detector_family(detector: str) -> str:
    if detector.startswith("persona."):
        return "persona"
    if detector.startswith("instruction."):
        return "instruction_override"
    if detector.startswith("stego.") or detector.startswith("encoding."):
        return "encoding_stego"
    if detector.startswith("role."):
        return "role_smuggling"
    if detector.startswith("tool."):
        return "tool_hijack"
    if detector.startswith("exfil.") or detector.startswith("output.markdown_image_beacon"):
        return "exfiltration"
    if detector.startswith("known."):
        return "known_jailbreak_marker"
    if detector.startswith("output."):
        return "output_safety"
    return "other"


def summarize_counter(counter: Counter[str], total: int) -> list[dict[str, Any]]:
    return [
        {"value": key, "records": count, "pct": pct(count, total)}
        for key, count in counter.most_common()
    ]


def summarize_group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    verdicts = Counter(row["verdict"] for row in rows)
    severities = Counter(row["severity"] for row in rows)
    detectors: Counter[str] = Counter()
    detector_families: Counter[str] = Counter()
    for row in rows:
        for detector in row.get("detectors", []):
            detectors[detector] += 1
            detector_families[detector_family(detector)] += 1
    return {
        "records": total,
        "verdicts": summarize_counter(verdicts, total),
        "rates": {
            "block_pct": pct(verdicts.get("Block", 0), total),
            "flag_pct": pct(verdicts.get("Flag", 0), total),
            "allow_pct": pct(verdicts.get("Allow", 0), total),
            "caught_pct": pct(verdicts.get("Block", 0) + verdicts.get("Flag", 0), total),
        },
        "severities": summarize_counter(severities, total),
        "detector_families": summarize_counter(detector_families, total),
        "detectors": summarize_counter(detectors, total),
    }


def build_summary(scan_rows: list[dict[str, Any]], manifest_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_record_id = {row.get("record_id"): row for row in manifest_rows if row.get("record_id")}
    by_sha256 = {row.get("sha256"): row for row in manifest_rows if row.get("sha256")}

    joined: list[dict[str, Any]] = []
    missing_manifest = 0
    for scan in scan_rows:
        manifest = by_record_id.get(scan.get("record_id")) or by_sha256.get(scan.get("sha256"))
        if manifest is None:
            missing_manifest += 1
            manifest = {}
        joined.append({**scan, "_manifest": manifest})

    metadata_keys = Counter()
    for row in joined:
        metadata = row["_manifest"].get("metadata", {})
        metadata_keys.update(metadata.keys())

    by_metadata: dict[str, dict[str, Any]] = {}
    for key, _count in metadata_keys.most_common(25):
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in joined:
            metadata = row["_manifest"].get("metadata", {})
            if key in metadata:
                grouped[str(metadata[key])].append(row)
        by_metadata[key] = {
            value: summarize_group(group_rows)
            for value, group_rows in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0]))[:50]
        }

    metadata_rollups: dict[str, list[dict[str, Any]]] = {}
    for key, groups in by_metadata.items():
        rows: list[dict[str, Any]] = []
        for value, group_summary in groups.items():
            rows.append(
                {
                    "value": value,
                    "records": group_summary["records"],
                    **group_summary["rates"],
                    "top_detector_families": group_summary["detector_families"][:8],
                    "top_detectors": group_summary["detectors"][:8],
                }
            )
        metadata_rollups[key] = sorted(rows, key=lambda row: (-row["records"], row["value"]))

    by_bucket: dict[str, Any] = {}
    for bucket in ["<500B", "500B-2KB", "2KB-10KB", "10KB-50KB", ">=50KB"]:
        group = [row for row in joined if length_bucket(int(row.get("bytes", 0))) == bucket]
        if group:
            by_bucket[bucket] = summarize_group(group)

    by_source_file: dict[str, Any] = {}
    grouped_sources: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in joined:
        source = row["_manifest"].get("source_file", "<missing>")
        grouped_sources[source].append(row)
    for source, group in sorted(grouped_sources.items(), key=lambda item: (-len(item[1]), item[0])):
        by_source_file[source] = summarize_group(group)

    return {
        "records": len(joined),
        "missing_manifest": missing_manifest,
        "overall": summarize_group(joined),
        "by_length_bucket": by_bucket,
        "by_source_file": by_source_file,
        "by_metadata": by_metadata,
        "metadata_rollups": metadata_rollups,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-jsonl", type=Path, required=True)
    parser.add_argument("--manifest-jsonl", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    summary = build_summary(load_jsonl(args.scan_jsonl), load_jsonl(args.manifest_jsonl))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "records": summary["records"],
                "missing_manifest": summary["missing_manifest"],
                "output": args.out.as_posix(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
