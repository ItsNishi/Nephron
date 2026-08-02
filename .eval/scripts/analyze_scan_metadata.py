#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import statistics
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = ROOT / "outputs"
MANIFESTS = OUTPUTS / "manifests"

DATASETS = {
    "qualifire-prompt-injections-benchmark": {
        "scan": OUTPUTS / "qualifire-prompt-injections-benchmark.scan.tsv",
        "records_dir": ROOT / "inputs" / "qualifire-prompt-injections-benchmark-records",
        "manifest": MANIFESTS / "qualifire-prompt-injections-benchmark.json",
    },
    "mindgard-evaded-prompt-injection-and-jailbreak-samples": {
        "scan": OUTPUTS / "mindgard-evaded-prompt-injection-and-jailbreak-samples.scan.tsv",
        "records_dir": ROOT / "inputs" / "mindgard-evaded-prompt-injection-and-jailbreak-samples-records",
        "manifest": MANIFESTS / "mindgard-evaded-prompt-injection-and-jailbreak-samples.json",
    },
}


def quantiles(values: list[int]) -> dict[str, float | int | None]:
    if not values:
        return {
            "count": 0,
            "min": None,
            "p25": None,
            "median": None,
            "p75": None,
            "p90": None,
            "p95": None,
            "p99": None,
            "max": None,
            "mean": None,
        }
    ordered = sorted(values)

    def pct(percent: float) -> int:
        if len(ordered) == 1:
            return ordered[0]
        rank = round((len(ordered) - 1) * percent)
        return ordered[rank]

    return {
        "count": len(ordered),
        "min": ordered[0],
        "p25": pct(0.25),
        "median": int(statistics.median(ordered)),
        "p75": pct(0.75),
        "p90": pct(0.90),
        "p95": pct(0.95),
        "p99": pct(0.99),
        "max": ordered[-1],
        "mean": round(statistics.fmean(ordered), 2),
    }


def record_metrics(path: Path) -> dict[str, int]:
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    controls = 0
    format_chars = 0
    tags = 0
    variation_selectors = 0
    non_ascii = 0
    replacement_chars = 0
    for char in text:
        code = ord(char)
        category = unicodedata.category(char)
        if code > 0x7F:
            non_ascii += 1
        if category == "Cc" and char not in "\n\r\t":
            controls += 1
        if category == "Cf":
            format_chars += 1
        if 0xE0000 <= code <= 0xE007F:
            tags += 1
        if 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF:
            variation_selectors += 1
        if char == "\ufffd":
            replacement_chars += 1
    return {
        "file_bytes": len(raw),
        "chars": len(text),
        "lines": text.count("\n") + (0 if not text else int(not text.endswith("\n"))),
        "non_ascii_chars": non_ascii,
        "control_chars_excluding_whitespace": controls,
        "format_chars": format_chars,
        "tag_chars": tags,
        "variation_selectors": variation_selectors,
        "unicode_replacement_chars": replacement_chars,
    }


def load_manifest(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {row["file"]: row for row in data.get("records", [])}


def load_scan(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def pct(part: int, total: int) -> float:
    return round((part / total) * 100, 2) if total else 0.0


def table(headers: list[str], rows: list[list[Any]]) -> str:
    rendered = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        rendered.append("| " + " | ".join(str(item) for item in row) + " |")
    return "\n".join(rendered)


def summarize_dataset(name: str, cfg: dict[str, Path]) -> dict[str, Any]:
    manifest = load_manifest(cfg["manifest"])
    scan_rows = load_scan(cfg["scan"])
    enriched: list[dict[str, Any]] = []
    missing_files: list[str] = []
    malformed_scan_rows = 0
    for row in scan_rows:
        if not row.get("path"):
            malformed_scan_rows += 1
            continue
        record_path = Path(row["path"])
        if not record_path.is_absolute():
            record_path = (ROOT.parent / record_path).resolve()
        if not record_path.exists():
            candidate = cfg["records_dir"] / Path(row["path"]).name
            record_path = candidate
        if not record_path.exists():
            missing_files.append(Path(row["path"]).name)
            metrics = {
                "file_bytes": manifest.get(Path(row["path"]).name, {}).get("bytes", 0),
                "chars": 0,
                "lines": 0,
                "non_ascii_chars": 0,
                "control_chars_excluding_whitespace": 0,
                "format_chars": 0,
                "tag_chars": 0,
                "variation_selectors": 0,
                "unicode_replacement_chars": 0,
            }
        else:
            metrics = record_metrics(record_path)
        enriched.append(
            {
                "verdict": row["verdict"],
                "severity": row["severity"],
                "n_detections": int(row["n_detections"]),
                "top_detector": row["top_detector"] or "<none>",
                "manifest_bytes": manifest.get(Path(row["path"]).name, {}).get("bytes"),
                **metrics,
            }
        )

    by_verdict: dict[str, Any] = {}
    for verdict in sorted({row["verdict"] for row in enriched}):
        group = [row for row in enriched if row["verdict"] == verdict]
        by_verdict[verdict] = {
            "records": len(group),
            "pct": pct(len(group), len(enriched)),
            "manifest_bytes": quantiles([row["manifest_bytes"] for row in group if row["manifest_bytes"] is not None]),
            "file_bytes": quantiles([row["file_bytes"] for row in group]),
            "chars": quantiles([row["chars"] for row in group]),
            "lines": quantiles([row["lines"] for row in group]),
        }

    detector_breakdown: dict[str, Any] = {}
    for detector, count in Counter(row["top_detector"] for row in enriched).most_common():
        group = [row for row in enriched if row["top_detector"] == detector]
        detector_breakdown[detector] = {
            "records": count,
            "pct": pct(count, len(enriched)),
            "verdicts": dict(sorted(Counter(row["verdict"] for row in group).items())),
            "severities": dict(sorted(Counter(row["severity"] for row in group).items())),
            "median_bytes": quantiles([row["file_bytes"] for row in group])["median"],
        }

    severity_breakdown: dict[str, Any] = {}
    for severity, count in sorted(Counter(row["severity"] for row in enriched).items()):
        group = [row for row in enriched if row["severity"] == severity]
        severity_breakdown[severity] = {
            "records": count,
            "pct": pct(count, len(enriched)),
            "verdicts": dict(sorted(Counter(row["verdict"] for row in group).items())),
            "detectors": dict(Counter(row["top_detector"] for row in group).most_common(10)),
        }

    unicode_totals = {
        key: sum(row[key] for row in enriched)
        for key in [
            "non_ascii_chars",
            "control_chars_excluding_whitespace",
            "format_chars",
            "tag_chars",
            "variation_selectors",
            "unicode_replacement_chars",
        ]
    }
    unicode_records = {
        key: sum(1 for row in enriched if row[key] > 0)
        for key in unicode_totals
    }

    length_buckets = Counter()
    for row in enriched:
        size = row["file_bytes"]
        if size < 500:
            length_buckets["<500B"] += 1
        elif size < 2_000:
            length_buckets["500B-2KB"] += 1
        elif size < 10_000:
            length_buckets["2KB-10KB"] += 1
        elif size < 50_000:
            length_buckets["10KB-50KB"] += 1
        else:
            length_buckets[">=50KB"] += 1

    detection_counts = Counter(row["n_detections"] for row in enriched)
    by_verdict_detector: dict[str, dict[str, int]] = defaultdict(dict)
    for verdict in sorted({row["verdict"] for row in enriched}):
        group = [row for row in enriched if row["verdict"] == verdict]
        by_verdict_detector[verdict] = dict(Counter(row["top_detector"] for row in group).most_common(15))

    return {
        "dataset": name,
        "records": len(enriched),
        "scan_rows": len(scan_rows),
        "manifest_records": len(manifest),
        "missing_files": len(missing_files),
        "malformed_scan_rows": malformed_scan_rows,
        "overall": {
            "manifest_bytes": quantiles([row["manifest_bytes"] for row in enriched if row["manifest_bytes"] is not None]),
            "file_bytes": quantiles([row["file_bytes"] for row in enriched]),
            "chars": quantiles([row["chars"] for row in enriched]),
            "lines": quantiles([row["lines"] for row in enriched]),
        },
        "length_buckets": dict(length_buckets),
        "by_verdict": by_verdict,
        "severity_breakdown": severity_breakdown,
        "detector_breakdown": detector_breakdown,
        "by_verdict_detector": by_verdict_detector,
        "detection_count_distribution": dict(sorted(detection_counts.items())),
        "unicode_totals": unicode_totals,
        "unicode_records": unicode_records,
    }


def markdown_report(summary: dict[str, Any]) -> str:
    parts = [
        "# Nephron Eval Metadata Review",
        "",
        "This report contains only aggregate metadata. It intentionally omits payload text and content-derived examples.",
        "",
    ]
    for name, data in summary["datasets"].items():
        parts.extend([f"## {name}", ""])
        parts.append(
            table(
                ["metric", "value"],
                [
                    ["scan rows", data["scan_rows"]],
                    ["manifest records", data["manifest_records"]],
                    ["missing files", data["missing_files"]],
                    ["malformed scan rows skipped", data["malformed_scan_rows"]],
                ],
            )
        )
        parts.extend(["", "### Overall length stats", ""])
        parts.append(
            table(
                ["measure", "count", "min", "p25", "median", "p75", "p90", "p95", "p99", "max", "mean"],
                [
                    [measure, *[stats[key] for key in ["count", "min", "p25", "median", "p75", "p90", "p95", "p99", "max", "mean"]]]
                    for measure, stats in data["overall"].items()
                ],
            )
        )
        parts.extend(["", "### Verdict length stats: file bytes", ""])
        parts.append(
            table(
                ["verdict", "records", "pct", "min", "median", "p90", "p95", "p99", "max", "mean"],
                [
                    [
                        verdict,
                        stats["records"],
                        stats["pct"],
                        stats["file_bytes"]["min"],
                        stats["file_bytes"]["median"],
                        stats["file_bytes"]["p90"],
                        stats["file_bytes"]["p95"],
                        stats["file_bytes"]["p99"],
                        stats["file_bytes"]["max"],
                        stats["file_bytes"]["mean"],
                    ]
                    for verdict, stats in data["by_verdict"].items()
                ],
            )
        )
        parts.extend(["", "### Verdict length stats: chars and lines", ""])
        rows: list[list[Any]] = []
        for verdict, stats in data["by_verdict"].items():
            rows.append(
                [
                    verdict,
                    stats["chars"]["median"],
                    stats["chars"]["p95"],
                    stats["chars"]["max"],
                    stats["lines"]["median"],
                    stats["lines"]["p95"],
                    stats["lines"]["max"],
                ]
            )
        parts.append(table(["verdict", "median chars", "p95 chars", "max chars", "median lines", "p95 lines", "max lines"], rows))
        parts.extend(["", "### Length buckets", ""])
        bucket_order = ["<500B", "500B-2KB", "2KB-10KB", "10KB-50KB", ">=50KB"]
        parts.append(
            table(
                ["bucket", "records", "pct"],
                [[bucket, data["length_buckets"].get(bucket, 0), pct(data["length_buckets"].get(bucket, 0), data["records"])] for bucket in bucket_order],
            )
        )
        parts.extend(["", "### Severity breakdown", ""])
        parts.append(
            table(
                ["severity", "records", "pct", "verdicts", "top detectors"],
                [
                    [severity, stats["records"], stats["pct"], json.dumps(stats["verdicts"], sort_keys=True), json.dumps(stats["detectors"], sort_keys=False)]
                    for severity, stats in data["severity_breakdown"].items()
                ],
            )
        )
        parts.extend(["", "### Top detectors", ""])
        parts.append(
            table(
                ["detector", "records", "pct", "verdicts", "severities", "median bytes"],
                [
                    [
                        detector,
                        stats["records"],
                        stats["pct"],
                        json.dumps(stats["verdicts"], sort_keys=True),
                        json.dumps(stats["severities"], sort_keys=True),
                        stats["median_bytes"],
                    ]
                    for detector, stats in list(data["detector_breakdown"].items())[:30]
                ],
            )
        )
        parts.extend(["", "### Unicode/stego aggregate counters", ""])
        parts.append(
            table(
                ["counter", "total chars", "records with count > 0", "record pct"],
                [
                    [key, total, data["unicode_records"][key], pct(data["unicode_records"][key], data["records"])]
                    for key, total in data["unicode_totals"].items()
                ],
            )
        )
        parts.append("")
    return "\n".join(parts)


def main() -> None:
    summary = {"datasets": {name: summarize_dataset(name, cfg) for name, cfg in DATASETS.items()}}
    json_path = OUTPUTS / "new-datasets-metadata-review.json"
    md_path = OUTPUTS / "new-datasets-metadata-review.md"
    json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(markdown_report(summary) + "\n", encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, sort_keys=True))


if __name__ == "__main__":
    main()
