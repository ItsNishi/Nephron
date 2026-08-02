#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

import pyarrow.parquet as pq
from huggingface_hub import snapshot_download
from huggingface_hub.errors import HfHubHTTPError


HF_DATASETS = {
    "qualifire-prompt-injections-benchmark": {
        "repo_id": "Qualifire/prompt-injections-benchmark",
        "revision": "9ef1aa46a7e5eedb096be0481be8011ede1e72e8",
        "allow_patterns": ["data/test-00000-of-00001.parquet"],
    },
    "microsoft-llmail-inject-challenge": {
        "repo_id": "microsoft/llmail-inject-challenge",
        "revision": "1063bdf01ec8762b812d5e06ee768a06faa5a6f7",
        "allow_patterns": [
            "data/emails_for_fp_tests.json",
            "data/labelled_unique_submissions_phase1.json",
            "data/labelled_unique_submissions_phase2.json",
            "data/raw_submissions_phase1.jsonl",
            "data/raw_submissions_phase2.jsonl",
        ],
    },
    "mindgard-evaded-prompt-injection-and-jailbreak-samples": {
        "repo_id": "Mindgard/evaded-prompt-injection-and-jailbreak-samples",
        "revision": "ec63ffb26ba6f29ca1095fabb2e9f9be5f8b9d34",
        "allow_patterns": ["dataset.parquet"],
    },
}


def normalize_text(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n").strip()


METADATA_FIELD_HINTS = (
    "label",
    "class",
    "category",
    "family",
    "attack",
    "split",
    "source",
    "target",
    "goal",
    "type",
    "kind",
    "score",
)


def scalar_texts(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, str):
        text = normalize_text(value)
        if text:
            yield text
        return
    if isinstance(value, dict):
        for item in value.values():
            yield from scalar_texts(item)
        return
    if isinstance(value, list):
        for item in value:
            yield from scalar_texts(item)
        return


def row_to_text(row: Any) -> str:
    return "\n\n".join(scalar_texts(row))


def scalar_items(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    if value is None:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from scalar_items(item, child_path)
        return
    if isinstance(value, list):
        for idx, item in enumerate(value):
            child_path = f"{path}[{idx}]" if path else f"[{idx}]"
            yield from scalar_items(item, child_path)
        return
    if isinstance(value, (str, int, float, bool)):
        yield path or "value", value


def safe_metadata_value(path: str, value: Any) -> Any | None:
    lowered = path.lower()
    if not any(hint in lowered for hint in METADATA_FIELD_HINTS):
        return None
    if isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        text = normalize_text(value)
        if text and len(text) <= 120 and "\n" not in text:
            return text
    return None


def row_to_text_and_metadata(row: Any) -> tuple[str, list[str], dict[str, Any]]:
    texts: list[str] = []
    source_fields: list[str] = []
    metadata: dict[str, Any] = {}
    for path, value in scalar_items(row):
        if isinstance(value, str):
            text = normalize_text(value)
            if text:
                texts.append(text)
                source_fields.append(path)
        meta = safe_metadata_value(path, value)
        if meta is not None:
            metadata[path] = meta
    return "\n\n".join(texts), sorted(set(source_fields)), metadata


def safe_name(prefix: str, idx: int, text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{idx:06d}-{digest}.txt"


def write_records(
    rows: Iterable[Any],
    out_dir: Path,
    prefix: str,
    source_dataset: str,
    source_file: str,
    manifest_rows: list[dict[str, Any]],
) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for row in rows:
        text, source_fields, metadata = row_to_text_and_metadata(row)
        if not text:
            continue
        count += 1
        name = safe_name(prefix, count, text)
        record_id = name.removesuffix(".txt")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        (out_dir / name).write_text(text + "\n", encoding="utf-8")
        manifest_rows.append(
            {
                "record_id": record_id,
                "file": name,
                "text_path": (out_dir / name).as_posix(),
                "source_dataset": source_dataset,
                "source_file": source_file,
                "source_fields": source_fields,
                "metadata": metadata,
                "bytes": len(text.encode("utf-8")),
                "sha256": digest,
            }
        )
    return count


def read_json_records(path: Path) -> Iterable[Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        yield from data
    else:
        yield data


def read_jsonl_records(path: Path) -> Iterable[Any]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def read_csv_records(path: Path) -> Iterable[Any]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        yield from csv.DictReader(handle)


def read_parquet_records(path: Path) -> Iterable[Any]:
    for batch in pq.ParquetFile(path).iter_batches():
        for row in batch.to_pylist():
            yield row


def write_manifest(manifest_path: Path, payload: dict[str, Any]) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    jsonl_path = manifest_path.with_suffix(".jsonl")
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for row in payload.get("records", []):
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")


def convert_data_files(
    source_dir: Path,
    out_dir: Path,
    manifest_path: Path,
    patterns: list[str] | None = None,
    source_dataset: str | None = None,
) -> dict[str, Any]:
    manifest_rows: list[dict[str, Any]] = []
    totals: dict[str, Any] = {"sources": [], "records": 0}
    files: list[Path] = []
    if patterns:
        for pattern in patterns:
            files.extend(sorted(source_dir.glob(pattern)))
    else:
        for suffix in ("*.parquet", "*.jsonl", "*.json", "*.csv"):
            files.extend(sorted(source_dir.rglob(suffix)))

    for path in sorted(set(files)):
        suffix = path.suffix.lower()
        if suffix == ".parquet":
            rows = read_parquet_records(path)
        elif suffix == ".jsonl":
            rows = read_jsonl_records(path)
        elif suffix == ".json":
            rows = read_json_records(path)
        elif suffix == ".csv":
            rows = read_csv_records(path)
        else:
            continue
        source_file = path.relative_to(source_dir).as_posix()
        prefix = source_file.replace("/", "__").replace(".", "_")
        before = len(manifest_rows)
        count = write_records(rows, out_dir, prefix, source_dataset or source_dir.name, source_file, manifest_rows)
        totals["sources"].append({"source": source_file, "records": count})
        totals["records"] += count
        if len(manifest_rows) == before and count != 0:
            raise RuntimeError(f"record accounting failed for {path}")

    write_manifest(manifest_path, {"totals": totals, "records": manifest_rows})
    return totals


def copy_text_files(
    source_dir: Path,
    out_dir: Path,
    manifest_path: Path,
    pattern: str,
    source_dataset: str | None = None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_rows: list[dict[str, Any]] = []
    count = 0
    for source in sorted(source_dir.glob(pattern)):
        if not source.is_file():
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        if not text.strip():
            continue
        count += 1
        name = safe_name(source.stem, count, text)
        record_id = name.removesuffix(".txt")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        (out_dir / name).write_text(text, encoding="utf-8")
        manifest_rows.append(
            {
                "record_id": record_id,
                "file": name,
                "text_path": (out_dir / name).as_posix(),
                "source_dataset": source_dataset or source_dir.name,
                "source": source.relative_to(source_dir).as_posix(),
                "source_file": source.relative_to(source_dir).as_posix(),
                "source_fields": ["file"],
                "metadata": {},
                "bytes": len(text.encode("utf-8")),
                "sha256": digest,
            }
        )
    write_manifest(manifest_path, {"totals": {"records": count}, "records": manifest_rows})
    return {"records": count}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--github-open-prompt-injection", type=Path, required=True)
    args = parser.parse_args()

    corpora_dir = args.root / "corpora"
    inputs_dir = args.root / "inputs"
    manifests_dir = args.root / "outputs" / "manifests"
    report: dict[str, Any] = {}

    for slug, cfg in HF_DATASETS.items():
        target = corpora_dir / slug
        try:
            snapshot_download(
                repo_id=cfg["repo_id"],
                repo_type="dataset",
                revision=cfg["revision"],
                local_dir=target,
                allow_patterns=cfg["allow_patterns"],
            )
            report[slug] = convert_data_files(
                target,
                inputs_dir / slug,
                manifests_dir / f"{slug}.json",
                source_dataset=cfg["repo_id"],
            )
        except HfHubHTTPError as exc:
            report[slug] = {"records": 0, "error": f"{type(exc).__name__}: HTTP access failure"}

    report["open-prompt-injection"] = copy_text_files(
        args.github_open_prompt_injection,
        inputs_dir / "open-prompt-injection",
        manifests_dir / "open-prompt-injection.json",
        "data/system_prompts/*.txt",
        "liu00222/Open-Prompt-Injection",
    )

    (args.root / "outputs" / "prepare-summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for name, summary in sorted(report.items()):
        print(f"{name}\trecords={summary['records']}")


if __name__ == "__main__":
    main()
