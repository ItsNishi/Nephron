#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PYTHON=".eval/tools/venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
	echo "missing evaluation virtualenv; follow .eval/README.md setup" >&2
	exit 1
fi

run_dataset() {
	local slug="$1"
	local input_dir="$2"
	local manifest="$3"
	local prefix=".eval/outputs/${slug}.latest"

	if [[ ! -d "$input_dir" ]]; then
		echo "missing input directory: $input_dir" >&2
		return 1
	fi
	if [[ ! -f "$manifest" ]]; then
		echo "missing manifest: $manifest" >&2
		return 1
	fi

	echo "== $slug =="
	dotnet run --project src/Nephron.Demo -c Release -- --scan-dir "$input_dir" --format jsonl \
		> "${prefix}.scan.jsonl" \
		2> "${prefix}.summary.txt"

	"$PYTHON" .eval/scripts/score_scan_jsonl.py \
		--scan-jsonl "${prefix}.scan.jsonl" \
		--manifest-jsonl "$manifest" \
		--out "${prefix}.score.json"

	"$PYTHON" .eval/scripts/missed_by_family.py \
		--scan-jsonl "${prefix}.scan.jsonl" \
		--manifest-jsonl "$manifest" \
		--out "${prefix}.missed-by-family.json"
}

dotnet build >/dev/null

run_dataset \
	"qualifire-prompt-injections-benchmark" \
	".eval/inputs/qualifire-prompt-injections-benchmark-structured" \
	".eval/outputs/manifests/qualifire-prompt-injections-benchmark-structured.jsonl"

run_dataset \
	"mindgard-evaded-prompt-injection-and-jailbreak-samples" \
	".eval/inputs/mindgard-evaded-prompt-injection-and-jailbreak-samples-structured" \
	".eval/outputs/manifests/mindgard-evaded-prompt-injection-and-jailbreak-samples-structured.jsonl"
