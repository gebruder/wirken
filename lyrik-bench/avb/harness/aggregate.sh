#!/usr/bin/env bash
# Aggregate AVB run outputs: recall, FP rate, rung distribution.
#
# Reads every SARIF emitted by run-bench.sh under
# lyrik-bench/avb/state/runs/<sample>/run-<N>/lyrik.sarif and joins
# against lyrik-bench/avb/oracle-framing-map.csv. Output is JSON at
# lyrik-bench/avb/state/aggregate.json.

set -euo pipefail

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
BENCH_DIR="$ROOT/lyrik-bench/avb"
STATE_DIR="$BENCH_DIR/state"
RUNS_DIR="$STATE_DIR/runs"
ORACLE="$BENCH_DIR/oracle-framing-map.csv"
OUT="$STATE_DIR/aggregate.json"

if ! command -v jq >/dev/null 2>&1; then
	printf 'error: jq not on PATH\n' >&2
	exit 1
fi

if [ ! -d "$RUNS_DIR" ]; then
	printf 'error: runs directory missing at %s\n' "$RUNS_DIR" >&2
	exit 1
fi

# Inventory all SARIF files.
sarifs=()
while IFS= read -r -d '' s; do
	sarifs+=("$s")
done < <(find "$RUNS_DIR" -name 'lyrik.sarif' -print0)

# Build a flat findings stream tagged by sample/run.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

for s in "${sarifs[@]}"; do
	# extract sample and run from path: .../runs/<sample>/run-<N>/lyrik.sarif
	rel=${s#"$RUNS_DIR"/}
	sample=${rel%%/*}
	rest=${rel#"$sample/"}
	run=${rest%%/*}
	jq --arg sample "$sample" --arg run "$run" '
		.runs[0].results[] |
		{
			sample: $sample,
			run: $run,
			rule_id: .ruleId,
			level: .level,
			file: .locations[0].physicalLocation.artifactLocation.uri,
			start_line: .locations[0].physicalLocation.region.startLine,
			end_line: .locations[0].physicalLocation.region.endLine,
			rung: .properties.lyrik.rung,
			deferral: .properties.lyrik.deferral.reason,
			tier: .properties.lyrik.tier,
			grade: .properties.lyrik.grade,
			stable_id: .properties.lyrik.stable_id
		}
	' "$s" >> "$tmp"
done

# Collect rung distribution.
rung_distribution=$(jq -s '
	group_by(.rung.name) |
	map({(.[0].rung.name // "suspicion"): length}) |
	add
' "$tmp")

deferral_distribution=$(jq -s '
	group_by(.deferral) |
	map({(.[0].deferral // "none"): length}) |
	add
' "$tmp")

total_findings=$(jq -s 'length' "$tmp")

# Recall and FP need the oracle. Each oracle row's framing_primary is
# what the harness expects Lyrik to produce; matching is by
# (sample-derived AVB id, file:line overlap, framing match).
# Without the canonical AVB layout finalized, this aggregator emits
# the rung distribution and total counts; recall/FP land once the
# canonical layout is confirmed and the oracle CSV is populated from
# upstream metadata.

mkdir -p "$STATE_DIR"
jq -n \
	--argjson rung "$rung_distribution" \
	--argjson deferral "$deferral_distribution" \
	--argjson total "$total_findings" \
	--arg oracle_pin "$(sha256sum < "$ORACLE" | cut -c1-12)" \
	'{
		total_findings: $total,
		rung_distribution: $rung,
		deferral_distribution: $deferral,
		oracle_pin_prefix: $oracle_pin,
		recall: null,
		precision: null,
		fp_count: null,
		note: "recall and FP populated once oracle CSV is canonical from AVB upstream metadata"
	}' > "$OUT"

printf 'wrote %s\n' "$OUT"
cat "$OUT"
