#!/usr/bin/env bash
# Drive the AVB benchmark: 22 samples × 3 runs.
#
# Reads the canonical pin from lyrik-bench/avb/README.md and the
# bench rubric from lyrik-bench/avb/rubric.md. Writes per-sample run
# state under lyrik-bench/avb/state/runs/<sample>/run-<N>/ and emits
# SARIF via `wirken lyrik report`.

set -euo pipefail

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
BENCH_DIR="$ROOT/lyrik-bench/avb"
UPSTREAM="$BENCH_DIR/upstream"
STATE_DIR="$BENCH_DIR/state"
RUBRIC="$BENCH_DIR/rubric.md"
RUNS_PER_SAMPLE="${RUNS_PER_SAMPLE:-3}"

if [ ! -d "$UPSTREAM" ]; then
	printf 'error: AVB clone missing at %s\n' "$UPSTREAM" >&2
	printf 'see lyrik-bench/avb/SETUP.md step 1\n' >&2
	exit 1
fi

if ! command -v wirken >/dev/null 2>&1; then
	printf 'error: wirken not on PATH\n' >&2
	exit 1
fi

mkdir -p "$STATE_DIR/runs"

# Sample inventory: every directory under upstream/ that contains a
# manifest the bench treats as a sample. Adjust the matcher when the
# AVB layout is confirmed; this loop is the placeholder that the
# canonical run validates.
samples=()
while IFS= read -r -d '' dir; do
	samples+=("$dir")
done < <(find "$UPSTREAM" -mindepth 1 -maxdepth 3 -type d -name 'sample-*' -print0 2>/dev/null || true)

if [ "${#samples[@]}" -eq 0 ]; then
	printf 'warn: no samples discovered under %s; sample matcher may need an update for the cloned AVB layout\n' "$UPSTREAM" >&2
fi

for sample_path in "${samples[@]}"; do
	sample_id=$(basename "$sample_path")
	for run_n in $(seq 1 "$RUNS_PER_SAMPLE"); do
		run_id="$sample_id/run-$run_n"
		run_dir="$STATE_DIR/runs/$run_id"
		mkdir -p "$run_dir"

		# Seed per-sample .lyrik state into the sample directory so
		# the lyrik skill picks it up from the target's working tree.
		mkdir -p "$sample_path/.lyrik/state/runs/$run_id"
		cp "$RUBRIC" "$sample_path/.lyrik/rubric.md"
		cat > "$sample_path/.lyrik/config.json" <<-CFG
			{
			  "scope": { "include": ["**/*"], "exclude": [".git/**"] },
			  "phases": {
			    "articulate": { "provider": "anthropic", "model": "claude-sonnet-4-20250514" },
			    "rubric":     { "provider": "anthropic", "model": "claude-sonnet-4-20250514" },
			    "recon":      { "provider": "anthropic", "model": "claude-sonnet-4-20250514" },
			    "framing":    { "provider": "anthropic", "model": "claude-sonnet-4-20250514" },
			    "score":      { "provider": "anthropic", "model": "claude-sonnet-4-20250514" }
			  },
			  "gates": {
			    "phase_0_signoff":      { "adapter": "noop", "target": "bench" },
			    "scoring_disagreement": { "adapter": "noop", "target": "bench" },
			    "high_severity_review": { "adapter": "noop", "target": "bench" }
			  },
			  "prior_findings_path": "./.lyrik/prior",
			  "memory_path": "./.lyrik/memory",
			  "bench_mode": true
			}
		CFG

		printf '== %s ==\n' "$run_id"
		# The lyrik skill is invoked through a wirken agent run; the
		# concrete invocation depends on the operator's configured
		# channel. Placeholder: a wrapper command that the operator
		# replaces with their preferred entry point. Ship the
		# placeholder; the canonical-run runbook documents the
		# operator-side completion.
		printf 'TODO: invoke lyrik on %s with run_id=%s\n' "$sample_path" "$run_id" >&2

		# After lyrik produces findings.json, emit SARIF.
		findings="$sample_path/.lyrik/state/runs/$run_id/findings.json"
		if [ -f "$findings" ]; then
			(cd "$sample_path" && wirken lyrik report \
				--run "$run_id" \
				--output "$run_dir/lyrik.sarif")
		else
			printf 'skip sarif emission: %s missing\n' "$findings" >&2
		fi
	done
done

printf 'done. aggregate with lyrik-bench/avb/harness/aggregate.sh\n'
