# AVB benchmark setup

Run prerequisites:

1. Clone the upstream AVB corpus next to this directory:

   ```
   git clone https://github.com/HeadyZhang/agent-audit \
     lyrik-bench/avb/upstream
   git -C lyrik-bench/avb/upstream rev-parse HEAD > lyrik-bench/avb/AVB_PIN.txt
   ```

   The clone is gitignored at the repo root entry `lyrik-bench/avb/upstream/`.
   Only `AVB_PIN.txt` is committed so a third party knows which SHA the
   canonical run was against.

2. Configure a Wirken vault entry for the canonical model pin (per
   `lyrik-bench/avb/README.md`):

   ```
   wirken credentials add anthropic-api-key
   ```

   The bench harness reads the credential by name. Lyrik never sees
   the raw key.

3. Confirm the rubric and oracle map are committed:

   ```
   ls lyrik-bench/avb/{rubric.md,oracle-framing-map.csv,recon-framings.csv}
   ```

4. Run the bench driver:

   ```
   ./lyrik-bench/avb/harness/run-bench.sh
   ```

   Outputs land at `lyrik-bench/avb/state/runs/<sample-id>/run-<N>/`.
   Each run writes its own `findings.json` and emits SARIF via
   `wirken lyrik report`.

5. Aggregate metrics:

   ```
   ./lyrik-bench/avb/harness/aggregate.sh
   ```

   Produces `lyrik-bench/avb/state/aggregate.json` with recall, FP,
   rung distribution, and per-set breakdown.

## Resource floor

- Anthropic API quota for ~22 samples × 3 runs × Lyrik phases. Phase 0
  articulate caches after first run; framings + scoring dominate.
- Wall-clock: tens of minutes to a few hours depending on context size
  per sample.
- Network egress to `api.anthropic.com`.

## Reproducibility

The canonical row in the report is the run with:

- AVB at the SHA pinned in `AVB_PIN.txt`.
- Wirken at the SHA on the same row of the report.
- Provider+model pin in `lyrik-bench/avb/README.md`.
- Rubric committed at `lyrik-bench/avb/rubric.md`.

A third party with the same provider account reproduces within
model-nondeterminism bounds across the three runs per sample.
