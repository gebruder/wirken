# AVB canonical pin

Provider `anthropic`, model `claude-sonnet-4-20250514`. Same pin
across every Lyrik phase, all 22 samples, 3 runs per sample.
Variant runs under other pins are separate rows in the report.

## Layout

- `SETUP.md` — runbook for cloning AVB, configuring credentials, running.
- `rubric.md` — bench-fixed severity rubric committed at this path so
  every sample scores against the same definition.
- `oracle-framing-map.csv` — AGENT-N to Lyrik framing mapping.
  Placeholder until the canonical layout is read from the AVB clone.
- `recon-framings.csv` — per-set framing activation. Set A is
  injection-heavy, Set B is MCP, Set C is data/auth.
- `harness/run-bench.sh` — driver that iterates samples and runs
  Lyrik per sample × per run.
- `harness/aggregate.sh` — jq aggregator. Reads emitted SARIF and
  writes `state/aggregate.json` with rung distribution and totals.
  Recall and FP land once the oracle CSV is canonical from upstream.
- `AVB_PIN.txt` — written by SETUP step 1; pins the AVB SHA the
  canonical run was against.

## Status

Harness scaffolded. The first canonical run is gated on (1) the AVB
clone, (2) provider credentials configured in the Wirken vault, and
(3) network egress. See SETUP.md.
