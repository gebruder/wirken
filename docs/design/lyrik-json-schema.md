# Lyrik JSON output schema (design)

Status: design pressure-tested through user review; implementation tracked at https://github.com/gebruder/wirken/issues/80.

Surfaced 2026-04-28 from a scan of OpenClaw's audit-skill ecosystem. Several skills emit structured output in JSON or CSV (`auditing-appstore-readiness`, `securityclaw`, `coin-news-openclaw`); none preserve a multi-stage assessment funnel as first-class fields.
The lyrik report's structural argument is funnel disclosure: *candidates → deduped → scored → exploit-verified*, with explicit categories for stages where verification was not attempted (`stopped_at_0_5`) and routings that aren't tier-invented (`gate_routed_disagreement`, `gate_routed_scope_bound`). When the report is markdown the structure is visible to a human reader. When the report becomes JSON, the structure has to survive flattening by ingestors that don't know about funnel discipline. A SIEM ingesting `findings[]` will treat lyrik output as a list of vulnerabilities and the structural argument evaporates at the API boundary.

### Two design constraints

1. **Funnel block at top level, not nested under findings.** Every category is a first-class field. Reporting tools, CI/CD gates, and trend dashboards read `funnel.*` directly.
2. **Each finding carries its own routing metadata.** Stream, stop reason, gate routing, dedup match, stable ID. Even if a SIEM flattens to `findings[]`, per-finding routing facts survive.

### Pipeline (strict, anchors the invariants)

```
Stage 1 — Framings produce raw candidates
Stage 2 — Cross-framing pairs fold → candidates_generated
Stage 3 — Dedup gate routes each → regression OR novel
Stage 4 — Scoring runs on regression + novel; produces tier+grade OR routes to gate (disagreement / scope_bound)
Stage 5 — Tier-assigned go to exploit phase; gate-routed leave the funnel here without tier
Stage 6 — Exploit phase outcomes: exploit_attempted, stopped_at_0_5 (with reason), grade_0_no_runtime_needed
Stage 7 — exploit_attempted resolves to: exploit_promoted_to_1_0 OR exploit_failed_in_budget
```

`scored` in the funnel means *"produced a tier"* (Stage 5 tier-assigned), **not** *"scoring was attempted"* — gate-routed items had scoring passes run but no tier emitted, and they leave the funnel at Stage 4 without entering `scored`.

### Top-level shape

```json
{
  "$schema": "TO BE LANDED — 1.0 blocker; placeholder will fail to resolve",
  "schema_version": "1.0",
  "run_id": "run-001",
  "produced_at": "2026-04-28T03:50:43+02:00",

  "target": {
    "scope": ["sys/rpc/rpcsec_gss/**/*"],
    "source_state": {
      "git_url": "https://github.com/freebsd/freebsd-src.git",
      "sha": "1fddb5435315ca44c96960b16bdda8338afd15a1",
      "qualifier": "pre_fix"
    }
  },
  "rubric": { "path": ".lyrik/rubric.md" },

  "funnel": {
    "candidates_generated":          9,
    "cross_framing_pairs_folded":    3,
    "deduped_to_regression":         1,
    "deduped_to_novel":              5,
    "gate_routed_disagreement":      1,
    "gate_routed_scope_bound":       2,
    "scored":                        6,
    "exploit_attempted":             0,
    "exploit_promoted_to_1_0":       0,
    "exploit_failed_in_budget":      0,
    "stopped_at_0_5":                4,
    "stopped_at_0_5_reasons":        { "kernel_runtime_oos": 4 },
    "grade_0_no_runtime_needed":     2
  },

  "concentration": {
    "method": "leave-top-N-out severity-weight aggregation",
    "weights": { "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0.1, "hardening_grade_0": 0.5 },
    "aggregate_full":             7.6,
    "aggregate_top_1_removed":    3.6,
    "aggregate_top_5_removed":    0.1,
    "aggregate_top_10_removed":   0,
    "concentration_index_top_5": 0.99
  },

  "findings": [
    {
      "id": "A1",
      "stable_id": "sys/rpc/rpcsec_gss::sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1158:svc_rpc_gss_validate",
      "stream": "regression",
      "framing": ["auth", "memory_safety"],
      "detection_source": "model_reasoning",
      "location": { "file": "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c", "line_start": 1158, "line_end": 1215, "function": "svc_rpc_gss_validate" },
      "title": "Stack overflow in svc_rpc_gss_validate()",
      "summary": "...",
      "tier": "CRITICAL",
      "grade": 0.5,
      "stop_reason": "kernel_runtime_oos",
      "tier_drop_applied": false,
      "dedup_match": {
        "tier_used": "exact",
        "prior_path": ".lyrik/prior/CVE-2026-4747.md",
        "match_keys": ["file", "function", "root_cause"]
      },
      "scoring_passes": [
        {"real_bug": "yes", "reachable": "yes", "attacker_reach": "yes", "blast_radius": "kernel-RCE"},
        {"real_bug": "yes", "reachable": "yes", "attacker_reach": "yes", "blast_radius": "kernel-RCE"}
      ]
    },
    {
      "id": "A5",
      "stable_id": "sys/rpc/rpcsec_gss::sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:651:svc_rpc_gss_init",
      "framing": ["auth"],
      "title": "INIT-storm legitimate-client eviction",
      "gate_routed": {
        "gate": "scoring_disagreement",
        "tag": "rubric_clarification",
        "rubric_refinement_question": "..."
      },
      "scoring_passes": [
        {"real_bug": "MEDIUM-shape: authn-state-displacement"},
        {"real_bug": "LOW-or-0-shape: LRU-cap-by-design"}
      ]
    }
  ],

  "audit": {
    "log_path": ".lyrik/state/runs/run-001/audit.log",
    "log_format": "iso8601 phase=<x> event=<y> [k=v ...]"
  },

  "observations": {
    "defensive_choices": [
      { "observation": "...", "evidence_path": "..." }
    ]
  }
}
```

Optional top-level fields, omitted when absent (no null literals): `comparison`, `cost`, `reproducibility`. When `cost.methodology == "estimated"`, the `tokens_in` / `tokens_out` fields are omitted, not set to null.

### Schema invariants (reconcile against serialized fields only)

```
funnel.candidates_generated  ==  funnel.deduped_to_regression
                               + funnel.deduped_to_novel
                               + funnel.gate_routed_disagreement
                               + funnel.gate_routed_scope_bound

funnel.scored                ==  funnel.deduped_to_regression + funnel.deduped_to_novel

funnel.scored                ==  funnel.exploit_attempted
                               + funnel.stopped_at_0_5
                               + funnel.grade_0_no_runtime_needed

funnel.exploit_attempted     ==  funnel.exploit_promoted_to_1_0 + funnel.exploit_failed_in_budget

sum(funnel.stopped_at_0_5_reasons.values())  ==  funnel.stopped_at_0_5

# General principle: any parent/sub-map pair where the sub-map enumerates
# named sub-counts MUST have a sum-to-parent invariant. Adding a new
# parent/sub-map pair without the corresponding invariant is a schema
# regression — the producer can populate the sub-map without updating
# the parent, and the report passes JSON Schema validation but fails
# reconciliation. Today the only such pair is stopped_at_0_5_reasons /
# stopped_at_0_5; any future sub-map must add its own invariant here.

count(findings where stream == "regression")           == funnel.deduped_to_regression
count(findings where stream == "novel")                == funnel.deduped_to_novel
count(findings where gate_routed.gate == "scoring_disagreement") == funnel.gate_routed_disagreement
count(findings where gate_routed.gate == "scope_bound")          == funnel.gate_routed_scope_bound
```

Every equation references serialized fields only. An ingestor can validate any report by computing these. A producer that fails reconciliation is broken.

### Stable IDs

Primary form: `findings[].stable_id` is canonical `"<scope_path>::<file>:<line_start>:<function>"`. Sufficient for ticketing dedupe within a single source state.

For cross-SHA diffs (the report-to-report diff ingestion behavior), pair runs by `target.source_state.git_url + target.scope` and match findings by fuzzy `(file, function)` with line-shift fallback. **A `root_cause_hash` was considered and rejected** — hashing LLM-generated description text means the ID changes when the model rewords the same finding, breaking ticketing dedupe. Function-name + AST-shape hash is more robust but heavyweight; defer to consumer side rather than producer side, since AST analysis at producer time is expensive and cross-SHA diff is a less common ingestion path than within-SHA ticketing.

**Brittleness annotation for consumer-side fuzzy matchers.** `line_start` is the brittle component of the stable ID — a finding at line 1158 in run N can be at line 1162 in run N+1 after an unrelated comment block is added above it, even though it's the same finding. Consumer-side fuzzy matchers must weight `function` heavier than `line_start`. The `function` field carries most of the stability; `line_start` is for disambiguation when two findings sit in the same function. Schema-doc consumers writing diff tools should be told this explicitly — the recommended match is `(file, function)` exact + `line_start` proximity within ±N lines for tie-breaking, where N is consumer-tuned.

For 1.0: ship the primary stable ID. Document the cross-SHA diff strategy and the line_start brittleness annotation. Don't bake AST hashing into the schema.

### `findings[].triage_status` reserved

Reserved as an optional string field, empty in 1.0. The CI/CD gating semantics question — *can a regression finding be marked "acknowledged, do not gate"?* — is a separate design turn; the schema leaves the field reserved so a gating-semantics design can populate it without bumping major version.

### `target.source_state.qualifier` enum

Closed:

- `current` — HEAD of working branch, mutable
- `pre_fix` — pinned SHA known to be before a specific patch
- `post_fix` — pinned SHA known to be after a specific patch
- `pinned` — pinned SHA, no fix relationship implied

Required for the report-to-report diff ingestion behavior: tools pair runs by `(git_url, scope, qualifier)` and `pre_fix` precedes `post_fix` for the same target.

### `findings[].gate_routed.tag` enum

Closed:

- `rubric_clarification` — the rubric does not cleanly tier this finding's class. The team's response is rubric refinement, then re-score against the refinement. Triggered by 3-way scoring disagreement where the cause is rubric-level, not finding-level.
- `framing_split` — the finding admits multiple valid interpretations under the current rubric. The team's response is **gate-routed disclosed** — see the Disagreement-handling section in `SKILL.md`. Lyrik does not pick one interpretation and ship it as if there was a single answer; that would collapse advisor-posture to actor-posture and silence structural information lyrik is structurally arguing for.
- `scope_expansion_required` — the candidate cannot be scored without expanding scope beyond the run plan. The team's response is to either expand scope in a follow-up run or accept the disclosure (A6, D1/D3 from run-001 are the type specimens).

### `findings[].detection_source` enum

Closed:

- `model_reasoning` — produced by the framing pass through model reasoning over the recon output.
- `static_prescreen` — produced by a deterministic pattern-match detector before the framing pass. Today's lyrik does not yet ship a static pre-screen; this enum value is reserved for the design that lands as item 5 (static pre-screen + detector provenance) in `skills/lyrik/FOLLOWUPS.md`.
- `both` — both detectors produced the candidate. Default for findings the framing pass and any future static pre-screen converge on.

Detector disagreement (only one of the two detectors produces a candidate) is **not** the same as scoring disagreement. It is upstream of scoring (Stage 1, candidate generation). It does not route through the `scoring_disagreement` gate. The detector-level handling lives in item 5 (static pre-screen + detector provenance).

### Six ingestion behaviors the schema must support

| Behavior | What it reads | How the schema supports it |
|---|---|---|
| **SIEM, takes findings[] only** | per-finding `stable_id`, `stream`, `tier`, `grade`, `stop_reason`, `gate_routed`, `dedup_match` | per-finding routing tags survive flattening |
| **SIEM with metadata** | top-level `funnel`, `concentration`, `target` + `findings[]` | full structure preserved |
| **Trend reporting (multi-run)** | `funnel.*` per run for time series; `concentration` per run | first-class funnel fields |
| **Ticketing (one ticket per finding)** | per-finding `stable_id`, `tier`, `location`, `summary`, `stream` | stable ID + per-finding self-sufficiency |
| **CI/CD gating** | `funnel.deduped_to_regression > 0` (block); `funnel.gate_routed_disagreement > 0` (require human review); `findings[].triage_status` (override) | direct field reads + reserved triage field |
| **Report-to-report diff** | pair runs by `target.source_state.{git_url, qualifier}`; match findings by `stable_id` (within source state) or fuzzy `(file, function)` (cross source state) | qualifier enum + stable_id + sort by `(file, line_start, function)` |

### Sort order for `findings[]`

`(location.file, location.line_start, location.function)`. Stream is a field, not a sort key. Stable diffing across runs of the same scope requires sort independence from stream classification — a finding moving from novel to regression must not jump positions in the sorted output.

### 1.0 blockers (must resolve before this schema ships)

1. **Schema URL.** `$schema` must resolve. Self-host on a wirken-controlled domain, register with JSON Schema Store, or embed in the wirken binary served via `wirken schema`. Decision required before customers pin.
2. **Stable ID canonicalization.** Define exact escaping for `<scope_path>::<file>:<line_start>:<function>` (colons in file paths, special characters in function names). Edge cases break ticketing dedupe.
3. **Invariant validator.** Ship a reference validator (`wirken lyrik validate <report.json>`) that any consumer or producer can run to verify reconciliation. Without it, the invariants are documentation, not enforcement.

### 1.0 deferrals (resolved as defer-to-1.x; not unresolved)

- **`comparison` block stays optional with documented MAY-include.** Conditional-required fields (e.g., "required when assessing against a public claim") are an ingestion nightmare — every consumer has to implement the conditional logic to validate. Optional with omission is correct. If the public-claims-comparison use case proves load-bearing, 1.1 can promote.
- **`audit.events[]` inline stays out.** Audit log is referenced via `audit.log_path`. Inlining events would explode payload size for any non-trivial run, and most consumers won't read them. Consumers needing the events fetch the log. 1.1 can add inline events as an optional flag-controlled field.
- **`observations.*` ships in 1.0 with only `defensive_choices`.** Adding `observations.anti_patterns_avoided` or `observations.design_rationale_inferred` speculatively means committing to a shape before seeing it twice. Document `observations.*` as a reserved namespace; ship 1.0 with only `defensive_choices`. New sub-arrays in 1.x are minor-version bumps.

### Revisions made in this draft (against an earlier version)

- Pipeline stages explicit, so invariants anchor to a strict flow. Earlier "items routed to gate after scoring" was an unserialized parenthetical; the model now is gate-routing happens *during* scoring (Stage 4) and gate-routed items leave the funnel without entering `scored`.
- `extensions` removed. Stop-reason categories first-class; closed enum for `stopped_at_0_5_reasons` keys (open list of named reasons that all sum to the parent count).
- Null literals removed. Optional fields are omitted, not null.
- `defensive_choices_observed` namespaced to `observations.defensive_choices`. Reserves `observations.*` for future expansion.
- Sort order `(file, line_start, function)`; stream is a field.
- Stable ID composite simplified to `(scope_path, file, line_start, function)`. `root_cause_hash` rejected.
- Sixth ingestion behavior added: report-to-report diff. `qualifier` enum required.
- `findings[].triage_status` reserved for the CI/CD gating semantics design.
- Schema URL marked as 1.0 blocker explicitly, not "open question."

