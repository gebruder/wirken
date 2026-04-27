---
name: lyrik
description: Security assessment of a codebase — red team, pentest, variant hunt, regression check
---

# Lyrik

Produce a security assessment of a codebase. Lyrik is the form the report takes: every claim stated in the smallest true number of words, every number disclosed with provenance, every finding traceable to the run's audit log.

## Inputs

- Target: repo path, scope spec (paths in / out), assessment type (`full`, `delta`, `variant_hunt`).
- Prior context: past CVEs and pentest reports, internal disclosures, ADRs, postmortems, threat models, security-keyword commit messages, FIXME/TODO/HACK/XXX comments.
- Confidentiality: when a phase handles material the user has marked confidential, route the model call to a Privatemode or Tinfoil provider if one is configured.

## Phase 0 — project context and rubric

Produce two artifacts before any candidate is generated.

**Project context.** Software identity (what it is, what it does), language and framework versions, dependency graph summary, entry points, trust boundaries, data flows, auth model, secrets handling surface, network surface. Enrich with hot zones (high churn × security-tagged history) when the inputs allow.

**Severity rubric.** Project-specific, not CVSS-shaped. Crash severity depends on whether availability is a security property of *this* software. State the tiers and what falls in each.

Deliver both through the configured channel adapter and wait for explicit sign-off before continuing. Do not proceed on silence.

## Recon

Map entry points, auth boundaries, trust transitions, data stores. Cheap pass — feeds the framings, not a finding source on its own.

## Framings

Run each as a separate pass over the recon output. They are different lenses, not categories of the same scan.

`auth` · `crypto` · `injection` · `deserialization` · `memory_safety` · `secrets` · `supply_chain` · `race_condition`

For each framing, run two sub-passes and union the candidates: a **careful auditor** (broad, conservative, codes assumptions explicitly) and an **attacker hunting one bug** (narrow, adversarial, fixates on a single hypothesis).

## Scanners (optional)

When the binaries are installed, dispatch them through the agent's exec sandbox (gVisor mode if configured, else exec-only) with no network and a read-only mount of the target.

`semgrep` · `gitleaks` · `trivy` · `checkov` · `nuclei`

Record each scanner's version in the audit log for the run. Scanner findings join the candidate pool with the same schema as model-generated findings; they are not privileged.

## Dedup (before scoring)

Three tiers, in order:

- **Exact.** File path + line range + rule ID.
- **Semantic.** Embed the root cause description; compare against past findings. Default similarity threshold 0.85.
- **Causal.** Ask the model whether the candidate is the same root cause as any of the top-K retrieved historical findings.

Matches do not get suppressed. They route to a separate regression stream. A duplicate of a past disclosed bug means a patch did not hold or a code path reintroduced the root cause — that is its own report, often higher value than novel findings.

## Scoring

Four axes, scored independently before they combine:

- Is this a real bug
- Is the code path reachable
- Can an attacker reach the entry point
- Blast radius

Score each high-severity candidate more than once. If two passes disagree by more than one severity tier on any axis, route the candidate plus all rationales to the user for adjudication. Do not proceed on silence.

## Concentration test

After scoring the full set, re-score with the top-5 and top-10 findings removed. Report a **concentration index**: how much aggregate severity collapses when the top findings are removed. A high concentration is a quality signal about the assessment, not a comparison metric — report it on its own.

## Exploit attempt

Run only on findings graded 0.5 (correct class, unverified reachability). Run inside the exec sandbox in gVisor mode, with no network egress and an ephemeral filesystem. Per-attempt budget: configurable, default 5 minutes wall clock plus a token cap.

- PoC succeeds → finding promoted to 1.0.
- PoC fails inside budget → finding stays as a finding, severity drops one tier.
- Sandbox permission denials during attempt construction are themselves logged as findings.

## Grades

- **0** — no real bug, or wrong root cause.
- **0.5** — correct class, location or reachability unverified.
- **1.0** — correct root cause, correct location, exploit demonstrated reachable.

## Report

Each finding rendered in the smallest true number of words. The report contains:

- **Novel findings stream**, each with grade, scorer rationales, exploit result if any.
- **Regression findings stream**, each pointing at the past finding it matches and the commit that was supposed to fix it.
- **Concentration index** from the concentration test.
- **Funnel disclosure**: candidates generated, after dedup, scored, exploit-verified. The numbers must reconcile.
- **Audit log reference** for the run.

Deliver the bundle through the configured channel adapter. Route any 1.0-grade finding through an encrypted channel (Signal, Matrix) when one is configured. Lyrik does not auto-disclose to vendors — that is a human action.

## Tips

- Every phase output writes to the audit subsystem. No opt-out, no exceptions.
- Verify before claim. A scorer rationale that names a function or flag is asserting it exists. Read the file before recommending.
- Log lines describe observed state, not intended state. "Exploit succeeded" is emitted after the PoC ran, never speculatively.
- A finding that pattern-matches a known false-positive class still goes into the candidate pool. The dedup gate decides routing, not the framing.
- Architectural changes invalidate the project context. Re-run Phase 0 after a major refactor or framework version bump.
- If actual use surfaces a real boundary that the markdown form can't carry — a state store, a typed schema, a programmatic dispatch — record it in `skills/lyrik/FOLLOWUPS.md`, don't grow this file into a substitute.
