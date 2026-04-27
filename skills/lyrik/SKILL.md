---
name: lyrik
description: Security assessment of a codebase — red team, pentest, variant hunt, regression check
---

# Lyrik

Produce a security assessment of a codebase. Lyrik is the form the report takes: every claim stated in the smallest true number of words, every number disclosed with provenance, every finding traceable to the run's audit log.

## Inputs

- Target: repo path, plus an optional scope override from the user (paths in / out) and an assessment type (`full`, `delta`, `variant_hunt`).
- Per-repo state: read `.lyrik/config.json` from the target repo for scope, model pins per phase, gate destinations, and the prior-findings path. Read `.lyrik/rubric.md` and `.lyrik/context.md` if they exist; treat them as approved unless invalidated. Read `.lyrik/prior/` for the dedup gate. If the config is missing, ask the user before generating artifacts. See `docs/lyrik.md` for the schema.
- Prior context (additional): ADRs, postmortems, threat models, security-keyword commit messages, FIXME/TODO/HACK/XXX comments.
- Confidentiality: pin confidential phases to a Privatemode or Tinfoil provider in `phases.<phase>.provider`. Lyrik references operator-level providers and channel adapters by name; credentials live in the Wirken vault and Lyrik never sees them.

## Phase 0 — project context and rubric

Produce two artifacts before any candidate is generated.

**Project context.** Software identity (what it is, what it does), language and framework versions, dependency graph summary, entry points, trust boundaries, data flows, auth model, secrets handling surface, network surface. Enrich with hot zones (high churn × security-tagged history) when the inputs allow.

**Severity rubric.** Project-specific, not CVSS-shaped. Crash severity depends on whether availability is a security property of *this* software. State the tiers and what falls in each.

Deliver both through the `phase_0_signoff` gate and wait for explicit sign-off before continuing. Do not proceed on silence. On approval, write `.lyrik/rubric.md` and `.lyrik/context.md` to the target repo so the team can commit them. Skip Phase 0 generation on subsequent runs unless the dependency lockfile hash or framework version fingerprint has changed.

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
- **Causal.** Ask the model whether the candidate is the same root cause as any of the top-K retrieved historical findings. Uses the `score` provider pin — same calibrated-judgment task class.

Matches do not get suppressed. They route to a separate regression stream. A duplicate of a past disclosed bug means a patch did not hold or a code path reintroduced the root cause — that is its own report, often higher value than novel findings.

If `.lyrik/prior/` is empty or absent, all three tiers are no-ops. Every finding routes to the novel stream. Do not call the model for the causal tier when there is nothing to compare against.

## Scoring

Four axes, scored independently before they combine:

- Is this a real bug
- Is the code path reachable
- Can an attacker reach the entry point
- Blast radius

Score each high-severity candidate more than once. If two passes disagree by more than one severity tier on any axis, route the candidate plus all rationales through the `scoring_disagreement` gate. If the rubric does not cleanly tier a finding (rather than scorers disagreeing on it), route to the same gate with a `rubric clarification` tag — the team can refine the rubric in-flight. Do not proceed on silence.

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

Deliver the bundle through the configured channel adapter. Each 1.0-grade finding pauses at the `high_severity_review` gate before delivery — a human reviewer signs off on the destination, redirects to a different channel, or holds. There is no auto-routing of 1.0-grade findings, encrypted channel or otherwise. Lyrik does not auto-disclose to vendors — that is a human action.

## Tips

- Every phase output writes to the audit subsystem. No opt-out, no exceptions.
- Verify before claim. A scorer rationale that names a function or flag is asserting it exists. Read the file before recommending.
- Log lines describe observed state, not intended state. "Exploit succeeded" is emitted after the PoC ran, never speculatively.
- A finding that pattern-matches a known false-positive class still goes into the candidate pool. The dedup gate decides routing, not the framing.
- Architectural changes invalidate the project context. Re-run Phase 0 after a major refactor or framework version bump.
- Config is per-repo. Provider credentials, channel adapter credentials, and the vault stay at the operator level (Wirken's existing config). `.lyrik/config.json` references those by name, never by credential.
- If actual use surfaces a real boundary that the markdown form can't carry — a state store, a typed schema, a programmatic dispatch — record it in `skills/lyrik/FOLLOWUPS.md`, don't grow this file into a substitute.
