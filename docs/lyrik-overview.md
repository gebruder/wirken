# Lyrik

<img src="img/lyrik-wirken.png" alt="Lyrik" width="400" align="right">

Lyrik audits a codebase against [a scoring guide your team has written](lyrik-rubric-authoring.md). The report shows every finding it considered, which it kept, which it threw out, which it could not decide on, and the reason for each.

## Who it is for

Highly technical security teams doing red-team or pentest work to find code flaws in products before they ship. Internal teams running pre-release defensive review. Teams that need the assessment to be defensible weeks after the run, not just at the moment it produces a findings list.

It is not for general code-review developers, compliance auditors, or buyers who want a single PASS/FAIL number.

## Why it exists

Common LLM code audits work for a single file. They become unreliable across a repository. The same bugs come back run after run. Severity scores drift. There is no log of what the model considered. CI cannot block on the output. When the model is unsure, the output does not say so.

Pre-ship defensive review needs more than a findings list. It needs a record of what the audit decided, what it deferred, what was a duplicate, and where the team and the model disagreed. Compliance scanners do not produce this; they produce a tier-collapsed verdict against a fixed framework. Lyrik produces an assessment whose every step is recorded against a scoring guide the team owns.

## What Lyrik is not

- Not a vulnerability scanner. Lyrik runs scanners; it is not one.
- Not a compliance tool. Lyrik does not score against MITRE ATLAS, OWASP, NIST, or any external framework unless the team's scoring guide chooses to.
- Not a continuous monitor or runtime watchdog. Lyrik audits source code on demand. It does not watch running systems or running skills.
- Not a single-number tool. Lyrik does not produce a PASS/FAIL or an aggregate severity score. The structure of the assessment is the output.
- Not a disclosure tool. Lyrik does not auto-notify vendors, file CVEs, or open tickets. It produces a report; the team decides what to do with it.

## What Lyrik will not do

- Will not claim a finding is exploitable without verifying it. Findings stop at grade 0.5 when runtime verification is out of scope, and the report says so.
- Will not invent a severity tier when the scoring guide does not cover the case. Such findings route to human review.
- Will not average disagreeing scorers into a consensus tier. Three-way disagreement routes to human review with all rationales preserved.
- Will not auto-route high-severity findings to delivery channels. Channel routing requires human signoff.

## What it does

### Your team writes the scoring guide

Severity is what your team has [written down and committed](lyrik-rubric-authoring.md) to the repository at `.lyrik/rubric.md`. The guide says what counts as critical for your project, what counts as high, what counts as low, which findings are ambiguous on purpose, and which hardening grades apply.

Each run scores against the guide your team committed. Different teams write different guides. The same team writes a different guide when the threat model changes.

### The report opens with the assessment shape

Each report starts with the structure of what was assessed, not just what was found. Counts of: findings produced, duplicates of each other, duplicates of earlier runs, scored, sent for human review, tested for real exploitability, set aside without scoring and the reason. The numbers reconcile. A reader can check the math.

This is the structural rebuttal to "we found N high-severity bugs." A finding count without disclosure of what was dropped, deferred, or stopped before scoring is not an assessment.

### Findings are scored more than once

Every finding is scored by two passes. If the two disagree by more than one severity level, a third pass runs. If two of the three agree, that score wins; both rationales are kept in the report. If all three disagree, the finding is sent for human review with the kind of disagreement tagged:

- The scoring guide does not clearly cover this kind of finding. The team updates the guide and re-scores.
- The finding admits more than one valid reading under the current guide. The report routes it through the human-review gate with all rationales and an explicit "team did not resolve" status. The reader sees every interpretation and decides; lyrik does not pick one reading or split the finding into separate items.

Disagreement is recorded, not averaged.

### New and repeat findings are tracked separately

Lyrik remembers findings from earlier runs. New findings go into a "new" list; findings that match earlier ones go into a "repeat" list. Both appear in the report. The team's CI policy decides which stream gates merges and which alerts, based on what the audit is for. Weekly review on an active codebase tends to gate on new; post-fix verification tends to gate on repeats.

### Concentration

The report adds up severity across all findings, then reports what the total would be without the worst finding, without the worst five, without the worst ten. Plus an index from 0 to 1.

A team reads the index to see whether their security depends on a few critical findings or spreads across many.

### Reproducible reports

Each report records the source code's location (git URL, commit SHA, and whether the run was on the current code, before a fix, after a fix, or on a pinned state), the scoring guide path, the audit log path, and instructions to reproduce the run from a clean clone.

## What ships today and what is in design

Today:

- **Scoring against the inline rubric in SKILL.md.** The rubric used to derive every finding's tier lives in the skill body. The production-mode committed-guide workflow (Phase 0 sign-off that writes `.lyrik/rubric.md` and `.lyrik/context.md` to the repo for the team to review) auto-approves under bench mode and is not yet wired in production runs.
- **Two-pass scoring, disagreement marked, lower tier picked, not averaged.** Each finding is scored by two independent passes. When the passes disagree by more than one step on any axis, the finding carries `scoring_disagreement: true` and the runner picks the lower-implied tier. This is the mechanism behind "will not average disagreeing scorers": disagreement is recorded and resolved conservatively, not collapsed into a synthetic consensus.
- **Grade caps at 0.5.** A finding gets `grade: 0.5` when both passes mark `real_bug: yes` and `reachable: yes`; everything else gets `grade: 0`. The 0.5 ceiling is by design: Lyrik confirms real-and-reachable, exploit verification is a separate workload that runs against the same findings later.
- **Per-finding `detection_source` provenance.** Closed enum `static_prescreen | model_reasoning | both` on every emitted finding, enforced when present per schema-v1.1.
- **Opt-in Semgrep scanner dispatch.** When `scanner.semgrep.enabled` is set in `.lyrik/config.json`, the runner invokes a pinned Semgrep version against the target before the LLM passes, materialises taint/dataflow candidates as seeds the model rules on, and records `lyrik.scanner.dispatched` with the binary version and bundled ruleset sha. Binary absent or version mismatch degrades to LLM-only with a `lyrik.scanner.unavailable` audit row. Semgrep is the only scanner that ships today.
- **Per-skill restricted tool lists.** Every skill's `permissions:` block (tools, egress, filesystem, inference) is enforced at runtime by the gateway. The Lyrik skill ships its own block; operators can review or tighten before install.
- **Audit logs.** Per-run NDJSON `<run>/audit.log` for every dispatch decision plus the signed hash-chained gateway audit chain at `~/.wirken/audit.db` for cross-session integrity.
- **JSON findings schema.** Schema-v1.1 with a reference validator (`wirken lyrik validate <path>`) and a SARIF report emitter (`wirken lyrik report --format sarif`) for SIEM and CI consumers.

In design:

- Three-pass scoring with tiebreak when the two passes disagree by more than one step, and the framing-split resolution shape that goes with it.
- Production-mode human gate routing to channel adapters with the three disagreement-kind tags (`rubric_clarification`, `framing_split`, `scope_expansion_required`).
- Separate streams for new and repeat findings, sourced from a `.lyrik/prior/` dedup pass against past CVEs, pentest reports, and internal disclosures.
- Concentration index reporting what severity total would look like without the worst finding, the worst five, the worst ten.
- Additional scanner dispatch beyond Semgrep.
- Markdown report output alongside the existing SARIF emitter.
- Prompt-injection framing wired into Lyrik alongside model-based detection. The static `InjectionDetector` already ships in the gateway; the Lyrik-side integration is what's pending.
- Opt-in for auto-running.

In research: capability tokens, runtime watchdog mode, sub-context isolation.

Tracked in `skills/lyrik/FOLLOWUPS.md` (case-accumulating records from dogfood runs) and the project's GitHub Issues (active design and implementation).

## Setup and use

For setup, configuration, and the channel target syntax, see `docs/lyrik.md`.

## See also

- `docs/lyrik.md` — setup, configuration, first-run.
- `docs/lyrik-rubric-authoring.md` — how the team writes and refines `.lyrik/rubric.md`.
- `skills/lyrik/SKILL.md` — the skill itself.
- `skills/lyrik/FOLLOWUPS.md` — open design questions from real runs.
- `lyrik.wirken.ai`
