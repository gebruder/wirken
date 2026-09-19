# Lyrik

<img src="img/lyrik-wirken.png" alt="Lyrik" width="360" align="right">

Lyrik audits a codebase against a scoring guide your team has written. The
report shows every finding it considered, which it kept, which it threw out,
which it could not decide on, and the reason for each.

## Who it is for

Highly technical security teams doing red-team or pentest work to find code
flaws before a product ships, and internal teams running pre-release defensive
review. Teams that need the assessment to be defensible weeks after the run,
not just at the moment it produces a findings list.

Not for general code-review developers, compliance auditors, or buyers who
want a single PASS/FAIL number.

## Why it exists

Common LLM code audits work for a single file and become unreliable across a
repository. The same bugs come back run after run, severity scores drift,
there is no log of what the model considered, CI cannot block on the output,
and when the model is unsure the output does not say so.

Pre-ship defensive review needs more than a findings list. It needs a record
of what the audit decided, what it set aside, what was a duplicate, and where
the team and the model disagreed. Compliance scanners produce a
tier-collapsed verdict against a fixed framework. Lyrik produces an assessment
whose every step is recorded against a scoring guide the team owns.

## What it is not

- Not a vulnerability scanner. Lyrik runs scanners; it is not one.
- Not a compliance tool. It scores against the team's own guide, not against
  an external framework, unless the guide chooses to anchor on one.
- Not a continuous monitor. It audits source on demand and does not watch
  running systems.
- Not a single-number tool. There is no PASS/FAIL and no aggregate severity
  score; the structure of the assessment is the output.
- Not a disclosure tool. It does not notify vendors, file CVEs or open
  tickets.

It will not claim a finding is exploitable without verifying it, will not
invent a severity tier the guide does not cover, will not average disagreeing
scorers into a consensus, and will not auto-route high-severity findings to a
delivery channel without human signoff.

## What ships today

- **Scoring against the inline rubric in `SKILL.md`.** The rubric that derives
  every finding's tier lives in the skill body. The committed-guide workflow
  (Phase 0 sign-off writing `.lyrik/rubric.md` and `.lyrik/context.md` for the
  team to review) auto-approves under bench mode and is not wired into
  production runs.
- **Two-pass scoring.** Each finding is scored by two independent passes. When
  they disagree by more than one step on any axis the finding carries
  `scoring_disagreement: true` and the runner picks the lower-implied tier.
  That is the mechanism behind "will not average": disagreement is recorded
  and resolved conservatively.
- **Grade caps at 0.5.** A finding gets `grade: 0.5` when both passes mark
  `real_bug: yes` and `reachable: yes`; everything else gets `0`. The ceiling
  is by design: Lyrik confirms real-and-reachable, and exploit verification is
  a separate workload against the same findings.
- **Per-finding `detection_source` provenance**, a closed enum enforced when
  present.
- **Opt-in Semgrep prescreen.** With `scanner.semgrep.enabled` set, the runner
  invokes a pinned Semgrep version before the LLM passes, materializes
  taint/dataflow candidates as seeds the model rules on, and records
  `lyrik.scanner.dispatched` with the binary version and ruleset sha. A
  missing binary or version mismatch degrades to LLM-only.
- **Tool-call preflight.** Before any target-touching work the runner probes
  the configured model through the same dispatch path, with one tool defined
  and a prompt asking the model to call it. Pass emits
  `lyrik.model.tool_calls_supported`; fail aborts before scanner dispatch with
  the case named.
- **Bundled skill staged per run**, self-signed with a one-shot keypair so the
  loader's signature gate accepts it, which is why `/lyrik` resolves to the
  staged copy regardless of operator state under `<data_dir>/skills/`.
- **Citation-resolution gate.** For every emitted finding the runner confirms
  the cited file exists and the cited line resolves, then runs class-specific
  sub-gates on the cited line plus a window, routing to a named deferred tag
  when no honest check is available.
- **Per-skill restricted tool lists.** The skill's `permissions` block is
  enforced at runtime by the gateway. Lyrik ships its own; operators can
  review or tighten it before install.
- **Audit logs.** A per-run NDJSON `<run>/audit.log` for every dispatch
  decision, plus the signed hash-chained gateway chain for cross-session
  integrity. See [audit-cli.md](audit-cli.md).
- **JSON findings schema** with a reference validator and a SARIF emitter.

## Setup

1. Install Wirken and pick at least one provider and one channel adapter that
   can carry the gates. See [getting-started.md](getting-started.md).
2. From the assessed repo, message the agent: *"run a lyrik assessment, full
   type."*
3. Phase 0 generates the project context and severity rubric and routes them
   to `gates.phase_0_signoff`. Lyrik does not proceed on silence.
4. On approval, Lyrik writes `.lyrik/rubric.md` and `.lyrik/context.md`.
   Commit them. Later runs skip Phase 0 unless the dependency lockfile hash or
   the framework version fingerprint changes, or the team asks for a re-run.
5. Optionally populate `.lyrik/prior/` with past CVEs, pentest reports and
   internal disclosures; the dedup gate reads it recursively. Without it the
   regression-finding stream stays empty.
6. Optionally populate `.lyrik/memory/` with ADRs, postmortems, threat models
   and design docs, plus `jira.csv` if you have an export. Both feed Phase 0's
   hot-zones and per-component history. Without them the context still builds,
   minus the history layer.

## What lives where

Operator-level state stays where it already lives in Wirken; the Lyrik config
does not duplicate or override it. Per-repo state lives in `.lyrik/` and is
committed.

| Lives at | What |
|---|---|
| Wirken vault | provider API keys, channel adapter credentials |
| `<data_dir>/sandbox.json` | sandbox mode |
| `<repo>/.lyrik/config.json` | scope, model pins per phase, gate destinations, prior-findings path, memory path |
| `<repo>/.lyrik/rubric.md` | severity rubric approved at Phase 0 |
| `<repo>/.lyrik/context.md` | project context approved at Phase 0 |
| `<repo>/.lyrik/prior/` | past CVEs, pentest reports, internal disclosures |
| `<repo>/.lyrik/memory/` | ADRs, postmortems, threat models, design docs |

`.lyrik/config.json` references operator-level resources by name:
`phases.score.provider: "privatemode"` resolves through the vault,
`gates.phase_0_signoff.adapter: "slack"` through the channel registry. Lyrik
never sees a credential.

## `.lyrik/config.json`

A sample is at [`lyrik.example.json`](lyrik.example.json).

**`scope`**: `include` globs (default `["**/*"]`) and `exclude` globs
(default `["target/**", "node_modules/**", ".git/**"]`). A user request like
"assess only `src/`" overrides this for the run.

**`phases`**: one entry per phase that makes a model call, pinning provider
and model. Phases: `articulate` (Phase 0 context generation), `rubric` (Phase
0 rubric derivation), `recon` (entry-point and trust-boundary mapping),
`framing` (the nine framing classes and their sub-passes, the largest token
consumer), `score` (four-axis scoring, multi-instance), `exploit`
(exploit-attempt code, run inside the gVisor sandbox).

Confidentiality is the pin: there is no `confidential: true` flag, so pinning
a phase to Privatemode or Tinfoil is the mechanism. Per-class pinning inside
`framing` is not supported.

The nine framings are `auth`, `crypto`, `injection`, `deserialization`,
`memory_safety`, `secrets`, `supply_chain`, `race_condition` and
`prompt_injection`. Recon activates `prompt_injection` when the scope contains
an LLM client, an agent loop, tool execution, system-prompt construction,
retrieval, or an MCP host. Untrusted text reaching a model's context is a
distinct trust model from classical SQL or shell injection: sanitization
shapes from those domains do not apply, and in-context content inherits trust
from the surrounding prompt by default.

**`gates`**: one entry per human gate, each naming an `adapter` and an
adapter-native `target`.

| Gate | Fires when |
|---|---|
| `phase_0_signoff` | Phase 0 artifacts await approval |
| `scoring_disagreement` | Two scoring passes disagree by more than one tier on any axis |
| `high_severity_review` | A finding lands at grade 1.0. There is no auto-routing for these, encrypted channel or otherwise |

Target syntax is whatever the adapter natively addresses a destination by:
Slack a channel ID (`C012ABCDEF`) or `#channel-name`, Matrix a room ID
(`!roomid:server.tld`), Signal an E.164 number. Others use their own
conversation ids.

**`prior_findings_path`** and **`memory_path`** default to `./.lyrik/prior`
and `./.lyrik/memory`.

**`walks` and `max_concurrent_walks`**: opt into per-walk dispatch: one agent
turn per named walk, run concurrently against the same target, producing a
single deduped `findings.json`.

```json
{ "walks": ["sink-walk", "chain-walk", "graph-walk"], "max_concurrent_walks": 4 }
```

The validator runs at config-parse time, before any LLM call, and hard-fails
when the array is empty (the way to skip Lyrik is not to run it), when a name
is outside the canonical set (`chain-walk`, `crypto-walk`,
`differential-walk`, `doc-walk`, `fuzz-walk`, `graph-walk`, `invariant-walk`,
`sink-walk`), or when the named walk is not installed at
`~/.claude/skills/<walk-name>/SKILL.md`. `max_concurrent_walks` defaults to 4,
tuned to the conservative end of common provider rate limits; 0 is rejected
and a value above the walk count is a no-op.

Each walk runs as its own task gated by a semaphore. Every walk's agent shares
the run-level session id (`lyrik-<run-id>`), so all walk turns land in one
signed audit chain however many run in parallel. Per-walk staging lives under
`.lyrik/state/runs/<run-id>/staging/<walk-name>/`.

Dedup on the merged output: findings sharing `(location.file,
location.line_start)` collapse to one; `framing` becomes the sorted unique
union; `tier` rises to the highest; `dedup_disagreement: true` when input
tiers differ; `dedup_sources` lists every contributing walk in first-seen
order. The first finding's `summary`, `id` and `stable_id` survive as
canonical. Findings without a file and line pass through unchanged, so a
malformed input does not collapse against everything else under a default key.

Exit `0` when at least one walk returned success with no permission denials;
non-zero when any walk hit a permission denial, which is operator intent and
never silently merged into partial success, or when every selected walk failed
transiently. Either way a partial `findings.json` is produced.

**`bench_mode`**: defaults false. When true, `phase_0_signoff` and
`high_severity_review` auto-approve so a run completes without an interactive
reviewer. `scoring_disagreement` is **not** short-circuited; three-way
disagreement still routes, to a benchmark-side log file rather than a channel.
Both auto-approvals emit audit records with `signoff.decision: "auto_bench"`
so bench runs are distinguishable after the fact. Set it only on benchmark or
batch-evaluation targets.

## Writing the scoring guide

A markdown file at `.lyrik/rubric.md` in the repo being assessed. The team
owns it, commits it, and reviews it in PR like any other artifact. It is not
CVSS-shaped (CVSS produces a number; a rubric produces tier definitions
specific to the software), not a compliance checklist, and not universal:
different projects need different rubrics, and the same project needs a
different one when its threat model changes.

Sections worth including: software identification; what counts as a security
property of *this* software and what does not; tier definitions with concrete
examples; **acknowledged tensions**, the project-level constraints the rubric
consciously accepts, so Lyrik can reference them as INFO-tier lines per run
instead of regenerating findings the team will discard; rubric-silent cases,
which route to human review rather than getting an invented tier; and any
run-specific constraints.

Lyrik drafts most of it at Phase 0 in collaboration with you, rather than
expecting you to write it from scratch. The form is whatever the channel
renders well: prose, tables, bulleted tiers. The team picks at first sign-off
and the chosen form is committed.

## Findings schema (1.1)

`findings.json` is the contract external consumers (SIEM ingestors, ticketing
systems, CI gates, diff tools) pin against.

`$id` is
`https://raw.githubusercontent.com/gebruder/wirken/schema-v1.1/docs/lyrik-json-schema.json`.
The schema is tag-pinned, not release-pinned: wirken releases that do not
change it do not move the tag, and schema changes cut a new tag and a new
spec. `wirken lyrik validate --path <path>` embeds the schema bytes and never
fetches `$id`; the URL is for external JSON Schema validators.

```json
{
  "schema_version": "1.1",
  "run_id": "<non-empty string>",
  "produced_at": "<RFC 3339 timestamp>",
  "findings": [ /* zero or more */ ]
}
```

Required per finding: `id`, `stable_id`, `framing` (array of one or more
closed-enum strings), `location.file` (workspace-relative), `location.line_start`
(1-based), `title`, `summary`, `tier`. Closed enums: `framing[*]` is `"auth"`
or `"injection"`; `tier` is `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`;
`detection_source`, optional but enforced when present, is `static_prescreen`,
`model_reasoning` or `both`.

`detection_source` records the origin of the candidate: `static_prescreen`
when the scanner raised the location and the model ruled it a real bug,
`model_reasoning` when the model raised it without a matching scanner
candidate, and `both` when the two converged on the same file and line across
walks. **`both` is produced only by per-walk dedup**, so single-call mode never
emits it.

Extra fields at both levels are allowed and ignored, so producers can carry
`grade`, `stream`, `scoring_passes`, `dedup_sources`, `location.line_end` and
similar through without the validator enforcing their shape.

**Stable-ID grammar.**

```
stable_id := framing "::" rel_file ":" line
```

The last `:` separates the line from the path, which admits `:` inside a
POSIX filename without an escape character. `rel_file` is byte-for-byte what
Lyrik sees on disk, with no Unicode normalization applied at the producer
side; filesystems disagree (Linux is bytes, macOS HFS+ may apply NFD, Windows
is UTF-16), so consumers comparing across platforms normalize themselves.

Conforming: `auth::src/foo.rs:42`, `injection::deeply/nested/file.py:1`,
`auth::a:b:c.rs:7`. Not conforming: an absolute path, an empty or unknown
framing, a missing or non-integer line.

`line` is the brittle component: a finding shifts line numbers when unrelated
edits land above it, so consumer-side fuzzy matchers should fall back to
file-proximity matching on an exact-ID miss.

`findings[]` is sorted by `(location.file, location.line_start)` ascending,
stable across runs of the same scope.

**Not in the 1.1 surface**, and consumers must not pin against them: a
top-level `target`, `funnel`, `concentration` or `observations` block;
per-finding `gate_routed`, `dedup_match` or `stream` as closed enums; a
`triage_status` field. 1.1 does not require producers to emit `$schema`, and
if a report carries one the validator asserts it string-equals `$id`.

## Reports and audit

```bash
wirken lyrik report --format sarif --run <run-id> --output findings.sarif
wirken lyrik validate --path findings.json
```

Every phase output writes to the Wirken audit subsystem with no opt-out, each
entry carrying a run ID that the final report includes so downstream readers
can pull the chain. The report opens with the assessment shape: counts of
findings produced, duplicates of each other, duplicates of earlier runs,
scored, sent for human review, exploit-tested, and set aside with the reason.
The numbers reconcile and a reader can check the math. That funnel disclosure
is the structural rebuttal to "we found N high-severity bugs": a finding count
without disclosure of what was dropped or stopped before scoring is not an
assessment.

Scanner rows (`lyrik.scanner.dispatched`, `lyrik.scanner.unavailable`,
`lyrik.candidate.declined`, `lyrik.candidate.unaddressed`) live in the per-run
NDJSON only and are not signed.

Each report records the source location (git URL, commit SHA, and whether the
run was on current code, before a fix, after a fix, or a pinned state), the
scoring guide path, the audit log path, and instructions to reproduce from a
clean clone.

## When markdown is not enough

If real use surfaces a boundary that `.lyrik/config.json` plus the `SKILL.md`
cannot carry, record it in `skills/lyrik/FOLLOWUPS.md` rather than growing
this guide or the skill body into a substitute for it.
