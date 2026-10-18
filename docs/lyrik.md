# Lyrik

<img src="img/lyrik-wirken.png" alt="Lyrik" width="360" align="right">

Lyrik audits a codebase against a scoring guide your team has written: a file
named with `--rubric`, else the `.lyrik/rubric.md` committed in the assessed
repo, else the rubric built into the skill. The findings it keeps go to
`findings.json`, with a funnel that accounts for every finding the run staged.
What it sets aside goes to the per-run audit log, one row each: scanner
candidates the model declined, with the model's reason, or left unaddressed,
and staged findings the runner refused or corrected.

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
there is no log of what the model considered, and when the model is unsure
the output does not say so.

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
scorers into a consensus, and does not send findings to any delivery channel.

## What ships today

- **Scoring against the team's rubric**, in single-call and walk mode, with
  the inline rubric in `SKILL.md` as the fallback. See
  [Writing the scoring guide](#writing-the-scoring-guide).
- **Team-owned files locked.** A run's agents may write only under the run's
  own directory, and the runner never writes `.lyrik/rubric.md`,
  `.lyrik/context.md` or `.lyrik/config.json`. It hashes all three at run
  start and end; if one changed, it records `lyrik.locked_file.changed` with
  the file and both sha256 values and the run fails.
- **Two-pass scoring.** Each finding is scored by two independent passes. When
  they disagree by more than one step on any axis the finding carries
  `scoring_disagreement: true` and the runner picks the lower-implied tier.
  That is the mechanism behind "will not average": disagreement is recorded
  and resolved conservatively.
- **Grade caps at 0.5.** The skill sets `grade: 0.5` when both passes mark
  `real_bug: yes` and `reachable: yes`, and `0` otherwise. The ceiling is by
  design: Lyrik confirms real-and-reachable, and exploit verification is a
  separate workload against the same findings. The runner enforces the cap
  for every walk: a staged finding whose `grade` is above 0.5 is written at
  0.5, and the per-run log records `lyrik.finding.grade_corrected` with the
  stable ID, the walk, and the original and new value.
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
  the case named. The probe is on the run's signed chain like every other
  model call.
- **Operator sign-off.** Outside `bench_mode` a run starts only on a yes at
  the terminal, recorded on the signed chain. See [Setup](#setup).
- **Bundled skill staged per run**, self-signed with a one-shot keypair so the
  loader's signature gate accepts it, which is why `/lyrik` resolves to the
  staged copy regardless of operator state under `<data_dir>/skills/`.
- **Citation-resolution gate.** For every emitted finding the runner confirms
  the cited file exists and the cited line resolves, then runs class-specific
  sub-gates on the cited line plus a window, routing to a named deferred tag
  when no honest check is available.
- **Per-skill restricted tool lists.** The skill's `permissions` block is
  enforced at runtime by the gateway. Lyrik ships its own; operators can
  review or tighten it before install. A run's agents attach only the run's
  own skills, the staged Lyrik copy and the staged walks, and nothing from the
  shared skills directory, so a shared skill's grants never widen a run:
  reads anywhere in the target, writes only under
  `.lyrik/state/runs/<run-id>/`.
- **Audit logs.** A per-run NDJSON `<run>/audit.log` for every dispatch
  decision, plus the signed hash-chained gateway chain for cross-session
  integrity. See [audit-cli.md](audit-cli.md).
- **Provenance, funnel and inference** on every `findings.json`. See
  [Reports and audit](#reports-and-audit).
- **JSON findings schema** with a reference validator and a SARIF emitter.

## Setup

1. Install Wirken and configure the provider that `phases.framing` names.
   See [getting-started.md](getting-started.md).
2. Write `.lyrik/config.json` in the assessed repo. Leave `bench_mode` false;
   it is for benchmark targets only.
3. Commit the team's rubric as `.lyrik/rubric.md`, and project context as
   `.lyrik/context.md` if you have one, or pass files outside the repo with
   `--rubric` and `--context`. See
   [Writing the scoring guide](#writing-the-scoring-guide).
4. Run `wirken lyrik run --target <repo> --run <run-id>` from a terminal. The
   run id names a directory under `.lyrik/state/runs/`, so an empty id, an
   empty, `.` or `..` component, an absolute path, `"`, `\` and control
   characters are refused, and on Windows `:` too; anything else, a timestamp
   or a name with spaces, is kept as given. Before any model call the run shows what it is about to
   do: the target's HEAD and whether tracked files changed, the rubric and
   context with their source and sha256, the provider and model, the walks and
   the commands each may ask to run through `exec`. It then asks
   `Sign off this run? [y/N]`. A yes is recorded on the signed chain as a
   one-shot `permission_approved` row whose action key carries the sha256 of
   the summary shown; anything else, or end of input, is recorded as a
   `permission_denied` row and the run stops. Without a terminal the run is
   refused.
5. The run writes `findings.json` and `audit.log` under
   `<repo>/.lyrik/state/runs/<run-id>/` and prints the funnel and inference.
6. The bundled skill does not run Phase 0. When a walk stages context or
   rubric sections, the runner joins them into
   `.lyrik/state/runs/<run-id>/proposed/context.md` and `proposed/rubric.md`
   and prints their paths; it never writes over the committed files.
   Promoting a proposal is a commit the team makes.

## What lives where

Operator-level state stays where it already lives in Wirken; the Lyrik config
does not duplicate or override it. The team's files in `.lyrik/` are
committed; run state lives under `.lyrik/state/`.

| Lives at | What |
|---|---|
| Wirken vault | provider API keys |
| `<data_dir>/sandbox.json` | sandbox mode |
| `<data_dir>/lyrik.json` | the operator's `walks_dir` |
| `<data_dir>/lyrik/walks/` | installed walk skills, by default |
| `<repo>/.lyrik/config.json` | scope, the run's model pin (`phases`), walks, scanner, bench mode |
| `<repo>/.lyrik/rubric.md` | the team's severity rubric |
| `<repo>/.lyrik/context.md` | the team's project context |
| `<repo>/.lyrik/state/runs/<run-id>/` | `findings.json`, `audit.log`, `proposed/`, staging; the only place a run's agents may write |

`.lyrik/config.json` names the provider, not its key:
`phases.framing.provider: "privatemode"` resolves through the vault. Lyrik
never sees a credential.

## `.lyrik/config.json`

A sample is at [`lyrik.example.json`](lyrik.example.json).

**`scope`**: `include` globs (default `["**/*"]`) and `exclude` globs
(default `["target/**", "node_modules/**", ".git/**"]`). A user request like
"assess only `src/`" overrides this for the run.

**`phases`**: provider and model pins keyed by phase name. The runner
resolves one pin for the whole run, `phases.framing`, else `phases.score`,
else `phases.recon`, and every model call in the run, the preflight probe and
each walk included, goes to it. Other keys, including `articulate`, `rubric`
and `exploit`, are accepted and not read; no exploit phase runs.

Confidentiality is the pin: there is no `confidential: true` flag, so pinning
the resolved phase to Privatemode or Tinfoil is the mechanism. A `score` pin
does not apply while a `framing` pin is present.

The skill assesses two framings, `auth` and `injection`, the same two the
findings schema 1.1 accepts. The SARIF emitter carries rules for nine: those
two plus `crypto`, `deserialization`, `memory_safety`, `secrets`,
`supply_chain`, `race_condition` and `prompt_injection`.

The runner holds every walk to the 1.1 enum before dedup. It removes framing
values outside the enum and records each removal in the per-run log as
`lyrik.finding.framing_stripped` with the stable ID, the walk and the removed
values. When the stable ID was keyed on a removed framing, it is rewritten to
the first framing that remains, and the row carries the written ID as
`stable_id_written`. A finding left with no framing in the enum, or with no
`framing` array, is not written to `findings.json`; the per-run log records
it whole as `lyrik.finding.refused`.

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
`sink-walk`), or when the named walk is not installed as
`<walks_dir>/<walk-name>/SKILL.md`; the error names the walks directory it
looked in. `max_concurrent_walks` defaults to 4,
tuned to the conservative end of common provider rate limits; 0 is rejected
and a value above the walk count is a no-op.

**The walks directory** is where installed walk skills live. It is the
operator's setting, not the target's: `walks_dir` in `<data_dir>/lyrik.json`,
a relative path resolved against the data directory and a leading `~/` the
home directory, else `<data_dir>/lyrik/walks`.

```json
{ "walks_dir": "~/walks" }
```

A `.lyrik/config.json` that sets `walks_dir` is refused before the run
starts. A target is input that may try to steer the run, and a directory it
chose would let its own text be staged as a walk. The runner reads the
installed walk files and never writes them; each run stages its own copy
under the run directory.

Each walk runs as its own task gated by a semaphore. Every walk's agent shares
the run-level session id (`lyrik-<run-id>`), so all walk turns land in one
signed audit chain however many run in parallel. Per-walk staging lives under
`.lyrik/state/runs/<run-id>/staging/<walk-name>/`.

The staged copy of a walk opens with a short section ahead of the installed
walk text: everything the walk writes goes under its staging directory, and a
harness the walk text would put in the project's test tree goes under
`staging/<walk-name>/harness/` instead. Promoting a harness into the test tree
is an operator step after the run. The staged frontmatter's `write_paths`,
`<workspace>/.lyrik/state/runs/<run-id>`, is what enforces it; the installed
walk files are not modified. When the run has a team rubric or context, the
staged walk carries it after that section.

`exec` stays gated. The staged section lists the commands a walk runs through
`exec` (`crypto-walk`: `cargo audit`; `fuzz-walk`: `cargo test`; `sink-walk`:
`git log`, `git blame`), and the run prints the same list before it starts.
With stdin on a terminal, the operator is asked at the moment each command is
about to run, one prompt at a time across concurrent walks, in a prompt that
is the walk's name and the exact command and nothing else; an answer covers
that one call and nothing is stored for later runs. Without a terminal every
such command is refused. A refused command is a skipped step, not a failed
walk. An approved command runs in the `exec` sandbox, so the sandbox image
needs `git` or `cargo` for these walks; the default image has neither. Before
the first prompt the run asks the sandbox which of the binaries its walks need
are missing, and names them, so no one approves a command that can only fail.

With sandbox `mode: off`, `exec` is not available in a run: an approved
command such as `cargo test` would run the target's build scripts on the host
with the host's network. The run's skills do not grant it, so a call is
refused by the tool gate and recorded on the chain, and the step is skipped.
The sign-off summary, each staged walk and the run's output say so.

Dedup on the merged output: findings sharing `(location.file,
location.line_start)` collapse to one; `framing` becomes the sorted unique
union; `tier` rises to the highest; `dedup_disagreement: true` when input
tiers differ; `dedup_sources` lists every contributing walk in first-seen
order. The first finding's `summary`, `id` and `stable_id` survive as
canonical. Findings without a file and line pass through unchanged, so a
malformed input does not collapse against everything else under a default key.

Exit `0` when at least one walk completed; non-zero when every selected walk
failed transiently. A refused call does not fail a walk or the run: the
refusal is on the chain, the model is told the step was not executed, and the
walk carries on. Each walk's `lyrik.walk.completed` row lists what it skipped
under `skipped`, as `tool (approval key)`, for example `exec (shell:git)`.
Either way a `findings.json` is produced. Two more conditions exit non-zero
after writing it: a funnel that does not reconcile, and a team-owned file that
changed during the run.

**`bench_mode`**: defaults false. Set it only on benchmark or
batch-evaluation targets: when true, the run does not ask for a sign-off and
writes `lyrik.phase_0.signoff` and `lyrik.high_severity_review.signoff` rows
with `decision: "auto_bench"`, so bench runs are distinguishable after the
fact. When false, the run asks at the terminal (see [Setup](#setup)); without
a terminal it writes a `lyrik.phase_0.signoff` row with `decision:
"pending_adapter_route"` and exits non-zero before dispatch. `scoring_disagreement` has no bench handling and no routing; a
disagreement is recorded on the finding as `scoring_disagreement: true`.

## Writing the scoring guide

A markdown file at `.lyrik/rubric.md` in the repo being assessed, or a file
outside it named with `--rubric`. The team owns it, commits it, and reviews it
in PR like any other artifact. It is not
CVSS-shaped (CVSS produces a number; a rubric produces tier definitions
specific to the software), not a compliance checklist, and not universal:
different projects need different rubrics, and the same project needs a
different one when its threat model changes.

Sections worth including: software identification; what counts as a security
property of *this* software and what does not; tier definitions with concrete
examples; **acknowledged tensions**, the project-level constraints the rubric
consciously accepts; and any run-specific constraints. A finding the rubric
does not cover is marked `rubric_silent: true` and keeps the tier the model
would otherwise emit, rather than getting an invented one.

The run picks its rubric in this order:

1. `--rubric <path>`, a file outside the target. A path inside the target is
   refused, since it would skip the check below.
2. `.lyrik/rubric.md`, when it is committed and its bytes match HEAD. An
   untracked or modified file is not used, nor one git would convert (a
   filter, LFS, line-ending or encoding conversion), whose bytes cannot be
   compared with HEAD; the run prints why and records it.
3. The inline rubric in the bundled `SKILL.md`.

Project context follows the same order with `--context` and
`.lyrik/context.md`, and is absent when neither applies. Whether a file
matches HEAD is decided by hashing it in-process against the blob HEAD
records, so no program the repository configures runs (see
[Reports and audit](#reports-and-audit)).

In single-call mode the team rubric takes the place of the inline rubric
section in the run's staged copy of the skill, followed by the context; in
walk mode each staged walk carries both after its run section. `findings.json`
records what was used as `rubric` and `context`, each `{source, path,
sha256}` with `source` one of `flag`, `team` or `inline`, and the per-run log
records the same as `lyrik.rubric.loaded`, with any skipped file and the
reason. For a flag file, `findings.json` carries the file name only, and the
full path stays in the per-run log.

Lyrik does not write the rubric for you. Rubric sections a run stages land
under the run's `proposed/` directory; promoting one is a commit the team
makes.

## Findings schema (1.1)

`findings.json` is the contract external consumers (SIEM ingestors, ticketing
systems, CI gates, diff tools) pin against.

`$id` is
`https://raw.githubusercontent.com/gebruder/wirken/schema-v1.1/docs/lyrik-json-schema.json`.
The schema is tag-pinned, not release-pinned: wirken releases that do not
change it do not move the tag, and schema changes cut a new tag and a new
spec. `wirken lyrik validate --path <path>` embeds the schema bytes and never
fetches `$id`; the URL is for external JSON Schema validators.

Pin the schema, not the CLI. `wirken lyrik` is outside Wirken's stability
surface: its subcommands, flags, run output, and the fields `findings.json`
carries outside schema 1.1 can change in any minor release. The 1.1 contract
changes only with a new schema tag.

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
`grade`, `stream`, `scoring_passes`, `dedup_sources`, `rubric_silent`,
`location.line_end` and similar through without the validator enforcing their
shape. The runner adds run-level extras of its own, outside the 1.1 contract:
`target_sha`, `target_dirty`, `audit_log_ref`, `rubric`, `context`, `funnel`
and `citation_check`.

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
top-level `target`, `funnel`, `concentration` or `observations` block (the
runner's `funnel` is one of the extras above);
per-finding `gate_routed`, `dedup_match` or `stream` as closed enums; a
`triage_status` field. 1.1 does not require producers to emit `$schema`, and
if a report carries one the validator asserts it string-equals `$id`.

## Reports and audit

```bash
wirken lyrik report --format sarif --run <run-id> --output findings.sarif
wirken lyrik validate --path findings.json
```

Every run writes the per-run `audit.log` with no opt-out, each row carrying
the run ID. The SARIF report carries the same ID as `automationDetails.id`
(`lyrik/run/<run-id>`) and on every result, so a reader can pull the rows for
a finding. `findings.json` carries a `citation_check` block with resolved and
unresolved counts per citation sub-gate; what the run set aside is in
`audit.log`, one row each: `lyrik.candidate.declined`,
`lyrik.candidate.unaddressed`, `lyrik.finding.refused`,
`lyrik.finding.framing_stripped` and `lyrik.finding.grade_corrected`.

**Funnel.** `findings.json` carries `funnel`, the run prints it at the end,
and the SARIF report carries it under the run's `properties.lyrik.funnel`:

- `walks`, one entry per walk (`lyrik` for single-call mode): `emitted`,
  `refused`, `framing_stripped`, `grade_corrected`, and the `skipped` steps
  from its `lyrik.walk.completed` row.
- `merged`: `emitted`, `refused`, `collapsed` (findings folded into another at
  the same location by dedup) and `kept` (findings in `findings.json`).
- `scanner`, when Semgrep ran: `candidates`, each counted once as `accepted`
  (a written finding sits at its location), `declined` (otherwise, when any
  walk declined it) or `unaddressed`.

Before writing, the runner checks emitted - refused - collapsed = kept, with
`kept` taken from the written findings list and `collapsed` from dedup's group
sizes, and that the scanner's three counts sum to its candidates. If either
check fails, `findings.json` is written without `funnel`, the per-run log
records `lyrik.funnel.mismatch` with every number, the staging directory is
kept, and the run exits non-zero.

Scanner rows (`lyrik.scanner.dispatched`, `lyrik.scanner.unavailable`,
`lyrik.candidate.declined`, `lyrik.candidate.unaddressed`) live in the per-run
NDJSON only and are not signed.

**Provenance.** At run start, before dispatch, the runner records on
`findings.json`:

- `target_sha`: HEAD of the repository the target sits in.
- `target_dirty`: whether any tracked file differs from HEAD in content,
  executable bit or kind, or a checked-out submodule sits at a different
  commit. Untracked files do not count. Files are compared byte for byte.
  Where git would convert content (a clean filter, LFS, line-ending, `ident`
  or encoding conversion, or `core.autocrlf`), the work-tree bytes are not the
  committed ones, so no comparison is made: `target_dirty` is null and a
  `lyrik.provenance.unavailable` row gives the reason.
- `audit_log_ref`: the run's `audit.log`, relative to the target.

The SARIF report carries all three in its invocation properties. A target
that is not in a git work tree, or whose HEAD has no commit, gets null git
fields and a `lyrik.provenance.unavailable` row with the reason. No remote URL
is recorded.

No program the target repository configures runs on the host. The runner asks
git only `rev-parse` and `ls-tree`, which read refs, config and objects and
neither refresh the index nor convert content, and `config --get` and
`check-attr`, which read config and attribute files, each with
`core.fsmonitor=false`, `protocol.allow=never`, no pager and inherited `GIT_*`
variables removed, and compares the work tree against HEAD in-process. It does
not use `git status` or `git diff`, which can run a repository's clean
filters.

**Inference.** `findings.json` carries `inference`, and the run prints it at
the end: `provider`, `model`, `calls` and `request_bytes`, read back from the
run's own rows on the signed chain, the tool-call probe and any compaction
summaries included. Each model call is an `llm_request` row naming the
provider, the model and the size of the messages and tool definitions it sent
(see [audit-cli.md](audit-cli.md)). `calls` counts distinct requests on the
chain; a rate-limit retry resends the same request to the same provider and
appears in the per-run log as `lyrik.dispatch.rate_limited`, not as another
call.

## Running on code you don't trust

A target is input, and its source, comments, config and git metadata can all
be written to steer the model or the host. Each protection below is enforced
by the runner or the gateway, and each has a test that drives the `wirken`
binary with a scripted model doing what a steered model would.

- **Writes confined to the run's directory.** A run's agents may write only
  under `.lyrik/state/runs/<run-id>/`; a write to `.lyrik/rubric.md`,
  `.lyrik/context.md`, `.lyrik/config.json`, another run's directory or the
  source tree is refused. The runner hashes the three team files at start and
  end and fails the run if one changed. `lyrik_team_files_stay_locked.rs`.
- **No network but the model provider.** `http_request`, `web_search`,
  `generate_image` and MCP tools are not offered to a run's agents; a call to
  one is refused at the tool gate, recorded on the chain, and the turn carries
  on. The runner refuses to attach a staged skill that grants any other tool,
  any egress or a credential, and runs Semgrep with metrics and its update
  check off. `lyrik_run_reaches_no_network.rs`.
- **No program the repository configures runs.** Provenance and the team-file
  check use only the git commands above; an fsmonitor hook and a clean filter
  set in the target's `.git/config` stay unrun.
  `lyrik_provenance_runs_nothing_the_repo_configures.rs`.
- **`exec` only in the sandbox.** With sandbox `mode: off` a run's agents get
  no `exec`. With the sandbox on, each command goes to the operator first.
  `lyrik_exec_sandbox_only.rs`.
- **Operator sign-off on the chain.** Outside `bench_mode` nothing reaches the
  model until the operator signs off at a terminal; the answer is on the
  signed chain, bound to the summary shown. `lyrik_signoff.rs`.
- **Every model call on the chain.** The probe, every turn and every
  compaction summary is an `llm_request` row with provider, model and size, and
  `inference` is read back from those rows. `lyrik_inference_matches_the_chain.rs`.

All six run with:

```bash
cargo test -p wirken-cli \
  --test lyrik_team_files_stay_locked \
  --test lyrik_run_reaches_no_network \
  --test lyrik_provenance_runs_nothing_the_repo_configures \
  --test lyrik_exec_sandbox_only \
  --test lyrik_signoff \
  --test lyrik_inference_matches_the_chain
```

They need `git` on `PATH`, and the sign-off tests need util-linux `script`
to give the run a terminal, so they run on Linux. None needs Docker or a
network.

What none of this prevents is a model that reports the wrong thing. Findings
are model output: a model steered by text in the target, or simply wrong, can
leave out a real bug or report one that is not there. The citation gate checks
that a cited file and line exist and the funnel accounts for every finding the
model staged, but nothing checks for a finding the model did not stage. An
approved `exec` command also still runs the target's code, inside the
sandbox.

## When markdown is not enough

If real use surfaces a boundary that `.lyrik/config.json` plus the `SKILL.md`
cannot carry, record it in `skills/lyrik/FOLLOWUPS.md` rather than growing
this guide or the skill body into a substitute for it.
