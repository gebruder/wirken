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
- **Team-owned files locked.** A run's agents' `write_file` is confined to the
  run's own directory by the staged skill's `write_paths`. In a per-walk run a
  walk's and a replay's `exec` runs with the target mounted read-only and its
  file tools write only the walk's own staging directory
  ([the exec envelope](#the-exec-envelope)); the single call's `exec` and the
  fix step's run with the target mounted read-write, so the hash check below
  is the control on that path. The runner never writes `.lyrik/rubric.md`,
  `.lyrik/context.md` or `.lyrik/config.json`. It hashes all three at run
  start and end; if one changed, it records `lyrik.locked_file.changed` with
  the file and both sha256 values and the run fails.
- **Two-pass scoring.** In single-call mode the skill scores each finding in
  two independent passes (`skills/lyrik/SKILL.md`); when they disagree by more
  than one step on any axis the skill sets `scoring_disagreement: true` and
  picks the lower-implied tier. The runner reads neither field; the SARIF
  emitter counts the passes (`crates/cli/src/commands/lyrik_sarif.rs`). The
  staged walk wrapper carries no two-pass instruction, so a walk scores in two
  passes only when its own text says so. That is the mechanism behind "will
  not average": disagreement is recorded and resolved conservatively by the
  skill.
- **Grade caps at 0.5.** The skill sets `grade: 0.5` when both passes mark
  `real_bug: yes` and `reachable: yes`, and `0` otherwise. The ceiling is by
  design: Lyrik confirms real-and-reachable, and exploit verification is a
  separate workload against the same findings. The runner enforces the cap
  for every walk: a staged finding whose `grade` is above 0.5 is written at
  0.5, and the per-run log records `lyrik.finding.grade_corrected` with the
  stable ID, the walk, and the original and new value.
- **Brocard rejections.** Eight rules for dismissing a candidate (`RULE_COUNT`,
  `crates/cli/src/commands/lyrik_brocards.rs`), the first seven adapted from
  the list at <https://vulnbrocards.com/>, where rule N is VB00N. Rule 1 (no
  threat model) is structural and runs in the gate. Rules 2 to 7 are judgment:
  the walks apply them under their own wrapper section, writing a file to
  `staging/<walk>/rejections/` (`WALK_RULE_MAX` is 7; nothing in the gate
  itself reads a seed's `detection_source` for rule 7). Rule 8 (replay
  disagrees) is the runner's, applied by `replay`; a walk-side rejection naming
  it is refused.
  Every applied rule is recorded under `rejected_candidates`, with its rule
  number, a one-line reason, and the gate or walk that applied it. The per-run
  log records `lyrik.brocard.rejected`, `lyrik.brocard.refused` for a rejection
  file that does not parse, and `lyrik.brocard.demoted`. What happens to the
  finding depends on `mode`: pentest halves its grade once per distinct rule,
  and defender removes it from `findings.json`. The same rejections are written
  one per line to `rejections.jsonl` in the run directory, each with
  `label: "negative"`, for calibration. A defender-mode fix an arm rejected
  adds a line with `kind: "fix"`, the arm and the reason.
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
- **Operator sign-off.** A run starts only on a yes at the terminal, recorded
  on the signed chain, unless the operator passes `--bench`. Nothing in the
  assessed repository skips it. See [Setup](#setup).
- **Bundled skill staged per run**, signed under a root the run's process
  holds in memory, so the loader accepts it in that process only, which is why `/lyrik` resolves to the
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
- **Provenance, funnel and inference** on every `findings.json` a run writes
  after its walks complete. The no-findings marker path carries neither
  `funnel` nor `inference`, the rate-limit and context-overflow paths carry
  `inference` only, and `--use-fixture` carries none. See
  [Reports and audit](#reports-and-audit).
- **JSON findings schema** with a reference validator and a SARIF emitter.

## Setup

1. Install Wirken and configure the provider that `phases.framing` names.
   See [getting-started.md](getting-started.md).
2. Write `.lyrik/config.json` in the assessed repo.
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
   the commands each may run through `exec`, and for a per-walk run
   [the envelope](#the-exec-envelope) they run in. It then asks
   `Sign off this run? [y/N]`. A yes is recorded on the signed chain as a
   one-shot `permission_approved` row whose action key carries the sha256 of
   the summary shown; anything else, or end of input, is recorded as a
   `permission_denied` row and the run stops. Without a terminal the run is
   refused.
5. The run writes `findings.json` and `audit.log` under
   `<repo>/.lyrik/state/runs/<run-id>/` and prints the funnel and inference.
6. The bundled skill does not run Phase 0. When the single-call skill stages
   context or rubric sections under `staging/context/` and `staging/rubric/`,
   the runner joins them into `.lyrik/state/runs/<run-id>/proposed/context.md`
   and `proposed/rubric.md` and prints their paths; it never writes over the
   committed files. Sections a walk writes under `staging/<walk>/context/` and
   `staging/<walk>/rubric/` are not aggregated (`aggregate_phase0_section`
   calls in `crates/cli/src/commands/lyrik.rs`).
   Promoting a proposal is a commit the team makes.

## What lives where

Operator-level state stays where it already lives in Wirken; the Lyrik config
does not duplicate or override it. The team's files in `.lyrik/` are
committed; run state lives under `.lyrik/state/`.

| Lives at | What |
|---|---|
| Wirken vault | provider API keys, and a plan sign-in when the pin names one |
| `<data_dir>/sandbox.json` | sandbox mode |
| `<data_dir>/lyrik.json` | the operator's `walks_dir`, `walk_tool_rounds`, `fix_tool_rounds`, `walk_continuations`, `transport_retries`, `run_ceiling_usd`, `run_ceiling_model_seconds`, `run_ceiling_model_calls` and `plan_child_binary` |
| `<data_dir>/lyrik/walks/` | installed walk skills, by default |
| `<repo>/.lyrik/config.json` | scope, the run's model pin (`phases`), walks, scanner, bench mode, brocard mode |
| `<repo>/.lyrik/rubric.md` | the team's severity rubric |
| `<repo>/.lyrik/fix-patches/<slug>.patch` | optional: a patch for the defender fix step to check in place of writing one |
| `<repo>/.lyrik/context.md` | the team's project context |
| `<repo>/THREAT_MODEL.md`, else `<repo>/docs/threat-model.md` | the target's own threat model, loaded when committed and unmodified. The first of the two that exists is the one checked; when it is uncommitted or modified it is skipped with its reason and the other path is not tried (`load_target_threat_model`, `crates/cli/src/commands/lyrik.rs`); see [lyrik-brocards.md](lyrik-brocards.md#the-targets-threat-model) |
| `<repo>/.lyrik/ledger/` | what earlier runs established about the target, one JSON record per claim; written by the runner, never by a run's agents |
| `<repo>/.lyrik/state/runs/<run-id>/` | `findings.json`, `rejections.jsonl`, `audit.log`, `proposed/`, staging; the only place a run's agents may `write_file` |

`.lyrik/config.json` names the provider, not its key:
`phases.framing.provider: "privatemode"` resolves through the vault. Lyrik
never sees a credential.

## `.lyrik/config.json`

A sample is at [`lyrik.example.json`](lyrik.example.json).

**`scope`**: `include` and `exclude` glob lists. The runner does not read
them; the keys it reads are `phases`, `mode`, `scanner`, `walks`,
`max_concurrent_walks` and `walks_dir`. The single-call skill text tells the
model to honour them, to treat the whole workspace as in scope when they are
absent, and to skip `.git/` and `.lyrik/` regardless (`skills/lyrik/SKILL.md`);
the staged walk prompts do not mention them (`crates/cli/src/commands/lyrik_walks.rs`).

**`phases`**: provider and model pins keyed by phase name. The runner
resolves the run pin from `phases.framing`, else `phases.score`, else
`phases.recon`, and the preflight probe, the replay step and the fix step use
it. A per-walk run may give a walk its own model: an entry keyed by the walk's
name (for example `phases.sink-walk`) overrides the `model` (and `max_tokens`)
for that walk only. The provider, base URL and credential stay the run's, so a
per-walk entry that names a different `provider` or a different `auth` is
refused; a walk with no entry of its own uses the run pin. Each distinct model is tool-call-probed
before the run, and a walk's model is on its `lyrik.walk.started` row. When a
walk has its own model, the sign-off summary carries a `models` line with the
model of each selected walk. Other
keys, including `articulate`, `rubric` and `exploit`, are accepted and not
read; no exploit phase runs. A pin may
carry `max_tokens`, the output tokens allowed per model reply; absent,
Wirken's own default applies, 16,000 for the `anthropic` provider and 4096
for every other. A reply that writes a whole file in one
tool call, as the fix step's patch does, is cut off at the limit, so a run
whose fixes are more than a few lines sets it higher. The sign-off summary
names the limit when the pin sets one.

Confidentiality is the pin: there is no `confidential: true` flag, so pinning
the resolved phase to Privatemode or Tinfoil is the mechanism. A `score` pin
does not apply while a `framing` pin is present.

The bundled single-call skill assesses two framings, `auth` and `injection`.
A walk may report a finding of any class: `framing` is the finding's class, a
lower-case name such as `memory_safety`, `unbounded_alloc` or
`race_condition`. The SARIF emitter carries named rules for nine classes
(`auth`, `injection`, `crypto`, `deserialization`, `memory_safety`, `secrets`,
`supply_chain`, `race_condition`, `prompt_injection`) and adds a rule for any
other class a run's findings carry.

The runner keeps a finding of any class. Schema 1.1 named only `auth` and
`injection`, and until schema 1.2 a walk finding of any other class was
dropped at aggregation. Before dedup the runner turns a single class written
as a string into a list of one, and removes `framing` values that are not
class names (`[a-z][a-z0-9_]*`), recording each removal in the per-run log as
`lyrik.finding.framing_stripped` with the stable ID, the walk and the removed
values. When the stable ID was keyed on a removed value, it is rewritten to
the first framing that remains, and the row carries the written ID as
`stable_id_written`. A finding left with no class name, or with no `framing`,
is not written to `findings.json`; the per-run log records it whole as
`lyrik.finding.refused`. The staged wrapper tells every walk the fields a
finding carries (`framing`, `location`, `stable_id`, `id`, `title`, `summary`,
`tier`); the runner does not rewrite a `stable_id` that is off the grammar or
supply a missing `tier`, and `wirken lyrik validate` reports both.

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
the run-level session id (`lyrik-<run-id>`, a `/` in a nested run id written as `-`), so all walk turns land in one
signed audit chain however many run in parallel. Per-walk staging lives under
`.lyrik/state/runs/<run-id>/staging/<walk-name>/`.

The staged copy of a walk opens with a short section ahead of the installed
walk text: everything the walk writes goes under its staging directory, and a
harness the walk text would put in the project's test tree goes under
`staging/<walk-name>/harness/` instead. Promoting a harness into the test tree
is an operator step after the run. The staged frontmatter's `write_paths`,
`<workspace>/.lyrik/state/runs/<run-id>`, confines writes to the run
directory; keeping to the walk's own staging directory within it is the
wrapper's instruction, not enforced (`run_write_scope`,
`crates/cli/src/commands/lyrik_walks.rs`). The installed walk files are not
modified. When the run has a team rubric or context, the
staged walk carries it after that section.

**Step records.** Each numbered step of a walk's text ends by writing
`staging/<walk-name>/steps/step-NN.json`, and the next step starts by reading
that file with `read_file`. The record holds `step`, `claim` (one falsifiable
sentence), `code_revision` (the revision the dispatch prompt names), `check`
(the command run, or the file and lines read), `evidence` (raw quoted lines or
command output, non-empty), `open_questions`, and `prior`, the file name of the
record the step read first; the first record has none. The runner checks each
file: it must parse, no field may be blank, `evidence` may not be empty,
`code_revision` must be the run's `target_sha` when the run has one, and
`prior` must name the file before it. A file that fails is recorded as
`lyrik.step.refused` in the audit log with the reason, and the walk's other
records stand. Accepted records are carried in `findings.json` under
`step_records`. A `check` that names a command is held to the run's chain: it
is a read when it opens with `read`, `read_file`, `list_files` or a file of
the target, and a command otherwise, and a command must be one an `exec` call
of the citing walk ran: a line the walk ran is split into its simple commands
on `;`, `&&`, `||`, `|` and newlines, and the cited command must equal one of
them word for word as a shell reads them, redirections aside, so quoting and
spacing do not matter and a command run as part of a longer line is found. The record carries
`check_status` `executed` or `not_executed`; a `not_executed` one is also a
`lyrik.step.check_not_executed` row and is counted in the walk's funnel. The staged wrapper tells the walk all of this; the walk text
itself is not edited.

**Target threat model.** When the scanned repository has `THREAT_MODEL.md`
at its root or, failing that file's existence, `docs/threat-model.md`, committed and unmodified, every staged
walk and the staged Lyrik copy carry its text after the project context, and
the brocard adjudication checks each finding's `threat_model` against it.
[lyrik-brocards.md](lyrik-brocards.md#the-targets-threat-model) has the
sections the file is expected to carry and which rule each check records.

**Fix step, defender mode only.** After aggregation, a run in `defender`
mode takes each confirmed finding, one kept by the gate and backed by a
reproduction the replay agreed with, and produces a candidate fix with a set
of arms that check it. [Defender fix step](#defender-fix-step) has the arms,
the record and what a state means.

**Reproductions and replay.** A command a walk runs to show a finding leaves
a record under `staging/<walk-name>/reproductions/`. After the walks return,
the run starts one fresh agent per record, whose prompt holds only the record
(it is told to read nothing else; the run's `read_paths` still cover the
target), runs
the same command, and writes its own observation under
`staging/<walk-name>/replays/`. The two are carried side by side in
`findings.json` under `reproductions`; a replay that disagrees is brocard
rule 8 against the finding. [lyrik-brocards.md](lyrik-brocards.md#reproductions-and-replay)
has the fields and the rule.

`exec` stays gated. The staged section lists the commands a walk is expected
to ask for, and the run prints the same list before it starts. The list is
read off the target, not fixed: `sink-walk` is offered `git log` and
`git blame` when the target is a git checkout; `crypto-walk` is offered
`cargo audit` when the target has a `Cargo.toml`; `fuzz-walk` and
`invariant-walk` are offered the target's test command, which is
`fix.test_command` from `.lyrik/config.json` when set and otherwise the usual
one for the language at the target's root (`cargo test`, `npm test`,
`go test ./...`, `python3 -m pytest`), or none. A shell project is not offered
`cargo test`. Every walk is also told it may ask to run a script it wrote
under its own `staging/<walk>/harness/` directory, with `sh` or the target's
interpreter, under the marker contract, that this is how a finding gets a
reproduction, and that the replay runs the same command. The list is what is
expected, not a limit. The section
also tells the walk how many tool rounds its turn has: 20, or
`walk_tool_rounds` in the data directory's `lyrik.json` when the operator set
one (`{ "walk_tool_rounds": 60 }`; zero is read as the default, and a
target's `.lyrik/config.json` does not set it). The number is on
`lyrik.dispatch.started`. A walk whose turn ends
with a reply is recorded on `lyrik.walk.completed` with status `turn_ended`,
which says the turn ended and nothing about what the walk staged;
`findings_staged` on the same row says that. A walk that uses its rounds
up ends there: the per-run log records `lyrik.walk.completed` with status
`incomplete` and the limit it reached, what it had staged is still aggregated,
and the walk's `walk_summary` entry in `findings.json` carries
`incomplete_at_tool_rounds`.

### The exec envelope

In a per-walk run every `exec` of a walk or a replay runs inside one envelope,
and the run's sign-off approves all of them: no command is asked again.

- The target is mounted read-only.
- The walk's own `staging/<walk>/` is the one directory mounted read-write. A
  replay writes `staging/<walk>/replays/` of the walk whose record it replays.
- Another walk's staging directory is behind an empty read-only mount: a
  command cannot read or write it.
- There is no network.

The walk's file tools are held to the same: `write_file` is refused outside
the walk's own staging directory, and `read_file` and `list_files` are refused
in another walk's staging directory except for the record files
`staging/index.json` lists (its `findings/*.json` and `rejections/*.json`).
Each refusal is a `skill_permission_denied` row.

The sign-off summary states the envelope on its `envelope` line, and the
summary's sha256 is on the sign-off's `permission_approved` row. Each command
still gets its own `permission_approved` row, with `approved_by`
`lyrik-signoff` and `approved_via` `{"kind":"grant","grant":"lyrik:signoff:<sha256>"}`,
the action key of the sign-off's own row, then its `assistant_tool_calls` and
`tool_result` rows. A
scope that cannot be mounted (a staging directory that is missing or is a
link) refuses the `exec`. A call that needs approval and is not an `exec` is
asked at the terminal. The single call (no `walks`) and the fix step have no
envelope and ask for each command as before. A `--bench` run has the same
mounts and file scope and no sign-off: at a terminal it asks before each
command.

Without a terminal there was no sign-off, and every `exec` is refused: the run
says so once, before it dispatches, and each
refusal's `permission_denied` row carries `denial_reason` `no terminal for
approval`. A refused command is a skipped step, not a failed
walk. A command runs in the `exec` sandbox, so the sandbox image
needs the binaries those commands name; the default image has neither `git`
nor `cargo`. Before
the walks are staged the run asks the sandbox, with the target mounted
read-only, which tools are missing and whether its shell expands braces, and
records the answer as `lyrik.sandbox.probed`. It asks about the binaries the
walks' commands need, about `rg`, `grep`, `find`, `jq` and `sha256sum` on
every run, and about `git`, `sed`, `awk`, `curl`, `cargo`, `semgrep`,
`python3`, `npm`, `go`, `make` and `node` when a selected walk's own text
names them. It names what is missing, and the staged walk text carries the
answer: a walk is not offered an interpreter the image lacks, is told each
tool that is not there with what to use in its place (`grep -rn` for `rg`,
`read_file` for `grep` and `jq`, `list_files` for `find`), and is told when
the shell does not expand braces, without being shown the form.

With sandbox `mode: off`, `exec` is not available in a run: an approved
command such as `cargo test` would run the target's build scripts on the host
with the host's network. The run's skills do not grant it, so a call is
refused by the tool gate and recorded on the chain, and the step is skipped.
The sign-off summary, each staged walk and the run's output say so.

Dedup on the merged output: findings sharing `(location.file,
location.line_start)` collapse to one; `framing` becomes the sorted unique
union; `tier` rises to the highest; `dedup_disagreement: true` when input
tiers differ; `dedup_sources` lists every contributing walk in first-seen
order, and `merged_from` each member's walk and the `stable_id` it gave the
finding. The first finding's `summary`, `id` and `stable_id` survive as
canonical. Its `evidence` is the strongest any member's reproductions earned,
looked up under each member's own id, and `evidence_source` names the walk, the
id and the reproduction that earned it, with the runner's trace (`execution`). Findings without a file and line pass through unchanged, so a
malformed input does not collapse against everything else under a default key.

Exit `0` when at least one walk completed, was stopped at the tool round
limit or was ended at one of the run's ceilings; non-zero when every selected
walk failed transiently. A refused call does not fail a walk or the run: the
refusal is on the chain, the model is told the step was not executed, and the
walk carries on. Each walk's `lyrik.walk.completed` row lists what it skipped
under `skipped`, as `tool (approval key)`, for example `exec (shell:git)`.
Either way a `findings.json` is produced. Two more conditions exit non-zero
after writing it: a funnel that does not reconcile, and a team-owned file that
changed during the run.

**`mode`**: `"pentest"` or `"defender"`, defaults to `"pentest"`. Any other
value fails the run before any walk runs. Pentest keeps a brocard-rejected finding
and halves its grade once per distinct rule that applied. Defender removes the
finding from `findings.json`; its rejection record stays. The funnel counts
removed candidates as `brocard_removed`. A Semgrep seed whose only candidate was
removed counts as `brocard_rejected` in the scanner funnel, not `accepted`.

**`fix`**: optional, read in defender mode. `test_command` is the project's
test suite and `coverage_command` a command whose output lists each source
file with a coverage percentage, both as run from the project root. The fix
step runs them in copies of the scanned revision for the functionality arm.
When absent, the `fix-recheck` agent picks the project's own.

**`--bench`**: a flag on `wirken lyrik run`, for benchmark and
batch-evaluation targets. With it the run does not ask for a sign-off and
writes a `lyrik.phase_0.signoff` row before dispatch and a
`lyrik.high_severity_review.signoff` row after the walks and the locked-file
check succeed, both with `decision: "auto_bench"`, so bench runs are
distinguishable after the
fact. A `bench_mode` key in `.lyrik/config.json` is not read: the config is a
file in the assessed repository, and the run says so when it finds the key set.
Without the flag, the run asks at the terminal (see [Setup](#setup)); without
a terminal it writes a `lyrik.phase_0.signoff` row with `decision:
"pending_adapter_route"` and exits non-zero before dispatch. `scoring_disagreement` has no bench handling and no routing; a
disagreement is recorded on the finding as `scoring_disagreement: true`.

## Staged results and truncation

**A walk's results are its staged records, not its last reply.** Each walk
writes every finding to its own `staging/<walk>/findings/finding-NNN.json` when
the finding is established, and ends with a summary of a few lines. The runner
builds `findings.json` from the staged files. The staged copy of each walk
carries these instructions; the installed walk text is not changed.

**A reply cut off at the output limit does not end a walk.** When a walk's
reply ends with stop reason `max_tokens`, the runner keeps what is staged,
records the walk as truncated with the number of findings kept, and sends a
continuation turn in the same conversation that names the kept records. The
operator caps continuations with `walk_continuations` in the data directory's
`lyrik.json`; the default is 2 and 0 sends none. A target's
`.lyrik/config.json` does not set it.

```json
{ "walk_continuations": 3 }
```

A walk that stops for another reason is not continued; what it staged before
stopping is still aggregated.

**A walk reads another walk's output through an index.** The runner writes
`staging/index.json` before the walks start and again after every turn: one
entry per staged finding or rejection with its `walk`, `kind`, `id`, `title`,
`file`, `line`, `tier` and `path`. A walk is told to read the index first and
then only the records it needs.

A walk whose provider request fails in transport (no response arrived) has the
request sent again, `transport_retries` times in the data directory's
`lyrik.json`; the default is 2 and 0 sends once. A walk stopped at the tool
round limit is recorded as `incomplete` with the limit it reached, not as a
failure; what it staged is aggregated.

## The ledger

### What it is for

A run costs model time, and most of that goes on showing that a finding is
real: writing a harness, running it, replaying it, checking a patch. Once a
run has shown something by running it, the next run on the same code should
not pay for it again. The ledger is the list of what earlier runs established
about the target, kept in the target under `.lyrik/ledger/`, one small JSON
file per claim.

It records three strengths of knowledge and treats them differently:

- **Observed**: code the claim is about ran, and the run is on record. For a
  finding or a replay rejection that means the runner's own trace of the
  reproduction shows a line of the cited function executing
  ([execution evidence](lyrik-brocards.md#execution-evidence)); for a fix arm,
  that the patch's check ran. While the file the claim is about has not
  changed, an observed claim is settled. A walk that sets out to check it
  again is told no, and pointed at the record.
- **Static confirmed**: a check of the claim ran and agreed, and nothing shows
  the code ran: a harness that read or parsed the source and printed the
  marker, a harness the tracer cannot follow. It settles nothing and is not
  carried.
- **Reasoned**: read from the source, nothing run. This is a lead. A walk is
  shown it and may check it properly.

When a file changes, every claim made about its old content is marked stale.
A stale claim settles nothing: the work is done again against the new content.

### How to read a record

This is the record run `ledger-a` wrote on the toy `slotcopy` target (a small
test target kept outside this repository):

```json
{
  "id": "8d119573a9960912",
  "kind": "finding",
  "key": "missing_bounds_check::len.sh:3",
  "claim": "decode_len returns the header-declared length unbounded; a.sh and b.sh copy it into an 8-byte slot",
  "file": "len.sh",
  "line": 3,
  "commit": "ceb4ad85a0b581ffe27ea2353ec01cf406a1cf58",
  "file_sha256": "b498b782f41a27e47d0fa666d6959789fa28cec924a4950d28765314987fcdeb",
  "evidence": "observed",
  "run": "ledger-a"
}
```

| Field | Meaning |
|---|---|
| `id` | stable for a `(kind, key)` pair; also the file name, `.lyrik/ledger/<id>.json` |
| `kind` | `finding` (the defect is there), `rejection` (a proposed defect was set aside) or `arm_result` (a check of a patch gave a result) |
| `key` | `<class>::<file>:<line>`; for an arm result, the finding's key and `#<arm>` |
| `claim` | the claim in words |
| `file`, `line` | where, relative to the target's root |
| `commit` | the revision it was established at, when the target is a git checkout |
| `file_sha256` | SHA-256 of the file's content when it was established |
| `evidence` | `observed`, `static_confirmed` or `reasoned` |
| `run` | the run that produced it; its `findings.json` and audit log hold the detail |
| `tier` | on a finding, the severity tier the run gave it |
| `stale` | present and true when the file's content has changed since |

A record names no model, provider, walk or harness. It is a statement about
the target.

After a run the runner writes one record per kept finding (`observed` when a
reproduction was agreed and its trace shows cited code ran, `static_confirmed`
when one was agreed without that, else `reasoned`), one per rejection (a replay
rejection, rule 8, is `observed` when its trace shows cited code ran and
`static_confirmed` otherwise; any other is `reasoned`), and one per fix
arm that passed or failed on an executed run. A finding or rejection record
written as `observed` carries `traced`; one stored without it, by a build that
took no traces, is rewritten as `static_confirmed` when the ledger is read. A
reasoned record never replaces
an observed one whose file is unchanged. The example that follows is of a shell
target, recorded before traces were taken: its finding record would now be
`static_confirmed`, and would not be settled or carried. After run `ledger-c`
the same target
held the finding and three arm results:

```
arm_result missing_bounds_check::len.sh:3#functionality  observed  a patch for this finding passed the functionality check
arm_result missing_bounds_check::len.sh:3#variant        observed  a patch for this finding failed the variant check
finding    missing_bounds_check::len.sh:3                observed  decode_len passes the header-declared length through unbounded
arm_result missing_bounds_check::len.sh:3#reproduction   observed  a patch for this finding passed the reproduction check
```

### What a walk is handed

Before a run's walks start, the runner reads the ledger and writes each walk
`staging/<walk>/ledger.json`:

- `area`: the full records, not stale, for the files of the run's area. The
  area is `scope` in `.lyrik/config.json`: a file an `include` pattern matches
  and no `exclude` pattern does; every file when there is no `include`.
- `index`: one line for every other record, stale ones included, with `id`,
  `key`, `evidence` and `stale`. A walk reads one of these whole at
  `.lyrik/ledger/<id>.json`.

In run `ledger-c`, after the decoder file had changed, the hand-off was:

```json
{
  "area": [],
  "index": [
    { "evidence": "observed", "id": "8d119573a9960912", "key": "missing_bounds_check::len.sh:3", "stale": true }
  ],
  "read_a_record_at": ".lyrik/ledger/<id>.json"
}
```

### A claim is registered before the work

Before a walk writes a harness, runs a check or stages a finding for a defect,
it writes `staging/<walk>/claims/claim-NNN.json` with the class, file and line
the finding would carry:

```json
{ "class": "missing_bounds_check", "file": "len.sh", "line": 3 }
```

The runner answers while the walks run, beside the claim, as
`claim-NNN.decision.json`. `registered` means go on, and the answer carries the
ledger records for that file. `refused` means an observed record already
settles it. This is the answer run `ledger-b` gave on the commit `ledger-a`
had scanned:

```json
{
  "decision": "refused",
  "established_by_run": "ledger-a",
  "key": "missing_bounds_check::len.sh:3",
  "reason": "an earlier run observed this claim against the file as it is now; do not check it again and do not stage a finding for it",
  "record": "8d119573a9960912",
  "record_path": ".lyrik/ledger/8d119573a9960912.json"
}
```

Each answer is a `lyrik.claim.registered` or `lyrik.claim.refused` row, and
`findings.json` lists the refusals under `claims_refused`.

A second check stands behind the first. When a run's results are put together,
a staged finding that repeats a settled record is refused: it is moved to
`staging/<walk>/ledger-refused/`, a `lyrik.ledger.refused` row names the record
and its run, and `findings.json` lists it under `ledger_refused`. A walk that
did not register a claim, or went on after a refusal, is caught there.

A claim matches a settled record by place, not by name: the same file, within
two lines of the record's line, whatever class the walk gave it. Two walks
that call one defect `unbounded_length` and `missing_bounds_check` are making
the same claim. During run `ledger-e2` a claim of class `heap_overflow` at
`len.sh:3` and one of class `missing_bounds_check` at `len.sh:4` were both
refused against the record `unbounded_length::len.sh:3` that `ledger-e1` had
written; the refusal quotes the record:

```json
{
  "decision": "refused",
  "established_by_run": "ledger-e1",
  "key": "heap_overflow::len.sh:3",
  "record": "6ccb28f1e9899bf6",
  "record_key": "unbounded_length::len.sh:3",
  "record_claim": "decode_len passes the header-declared length through unbounded; a.sh/b.sh copy more than the 8-byte slot",
  "if_yours_is_a_different_defect": "register again with `differs_from` set to the record id and `how`, one sentence on how your claim differs from it"
}
```

Those two claims were written by the operator into the run's staging directory
while it ran, to see the runner's answer; the walks' own claims in that run
were at other places.

Refusal is the default. A walk whose claim really is another defect at the
same place registers again with two more fields:

```json
{ "class": "race", "file": "len.sh", "line": 3,
  "differs_from": "6ccb28f1e9899bf6",
  "how": "The record is the missing bound; this is two writers to the same slot." }
```

That is answered `registered_distinct`, written as a
`lyrik.claim.registered_distinct` row with the sentence, and counted in the run
summary. Its finding is then left alone when results are put together.

### Settled findings are carried into a run's output

A repeat run on unchanged code does not read as empty. After a run's own
findings are final, the runner adds to `findings.json` each settled finding
record for a file in the run's scope that the run did not keep a finding at
itself. A carried finding has the record's class, place, claim and tier, and a
`carried` object naming the run that established it:

```json
"carried": { "commit": "022ca0eb6e280b504f8507cd4eb4df59938492e6", "evidence": "observed",
             "from_run": "ledger-e1", "record": "6ccb28f1e9899bf6" }
```

The run prints what it carried, here from `ledger-e2`:

```
carried from the ledger: 1 finding(s) an earlier run observed, files unchanged: unbounded_length::len.sh:3
```

In SARIF the result's `properties.lyrik.carried` has the same object. A stale
record is not carried, and neither is a reasoned one. A carried finding gets
no replay and no fix step in the run that carries it, and writes no new ledger
record.

### What it looks like across runs

Four runs on the toy target, in order. The run prints one line per walk, and
`findings.json` carries the same under `walk_summary`.

Run `ledger-a`, first run, empty ledger. 293 seconds: two walks, two replays
and the fix step.

```
walk sink-walk: 1 finding(s) staged, 1 claim(s) registered, 0 refused at registration as already observed
walk fuzz-walk: 1 finding(s) staged, 1 claim(s) registered, 0 refused at registration as already observed
```

Run `ledger-b`, same commit. 58 seconds: both walks were refused at
registration, nothing was staged, and no harness, replay or fix step ran.

```
walk sink-walk: 0 finding(s) staged, 0 claim(s) registered, 1 refused at registration as already observed
walk fuzz-walk: 0 finding(s) staged, 0 claim(s) registered, 1 refused at registration as already observed
```

Run `ledger-c`, after one line was added to `len.sh`. The run's log has
`lyrik.ledger.loaded {"records": 1, "settled": 0, "stale": 1}`; both claims
were registered and the work was done again, in 350 seconds.

```
walk sink-walk: 1 finding(s) staged, 1 claim(s) registered, 0 refused at registration as already observed
walk fuzz-walk: 1 finding(s) staged, 1 claim(s) registered, 0 refused at registration as already observed
```

Run `ledger-d2`, a fresh copy with the output limit set to 350 tokens a reply.
Each walk's final reply was cut off, the runner kept what was staged and sent
continuations up to the cap of 2, and each walk ended with one finding.

```
walk sink-walk: 1 finding(s) staged, truncated 3 time(s) at the output limit (kept 0, 0, 1), 2 continuation(s), 1 claim(s) registered, 0 refused at registration as already observed
walk fuzz-walk: 1 finding(s) staged, truncated 2 time(s) at the output limit (kept 1, 1), 2 continuation(s), 1 claim(s) registered, 0 refused at registration as already observed
```

### Staleness, and starting over

A record whose file no longer has the content it was established against is
marked `stale` in its file the next time the ledger is read. A stale record
blocks nothing and is handed to walks only as an index line. If the file
returns to that content the mark is removed. A new observation of the same
claim replaces the stale record.

The ledger is read and written only in per-walk runs. A `--bench` run and a
fixture replay neither read nor write it. `.lyrik/ledger/` can be committed
with the repository or ignored; delete it to start over.

## Cost guard

A run has three ceilings, each set in the data directory's `lyrik.json` and
each optional: recorded cost (`run_ceiling_usd`), model time
(`run_ceiling_model_seconds`) and model calls (`run_ceiling_model_calls`). A
target's `.lyrik/config.json` sets none of them. The run stops at the first
one it reaches.

**A ceiling on a run's cost.** `run_ceiling_usd` in the data directory's
`lyrik.json` is the most a run may spend, in USD of recorded cost. There is no
ceiling unless the operator sets one. A target's `.lyrik/config.json` does not
set it.

```json
{ "run_ceiling_usd": 25 }
```

The runner adds up the cost on the run's `llm_response` rows every two seconds.
When the sum reaches the ceiling it says so, ends the walks' turns, starts no
replay and no fix step, and builds `findings.json` from what is staged. The
run exits zero. Because the check runs every two seconds a run goes over by
what it spends in that time. From run `ledger-f`, with the ceiling at $0.15:

```
wirken lyrik: the run reached its cost ceiling of $0.15 ($0.18 recorded over 10 model calls); stopping, staged findings are kept
walk sink-walk: 0 finding(s) staged, stopped at the run's cost ceiling, staged findings kept
walk fuzz-walk: 0 finding(s) staged, stopped at the run's cost ceiling, staged findings kept
cost: $0.18 recorded over 10 model call(s)
stopped at the cost ceiling of $0.15: walks were ended, staged findings were kept, and no replay or fix step ran after it
```

The sign-off banner shows the ceiling, or that none is set. The first line is
from run `ledger-e1`; the second is the text for a data directory with no
ceiling:

```
  ceiling  the run stops at $5.00 of recorded cost (`run_ceiling_usd` in lyrik.json)
  ceiling  none set: this run has no cost limit (`run_ceiling_usd` in lyrik.json sets one)
```

**Ceilings on model time and model calls.** `run_ceiling_model_seconds` is the
most model time a run may take: the `latency_ms` of its `llm_response` rows,
summed, so calls that overlap in concurrent walks each count in full.
`run_ceiling_model_calls` is the most model calls it may make, the preflight
probe included. Neither depends on a price, so both hold for a model with no
price entry and for any plan sign-in. They are checked with the cost ceiling,
every two seconds, and a run stopped at one ends as a run stopped at the cost
ceiling does. Zero is read as unset.

```json
{ "run_ceiling_model_seconds": 7200, "run_ceiling_model_calls": 400 }
```

The banner, the stop and the summary name each one that is set (from the
tests in `crates/cli/src/commands/lyrik_cost.rs`, not a run):

```
  time     the run stops at 3600 second(s) of model time (`run_ceiling_model_seconds` in lyrik.json)
  calls    the run stops at 400 model call(s) (`run_ceiling_model_calls` in lyrik.json)
wirken lyrik: the run reached its model-call ceiling of 3 (3 model calls recorded); stopping, staged findings are kept
model-time ceiling 3600 second(s): not reached (75 recorded)
```

**A run on a plan sign-in.** A pin with `"auth": "plan"` runs on the
operator's plan at the `openai` provider in place of an API key (see
[Plan sign-in](credentials.md#plan-sign-in-openai)):

```json
"phases": { "framing": { "provider": "openai", "auth": "plan", "model": "<slug>" } }
```

`credential` names the vault entry `wirken credentials authorize` wrote,
`openai-plan` when absent. The pin takes no `base_url`. The run asks for no
`openai-api-key`; every walk, replay and fix agent and the probe use the one
sign-in, and a per-walk entry changes the model only. The `llm_request` and
`llm_response` rows carry the step, the model and the token counts as on any
run, with the entry as `credential_id`, null cost fields and, where the model
has a price entry, an estimate.

**A run on a child process.** A pin with `"auth": "plan"` on the `anthropic`
provider is not run by Wirken's own model client. Each turn is run by a child
process: an agent program the operator has installed and signed in to
themselves, on their own plan. The data directory's `lyrik.json` names it by
absolute path:

```json
{ "plan_child_binary": "/usr/local/bin/<agent>" }
```

```json
"phases": { "framing": { "provider": "anthropic", "auth": "plan", "model": "<model id>" } }
```

The pin takes no `base_url` and no `credential`. A target's
`.lyrik/config.json` cannot set the binary. On this route:

- Wirken makes no model call and holds no credential. The child runs the
  model loop with the operator's sign-in.
- The child is served the run's tools and nothing else. Every tool call it
  makes arrives at Wirken and passes the gate, the sandbox envelope and leak
  detection as on any route
  (`a_walk_runs_as_a_child_whose_tool_calls_pass_the_gate`,
  `crates/cli/tests/lyrik_plan_child.rs`). A child that lists a tool that is
  not the run's is refused before anything is asked of the model
  (`a_child_with_a_tool_that_is_not_the_runs_is_refused`).
- The child starts in an empty directory outside the target, from a cleared
  environment: the base set every host-side child gets, the proxy and
  certificate variables an HTTP client reads, and the directories and session
  keyring a program finds its own sign-in through (`HOME`, the `XDG_*`
  directories, `DBUS_SESSION_BUS_ADDRESS`). The vault passphrase, the data
  directory and everything else in the environment `wirken lyrik` was started
  from do not reach it
  (`the_child_gets_a_named_environment_and_nothing_else`,
  `crates/agent/src/runtime/plan_child.rs`).
- Wirken does not see the model call. Each call the child reports is an
  `llm_response` row with `reported` set and no `llm_request`, carrying the
  step, the model and the token counts
  (`each_reported_step_is_a_marked_row_with_step_model_and_tokens`). A step
  whose reported model is not the pinned one fails the walk
  (`a_step_by_another_model_fails_the_walk`).
- The child runs on the host as the operator, not in a container. What holds
  it to Wirken's tools is the tool list it reports at its start.

Plan calls are not billed, so they record no cost. Where the price table has
the model, each `llm_response` row carries `estimated_cost_usd_micros`: what
the call's tokens would have cost at the table's API rates. It is an estimate,
kept apart from the cost fields, which stay null. Where the table does not have
the model there is no estimate.

A plan run does not start unless a ceiling is set that can count its calls:
`run_ceiling_model_seconds`, `run_ceiling_model_calls`, or `run_ceiling_usd`,
which on a plan run is held against the estimated cost and so needs every
model the run is pinned to, a walk's own included, to have a price entry. A
run with none is refused before the sign-off and before the vault is opened.
The banner, the stop and the summary say the figure is an estimate and that
nothing is billed, and the summary lists the estimate by step and model (from
the tests in `crates/cli/src/commands/lyrik_cost.rs`, not a run):

```
  ceiling  the run stops at $20.00 of estimated cost at API rates; nothing is billed (`run_ceiling_usd` in lyrik.json)
  pricing  the run is on the plan sign-in 'openai-plan': nothing is billed, and every cost figure is an estimate at API rates
wirken lyrik: the run reached its cost ceiling of $1.00 ($1.05 estimated at API rates, nothing billed, over 3 model calls); stopping, staged findings are kept
cost: nothing billed, the run was on the plan sign-in 'openai-plan'; an estimated $1.54 at API rates over 3 model call(s), 1 of them with no price entry and not estimated, 75 second(s) of model time
cost ceiling $20.00 on estimated cost: not reached
estimated cost at API rates, by step and model (nothing billed):
  sink-walk on small: $0.0412 over 12 model call(s)
```

For a model with no price entry the banner says so:

```
  ceiling  $20.00 is set but cannot be enforced: openai no-such-model has no price entry
  pricing  the run is on the plan sign-in 'openai-plan': nothing is billed, and openai no-such-model has no price entry, so no cost estimate is recorded
```

**A model with no price entry.** Cost comes from the price table
(`crates/audit/src/pricing.toml`). When the run's model is not in it, no cost
is recorded and a ceiling cannot hold. The banner says so before the run
starts, in these words (from the test
`the_banner_shows_the_ceiling_and_a_missing_price_entry`, not a run):

```
  ceiling  $25.00 is set but cannot be enforced: anthropic no-such-model has no price entry
  pricing  anthropic no-such-model has no price entry: this run's cost is not recorded
```

**A check that the prompt cache is in use.** For a provider that reports cache
tokens (Anthropic), from the third model call on the runner compares what was
sent uncached with what was read from and written to the cache. A cached
conversation sends almost nothing uncached. When more than half of all the
prompt tokens so far were sent uncached, and at least 10,000 prompt tokens
have been sent, the run prints a warning once with the tokens and an estimate
of the extra cost, writes a `lyrik.cost.cache_warning` row, and repeats the
line in the run summary. The estimate is the uncached tokens priced at the
difference between the model's input and cache-read rates.

Every run ends with its cost, and `findings.json` carries it under `cost`:
the recorded spend, the number of calls, how many had no price and the model
time they took, each ceiling and which one stopped the run, the plan sign-in
and the estimated cost by step and model when the run was on one, and the
cache warning if there was one.

## Defender fix step

A fix is recorded as a `candidate fix`. Nothing in a run calls a fix fixed or
verified: the record lists what was checked, how, and what was not.

**Who decides.** Three agents run per finding, each with a fresh context, under
staged skills `fix`, `fix-attack` and `fix-recheck`. Each carries the project
context and the target's threat model the walks were given, when the run has
them. None of them judges
anything. The runner composes each command an arm rests on. The agents run
them through `exec`, and the runner runs some itself, with no model, through
the same `exec` tool, sandbox and approval prompt (it asks as `fix-runner`).
The runner reads the exit status and output of
exactly those commands from the run's session log. What an agent writes about
a run is not read. No model grades a patch, its own or another's. Where a step
does rest on a model's reading it is recorded as `model_judged`. Such a step
cannot pass an arm and cannot fail one: the arm is `inconclusive`, and what
the model reported is kept on the arm under `model_claims` for a maintainer
to read. An arm fails only on an executed run. A model-judged claim never
rejects a fix by itself.

**Any patch.** The arms take a patch and return a verdict. To check a patch
Lyrik did not write (a maintainer's, an upstream fix), put it at
`.lyrik/fix-patches/<slug>.patch` in the target, where `<slug>` is the
finding's `stable_id` with every run of bytes outside `[A-Za-z0-9._]` replaced
by `-`. The run checks that patch in place of writing one, records
`patch_source` `supplied` (`generated` for a patch the fix agent wrote) and
its SHA-256, and runs the same arms. Matching a
known fix earns nothing: in the 1Password study the reference fix itself
carried an off-by-one that a third of the generated patches reproduced and the
grader took as equivalent ([FLAWED] 4.4).

**Run inputs.** The fix step takes three inputs from the target: the `fix`
keys in `.lyrik/config.json` (`test_command`, `coverage_command`,
`explicit_opt_outs`), the patches under `.lyrik/fix-patches/`, and the
reproductions under `.lyrik/fix-reproductions/`. All are read once, at run
start, before any agent runs, and nothing reads them again except to compare.
A patch, a reproduction or a command that appears there during the run is
never used. `write_file` cannot
reach either path: every staged skill's `write_paths` is the run's own
directory. An approved `exec` runs with the target mounted read-write, so
after the fix agents finish the runner hashes both again. A changed
`.lyrik/config.json` makes the functionality arm `inconclusive`; a changed,
added or removed patch for a finding makes every arm of that finding
`inconclusive`, and so does a changed supplied reproduction the arms ran on;
the run records `lyrik.fix.input_changed`. A changed
`.lyrik/config.json` also fails the run, as it always has. Each fix record
carries `inputs` with `config_sha256` and, for a supplied patch,
`supplied_patch_sha256`, and for a supplied reproduction
`supplied_reproduction_sha256`, as read at run start; the `lyrik.fix.started`
and `lyrik.fix.verdict` rows carry the config and patch digests. A link under
`.lyrik/fix-patches/` or `.lyrik/fix-reproductions/` is not read.

**The contract for a command that shows a defect.** It prints the value of the
`LYRIK_REACHED` environment variable on a line of its own on stdout
immediately before its assertion (`echo "$LYRIK_REACHED"`, or
`print(os.environ["LYRIK_REACHED"], flush=True)`), once the
code under test has run and returned what the assertion reads, and exits
non-zero when the defect shows and zero when it does not. Stderr is not read
for the line. One command string runs unchanged
in each copy; a command that names a copy is refused. Every `exec` is given a
fresh value, and its result row records `reached` when stdout carried it on a
line of its own; the line is taken out of the recorded output. The code under
test cannot print a value it was never shown, and no file in the tree can hold
one, so the row, not the output, says the harness reached its assertion. A run
that did not print it never reached its assertion (a failed build, a missing
dependency) and is `inconclusive`, whatever it exited with. Code under test
that reads its own process environment can still see the value. The staged walk
wrapper tells every walk to write reproductions this way.

**Copies and build reuse.** A fix is checked in two copies of the scanned
revision, not three. The `baseline` copy is made once per run, under
`staging/fix/_shared/`, and shared by every finding, so whatever the
project's toolchain builds there is built once. Each finding has its own
`patched` copy. The revert is checked in that same copy, in place: the patch
is taken out with `git apply -R`, `git diff --quiet` against the scanned
revision confirms every tracked file is as it was, the reproduction runs
again, and the patch is applied again. An incremental toolchain rebuilds only
what the patch touched for that step, where a third copy would be built from
nothing. The reproduction's command in the patched copy is one string run
twice; which state it saw is read from its place on the session log between
the apply, the revert and the second apply. If the patch is not applied again
after the revert check, the arms that ran in the patched copy afterwards are
`inconclusive`. The fix step takes one finding at a time, so two findings do
not build in the shared baseline at once. One command string still runs
unchanged in each copy.

**The same harness in the target and in a copy.** A walk's harness lives
under the run's staging directory and names its own files by their path from
the project root. A copy of the scanned revision does not hold the run's
state, so each copy is given the `harness/` directory of every walk the
reproduction command or one of the finding's other confirmed reproductions
names, at the same relative path, and the command runs in the copy exactly as
it ran in the target. The wrapper tells walks to keep
a harness's inputs, markers and scratch output under its own `harness/`
directory or in a temporary directory.

**Arm states.** `pass`, `fail`, `inconclusive`, `not_run`. A refused `exec` is
`not_run`. A failed build, a missing dependency, a timeout, or two runs of one
command that disagree is `inconclusive`. Neither is a reproduction and neither
is a pass.

The arms, in `arms` order:

| Arm | Passes when | Fails when |
|---|---|---|
| `reproduction` | The original reproduction shows the defect in the `baseline` copy of the scanned revision, does not in the `patched` copy, and shows it again in that copy after the patch is taken back out and every tracked file there is as the scanned revision has it | It still shows the defect in the patched copy |
| `variant` | At least two variants (another deployment, another caller, another input shape, a cleanup or error path) each show the defect in the baseline and not in the patched copy | Any variant shows the defect in the patched copy. Shown in the baseline too, the fix is partial and the record names the path |
| `root_cause` | The patch touches the finding's `origin`, the root-cause claim is confirmed by an executed run, and the reproduction reached its assertion in the patched copy | The patch touches the sink at `location` and not the origin, and a variant by another path still shows the defect in the patched copy: `symptom_patch` |
| `relocation` | The re-walk reported no candidate and a bounded fuzz run over the patched functions executed clean | A security candidate's proof of concept shows it in the patched copy and not in the baseline, or the fuzz run shows a defect in the patched copy |
| `functionality` | The test suite passes in both copies, a coverage report shows each patched file exercised, and the benign-input output is identical in both copies when that differential ran | The suite passes in the baseline and fails in the patched copy, benign-input output differs, or a regression the re-walk reported has a proof that shows in the patched copy and not in the baseline |

- **Variant.** A variant is credited from the runs on the session log, never
  from a list an agent wrote. There are two kinds.
  The finding's other confirmed reproductions: every reproduction of the same
  finding the replay agreed with, other than the one the reproduction arm
  uses, is a variant (another deployment, another caller). The list is fixed
  from `findings.json` before any fix agent runs and is on the
  `lyrik.fix.started` row. Once the patch exists the runner makes sure both
  copies are there and the patch is in, then runs each in the baseline and,
  where it shows the defect there, in the patched copy.
  Agent-written variants: the `fix-attack` agent writes one directory per
  variant, `variants/<id>/` with `run.sh` or `run.py` and a one-line
  `path.txt`, and runs it in both copies before starting the next. A variant
  is on record from the moment its run file exists. After the agent stops,
  for whatever reason, the runner runs any registered variant that has a run
  missing, so an agent that ran out of rounds keeps every variant it wrote.
  A script under `variants/` the agent ran under another name is read the
  same way.
  `variants` on the record lists each one with its source (`reproduction` or
  `agent`), its command, what the baseline and the patched run showed, and
  its outcome: `held`, `open` (shown in both: the patch does not cover it),
  `introduced` (shown in the patched copy only), `not_a_variant` (not shown
  in the baseline) or `inconclusive`. A patched run counts only if the patch
  was in the copy when it ran.
  When the reproduction arm passes and a variant is `open`, the record
  carries `partial` with `open_paths`, each path's id, description and
  command, and the first of `reasons` says so. The verdict is `rejected`.
  `attack.json` is optional: the agent's list of paths, read only to fill
  `untested_paths` with the paths nothing was run for. That the held variants
  take different paths is their authors' claim; the runner counts distinct
  commands and does not check it.
- **Root cause.** The comparison is of the patch's hunks against `origin` and
  `location`. With no `origin` on the finding, or a patch that touches
  neither site, the arm is `inconclusive`. It is also `inconclusive` when the
  patched copy did not build or the reproduction never reached its assertion
  there: no arm passes on a copy that did not run. A patch on the sink with
  the origin elsewhere is a symptom patch only by the walks' placement of the
  origin, which is a model's reading: alone it leaves the arm `inconclusive`
  with the claim under `model_claims` and the label `symptom_patch_claimed`.
  It fails, with the label `symptom_patch`, when the variant arm has an
  executed variant that still shows the defect in the patched copy.
- **Root-cause claim.** `root_cause_claim` holds the invariant the fix was
  given, the `origin`, and `evidence_state`: `confirmed_by_executed_poc` when
  the baseline run showed the defect and its output names the origin's file
  or function, `asserted_only` otherwise. A fix built on an asserted claim
  carries the label `asserted_only_root_cause`. A failed variant arm sets
  `suspect` and the label `root_cause_suspect`.
- **Relocation.** The `fix-recheck` agent applies the staged `invariant-walk`
  and `differential-walk` texts to everything reachable from the patched
  functions, not only the patched lines, looking for the violation moved
  rather than removed, for example into a callback. A candidate it reports is
  a claim. The agent is told to write a proof of concept for each under
  `relocation/<id>/` and run it in both copies, and to give each candidate a
  `kind`: `new` or `relocated` for a security defect, `regression` for
  something that worked before the patch and does not after it. This arm
  fails only on a security candidate whose proof shows it in the patched copy
  and not in the baseline. One shown in both copies was there before the
  patch; one with no proof, with no baseline run, or whose proof does not
  show it, is listed under `model_claims`, the arm is `inconclusive`, and the
  fix is not rejected for it. A `regression` candidate is read by the
  functionality arm, never by this one. The kind is the agent's label: it
  decides which arm a confirmed proof fails, not whether the fix is rejected. Without a fuzz harness
  the arm cannot pass: a re-walk that reports nothing is a model's reading,
  and the arm is `inconclusive`, `model_judged`.
- **Functionality.** The suite and coverage commands come from `fix` in
  `.lyrik/config.json` when set; otherwise the `fix-recheck` agent picks the
  project's own. A suite that fails in both copies attributes nothing and is
  `inconclusive`. A patch that edits test files cannot pass on the suite.
  With no coverage report listing each patched file above zero the arm
  records `functionality unverified`, carries the label
  `functionality_unverified`, and does not pass. The benign-input harness
  runs twice in the baseline; output that differs between those two runs is
  `inconclusive`. A difference between baseline and patched output blocks
  the fix even where the change is intended: with no reference build the
  runner cannot tell the two apart, and the differing line is in the arm's
  reasons for a maintainer to decide.
- **Class report.** `class_open_sites` lists other sites with the same
  invariant pattern unguarded: `count`, `locations`, and `unverified` for
  sites whose quoted line is not in the file they name. A fix closes one
  instance. It is never described as closing the class.
- **Locality.** `fix_locality` is computed from the diff: `localized` for one
  hunk, or hunks inside one function of one file; `cross_cutting` otherwise.
  A cross-cutting patch raises `variant_minimum` to four and requires the
  benign-input differential. With fewer variants held the variant arm is
  `inconclusive`, and so is the verdict. `apply.sh` is written either way.

**Verdict.** The rule, in order:

1. `rejected` when any arm is `fail`.
2. Otherwise `inconclusive` when any of these holds: the `reproduction` arm
   is not `pass`; the `variant` arm is not `pass`; `fix.patch` is missing or
   holds no hunk; the patch in the fix directory is not the supplied patch
   read at run start; a run input changed during the run; the target's
   tracked files changed during the run, or whether they did is unknown.
3. Otherwise `candidate_fix`.

So a `candidate_fix` has stopped the original reproduction and the required
number of variants by other paths, in runs the runner observed, on a patch,
inputs and target tree that did not change. A reproduction that passes with
the variant arm `inconclusive` or `not_run` is `inconclusive`: one path
closed says nothing about the others. The other three arms do not decide
the verdict unless they fail: a `candidate_fix` may carry `root_cause`,
`relocation` or `functionality` as `inconclusive` or `not_run`. For that
reason `candidate_fix` is never shown without the arm tally. `label` reads
`candidate fix: 3 of 5 arms passed, 2 inconclusive, 0 not_run` (the label of
`unbounded_length::b.sh:3` in the `toy-slotcopy` run quoted under
[Reading a fix record](#reading-a-fix-record)), and
`arm_tally` holds the counts. A fix whose `functionality` arm is
`inconclusive` or `not_run` carries the label `functionality_unverified`
and is counted as such in the summary.

**Target tree.** `target_tree` on the record is `unchanged`, `changed` or
`unknown` with the reason. It compares a digest of every tracked file as it
is on disk at run start with the same digest after the fix step. Nothing is
compared with HEAD, so it works on a tree that was already modified and on a
repository whose git attributes declare a filter or a line-ending
conversion. `unknown` means the target is not a git work tree or a file
could not be read; the verdict is then `inconclusive` and the record says
the tree state was unknown.

**Tool rounds.** Each of the three agents may make 60 model calls in its
turn. The operator sets another number as `fix_tool_rounds` in the data
directory's `lyrik.json`; a target's `.lyrik/config.json` does not set it.
`agents` on the record lists each agent's `rounds`, `round_limit` and
`incomplete`. An agent stopped at the limit is recorded on its
`lyrik.fix.completed` row with `status` `incomplete` and the counts, and
each arm it feeds carries `incomplete` with the same statement: `fix` feeds
`reproduction`, `fix-attack` feeds `variant`, `fix-recheck` feeds
`relocation` and `functionality`. The arm's state is still what the runs it
did get show. `fix_summary.agents_stopped_at_round_limit` counts them.

**Run summary.** `fix_summary.by_verdict.candidate_fix` is an object, not a
count: `count`, `all_arms_passed`, `functionality_unverified` (candidates
whose functionality arm did not pass) and `arms` with `passed`,
`inconclusive` and `not_run` summed over the candidates. `rejected` and
`inconclusive` are counts, `partial` counts the rejected fixes that are
partial, and `by_arm` counts fixes in each state of each
arm. The terminal line prints the same. From the `toy-slotcopy` run:
`1 candidate (their arms: 3 passed, 2 inconclusive, 0 not_run; 0 with all
arms passed; 0 functionality unverified), 2 rejected, 0 inconclusive (1 of
the rejected partial)`, followed by the per-arm counts.

**Combined record.** When two or more findings of a run share an origin (the
same file and function, or line where the finding names no function) or
state the same invariant, and each one's own fix was rejected as partial, the
runner checks their patches together. It makes one more patched copy under
`staging/fix/_combined-<n>/`, applies each member's `fix.patch` to it in
finding order, and runs, itself, every member's reproduction, every variant
the members have on record and the configured test command, in the baseline
and in that copy. No agent takes part and no patch is written or merged. The
result is a record under `combined_fixes` in `findings.json`: `members`,
`shared`, `patches_apply_together`, the three arms it has (`reproduction`,
`variant`, `functionality`; there is no re-walk of a union, so no
`root_cause` and no `relocation`), `variants`, `partial` and a `verdict`
under the same rule. Member patches that do not apply on top of one another
are recorded as such and the verdict is `inconclusive`. In the
`toy-combined-3` run on the `slotcopy` test target described under
[Reading a fix record](#reading-a-fix-record), two supplied patches
that each guarded one tool were each rejected as partial; together they
stopped both reproductions and eleven of twelve variants, and the combined
record was `rejected` and `partial`, naming the one variant still open, a
direct call to the shared decoder.

**Rejections.** Each failed arm of a rejected fix is appended to
`rejections.jsonl` as `{"kind": "fix", "stable_id", "arm", "basis",
"reason", "patch", "patch_source"}`. A rejected fix is not retried.

**What is left for a maintainer.** Under `staging/fix/<slug>/`: `fix.patch`,
`apply.sh` to run from the project root, `variants/` and `attack.json`,
`benign/` and `recheck.json`, `supplied/` when a reproduction was supplied,
and `observed.json`, every command the arms read
with its exit status and output. `artifacts` on the record has the paths and
the reproduction command. `patch` has the files touched, any test files and
any dependency manifests among them.

**Exec** is gated as everywhere under `wirken lyrik`, with one difference in
how the operator is asked. For each finding the runner shows the commands it
composes for that finding's arms as one numbered plan and asks once:
`approve plan? [y/N]`. A yes covers exactly those command strings, for that
finding, in that run; it is held in memory and nothing is stored. A command
that differs by a byte, and every command an agent originates (reading code,
checking a patch, running a variant script it wrote), is asked on its own,
and so is every command when the plan is refused. A combined record has its
own plan. An approval is a one-shot bypass that stores no grant, and a
refused command is an arm not run. Each command that ran under a plan has
its own `permission_approved` row on the session log, approved by
`lyrik-fix-plan`, and the `lyrik.fix.plan` audit row carries the plan, the
answer and what ran under it. In the `toy-slotcopy` run each of the three
findings had one plan of 14 commands. The step prints the command words it
uses (`mkdir`, `git archive`, `tar`, `cp`, `git apply`, `diff`) before the
first prompt. Nothing is written into the project's tree. With the sandbox off no
replay runs, so no finding is confirmed and the run records
`lyrik.fix.none_confirmed`; `lyrik.fix.skipped` is written per finding when
findings were confirmed and `exec` is unavailable. The audit log carries
`lyrik.fix.started`, `lyrik.fix.plan`, `lyrik.fix.supplied_reproduction`,
`lyrik.fix.completed` per agent with its `step`, `lyrik.fix.input_changed`,
`lyrik.fix.verdict` with the label, the arm tally, the arms, `patch_source`
and the input digests, `lyrik.fix.combined`, and `lyrik.fix.summary`.

**What the arms do not catch.**

- **Fuzzer-scale variant corpora.** Two or four hand-written variants is a
  floor. [PatchBench] derives dozens of inputs per vulnerability by fuzzing
  from the original proof of concept, and still reports patches that pass
  them all and leave the root cause partly open.
- **Sanitizer errors on benign input.** The benign-input differential compares
  output. It does not build with a sanitizer, so a memory error that does not
  change the output is not seen.
- **Reuse of project constructs.** A patch that adds its own check where the
  project has a helper for it passes every arm.
- **Performance regressions.** Nothing measures time or memory; a timeout is
  `inconclusive`, not a finding.
- **A different latent bug in the patched function.** The arms follow the
  finding's invariant. Another defect in the same code is outside them.
- **Defaults that regenerate a class.** `class_open_sites` lists code sites
  with the same pattern. A default or a configuration that keeps producing
  new instances is not a code site.
- **Reproductions written before the marker contract.** A reproduction
  command that does not print the value of `$LYRIK_REACHED` cannot be read, so a finding
  from a run before this contract gets a fix whose `reproduction` arm, and
  with it the verdict, is `inconclusive`.
- **A dependency that is not the package intended.** `patch` lists any
  dependency manifest the patch touches; nothing checks the package.
- **Paths nobody listed.** No runner can show that an omitted path does not
  exist.

**Sources.** The arms follow checks described in:

- OpenSSF, [Finding and Fixing Vulnerabilities Using AI][OpenSSF], sections
  5.4, 5.6 and 5.7: re-run the proof of concept, try variations with a
  separate agent, fix the root cause and not the instance, and keep what was
  learned as a deterministic check.
- Shen et al., [PatchBench]: variants derived from the original proof of
  concept, benign-input output state, unit tests, and the four patterns of
  patches that stop the proof of concept and are still wrong.
- Trail of Bits, [1Password's AI patching benchmark is misleading][ToB] and
  the [post-patch-validation skill][ToB-skill]: the reach marker, checks that
  cannot see which revision they run on, a variant that must fail on the
  base, broken runs as gaps, and provenance as context, not evidence.
- 1Password Off-by-1 Labs, [Frontier Models' Vulnerability Patches are Often
  F.L.A.W.E.D.][FLAWED], sections 2.7, 2.8, 4.4 and 4.9: a reproducer covers
  one path, a model grader agreed with human review on about two grades in
  three, a reference fix carried a bug, and a use-after-free relocated into a
  callback passed both the reproducer and the grader.
- flyingpenguin, [Disinformation Pushed by 1Password][fp-1p] and [OpenClaw is
  Cooked][fp-oc]: grading by the models under test, and a class that
  reappears wherever its generator is still in place.

[OpenSSF]: https://best.openssf.org/Finding-and-Fixing-Vulnerabilities-Using-AI/verify-fixes.html
[PatchBench]: https://arxiv.org/abs/2609.04075
[ToB]: https://blog.trailofbits.com/2026/09/15/1passwords-ai-patching-benchmark-is-misleading/
[ToB-skill]: https://github.com/trailofbits/skills/tree/main/plugins/post-patch-validation
[FLAWED]: https://1password.com/files/resources/frontier-models-vulnerability-patches-flawed.pdf
[fp-1p]: https://www.flyingpenguin.com/disinformation-pushed-by-1password-ai-patching-report-is-false/
[fp-oc]: https://www.flyingpenguin.com/openclaw-is-cooked-433-cves-patched-by-agents-that-cant-fix-whats-broken/

## Reading a fix record

This section is plain-language: what the fix arms are for, and how to read one
record. The mechanics are in [Defender fix step](#defender-fix-step) above.

### What the arms are for

A patch can stop the one input that was reported and leave the hole open. The
arms exist so that "this fix works" is never a model's word for it; each arm is
a question answered by running a command and reading its exit status.

- **reproduction**: does the exact input that was reported still get through?
  The runner runs the walk's own reproduction in a copy with the patch and a
  copy without it. The patch has to stop it in the patched copy and the defect
  has to come back when the patch is taken out.
- **variant**: does any *other* way in still get through? A finding often has
  more than one reproduction (the same hole from another entry point, another
  deployment); each of those is run against the patch. The fix-attack agent may
  add more. A patch that closes the reported input but not a sibling is a
  partial fix.
- **root_cause**: does the patch sit where the violation starts, or at the
  place it happened to surface? A guard bolted on at the crash site, with the
  bad value still produced upstream, is a symptom patch.
- **relocation**: did the patch move the defect somewhere else, or open a new
  one? The fix-recheck agent re-walks the patched code. This arm fails only on
  a *security* defect newly shown or moved; a functional regression (something
  that worked before and does not now) is the functionality arm's.
- **functionality**: does the patched code still do its job? The project's
  own tests run in both copies, and, when they exist, a coverage report and a
  benign-input check. A fix that breaks a legitimate path fails here.

No arm "passes" on a model's reading. Where only a model's judgement is
available (no proof of concept was run), the arm is `inconclusive` and the
claim is kept beside it under `model_claims`; it never rejects a fix on its
own.

### The verdict, and why a candidate fix is not a verified fix

- **rejected**: an arm failed. The patch is wrong or incomplete, and the
  failing arm's reason says how.
- **candidate_fix**: the reproduction and variant arms passed, no arm failed,
  and the patch and the target did not change under the run. It is the
  strongest thing a run says, and it still is not "verified": the other three
  arms may be `inconclusive` (for example no coverage tool exists), which is
  why a candidate fix is always printed with its arm tally and never alone.
- **inconclusive**: nothing failed, but the reproduction or variant arm did
  not pass, or an input changed, or the tree state could not be read.

### A record, field by field

Each entry under `fixes` in `findings.json`:

```json
{
  "stable_id": "unbounded_length::b.sh:3",
  "dir": "staging/fix/unbounded_length-b.sh-3",
  "verdict": "candidate_fix",
  "label": "candidate fix: 3 of 5 arms passed, 2 inconclusive, 0 not_run",
  "patch_source": "generated",
  "arms": [
    { "arm": "reproduction", "state": "pass",         "basis": "executed" },
    { "arm": "variant",      "state": "pass",         "basis": "executed" },
    { "arm": "root_cause",   "state": "inconclusive", "basis": "model_judged" },
    { "arm": "relocation",   "state": "inconclusive", "basis": "model_judged" },
    { "arm": "functionality","state": "pass",         "basis": "executed" }
  ],
  "variants": [
    { "outcome": "held", "source": "agent", "id": "variants/v1_sibling_a/run.sh" },
    { "outcome": "held", "source": "agent", "id": "variants/v4_direct_decode_len/run.sh" }
  ],
  "fix_locality": "cross_cutting",
  "target_tree": { "state": "unchanged" },
  "agents": [
    { "step": "fix",         "rounds": 6,  "round_limit": 60, "incomplete": false },
    { "step": "fix-attack",  "rounds": 16, "round_limit": 60, "incomplete": false },
    { "step": "fix-recheck", "rounds": 12, "round_limit": 60, "incomplete": false }
  ],
  "patch": { "files": ["len.sh", "a.sh", "b.sh"] }
}
```

This record is from the `toy-slotcopy` run on `slotcopy`, a small test target
kept outside this repository: two shell tools, `a.sh` and `b.sh`, that each
copy a header-declared length into an 8-byte slot without a bound check. The reproduction and both executed arms
(reproduction, variant, functionality) passed, so the verdict is a candidate
fix, with the tally `3 of 5`; `root_cause` and `relocation` stayed
`inconclusive` on a model's reading because no executed run settled them. In
the same run the sibling finding `unbounded_length::a.sh:3` was rejected, its
first reason:

```
partial fix: the reproduction no longer shows the defect and 1 other path(s) still do: variants/v3-cwd-source/run.sh
```

Reading it: `verdict` and `label` first (the label carries the tally). `arms`
is the five arms with each one's `state`, its `basis` (`executed` or
`model_judged`), and `reasons`. `variants` lists every variant that ran, where
it came from (`reproduction` or `agent`) and its `outcome` (`held`, `open`,
`open_by_configuration`, `introduced`, `not_a_variant`, `inconclusive`).
`partial`, when present, names the paths a fix closed one reproduction but left
open. `target_tree` is whether the tree changed. `agents` is each fix-step
agent's tool-round use. Everything an arm read is in
`staging/fix/<slug>/observed.json`, each command with its exit status.

When several findings share an origin or an invariant and each one's own patch
was rejected as partial, the run also writes a `combined_fixes` record: the
member patches applied together to one copy, with the arms run on the union.

### How-to: check your own patch, or an upstream fix

The arms take any patch, not only one Lyrik wrote. Put it at
`.lyrik/fix-patches/<slug>.patch` in the target, where `<slug>` is the
finding's `stable_id` with every run of bytes outside `[A-Za-z0-9._]` replaced
by `-` (the run prints each finding's `stable_id`). The run checks that patch
in place of writing one, records `patch_source` `supplied`, and runs the same
arms. Matching a known-good fix earns nothing: the arms still have to pass on
the runs.

### How-to: supply a reproduction

When you already have a script that shows a defect, give it to the run. Put it
at `.lyrik/fix-reproductions/<slug>.sh` (or `<slug>.py`) in the target, with
`<slug>` formed as for a supplied patch. It follows the same contract as any
proof of concept: it prints the value of `$LYRIK_REACHED` on its own line on stdout once the
code under test has run, then exits non-zero when the defect shows and zero
when it does not, and it must run unchanged from the root of any copy of the
source.

The file is read once at run start and its SHA-256 goes on the record; it is a
regular file or it is not read. The runner copies those bytes into the run
directory and runs them itself in the baseline copy, before any fix agent
starts, through the same `exec` prompt as every other command. What it
observes is recorded under `supplied_reproductions` in `findings.json` and on
a `lyrik.fix.supplied_reproduction` audit row:

- `confirmed`: the marker, then a non-zero exit. The finding is treated as
  confirmed, the supplied script is the reproduction the arms run, and any
  reproduction the walks had confirmed for the same finding becomes a variant.
- `not_shown`: the marker, then a zero exit.
- `inconclusive`: it was refused, timed out, was not run, or never printed the
  marker.

A supplied script is never counted as confirmed without that observed run. If
the file changes during the run, every arm that rested on it is withdrawn and
the verdict is `inconclusive`. A supplied reproduction and a supplied patch for
the same finding can be used together.

### How-to: the test and coverage commands

Set them under `fix` in `.lyrik/config.json`:

```json
"fix": {
  "test_command": "sh test.sh",
  "coverage_command": "bash cover.sh"
}
```

`test_command` is run in the baseline and the patched copy; a fix that makes it
fail is rejected by the functionality arm. `coverage_command` is run in the
patched copy and its output has to show each patched file exercised; without it
the functionality arm is `functionality_unverified` even when the tests pass.
A patch that edits a test file makes the suite unusable as a before/after
check, and the arm says so.

If a variant works only because the operator switched the control off on
purpose, list that setting under `fix.explicit_opt_outs` (each as the text a
script would carry); such a variant is recorded `open_by_configuration` and
does not fail the variant arm.

### How-to: sandbox limits for the arms

The arms build and run the target, which can need more than the exec sandbox's
defaults (512 MB of memory, 256 processes, 300 s a command). Raise them in the
data directory's `sandbox.json` (operator-only; a target cannot set them):

```json
{ "mode": "exec-only", "memory_mb": 2048, "pids_limit": 1024, "timeout_secs": 300 }
```

Non-default limits appear in the sign-off banner and on the audit rows. See
[sandbox properties](sandbox-properties.md).

### How-to: fix-step round limits

Each fix-step agent may make 60 model calls by default. A large codebase can
need more; set `fix_tool_rounds` in the data directory's `lyrik.json`
(operator-only):

```json
{ "fix_tool_rounds": 90 }
```

An agent stopped at its limit is recorded `incomplete` with the count, and each
arm it feeds carries that note; the arm's state is still what the commands that
did run show.


## Agent configuration in the scanned repository

Some tracked files make an agent or editor session that is opened in a
checkout run a program before the person has asked for anything: a hook, a
status-line or key-helper command, a tool server started with the session. A
repository that tracks one hands that program to everyone who opens it.

Every run reads the scanned revision's tracked files for these and reports
each declared program as a finding of class `agent_config`, tier `MEDIUM`,
with the file, the line, the kind of declaration and the command, bounded to
400 characters. The files read are the project-level settings, hook and
tool-server files of the coding agents and editors in common use, at the top
level or under any directory; the exact paths are `CONFIG_PATHS` in
`crates/cli/src/commands/lyrik_agent_config.rs`. A tracked symlink is reported too when it makes such a
file appear at one of those paths, whether the link is the file or a directory
that holds it, and when a link at one of those paths points out of the
repository. The finding's `agent_config` object carries `kind`, `command`,
`via_symlink` and `executed: false`.

Nothing is executed. The tracked paths come from HEAD's tree, a file is read
as bytes and parsed as JSON, and a symlink is read with `readlink` and followed
by path arithmetic, never opened through the link. Each declaration is also a
`lyrik.agent_config.declared` audit row. The findings are staged beside the
walks' and pass the same gates; they carry `detection_source`
`static_prescreen` and are counted in the funnel under `agent-config`.

The scan reads configuration that is tracked. A file that is present and
untracked, a command reached through a script the declared command runs, and
agent configuration in a format other than those listed are not reported.

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

## Findings schema (1.2)

`findings.json` is the contract external consumers (SIEM ingestors, ticketing
systems, CI gates, diff tools) pin against. Candidates declined under a brocard
rule are recorded alongside the findings; see [lyrik-brocards.md](lyrik-brocards.md).

`$id` is
`https://raw.githubusercontent.com/gebruder/wirken/schema-v1.2/docs/lyrik-json-schema.json`.
The schema is tag-pinned, not release-pinned: wirken releases that do not
change it do not move the tag, and schema changes cut a new tag and a new
spec. The 1.1 schema stays at its own tag, `schema-v1.1`, unchanged.

**1.2 adds one thing to 1.1: a finding of any class is kept.** In 1.1
`framing[*]` was `"auth"` or `"injection"` and the `stable_id` framing segment
was one of those two. In 1.2 both are any class name, `[a-z][a-z0-9_]*`.
Nothing else changed, so every 1.1 document is a valid 1.2 document. The
runner writes `schema_version` as the lowest version the document fits:
`"1.1"` when every finding's framings are `auth` or `injection`, `"1.2"` when
any finding has another class. A consumer pinned to 1.1 therefore reads every
1.1 document exactly as before; a run that kept a finding of another class is
labelled 1.2, where 1.1 would have dropped that finding without saying so.

`wirken lyrik validate --path <path>` checks the rules of the version the
document names in code
(`crates/cli/src/commands/lyrik_validate.rs`; the schema file is read only by
its tests) and never fetches `$id`; the URL is for external JSON Schema
validators.

Pin the schema, not the CLI. `wirken lyrik` is outside Wirken's stability
surface: its subcommands, flags, run output, and the fields `findings.json`
carries outside the schema can change in any minor release. A schema
contract changes only with a new schema tag.

Lyrik has its own version, 1.0.1; it was 1.0.0 in Wirken 3.4.0. It is the
first line of
the sign-off summary (`Lyrik 1.0.1 run <id> on <target>`), the
`lyrik_version` field at the top of `findings.json`, and the
`lyrik_version` field of the `lyrik.run.started` row, where
`driver_version` is the Wirken version. What it covers: the tag-pinned
findings schema is stable and versioned by its tags; subcommands, flags,
run output and fields outside the pinned schema may change in any Wirken
minor, and the Lyrik version changes with them. `lyrik_version` is itself
a field outside the pinned schema.

```json
{
  "schema_version": "1.1 or 1.2",
  "run_id": "<non-empty string>",
  "produced_at": "<RFC 3339 timestamp>",
  "findings": [ /* zero or more */ ]
}
```

Required per finding: `id`, `stable_id`, `framing` (array of one or more
class names), `location.file` (workspace-relative), `location.line_start`
(1-based), `title`, `summary`, `tier`. `framing[*]` is a class name,
`[a-z][a-z0-9_]*`; under `schema_version` `"1.1"` it is `"auth"` or
`"injection"`. Closed enums: `tier` is `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`;
`detection_source`, optional but enforced when present, is `static_prescreen`,
`model_reasoning` or `both`.

`detection_source` records the origin of the candidate: `static_prescreen`
when the scanner raised the location and the model ruled it a real bug,
`model_reasoning` when the model raised it without a matching scanner
candidate, and `both` when the two converged on the same file and line across
walks. **The runner sets `both` only in per-walk dedup**; a value the model
staged is kept as written (`annotate_detection_source` inserts only when the
field is absent), so single-call mode never produces it on its own.

Extra fields at both levels are allowed and ignored, so producers can carry
`grade`, `stream`, `scoring_passes`, `dedup_sources`, `rubric_silent`,
`location.line_end` and similar through without the validator enforcing their
shape. The runner adds run-level extras of its own, outside the schema contract:
`target_sha`, `target_dirty`, `audit_log_ref`, `rubric`, `context`,
`target_threat_model`, `funnel` and `citation_check`.

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
`auth::a:b:c.rs:7`, and under 1.2 `unbounded_alloc::a.sh:4`. Not conforming:
an absolute path, an empty framing or one that is not a class name, a missing
or non-integer line.

`line` is the brittle component: a finding shifts line numbers when unrelated
edits land above it, so consumer-side fuzzy matchers should fall back to
file-proximity matching on an exact-ID miss.

`findings[]` is not sorted: single-call mode keeps staged file-name order, and
walk mode keeps first-seen group order across walks in config order, with
findings that have no location at the end. The validator does not check
order.

**Not in the schema surface**, and consumers must not pin against them: a
top-level `target`, `funnel`, `concentration` or `observations` block (the
runner's `funnel` is one of the extras above);
per-finding `gate_routed`, `dedup_match` or `stream` as closed enums; a
`triage_status` field. The schema does not require producers to emit `$schema`, and
if a report carries one the validator asserts it string-equals `$id`.

A run that finds nothing still writes `findings.json`, with an empty `findings`
array, but only when the agent also wrote a no-findings marker at
`staging/no-findings.json`. The marker names the framings checked and the files
read, both as non-empty lists of strings. The runner copies those two lists into
a top-level `no_findings` key. In single-call mode a run with no findings and
no marker fails, and a marker beside a finding fails the run. In walk mode the
per-walk staging directories always count as consumed, so `findings.json` is
written even with no findings and no marker, with no `no_findings` key, and a
marker with zero findings fails the run. A single-call run that ends in
rate-limit exhaustion or context overflow writes an empty `findings.json`
without a marker and exits zero.

### Carried outside the schema

Thirteen additions sit outside the schema contract. The validator tolerates unknown
keys, so they do not change `schema_version`, and a later minor release may
change them:

- `walk_summary`, a top-level array with one entry per walk: `walk`,
  `findings_staged`, `truncations`, `kept_at_truncation`, `continuations`,
  `claims_registered`, `registered_as_distinct`, `refused_at_registration`,
  `refused_at_aggregation`, `completed`, `incomplete_at_tool_rounds` for a
  walk stopped at the tool round limit, and `stopped_at_cost_ceiling` with
  `ceiling_reached` for a walk stopped at any of the run's ceilings.
- `carried` on a finding the run carried from the ledger (`from_run`, `record`,
  `evidence`, `commit`), and a top-level `carried` with the `count` and the
  keys; the funnel's `merged.carried` is the same count. See
  [The ledger](#settled-findings-are-carried-into-a-runs-output).
- `cost`, a top-level object: `spend` (`usd_micros`, `calls`,
  `unpriced_calls`, `model_millis`, `estimated_usd_micros`), `ceiling_usd`,
  `ceiling_model_seconds`, `ceiling_model_calls`, `stopped_at_ceiling`,
  `ceiling_reached` (`usd`, `model_seconds`, `model_calls` or null), `priced`,
  `plan_sign_in`, `cache_warning` and, on a plan run, `estimate`: `billed`
  (false), `total_usd_micros`, `unestimated_calls` and `by_step_and_model`
  (`step`, `model`, `calls`, `estimated_usd_micros`, `unpriced_calls`). See
  [Cost guard](#cost-guard).
- `claims_refused`, a top-level array present when a claim was refused at
  registration: `walk`, `file`, `key`, `decision`, `record` and
  `established_by_run`.
- `ledger_refused`, a top-level array present when a staged finding was refused
  at aggregation: `walk`, `file`, `key`, `record` and `established_by_run`. See
  [The ledger](#the-ledger).
- `rejected_candidates`, a top-level array. Each entry carries `rule` (1 to 8),
  `walk` (absent in single-call mode), `stable_id`, `title`, `location`,
  `reason`, and `applied_by`. In SARIF each entry is a result under rule
  `lyrik.brocard.<rule>`, with a `suppressions` entry of kind `external` whose
  justification is the reason.
- `threat_model` on a finding, an object with the strings
  `attacker_capability` and `harm_path`. Walk runs and the bundled `lyrik`
  skill are told to emit it. A finding without both is a rule 1 rejection.
- `step_records`, a top-level array, one entry per accepted step record a
  walk wrote (see "Step records" under `walks` above). Each entry carries
  `walk`, `file`, `step`, `claim`, `code_revision`, `check`, `evidence`,
  `open_questions` and, from the second record of a walk on, `prior`; a
  record whose `check` names a command also carries `check_status`.
- `reproductions`, a top-level array, one entry per reproduction record a
  walk wrote, with the fresh-context replay beside it when one ran: `walk`,
  `file`, the record's `stable_id`, `command`, `harness`, `expected` and
  `code_revision`, `outcome` and `observed` as the run's chain recorded them,
  what the walk wrote for those under `claimed`, `replay`, `agreement`, and for a reproduction
  that was agreed or disagreed `evidence` (`observed` or `static_confirmed`)
  with the runner's traced run as `execution`. Each finding carries `evidence`
  too: `observed`, `static_confirmed` or `reasoned`. See
  [lyrik-brocards.md](lyrik-brocards.md#reproductions-and-replay).
- `fixes`, a top-level array present after a defender-mode run with at least
  one confirmed finding, one record per finding: `stable_id`, `dir`,
  `verdict` (`candidate_fix`, `rejected` or `inconclusive`), `label` (on a
  `candidate_fix` only, always with the arm tally), `arm_tally`,
  `patch_source` (`supplied` or `generated`), `inputs`, `reasons`, `labels`,
  `arms`, `fix_locality`, `variant_minimum`, `root_cause_claim`, `variants`,
  `partial` (when the fix is partial), `untested_paths`, `class_open_sites`,
  `patch`, `fix_model`, `target_tree`, `agents` and `artifacts`.
  A `verdict` of `fix` in a `findings.json` from 3.3.1 or earlier was read
  from the fix agent's own report and is unverified. See
  [Defender fix step](#defender-fix-step).
- `fix_summary`, beside `fixes`: `fixes`, `by_verdict` (where
  `candidate_fix` is an object carrying the arm tally and
  `functionality_unverified`), and `by_arm` with the count of fixes in each
  state of each arm.
- `origin` on a finding, when the walk traced it: `file`, `line_start` and
  `function`, the code where the invariant violation starts, as distinct from
  `location`, where it surfaces.

## Reports and audit

```bash
wirken lyrik report --format sarif --run <run-id> --output findings.sarif
wirken lyrik validate --path findings.json
```

Rejected candidates appear in SARIF as suppressed results. See
[lyrik-brocards.md](lyrik-brocards.md#sarif).

Every run writes the per-run `audit.log` with no opt-out, each row carrying
the run ID. The SARIF report carries the same ID as `automationDetails.id`
(`lyrik/run/<run-id>`) and on every finding result (a rejection result carries
`rule`, `walk`, `stable_id` and `applied_by` only), so a reader can pull the rows for
a finding. Each finding carries `citation_check` with a `status`. `resolved`
means the cited line holds the text the finding quotes in `location.quote`,
compared with whitespace folded, and the sub-gate that ran on the line passed.
A quote found on exactly one other line of the file moves `line_start` there,
and `corrected_from` records the line the finding gave. A quote found nowhere
or on several lines leaves the lines as cited with status `mismatch`, and a
finding with no quote of three characters or more is `unquoted`. `unresolved`
is a missing file or line, or a sub-gate that did not pass. An `origin` whose
`function` is one identifier is held the same way to the line that defines it
(`origin_corrected_from`). The bundled single-call skill does not ask for a
quote, so its findings are `unquoted`. `findings.json` carries a
`citation_check` block with resolved and unresolved counts per citation
sub-gate, and `corrected`, `mismatch` and `unquoted` across them; what the run
set aside is in
`audit.log`, one row each: `lyrik.candidate.declined`,
`lyrik.candidate.unaddressed`, `lyrik.finding.refused`,
`lyrik.finding.framing_stripped` and `lyrik.finding.grade_corrected`.

**Funnel.** `findings.json` carries `funnel`, the run prints it at the end,
and the SARIF report carries it under the run's `properties.lyrik.funnel`:

- `walks`, one entry per walk (`lyrik` for single-call mode): `emitted`,
  `refused`, `framing_stripped`, `grade_corrected`, `brocard_removed`
  (candidates a defender-mode rejection removed), `checks_not_executed` (step
  records naming a command the run has no `exec` row for), and the `skipped`
  steps from its `lyrik.walk.completed` row.
- `merged`: `emitted`, `refused`, `brocard_removed`, `collapsed` (findings
  folded into another at the same location by dedup) and `kept` (this run's
  own findings in `findings.json`). When the run carried findings from the
  ledger, `carried` is their count, and `kept` plus `carried` is the length
  of the findings list.
- `scanner`, when Semgrep ran: `candidates`, each counted once as `accepted`
  (a kept finding sits at its location), `brocard_rejected` (otherwise, when
  a candidate there was removed in defender mode), `declined` (otherwise, when
  any walk declined it) or `unaddressed`.

Before writing, the runner checks emitted - refused - brocard_removed - collapsed = kept, with
`kept` taken from the written findings list and `collapsed` from dedup's group
sizes, and that the scanner's four counts (accepted, brocard_rejected,
declined, unaddressed) sum to its candidates. If either check fails,
`findings.json` is written without `funnel`, the per-run log records
`lyrik.funnel.mismatch` with every number, the staging directory is kept (its
`declines/` directories have already been removed by then), and the run exits
non-zero.

Scanner rows (`lyrik.scanner.dispatched`, `lyrik.scanner.unavailable`,
`lyrik.candidate.declined`, `lyrik.candidate.unaddressed`) live in the per-run
NDJSON only and are not signed.

**Provenance.** At run start, before dispatch, the runner records on
`findings.json`:

- `target_sha`: HEAD of the repository the target sits in.
- `target_dirty`: whether any tracked file differs from HEAD in content,
  executable bit or kind, or a checked-out submodule sits at a different
  commit. Untracked files do not count. Files are compared byte for byte, and
  a file whose bytes are the committed ones is unchanged whatever its git
  attributes declare. A file that differs under line-ending conversion alone
  (`text`, `eol`, `crlf`, `core.autocrlf`) is compared again with CRLF read
  as LF. A file that differs under a clean filter, LFS, `ident` or an
  encoding conversion cannot be compared without running the conversion,
  which the runner does not do: when such files are the only differences,
  `target_dirty` is null and a `lyrik.provenance.unavailable` row gives the
  reason.
- `audit_log_ref`: the run's `audit.log`, relative to the target.

The SARIF report carries all three in its invocation properties. A target
that is not in a git work tree, or whose HEAD has no commit, gets null git
fields and a `lyrik.provenance.unavailable` row with the reason. No remote URL
is recorded.

No program the target repository configures runs on the host. The runner asks
git only `rev-parse` and `ls-tree`, which read refs, config and objects and
neither refresh the index nor convert content, and `config --get` and
`check-attr`, which read config and attribute files, each with
`core.fsmonitor=false`, `protocol.allow=never`, no pager and a child
environment that starts from the minimal host-child set and carries only the
three `GIT_*` settings the operation needs (`git_env`,
`crates/cli/src/commands/lyrik_git.rs`), so no `GIT_*` the operator exported
and no vault passphrase reaches it, and compares the work tree against HEAD
in-process. It does
not use `git status` or `git diff`, which can run a repository's clean
filters.

**Inference.** `findings.json` carries `inference`, and the run prints it at
the end: `provider`, `model`, `calls` and `request_bytes`, read back from the
run's own rows on the signed chain, the tool-call probe and any compaction
summaries included. Each model call is an `llm_request` row naming the
provider, the model and the size of the messages and tool definitions it sent
(see [audit-cli.md](audit-cli.md)). `calls` counts distinct requests on the
chain; a rate-limit retry resends the same request to the same provider and
is not another call. It appears in the per-run log as
`lyrik.dispatch.rate_limited` for the single-call agent, the only one with a
recovery observer attached; walk, replay and fix agents retry without that row.

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
  check off, in a child environment that starts from the minimal host-child
  set and carries only those two settings (`semgrep_env`,
  `crates/cli/src/commands/lyrik_semgrep.rs`). `lyrik_run_reaches_no_network.rs`.
- **No program the repository configures runs.** Provenance and the team-file
  check use only the git commands above; an fsmonitor hook and a clean filter
  set in the target's `.git/config` stay unrun.
  `lyrik_provenance_runs_nothing_the_repo_configures.rs`.
- **`exec` only in the sandbox.** With sandbox `mode: off` a run's agents get
  no `exec`. With the sandbox on, each command goes to the operator first.
  `lyrik_exec_sandbox_only.rs`.
- **Operator sign-off on the chain.** Without `--bench` nothing reaches the
  model until the operator signs off at a terminal; the answer is on the
  signed chain, bound to the summary shown. A `bench_mode` key in the assessed
  repository's config does not skip it. `lyrik_signoff.rs`.
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
