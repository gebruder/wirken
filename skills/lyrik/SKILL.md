---
name: lyrik
description: Security assessment of a codebase — minimal mode for runner validation
disable-model-invocation: true
permissions:
  tools:
    allow: [exec, read_file, write_file, list_files]
  egress:
    mode: deny
  filesystem:
    read_paths: ["<workspace>"]
    write_paths: ["<workspace>/.lyrik"]
  inference:
    allow: ["*"]
---

# Lyrik (recon + multi-framing + scoring)

Run a security assessment of the codebase under `<workspace>` across two framings — `auth` and `injection` — and emit one finding per identified vulnerability per applicable framing. Each finding is scored across four axes by two independent passes. The runner aggregates the staging directory into the canonical `findings.json`.

Out of scope in this mode: Phase 0 (context document, separate rubric file), framings beyond `auth` and `injection`, two-pass framing union (the two passes here are *scoring*, not framing), three-pass scoring-disagreement gate and resolution, dedup, concentration index, gate-routed disclosed, exploit adapter. They return as separate slices.

## Recon (mandatory, before any finding)

**Before emitting any finding, you must read at least one source file in scope, and every path you cite in `location.file` must be a file you have actually opened in this turn.** Inventing paths is the failure mode this section exists to prevent.

Recon steps:

1. **Read scope.** Open `.lyrik/config.json` if present; honor `scope.include` and `scope.exclude` glob lists. Otherwise treat the whole workspace as in-scope. Skip `.git/` and `.lyrik/` regardless.

2. **List files in scope.** Use `list_files(<dir>)` starting at the workspace root. For tiny workspaces (a handful of files), one `list_files(".")` suffices. For larger ones, descend into subdirectories whose names suggest content under either framing — auth-relevant (`auth/`, `session/`, `acl/`, `permission/`, `admin/`, `user/`, `login/`, `token/`, `crypto/`) or injection-relevant (`api/`, `handler/`, `parser/`, `eval`, `exec`, `shell`, `query`, files exposing string-interpolated commands or SQL).

3. **Read the candidate files** via `read_file(<path>)`. For tiny workspaces, read every source file. For larger ones, read at least one file matching each framing's heuristics. If `read_file` returns an error, pick a different file. Do not synthesize content; do not cite a path you couldn't read.

4. **Select which framings apply.** From what you read, decide which framings have signal in the codebase:
   - **`auth`** activates if the code contains anything that affects who can do what, or how privileges propagate (callable surfaces with no per-caller authorization, hardcoded credentials, weak comparison of secrets, untrusted input folded into elevated-authority scope such as a system prompt, broken-by-default access posture).
   - **`injection`** activates if the code contains an interpreter-shaped sink that can take attacker-influenced data (`eval`, `exec`, `shell=True` subprocess, dynamic SQL string concatenation, format-string-on-user-input, deserialization of untrusted data, command construction via string concatenation).
   - Both can apply to the same file. Both can apply to the same line in different framings (e.g., `eval(user_input)` is an `injection` concern and is also an `auth` concern under "untrusted input inheriting elevated authority"). When the same line carries weight under both framings, emit one finding under each framing rather than picking one — the runner will see two findings sharing a `location` and that is the correct shape.
   - If recon shows neither framing applies, emit one `tier: INFO` finding under whichever framing fits least badly, with a `summary` that names the absence — exercise the pipeline truthfully rather than invent vulnerabilities.

5. **Route each observed vulnerability to a `write_file` call, immediately.** When you observe a vulnerability matching an active framing, your next action is `write_file(path=".lyrik/state/runs/<run-id>/staging/findings/finding-NNN.json", content=<finding object>)`. Then continue to the next vulnerability or the next file. Do not list, summarize, describe, or annotate vulnerabilities in your assistant message — every vulnerability is a `write_file` call, no exceptions.

Recon's only artifacts are the file paths, line ranges, and framing assignments cited inside the staged finding objects. No separate context document, no per-component history. Those return in later slices.

## Override feedback (fire-once)

If your invocation prompt carries feedback from a prior run or an external reviewer (for example, "the prior recon missed X, focus on Y this round"), treat it as authoritative scoping for THIS run only:

1. Read the feedback before recon.
2. Let it override recon defaults. If the feedback names a file or framing to focus on, prioritize that over the heuristics in Recon step 2.
3. Do not re-inject the feedback into your reasoning across multiple turns within the run. The feedback applies once, at the top of the working set.
4. The feedback is not carried into future runs. Each invocation starts fresh; the runner does not persist override feedback between runs.

Absent such feedback in the invocation prompt, proceed directly to recon.

## Framings

### `auth`

Anything that affects who can do what, or what privileges propagate without verification. Worked classes: missing access check before a privileged operation; hardcoded credentials; weak comparison (`==` of secrets); broken-by-default permission posture; untrusted input inheriting elevated authority (e.g., user-controlled string folded into a system prompt scope); tool surfaces invoked without per-caller authorization.

The framing is *who can do this*, not *what bytes go where*.

### `injection`

Untrusted data reaching an interpreter without separation. Worked classes: `eval` of caller-controlled string; `exec` of caller-controlled string; `subprocess(..., shell=True)` with caller-controlled command; SQL built via string concatenation rather than parameter binding; format-string applied to caller-controlled template; deserialization of attacker-influenced bytes (pickle, YAML with unsafe loaders, custom binary formats with executable callbacks); template engines with autoescape disabled receiving caller-controlled markup.

The framing is *attacker-controlled bytes flow into an interpreter that grants them effect*. The classical sanitization defenses (escape, parameter-bind, type-check) apply.

Note: `prompt_injection` is a distinct framing (untrusted text reaching model context inheriting the surrounding prompt's authority); it is **not in scope for this mode** — it returns when the framings list re-expands.

## Inline rubric

Phase 0 will eventually produce a project-specific rubric file. Until that slice ships, scoring uses this inline rubric:

- **CRITICAL** — exploit confirmed in this codebase or trivially reachable from an untrusted boundary, with effects that compromise confidentiality, integrity, or availability of the entire system (host RCE, full data exfiltration, total auth bypass).
- **HIGH** — real bug, reachable from an untrusted boundary, with effects scoped to a major component or class of users (privilege escalation within the application, sensitive-data leak).
- **MEDIUM** — real bug, reachability requires assumptions that are usually-but-not-always true (an authenticated user, a specific configuration), or effects are bounded to one user's data or one feature.
- **LOW** — real bug but reachability requires unusual conditions, or effects are minor (information disclosure of non-sensitive metadata, denial of one feature for one user).
- **INFO** — no defensible bug under the current threat model; recorded for posture-of-codebase context only.

Tier is derived from the four scoring axes (see Scoring), not asserted directly.

## Scoring (two-pass)

Each finding is scored by two independent passes. Each pass evaluates four axes and writes one rationale paragraph that names how each axis was assessed. The passes are stored in `scoring_passes` (an array of two objects); the final `tier` and `grade` are derived from agreement across the two passes.

The four axes:

- **`real_bug`** — `"yes"` / `"no"` / `"unclear"`. Is this a defect under any reasonable reading of the code, or is it intended behavior misread as a bug?
- **`reachable`** — `"yes"` / `"no"` / `"unclear"`. Is the buggy code path executed under realistic operation, or is it dead/test-only code?
- **`attacker_reach`** — `"low"` / `"medium"` / `"high"`. How many capabilities does an attacker need to invoke the buggy path? `low` = unauthenticated network reach; `medium` = authenticated user; `high` = local admin or insider.
- **`blast_radius`** — `"contained"` / `"scoped"` / `"system"`. What does success buy the attacker? `contained` = one user's session; `scoped` = a feature or major component; `system` = host RCE, full data exfiltration, full auth bypass.

Each pass records its axis verdicts plus a `rationale` paragraph (two to four sentences) explaining the four-axis assessment.

**Deriving the final `tier`:** if both passes agree on the axes, use the rubric tier the agreement implies. If passes disagree by **one step on any axis** (e.g. pass A says `attacker_reach: low`, pass B says `medium`), pick the lower-implied tier (conservative). If passes disagree by **more than one step on any axis** (`low` vs `high`, `contained` vs `system`, `yes` vs `no`), set `scoring_disagreement: true` on the finding and pick the lower-implied tier; the runner flags the disagreement without resolving it. The three-pass disagreement gate and the `framing_split` resolution shape return in a later slice.

**Deriving `grade`:** core Lyrik runs cap at `0.5` because no exploit adapter has been invoked. The current slice keeps `grade: 0.5` for any finding where both passes mark `real_bug: yes` and `reachable: yes`. Anything else gets `grade: 0`.

## Emission discipline (the only output channel for findings)

**Findings are emitted exclusively as `write_file` tool calls.** The runner reads only the staged files; any finding content placed in your assistant message is lost and irrecoverable. Prose-shaped output is not a finding.

Concretely:

- Each vulnerability you observe becomes one `write_file(path=".lyrik/state/runs/<run-id>/staging/findings/finding-NNN.json", content=<finding object>)` call. Make the call as soon as you observe the vulnerability.
- The calls are **sequential and discrete**. The first vulnerability writes to `finding-001.json`. The next writes to `finding-002.json`. The third writes to `finding-003.json`. And so on. Each is one call. They are not batched, summarized, or planned-out-loud first.
- Your assistant message for this turn contains a single terminal sentence — for example, `Findings emitted to staging.` That is the entire message. No headings, no bullets, no per-finding summaries, no framing-by-framing lists.
- If you find yourself starting to write `### Auth Framing` or `**Vulnerability:**` or any markdown heading or list in your assistant message, stop. The next action is `write_file`, not prose.

This is a hard constraint. The runner is incapable of reading your assistant message; the file aggregator is what produces `findings.json`. The terminal sentence exists only to acknowledge the turn is complete.

## Finding shape

The staged file holds one finding object — same shape as one element of the canonical `findings` array. Required fields:

```json
{
  "id": "F001",
  "stable_id": "<framing>::<relative-file>:<line>",
  "stream": "novel",
  "framing": ["<one of: auth, injection>"],
  "location": {
    "file": "<relative path under workspace>",
    "line_start": <integer, 1-based>
  },
  "title": "<one short sentence>",
  "summary": "<one sentence — what is the concern and why>",
  "tier": "<derived from scoring_passes per the inline rubric>",
  "grade": 0.5,
  "rung": "static_corroboration",
  "deferral": null,
  "scoring_passes": [
    {
      "real_bug": "yes",
      "reachable": "yes",
      "attacker_reach": "medium",
      "blast_radius": "scoped",
      "rationale": "<two to four sentences explaining the four-axis assessment>"
    },
    {
      "real_bug": "yes",
      "reachable": "yes",
      "attacker_reach": "medium",
      "blast_radius": "scoped",
      "rationale": "<an independent two-to-four-sentence assessment; do not copy pass 1 verbatim>"
    }
  ],
  "scoring_disagreement": false
}
```

Field rules:
- `tier` is uppercase, one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Derived from `scoring_passes` per the inline rubric — do not assert directly.
- `grade` is one of `0`, `0.5`, `1`. Cap at `0.5` in this slice (no exploit adapter); use `0` if either pass marks `real_bug: no` or `reachable: no`.
- `rung` is one of `suspicion`, `static_corroboration`, `property_violated`, `root_cause_explained`, `variant_observed`, `patch_localized`. With one file read and no exploit attempt, `static_corroboration` is the realistic ceiling.
- `deferral` is `null` in this minimal-plus-recon-plus-scoring mode.
- `scoring_passes` is a two-element array. Each element carries `real_bug`, `reachable`, `attacker_reach`, `blast_radius`, and a `rationale` paragraph.
- `scoring_disagreement` is `true` only when the two passes disagree by more than one step on any axis. False otherwise.
- `framing` is a one-element array containing exactly one of `"auth"` or `"injection"` in this mode (additional framings re-enable in later slices). The same vulnerability under two framings emits as two separate findings, each with a single-element `framing` array.
- `id` increments per finding (`F001`, `F002`, …), matching the staging filename ordinal. `stable_id` follows `<framing>::<relative-file>:<line>`.

## Path format

`<run-id>` substitutes whatever the runner passes as the run-id parameter. The skill receives it via the runner's prompt; do not invent it.

Final write paths, in the order they are produced:

- First vulnerability observed: `.lyrik/state/runs/<run-id>/staging/findings/finding-001.json`
- Second: `.lyrik/state/runs/<run-id>/staging/findings/finding-002.json`
- Third: `.lyrik/state/runs/<run-id>/staging/findings/finding-003.json`
- And so on, zero-padded three digits.

The directory is created on first write — `write_file` will create parents as needed.

## Run journal

After all findings are staged and recon is complete, write one summary file to `.lyrik/state/runs/<run-id>/journal.md`. The journal is metadata for human reviewers and audit; the runner does not aggregate it.

This is a `write_file` call, not assistant-message prose. The "no prose in your assistant message" rule from the emission discipline section still holds: `journal.md` is a markdown *file* you write, not a heading inside the chat reply.

Contents, in this order:

1. **Status header**: phase reached, framings activated, finding count by tier (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`), count of files surveyed.
2. **Per-finding line**: one line per emitted finding, form `F001 <framing> <attacker_reach> <blast_radius> <file>:<line>: <title>`.
3. **Notes**: free-text observations not captured in findings. Example: "framing `injection` had no candidate sites; only `auth` findings emitted."

The journal is one `write_file` call. Path: `.lyrik/state/runs/<run-id>/journal.md`. It is the only write this skill produces outside `staging/`.
