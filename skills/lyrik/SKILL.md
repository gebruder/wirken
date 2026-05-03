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

# Lyrik (minimal + recon + scoring)

Find one auth-related finding in the codebase under `<workspace>`, score it across four axes via two independent passes, and write the result to a single staging file. The runner aggregates that file into the canonical `findings.json`. This adds two-pass scoring on top of the minimal-plus-recon shape — the model produces real judgment about severity and reachability, not just a label.

Out of scope in this mode: Phase 0 (context document, separate rubric file), multi-framing, two-pass framing union (the two passes here are *scoring*, not framing), three-pass disagreement gate and resolution, dedup, concentration index, gate-routed disclosed, exploit adapter. They return as separate slices.

## Recon (mandatory, before any finding)

The minimal-skill mode without recon produced fabricated paths — the model emitted findings against files that don't exist in the workspace. This section closes that hole. **Before emitting any finding, you must read at least one source file in scope, and the file you cite in `location.file` must be a file you have actually opened in this turn.** Inventing paths is the failure mode this section exists to prevent.

Recon steps:

1. **Read scope.** Open `.lyrik/config.json` if present; honor `scope.include` and `scope.exclude` glob lists. Otherwise treat the whole workspace as in-scope. Skip `.git/` and `.lyrik/` regardless.

2. **List files in scope.** Use `list_files(<dir>)` starting at the workspace root. For tiny workspaces (a handful of files), one `list_files(".")` suffices. For larger ones, descend into subdirectories whose names suggest auth-relevant content (`auth/`, `session/`, `acl/`, `permission/`, `admin/`, `user/`, `login/`, `token/`, `crypto/`).

3. **Pick a candidate file.** Prefer source files (`.py`, `.js`, `.ts`, `.go`, `.rs`, `.c`, `.h`, `.java`, `.rb`) whose name or directory matches the heuristics above. With nothing matching, pick the largest source file in scope. With only one source file, pick that one.

4. **Read it in full** via `read_file(<path>)`. If `read_file` returns an error, pick a different file from the listing and retry. Do not synthesize content; do not write a finding against a path you couldn't read.

5. **Locate the framing target.** From the file content, find one auth concern. The framing is broad — anything that affects who can do what, or what privileges propagate without verification, counts: missing access check before a privileged operation, hardcoded credentials, weak comparison (`==` of secrets), broken-by-default permission posture, untrusted input inheriting elevated authority (e.g., user-controlled string folded into a system prompt scope), tool surfaces invoked without per-caller authorization. If the file genuinely has no auth concern, write the smallest defensible finding with `tier: INFO` and a `summary` that names the absence — the goal is to exercise the pipeline truthfully, not to invent vulnerabilities.

Recon's only artifact is "the file path and line range you'll cite in the finding." No separate context document, no per-component history. Those return in later slices.

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

## Emission

6. **Stage the finding.** Write the finding object to `.lyrik/state/runs/<run-id>/staging/findings/finding-001.json` via `write_file`. One file, one finding, this minimal-plus-recon mode emits exactly one. The `location.file` must be the path you read in step 4. Do **not** write `findings.json` directly — the runner aggregates `staging/findings/*.json` into the final file.

7. **Return briefly.** Reply with one short sentence naming the file and the concern. The runner takes over aggregation.

## Finding shape

The staged file holds one finding object — same shape as one element of the canonical `findings` array. Required fields:

```json
{
  "id": "F001",
  "stable_id": "auth::<relative-file>:<line>",
  "stream": "novel",
  "framing": ["auth"],
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

## Path format

`<run-id>` substitutes whatever the runner passes as the run-id parameter. The skill receives it via the runner's prompt; do not invent it.

Final write path: `.lyrik/state/runs/<run-id>/staging/findings/finding-001.json`. The directory is created on first write — `write_file` will create parents as needed.
