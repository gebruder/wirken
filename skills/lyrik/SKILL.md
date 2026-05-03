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

# Lyrik (minimal)

Find one auth-related finding in the codebase under `<workspace>` and write it to a single staging file. The runner aggregates that file into the canonical `findings.json`. This is the smallest viable assessment shape — one framing, one finding, one write — used to validate the runner pipeline end-to-end before broader assessment forms re-enable.

Out of scope in this minimal mode: Phase 0 (context, rubric), recon, multi-framing, two-pass union, dedup, multi-pass scoring, concentration index, gate routing, exploit adapter. They return as separate slices once the minimal pipeline is confirmed working.

## Steps

1. **Read scope.** Open `.lyrik/config.json` if present; honor `scope.include` and `scope.exclude` glob lists. Otherwise treat the whole workspace as in-scope. Skip `.git/` and `.lyrik/` regardless.
2. **List files in scope.** Walk the workspace, picking source files (`.py`, `.js`, `.ts`, `.go`, `.rs`, `.c`, `.h`, `.java`, `.rb`). For tiny workspaces, every file is fair game.
3. **Pick one file likely to carry an auth concern.** Heuristics: filename or directory contains `auth`, `login`, `session`, `acl`, `permission`, `role`, `admin`, `token`. Otherwise, any file that exposes callable surfaces or builds prompts that mix trusted/untrusted text. With nothing better, pick the largest source file in scope.
4. **Read the file.** Identify one auth concern. The framing is broad — anything that affects who can do what, or what privileges propagate without verification, counts: missing access check before a privileged operation, hardcoded credentials, weak comparison (`==` of secrets), broken-by-default permission posture, untrusted input inheriting elevated authority (e.g., user-controlled string folded into a system prompt scope), tool surfaces invoked without per-caller authorization. If the file genuinely has no auth concern, write the smallest defensible finding anyway with `tier: INFO` and a rationale that names the absence — the goal of the minimal pipeline is to exercise emission, not to invent vulnerabilities.
5. **Stage the finding.** Write the finding object to `.lyrik/state/runs/<run-id>/staging/findings/finding-001.json` via `write_file`. One file, one finding, this minimal mode emits exactly one. Do **not** write `findings.json` directly — the runner aggregates `staging/findings/*.json` into the final file.
6. **Return briefly.** Reply with one short sentence naming the file and the concern. The runner takes over aggregation.

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
  "tier": "MEDIUM",
  "grade": 0.5,
  "rung": "static_corroboration",
  "deferral": null
}
```

Field rules:
- `tier` is uppercase, one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
- `grade` is one of `0`, `0.5`, `1` (use `0.5` in this minimal mode — no exploit run).
- `rung` is one of `suspicion`, `static_corroboration`, `property_violated`, `root_cause_explained`, `variant_observed`, `patch_localized`. Pick the rung your evidence actually defends; with one file read and no exploit attempt, `static_corroboration` is the realistic ceiling.
- `deferral` is `null` in this minimal mode.

## Path format

`<run-id>` substitutes whatever the runner passes as the run-id parameter. The skill receives it via the runner's prompt; do not invent it.

Final write path: `.lyrik/state/runs/<run-id>/staging/findings/finding-001.json`. The directory is created on first write — `write_file` will create parents as needed.
