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

# Lyrik (minimal + recon)

Find one auth-related finding in the codebase under `<workspace>` and write it to a single staging file. The runner aggregates that file into the canonical `findings.json`. This is the smallest viable assessment shape with recon — one framing, one finding, one write, one mandatory pass over the source — used to validate the runner pipeline before broader assessment forms re-enable.

Out of scope in this mode: Phase 0 (context, rubric), multi-framing, two-pass union, dedup, multi-pass scoring, concentration index, gate routing, exploit adapter. They return as separate slices.

## Recon (mandatory, before any finding)

The minimal-skill mode without recon produced fabricated paths — the model emitted findings against files that don't exist in the workspace. This section closes that hole. **Before emitting any finding, you must read at least one source file in scope, and the file you cite in `location.file` must be a file you have actually opened in this turn.** Inventing paths is the failure mode this section exists to prevent.

Recon steps:

1. **Read scope.** Open `.lyrik/config.json` if present; honor `scope.include` and `scope.exclude` glob lists. Otherwise treat the whole workspace as in-scope. Skip `.git/` and `.lyrik/` regardless.

2. **List files in scope.** Use `list_files(<dir>)` starting at the workspace root. For tiny workspaces (a handful of files), one `list_files(".")` suffices. For larger ones, descend into subdirectories whose names suggest auth-relevant content (`auth/`, `session/`, `acl/`, `permission/`, `admin/`, `user/`, `login/`, `token/`, `crypto/`).

3. **Pick a candidate file.** Prefer source files (`.py`, `.js`, `.ts`, `.go`, `.rs`, `.c`, `.h`, `.java`, `.rb`) whose name or directory matches the heuristics above. With nothing matching, pick the largest source file in scope. With only one source file, pick that one.

4. **Read it in full** via `read_file(<path>)`. If `read_file` returns an error, pick a different file from the listing and retry. Do not synthesize content; do not write a finding against a path you couldn't read.

5. **Locate the framing target.** From the file content, find one auth concern. The framing is broad — anything that affects who can do what, or what privileges propagate without verification, counts: missing access check before a privileged operation, hardcoded credentials, weak comparison (`==` of secrets), broken-by-default permission posture, untrusted input inheriting elevated authority (e.g., user-controlled string folded into a system prompt scope), tool surfaces invoked without per-caller authorization. If the file genuinely has no auth concern, write the smallest defensible finding with `tier: INFO` and a `summary` that names the absence — the goal is to exercise the pipeline truthfully, not to invent vulnerabilities.

Recon's only artifact is "the file path and line range you'll cite in the finding." No separate context document, no rubric, no per-component history. Those return in later slices.

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
