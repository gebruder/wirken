# Lyrik JSON output schema (1.0)

This document specifies the contract that `findings.json` files
produced by Lyrik conform to. External consumers (SIEM ingestors,
ticketing systems, CI/CD gates, report-to-report diff tools) pin
against the surface described here.

A larger funnel-disclosure surface is forward-looking work; see
`docs/design/lyrik-json-schema-future.md`. 1.0 is what the current
producer emits, nothing more.

## Identity

- `$id`: `https://raw.githubusercontent.com/gebruder/wirken/schema-v1.0/docs/lyrik-json-schema.json`
- Versioning policy: the schema is tag-pinned, not release-pinned.
  Patch and minor wirken releases that do not change the schema do
  not move the tag; consumers pinned against `schema-v1.0` stay
  valid across wirken updates. Schema changes cut a new tag
  (`schema-v1.1`, `schema-v2.0`) and a new spec document.
- `$id` is canonical identity. It resolves to a fetchable copy of
  the schema once the `schema-v1.0` tag is cut. `wirken lyrik
  validate` embeds the schema bytes and never fetches `$id` over
  the network; the URL is for external JSON Schema validators.

## Top-level shape

```json
{
  "schema_version": "1.0",
  "run_id": "<non-empty string>",
  "produced_at": "<RFC 3339 timestamp>",
  "findings": [ /* zero or more finding objects */ ]
}
```

Required fields:

| Field            | Type   | Notes                                  |
|------------------|--------|----------------------------------------|
| `schema_version` | string | Must be `"1.0"` for this version       |
| `run_id`         | string | Non-empty                              |
| `produced_at`    | string | RFC 3339 timestamp                     |
| `findings`       | array  | Zero or more finding objects           |

Extra top-level fields are allowed and ignored. Producers may carry
optional metadata (`comparison`, `cost`, `reproducibility`,
forward-looking forms of `target`/`funnel`/`concentration`); 1.0
validators do not enforce their shape.

## Finding shape

Required per-finding fields:

| Field                  | Type    | Notes                                   |
|------------------------|---------|-----------------------------------------|
| `id`                   | string  | Per-run finding id (e.g. `F001`)        |
| `stable_id`            | string  | Conforms to the grammar below           |
| `framing`              | array   | One or more closed-enum strings         |
| `location.file`        | string  | Workspace-relative path                 |
| `location.line_start`  | integer | 1-based                                 |
| `title`                | string  | One short sentence                      |
| `summary`              | string  | One sentence                            |
| `tier`                 | string  | Closed enum (see below)                 |

Closed enums:

- `framing[*]`: `"auth"` or `"injection"`.
- `tier`: `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"INFO"`.

Extra per-finding fields are allowed and ignored (`stream`, `grade`,
`rung`, `deferral`, `scoring_passes`, `scoring_disagreement`,
`location.line_end`, `location.function`, etc.). Producers may carry
them through; 1.0 validators do not enforce their shape.

## Stable-ID grammar

```
stable_id := framing "::" rel_file ":" line
framing   := "auth" | "injection"
rel_file  := byte sequence as it appears on disk to lyrik
line      := decimal integer, 1-based, equal to location.line_start
```

Parse rule: the last `:` in the string separates `line` from
`rel_file`. Everything before the rightmost `:` and after the `::`
is the file path; this admits `:` inside `rel_file` (legal on
POSIX) without an escape character.

Byte rule: `rel_file` is byte-for-byte the path lyrik sees on disk.
No Unicode normalization is applied at the producer side. File
systems disagree (Linux is bytes, macOS HFS+ may apply NFD, Windows
is UTF-16); consumers that compare stable IDs across platforms
perform their own normalization.

Examples that conform:

```
auth::src/foo.rs:42
injection::deeply/nested/path/file.py:1
auth::a:b:c.rs:7        # colon in filename, parses right-to-left
auth::main.go:1
```

Examples that do not conform:

```
unknown_framing::file.rs:1   # framing not in the enum
::file.rs:1                  # empty framing
auth::file.rs:               # missing line
auth::file.rs:1.5            # non-integer line
auth::file.rs                # missing line separator
auth::/abs/path.rs:1         # absolute path, not workspace-relative
```

Stability annotation for consumer-side diff tools: `line` is the
brittle component. A finding can shift line numbers between runs
because of unrelated edits above it. Consumer-side fuzzy matchers
should prefer `(file, line) → (file)` proximity matching when an
exact stable_id miss happens.

## Validation

`wirken lyrik validate <path>` reads the file at `path`, parses it
as JSON, and validates every rule in this document. Exits 0 on
conformance; exits 1 with a list of structured errors otherwise.
The validator embeds the canonical schema; no network fetch.

## Sort order

`findings[]` is sorted by `(location.file, location.line_start)`
ascending. Stable across runs of the same scope; a finding moving
between framings does not jump positions.

## What is not in 1.0

The fields below are described in
`docs/design/lyrik-json-schema-future.md` as forward-looking work
and are not part of the 1.0 surface. Consumers must not pin against
them. They will land in a future schema version alongside producer
changes.

- Top-level `target` block (scope, source_state, qualifier enum).
- Top-level `funnel` block and its reconciliation invariants.
- Top-level `concentration` block.
- Top-level `observations` block.
- Per-finding `gate_routed`, `dedup_match`, `stream`,
  `detection_source` as closed enums.
- `triage_status` reserved field.
- Schema URL embedded in reports as `$schema`. 1.0 does not require
  producers to emit `$schema`; if a report carries one, the
  validator asserts it string-equals `$id`.
