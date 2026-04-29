# Audit CLI

`wirken audit` reads and verifies the hash-chained audit log produced by every running gateway. The log is per-session: each session has its own chain of events, and the integrity of any one session is provable independently. This page documents the user-facing surface so you can cite results in research output, script integrity checks, or hand the schema to a downstream tool.

The schema is versioned. As of this release, JSON output is `schema_version: 1`.

## Commands

### `wirken audit log`

Show events from the audit log.

Flags:

- `--action <name>` filter by action string (e.g. `exec`, `permission.denied`).
- `--actor <name>` filter by actor.
- `--channel <name>` filter by channel.
- `--session <id>` filter by full session id (e.g. `assistant/webchat/abc123`).
- `--since <iso8601>` filter to events at or after this timestamp.
- `--until <iso8601>` filter to events at or before this timestamp.
- `-n <n>` / `--limit <n>` cap the number of events returned (default 50).
- `--format human|json` choose output format (default `human`).

When `--session <id>` is provided, the human output includes a header that decomposes the session id:

```
  Session: assistant/webchat/abc123
    Agent:   assistant
    Channel: webchat
    ID:      abc123
```

If the id is not in the canonical `{agent}/{channel}/{id}` form (system sentinel sessions, zirkel runs whose id is just a UUID, etc.), only the `Session:` line is shown.

### `wirken audit verify`

Verify the hash-chained integrity of every per-session log.

Flags:

- `--format human|json` choose output format (default `human`).

Exit codes:

- `0` — the chain is intact, or the log is empty.
- `1` — at least one session's chain is broken. The output identifies the session, the seq where the break was detected, the hashes that disagreed, and the count of events that verified before the break.

Scripted usage:

```sh
wirken audit verify && publish-results.sh
```

If `verify` exits non-zero, the chain failed and the script will not publish.

## JSON schema

Every JSON document includes a `schema_version` and `wirken_version` at the top level:

```json
{
  "schema_version": 1,
  "wirken_version": "0.9.1",
  ...
}
```

`schema_version` is the contract: when the shape of the output changes in a way that breaks existing consumers, the version bumps. Within a major schema version, fields may be added but existing fields will not be removed or have their meaning changed. Consumers should ignore unknown fields and fall over loudly if `schema_version` is greater than what they were written against.

`wirken_version` is the binary that produced the output. Pin a specific Wirken version in scripted pipelines if you want bit-stable output across operator upgrades.

### Session id shape

Session ids in JSON output are objects, not bare strings:

```json
{
  "full": "assistant/webchat/abc123",
  "agent": "assistant",
  "channel": "webchat",
  "id": "abc123"
}
```

`full` is the canonical form used internally and is always present. The decomposed fields (`agent`, `channel`, `id`) are convenience fields and may be absent for non-canonical session ids; they may not exhaust future structure (i.e. a future Wirken version could add more decomposed fields without bumping the schema). When in doubt, round-trip through `full`.

### `wirken audit log --format json`

```json
{
  "schema_version": 1,
  "wirken_version": "0.9.1",
  "events": [
    {
      "id": 47,
      "ts": "2026-04-29T12:34:56+00:00",
      "actor": "gateway",
      "action": "orchestrator.push.refused",
      "target": "orchestrator",
      "channel": "",
      "session": { "full": "" },
      "detail": {
        "reason": "principal_mismatch",
        "expected": "uid:1000",
        "actual": "uid:1001"
      },
      "hash": "..."
    }
  ]
}
```

### `wirken audit verify --format json`

For an intact chain:

```json
{
  "schema_version": 1,
  "wirken_version": "0.9.1",
  "result": "ok",
  "rows_verified": 1234
}
```

For an empty log:

```json
{
  "schema_version": 1,
  "wirken_version": "0.9.1",
  "result": "empty"
}
```

For a broken chain (process exit code is `1`):

```json
{
  "schema_version": 1,
  "wirken_version": "0.9.1",
  "result": "broken",
  "session": {
    "full": "assistant/webchat/abc123",
    "agent": "assistant",
    "channel": "webchat",
    "id": "abc123"
  },
  "seq": 47,
  "expected_hash": "...",
  "actual_hash": "...",
  "verified_count": 1180
}
```

`verified_count` is the total number of events that verified before the break, summed across all sessions plus the per-session count up to (but not including) the breaking event in the broken session. Use this to scope what data downstream of the break can still be relied on.

## Citing a session in published research

The hash-chained audit log is designed to support reproducible-claim citation. The shape we recommend:

1. Run `wirken audit verify --format json` and record the result. If `result == "ok"`, the chain at the moment of citation is provably intact.
2. Run `wirken audit log --session <id> --format json` and archive the JSON alongside whatever artifact references it.
3. Cite the session by its `full` id and reference the archived JSON. The `wirken_version` and `schema_version` fields in the archive let a future reader reproduce the exact output format.

Note that session ids encode `{agent_id}/{channel}/{conversation_id}` as a prefix, which means citations reveal the agent name and channel. Keep this in mind for privacy-sensitive citation contexts.
