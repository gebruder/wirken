# Audit CLI

`wirken audit` reads and verifies the hash-chained audit log produced by every running gateway. The log is per-session: each session has its own chain of events, and the integrity of any one session is provable independently. This page documents the user-facing surface so you can cite results in research output, script integrity checks, or hand the schema to a downstream tool.

The schema is versioned. As of this release, JSON output is `schema_version: 2`. Schema 2 is the first version with chain-head signature reporting; schema 1 archives stay readable through the same fields, signatures simply read as zero counters.

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

Verify the hash-chained integrity of every per-session log, plus the Ed25519 signature on every `ChainHead` row.

Flags:

- `--format human|json` choose output format (default `human`).
- `--require-signed` hard-fail on any session that has zero signed `ChainHead` rows. Without this flag, transition-era sessions recorded before chain-head signing was wired in are reported in counts and the verify exits zero. Invalid signatures are always a hard fail regardless of this flag.

Exit codes:

- `0`: the chain is intact and (under `--require-signed`) every session carries at least one signed head.
- `1`: at least one of these fired: a per-session hash chain is broken, a `ChainHead` signature did not verify, or `--require-signed` is set and a session has no signed heads. The output identifies which case fired and the session and seq involved.

Verifier behaviour:

- `Broken` (chain hash mismatch) is always a hard fail.
- `SignatureInvalid` is always a hard fail. Reasons include: claimed `current_chain_hash` does not match the stored chain hash at `sequence_range_end`; claimed `prev_chain_hash` does not match the stored hash at `sequence_range_start - 1`; the embedded `signing_key_id` is malformed; the Ed25519 signature did not verify; the embedded `schema_version` differs from the verifier's.
- `MissingChainHead` is reachable only under `--require-signed`; without the flag the same session contributes to the `sessions_with_no_signed_heads` counter and the verify exits zero.

Scripted usage:

```sh
wirken audit verify --require-signed && publish-results.sh
```

If `verify` exits non-zero, the chain failed (or the operator-pinned signed-head requirement was not met) and the script will not publish.

## JSON schema

Every JSON document includes a `schema_version` and `wirken_version` at the top level:

```json
{
  "schema_version": 2,
  "wirken_version": "1.2.0",
  ...
}
```

`schema_version` is the contract: when the shape of the output changes in a way that breaks existing consumers, the version bumps. Within a major schema version, fields may be added but existing fields will not be removed or have their meaning changed. Consumers should ignore unknown fields and fall over loudly if `schema_version` is greater than what they were written against.

Schema 2 history: introduced chain-head signature reporting on `verify --format json` (`signed_heads_count`, `unsigned_heads_count`, `invalid_signatures_count`, `signing_key_ids_seen`, `sessions_with_no_signed_heads`, `unsigned_tail_max_len`), plus two new `result` values (`signature_invalid` and `missing_chain_head`).

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

For an intact chain with signed chain heads:

```json
{
  "schema_version": 2,
  "wirken_version": "1.2.0",
  "result": "ok",
  "rows_verified": 1234,
  "sessions_total": 7,
  "signed_heads_count": 24,
  "unsigned_heads_count": 0,
  "invalid_signatures_count": 0,
  "sessions_with_no_signed_heads": 0,
  "signing_key_ids_seen": ["a3f2..."],
  "unsigned_tail_max_len": 12,
  "require_signed": true
}
```

`signed_heads_count` is the number of `ChainHead` rows whose Ed25519 signature verified. `unsigned_heads_count` is reserved for forward-compat (a future schema may admit unsigned heads) and is always `0` under schema 2. `invalid_signatures_count` is `0` in this `result: ok` shape: an invalid signature is a hard fail and surfaces as `signature_invalid`. `sessions_with_no_signed_heads` is the count of transition-era sessions; `--require-signed` hard-fails on these instead of reporting them. `signing_key_ids_seen` is the sorted list of distinct signing key ids; length > 1 indicates a key rotation across the verified window. `unsigned_tail_max_len` is the largest count of events past the last signed head observed across sessions; operators can use it to flag stale tails without failing the verify.

For an empty log:

```json
{
  "schema_version": 2,
  "wirken_version": "1.2.0",
  "result": "empty",
  "require_signed": false
}
```

For a broken chain (process exit code is `1`):

```json
{
  "schema_version": 2,
  "wirken_version": "1.2.0",
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
  "verified_count": 1180,
  "require_signed": false
}
```

For an invalid chain-head signature (process exit code is `1`):

```json
{
  "schema_version": 2,
  "wirken_version": "1.2.0",
  "result": "signature_invalid",
  "session": { "full": "assistant/webchat/abc123", "agent": "assistant", "channel": "webchat", "id": "abc123" },
  "seq": 102,
  "signing_key_id": "a3f2...",
  "reason": "current_chain_hash claim ... does not match stored hash ... at seq 101",
  "verified_count": 1500,
  "invalid_signatures_count": 1,
  "require_signed": false
}
```

`reason` cites the specific check that failed. The verifier short-circuits on the first invalid signature, so `invalid_signatures_count` is always `1` in this result.

For a missing chain head under `--require-signed` (process exit code is `1`):

```json
{
  "schema_version": 2,
  "wirken_version": "1.2.0",
  "result": "missing_chain_head",
  "session": { "full": "assistant/webchat/abc123", "agent": "assistant", "channel": "webchat", "id": "abc123" },
  "rows": 240,
  "verified_count": 1500,
  "require_signed": true
}
```

`verified_count` is the total number of events that verified before the break, summed across all sessions plus the per-session count up to (but not including) the breaking event in the broken session. Use this to scope what data downstream of the break can still be relied on.

### Transition behaviour

A log accumulated before chain-head signing was wired in has no `ChainHead` rows. Under default verify (no `--require-signed`), such sessions are counted in `sessions_with_no_signed_heads` and the verify exits zero. Under `--require-signed`, the same sessions surface as `missing_chain_head` and the verify exits `1`. Operators upgrading should run `wirken audit verify` first to see how many sessions are transition-era, then plan to enable `--require-signed` after the relevant retention window has rolled over to fully signed sessions.

## Citing a session in published research

The hash-chained audit log is designed to support reproducible-claim citation. The shape we recommend:

1. Run `wirken audit verify --format json` and record the result. If `result == "ok"`, the chain at the moment of citation is provably intact.
2. Run `wirken audit log --session <id> --format json` and archive the JSON alongside whatever artifact references it.
3. Cite the session by its `full` id and reference the archived JSON. The `wirken_version` and `schema_version` fields in the archive let a future reader reproduce the exact output format.

Note that session ids encode `{agent_id}/{channel}/{conversation_id}` as a prefix, which means citations reveal the agent name and channel. Keep this in mind for privacy-sensitive citation contexts.
