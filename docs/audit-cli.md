# Audit

Wirken's audit surface is a per-session, hash-chained SQLite table of typed
`SessionEvent` rows at `<data_dir>/audit.db`. Every row is appended before the
action it records runs, every row's payload is SHA-256-hashed, and the
integrity of any one session is provable independently of every other.

This page owns the chain, the event surface, and the CLI. Other pages link
here rather than restating any of it.

The audit schema version is the workspace version: the audit crate inherits it
(`version.workspace = true`), so a change to this schema bumps the workspace,
and therefore the binary, version.

## Event surface

Audit events come in two shapes: typed `SessionEvent` variants for actions the
agent runtime drives, and the `AuditLegacy` wrapper for the flat-tuple events
the gateway and subsystems emit (`gateway.start`, `audit.chain_broken`,
adapter handshake records). Variants are serde-tagged with `kind =
"<snake_case>"` so wire consumers dispatch on a single string field.

| `kind` | Identity fields | Emit context |
|--------|-----------------|--------------|
| `user_message` | `adapter_id`, `sender_id`, `inbound_id` | Inbound that triggered a turn. `None` for subagent recursion. |
| `assistant_message` | `agent_id` | Final assistant text for a turn. |
| `assistant_tool_calls` | `agent_id`, `adapter_id`, `sender_id` | Model requested one or more tool calls. Adapter and sender carry the originating channel so a SIEM need not join to the sibling `UserMessage`. `text` is what the model said in the same message as the calls; absent when it said nothing. |
| `tool_result` | `agent_id`, `adapter_id`, `sender_id` | Result of a tool call. `sandbox` says where an `exec` ran; absent for every tool that runs in the gateway's own process. |
| `llm_request` | `agent_id`, `credential_id`, `sender_id` | Pre-call row carrying `messages_hash`, `tools_hash` and `tools_hash_version` for replay. `credential_id` is the vault entry name, never the secret. `sender_id` is the platform-side human the call is on behalf of; `None` for CLI, cron and subagent sessions. |
| `llm_response` | `agent_id`, `credential_id`, `sender_id` | Token usage, latency, and per-call cost. See [cost monitoring](cost-monitoring.md). |
| `budget_exceeded` | `agent_id`, `credential_id` | Spend ceiling reached. `action` is `alerted` or `blocked`. |
| `http_fetch` | `agent_id`, `skill_name` | Egress through `EgressClient`. Host, URL, outcome, bytes, status. |
| `permission_denied` | `agent_id` | Tier or org-policy denial. Carries `tool`, `action_key`, `denial_source`, and `tier` when the source is `Tier`. |
| `permission_approved` / `permission_renewed` / `permission_grant_expired` / `permission_grant_pruned` | `agent_id` | Grant lifecycle. See [permissions](permissions-and-identity.md#what-the-chain-records-about-a-grant). |
| `permission_revoked` | `agent_id` | An operator removed a grant. Carries `revoked_by` and the `tier` and `expires_at` the row held. |
| `permission_approval_refused` | `adapter_id` | A decision arrived from a caller the gate would not take it from. Carries `request_id`, `caller` and `reason`; see [permissions](permissions-and-identity.md#what-the-chain-records-about-a-grant). |
| `skill_permission_denied` | `agent_id` | A per-skill profile denied an axis. |
| `sandbox_egress_verdict` / `sandbox_egress_unsupported` | `agent_id`, `channel`, `adapter_id`, `sender_id` | One row per sandbox egress request, allowed or not. See [egress](egress.md#audit). |
| `subagent_spawned` / `subagent_session_bound` / `subagent_result` | `agent_id`, `child_agent_id` | Sub-agent lifecycle under capability-attenuated ceilings. |
| `phase_entered` / `phase_exited` | `skill_id` | Skill-declared phase overlays. See [skills](skills.md#phase-boundaries). |
| `hook_dispatched` / `egress_hook_dispatched` / `tool_output_redacted` | `hook_id`, `agent_id` | Operator hook outcomes. See [enforcement model](enforcement-model.md#veto-and-egress-hooks). |
| `mcp_entry_verified` / `mcp_entry_refused` | `server_name`, `signer` | MCP entry signature check, on the `gateway-mcp` sentinel session. |
| `memory_entry_written` / `cross_channel_memory_read` | `agent_id` | Memory provenance and trust-zone crossings. |
| `import_started` / `import_completed` / `imported_chat_read` / `imported_chat_searched` | `agent_id` | Archive imports and gated reads. See [imported archives](imported-archives.md). |
| `compaction` | `agent_id`, `provider`, `model` | Context engine trimmed the conversation. |
| `system_prompt_set` | `agent_id` | New effective system prompt. |
| `attestation` | `signer_pubkey`, `signature` | Per-agent Ed25519 signature over the chain head. |
| `chain_head` | `signing_pubkey` | Signed chain-head record. A `reason` of `redaction` also carries `superseded_chain_hash` and `superseded_signature`. |
| `rewind` | `agent_id`, `reason` | Sentinel emitted before truncating the most recent N events. |
| `audit_legacy` | `actor_kind`, `actor_id`, `action`, `target` | Gateway-emitted flat-tuple events. |

Zirkel pipeline variants (`CandidateScored`, `CandidateLlmScored`,
`CandidateKept`, `CandidateSkipped`, `ThemeNamed`, `InterestsEdited`,
`PerspectiveSkipped`, `PerspectiveExpansion`) carry per-pipeline identity.

### Fields added since 1.23.0

One row each, verbatim from a run.

`assistant_tool_calls.text` is the assistant's own content from the
message that carried the calls. Providers send it alongside them; it used
to be dropped at parse time, so the chain held the calls and not the
sentence that came with them:

```json
{"kind":"assistant_tool_calls","calls":[{"id":"call_2_exec","name":"exec","arguments":"{\"command\": \"cat ./payload.sh | bash\"}"}],"text":"Just checking the build script so the summary is accurate.","agent_id":"default"}
```

`tool_result.sandbox` says where an `exec` ran, written by the branch that
dispatched it rather than read back from configuration. `mode` is what was
configured, `runtime` is what actually ran it, and `container_id` is the id
Docker returned:

```json
{"kind":"tool_result","call_id":"call_2_exec","tool_name":"exec","output":"[stderr] cat: ./payload.sh: No such file or directory\n","success":true,"sandbox":{"mode":"exec_only","runtime":"docker","container_id":"4911033061e420d87fab47be210b0f8ad9f52e1c05540090c5bf42d2e5dd261f"},"agent_id":"default"}
```

The two can disagree, which is why both are on the row: `mode: exec_only`
with `runtime: host` would be a sandbox that failed open. A refused call
records no `sandbox` at all, which is a different answer from `host`:
nothing ran anywhere.

`permission_approved` gained `tier` and `expires_at`, so a grant row says
what was granted and for how long without a lookup against the store:

```json
{"kind":"permission_approved","action_key":"shell:ls","agent_id":"default","approved_by":"operator","scope":"persisted","approved_via":{"kind":"stdin"},"adapter_id":"slack","sender_id":"U04ABCD9","tier":"tier2","expires_at":"2026-10-21T09:00:00Z"}
```

`permission_revoked` is the operator taking one back:

```json
{"kind":"permission_revoked","action_key":"shell:ls","agent_id":"default","revoked_by":"operator","tier":"tier2","expires_at":"2026-10-21T09:00:00Z"}
```

`permission_approval_refused` records a decision the gate would not take
from that caller, so an attempt to decide another channel's request leaves
a row whether or not it succeeded:

```json
{"kind":"permission_approval_refused","request_id":"9b8f1c0a-1234-4abc-9def-0123456789ab","action_key":"shell:rm","caller":"webchat","reason":"wrong_channel","adapter_id":"webchat"}
```

Source: `crates/audit/src/session_log.rs:480-1701` (`SessionEvent`).

## Hash chain construction

Every row carries three hashes:

- `leaf_hash` = SHA-256 over the canonical-JSON payload of the row.
- `prev_hash` = the chain hash of the previous row in the same `session_id`.
  Empty string for the first row.
- `hash` = SHA-256 over `prev_hash` and `leaf_hash` in **ASCII hex** form, the
  same form stored in the column. Length-prefixed by virtue of fixed 64-char
  hex.

Construction is per-session: a fresh `session_id` starts with an empty
`prev_hash`, and each subsequent append's `prev_hash` is the prior row's
`hash`. Two sessions on the same database never share chain state, so the
chain is not one chain for the whole deployment.

Source: `chain_hex()` at `crates/audit/src/session_log.rs:3258-3263`.

## Chain-head signing

`ChainHead` carries an Ed25519 signature over a length-prefixed message
binding the schema version, the session's sequence range, the previous chain
hash, and the current chain hash. Heads are written at session boundaries, on
a cadence of every 1000 appends or 5 minutes of wall-clock since the last
head, and on log rotation.

```text
"wirken/audit-chain-head/v1\0"        (domain separator, including the NUL)
|| seq_start.to_le_bytes()             (8 bytes, u64 little-endian)
|| seq_end.to_le_bytes()               (8 bytes, u64 little-endian)
|| (prev_chain_hash.len() as u32).to_le_bytes()
|| prev_chain_hash.as_bytes()          (ASCII hex form)
|| (current_chain_hash.len() as u32).to_le_bytes()
|| current_chain_hash.as_bytes()       (ASCII hex form)
|| schema_version.to_le_bytes()        (4 bytes, u32 little-endian)
```

`schema_version` is `2`. Bumping it is a wire-incompatible change to
chain-head verification.

The signing key lives at `<data_dir>/audit/audit-signing.key` (Ed25519 raw
32-byte seed, mode 0o600 on Unix), public half alongside it. It is distinct
from the IPC handshake keypair and from per-agent attestation identities. See
[signing.md](signing.md#chain-head-signing).

**What the signature does not protect against:** a malicious gateway that
signs a fabricated chain in real time. The key is held by the same process
that writes the chain, so a compromised gateway can record any sequence of
events and sign it. The signature is meaningful for offline replay and for
tamper detection by a third party reading the database.

Source: `build_signed_message()` at `crates/audit/src/signing.rs:189-208`;
constants at `:38` and `:44`; `load_or_create` / `load_from` at `:78-110`.

## Redaction

The chain is over payloads, so rewriting a row moves every hash from that
row onward and the head signed before it stops covering what is on disk.
Left there, the log reads as tampered from that row on and every row after
it is unusable with it.

`SqliteSessionLog::redact` is the sanctioned form. It replaces the row,
re-hashes to the end of the session, and mints a head with
`reason: redaction` over the rewritten range. That head carries the
superseded head's `current_chain_hash` and `signature`:

```json
{"kind":"chain_head","reason":"redaction","sequence_range_start":4,"sequence_range_end":7,"prev_chain_hash":"05a111eca546eed5bd0d94c22c94450ee9a40daccb7f3b0ab30559ca7148cc8d","current_chain_hash":"498d3721c78657dda557947b9b700dec626179ffccd123cbdd683a90bf42d951","signature":"73c82b648bd193a218e30896cb5dba999d4c0d9ee9c738c8b958f8ceef50c9d921fcd24e99afc62aea015e8aa568599fc860937847072132156c24ca3250140c","signing_pubkey":"81910acd06b86508de1dc28738d7ac18da03b5ed943f77adb58ffd191827a0fb","schema_version":2,"superseded_chain_hash":"70d69a1e854260de9e369cb0fa56124fc6e493c98b8f49e3e512960ef0a30164","superseded_signature":"5aaf615f06ff35699dab9f0a0a310feff7f4893a6c541d38fc5e4312be30f214d3016f4d280d2a96d69f322d56907c6549977f661acdc1835a27df8b0c051b07"}
```

`superseded_chain_hash` here is the `current_chain_hash` of the checkpoint
head that covered the range before the rewrite, and `superseded_signature`
is the signature made over it. Both are on the row so an auditor holding
the old head can see the range it signed, the hash it signed that range to,
and that the hash on disk is a different one.

`verify` treats a head that a redaction names as accounted for rather than
invalid; every other head still has to match its stored hash. A row
rewritten without minting a redaction head still reports `broken` at that
row, with the count of rows that verified before it.

**What redaction buys is attribution, not invisibility.** Anyone who can
call it can rewrite history, and the signing key is held by the process
that writes the chain, which is the same caveat the signature carries
above. What it cannot do is rewrite quietly: exactly one range shows as
resealed, under a named key. It refuses on an unsigned log, where there
would be no head to mint and nothing to tell a redaction from tampering.

## Tamper response

When the continuous verifier inside `AuditWriter`'s flush loop detects a chain
break, two records get written. The out-of-chain alarm comes first and is the
load-bearing record; the in-chain `audit.chain_broken` row is best-effort.

- **Alarm log.** `AlarmLog::append` writes one JSON record per line to
  `<data_dir>/audit-alarms.log` (mode 0o600 on Unix, append-only). Structure
  at `crates/audit/src/alarm_log.rs:78-106`, append boundary at `:177`.
  Operators read alarms via `wirken doctor`.
- **In-chain row.** The verify pass emits `AuditLegacy { action:
  "audit.chain_broken" }` through the writer's mpsc channel, so SIEM receivers
  see chain-tamper events alongside the rest of the legacy stream.

The dispatch is best-effort because the rest of the chain is compromised by
definition: an attacker who tampered the SQLite chain can also tamper any
follow-up row, so the alarm log (independent file, separate inode) is the
surviving channel. The independence is inode-level only; a same-UID attacker
can rewrite both files. Detection against that attacker rests on SIEM
corroboration of the alarm log plus the writer's `tracing::error!` halt event.

**Halt-boundary gap.** When the writer halts at `MAX_INTEGRITY_FAILURES` (3),
the `audit.chain_broken` event from the halt-triggering pass can be dropped
before flush. Operators see `N-1` chain_broken rows on the SIEM pipe plus the
halt log line plus the full alarm-log set. The alarm log is canonical at the
halt boundary.

**Halt counters are per-process.** The writer halts after 3 consecutive failed
verification passes or 3 consecutive failed alarm-log writes. Both counters
live in the in-process flush loop and reset on every gateway restart, so an
attacker with restart authority can drain the counter between failures. That
attacker already has UID-equivalent control of the host, at which point the
chain is no longer a defended boundary. A persistent state file was rejected
for the same reason: it would be writable at the same UID.

After a halt, `wirken audit acknowledge --all` archives the alarm log to a
timestamped sibling before the next `wirken run` will start.

## Commands

### `wirken audit log`

- `--action <name>` filter by action string (`exec`, `permission_denied`).
- `--actor <name>`, `--channel <name>`, `--session <id>` filters.
- `--since <iso8601>`, `--until <iso8601>` time bounds.
- `-n` / `--limit <n>` cap the events returned (default 50).
- `--format human|json` (default `human`).

With `--session <id>` the human output decomposes the id:

```
  Session: assistant/webchat/abc123
    Agent:   assistant
    Channel: webchat
    ID:      abc123
```

A non-canonical id (system sentinel sessions, zirkel runs keyed by UUID) shows
only the `Session:` line.

The human table does not carry the detail payload; `--format json` does.

### `wirken audit verify`

Verifies the hash-chained integrity of every per-session log, plus the Ed25519
signature on every `ChainHead` row.

- `--format human|json` (default `human`).
- `--require-signed` hard-fails on any session with zero signed `ChainHead`
  rows. Without it, sessions recorded before chain-head signing was wired in
  are reported in counts and the verify exits zero. Invalid signatures are
  always a hard fail regardless. Under this flag the verifier also enforces an
  operator trust anchor.
- `--anchor <hex-or-path>` operator-pinned audit-signing public key,
  repeatable so a rotated key set can list every accepted key. Each value is a
  64-character hex Ed25519 public key, or a path to a file containing one.
  Under `--require-signed`, a chain-head whose embedded `signing_key_id` is
  not in the anchor set is rejected, so a gateway that minted a fresh key
  cannot pass off a fabricated chain that otherwise verifies.

Exit `0` for an intact chain; exit `1` when a per-session chain is broken, a
`ChainHead` signature did not verify, `--require-signed` found a session with
no signed heads, or a chain-head is signed by a key outside the anchor set.
The output identifies which case fired and the session and seq involved.

**The default anchor is co-resident and says so.** When no `--anchor` is
given, the local `<data_dir>/audit/audit-signing.pub` is used when present,
and the verifier emits a `WARNING (audit anchor)` line to stderr and in human
output, plus an `anchor_warning` field in JSON, stating that a same-UID
attacker can swap that anchor together with the chain. Without
`--require-signed`, report-only verification carries an analogous note that no
operator trust anchor was consulted. The exit code is unchanged; this removes
a silent false assurance rather than changing behaviour. Tamper-evident
verification requires an out-of-band `--anchor`.

`SignatureInvalid` is always a hard fail. Reasons: claimed
`current_chain_hash` does not match the stored hash at `sequence_range_end`;
claimed `prev_chain_hash` does not match the stored hash at
`sequence_range_start - 1`; malformed `signing_key_id`; the signature did not
verify; the embedded `schema_version` differs from the verifier's.

Both stored hashes are read from the row's `hash` column, which rides on raw
bytes and does not depend on the payload parsing. A row inside a signed range
that this binary cannot deserialize, because a newer one wrote a variant it
does not know, is therefore reported as schema drift and leaves the head's
signature verdict alone. Drift inside a signed range is never
`SignatureInvalid`.

```sh
wirken audit verify --require-signed --anchor /etc/wirken/audit-signing.pub && publish-results.sh
```

### `wirken audit verify-attestations`

Checks every attestation signature against the **configured identity** of the
agent whose session it is, read from `{data_dir}/agents/<id>/identity.pub`.
The key is never taken from the attestation row: a row naming its own signer
and checked against that same key establishes only that the row is internally
consistent, which is true of any row an attacker writes. The row's
`signer_pubkey` is still checked, against the configured key, and a mismatch
is the failure.

Each session's agent is resolved from its id, except a sub-agent session,
whose id names its parent and whose own `SubagentSessionBound` row names the
agent it was woken as. `--agent <AGENT>` pins every session to one agent's
identity instead, which is the question to ask when a log arrives from
elsewhere.

An agent with no identity on disk has attestation disabled, so its sessions
carry signatures only if they were written when one existed. Those are
reported as **unpinned** under their own count and exit `6`: the signatures
are real and nothing here can say whose. That is distinct from a verification
failure, which exits `1`.

### `wirken sessions verify`

Replays one session log, re-checks per-session chain integrity, recomputes
message hashes at each `LlmRequest`, and re-executes deterministic tools
(`read_file`, `list_files`) against the current workspace. Reports events as
verified, unverifiable, or divergent.

Exit codes: `3` broken chain, `1` divergences, `2` unverifiable under
`--strict`, `5` cross-check disagreement, `4` no such agent or no events.

#### What a `tools_hash` attests

Each `LlmRequest` records a `tools_hash` over the tools the model was offered
and a `tools_hash_version` naming the rules it was computed under. `verify`
recomputes each row under its own version, so a session recorded under older
rules is not re-judged against rules that postdate it.

| Version | Covers | Does not cover |
| --- | --- | --- |
| `v1` | Base tools, MCP definitions, wasm skill definitions, the phase tools, filtered by the per-skill permission profile. | `spawn_subagent`, so a configured sub-agent ceiling was outside the attestation, and the `restrict_tools` clamp, so a child's narrowed tool set was outside it too. |
| `v2` | Everything `v1` covers, plus `spawn_subagent` when a ceiling is configured, plus the `restrict_tools` clamp. One builder produces both the offered set and the recomputation. | |

Rows written before the version field existed read as `v1`, which is what they
are. Nothing rewrites a stored row. A clean verify over `v1` rows is a
narrower claim than one over `v2` rows, and the difference is exactly the
sub-agent ceiling and clamp; the report prints a `tools_hash v1 rows` count
when any are covered.

#### Sub-agent sessions and `--with-parent`

A sub-agent session (`{parent}#sub-N`) verifies on its own. At spawn the child
writes a `SubagentSessionBound` row on its own chain, before its first
`LlmRequest`, naming the agent it was woken as and the tool set its parent's
ceiling narrowed it to. The parent's chain is never opened; a child session
verifies clean even when the parent's session is not present at all.

`--with-parent` compares the child's binding row against the parent's
`SubagentSpawned` row: agent id, granted tool set (as a set, since order is
not meaningful), and permission-tier cap. `offered_tools` is deliberately not
compared, being the granted set after the per-skill profile filter, so
asserting equality would report a disagreement every time a profile did its
job. A parent spawn row written before the tier was recorded there cannot be
compared on that field, and the output says so rather than letting absence
read as agreement.

A disagreement is not a tampered row. Both rows sit inside per-session hash
chains that `verify` checks separately, so neither can be edited after the
fact without breaking its own chain. A disagreement is either the spawn path
writing two different values, or two chains that do not belong together being
presented as a pair, which is what a spliced audit trail looks like. A missing
spawn row on the named parent (`NO MATCHING SPAWN ROW`) is the same class of
finding.

You cannot produce a cross-check failure by editing a row: an edit breaks that
session's own chain, `verify` reports `chain: BROKEN`, exits `3`, and the
cross-check never runs. Producing one takes two real runs, then moving the
second run's child-session rows verbatim, hashes included, into the first
run's log. Both chains still verify; what is false is the pairing.

#### Sessions with no binding row

A session whose id has the sub-agent shape but carries no binding row arises
two ways: a chain written before the row existed, or one where the write
failed or the chain was truncated. Either way the ceiling it ran under is
unrecoverable.

**Running it.** A live-purpose wake clamps to `tier1` with an empty tool set
and logs at `error`. That is deliberately unusable: the child cannot be
resumed under its original ceiling, because that ceiling is not recorded on
it, and running it under a guessed one is worse than not running it. Respawn
the child from its parent instead.

**Verifying it.** `verify` does not clamp and does not recompute a ceiling.
Inventing one would have the recomputation attest a tool set the verifier
chose. The `tools_hash` on those rows is left unchecked and the report prints
a `tools not attestable` count. Everything else about the session still
verifies. A clean report carrying a non-zero `tools not attestable` count says
nothing about which tools that session offered.

## JSON schema

Every JSON document carries `schema_version` and `wirken_version` at the top
level. `schema_version` is the contract: within a major version, fields may be
added but existing fields will not be removed or change meaning. Consumers
should ignore unknown fields and fall over loudly on a greater
`schema_version`. As of this release it is `2`, the first version with
chain-head signature reporting; schema 1 archives stay readable through the
same fields, with signatures reading as zero counters.

Session ids in JSON are objects, not bare strings:

```json
{ "full": "assistant/webchat/abc123", "agent": "assistant", "channel": "webchat", "id": "abc123" }
```

`full` is always present. The decomposed fields are conveniences and may be
absent for non-canonical ids. Round-trip through `full` when in doubt.

`wirken audit verify --format json` on an intact chain returns
`"result": "ok"` with `rows_verified`, `sessions_total`, `signed_heads_count`,
`unsigned_heads_count`, `invalid_signatures_count`,
`sessions_with_no_signed_heads`, `signing_key_ids_seen`,
`unsigned_tail_max_len` and `require_signed`.

`unsigned_heads_count` is reserved for forward-compat and is always `0` under
schema 2. `signing_key_ids_seen` longer than one entry indicates a key
rotation across the verified window. `unsigned_tail_max_len` is the largest
count of events past the last signed head observed across sessions, which lets
an operator flag a stale tail without failing the verify.

Other `result` values are `empty`, `broken`, `signature_invalid` and
`missing_chain_head`. A `broken` result adds `session`, `seq`,
`expected_hash`, `actual_hash` and `verified_count`. A `signature_invalid`
result adds `signing_key_id` and a `reason` citing the specific check that
failed; the verifier short-circuits on the first one, so
`invalid_signatures_count` is always `1` there. `verified_count` is the total
that verified before the break, summed across sessions, so downstream data can
be scoped to what still holds.

A `sessions_with_no_signed_heads` count is the transition-era case: a log
accumulated before chain-head signing was wired in has no `ChainHead` rows.
Under default verify those sessions are counted and the verify exits zero;
under `--require-signed` the same sessions surface as `missing_chain_head` and
it exits `1`. Run the default verify first to see how many there are before
enabling the flag.

## Citing a session

1. Run `wirken audit verify --format json` and record the result.
2. Run `wirken audit log --session <id> --format json` and archive it.
3. Cite the session by its `full` id. The `wirken_version` and
   `schema_version` fields let a future reader reproduce the output format.

Session ids encode `{agent_id}/{channel}/{conversation_id}`, so citations
reveal the agent name and channel. Keep that in mind for privacy-sensitive
contexts.

## Source references

- Variants and serde shape: `crates/audit/src/session_log.rs:480-1701`.
- Hash chain: `crates/audit/src/session_log.rs:3258-3263` (`chain_hex`).
- Chain-head signing: `crates/audit/src/signing.rs:38-208`.
- Alarm log: `crates/audit/src/alarm_log.rs:78-205`.
- Halt-boundary gap: [gebruder/wirken#107](https://github.com/gebruder/wirken/issues/107).
