# Audit events

Wirken's audit surface is a per-session, hash-chained SQLite table of typed `SessionEvent` rows. Every row is appended before the action it records runs, every row's payload is SHA-256-hashed, and every row's chain hash is `SHA-256(prev || leaf)` in ASCII hex.

## Event surface

Audit events come in two shapes: typed `SessionEvent` variants for actions the agent runtime drives, and the `AuditLegacy` wrapper for the flat-tuple events the gateway and subsystems emit (`gateway.start`, `audit.chain_broken`, adapter handshake records, etc.).

Variants are serde-tagged with `kind = "<snake_case>"` so wire consumers can dispatch on a single string field.

| `kind` | Variant | Identity fields | Emit context |
|--------|---------|-----------------|--------------|
| `user_message` | `UserMessage` | `adapter_id`, `sender_id`, `inbound_id` | Inbound that triggered an agent turn. Adapter and sender identify the platform; `None` for subagent recursion. |
| `assistant_message` | `AssistantMessage` | `agent_id` | Final assistant text for a turn. |
| `assistant_tool_calls` | `AssistantToolCalls` | `agent_id`, `adapter_id`, `sender_id` | Model requested one or more tool calls. Adapter/sender carry the originating channel for SIEM correlation without joining to the sibling `UserMessage`. |
| `tool_result` | `ToolResult` | `agent_id`, `adapter_id`, `sender_id` | Result of a tool call. Same identity contract as `AssistantToolCalls`. |
| `llm_request` | `LlmRequest` | `agent_id`, `credential_id` | Pre-LLM-call row carrying tool/messages hashes for replay. `credential_id` is the vault entry name the api_key was resolved from; never the raw secret. |
| `llm_response` | `LlmResponse` | `agent_id`, `credential_id` | Post-LLM-call row carrying token usage and latency. |
| `http_fetch` | `HttpFetch` | `agent_id`, `skill_name` | Egress through the agent's `EgressClient`. Records host, URL, outcome, bytes, HTTP status. |
| `permission_denied` | `PermissionDenied` | `agent_id` | Runtime tier or org-policy denial. Carries `tool`, `action_key`, `denial_source` (`Tier` or `OrgPolicy`), and `tier` when the source is `Tier`. |
| `skill_permission_denied` | `SkillPermissionDenied` | `agent_id` | Per-skill effective profile denied an axis (egress / filesystem / inference / tool). |
| `subagent_spawned` | `SubagentSpawned` | `agent_id`, `child_agent_id` | Parent spawned a child agent under capability-attenuated ceilings. |
| `subagent_result` | `SubagentResult` | `agent_id`, `child_agent_id` | Child returned (`Ok` / `Error` / `RoundsExceeded` / `DepthExceeded` / `Timeout`). |
| `compaction` | `Compaction` | `agent_id`, `provider`, `model` | Context engine trimmed the conversation before an LLM call. |
| `system_prompt_set` | `SystemPromptSet` | `agent_id` | New effective system prompt for the session. |
| `attestation` | `Attestation` | `signer_pubkey`, `signature` | Per-agent Ed25519 signature over the chain head. |
| `chain_head` | `ChainHead` | `signing_pubkey` | Signed chain-head record bracketing session start/end and cadence checkpoints. |
| `rewind` | `Rewind` | `agent_id`, `reason` | Rewind sentinel emitted before truncating the most recent N events. |
| `audit_legacy` | `AuditLegacy` | `actor_kind`, `actor_id`, `action`, `target` | Wrapper for gateway-emitted flat-tuple events that don't fit a typed variant: `gateway.start`, `audit.chain_broken`, adapter `connect` / `disconnect`, MCP proxy registration, etc. |

Skill candidate scoring variants (`CandidateScored`, `CandidateLlmScored`, `CandidateKept`, `CandidateSkipped`, `ThemeNamed`, `InterestsEdited`, `PerspectiveSkipped`, `PerspectiveExpansion`) record Zirkel pipeline state and carry the relevant per-pipeline identity.

## Hash chain construction

Every row carries three hashes:

- `leaf_hash` = SHA-256 over the canonical-JSON payload of the row.
- `prev_hash` = the chain hash of the previous row in the same `session_id`. Empty string for the first row.
- `hash` = SHA-256 over `prev_hash` and `leaf_hash` in **ASCII hex** form (the same form stored in the column). Length-prefixed by virtue of fixed 64-char hex.

Construction is per-session: a fresh `session_id` starts with empty `prev_hash`, and each subsequent append's `prev_hash` is the prior row's `hash`. Two sessions on the same database never share chain state.

Source: `chain_hex()` at `crates/audit/src/session_log.rs:2653-2658`.

## Chain-head signing

The `ChainHead` variant carries an Ed25519 signature over a length-prefixed message that binds the schema version, the session's sequence range, the previous chain hash, and the current chain hash. The signed bytes layout is:

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

`schema_version` is currently `2`. Bumping it is a wire-incompatible change to chain-head verification.

Source: `build_signed_message()` at `crates/audit/src/signing.rs:189-208`. Domain separator and schema version constants at `crates/audit/src/signing.rs:38` and `:44`. Per-instance signing key at `<data_dir>/audit/audit-signing.key` (Ed25519 raw 32-byte seed, mode 0o600 on Unix); see `crates/audit/src/signing.rs:78-110` for `load_or_create` and `load_from`.

## Tamper response

When the continuous verifier inside `AuditWriter`'s flush loop detects a chain break, two records get written. The out-of-chain alarm comes first and is the load-bearing record; the in-chain `audit.chain_broken` row is best-effort.

- **Alarm log.** `AlarmLog::append` writes one JSON record per line to `<data_dir>/audit-alarms.log` (mode 0o600 on Unix, append-only). The structure is `AlarmRecord` at `crates/audit/src/alarm_log.rs:78-106`. The append boundary is at `crates/audit/src/alarm_log.rs:177`. Operators read alarms via `wirken doctor`.

- **In-chain row.** The verify pass emits `AuditLegacy { action: "audit.chain_broken", ... }` through the `AuditWriter`'s mpsc channel. The flush loop drains the channel, writes the row to SQLite, and SIEM-forwards it on the next flush. Receivers see chain-tamper events alongside the rest of the legacy stream.

The dispatch is best-effort because the rest of the chain is already compromised by definition: an attacker who tampered the SQLite chain can also tamper any follow-up row, so the alarm log (independent file, separate inode) is the surviving channel. SIEM corroboration of the alarm log plus the writer's `tracing::error!` halt event and the now-forwarded `audit.chain_broken` rows is the path to detection when a same-UID attacker can rewrite both files.

**Halt-boundary gap.** When the writer halts at `MAX_INTEGRITY_FAILURES`, the `audit.chain_broken` event from the halt-triggering pass can be dropped before flush. Operators see `N-1` chain_broken rows on the SIEM pipe plus the halt log line plus the full alarm-log set. The alarm log is canonical at the halt boundary. Tracked at [gebruder/wirken#107](https://github.com/gebruder/wirken/issues/107).

## Source references

- Variants and serde shape: `crates/audit/src/session_log.rs:263-720`.
- Hash chain: `crates/audit/src/session_log.rs:2653-2658` (`chain_hex`).
- Chain-head signing: `crates/audit/src/signing.rs:38-208` (domain separator, schema version, key load, message build).
- Alarm log: `crates/audit/src/alarm_log.rs:78-205` (record, log, append).
- Halt-boundary gap: [gebruder/wirken#107](https://github.com/gebruder/wirken/issues/107).
