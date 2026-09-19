# Enforcement model

Which guarantees the compiler enforces and which are runtime policy. The
distinction matters for a long-running agent: structural safety must not be
compromised, while operational policy must be tunable without downtime.

This page also owns two mechanisms that sit across the boundary: the hook
surface and cross-channel memory.

## Compile-time

Enforced by the Rust compiler. Not bypassable by configuration, input or
runtime state; violating one requires modifying source and recompiling.

### Channel isolation

`wirken-ipc`, `crates/ipc/src/channel.rs`.

Each channel adapter is scoped to a zero-sized marker via `PhantomData<C>`:

```rust
pub struct SessionHandle<C: Channel> {
    id: SessionId,
    _channel: PhantomData<C>,
}
```

Markers are zero-sized structs (`Telegram`, `Discord`, `Slack`, `Matrix`,
`Teams`, `Signal`, `IMessage`, `GoogleChat`, `Generic`) implementing the
sealed `Channel` trait, which can only be implemented inside `wirken-ipc`.

The compiler prevents a Telegram adapter constructing a
`SessionHandle<Discord>`, and prevents a function taking
`SessionHandle<Telegram>` being called with the wrong one. Cross-channel
routing mistakes are caught at compile time **in code that uses
`SessionHandle<C>`**.

**The production message path does not.** Production frames carry a
`String`-typed channel discriminator on the `AuthenticatedChannel` value
resolved at handshake, and a cross-channel mismatch is rejected at runtime via
the `adapter.channel_mismatch` audit event rather than at compile time. The
typed API and its negative-test scaffolding exist at the type-system level;
the live cross-channel control is the runtime match.

What this does not cover either way: which agent handles which channel, which
is routing policy.

### Credential leak prevention

`wirken-vault`, `crates/vault/src/secret.rs`.

`VaultSecret` wraps `SecretString` and intentionally implements none of:

| Missing trait | Compile-time effect |
|---|---|
| `Display` | `println!("{}", secret)` is a compile error |
| `Debug` | `tracing::info!("{:?}", secret)` is a compile error |
| `Clone` | Cannot make copies that escape the intended scope |
| `Serialize` | Cannot write to JSON, logs or files |

The only access path is `expose() -> &str`, a short-lived borrow that cannot
outlive the value. Memory is zeroed on drop.

**What this does not cover:** a caller who captures the `&str` and copies it
into a new `String`. Deliberate: the API makes the safe path easy and the
unsafe path visible in code review.

### Adapter authentication identity

`crates/ipc/src/auth.rs`. Each adapter holds an `AdapterIdentity` containing
an Ed25519 signing key, generated at registration and verified during the
handshake: the gateway sends a 32-byte nonce, the adapter signs it, the
gateway verifies against the registered public key.

The handshake protocol is encoded in the type signatures of
`perform_adapter_handshake` and `perform_gateway_handshake`; a caller cannot
skip the challenge step because the function requires both reader and writer
and the protocol is sequential. `SigningKey` implements neither `Serialize`
nor `Display`, preventing accidental export.

**What this does not cover:** which public keys are trusted, which is runtime
state in `AdapterRegistry`.

### IPC frame safety

`crates/ipc/src/transport.rs`. `FrameReader` enforces a 16MB frame size limit
and passes Cap'n Proto reader options with a 64M word traversal limit (512 MB)
and a 64-level nesting limit. These are compile-time constants; a frame
exceeding the size limit is rejected before allocation.

Cap'n Proto's generated reader types are lifetime-parameterized, so
deserialized data cannot outlive its buffer, and the schema is compiled from
`.capnp` at build time, so structure mismatches are caught by `cargo build`.

## Runtime

Enforced by configuration and runtime checks. Changeable by operators without
recompiling.

| Surface | Live update? | Owner |
|---|---|---|
| Permission tiers and grants | Yes. `approve` and `revoke` are SQLite writes checked on every query | [permissions-and-identity.md](permissions-and-identity.md) |
| Skill loading | On next `load_skills`, currently a gateway restart; there is no filesystem watcher | [skills.md](skills.md) |
| Org policy | Refreshed at gateway start. Mid-session changes require a restart | [enterprise.md](enterprise.md) |
| Provider configuration | Requires a restart. The `LlmClient` is constructed once per agent at startup | [configuration.md](configuration.md) |
| Sandbox mode | Requires a restart. Container resource limits are constants in the sandbox module | [sandbox-properties.md](sandbox-properties.md) |
| Sandbox egress per channel | Next `exec` | [egress.md](egress.md#sandbox-egress) |
| SIEM targets | Requires a restart after editing `siem.json`. Forwarding is non-blocking; failures are logged and do not block the audit pipeline | [siem-forwarder.md](siem-forwarder.md) |
| Audit chain-head key rotation | A fresh gateway start picks up a new keypair. The verifier accepts heads signed by any key whose public part is on the row and reports the distinct set | [audit-cli.md](audit-cli.md#chain-head-signing) |
| Hook registry | Durable in `hooks.db`. Active connections survive a registry edit and continue dispatching until disconnect; new connections honor the updated registry at handshake | below |

### Rate limits

`crates/gateway/src/rate_limit.rs`. Two limiters, both in memory:

- `AuthRateLimiter`: per-source, 5 failures / 60s / 10-minute lockout, with no
  loopback exemption.
- `ControlPlaneRateLimiter`: global GCRA via `governor`, lock-free atomics.

State resets on gateway restart; thresholds are set at startup from
`GatewayConfig`.

### Model governance

The model an agent runs is operator configuration, not a chat setting. There
is no user-facing model selector: an end user talking to an agent over any
channel cannot choose or change the model, and no chat command switches it.
The global default is pinned in `provider.json`; a per-agent override is
pinned in `AgentConfigStore` and takes precedence when a record exists.
Because both are admin-side files applied at gateway start, pinning a model
version is an operator control: changing it means editing one of them and
restarting, which is auditable rather than user-driven.

Model pinning pairs with cost metering: the pinned pair is what per-call cost
is priced against and what per-agent spend attributes to. See
[cost-monitoring.md](cost-monitoring.md).

### Prompt injection detection

`crates/gateway/src/injection_detect.rs`. `InjectionDetector` scans inbound
messages for role-switching attempts, instruction-override markers,
base64-encoded commands, tool-call injection structures and system-prompt
extraction attempts.

**Detection does not block.** It tags the audit event with a `threat` detail
object and emits a separate `message.threat_flagged` event for SIEM
visibility. The permission tiers and the sandbox are what limit what an
injected agent can actually do.

Patterns are compiled into the binary, so adding one requires recompilation.
The detector is stateless and shared across all adapter connections.

## Veto and egress hooks

Operators register external hook processes:

```bash
wirken hooks register <id> <pubkey-hex> --type <observe|veto|egress>
```

Each hook holds its own Ed25519 keypair, connects inbound on
`<data_dir>/sockets/gateway-hooks.sock`, and is matched against the registry
at handshake. The handshake binds the signature under a domain separator
distinct from the adapter handshake, so a key valid for one cannot replay
against the other. The `observe` role and the wire protocol are in
[siem-forwarder.md](siem-forwarder.md#observe-hook).

**Veto hooks run pre-dispatch.** After the built-in tier and per-skill gates
accept a tool call, the runtime calls
`HookDispatcher::dispatch(tool_name, arguments, session_id)`. Hooks run in
registration order under a cumulative wall-clock budget
(`WIRKEN_VETO_BUDGET_MS`, 1000ms default) with a per-hook ceiling of 500ms.
The first `Deny` short-circuits and the remaining hooks are recorded as
`Skipped` with no audit row; a `Timeout` row lands on the chain so budget
exhaustion is distinguishable from an operator deny. Each non-skipped outcome
emits one `HookDispatched` row.

**Egress hooks run post-execution.** After a tool returns and before its
output enters the LLM conversation, the runtime calls
`EgressDispatcher::dispatch(tool_name, output_bytes, session_id)` under a
`WIRKEN_EGRESS_BUDGET_MS` budget with the same per-hook cap. Each hook returns
one of:

- `Allow`: the working bytes pass through unchanged.
- `Replace { bytes }`: the working bytes are substituted, and the next hook in
  the pipeline sees the new bytes.
- `Refuse { reason }`: short-circuits; the tool's output becomes a refusal
  placeholder and the LLM sees that the call produced no usable bytes.

Each non-skipped outcome emits one `EgressHookDispatched` row carrying the
operator-readable decision. When the final bytes differ from the original, a
paired `ToolOutputRedacted` row records `original_sha256`, `original_size`,
`redacted_sha256`, `redacted_size` and the attribution fields.

**The original bytes are not on the chain by design.** An egress hook's
purpose is preventing those bytes from spreading; recording them defeats the
redaction. The original sha256 is the only on-chain reference, which is
sufficient for an auditor holding a candidate plaintext to verify the
redaction was applied to the bytes they expect.

**Chain invariant.** `ToolResult.output` carries the post-mediation bytes
verbatim, and the conversation that produced the next `LlmRequest`'s
`messages_hash` was built from those same bytes, so `sessions verify`
reconstitutes an identical conversation and the hash matches.
Deterministic-tool re-execution checks skip rows that have a
`ToolOutputRedacted` paired row at a higher seq for the same `call_id`: the
redaction is operator policy, not wirken behaviour, and re-execution would
compare freshly-produced source bytes against operator-redacted ones.

**Timeout posture.** Both dispatchers fail closed by default.
`WIRKEN_ALLOW_UNREGISTERED_HOOKS=1` flips the timeout path to fail open with a
`tracing::warn!`; the audit row records the timeout regardless, so a reviewer
can distinguish "hook timed out" from "hook ran clean".

## Cross-channel memory

`crates/gateway/src/memory.rs`, `crates/agent/src/memory_tool.rs`.

Continuity between channels is carried by labelled entries, not by replaying
other channels' session logs. Replay would import history written before these
labels existed, so provenance would be incomplete from the first read.

Every entry carries five origin labels stamped at insert: `channel`,
`adapter_id`, `sender_id`, `agent_id`, `origin_session_id`.
`MemoryStore::write` refuses an entry with any label empty and is the only
insert path; every column is `NOT NULL` and nothing backfills. The labels are
built by the runtime from the turn's inbound context and are not reachable
from tool arguments, so a model cannot author its own provenance. A turn
missing a channel, adapter or sender installs no memory context at all, which
leaves the tools unconfigured for that turn rather than writing a partial
entry; cron and CLI turns land there.

`origin_session_id` is carried because the other labels reconstruct
`{agent_id}/{channel}/…` but not the conversation segment. Without it an entry
narrows only to "some conversation on this channel with this agent"; with it
the entry pins to the hash chain that recorded its creation.

Three tools, all registered in `tool_to_action` so none reaches the gate as an
unregistered name:

| Tool | Action | Tier |
|---|---|---|
| `memory_write` | `WorkspaceFileAccess` | 1 |
| `memory_read` | `WorkspaceFileAccess` | 1 |
| `memory_read_channel` | `CrossChannelMemoryRead { from_channel }` | 3 |

Writing, and reading the current channel's own entries, cross no trust zone.
Reading another channel's entries is a crossing: Tier 3, prompting on every
use, and `approve_by_key` refuses a `cross_channel_memory:` key outright so an
operator cannot come to believe otherwise. The key carries the channel being
read *from*, so approving one channel's history approves no other; the
destination is the channel the turn already runs on and is recorded on the
audit row instead. A missing `channel` argument produces an empty key, which
matches no stored channel and returns nothing rather than widening.

Two events land on the chain: `MemoryEntryWritten` with the full label set,
and `CrossChannelMemoryRead` with both ends of the crossing plus the entry
count. The crossing event is emitted even when the read returns nothing,
because the crossing was still made.

Reads are scoped to one agent. **Cross-channel means another channel of the
same agent, never another person.** `(adapter_id, sender_id)` is a
platform-scoped principal, not a person: a Slack uid and a Signal number are
different values for the same human, and wirken has no identity linking to
join them. Per-channel process isolation is untouched, since continuity is
mediated entirely through the gateway store with no adapter-to-adapter path
and no shared state between channel processes.

## Orchestrator push

The gateway exposes a push socket (`<data_dir>/sockets/orchestrator.sock` on
unix, a named pipe on windows) used by `wirken zirkel run`'s digest push and
similar callers to deliver outbound messages without going through the
per-adapter Ed25519 handshake. Because the socket bypasses adapter
authentication, every accepted connection has its peer credentials checked
against the gateway's own identity.
