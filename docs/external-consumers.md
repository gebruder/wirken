# External consumers of the audit chain

Wirken's audit chain is exposed to out-of-process consumers (a local SIEM forwarder, a Sentinel sidecar, a Purview connector, an in-house alerting daemon) over two independent subscription surfaces. Both are wired in code today; this page documents how an external consumer attaches to either one.

## The two surfaces

| | Observe hook (IPC) | Webhook (HTTPS) |
|---|---|---|
| Transport | Cap'n Proto over Unix domain socket (Linux/macOS) or named pipe (Windows) | HTTPS POST out from wirken |
| Authentication | Ed25519 challenge-response, hook process holds keypair | Optional HMAC-SHA-256 over the request body |
| Direction | Pull (consumer drives cursor) | Push (wirken polls `session_events`, posts batches) |
| Replay control | Consumer-driven `sinceSeq` cursor | Single global cursor over `session_events.id` in the wirken-side worker, one indexed range query per poll across all sessions |
| Co-location | Must run at the same UID as the gateway | Can run anywhere reachable from the gateway |
| Payload shape | JSON-serialized `SessionEvent` inside a Cap'n Proto wrapper | JSON envelope built per target (`docs/siem-forwarder.md`) |

Pick the observe-hook surface for a same-UID consumer that wants Ed25519 authentication, pull-based backpressure, and cursor-driven replay. Pick the webhook surface for a cloud SIEM that cannot run a local connector at the wirken UID, where HMAC over HTTPS is the right trust model.

A single hook process can register against any combination of `observe`, `veto`, and `egress` roles under different hook ids; one consumer can tail the chain, veto pre-dispatch tool calls, and mediate post-execution tool output.

## Observe hook (IPC)

### Registering

The hook process holds an Ed25519 keypair. Mint one, then register the public key with the gateway:

```bash
wirken hooks register <hook-id> <pubkey-hex> --type observe
```

The hook id is operator-chosen and visible on every audit row the hook produces. The pubkey is the 32-byte Ed25519 public key, hex-encoded (64 characters). Source: `crates/cli/src/commands/hooks.rs`.

### Handshake

The hook connects to `<data_dir>/sockets/gateway-hooks.sock` (Linux/macOS) or the equivalent named pipe on Windows. Path is derived in `crates/gateway/src/config.rs::socket_dir`.

The gateway sends an `AuthChallenge` frame. The hook responds with `HookAuthResponse { publicKey, signature, hookId, hookType: "observe" }`. The signature is Ed25519 over `HOOK_HANDSHAKE_DOMAIN || hookId || 0x00 || nonce`, where `HOOK_HANDSHAKE_DOMAIN = b"wirken-ipc-hook-handshake-v1\x00"`. The gateway looks `hookId` up in its `hook_registry` SQLite table, verifies the signature with `verify_strict`, and accepts or rejects.

The domain separator means an adapter signature can never replay against the hooks acceptor and vice versa. Source: `crates/ipc/src/auth.rs` (`HOOK_HANDSHAKE_DOMAIN`, `perform_hook_handshake`, `perform_gateway_hook_handshake`).

### Subscription protocol

Once the handshake completes, the hook drives a pull loop. Each iteration sends one `SessionLogTail` frame and reads one `SessionLogTailResponse` frame.

`SessionLogTail`:

```
sessionId: Text     # which session to tail
sinceSeq:  UInt64   # consumer-held cursor; first call passes 0
maxRows:   UInt32   # soft cap on the response batch size
```

`SessionLogTailResponse`:

```
events:  List<SessionLogTailEvent>   # ordered ascending by seq
nextSeq: UInt64                      # pass this as the next sinceSeq
```

Each `SessionLogTailEvent`:

```
seq:     UInt64                      # per-session monotonic sequence
payload: Text                        # JSON-serialized SessionEvent
```

The capnp `payload` field is `Text` carrying a JSON document. The hook deserializes it against its own copy of the `SessionEvent` enum. The JSON wire keeps the capnp schema independent of audit-side variant churn: when wirken adds a new `SessionEvent` variant, the capnp schema does not change.

Source: `crates/ipc/schema/wirken.capnp` (`SessionLogTail`, `SessionLogTailEvent`, `SessionLogTailResponse`), `crates/cli/src/commands/run.rs::serve_observe_loop`.

### Cursor model

The hook owns its cursor. On a successful response with `events` non-empty, the hook persists `nextSeq` and uses it as the next `sinceSeq`. On an empty response, `nextSeq` equals the request's `sinceSeq` and the hook can either wait and retry or back off.

The wirken side keeps no per-hook cursor state. A hook that crashes and restarts re-reads its last-persisted cursor and resumes; rows the hook had already processed are not replayed if the cursor was advanced before the crash.

### At-least-once delivery

The observe loop has no replay protection on its own. A hook that receives a batch but crashes before persisting the new cursor will see the same rows on its next connection. The per-session `seq` is the canonical dedup key: the consumer should treat `(sessionId, seq)` as a primary key and ignore duplicates.

The chain is append-only and per-session monotonic, so the dedup is unambiguous.

### Multi-session

The hook must request each session id independently. To discover sessions, the hook can poll a known session id (the gateway's sentinel sessions like `gateway-hooks` and `gateway-mcp` exist for cross-cutting events), or maintain a list of agent sessions out of band. Wirken does not currently push a session-list endpoint over IPC; that's an operator-side concern.

### What's on the chain

Every `SessionEvent` variant defined in `crates/audit/src/session_log.rs` can flow through the observe loop. The variants currently in scope:

- Tool-call lifecycle: `UserMessage`, `AssistantMessage`, `AssistantToolCalls`, `ToolResult`.
- Policy decisions: `PermissionDenied`, `PermissionApproved`, `SkillPermissionDenied`, `HookDispatched`, `HookRegistered`, `HookCrashed`.
- Sub-agent lifecycle: `SubagentSpawned`, `SubagentResult`.
- Phase overlays: `PhaseEntered`, `PhaseExited`.
- LLM cost accounting: `LlmRequest`, `LlmResponse`.
- Network egress: `HttpFetch`.
- Chain integrity: `ChainHead`, `Attestation`, `AuditLegacy`, `Rewind`.
- Compaction and prompt: `SystemPromptSet`, `Compaction`.

The hook receives every event in every session it tails. There is no server-side filter on the observe pipe; filtering is the consumer's responsibility.

The webhook pipe (below) carries a curated default-forwarded subset defined in `crates/audit/src/siem_typed.rs::should_forward`. An observe consumer that wants to mirror that default has access to the same source-of-truth list.

## Webhook (HTTPS)

The legacy and typed pipes both post HTTPS batches to an operator-configured endpoint. Full wire shape, HMAC details, target-specific envelopes, and the include / exclude variant policy are documented in `docs/siem-forwarder.md`.

The typed pipe holds a single global cursor over `session_events.id` and issues one indexed range query per poll across all sessions (`get_events_after`), then ships batches; the cursor advances only on a successful POST so transient transport failures replay rather than drop. HMAC, when configured, is computed over the exact serialized request body via `crates/audit/src/siem.rs::compute_webhook_signature`.

The webhook surface is the right pick when the consumer is a cloud SIEM or an off-host pipeline. It is not the right pick when the consumer is a local sidecar at the same UID as the gateway; the observe-hook surface has stronger authentication and tighter cursor semantics for that case.

## Trust posture

The Ed25519 handshake binds the consumer's key to the `hookId` it claims, so an off-host attacker who has not registered a key cannot impersonate a hook. The HMAC pipe binds the message body to a shared secret, so an off-host attacker who has not stolen the secret cannot forge a delivery.

Neither surface defends against a same-UID attacker. The hook process's secret key is a file on disk at the wirken UID; the HMAC secret lives in `siem.json` at the same UID. A same-UID attacker who can read those can produce indistinguishable subscription clients. The chain itself is tamper-evident via the per-session hash chain and the signed `ChainHead` rows; consumers that want to detect mid-stream tampering verify the chain offline with `wirken sessions verify`, not on the wire.

## Building a consumer

The Rust ergonomics: depend on `wirken-ipc` for the capnp frame types and the handshake helpers, point the client at `gateway-hooks.sock`, drive `SessionLogTail` in a loop. The `serve_observe_loop` in `crates/cli/src/commands/run.rs` is the server side of the same protocol and reads as a reference implementation.

Non-Rust consumers can implement the protocol from the capnp schema (`crates/ipc/schema/wirken.capnp`) and the auth domain separator constant. The handshake is small enough to reimplement directly; the wire format is stable Cap'n Proto.

## Source references

- Observe loop: `crates/cli/src/commands/run.rs::serve_observe_loop`.
- Wire schema: `crates/ipc/schema/wirken.capnp` (`HookAuthResponse`, `SessionLogTail`, `SessionLogTailEvent`, `SessionLogTailResponse`).
- Handshake: `crates/ipc/src/auth.rs` (`HOOK_HANDSHAKE_DOMAIN`, `perform_hook_handshake`, `perform_gateway_hook_handshake`).
- Registry: `crates/gateway/src/hook_registry.rs`, `crates/cli/src/commands/hooks.rs`.
- Webhook pipe: `docs/siem-forwarder.md`.
- Default variant set: `crates/audit/src/siem_typed.rs::should_forward`.
- Offline chain verification: `docs/audit-cli.md`.
