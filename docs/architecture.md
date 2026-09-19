# Architecture

**Wirken**: German, *to work*, *to weave*, *to have effect*. Named for
[Gebruder Ottenheimer](https://gebruder.ottenheimer.app/briefs/wirken.html), a
weaving mill in Wurttemberg, 1862-1937.

A model-agnostic agent switchboard: multi-channel, skill-driven, local-first.
This page is the shape and the reasoning. Each mechanism has an owning page
and is linked, not restated.

Written in Rust because the properties this architecture needs (memory safety,
no prototype pollution, no deserialization exploits, no dynamic property
access, compile-time enforcement of isolation boundaries) are ones the
compiler provides and a garbage-collected runtime cannot.

## Design principles

1. Every channel gets its own credential. Compromise of one does not leak
   another.
2. Credentials are encrypted at rest and scoped by lifetime.
3. Every agent action is logged to an append-only ledger before execution.
4. Skills run in sandboxed execution environments by default, not as opt-in.
5. The user never configures security. Secure defaults are the only defaults.
6. Security boundaries are enforced by the type system where the code carries
   the type.

## 1. Channel isolation

**Threat (CWE-250):** a single static gateway token controlling all channels
means one compromised channel grants full gateway access.

Each connector runs as an isolated **adapter process** talking to the gateway
over a local duplex stream, authenticating with a per-adapter Ed25519
challenge-response.

```
[Telegram Adapter] --UDS+Cap'n Proto--> [Gateway Core] <--UDS+Cap'n Proto-- [Discord Adapter]
                                              |
                                        [Slack Adapter]
```

An adapter can deliver inbound messages for its channel, request outbound
sends for its channel, and read session state scoped to its channel. It cannot
invoke tools, read another channel's messages, or reach another channel's
credentials. Compromise one and the blast radius is one channel.

The adapter trait is generic over a zero-sized channel marker, so a
`SessionHandle<Telegram>` is a different type from a `SessionHandle<Discord>`
and the `Channel` trait is sealed within `wirken-ipc`. Within code that
carries `SessionHandle<C>`, cross-channel access is a compile error rather
than a runtime check.

**That API is not on the production message path.** Production frames carry a
`String` channel discriminator on the `AuthenticatedChannel` value resolved at
handshake, and a cross-channel frame is rejected at runtime with an
`adapter.channel_mismatch` audit event. The live control is the runtime match;
the compile-time guarantee covers the type-level API and its negative-test
scaffolding. See [enforcement-model.md](enforcement-model.md#channel-isolation).

**Transport.** Local-only duplex streams behind the `wirken_ipc::Stream`
trait: Unix domain sockets on Linux and macOS, named pipes on Windows. No TCP
and no HTTP between adapter and gateway, which removes the network attack
surface entirely. Peer identity is checked at accept time on both platforms
(`SO_PEERCRED` on unix, `GetNamedPipeClientProcessId` plus token-SID
extraction on windows).

**Process management.** The gateway spawns adapters with
`tokio::process::Command`; each is the same binary invoked as
`wirken adapter <channel>`. Dead adapters are detected by EOF plus heartbeat
timeout and restarted with exponential backoff.

**Tradeoff.** More processes than a monolith, at roughly 3-8MB each. A
personal gateway runs three to five adapters, not five hundred.

## 2. Credential lifecycle

**Threat (CWE-256):** plaintext credentials with no rotation or expiry; any
process with filesystem read can extract them.

All secrets are encrypted at rest under a **device key** derived from the OS
keychain: macOS Keychain via `security-framework`, Linux Secret Service over
D-Bus from a dedicated blocking thread to avoid a known tokio deadlock, and an
age-encrypted file with an Argon2id-derived passphrase as the headless
fallback. Windows uses the age-file backend.

Decrypted secrets are wrapped in `VaultSecret` over `SecretString`, which
implements neither `Display`, `Debug`, `Serialize` nor `Clone`. Logging,
serializing, printing or cloning a secret is a compile error, not a runtime
check someone can forget. The only access path returns a short-lived `&str`
that cannot outlive the wrapper, and memory is zeroed on drop.

```rust
pub struct VaultEntry {
    secret: VaultSecret,       // cannot be logged, serialized, or printed
    meta: CredentialMetadata,  // can be freely logged
}
```

**What this does not cover:** a caller who copies the `&str` into a new
`String`. That is deliberate. The API makes the safe path easy and the unsafe
path visible in review.

Each adapter opens the vault directly at startup through the same keychain and
retrieves its channel credentials; decrypted values are passed to the
adapter's constructor and never written to environment variables or command
lines. See [credentials.md](credentials.md).

## 3. Permissions

**Threat (OWASP T3):** without a granular model, authenticated agents have
unrestricted access to all tools, and session IDs get used as routing controls
rather than authorization boundaries.

A three-tier capability model, keyed on `(action_key, agent_id)`, with
first-use approval, expiry and revocation, plus capability-attenuated
sub-agents. Owned by
[permissions-and-identity.md](permissions-and-identity.md) and
[multi-agent.md](multi-agent.md#sub-agent-orchestration).

Each agent gets its own workspace directory, session store, permission set and
bound channels. Enforcement is runtime, not type-level: lookups key on the
agent id, session ids are prefixed by it, and the factory names each agent
before attaching a permission store.

## 4. Audit

**Threat (OWASP T8):** without a persistent trail, there is no way to detect,
investigate or respond. Logging only control-plane commands misses tool
invocations, credential access and file operations.

An append-only per-session hash chain in SQLite, written before each action
executes, with per-agent Ed25519 attestation over the chain head. Owned by
[audit-cli.md](audit-cli.md).

**Crash recovery.** Agents are stateless between turns. The `AgentFactory`
wakes each agent by replaying its session log. An incomplete tool round, an
`AssistantToolCalls` event with no matching `ToolResult`, is detected on wake
and surfaced as a failure: the harness never silently re-executes a
non-idempotent tool.

**Performance.** Legacy audit writes batch through an mpsc channel. Session
events are written synchronously per turn, one insert per event, with the
chain hash computed inline.

## 5. Skill execution

**Threat (OWASP T11):** skills running in-process with full OS privileges and
no sandbox.

Three execution models, because the skill ecosystem is not one thing.

**Markdown skills** are the majority: structured natural-language instructions
the LLM reads as system-prompt context, carried out with built-in tools. Zero
compilation, zero migration cost. What confines them is the tools they drive.

**Sandboxed shell.** The `exec` tool runs in a Docker container, or gVisor
when configured, which is what actually confines a skill that shells out to
`git`, `curl` or `jq`. Owned by
[sandbox-properties.md](sandbox-properties.md).

**Wasm skills** run in Wasmtime with a fuel limit, no filesystem and no
network. Owned by [skills.md](skills.md).

### Classifier failure direction

The tool classifier fails closed in both dimensions, and this is load-bearing
rather than incidental.

A tool name it cannot place resolves to `UnknownTool`, which is Tier 3, so an
unregistered tool cannot run ungated. The same name also records
`ReadSensitivity::Workspace`, the most restricting confidentiality label, so
an unregistered tool cannot read something sensitive and leave the session
looking clean to the egress proxy.

The second half looks wrong at a glance. Marking an unknown tool as having
read the operator's workspace is deliberately pessimistic, and trimming it as
too aggressive would remove the property that keeps the egress verdict honest
when the classifier is incomplete. Both defaults exist so that forgetting to
register a tool costs friction, never silent permission.

## 6. LLM integration

**Threat (CWE-312):** API keys in plaintext config and environment variables;
one key shared across all agents means one leak exposes everything.

All keys live in the vault, never in environment variables or config files.
Each agent has its own auth profile, so agent A can run `openai/gpt-4o` and
agent B `anthropic/claude-sonnet-4` with separate keys.

**Direct calls.** The agent's `LlmClient` calls providers over HTTPS with
`reqwest` and `rustls`; streaming uses `reqwest-eventsource`. Keys are
decrypted from the vault at startup and held in memory for the process
lifetime.

**Process boundary, current state.** The agent runs as a library inside the
gateway process. `crates/cli` pulls `wirken-agent` as a path dependency and
`run.rs` constructs `Agent` values via `AgentFactory::wake` and calls
`process_message` directly. There is no UDS between agent and gateway; **they
share an address space.** Channel adapters are separate processes; agents are
not. The in-memory provider keys are therefore held by the same process that
holds the vault unwrap key, the audit writer and the session log, so splitting
a proxy out today would not change the threat model, because the proxy and the
consumer would live in the same address space. The vault's encryption protects
keys at rest regardless, and the agent-process-compromise threat model only
activates once there is a process boundary between agent and gateway.

**Usage tracking.** Every call logs an `LlmRequest` / `LlmResponse` pair with
token counts, model ID, latency and cost estimate. Neither row carries prompt
or completion text: `LlmRequest` records hashes of the messages and tools
sent, which is what makes offline replay verifiable. Message bodies do reach
the chain, on the separate `UserMessage` and `AssistantMessage` rows.

Provider list and confidential-inference deployment:
[configuration.md](configuration.md#providerjson).

## 7. Rate limiting

**Threat (CWE-307):** exempting localhost when the gateway binds to localhost
by default leaves the primary attack surface unprotected.

No loopback exemption. Auth: 5 failed attempts per 60 seconds per source, then
a 10-minute lockout, applied to 127.0.0.1 like anything else. Control plane:
10 mutations per minute per client. Both via `governor`, GCRA over lock-free
atomic state, one limiter per scope.

There is no per-provider LLM rate limiter. Outbound model calls are bounded by
the per-turn round cap, the per-agent spend budget
([cost-monitoring.md](cost-monitoring.md)), and the provider's own limits.

The CLI is not a network client and holds no session token. It runs at the
operator's UID, unlocks the vault, and reaches the gateway over local sockets
whose 0o600 permissions are the boundary.

## 8. Sessions

**Threat (CWE-613):** sessions that persist indefinitely, and session IDs used
as routing controls rather than security boundaries.

Sessions expire after 24 hours of inactivity, configurable. The session store
holds metadata only: id, channel, conversation id, timestamps, message count,
expiry flag. Conversation ids are UUIDv4. Creation and expiry are logged.

Transcripts are durably logged as typed session events in `audit.db`, and the
`AgentFactory` reconstructs any session from its log on wake.

## 9. IPC protocol

| Protocol | Zero-copy | Schema evolution | Traversal limits |
|----------|-----------|------------------|------------------|
| Cap'n Proto | Yes | Yes, additive fields | Yes, built-in |
| MessagePack | No | Weak, field ordering | No |
| FlatBuffers | Yes | Yes | No built-in |

**Cap'n Proto**, for four reasons. Zero-copy deserialization: readers traverse
binary data in place, which for high-frequency IPC eliminates per-message
allocation. Built-in traversal limits: a malformed message cannot cause
unbounded memory or CPU during deserialization, which matters at a boundary
where adapter processes are semi-trusted. Additive schema evolution, so
adapters and gateway upgrade independently. And lifetime-parameterized reader
types, so the compiler prevents use of deserialized data after its buffer is
freed.

The `.capnp` schema files are the canonical IPC contract, compiled at build
time, so a structure mismatch is caught by `cargo build` rather than at
runtime.

## 10. Technology stack

Versions are pinned in the workspace `Cargo.toml` and are not restated here.

| Component | Crate | Why |
|-----------|-------|-----|
| Async runtime | `tokio` | De facto standard; timers, IO, process, signal |
| HTTP client | `reqwest` | Built on hyper, UDS support, SSE via `reqwest-eventsource` |
| SQLite | `rusqlite` | `bundled` compiles SQLite from source, no system dependency |
| macOS keychain | `security-framework` | Direct bindings to Security.framework |
| Linux keychain | `secret-service` | D-Bus to GNOME Keyring or KDE Wallet |
| Windows Win32 | `windows-sys` | Named-pipe peer-SID extraction for the orchestrator-push boundary |
| AEAD | `chacha20poly1305` | RustCrypto XChaCha20-Poly1305, pure Rust, audited |
| Secret handling | `secrecy` + `zeroize` | Prevents accidental logging or serialization; zeroes on drop |
| Ed25519 | `ed25519-dalek` | Pure Rust, audited by Quarkslab |
| Password hashing | `argon2` | Argon2id for the age-file passphrase |
| Hashing | `sha2` | Audit hash chain |
| IPC | `capnp` | Zero-copy, traversal limits, schema evolution |
| Wasm | `wasmtime` | WASI preview 1, fuel metering, resource limits |
| Containers | `bollard` | Async Docker and gVisor integration |
| CLI | `clap` | Derive and builder APIs |
| Prompts | `dialoguer` | Setup wizard |
| Rate limiting | `governor` | GCRA, lock-free, zero-alloc hot path |
| Logging | `tracing` | Span-based, async-aware |
| Channel SDKs | `teloxide`, `serenity`, `slack-morphism` | Per-platform bot APIs |

**TLS via `rustls`.** OpenSSL is present as a transitive dependency of some
channel SDKs, configured `vendored` so it compiles from source: no system
headers at build time and no dynamic linking against the host OpenSSL.

**Single static binary.** Gateway, adapters, MCP proxy and CLI compile to one
binary with subcommands; one `cargo build --release` produces everything.

## Threat model summary

| Threat | CWE/OWASP | Mitigation |
|--------|-----------|------------|
| Single token controls all channels | CWE-250 | Per-adapter Ed25519 identity, per-channel credentials |
| Plaintext credentials on disk | CWE-256, CWE-312 | XChaCha20-Poly1305 vault, OS keychain for the device key |
| No per-channel isolation | CWE-653 | Separate adapter processes |
| Excessive agent privileges | OWASP T3 | Three-tier model with expiring approvals |
| Unsandboxed code execution | OWASP T11 | Docker and Wasm sandboxes, workspace confinement |
| No audit trail | OWASP T8 | Append-only hash-chained log, SIEM forwarding |
| Localhost rate limit exemption | CWE-307 | Uniform limiting, no loopback exemption |
| No session expiry | CWE-613 | 24h inactivity expiry |
| Runtime memory unsafety | CWE-119 | Rust |

Full mappings and the gap column: [security-properties.md](security-properties.md).
