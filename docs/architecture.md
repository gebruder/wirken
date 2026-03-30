# Architecture: Secure Personal AI Gateway

Codename: **Wirken**

A secure, model-agnostic AI agent gateway. Multi-channel personal AI assistant with skills, tool execution, and local-first operation.

Wirken — from the Old English *wyrcan*, to work, to make, to build. The thing that does the work.

Written in Rust. Not because Rust is fashionable, but because the security properties this architecture requires — memory safety, no prototype pollution, no deserialization exploits, no dynamic property access, compile-time enforcement of isolation boundaries — are properties that Rust provides at compile time and garbage-collected runtimes cannot.

---

## Design Principles

1. Every channel gets its own credential. Compromise of one channel does not leak another.
2. Credentials are encrypted at rest and scoped by lifetime.
3. Every agent action is logged to an append-only audit ledger before execution.
4. Skills run in sandboxed execution environments by default, not as opt-in.
5. The user never configures security. Secure defaults are the only defaults.
6. Security boundaries are enforced by the type system at compile time, not by runtime checks.

---

## 1. Channel Isolation Model

**Threat (CWE-250, Execution with Unnecessary Privileges):** A single static gateway token controlling all channels means one compromised channel grants full gateway access.

**Fix:**

Each channel connector runs as an isolated **adapter process** communicating with the gateway over a Unix domain socket with a per-adapter mTLS identity.

```
[Telegram Adapter] --UDS+Cap'n Proto--> [Gateway Core] <--UDS+Cap'n Proto-- [Discord Adapter]
                                              |
                                        [Slack Adapter]
```

- Each adapter has a unique Ed25519 keypair generated at setup.
- The gateway maintains an adapter registry mapping adapter public keys to channel IDs and permission sets.
- An adapter can only: (a) deliver inbound messages for its channel, (b) request outbound sends for its channel, (c) read session state scoped to its channel's sessions.
- Adapters cannot invoke tools, read other channels' messages, or access credentials for other channels.
- If an adapter process is compromised, the blast radius is one channel.

**Compile-time isolation via Rust's type system:**

The adapter trait is generic over a channel marker type. The marker is a zero-sized type (ZST) that carries no runtime cost but makes cross-channel access a compile error:

```rust
/// Zero-sized marker. Each channel defines its own.
pub struct Telegram;
pub struct Discord;

/// A session handle scoped to a specific channel.
/// TelegramAdapter holds SessionHandle<Telegram>.
/// It cannot construct or convert to SessionHandle<Discord>.
pub struct SessionHandle<C: Channel> {
    id: SessionId,
    _channel: PhantomData<C>,
}

/// The adapter trait is parameterized by channel.
/// An impl for Telegram cannot call methods that require Discord.
pub trait Adapter<C: Channel> {
    fn deliver_inbound(&self, msg: InboundMessage<C>) -> Result<()>;
    fn request_outbound(&self, msg: OutboundMessage<C>) -> Result<()>;
    fn read_session(&self, handle: &SessionHandle<C>) -> Result<SessionView>;
}

/// Gateway dispatch: the match arm for a Telegram IPC frame
/// can only produce InboundMessage<Telegram>. The compiler
/// rejects any attempt to route it to a Discord session.
```

This is not a runtime permission check that can be bypassed — it is a type constraint that the compiler enforces. A Telegram adapter binary physically cannot construct a `SessionHandle<Discord>` because the type parameter is sealed.

**IPC transport:** Unix domain sockets via `tokio::net::UnixStream` (tokio 1.50). No TCP, no HTTP between adapter and gateway — eliminates network attack surface.

**Process management:** Gateway spawns adapters via `tokio::process::Command`. Each adapter is a separate Rust binary (compiled from the same workspace). Dead adapters detected by UDS EOF + heartbeat timeout, restarted with exponential backoff.

**Tradeoff:** More processes than a monolith. Acceptable: a personal gateway runs 3-5 adapters, not 500. Memory overhead ~3-8MB per adapter.

---

## 2. Credential Lifecycle

**Threat (CWE-256, Plaintext Storage of a Password):** Credentials stored in plaintext config files with no rotation or expiry. Any process with filesystem read access can extract them.

**Fix:**

All secrets encrypted at rest using a **device key** derived from the OS keychain.

- **macOS:** `security-framework` 3.7 (Keychain Services bindings). Device key stored in Keychain via `SecItemAdd`/`SecItemCopyMatching`, never on filesystem.
- **Linux:** `secret-service` 5.1 (D-Bus to GNOME Keyring / KDE Wallet). Called from a dedicated blocking thread to avoid tokio deadlocks (known `secret-service` + tokio issue). Fallback for headless: `age`-encrypted file with passphrase derived via `argon2` 0.5 (Argon2id, 64MB memory cost, 3 iterations).
- **Credential store:** SQLite database at `~/.wirken/vault.db` via `rusqlite` 0.39 (bundled feature). All secret values encrypted with XChaCha20-Poly1305 via `chacha20poly1305` 0.10 keyed from the device key.
- **Per-credential metadata:** `created_at`, `expires_at`, `last_used_at`, `rotation_due_at`.
- **Rotation policy:** API keys flagged for rotation every 90 days. Gateway emits a warning 7 days before expiry. CLI command: `wirken credentials rotate <channel>`.
- **No plaintext export.** Credentials can be re-entered but never displayed after initial storage.

**Compile-time secret safety via `secrecy` 0.10 + `zeroize` 1.8:**

Decrypted secrets are wrapped in `SecretString` (from the `secrecy` crate), which:
- Does **not** implement `Display`, `Debug`, `Serialize`, or `Clone`.
- Implements `Zeroize` + `ZeroizeOnDrop` — memory is overwritten when the value goes out of scope.
- The only access path is `.expose_secret()`, which returns a `&str` reference that cannot outlive the `SecretString`.

This makes it a **compile error** to accidentally log, serialize, print, or persist a decrypted secret. The Rust compiler rejects `tracing::info!("key: {}", api_key)` because `SecretString` does not implement `Display`. There is no runtime check to forget — the type system prevents the mistake.

```rust
use secrecy::{ExposeSecret, SecretString};

pub struct VaultEntry {
    secret: SecretString,      // Cannot be logged, serialized, or printed
    meta: CredentialMetadata,  // Can be freely logged
}

impl VaultEntry {
    /// The only way to use the secret. Returns a short-lived reference.
    /// Caller must use it immediately (e.g., set an HTTP header) and drop.
    pub fn expose(&self) -> &str {
        self.secret.expose_secret()
    }
}
```

**Adapter credential access:** Each adapter receives its channel credentials via a one-time file descriptor pass at process spawn time (`SCM_RIGHTS` on Linux, inherited FD on macOS). The FD contains the encrypted credential; the adapter decrypts it in-memory using a session key derived during the mTLS handshake. Credentials never written to environment variables or command-line arguments.

**Tradeoff:** Requires OS keychain access. Headless servers without a desktop session need the age-file fallback with a passphrase. Documented in onboarding.

---

## 3. Agent Permission Model

**Threat (OWASP AG01, Excessive Agency):** Without a granular permission model, authenticated agents have unrestricted access to all tools and resources. Session IDs used as routing controls rather than authorization boundaries.

**Fix:**

Agents operate under a **capability-based permission model** with three tiers:

**Tier 1 — Always allowed (no approval):**
- Read/write files within agent workspace
- Converse on bound channels
- Web search (read-only)

**Tier 2 — First-use approval, then remembered:**
- Shell command execution (by command prefix pattern)
- File access outside workspace (by path glob)
- Sending messages to contacts not in the current conversation

**Tier 3 — Always prompt:**
- Destructive file operations (rm, overwrite outside workspace)
- Network requests to new domains
- Credential access
- Cron job creation
- Skill installation

Approvals stored in `~/.wirken/permissions.db` (SQLite, `rusqlite` 0.39) with `approved_at`, `approved_by` (channel the approval came from), and `expires_at` (default 30 days, re-promptable).

**Multi-agent isolation:** Each agent gets its own workspace directory, session store, permission set, and bound channels. Agent A cannot invoke Agent B's tools or read Agent B's sessions. The gateway enforces this at the IPC boundary using the same channel-typed generic pattern as adapters — agent handles are parameterized by agent ID at the type level.

---

## 4. Audit System

**Threat (OWASP AG09, Insufficient Logging and Monitoring):** Without a persistent audit trail for agent actions, there is no way to detect, investigate, or respond to incidents. Logging only control-plane commands misses tool invocations, credential access, and file operations.

**Fix:**

Append-only structured audit log.

**Implementation:**
- SQLite WAL-mode database at `~/.wirken/audit.db` via `rusqlite` 0.39 (bundled).
- Every gateway action (tool invocation, message send/receive, credential access, permission grant, config change, adapter connect/disconnect) produces an audit event before the action executes.
- Schema: `(id INTEGER PRIMARY KEY, ts TEXT, actor TEXT, action TEXT, target TEXT, channel TEXT, session TEXT, detail JSON, hash TEXT)`.
- Each row includes a SHA-256 hash (`sha2` 0.10) of `(previous_hash || ts || actor || action || detail)` creating a hash chain. Tampering with the log breaks the chain.
- Retention: 90 days default, configurable. Pruning preserves the hash chain by keeping a checkpoint hash.

**Performance:** Audit writes go through a `tokio::sync::mpsc` channel. A dedicated task flushes to SQLite in batches (every 50ms or 100 events, whichever comes first). Events are held in memory with monotonic sequence numbers. Crash recovery: un-flushed events are lost (acceptable — the alternative is fsync on every event, which is 5-10ms each). Hash chain computed at flush time over the batch.

**CLI access:**
```bash
wirken audit log                    # last 50 events
wirken audit log --action exec      # filter by action type
wirken audit log --channel telegram  # filter by channel
wirken audit verify                 # verify hash chain integrity
```

---

## 5. Skill Execution

**Threat (OWASP AG02, Unexpected Code Execution):** Skills running in-process with full OS privileges and no sandbox. A malicious or compromised skill has complete access to the host filesystem, network, and credentials.

**Fix:**

Three skill categories, each with a different execution model:

### Category 1: Markdown skills (the majority — drop in, they work)

Most agent gateway skills are not code. They are `SKILL.md` files — structured natural-language instructions with YAML frontmatter that the LLM reads as system prompt context. The agent interprets the instructions at runtime and uses built-in tools (exec, web search, file read/write) to carry them out.

Examples:
- `weather/SKILL.md`: "Use `curl wttr.in/{city}` for current weather." Requires: `curl` binary on host.
- `github/SKILL.md`: "Use `gh` CLI for issues, PRs, CI runs." Requires: `gh` binary on host.
- `tmux/SKILL.md`: "Send keystrokes to tmux sessions, scrape pane output." Requires: `tmux` binary on host.

These skills have zero compilation and zero migration cost. Wirken's agent runtime reads `SKILL.md` files from a skill directory and injects them into the system prompt.

**Frontmatter contract to match:**
```yaml
---
name: weather
description: "Get current weather via wttr.in"
metadata: { "openclaw": { "emoji": "☔", "requires": { "bins": ["curl"] } } }
---
```

Wirken reads the `name`, `description`, and `requires.bins` fields. The emoji and other metadata are optional. The markdown body is injected verbatim into the agent's system prompt when the skill is active.

### Category 2: Code skills (minority — gVisor container)

A small number of skills on ClawHub are actual JavaScript/TypeScript code that executes outside the LLM — custom tool implementations that do things the built-in tools can't. These are the skills that shell out, run native tools, make HTTP calls, or do filesystem operations.

These run in gVisor containers:

- Runtime: gVisor (`runsc`) with OCI images via `bollard` 0.20 (Docker API client).
- Container includes Node.js for JS/TS skill execution, plus common tools (curl, git, jq, python3).
- Skill directory mounted read-only, workspace mounted read-write. No host filesystem access outside these mounts.
- **Network:** Denied by default. Skills that declare `"network": true` in `skill.toml` get outbound-only network with DNS, logged to audit.
- **Resource limits:** 512MB memory, 30-second timeout, no capability escalation.
- **Cold start:** ~200ms from pre-warmed pool (3 containers at gateway start). ~800ms cold.
- macOS fallback: Docker Desktop with seccomp-bpf profiles (gVisor is Linux-only).
- Skills communicate with the gateway via stdin/stdout JSON-RPC.

### Category 3: Wasm skills (new skills, Wirken-native)

For skills written against Wirken's SDK in any language that compiles to WebAssembly. This is the long-term path — 5ms startup, deterministic resource limits, no container dependency.

- Runtime: `wasmtime` 43.0 with WASI preview 2 (component model).
- **CPU limiting:** Fuel metering via `Store::set_fuel()`. Default budget: 10 billion fuel units (~10 seconds of computation). Skills that exhaust fuel are terminated.
- **Memory limiting:** `ResourceLimiter` trait caps memory at 256MB and table elements at 10,000.
- **Filesystem:** WASI preopened directories grant read-only access to the skill's own directory and read-write access to a per-skill temp directory.
- **Network:** Denied by default. Skills that declare `"network": true` in `skill.toml` get outbound-only TCP/UDP via WASI sockets, logged to audit.
- **Startup:** ~5ms cold start for a precompiled module (`Module::deserialize`). Cached in `~/.wirken/cache/`.
- Skills communicate with the gateway via WASI stdin/stdout using JSON-RPC.
- **Gateway-proxied capabilities (post-MVP):** Wasm skills can request filesystem and network access through the JSON-RPC interface. The gateway serves these requests with per-request permission checks, keeping the skill sandboxed while making it useful.

### Path selection

```toml
# skill.toml — only needed for code skills and wasm skills
[runtime]
type = "container" # gVisor/Docker for JS/TS code skills
# type = "wasm"    # Wasmtime for Rust/Go/compiled skills

[permissions]
network = false
```

Skills with only a `SKILL.md` and no `skill.toml` are markdown skills. No sandbox needed — the LLM reads the instructions and uses the agent's existing tools, which are already subject to the permission model (Section 3).

**Signing:**
- Skills from the official registry are signed with Ed25519 (`ed25519-dalek` 2.2). The gateway verifies signatures before loading.
- Local/workspace skills are unsigned but sandboxed. The user sees a one-time "trust this skill?" prompt on first load.
- No unsigned skill can request network access without explicit approval.

**Why three categories:** Because the skill ecosystem is not one thing. The majority of skills are markdown (system prompt instructions) that need no sandbox, no compilation, and no migration. Some are code that needs containerization. And Wasm provides a deterministic, fast, cross-platform alternative. The three-category model matches these realities.

---

## 6. LLM Integration

**Threat (CWE-312, Cleartext Storage of Sensitive Information):** API keys in plaintext config files and environment variables. A single key shared across all agents and channels means one leak exposes everything.

**Fix:**

**Key storage:** All API keys in the encrypted credential vault (Section 2). Never in environment variables, never in config files.

**Per-agent scoping:** Each agent has its own LLM auth profile. Agent A can use `openai/gpt-5.4` and Agent B can use `anthropic/claude-4.6`, each with separate API keys. The gateway proxies LLM requests on behalf of agents — agents never see raw API keys.

**LLM proxy architecture:**
```
[Agent Runtime] --Cap'n Proto/UDS--> [Gateway LLM Proxy] --HTTPS/SSE--> [OpenAI/Anthropic/etc]
```

The agent sends a structured completion request to the gateway via IPC. The gateway resolves the provider, decrypts the API key from the vault (via `SecretString::expose_secret()` — key exists as cleartext only in the HTTP Authorization header buffer), opens a streaming connection to the provider, and pipes the response back.

**SSE streaming without buffering:**

HTTP client: `reqwest` 0.13 + `reqwest-eventsource` 0.8. Async runtime: `tokio` 1.50.

```rust
// Streaming SSE events from LLM provider back to agent over IPC.
// No buffering — each SSE event is forwarded as it arrives.
let mut es = EventSource::new(reqwest_client.post(url).headers(headers).body(body));

while let Some(event) = es.next().await {
    match event {
        Ok(Event::Message(msg)) => {
            // Forward immediately to agent via IPC.
            // Backpressure: if the IPC write blocks (agent slow),
            // tokio's cooperative scheduling suspends this task.
            // The TCP window to the LLM provider shrinks naturally.
            // No explicit buffering or flow control needed.
            ipc_tx.send(LlmChunk::Data(msg.data)).await?;
        }
        Ok(Event::Open) => {},
        Err(e) => {
            ipc_tx.send(LlmChunk::Error(e.to_string())).await?;
            break;
        }
    }
}

// Audit: log metadata at stream completion, not during streaming
audit.log(LlmCallCompleted { model, tokens_in, tokens_out, duration }).await;
```

Backpressure is handled by tokio's cooperative task scheduling + TCP window management. If the agent is slow to consume IPC messages, the `ipc_tx.send().await` suspends, which stops reading from the SSE stream, which causes the TCP receive buffer to fill, which causes the sender (LLM provider) to slow down. No explicit backpressure mechanism needed — the async runtime and TCP stack handle it.

**Supported providers:**
- OpenAI (API key, Bearer token)
- Anthropic (API key, x-api-key header)
- Google Gemini (API key via `x-goog-api-key` header, generateContent API)
- AWS Bedrock (SigV4 signed requests, Converse API)
- Ollama (local, no key needed)
- Any OpenAI-compatible endpoint (custom URL + key)

**Usage tracking:** Every LLM call logged to audit with token counts, model ID, and cost estimate. No prompt content in audit log (privacy). Monthly usage summary via `wirken usage`.

---

## 7. Rate Limiting

**Threat (CWE-307, Improper Restriction of Excessive Authentication Attempts):** Exempting localhost from rate limiting when the gateway binds to localhost by default leaves the primary attack surface unprotected against brute-force attempts.

**Fix:**

No loopback exemption. Rate limiting applies uniformly.

- **Auth rate limit:** 5 failed attempts per 60 seconds per source, then 10-minute lockout. Applies to all sources including 127.0.0.1.
- **Control plane write limit:** 10 mutations per minute per client.
- **LLM proxy limit:** Configurable per-provider (default: 60 requests/minute for OpenAI, matches their tier-1 rate limit).
- **Implementation:** `governor` 0.10 (GCRA algorithm, lock-free 64-bit atomic state). Thread-safe, zero-allocation on the hot path. One `RateLimiter` per scope (auth, control-plane, per-provider LLM).

**CLI sessions:** Authenticated via the device key (Section 2), not a bearer token. The CLI unlocks the vault, proves device identity, and gets a short-lived session token (1 hour). No static token to brute-force.

---

## 8. Session Management

**Threat (CWE-613, Insufficient Session Expiration):** Sessions that persist indefinitely without expiry or inactivity timeout. Session IDs used as routing controls rather than security boundaries.

**Fix:**

- Sessions expire after 24 hours of inactivity (configurable).
- Session tokens are JWTs signed with a gateway-local Ed25519 key (`jsonwebtoken` 10.3 with `rust_crypto` backend), with `exp` claim.
- Session creation logged to audit.
- Session content (transcripts) encrypted at rest in SQLite with per-session derived keys.
- CLI command: `wirken sessions list`, `wirken sessions close <id>`.

---

## 9. IPC Protocol

**Evaluation:**

| Protocol | Zero-copy | Schema evolution | Traversal limits | Rust maturity |
|----------|-----------|-----------------|-------------------|---------------|
| Cap'n Proto | Yes | Yes (additive fields) | Yes (built-in) | `capnp` 0.25, 10M downloads |
| MessagePack | No (deserialization copies) | Weak (field ordering) | No | `rmp-serde` mature |
| FlatBuffers | Yes | Yes | No built-in | `flatbuffers` less mature |

**Decision: Cap'n Proto** via `capnp` 0.25.

Reasons:
1. **Zero-copy deserialization.** Reader types traverse binary data in-place without allocation. For high-frequency IPC (streaming LLM tokens), this eliminates per-message allocation entirely.
2. **Traversal limits.** Built-in protection against amplification attacks — a malformed message cannot cause unbounded memory or CPU consumption during deserialization. Critical for the adapter→gateway boundary where adapter processes are semi-trusted.
3. **Schema evolution.** New fields can be added to messages without breaking existing adapters. Adapters and gateway can be upgraded independently.
4. **Lifetime-parameterized API.** The Rust bindings use lifetime parameters on Reader types, so the compiler ensures you don't use deserialized data after the buffer is freed.

The `.capnp` schema files become the canonical IPC contract. Adapters and the gateway compile against the same schema.

---

## 10. Onboarding

**Two commands to a running gateway.**

```bash
curl -fsSL https://wirken.dev/install.sh | sh
wirken setup
```

The install script downloads a precompiled binary for the user's platform (Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64). Single static binary, no runtime dependencies. No npm.

`wirken setup` is a single interactive flow powered by `dialoguer` 0.12:

1. **"Pick your AI"** — select provider (OpenAI / Anthropic / Google Gemini / AWS Bedrock / Ollama / custom). Enter API key (or AWS credentials for Bedrock). Key immediately encrypted into vault.
2. **"Pick your channels"** — select from Telegram / Discord / Slack / Microsoft Teams / Matrix. Enter bot token per channel. Each token encrypted separately.
3. **Done.** Gateway starts as a system service. User gets a message on their chosen channel: "I'm ready. Send me a message."

**What the user never has to see or decide:**
- Credential encryption (automatic via OS keychain)
- Channel isolation (automatic — separate adapter processes)
- Permission model tier assignments (sensible defaults)
- Audit logging (always on)
- Skill sandboxing (always on)
- Rate limiting (always on, no loopback exemption)
- Session expiry (default 24h)
- Wasm/container runtime details (managed internally)

**What the user can customize later:**
- Add more channels: `wirken channel add matrix`
- Add more agents: `wirken agent add work --model anthropic/claude-4.6 --channels slack`
- Adjust permissions: `wirken permissions list`, `wirken permissions revoke`
- Review audit: `wirken audit log`

---

## 11. Technology Stack

| Component | Crate | Version | Why |
|-----------|-------|---------|-----|
| Async runtime | `tokio` | 1.50 | De facto standard. Full-featured (timers, IO, process, signal). |
| HTTP client | `reqwest` | 0.13 | Built on hyper. UDS support. SSE via `reqwest-eventsource` 0.8. |
| SSE streaming | `reqwest-eventsource` | 0.8 | Async SSE event iterator over reqwest responses. |
| SQLite | `rusqlite` | 0.39 | `bundled` feature compiles SQLite from source. No system dependency. |
| macOS Keychain | `security-framework` | 3.7 | Direct bindings to Apple Security.framework. |
| Linux keychain | `secret-service` | 5.1 | D-Bus to GNOME Keyring / KDE Wallet. |
| AEAD encryption | `chacha20poly1305` | 0.10 | RustCrypto. XChaCha20-Poly1305. Pure Rust, audited. |
| Secret management | `secrecy` | 0.10 | Prevents accidental logging/serialization of secrets. |
| Memory zeroing | `zeroize` | 1.8 | Zeroes secret memory on drop. |
| Ed25519 signatures | `ed25519-dalek` | 2.2 | Pure Rust. Audited by Quarkslab. |
| Password hashing | `argon2` | 0.5 | Argon2id for age-file passphrase derivation. |
| SHA-256 | `sha2` | 0.10 | Hash chain for audit log. |
| IPC serialization | `capnp` | 0.25 | Zero-copy, traversal limits, schema evolution. |
| Wasm sandbox | `wasmtime` | 43.0 | WASI preview 2. Fuel metering. Resource limits. |
| Container API | `bollard` | 0.20 | Async Docker/gVisor integration for native-binary skills. |
| CLI parser | `clap` | 4.6 | Derive + builder APIs. |
| Interactive prompts | `dialoguer` | 0.12 | Setup wizard (Select, Input, Password, Confirm). |
| Rate limiting | `governor` | 0.10 | GCRA, lock-free atomics, zero-alloc hot path. |
| Structured logging | `tracing` | 0.1 | Span-based, async-aware. Subscribers via `tracing-subscriber` 0.3. |
| JWT | `jsonwebtoken` | 10.3 | Session tokens. `rust_crypto` backend (no OpenSSL dependency). |
| Telegram Bot API | `teloxide` | 0.17 | Full Bot API v9.1. Long polling + webhooks. Media support. |
| Discord Bot API | `serenity` | 0.12 | Gateway + REST. Guilds, DMs, threads, slash commands. |
| Slack API | `slack-morphism` | 2.19 | Socket Mode + Events API. Block Kit typed models. |
| Serialization | `serde` / `serde_json` | 1.x | JSON for config, skill manifest, LLM payloads. |

**Zero OpenSSL dependency.** TLS via `rustls` (pulled in by reqwest with `rustls-tls` feature). The entire binary links against pure-Rust crypto. No system OpenSSL version mismatches, no dynamic linking surprises.

**Single static binary.** The gateway, all built-in adapters, and the CLI compile to one binary with subcommands. Adapter processes are the same binary invoked with `wirken adapter telegram` etc. — a single `cargo build --release` produces everything.

---

## Threat Model Summary

| Threat | CWE/OWASP | Mitigation |
|--------|-----------|------------|
| Single token controls all channels | CWE-250 | Per-adapter Ed25519 identity, per-channel credentials |
| Plaintext credentials on disk | CWE-256, CWE-312 | XChaCha20-Poly1305 vault, OS keychain for master key |
| No per-channel isolation | CWE-653 | Separate adapter processes with compile-time type-safe scoping |
| Excessive agent privileges | OWASP AG01 | Three-tier permission model with expiring approvals |
| Unsandboxed code execution | OWASP AG02 | Docker sandbox, Wasm sandbox (Wasmtime), workspace confinement |
| No audit trail | OWASP AG09 | Append-only hash-chained audit log, SIEM forwarding |
| Localhost rate limit exemption | CWE-307 | Uniform rate limiting, no loopback exemption |
| No session expiry | CWE-613 | JWT sessions with 24h inactivity expiry |
| Runtime memory unsafety | CWE-119 | Rust: memory safety at compile time |
