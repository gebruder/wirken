# Enforcement Model: Compile-Time vs. Runtime

Wirken's security guarantees split into two categories: **compile-time invariants** enforced by Rust's type system (cannot be bypassed without recompiling the binary) and **runtime policies** configurable by operators (can be changed without rebuilding). This distinction matters for long-running agents: structural safety must never be compromised, while operational policies must be tunable without downtime.

---

## Compile-Time Guarantees

These properties are enforced by the Rust compiler. They cannot be bypassed by configuration, user input, or runtime state. Violating them requires modifying source code and recompiling.

### Channel Isolation

**Crate:** `wirken-ipc` | **File:** `crates/ipc/src/channel.rs`

Each channel adapter is scoped to a zero-sized type marker via `PhantomData<C>`. Session handles are parameterized by channel type:

```rust
pub struct SessionHandle<C: Channel> {
    id: SessionId,
    _channel: PhantomData<C>,
}
```

Channel markers are zero-sized structs (`Telegram`, `Discord`, `Slack`, `Matrix`, `Teams`) that implement the sealed `Channel` trait. The trait is defined with `Send + Sync + 'static` bounds and can only be implemented within the `wirken-ipc` crate.

**What the compiler prevents:**
- A Telegram adapter cannot construct `SessionHandle<Discord>` -- the type parameter is wrong.
- A function accepting `SessionHandle<Telegram>` cannot be called with `SessionHandle<Discord>`.
- Cross-channel routing mistakes in code that uses `SessionHandle<C>` are caught at compile time.

**Status of the production message path:** The `SessionHandle<C: Channel>` API and its negative-test scaffolding (regression-tested in `crates/ipc/src/tests.rs:20-30`) exist at the type-system level but are not yet threaded through the production gateway routing path. Production frames carry a `String`-typed channel discriminator on the `AuthenticatedChannel` value resolved at handshake time, and cross-channel mismatch is rejected at runtime via the `adapter.channel_mismatch` audit event rather than at compile time. The phantom-type rollout that retires the `String` discriminator is tracked as I-W-1 in the audit deferred list.

**What this does NOT cover:** The runtime decision of which agent handles which channel. That is a routing policy (see Runtime section).

### Credential Leak Prevention

**Crate:** `wirken-vault` | **File:** `crates/vault/src/secret.rs`

Decrypted secrets are wrapped in `VaultSecret`, which wraps `SecretString` from the `secrecy` 0.10 crate:

```rust
pub struct VaultSecret {
    inner: SecretString,
}
```

`VaultSecret` intentionally does **not** implement:

| Missing Trait | Compile-Time Effect |
|---|---|
| `Display` | `println!("{}", secret)` is a compile error |
| `Debug` | `tracing::info!("{:?}", secret)` is a compile error |
| `Clone` | Cannot make copies that escape the intended scope |
| `Serialize` | Cannot accidentally write to JSON, logs, or files |

The only access path is `expose() -> &str`, which returns a short-lived borrow. The reference cannot outlive the `VaultSecret`. On drop, `zeroize` 1.8 overwrites the memory.

**What the compiler prevents:**
- Logging a secret via `tracing`, `println!`, or `format!`.
- Serializing a secret into a JSON response, config file, or audit event.
- Cloning a secret into a long-lived cache or collection.
- Passing a secret to any function that requires `Display`, `Debug`, or `Serialize`.

**What this does NOT cover:** A caller who captures the `&str` from `expose()` and copies it into a new `String`. This is deliberate -- the API makes the safe path easy and the unsafe path visible in code review.

### Adapter Authentication Identity

**Crate:** `wirken-ipc` | **File:** `crates/ipc/src/auth.rs`

Each adapter holds an `AdapterIdentity` containing an Ed25519 `SigningKey`. The keypair is generated at adapter registration and verified during the IPC handshake via challenge-response:

1. Gateway sends a 32-byte random nonce.
2. Adapter signs the nonce with its private key.
3. Gateway verifies the signature against the registered public key.

**What the compiler prevents:**
- The handshake protocol is encoded in the type signatures of `perform_adapter_handshake` and `perform_gateway_handshake`. A caller cannot skip the challenge step -- the function requires both reader and writer, and the protocol is sequential.
- `SigningKey` does not implement `Serialize` or `Display`, preventing accidental export of private keys.

**What this does NOT cover:** The registry of which public keys are trusted. That is runtime state in `AdapterRegistry` (SQLite).

### IPC Frame Safety

**Crate:** `wirken-ipc` | **File:** `crates/ipc/src/transport.rs`

`FrameReader` enforces a 16MB frame size limit and passes Cap'n Proto reader options with a 512MB word traversal limit and 64-level nesting limit. These are compile-time constants in the transport layer:

```rust
// Frame too large -- rejected before allocation
if length > 16 * 1024 * 1024 {
    return Err(IpcError::FrameTooLarge(length));
}
```

Cap'n Proto's generated reader types are lifetime-parameterized (`Reader<'a>`), ensuring deserialized data cannot outlive its buffer. The schema is compiled from `.capnp` files at build time -- message structure mismatches are caught by `cargo build`, not at runtime.

---

## Runtime Guarantees

These properties are enforced by configuration, runtime checks, and operational policy. They can be changed by operators without recompiling.

### Skill Loading

**Crate:** `wirken-agent` | **Files:** `crates/agent/src/skill.rs`, `crates/agent/src/wasm_sandbox.rs`

Skills are loaded from the filesystem at gateway startup:
- `SkillLoader::load_dir()` scans `~/.wirken/skills/` and per-agent skill directories.
- `Agent::load_skills()` rebuilds the system prompt with available skills.
- Wasm skills are compiled from `.wasm` files via `wasmtime` 43.0.

**Live update:** Add or remove SKILL.md files from the skills directory. The agent picks up changes on next `load_skills()` call (currently requires gateway restart; no filesystem watcher yet).

### Permission Tiers

**Crate:** `wirken-gateway` | **File:** `crates/gateway/src/permissions.rs`

The three-tier permission model is backed by SQLite:

| Tier | Behavior | Example Actions |
|---|---|---|
| Tier 1 | Always allowed | Workspace file access, web search |
| Tier 2 | First-use approval, 30-day expiry | A curated allowlist of shell-inspection verbs (ls / cat / grep / stat / pwd / whoami / ...), external file access. See AG01 in [security-properties.md](security-properties.md) for the canonical list. There is no documented Tier-2 exec escape hatch -- shell wrappers, language interpreters with `-c`/`-e` eval, and build/deploy tools default to Tier 3. |
| Tier 3 | Always prompt | Credential access, destructive ops, cron creation, every shell verb outside the Tier 2 inspection-verb allowlist |

**Live update:** `PermissionStore::approve()` and `PermissionStore::revoke()` take effect immediately -- they are SQLite writes checked on every permission query. No restart required.

```bash
wirken permissions revoke shell:curl --agent default  # immediate effect
```

### Organization Policy

**Crate:** `wirken-gateway` | **File:** `crates/gateway/src/org.rs`

`OrgConfig` is fetched from a central HTTP endpoint and applied to local configuration files (`provider.json`, `siem.json`, `mcp.json`). Fields include provider settings, SIEM targets, MCP servers, permission overrides, and skill policies.

**Live update:** Org config is refreshed at gateway start. Mid-session changes require a gateway restart. A SIGHUP-triggered refresh is a planned enhancement.

### Provider Configuration

**Crate:** `wirken-agent` | **File:** `crates/agent/src/llm.rs`

`LlmConfig` specifies provider, model, base URL, and parameters. Per-agent configs are stored in `AgentConfigStore` (SQLite).

**Live update:** Provider changes require gateway restart. The `LlmClient` is constructed once per agent at startup and holds an `reqwest::Client` with HTTPS enforcement.

### Rate Limits

**Crate:** `wirken-gateway` | **File:** `crates/gateway/src/rate_limit.rs`

Two rate limiters, both in-memory:
- `AuthRateLimiter`: per-source tracking, 5 failures / 60s / 10-minute lockout. No loopback exemption.
- `ControlPlaneRateLimiter`: global GCRA via `governor` 0.10, lock-free atomics.

**Live update:** Rate limit state resets on gateway restart. Thresholds are set at startup via `GatewayConfig`.

### SIEM Forwarding

**Crate:** `wirken-audit` | **File:** `crates/audit/src/siem.rs`

`SiemForwarder` sends audit events to Datadog, Splunk HEC, Microsoft Sentinel (Logs Ingestion API), or a generic webhook endpoint. Configuration is read from `~/.wirken/siem.json` at gateway start.

**Live update:** Changing SIEM targets requires editing `siem.json` and restarting the gateway. Event forwarding is non-blocking -- failures are logged but do not block the audit pipeline.

### Sandbox Configuration

**Crate:** `wirken-agent` | **File:** `crates/agent/src/sandbox.rs`

`SandboxMode` (`Off`, `ExecOnly`, `GVisor`) and `SandboxConfig` (image, timeout, network, memory/PID limits) are set at agent construction. `SandboxConfig::default()` is `ExecOnly` as of 0.7.5; the operator can override to `Off` or `GVisor` via `sandbox.json` in the data dir, which the CLI writes during `wirken setup` (with an upgrade prompt if `runsc` is registered) and which `apply_org_config` populates from `OrgPermissions.sandbox_mode`. `GVisor` mode uses the `runsc` OCI runtime via Docker, providing kernel attack surface reduction: agent code syscalls are intercepted by gVisor's Sentry rather than reaching the host kernel. Container hardening is identical across `ExecOnly` and `GVisor`: `cap_drop=ALL`, `no-new-privileges`, default seccomp, read-only rootfs with a 64 MB tmpfs at `/tmp`, 512 MB memory, 256 PIDs, no network, non-root user (1000:1000), workspace bind-mounted RW at `/workspace`.

If Docker is not reachable when the first sandboxed tool runs, the `ToolRegistry` logs a warning naming `Docker` specifically and falls back to host execution for the agent's lifetime. If `gvisor` mode is configured but `runsc` is not registered with Docker, the warning names `runsc` specifically. Provisioning failures are sticky for the lifetime of the registry; a fresh `wirken run` retries.

**Live update:** Sandbox mode changes require gateway restart. Container resource limits are constants in the sandbox module.

### Prompt Injection Detection

**Crate:** `wirken-gateway` | **File:** `crates/gateway/src/injection_detect.rs`

`InjectionDetector` scans inbound messages for common prompt injection signatures: role-switching attempts, instruction override markers, base64-encoded commands, tool-call injection structures, and system prompt extraction attempts. Detection does not block messages — it tags the audit event with a `threat` detail object and emits a separate `message.threat_flagged` event for SIEM visibility.

**Live update:** Detection patterns are compiled into the binary. Adding new patterns requires recompilation. The detector is stateless and shared across all adapter connections.

### Permission Denial Logging

**Crate:** `wirken-agent` | **File:** `crates/agent/src/runtime.rs`

When a `PermissionStore` is configured on an agent, tool calls are checked against the three-tier permission model before execution. Denials are collected as `PermissionDenialContext` structs in the `ProcessResult` returned by `process_message()`. The gateway's message loop logs each denial as a `permission.denied` audit event with full context: tool name, required tier, agent ID, and the trigger message that prompted the tool call.

**Live update:** Permission approvals and revocations take effect immediately (SQLite). New tool-to-action mappings require recompilation.

### Orchestrator Push Peer-Credential Check

**Crate:** `wirken-cli` | **File:** `crates/cli/src/commands/run.rs` (accept loop), `crates/ipc/src/stream.rs` (peer-identity extraction)

The gateway exposes an orchestrator push socket (`~/.wirken/sockets/orchestrator.sock` on unix, a named pipe on windows) used by `wirken zirkel push` and similar tools to deliver outbound messages without going through the per-adapter Ed25519 handshake. Because the socket bypasses adapter authentication, every accepted connection has its peer credentials checked against the gateway's own identity:

- **Unix:** `SO_PEERCRED` returns the connecting process's EUID at accept time (`tokio::net::UnixStream::peer_cred()`). The EUID is wrapped in a `Principal::Uid` and compared with the gateway's own `Principal::Uid(geteuid())`.
- **Windows:** the named-pipe handle is queried via `GetNamedPipeClientProcessId`, then the client process's user SID is extracted via `OpenProcessToken` + `GetTokenInformation(TokenUser)` + `ConvertSidToStringSidW`. The SID is wrapped in a `Principal::Sid` and compared with the gateway's own user SID. The check happens in gateway code, not at the named-pipe DACL level, so the audit log witnesses the refusal in the same shape as on unix.

The unified peer-identity surface is the `wirken_ipc::Stream::peer_principal()` method, which returns a `Principal` enum:

```rust
pub enum Principal {
    Uid(u32),       // unix
    Sid(String),    // windows
}
```

`Principal` displays as a tagged string (`uid:1000` or `sid:S-1-5-21-...`) and serializes through that form, so audit consumers parse one schema regardless of platform.

A refusal emits an `orchestrator.push.refused` audit event with structured detail. Two reason variants exist today:

```json
{
  "reason": "principal_mismatch",
  "expected": "uid:1000",
  "actual": "uid:1001"
}
```

```json
{
  "reason": "peer_principal_unavailable",
  "expected": "uid:1000",
  "error": "..."
}
```

`principal_mismatch` is the load-bearing case: the connecting peer ran as a different user. `peer_principal_unavailable` is the defensive case: the OS could not return peer credentials, so the gateway refuses rather than risk admitting an unverified peer. Both refusals are recorded in the hash-chained audit log; a missing entry is itself a tampering signal.

**File and pipe permissions** are defense-in-depth, not the load-bearing gate: 0600 on the unix socket, owner-only DACL on the windows named pipe. The peer-credential check above is what enforces the cross-user trust boundary; the surface posture protects against accidentally permissive defaults.

**What this protects:** a process running as a different user on the same machine cannot inject orchestrator pushes through this socket, even if file permissions or pipe DACLs are accidentally relaxed. Every refusal is witnessed by the audit log.

**What this does NOT protect:** code running as the same user. The orchestrator socket is a same-user trust boundary; user-level isolation (per-agent unix accounts, separate Windows user profiles) is the operator's responsibility.

**Live update:** N/A — the gateway's own identity is fixed at startup.

---

## Live Policy Updates Without Restart

| Capability | Hot-Reloadable | Mechanism | Latency |
|---|---|---|---|
| Permission approvals | Yes | SQLite write, checked per-request | Immediate |
| Permission revocations | Yes | SQLite delete, checked per-request | Immediate |
| Cron job create/pause/resume | Yes | SQLite, polled every 30 seconds | Up to 30s |
| Adapter registration | No | Requires restart | -- |
| Skill installation | No | Requires restart (no fs watcher) | -- |
| SIEM target change | No | Requires restart | -- |
| Provider/model change | No | Requires restart | -- |
| Sandbox mode change | No | Requires restart | -- |
| Org policy refresh | No | Refreshed on startup only | -- |
| Injection detection patterns | No | Compiled into binary | -- |

---

## Why Compile-Time Enforcement Does Not Prevent Hot-Reloading

A common objection: "If security is enforced at compile time, how can you update policies in a long-running agent without restarting?"

The answer is that **compile-time and runtime enforcement protect different things**, and they are complementary.

**Compile-time guarantees protect structural invariants** -- properties that must hold for the entire lifetime of the process, under all configurations, and cannot safely vary:
- A Telegram session handle must never be usable as a Discord session handle.
- A decrypted secret must never be printable or serializable.
- An adapter must prove its identity before communicating with the gateway.

These invariants have no legitimate reason to change at runtime. An operator should never need to "temporarily allow cross-channel session access" or "make secrets serializable for this one request." Making these invariants compile-time eliminates an entire class of bypass bugs.

**Runtime guarantees protect operational policies** -- properties that operators legitimately need to tune for their deployment:
- Which tools an agent is allowed to use (permission tiers).
- Where audit events are forwarded (SIEM targets).
- Which LLM provider handles requests (provider config).
- How often scheduled jobs run (cron schedules).

These are naturally dynamic. An operator granting shell access to an agent at 2 PM should not require recompiling and redeploying the binary.

**The split is not a compromise.** It is the correct decomposition. The type system handles the things that *must never change*. The runtime handles the things that *must be changeable*. Neither mechanism is sufficient alone, and they do not interfere with each other.

---

## Guarantee Map

| Guarantee | Enforcement | Crate | Key Type / Function |
|---|---|---|---|
| Channel isolation (handle API) | Compile-time | `wirken-ipc` | `SessionHandle<C: Channel>`, `PhantomData<C>` (type-system layer; production routing still uses a `String`-typed `AuthenticatedChannel` discriminator with runtime mismatch detection) |
| No credential logging | Compile-time | `wirken-vault` | `VaultSecret` (no `Debug` / `Display`) |
| No credential serialization | Compile-time | `wirken-vault` | `VaultSecret` (no `Serialize`) |
| No credential copying | Compile-time | `wirken-vault` | `VaultSecret` (no `Clone`) |
| Credential memory zeroing | Compile-time | `wirken-vault` | `SecretString` + `zeroize` 1.8 |
| Adapter identity proof | Compile-time | `wirken-ipc` | `AdapterIdentity`, Ed25519 challenge-response |
| IPC frame size bound | Compile-time | `wirken-ipc` | `FrameReader` (16MB constant) |
| IPC traversal limits | Compile-time | `wirken-ipc` | Cap'n Proto reader options (512MB words, 64 nesting) |
| Schema wire format | Compile-time | `wirken-ipc` | `.capnp` schema, generated `Reader<'a>` / `Builder` |
| Permission tiers | Runtime | `wirken-gateway` | `PermissionStore::check()` |
| Permission approvals | Runtime | `wirken-gateway` | `PermissionStore::approve()` / `revoke()` |
| Rate limiting (auth) | Runtime | `wirken-gateway` | `AuthRateLimiter` |
| Rate limiting (control plane) | Runtime | `wirken-gateway` | `ControlPlaneRateLimiter` |
| Audit logging | Runtime | `wirken-audit` | `AuditWriter::log()` |
| Audit hash chain | Runtime | `wirken-audit` | `AuditLog::write_batch()`, SHA-256 chain |
| SIEM forwarding | Runtime | `wirken-audit` | `SiemForwarder::forward()` |
| Skill availability | Runtime | `wirken-agent` | `SkillLoader::load_dir()` |
| Wasm resource limits | Runtime | `wirken-agent` | `WasmSkill::execute()`, fuel + memory cap |
| Sandbox mode | Runtime | `wirken-agent` | `SandboxConfig`, `DockerSandbox::exec()` |
| Org policy | Runtime | `wirken-gateway` | `OrgConfig`, `apply_org_config()` |
| Provider selection | Runtime | `wirken-agent` | `LlmConfig`, `LlmClient::new()` |
| Session expiry | Runtime | `wirken-gateway` | `SessionStore`, 24h inactivity timeout |
| Cron scheduling | Runtime | `wirken-gateway` | `CronStore::due_jobs()`, 30s poll |
| Prompt injection detection | Runtime | `wirken-gateway` | `InjectionDetector::scan()` |
| Permission denial logging | Runtime | `wirken-agent` | `ProcessResult::denials` |
| gVisor sandbox isolation | Runtime | `wirken-agent` | `SandboxMode::GVisor`, `runtime: "runsc"` |
