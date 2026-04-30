# Changelog

All notable changes to Wirken are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [semver](https://semver.org).

The `release-process.md` runbook covers how versions get cut and
signed. Unreleased changes accumulate at the top until a release is
tagged.

## 1.0.0 — Windows 11; audit CLI user-grade; cross-platform IPC trait surface

The cross-platform release. Wirken now ships a native Windows 11 binary alongside the existing Linux and macOS builds. The audit CLI is user-grade across all three platforms: structured JSON output, citable session IDs, schema versioning, the verify command emits typed failure data. The IPC layer is now expressed as the `wirken_ipc::Stream` and `wirken_ipc::Listener` trait surface; production code talks through the trait, with unix-domain sockets on Linux/macOS and named pipes on Windows behind it.

This is the first release with semver stability commitments. The surfaces called out in [docs/audit-cli.md](docs/audit-cli.md) (`schema_version: 1` JSON shape, `wirken_version` field, session-ID format, `Principal` tagged-string form), in [docs/architecture.md](docs/architecture.md) (the `wirken_ipc` trait surface), and in [docs/cli.md](docs/cli.md) (the command-line surface) are stable within 1.x. Additive changes (new fields, new optional flags, new subcommands) are non-breaking; field removals or shape changes bump the major.

### Windows 11 support

- **Native `wirken-x86_64-pc-windows-msvc.exe`.** Single binary, no installer dependencies beyond Cap'n Proto at build time. Ships in the same release artifacts as the Linux and macOS builds (`8e6cc37`, `dec99e0`). See [docs/windows.md](docs/windows.md) for the install path, SmartScreen behavior, and the documented feature deltas.
- **Named-pipe IPC with peer-SID enforcement.** The gateway↔adapter and gateway↔mcp-proxy paths use `tokio::net::windows::named_pipe` on Windows behind the same `wirken_ipc::Stream` interface as unix-domain sockets on Linux/macOS. Peer identity at accept time goes through `GetNamedPipeClientProcessId` → `OpenProcessToken` → `GetTokenInformation(TokenUser)` → `ConvertSidToStringSidW`, returning a `Principal::Sid("S-1-5-21-...")`. The check happens in gateway code (audit-witnessable), not at the named-pipe DACL level. See [docs/enforcement-model.md §Orchestrator Push Peer-Credential Check](docs/enforcement-model.md) for the cross-platform principal model. (`b7dd9dd`, `c6f2fa3`, `3f7768e`)
- **`exec.shell` config knob.** When `sandbox.json` is set to `mode: off` on any platform, the host-exec fallback resolves a shell at gateway startup. Auto-detect order: `sh` → `powershell` → `cmd`. Operators on Windows who install Git for Windows get POSIX-shell semantics for cross-platform skill portability without configuration. The resolved shell is logged at gateway startup. (`9120b1d`)
- **Documented platform deltas on Windows:** Signal adapter, `wirken zirkel push` (orchestrator-push API), the `wirken service` installer, and `wirken cron` preset installer are Linux/macOS only at compile time. Vault uses the age-encrypted-file backend (native Credential Manager / DPAPI on the roadmap). The Windows binary is unsigned; SmartScreen warns on first run. ([docs/windows.md](docs/windows.md))
- **CI matrix extended.** A `windows-smoke.yml` workflow exercises the named-pipe Stream impl on every push to main; `release.yml` builds the Windows .exe on every release tag.

### Audit CLI user-grade across all platforms

The audit log was always hash-chained, but the CLI surface was developer-debug shape. This release makes it citable in research and scriptable in compliance pipelines.

- **`wirken audit log` flags.** New flags: `--session <id>`, `--actor <name>`, `--since <iso8601>`, `--until <iso8601>`, `--format human|json`. The underlying `AuditQuery` already supported actor/since/until; this exposes them at the CLI. When `--session <id>` is provided, human output prints a structured session header decomposing the `{agent}/{channel}/{id}` form. (`1869b4e`)
- **JSON schema with versioning.** Both `wirken audit log --format json` and `wirken audit verify --format json` emit a top-level `schema_version: 1` and `wirken_version` field. Session IDs in JSON are objects (`full`, `agent`, `channel`, `id`) — `full` is the canonical round-trippable form, the decomposed fields are convenience. Unknown future fields may be added; consumers should ignore them. ([docs/audit-cli.md](docs/audit-cli.md))
- **`VerifyResult::Broken` restructured.** The variant now carries typed fields: `session_id: SessionId`, `seq: u64`, `expected_hash: String`, `actual_hash: String`, `verified_count: u64`. Replaces the prior free-form `(row_id, expected, found)` shape. `wirken audit verify` failure output names the session, the seq, the verified-count up to the break, and exits 1. (`0d4e964`)
- **Per-session chains documented.** The verify pass walks every session's chain independently; a break in one session is reported with the verified count summed across complete sessions plus the per-session count up to the break.

### IPC trait surface and production migration

- **`wirken_ipc::Stream` and `wirken_ipc::Listener`.** New trait surface. `Stream` composes `AsyncRead + AsyncWrite + Send + Unpin` plus `peer_principal() -> Result<Principal, IpcError>`; `Listener` is async-trait with an `accept() -> BoxStream` method. Implementations for `tokio::net::UnixStream`/`UnixListener` on unix and the named-pipe types on windows live in the IPC crate. (`d45c7d6`, `b7dd9dd`)
- **`wirken_ipc::bind(path)` and `connect(path)` helpers.** Path-based listener and client construction; on Windows the path is mapped to a deterministic pipe name (last-segment + 16-hex-digit hash of full path) so multiple gateways with different data dirs don't collide.
- **Generic `FrameReader<R>` and `FrameWriter<W>`.** The capnp framing layer is now generic over `AsyncRead + Unpin` / `AsyncWrite + Unpin`. Production code uses the `IpcFrameReader` / `IpcFrameWriter` aliases over `ReadHalf<BoxStream>` / `WriteHalf<BoxStream>`. (`8e6cc37`)
- **All ten channel adapters migrated.** The gateway accept loop, mcp-proxy server, outbound dispatcher, and `McpProxyClient` all use the trait surface. Tests stay unix-only; the windows-smoke workflow proves the named-pipe path on every CI run.

### Orchestrator-push audit reconciliation

- **Refused pushes are now witnessed by the audit log.** Prior behavior: cross-uid push refusals on the orchestrator socket emitted a `tracing::warn!` line that was not recorded in the hash-chained log. New behavior: every refusal emits an `orchestrator.push.refused` audit event with structured detail (`reason`, `expected`, `actual`, plus `error` for the unavailable-credential case). Two reason variants today: `principal_mismatch` and `peer_principal_unavailable`. Closes the existing tracing-only gap on Linux/macOS and applies the same shape on Windows. (`3f7768e`)
- **Peer-identity check expressed as `Stream::peer_principal()`.** The orchestrator accept loop in `wirken-cli` uses the trait method instead of the direct `peer_cred()` call; the result is a `Principal` enum that displays as `uid:N` on unix and `sid:S-1-5-...` on windows. The audit event detail uses the tagged-string form so consumers parse one schema regardless of platform.

### File-permission posture

- **Operator-visible warning on platforms without 0o600.** Vault device key writes, agent identity-key writes, and skill-signing-key writes emit a `tracing::warn!` on platforms (Windows, primarily) where the unix `chmod 0o600` step is unavailable. The keys rely on user-profile isolation of the data directory for confidentiality. Native ACL-on-write is on the roadmap. (`401db72`)

### Other

- **Gateway session-ID format normalized to UUID.** The gateway's `generate_session_id()` previously emitted 32-char hex from `rand::rng().fill_bytes`; now it emits `Uuid::new_v4().to_string()` for visual consistency with zirkel-issued session IDs. Existing audit-log entries under hex IDs remain queryable as opaque strings — the change is forward-only. (`09c5ae2`)
- **Dependency bumps.** `reqwest` 0.13.2 → 0.13.3 (#90), `slack-morphism` 2.19.0 → 2.20.0 (#91), `open` 5.3.3 → 5.3.4 (#92), `lru` 0.16.3 → 0.18.0 (#94, validated against the agent-factory cache). `cap-std` 4.x bump (#93) deferred — pinned by `wasmtime-wasi 43.0.1`.

### Not committed in 1.0 — explicit roadmap items

These are out-of-scope for the tier-2 Windows release and noted here for completeness:

- DPAPI / native Windows Credential Manager vault backend
- Code-signed Windows binary
- Windows service installer (parallel to systemd/launchd)
- gVisor sandbox on Windows (gVisor doesn't run on Windows)
- Signal adapter on Windows (signal-cli's transport is unix-only)

## 0.9.1 — Audit-pass security fixes; doc accuracy

No breaking changes. Five real fixes, all from a single security-audit pass against `e9bc65a`. Operators upgrading from 0.9.0 should pull this release; the env-passthrough escape closed in `5fcf3c1` was a real privilege escalation path.

- **mcp-proxy: env-passthrough escape closed** (`5fcf3c1`). Prior behavior: `wirken-mcp-proxy` reads `WIRKEN_VAULT_PASSPHRASE` on startup (`crates/mcp-proxy/src/runner.rs::open_vault`) and the variable stays in the proxy's environ for the proxy's lifetime. `StdioTransport::spawn` did not call `env_clear()`, so every spawned MCP server inherited the parent's full environ — including the vault passphrase. A compromised MCP server could read it from its own env, open `~/.wirken/vault.db` at the operator UID, and decrypt every credential (provider API keys, adapter Ed25519 secrets, channel tokens). Fix: `StdioTransport::spawn` now calls `env_clear()` first and re-adds only an explicit allowlist (`PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_*`, `TERM`, `TZ`, `TMPDIR`, `XDG_*`) plus the per-MCP `env` from `mcp.json`. Belt-and-suspenders: `open_vault` now removes `WIRKEN_VAULT_PASSPHRASE` from the proxy's environ immediately after `probe_keychain` reads it, so a `/proc/<mcp-proxy-pid>/environ` read by another same-UID process turns up nothing. 7 new tests in `mcp_transport::env_isolation_tests` lock in the property.
- **WebChat: CSRF defence + rate limit** (`5d60f81`). Prior behavior: `POST /api/chat` accepted any request that reached `127.0.0.1:18790` — no `Origin` check, no rate limit. A page the operator visits in the browser could drive the agent unbounded; same-origin policy stops the attacker reading the SSE response, but the agent runs the prompt anyway and bills the operator's API key. Fix: explicit `Origin:` header allowlist matched against `http://127.0.0.1:<port>`, `http://localhost:<port>`, `http://[::1]:<port>` for the bound port (rejects `https://`, non-loopback hosts, and port mismatches; missing Origin allowed for non-browser clients). GCRA rate limit at 60 POSTs / minute via the existing `wirken-gateway::rate_limit::ControlPlaneRateLimiter`. 4 new tests on the Origin matcher.
- **Agent: SSE buffer cap** (`361e9bf`). Prior behavior: `crates/agent/src/llm_stream.rs` accumulated SSE chunks into a `String::new()` buffer until a `\n\n` separator arrived. A hostile or buggy LLM endpoint that sends bytes without separators (intentionally or via a misconfigured proxy) made the buffer grow unbounded → gateway OOM. Real for self-hosted vLLM, relays, and TEE-mediated proxies. Fix: hard cap at 1 MB (two orders of magnitude above any plausible single SSE event); error returned cleanly when exceeded.
- **Vault: dead `unsafe` block deleted** (`626e8f6`). `pub fn write_to_fd` (`File::from_raw_fd` + `mem::forget` for an unimplemented "vault export over fd" path) had no callers outside its own test. The only `unsafe` block in `wirken-vault` removed; future fd-write paths must restore the function with the safety contract documented at each call site.
- **docs/architecture.md, docs/mcp.md** (`e9bc65a`, `687d890`). The architecture doc previously described the agent as running in a separate process from the gateway; the actual layout has them in one address space (`crates/cli/Cargo.toml` pulls `wirken-agent` as a path dep). The `architecture.md` §6 ("Direct LLM calls") now describes the single-process reality and lists subprocess isolation as a future architectural option, not an in-flight roadmap item. `docs/mcp.md` gained a "Trust boundary" section that enumerates what is and is not protected by the existing process topology after the env-isolation fix above.

## 0.9.0 — Channel formatters cohort; Sentinel SIEM; Slack live transport; pipeline-laundering hardening

No breaking config changes. Operators upgrading from 0.8.0 keep their
existing `~/.wirken/` layout; the changes are all additive on the wire
(new formatters, new SIEM target) or hardening on the runtime
(pipeline metacharacters, Slack echo and thread fixes).

- **Per-channel outbound formatters in `adapter-core`** (closes #71).
  Slack (`mrkdwn`: `<url|text>` links, `*bold*` collapse, GFM tables
  flattened), Discord (CommonMark pass-through; only tables flatten,
  `<hr>` collapses), Telegram (HTML mode with bounded escape surface
  `<>&`, single-pass tokenizer that shields markdown markers inside
  inline code from re-tokenization, `<pre><code class="language-…">`
  for fenced blocks), Matrix (`org.matrix.custom.html` with real
  `<h1>`–`<h6>`, native `<ul>`/`<ol>`/`<li>`, real `<table>`,
  `<strong>`/`<em>`/`<del>`, dual-field `body` + `formatted_body` on
  `m.room.message`). Each formatter wired into its adapter's send
  path with a regression-test bar of UTF-8 parity (Devanagari, CJK,
  emoji, smart quotes) plus a full round-trip test. The Telegram
  inline tokenizer is parameterised on a tag set; Matrix reuses it
  with semantic tag pairs.
- **Microsoft Sentinel SIEM target** on the audit forwarder. POST to
  the Logs Ingestion API endpoint (`<dce>/dataCollectionRules/<dcr>/
  streams/Custom-…`) with an Azure-AD bearer token in `api_key`. JSON
  record body uses the Custom-table column convention (`TimeGenerated`,
  `Actor`, `Action`, …) so a DCR transform can map straight into the
  operator's table without renaming. Joins existing Datadog Log
  Intake, Splunk HEC, and generic webhook. Wirken does not refresh
  the bearer token; the operator's responsibility (typically a
  sidecar that rewrites `~/.wirken/siem.json` before expiry).
- **Slack adapter live transport.** Two upstream issues that
  previously blocked any real Slack round-trip, both fixed:
  `slack-morphism 2.19`'s `SlackClientSocketModeListener::listen_for`
  only registers an app token; the WSS handshake comes from
  `start()`/`shutdown()`. The adapter now drives that explicitly,
  with the misleading "connected and listening" log line replaced
  by truthful "WSS connection started" / "shutdown initiated"
  markers. And `slack-morphism`'s `hyper` feature activates
  `tokio-tungstenite/rustls-native-certs` — an optional-dep name in
  `tokio-tungstenite 0.28`, not the feature that activates
  `__rustls-tls`. Workspace feature unification fixes it via a
  feature-only direct dep on `tokio-tungstenite` with
  `features = ["rustls-tls-native-roots"]`. Tungstenite now compiles
  with rustls 0.23 + the patched rustls-webpki 0.103.13.
- **Slack echo loop closed; thread_ts preserved.** The bot's own
  outbound used to come back through `message.im` and re-enter the
  agent as fresh user input, generating an autoresponse, repeating
  indefinitely. The slack-adapter event filter now drops messages
  whose `sender.user` matches `bot.user_id`, whose `sender.bot_id`
  matches `bot.bot_id`, or whose subtype is `bot_message` /
  `message_changed` / `message_deleted` / any of the
  membership/system variants. The conversion lives in
  `convert::from_push_event` so the filter is unit-testable; 14 new
  tests cover each drop case plus the thread_ts pass-through.
  Separately, the gateway dispatcher in `cli/src/commands/run.rs`
  used to set `outbound.reply_to_id = inbound.id` (the inbound's own
  message ts), which auto-threaded every root message off itself.
  It now propagates `inbound.reply_to_id` (the inbound's thread
  root) — empty string for root inbounds, the thread root for
  thread inbounds. Bot replies land in the same thread as the
  question; root messages don't auto-thread.
- **Pipeline-laundering hardening on shell exec** (closes #36). The
  Tier 2 allowlist for shell verbs lets `ls`, `cat`, `pwd`, etc.
  through with first-use approval. Without metacharacter awareness,
  an agent could lead with an allowlisted verb and chain to a
  non-allowlisted one: `echo "rm -rf /" | bash`, `pwd && curl evil`,
  `cat /etc/passwd > /tmp/leak`, multi-line bodies fed to a shell.
  `tool_to_action` now scans the raw command for shell
  metacharacters (`| ; & $( ` `` ` ` `` `> < \n`) before splitting
  on whitespace; any presence forces a sentinel pattern
  (`:pipeline:`) that cannot match the allowlist, landing the
  action on Tier 3.
- **`docs/sandbox-properties.md` and code-anchored RMF mapping.** New
  `docs/sandbox-properties.md` enumerates the three `SandboxMode`
  values, container hardening (`cap_drop=ALL`,
  `no-new-privileges:true`, `readonly_rootfs`, `network_mode=none`,
  512 MB memory, 256 PID, non-root UID, 300 s timeout), Docker
  default seccomp coverage, gVisor (`runsc`) syscall-trap delta,
  and the Wasmtime WASI surface for skills. Every property cites
  the source line that implements it; six verification commands an
  operator can run to confirm each claim. `docs/security-properties.md`
  NIST AI RMF rows now carry file:line citations on every
  implementation reference instead of the previous crate-name-only
  form.

## 0.8.0 — Signal socket transport; adapter-core formatters; audit concurrency

Breaking-on-upgrade for Signal operators: the adapter no longer speaks
HTTP to signal-cli. The daemon must run with `--socket <path>` and the
endpoint stored in the vault must be a filesystem path (or
`unix:///path`). Pre-0.8.0 installs with an `http://` endpoint get a
clear migration error at startup and must re-run `wirken setup` or
`wirken channel add signal`. Every other provider and channel is
unchanged.

- **Signal adapter rewritten to `--socket` JSON-RPC.** signal-cli
  0.14.x's HTTP daemon auto-consumes inbound messages in the
  background and rejects concurrent `receive` RPCs, which broke
  every tick of the previous polling loop with `"Receive command
  cannot be used if messages are already being received."` The
  adapter now calls `subscribeReceive` once and consumes push
  notifications over a Unix socket. Reader-side subscription-id
  interception so no race between subscribe response and first
  notification. Reconnect-with-exponential-backoff around
  connect + subscribe + read_loop. Bounded inbound channel (256)
  for backpressure. Self-echo LRU (1024 entries) keyed on the
  timestamp signal-cli returns from `send` so Signal's
  multi-device mirror does not re-enter the agent as fresh
  inbound. End-to-end test against a fake Unix socket; byte-accurate
  captured envelopes from a real signal-cli 0.14.2 daemon land
  as the authoritative parse fixture.
- **Signal envelope coverage expanded.** `dataMessage.groupV2.id`
  (modern signal-cli) reads before legacy `groupInfo.groupId`.
  `sourceUuid` is surfaced on `SignalInbound` and the allowlist
  accepts UUID entries alongside E.164 phone numbers, so contacts
  using Signal's phone-privacy feature can reach the agent.
  Outbound sends to a group route via the `groupId` RPC param
  instead of always using `recipient` — group replies used to be
  silently rejected by signal-cli.
- **`wirken channel add signal`.** Signal has its own arm that
  collects phone, socket path, and allowlist through the same
  helper the setup wizard uses. Previously it went through the
  generic bot-token prompt and produced a half-populated vault
  state that crashed the adapter at startup.
- **`adapter-core` crate.** Channel-specific outbound formatting
  has a typed home: `OutboundFormatter` trait, `PlainFormatter`
  (explicit pass-through so "no formatter" stops being
  accidental), `SignalFormatter` (renders markdown to Signal's
  `*bold*` / `_italic_` dialect and flattens GFM tables to
  `header: value` per cell). Wired into the signal adapter's
  `send_message`. Slack / Discord / Telegram / Matrix formatters
  are tracked in #71.
- **UTF-8 correctness in cli and formatter.** Three `truncate(&str,
  max)` helpers in `run.rs`, `audit.rs`, `skills.rs` were slicing
  `&s[..max]` on byte offsets, which panics when the offset falls
  inside a multi-byte UTF-8 scalar — `byte index 80 is not a char
  boundary; it is inside 'ा'` crashed the gateway on a Hindi LLM
  reply during live testing. All three walk back to the nearest
  `is_char_boundary` now. `SignalFormatter::replace_links` had the
  same bug (`bytes[i] as char` per non-bracket byte) and now
  copies full codepoints via `&str` slicing.
- **Agent error text no longer leaks to the end user.** When
  `agent.process_message` returned `Err`, the raw error string
  (database paths, session-log locks, provider stack traces) was
  formatted and sent back through whatever channel the sender
  reached us on. Outbound reply is now a generic apology; the
  full error still lands in the operator log and the audit trail.
- **Audit writer serializes concurrent writers.** Two inbound
  messages arriving within seconds of each other produced
  `database error: database is locked` on the session log.
  `SqliteSessionLog::init_schema` now sets `busy_timeout=5000` and
  `synchronous=NORMAL` on every open alongside the existing WAL;
  `append_inner` uses `BEGIN IMMEDIATE` instead of the default
  DEFERRED so the write lock is claimed up front where
  `busy_timeout` applies. Concurrent writers serialize instead of
  erroring. Regression test: 100 concurrent appends across two
  `SqliteSessionLog` instances on the same file, all succeed.
- **AuditWriter connection reuse.** `flush` was reopening the
  SQLite connection on every 50ms tick, paying the full
  pragma + migration cost for nothing. `flush_loop` now opens
  once at startup and threads the `Arc<AuditLog>` through.
- **`wirken sessions list` / `verify` id mapping.** `list` prints
  both the `STORE ID` (hex primary key in `sessions.db`) and the
  `LOG ID` (composite `{agent}/{channel}/{conversation}` keyed by
  the audit log). Operators copying either into the right command
  works; previously the hex id from `list` produced `No events for
  session …` on `verify`. `verify` also translates a bare hex id
  to the composite via a SessionStore lookup, so pre-0.8.0 scripts
  that passed the `list` output keep working.
- **Privatemode reference doc rewritten.** `docs/reference/privatemode.md`
  drops the `_Target_` sections describing work that was never
  built (packaged `deploy/privatemode/` sidecar recipes, direct
  proxy sidecar spawning, an Anthropic-shape provider switch). The
  doc now describes only what works on the current binary.
  Tracking issue #57 closed; remaining CI-stub work relocated to #72.

## 0.7.8 — Setup-time vault corruption fix; credential CLI gaps

Headline is a setup-time data-loss bug: every multi-step channel setup
(signal, slack, teams, matrix, imessage, whatsapp) reopened the
keychain with an empty-passphrase fallback after the first real prompt,
which silently re-keyed the AgeFile keychain and made every row written
under the original passphrase undecryptable. User-visible symptom was
`aead::Error` at `wirken run` time complaining the channel token would
not decrypt.

- **Setup-time vault corruption (cli).** Each `probe_keychain(data,
  String::new)` after `register_channel` constructed an `AgeFileKeychain`
  with an empty passphrase. `CredentialStore::open` then fell into its
  "first run" branch, generated a fresh device key, and overwrote the
  keychain file with that key under empty passphrase — orphaning the
  rows from the first open. Same pattern bit `register_channel`, the
  org-config arm, `store_key_and_pick_model` (cloud providers), the AWS
  Bedrock arm, and `configure_channel_overrides` from #68. New
  `cached_vault_passphrase()` helper prompts once per process and
  stashes the result in `WIRKEN_VAULT_PASSPHRASE` (the env var
  `wirken run` already propagates to spawned adapters), so every
  keychain open in the same invocation derives the same wrapping key.
- **`CredentialStore::open` hardened (vault).** Previously any
  `retrieve_device_key` failure was treated as "first run" and triggered
  an auto-generate-and-overwrite. `open` now distinguishes
  `VaultError::Decryption` (existing keychain that will not unwrap —
  hard error) from other errors (no keychain yet — auto-generate).
  Defense in depth: even if a future call site reintroduces a
  passphrase-mismatch open, the vault layer surfaces it instead of
  silently corrupting.
- **`wirken credentials remove <name>` (cli).** New subcommand. The
  vault layer already exposed `CredentialStore::delete`; only the CLI
  was missing. Errors with `VaultError::NotFound` if no row matches.
- **`wirken channel remove <ch>` clears every per-channel row (cli).**
  Previously deleted only `<channel>-token`, with a hardcoded fallback
  for the four whatsapp keys, leaving entries like `signal-adapter-key`,
  `signal-endpoint`, `signal-allowed-senders`, and `slack-app-token`
  orphaned. Now calls a new `CredentialStore::delete_by_channel` that
  removes every row tagged with the channel in one statement, and
  reports the cleared count.

## 0.7.7 — Security audit fix (generate_image)

Single finding from the Round 2 audit.

- **Vuln 9 — generate_image path traversal (agent).** The
  `generate_image` tool read `filename` directly from LLM-controlled
  tool args and built the output path with
  `images_dir.join(format!("{filename}.png"))` with no validation.
  `PathBuf::join` with an absolute path replaces the base, and
  `..` components walk out of the workspace. The Vuln 2 fix did
  not cover this call site (it guarded `write_file` via
  `resolve_path_for_write`; `generate_image` built its path
  directly). New `sanitize_image_filename` strips `/`, `\`, and
  null bytes to `_` and refuses empty / `.` / `..`; the write now
  routes through `resolve_path_for_write` so the leaf-symlink
  refusal that protects `write_file` also guards this path.

## 0.7.6 — Security audit fixes

Eight findings from the security audit. Numbered to match the audit
report; HIGH unless otherwise noted.

- **Vuln 1 — shell-exec Tier 3 bypass (permissions).** Tier 3
  classification for high-risk commands used a case-sensitive
  contains check on the raw first token, so `/usr/bin/curl`,
  `./curl`, `CURL`, and shell wrappers like `sh -c 'curl ...'` all
  bypassed the gate. `Action::tier` and `Action::approval_key` now
  canonicalize via `Path::file_name()` + `to_ascii_lowercase`, and
  `HIGH_RISK_PREFIXES` is expanded with shell and process wrappers
  (`sh`, `bash`, `dash`, `zsh`, `env`, `xargs`, `nohup`, `timeout`,
  `nice`, `ionice`, `setsid`, `stdbuf`).
- **Vuln 2 — broken-symlink write (agent).** `resolve_path_for_write`
  returned an uncanonicalized path; a dangling symlink inside the
  workspace passed ancestor validation, and `tokio::fs::write`
  then created the target at the symlink destination, possibly
  outside the workspace. A `symlink_metadata` check on the leaf
  now refuses any symlink target. Separately, the `exec` sandbox
  no longer falls back silently to host execution when Docker is
  unreachable — that amplified this vuln. `SandboxMode::Off` is
  the only mode that permits host exec; `ExecOnly` / `GVisor`
  return a clear error when the sandbox is unavailable.
- **Vuln 3 — audit buffer loss on flush failure (audit).** The
  flush loop cleared the in-flight batch unconditionally, so any
  transient SQLite write error dropped the events that recorded
  activity in that window. Flush now retains the buffer on error
  and the loop halts after persistent failure, closing the mpsc
  channel so callers observe `ChannelClosed` instead of
  continuing with silent audit loss.
- **Vuln 4 — WhatsApp HMAC timing (adapter-whatsapp, MEDIUM).**
  `verify_signature` compared HMAC-SHA256 results with
  short-circuiting string equality. Now hex length is checked
  before decode, and `Mac::verify_slice` performs the
  constant-time comparison on decoded bytes. A misleading
  `// Constant-time comparison` comment is removed.
- **Vuln 5 — Teams webhook had no auth (adapter-teams).** The
  webhook accepted any POST matching the Activity shape. New
  `auth` module fetches Microsoft's JWKS through the Bot
  Framework OpenID config, caches by `kid` with rotation refresh,
  and validates inbound JWTs: RS256 signature, issuer equals
  `https://api.botframework.com`, audience equals the bot's
  configured app id, `exp` in the future. `TeamsAdapter::new`
  now returns `Result` and refuses empty `app_id` or
  `app_password`.
- **Vuln 6 — Google Chat webhook had no auth (adapter-google-chat).**
  Same class as Vuln 5. New `auth` module validates inbound JWTs
  against Google's Chat service-account JWKS: issuer equals
  `chat@system.gserviceaccount.com`, audience equals the bot's
  Cloud project number. `GoogleChatAdapter::new` now returns
  `Result` and requires both `service_account_token` and
  `app_project_number`. CLI now reads `{channel}-project-number`
  from the vault.
- **Vuln 7 — iMessage BlueBubbles webhook had no auth
  (adapter-imessage).** The `server_password` was stored at
  registration but never checked on inbound. Now extracted from
  the JSON body `password` field (matches the outbound flow) or
  the `X-BlueBubbles-Password` / `X-BB-Password` headers, and
  compared constant-time. `IMessageAdapter::new` returns `Result`
  and refuses empty `server_password`.
- **Vuln 8 — WhatsApp fail-open on empty secret
  (adapter-whatsapp, MEDIUM).** `verify_signature` was gated
  behind `if !app_secret.is_empty()`, so an empty secret silently
  disabled HMAC verification. `WhatsAppAdapter::new` now returns
  `Result` and refuses empty `app_secret`; the webhook handler
  always requires the signature.

### Deployment impact

Self-hosted deployments that previously relied on missing or empty
secrets to skip auth will fail to start on upgrade. Provision the
required config:

- `{channel}-app-id` and `{channel}-app-password` for Teams.
- `{channel}-project-number` in addition to the service account
  token for Google Chat.
- `{channel}-bluebubbles-password` (non-empty) for iMessage.
- `{channel}-app-secret` (non-empty) for WhatsApp.

Deployments running `sandbox_mode = "exec-only"` or `"gvisor"` on
hosts without Docker will fail at first `exec` call rather than
silently using host execution. Either install Docker/gVisor or
set `"mode":"off"` explicitly in `sandbox.json`.

## Unreleased

### Sandbox defaults, configuration plumbing, hardening, and exec tier granularity

Four changes that together close the gaps documented in the 0.7.4
verification report:

- **Wire `sandbox_mode` config through to the runtime.** `OrgPermissions.sandbox_mode` now writes `sandbox.json` in the data dir via `apply_org_config`, and the CLI reads it at gateway start. `AgentStaticConfig` carries a `sandbox` field that the factory clones into every waked agent. `Agent::new_with_sandbox` is the new explicit constructor; `Agent::new` becomes a shim that uses the default. `Agent::from_session_log` takes a `SandboxConfig` parameter. Precedence: org config (force-overwrite on `wirken run`) > local `sandbox.json` > default.
- **Flip the default sandbox mode from `Off` to `ExecOnly`.** Fresh installs sandbox shell exec in an ephemeral Docker container by default. `SandboxMode::from_str_config` unknown/empty values now fall back to the current default rather than silently stripping the sandbox. `ToolRegistry::sandbox` probes Docker first and emits a distinct warning if Docker is unreachable; if `gvisor` is configured but `runsc` is not registered, the warning names `runsc` specifically. Both fall through to host execution with the existing sticky-failure semantics. `wirken setup` adds a fourth step that detects `runsc` and offers to upgrade to `gvisor`, writing `sandbox.json` either way.
- **Harden the sandbox container.** `cap_drop=ALL`, empty `cap_add`, `security_opt=["no-new-privileges:true","seccomp=default"]`, `readonly_rootfs=true`, and a 64 MB `tmpfs` at `/tmp` with `mode=1777`. Workspace stays bind-mounted RW at `/workspace`. Memory, PID, no-network, and non-root user settings are unchanged. Structural unit tests assert each field, and Docker-backed integration tests (skipped when Docker is absent) verify the kernel-level effect: write to `/` fails, writes to `/workspace` and `/tmp` succeed, `chown` fails under `cap_drop`, and setuid binaries fail to elevate under `no-new-privileges`.
- **Promote high-risk shell exec prefixes to Tier 3.** `curl`, `wget`, `ssh`, `scp`, `sftp`, `sudo`, `su`, `doas`, `kubectl`, `helm`, `docker`, `podman`, `nc`, `ncat`, `socat`, and `git` now always prompt instead of remembering a single approval for 30 days. Other `exec` prefixes keep the Tier 2 first-use-approval behaviour. No `permissions.db` schema change; existing Tier-2-style approvals for newly-Tier-3 prefixes are ignored by the tier lookup rather than migrated.

### Docs

- `docs/permissions-and-identity.md` no longer says `sandbox_mode` is parsed-but-not-enforced. `allowed_tools` and `blocked_tools` remain in the "parsed, not enforced" set.
- `docs/enforcement-model.md` describes the new default, the fallback warning paths, and the `sandbox.json` override.
- `README.md` Status section describes the new default and container hardening.

### Version

No version bump in these commits. The next release will be tagged
`0.7.5` per the maintainer runbook, with the bump in its own commit
at release time.
