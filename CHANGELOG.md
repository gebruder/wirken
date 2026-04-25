# Changelog

All notable changes to Wirken are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [semver](https://semver.org).

The `release-process.md` runbook covers how versions get cut and
signed. Unreleased changes accumulate at the top until a release is
tagged.

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
