# Changelog

All notable changes to Wirken are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [semver](https://semver.org).

The `release-process.md` runbook covers how versions get cut and
signed. Unreleased changes accumulate at the top until a release is
tagged.

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
