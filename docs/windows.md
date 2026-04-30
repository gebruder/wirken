# Wirken on Windows

Wirken runs natively on Windows 11 (x86_64). The Windows binary uses named pipes for IPC, native peer-SID extraction for the orchestrator-push trust boundary, and the same hash-chained audit log as the Linux and macOS builds. This page is the installation and operational reference for Windows.

## What's different on Windows

Wirken targets a researcher / single-user-workstation profile on Windows. The Linux/macOS builds support more deployment shapes; the Windows build deliberately scopes down to what a single user actually needs:

- **`mode: off` is a viable default.** The host-exec path runs through a configured shell (see [Shell choice](#shell-choice) below). Docker Desktop is supported but not required; the configurable sandbox is on the same code path as Linux/macOS.
- **Vault uses an age-encrypted file.** Keys are stored in `%APPDATA%\wirken\keychain\` and unlocked with a passphrase. Native Credential Manager / DPAPI integration is on the roadmap; the age-file backend is portable across machines if you keep the passphrase.
- **`wirken zirkel push` (the orchestrator-push API) is Linux/macOS only.** The push socket is a same-user JSON-line trust boundary that has no analog on Windows; the rest of zirkel works.
- **The Signal adapter is Linux/macOS only.** It connects to `signal-cli`'s unix-domain socket, which doesn't exist on Windows. The other channel adapters (Telegram, Discord, Slack, Teams, Matrix, WhatsApp, Google Chat) work.
- **`wirken service` (systemd/launchd installer) is not available.** Run the gateway manually, or schedule it via Task Scheduler.
- **`wirken cron` (preset cron) is not available.** Use Task Scheduler.

These are not bugs to file; they are deliberate scope cuts. The Linux/macOS docs describe the full surface.

## Why audit log, not sandbox

The Wirken differentiator on Windows is the **hash-chained audit log**, not sandboxing. Every tool call, every refusal, every session is recorded in `%APPDATA%\wirken\audit.db` under a per-session hash chain. `wirken audit verify` proves the chain is intact; `wirken audit log --session <id> --format json` produces a citable artifact. See [`audit-cli.md`](audit-cli.md) for the schema.

For research work where reproducibility and auditability matter more than container isolation, this is the load-bearing claim. A peer reviewer can verify a session's integrity months later without trusting the binary that produced it.

## Install

Download the latest release binary from [github.com/gebruder/wirken/releases](https://github.com/gebruder/wirken/releases):

- `wirken-x86_64-pc-windows-msvc.exe`

Place it on your `PATH` (e.g. in `%USERPROFILE%\bin\`) and rename to `wirken.exe`.

The binary is unsigned. On first run, Windows SmartScreen will warn that the publisher is unverified; click "More info" then "Run anyway". This is expected. Code signing is on the roadmap.

To build from source:

```powershell
# Install Cap'n Proto (build-time dep)
choco install capnproto -y

# Install Rust (https://rustup.rs)
# Then:
cargo install --path crates\cli --target x86_64-pc-windows-msvc
```

## Shell choice

The `exec` tool runs commands through a shell. On Windows, three shells are supported and the default tries them in order:

| Shell        | Default invocation        | Cross-platform skill compatibility               |
|--------------|---------------------------|--------------------------------------------------|
| `sh`         | `sh.exe -c <command>`     | Yes — same as Linux/macOS                        |
| `powershell` | `pwsh.exe -Command ...`   | PowerShell only (`&&` requires PowerShell 7+)    |
| `cmd`        | `cmd.exe /C <command>`    | Windows-only, different escaping than sh         |

The `auto` default probes `PATH` in order: `sh` (typically from Git for Windows), then `pwsh` or `powershell`, then `cmd`. If you share skills with collaborators on Linux/macOS, install [Git for Windows](https://gitforwindows.org/) so `sh.exe` is on `PATH` and skill portability works without configuration.

To pin a specific shell, set `shell` in `%APPDATA%\wirken\sandbox.json`:

```json
{
  "mode": "off",
  "shell": "sh"
}
```

The gateway prints the resolved shell at startup:

```
  Host exec shell: sh (C:\Program Files\Git\usr\bin\sh.exe)
```

## File-permission posture

Wirken sets `0o600` on its key files (vault device key, agent identity, signing keys) on Linux/macOS. Windows does not have a direct equivalent; the keys are written without ACL tightening and rely on the user-profile isolation of `%APPDATA%`. The gateway emits a `tracing::warn!` on each such write so the posture is visible.

If your threat model requires owner-only ACLs on these files, set them manually with `icacls` or PowerShell after first run. Native ACL-on-write is on the roadmap.

## Citing a session in research

Sessions are identified by a string of the form `{agent_id}/{channel}/{conversation_id}`, e.g.:

```
assistant/webchat/550e8400-e29b-41d4-a716-446655440000
```

The conversation_id portion is a 128-bit random ID, so session IDs are globally unique. The `agent_id/channel/` prefix is visible in the citation, which means citations reveal the agent name and the channel it ran on. For most research contexts this is fine and probably useful; for privacy-sensitive citations, the session ID is not opaque-by-construction.

To produce a citable archive of a session:

```powershell
wirken audit verify --format json > integrity.json
wirken audit log --session "assistant/webchat/550e..." --format json > session.json
```

`integrity.json` proves the chain is intact at the moment of citation. `session.json` is the event sequence. Both include `schema_version` and `wirken_version` fields so a future reader can reproduce the exact output format. See [`audit-cli.md`](audit-cli.md) for the schema contract.

## Data and IRB / FERPA / HIPAA considerations

If your research involves data subject to IRB review, FERPA, HIPAA, or institutional data-handling policies, two facts about Wirken are relevant:

1. **Where data goes.** The model provider's API. Wirken sends user messages and tool results to the configured provider (OpenAI, Anthropic, Gemini, Bedrock, Tinfoil, Privatemode, Ollama, or a custom endpoint). The provider's data-handling policy governs what happens to that data; check it against your institutional requirements.
2. **What's logged locally.** The hash-chained audit log records every tool call, message, and refusal locally at `%APPDATA%\wirken\audit.db`. The audit log is not transmitted anywhere unless you've configured SIEM forwarding. Local provider (Ollama) keeps everything on your machine.

The audit log is the artifact that makes a Wirken-driven research workflow auditable. The provider's logs are governed by the provider's policy, not Wirken's.

## Troubleshooting

**SmartScreen blocks the binary on first run.** Expected. Click "More info" → "Run anyway". Code signing is on the roadmap.

**`exec` tool says "no shell found."** No `sh`, `powershell`, or `cmd` resolved. Install Git for Windows (recommended) or pin `"shell": "cmd"` in `sandbox.json`.

**Vault prompts for a passphrase every restart.** Expected — the age-file backend uses a user-provided passphrase. Native Credential Manager integration is on the roadmap.

**Audit log integrity check fails after a crash.** SQLite WAL recovery should handle clean crashes; if you see `BROKEN` from `wirken audit verify`, that's a tampering signal, not a crash artifact. Open an issue with the failing session ID and seq.
