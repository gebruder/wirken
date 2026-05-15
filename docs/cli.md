# CLI Reference

## wirken setup

Interactive setup wizard. Configures AI provider, messaging channels, and optionally installs as a system service.

```
wirken setup [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--install-service` | Install as a systemd (Linux) or launchd (macOS) service |
| `--uninstall-service` | Remove the system service |
| `--org <URL>` | Pull provider, SIEM, MCP, and permission config from a company endpoint |

## wirken run

Start wirken. Spawns adapter processes, starts WebChat, and accepts connections.

```
wirken run [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-p, --port <PORT>` | WebChat port (default: 18790) |

## wirken ask

Send a message directly to an agent and print the response. No channel setup needed.

```
wirken ask -m "your message"
```

| Option | Description |
|--------|-------------|
| `-m, --message <MESSAGE>` | The message to send (required) |
| `--agent <AGENT>` | Agent ID (default: "default") |

## wirken channel

Manage messaging channels.

```
wirken channel add <CHANNEL>     # telegram, discord, slack, teams, matrix,
                                 # signal, google-chat, imessage, whatsapp
wirken channel list
wirken channel remove <CHANNEL>
```

The `add` command prompts for the channel's primary token (and Slack's app token). Channels that need additional fields — Teams app ID, Matrix homeserver/username, Signal phone, BlueBubbles password, WhatsApp phone-number-id/verify-token/app-secret — are wired up by `wirken setup`'s per-channel sub-flows. WhatsApp's setup flow is on the roadmap; see [WhatsApp channel docs](channels/whatsapp.md) for the vault entries it expects in the meantime.

> **Signal is Linux/macOS only.** The Signal adapter requires a Unix-domain socket to a local `signal-cli` daemon and is excluded at compile time on the Windows build. See [docs/channels/signal.md](channels/signal.md) and [docs/windows.md](windows.md).

## wirken agents

Manage multi-agent configurations. Each agent can have its own model, API key, workspace, and channel bindings.

```
wirken agents add                       # interactive wizard
wirken agents list
wirken agents remove <ID>
wirken agents bind <AGENT> <CHANNEL>    # route a channel to an agent
```

## wirken skills

Search, install, and manage skills.

```
wirken skills search <QUERY>
wirken skills install <NAME>
wirken skills list
wirken skills sign <DIR>         # sign a skill with Ed25519
wirken skills verify <DIR>       # verify a skill's signature
```

## wirken cron

Manage scheduled cron jobs. Jobs send a message to an agent on a schedule.

```
wirken cron create <SCHEDULE> <MESSAGE> [OPTIONS]
wirken cron list [--agent <ID>]
wirken cron delete <JOB-ID>
wirken cron pause <JOB-ID>
wirken cron resume <JOB-ID>
```

| Option | Description |
|--------|-------------|
| `--agent <AGENT>` | Agent to run the job (default: "default") |
| `--description <TEXT>` | Description of the job |

Schedule format is standard 6-field cron: `sec min hour day month weekday`. Examples:
- `0 0 9 * * *` every day at 9:00 AM
- `0 */30 * * * *` every 30 minutes
- `0 0 0 * * Mon` every Monday at midnight

## wirken audit

Query and verify the audit log.

```
wirken audit log [OPTIONS]
wirken audit verify
```

| Option | Description |
|--------|-------------|
| `--action <ACTION>` | Filter by action type (e.g., "exec", "credential.access") |
| `--channel <CHANNEL>` | Filter by channel |
| `-n, --limit <N>` | Number of events to show (default: 50) |

`audit verify` checks the SHA-256 hash chain for tamper detection.

## wirken sessions

Manage and verify conversation sessions.

```
wirken sessions list [--channel <CHANNEL>]
wirken sessions close <SESSION-ID>
wirken sessions verify <SESSION-ID>
```

`verify` replays the session log, re-checks per-session hash chain integrity, recomputes message hashes at each LlmRequest event, and re-executes deterministic tools (read_file, list_files) against the current workspace. Reports events as verified, unverifiable, or divergent.

## wirken permissions

Manage tool approval records.

```
wirken permissions list [--agent <AGENT>]
wirken permissions revoke <KEY> [--agent <AGENT>]
```

## wirken credentials

Manage encrypted credentials in the vault.

```
wirken credentials list      # metadata only, no secrets shown
wirken credentials rotate <NAME>
```

## wirken doctor

Run diagnostics. Checks provider config, vault access, adapter registration, and Docker availability.

```
wirken doctor
```
