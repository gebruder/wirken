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

The `add` command prompts for the channel's primary token (and Slack's app token). Channels that need additional fields (Teams app ID, Matrix homeserver/username, Signal phone, BlueBubbles password, WhatsApp phone-number-id/verify-token/app-secret) are wired up by `wirken setup`'s per-channel sub-flows. WhatsApp's setup flow is interactive and collects the four Cloud API credentials (access token, phone number ID, verify token, app secret); see [WhatsApp channel docs](channels/whatsapp.md) for the vault entries it writes.

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

### What a tools_hash attests

Each `LlmRequest` row records a `tools_hash` over the tools the model was offered, and a `tools_hash_version` naming the rules it was computed under. `verify` recomputes each row under its own version, so a session recorded under older rules is not re-judged against rules that postdate it.

| Version | Covers | Does not cover |
| --- | --- | --- |
| `v1` | Base tools, MCP definitions, wasm skill definitions, the phase tools, filtered by the per-skill permission profile. | `spawn_subagent`, so a configured sub-agent ceiling was outside the attestation. The sub-agent `restrict_tools` clamp, so a child's narrowed tool set was outside it too. |
| `v2` | Everything `v1` covers, plus `spawn_subagent` when a ceiling is configured, plus the `restrict_tools` clamp. One builder produces both the offered set and the recomputation, so the hash attests exactly what the model saw. |  |

Rows written before the version field existed read as `v1`, which is what they are. Nothing rewrites a stored row.

A sub-agent session (`{parent}#sub-N`) verifies on its own. At spawn the child writes a `SubagentSessionBound` row on its own chain, before its first `LlmRequest`, naming the agent it was woken as and the tool set its parent's ceiling narrowed it to. `verify` reads the agent and the clamp from that row and prints which agent it resolved. The parent's chain is never opened; a child session verifies clean even when the parent's session is not present at all.

The parent's `SubagentSpawned` row is unchanged and records the same grant from the parent's side. The two are independent records; comparing them is a separate check that `verify` does not perform.

When a report covers any `v1` rows it prints a `tools_hash v1 rows` line with the count and says what those rows do not attest. A clean verify over `v1` rows is a narrower claim than a clean verify over `v2` rows, and the difference is exactly the sub-agent ceiling and clamp.

## wirken permissions

Manage tool approval records.

```
wirken permissions list [--agent <AGENT>]
wirken permissions approve <KEY> [--agent <AGENT>] [--session <SESSION_ID>] [--expires-in-days <DAYS>]
wirken permissions revoke <KEY> [--agent <AGENT>]
```

Only Tier 2 action keys can be approved: a shell verb on the Tier 2
allowlist, `file:<path>`, or `cross-conversation`. Tier 1 is allowed
without a stored grant and Tier 3 prompts on every use, so a stored row
for either would never be read by the gate.

`--expires-in-days` overrides the window for one grant. Without it a
persisted grant takes `default_expiry_days` from
`~/.wirken/permissions.json`, which defaults to 30. The flag is refused
alongside `--session`: a session grant is cleared on session end and
carries no window.

## wirken credentials

Manage encrypted credentials in the vault.

```
wirken credentials list      # metadata only, no secrets shown
wirken credentials add <NAME> [--stdin | --value-file FILE] [--host HOST]...
wirken credentials rotate <NAME> [--stdin | --value-file FILE]
wirken credentials show <NAME>
wirken credentials remove <NAME>
```

Every verb takes the vault passphrase from `WIRKEN_VAULT_PASSPHRASE` when
it is set and prompts only when it is not. With the variable set and the
value supplied by `--stdin` or `--value-file`, `add` and `rotate` complete
with no terminal.

## wirken doctor

Run diagnostics. Checks provider config, vault access, adapter registration, and Docker availability.

```
wirken doctor
```
