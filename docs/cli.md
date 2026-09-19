# CLI reference

Command surface only. Mechanisms live on their owning pages and are linked
rather than restated.

## wirken setup

Interactive wizard: provider, channels, credentials, service, sandbox, audit.

| Option | Description |
|--------|-------------|
| `--install-service` | Install as a systemd (Linux) or launchd (macOS) service |
| `--uninstall-service` | Remove the system service |
| `--org <URL>` | Pull provider, SIEM, MCP and permission config from a company endpoint. See [enterprise.md](enterprise.md) |

## wirken run

Starts the gateway. Spawns adapter processes, serves WebChat, accepts
connections.

| Option | Description |
|--------|-------------|
| `-p, --port <PORT>` | WebChat port (default: 18790) |

## wirken ask

Send a message to an agent and print the response. No channel setup needed.

```bash
wirken ask -m "your message" [--agent <AGENT>]
```

`--persona` is an interchangeable alias for `--agent`; every persona is an
`AgentConfig` row keyed by its name. Default: `default`.

When stdin is a terminal, an approval gate prompts for Tier 3 actions and
reads one line: `y` or `yes` approves, anything else denies, and text after a
space is recorded as the denial reason. A piped or redirected `wirken ask`
gets no gate and short-circuits with a terminal deny, so a script does not
hang on a prompt nobody will answer. `WIRKEN_ASK_APPROVAL_TIMEOUT_S` sets the
read deadline (default 60).

## wirken channel

```bash
wirken channel add <CHANNEL>     # telegram, discord, slack, teams, matrix,
                                 # signal, google-chat, imessage, whatsapp
wirken channel list
wirken channel remove <CHANNEL>
```

Per-channel prompts, vault entries and limits: [channels.md](channels.md).

## wirken agents

```bash
wirken agents add                        # wizard, or --id/--provider/--model for scripted use
wirken agents list
wirken agents remove <ID>
wirken agents bind <AGENT> <CHANNEL>
wirken agents set <ID> [--model M] [--base-url U] [--tools-enabled true|false|auto] [--api-key]
wirken agents set-egress <ID> --channel C --mode none|allowlist|open [--domains "a,b"]
wirken agents allow-subagent <PARENT> <CHILD> [--tools T] [--max-tier tier1|tier2|tier3]
                                              [--max-rounds N] [--max-runtime S]
wirken agents deny-subagent <PARENT> <CHILD>
```

`--api-key` prompts for the value rather than taking it on the command line,
so it does not reach shell history or the process table. Defaults for
`allow-subagent`: no tools, `tier1`, 5 rounds, 30s. See
[multi-agent.md](multi-agent.md) and [egress.md](egress.md#sandbox-egress).

## wirken persona

Operator-facing bundle of an agent config plus an optional preset. See
[multi-agent.md](multi-agent.md#personas).

```bash
wirken persona create <NAME> [--preset P] [--provider P] [--model M] [--base-url U]
                             [--credential C] [--channel C]... [--allow-subagent A]...
wirken persona list
wirken persona show <NAME>
wirken persona edit <NAME> (--preset P | --clear-preset) [--provider P] [--model M]
                           [--base-url U] [--credential C] [--channel C]... [--display-name D]
wirken persona delete <NAME>
```

`edit` requires at least one field flag. `--preset` and `--clear-preset` are
mutually exclusive. `delete` leaves the workspace and per-agent skill
directories on disk.

## wirken preset

```bash
wirken preset list
wirken preset install <NAME>
wirken preset schedule <NAME>      # daily cron entry for the preset's orchestrator
wirken preset unschedule <NAME>
```

Schedule and unschedule are Linux and macOS only.

## wirken skills

```bash
wirken skills search <QUERY>
wirken skills install <NAME>
wirken skills list
wirken skills sign <DIR> [--root-key <OFFLINE_ROOT_SEED>]
wirken skills verify <DIR> [--strict]
wirken skills trust-root <PUBKEY_HEX>
wirken skills migrate [PATH] [--dry-run]
```

`--strict` on `verify` treats a self-signed bundle as a failure and exits 1.
`trust-root` installs an operator root so the loader requires delegation.
`migrate` rewrites deprecated `metadata.openclaw.*` keys, backing each file up
first. See [signing.md](signing.md#skill-signing) and [skills.md](skills.md).

## wirken mcp

```bash
wirken mcp authorize <SERVER> [--scope ID]... | [--no-scopes] | [--all-scopes]
wirken mcp sign <SERVER>
wirken mcp verify [<SERVER>]
```

See [mcp.md](mcp.md) and [credentials.md](credentials.md).

## wirken hooks

```bash
wirken hooks register <ID> <PUBKEY_HEX> --type <observe|veto|egress>
```

See [enforcement-model.md](enforcement-model.md#veto-and-egress-hooks) and
[siem-forwarder.md](siem-forwarder.md#observe-hook).

## wirken approvers

Channel-adapter approver allowlist and per-adapter approval chat.

```bash
wirken approvers add <ADAPTER_ID> <USER_ID> [--display NAME]
wirken approvers list [--adapter A]
wirken approvers remove <ADAPTER_ID> <USER_ID>
```

## wirken cron

```bash
wirken cron create <SCHEDULE> <MESSAGE> [--agent A] [--description T]
wirken cron list [--agent A]
wirken cron delete|pause|resume <JOB-ID>
```

Standard 6-field cron: `sec min hour day month weekday`. `0 0 9 * * *` is
daily at 09:00, `0 */30 * * * *` every 30 minutes, `0 0 0 * * Mon` Mondays at
midnight.

## wirken audit

```bash
wirken audit log [OPTIONS]
wirken audit verify [--require-signed] [--anchor HEX_OR_PATH]... [--format human|json]
wirken audit verify-attestations [--agent AGENT]
wirken audit acknowledge --all
```

Flags, exit codes, JSON schema and what each verification proves:
[audit-cli.md](audit-cli.md).

## wirken sessions

```bash
wirken sessions list [--channel C] [--parent SESSION_ID]
wirken sessions close <SESSION-ID>
wirken sessions verify <SESSION-ID> [--strict] [--with-parent]
```

What `verify` replays and what a `tools_hash` attests:
[audit-cli.md](audit-cli.md#wirken-sessions-verify).

## wirken permissions

```bash
wirken permissions list [--agent A]
wirken permissions approve <KEY> [--agent A] [--session ID] [--expires-in-days N]
wirken permissions revoke <KEY> [--agent A]
wirken permissions list-pending [--agent A]
wirken permissions pending list
wirken permissions pending show <REQUEST_ID>
wirken permissions pending approve <REQUEST_ID>
wirken permissions pending deny <REQUEST_ID> [REASON]
```

`list-pending` walks the audit log for historical denials with no matching
approval. The `pending` subgroup operates on the gateway's in-memory queue of
in-flight requests and resumes the awaiting agent task; ids accept any prefix
unique to one row. Which keys are storable, and the grant window:
[permissions-and-identity.md](permissions-and-identity.md).

## wirken credentials

```bash
wirken credentials list
wirken credentials add <NAME> [--channel C] [--stdin | --value-file FILE] [--host HOST]...
wirken credentials rotate <NAME> [--stdin | --value-file FILE]
wirken credentials show <NAME>
wirken credentials remove <NAME>
wirken credentials rescope <NAME> [--scope ID]... | [--no-scopes] | [--all-scopes]
```

Every verb takes the vault passphrase from `WIRKEN_VAULT_PASSPHRASE` when set
and prompts only when it is not, so `add` and `rotate` complete with no
terminal. `--host` binds a credential to hosts `http_request` may send it to;
see [egress.md](egress.md#credential-host-binding). Scopes and redaction:
[credentials.md](credentials.md).

## wirken vault

```bash
wirken vault reset
```

Destroys the device key and all stored credentials. Used after a forgotten
passphrase, where the vault refuses to overwrite a keychain it cannot unwrap.
Requires typing `reset`.

## wirken zirkel

```bash
wirken zirkel run
wirken zirkel bind --channel C --conversation ID [--agent A] [--force]
wirken zirkel unbind [--agent A]
wirken zirkel status
wirken zirkel auth-set --source SOURCE
wirken zirkel auth-list
wirken zirkel calibrate [--run-id R] [--buckets N] [--by overall|source|keyword]
```

See [zirkel.md](zirkel.md).

## wirken lyrik

```bash
wirken lyrik run --target DIR --run RUN_ID [--use-fixture FINDINGS_JSON]
wirken lyrik report [--format sarif] (--findings PATH | --run RUN_ID) --output PATH
wirken lyrik validate --path PATH
```

See [lyrik.md](lyrik.md).

## wirken import

```bash
wirken import <ARCHIVE> [--sealed]
```

`--sealed` declares the source account closed; a sealed source imports once
and refuses afterwards, and there is no unseal. See
[imported-archives.md](imported-archives.md).

## wirken doctor

```bash
wirken doctor
```

Checks the data directory, provider config, vault access, adapter registry,
MCP signing, the audit log and its alarm log, the attestation chain across all
sessions, Docker, and gVisor.
