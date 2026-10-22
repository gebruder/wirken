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

### What WebChat serves

Every route is bound to loopback and checks the `Host` header against the
loopback names for the bound port, which is what closes DNS rebinding. The
state-changing routes (`POST /api/chat`, `POST /api/approvals/{id}`,
`POST /api/verify`) also require a matching `Origin`; safe reads validate
one only when the browser sends it, because a browser omits it on a
same-origin GET.

Routes match on the request path with the query string taken off. They
used to match the request line up to the space after the path, so a
target carrying a query reached no route: `GET /api/approvals?c=<key>` is
the only request the page makes to that route, and it answered 404. With
it refused the page's approvals snapshot stayed null, which meant no
"awaiting you elsewhere" chip, no other-channel badge, no awaiting marker
in the rail, and no pending card restored after a reload however many
decisions were waiting.

The approval card is the one every surface renders: the action key, the
arguments the model sent, for an `exec` where it runs and under which
runtime, the message the turn replies to and, set apart, the model's own
words labeled `model's claim (unverified)`, all off the `ApprovalRequest`
event. See
[permissions](permissions-and-identity.md#what-an-approval-prompt-shows).

The About panel draws the capabilities of the conversation it is open on.
It asked `/api/capabilities` with no conversation key, so it always
showed the legacy conversation: a turn running in the conversation
being viewed read as idle, and a turn in the legacy one read as busy. It
sends the key now and reloads when a switch happens while it is open.

## wirken ask

Send a message to an agent and print the response. No channel setup needed.

```bash
wirken ask -m "your message" [--agent <AGENT>]
```

`--persona` is an interchangeable alias for `--agent`; every persona is an
`AgentConfig` row keyed by its name. Default: `default`.

When stdin is a terminal, an approval gate prompts for Tier 3 actions and
reads one line: `y` or `yes` approves, anything else denies, and text after a
space is recorded as the denial reason. The prompt says what is being
approved before it asks; see
[permissions](permissions-and-identity.md#what-an-approval-prompt-shows)
for what is on those lines and why. A piped or redirected `wirken ask`
gets no gate and short-circuits with a terminal deny, so a script does not
hang on a prompt nobody will answer. `WIRKEN_ASK_APPROVAL_TIMEOUT_S` sets the
read deadline (default 60). A prompt left unanswered past the deadline is a
denial: the model is told the action was refused and not executed, and the
chain records a `PermissionDenied` row with `approval timeout` as its reason.

## wirken chat

A full-screen chat with an agent in the terminal, through the running
gateway.

```bash
wirken chat [--agent <AGENT>]
```

The chat is a client of `wirken run`, not a second gateway. It connects to
`gateway.sock` as the `terminal` channel and refuses, starting nothing, when
no gateway answers there: start one with `wirken run` or start the service
`wirken setup --install-service` installed. On a first run with no provider
configured it runs `wirken setup` before it takes the screen. It needs a
terminal on stdin and stdout; from a script or a pipe it refuses and points
to `wirken ask -m`.

Every message takes the path any channel's message takes: the injection
scan, the `message.inbound` row, the session store, the router, the tier
gate, and the agent's session `{agent}/terminal/c-<id>`, a new conversation
each time the chat starts. `--agent` (alias `--persona`) picks the agent;
without it the router picks, as for any channel, and an agent the gateway
does not know is refused before the screen opens.

A draft that starts with one of these words is a command, run by the chat and
never sent to the model. It counts only as the first word, by its exact
lowercase name; text after it is ignored. Any other `/word` (a skill, `/HELP`,
`/etc/hosts`) goes to the agent as typed.

| Command | What it does |
|---|---|
| `/status` | Every panel, as the gateway has them now |
| `/context`, `/cost`, `/tools`, `/approvals`, `/audit` | That one panel |
| `/verify` | Checks this conversation's chain, as Ctrl+K does |
| `/clear` | A new conversation, as Ctrl+N opens one; refused mid-turn |
| `/help` | The command list and the keys |
| `/quit`, `/exit` | Leaves the chat, as Ctrl+C does |

Commands run during a turn. `/clear` waits for the turn to end, as Ctrl+N does.

Agent replies are drawn as light Markdown: headings without their hashes,
bullets and numbered items with a hanging indent, fenced code behind a rule
with its language as a label, `inline code`, **bold** and *italic*, links as
their text and then their address, horizontal rules, and pipe tables. A table
draws its columns under a bold header, ruled off from the body. When it is wider
than the transcript its cells wrap; when even that does not fit, each row is one
line with its cells apart. Blockquotes, images and HTML are shown as written. Your own
messages, tool output and the approval card stay plain.

Below 90 columns the panels take one narrow column of 24, beside a transcript
of at least 40. Below 64 columns they are not drawn, and the status line says
how many columns they need.

The socket is mode 0600 and the gateway checks the peer's user, as for every
connection. The chat then answers the gateway's challenge with the operator
key (`<data_dir>/operator/operator.key`), the key `wirken permissions
pending` signs with; a client without it is refused and recorded as
`adapter.handshake_rejected`. The `message.inbound` row and the session's
`UserMessage` name the sender as `operator:<key id>`, and the connection is
recorded on the adapter lane as `AdapterConnect` and `AdapterDisconnect` with
channel `terminal`.

The reply streams in as the model writes it, and each tool call shows when
its row is on the chain and again when it finishes. An approval the turn
needs is asked on a card at the terminal whose message started the turn
(`TerminalApprovalGate`), with the lines every approval surface shows; see
[permissions](permissions-and-identity.md#what-an-approval-prompt-shows).
The card takes no keys for its first 0.7 seconds. Only a lone `y` or `yes`
approves; anything else refuses, and text after `n` or `no`, or anything
else typed, is recorded as the reason. Enter with nothing typed refuses, and
the two answers are drawn alike, so approving is never the default. The card
is the one every surface renders, line by line: the request, the action key,
the arguments that will run, where an `exec` runs, the runtime it runs under
and the message the turn replies to as the gateway established them; what
the model said beside the call is drawn apart and labeled `model's claim
(unverified)`. A draft being typed when a card
arrives is set aside and comes back once the cards are answered; cards that
arrive together are asked in order. The decision is recorded with
`approved_via` / `denied_via` `{"kind":"channel_adapter","channel":"terminal"}`
and, for an approval, `approved_by` `<user> (operator key <key id>)`.

The gateway waits `WIRKEN_TERMINAL_APPROVAL_TIMEOUT_S` seconds (default 300)
for a decision. The card closes a few seconds before that and stays on
screen as expired until Enter or Esc puts it away, so a late `y` answers
nothing; the chain records the timeout as a `PermissionDenied` with
`approval timeout`. If the chat disconnects while a card is open, the request
is withdrawn and recorded as refused with the reason
`terminal client disconnected`.

The runtime is the one the gateway's sandbox settings for the agent give
`exec`: `gVisor (runsc)` under `"mode": "gvisor"`, Docker's default runtime
(runc) under `exec-only`, and the host under `off`. There is no fallback
between them: a `gvisor` mode whose `runsc` runtime is missing refuses
`exec`. The gateway sends the value; the chat names it and never guesses.

Beside the transcript, panels show what the gateway reports for the
conversation: Environment (data dir, agent and model, exec runtime and
sandbox mode), Context (tokens of the last call against the model's
window), Cost and tokens (calls, tokens in and out, the cost or `uncosted`,
the budget in force), Audit (rows and chain heads; Ctrl+K has the gateway
verify the conversation's chain and signed heads and shows the result),
Approvals (approved and denied on this conversation, the agent's stored
grants) and Tools (how many, how many ask first, skills, names). A sidebar
lists the agents with their models and every terminal conversation on the
chain, newest first; Ctrl+F filters it by agent, model or first message,
and Enter on a conversation resumes it, its messages read back from the
session chain. A conversation of another agent opens a new connection for
that agent. The chat opens no store itself: all of this comes from the
gateway over the terminal connection.

The panels take 36 columns and the sidebar 30, and the transcript keeps
at least 54, so both are drawn from 120 columns. From 90 the panels are
drawn and the sidebar yields to them; below 90 the panels are not drawn.
Either way the status line says what is hidden and how many columns it
needs. Both start shown; Ctrl+B and Ctrl+P toggle them.

| Key | Action |
|-----|--------|
| Enter | Send the message, or answer the card |
| Ctrl+J | New line in the message |
| PgUp / PgDn | Scroll the transcript |
| Ctrl+U | Clear the message or the answer |
| Ctrl+F | Search the sidebar; arrows select, Enter opens, Esc leaves |
| Ctrl+N | New conversation with the same agent |
| Ctrl+B / Ctrl+P | Show or hide the sidebar / the panels |
| Ctrl+K | Verify this conversation's chain |
| Ctrl+C | Leave the chat |

Log output written while the screen is up is held and printed to stderr when
the chat exits. The chat is not available on Windows.

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
wirken agents add --id ID --provider openai --model SLUG --auth plan [--credential ENTRY]
wirken agents list
wirken agents remove <ID>
wirken agents bind <AGENT> <CHANNEL>
wirken agents set <ID> [--model M] [--base-url U] [--tools-enabled true|false|auto] [--api-key]
wirken agents set-egress <ID> --channel C --mode none|allowlist|open [--domains "a,b"]
wirken agents allow-subagent <PARENT> <CHILD> [--tools T] [--max-tier tier1|tier2|tier3]
                                              [--max-rounds N] [--max-runtime S]
wirken agents deny-subagent <PARENT> <CHILD>
```

An agent in plan mode (`--auth plan`) runs on a sign-in stored by `wirken
credentials authorize`, named by `--credential` (default `openai-plan`). It
takes no `--api-key-env` or `--base-url`, and `agents set` refuses `--api-key`
and `--base-url` on it; `agents set --model list` lists the signed-in
account's models.

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
wirken skills sign-index <INDEX> --root-key <OFFLINE_ROOT_SEED> --skills-dir <CHECKOUT> [--url-prefix <URL>]
wirken skills verify <DIR> [--strict]
wirken skills trust-root <PUBKEY_HEX> [--yes]
wirken skills restore-bundled
wirken skills migrate [PATH] [--dry-run]
```

`search` and `install` read the skill index at
`https://raw.githubusercontent.com/gebruder/wirken-skills/main/index.json`, or
`WIRKEN_SKILLS_INDEX` when set. No public index is published yet: that URL
returns 404, and both commands stop with an error naming it.
`list` prints a row for every installed skill. One that loaded shows how its
signature passed: `self-signed`, `delegated`, or `no` under the unsigned
opt-in. One that did not load shows `refused:` and the reason, and a bundled
copy that `restore-bundled` would fix says so.
`--strict` on `verify` treats a self-signed bundle as a failure and exits 1.
`trust-root` installs an operator root so the loader requires delegation. It
first lists the installed skills that would stop loading under that root and
asks for confirmation; `--yes` skips the question. `restore-bundled` gives
each installed bundled skill whose `SKILL.md` is unmodified the signature files
shipped with it, which is what makes those copies load under the project root.
It installs nothing else and leaves the root alone.
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
wirken sessions verify <SESSION-ID> [--strict] [--with-parent] [--with-children]
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
wirken credentials authorize [ENTRY] [--port P] [--no-browser]   # plan sign-in, ENTRY defaults to openai-plan
wirken credentials sign-out [ENTRY]
wirken credentials export-plan [ENTRY] --out FILE
wirken credentials import-plan [ENTRY] --from FILE
```

`authorize` signs in to the `openai` provider's plan mode in the browser and
stores the sign-in; `sign-out` clears its tokens and revokes the session, keeping the
registration; `export-plan` and `import-plan` move it to a host without a
browser. `remove` on a plan entry revokes it first, and `rescope` on one signs
in again. See [credentials.md](credentials.md#plan-sign-in-openai).

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

See [lyrik.md](lyrik.md). Brocard rejections, as they appear in `findings.json`, SARIF and the run summary: [lyrik-brocards.md](lyrik-brocards.md).

## wirken import

```bash
wirken import <ARCHIVE> [--sealed]
```

`--sealed` declares the source account closed; a sealed source imports once
and refuses afterwards, and there is no unseal. See
[imported-archives.md](imported-archives.md).

## wirken update

```bash
wirken update --check
wirken update [--to <VERSION>] [--allow-downgrade] [--base-url <URL>]
wirken update --rollback
```

Checks for, installs, or rolls back a signed release. Runs only when asked.
Install and rollback need a terminal and a stopped gateway, and ask for a
typed confirmation. `--base-url` must be on a loopback address or be the
mirror in `<data_dir>/update.json`. See [update.md](update.md).

## wirken status

```bash
wirken status
```

Prints the version, commit, dirty flag, build age from the commit's
timestamp, target and binary path. Makes no network request.

## wirken doctor

```bash
wirken doctor
```

Checks the data directory, provider config, vault access, adapter registry,
MCP signing, the audit log and its alarm log, the attestation chain across all
sessions, Docker, and gVisor.
