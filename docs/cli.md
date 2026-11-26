# CLI reference

Command surface only. Mechanisms live on their owning pages and are linked
rather than restated.

A subcommand that changes authority or configuration refuses to run inside
a Wirken `exec` (`WIRKEN_EXEC` set) and records an `operator_command_refused`
row on the `gateway-operator` lane: `permissions approve`, `revoke`,
`pending approve` and `pending deny`; `skills install`, `sign`, `sign-index`,
`trust-root`, `restore-bundled` and `migrate`; `mcp authorize` and `sign`;
every `credentials` subcommand but `list` and `show`; `vault reset` and
`migrate`; `audit acknowledge`; every `agents` subcommand but `list`;
`channel add` and `remove`; `cron create`, `delete`, `pause` and `resume`;
`hooks register` and `unregister`; `persona create`, `edit` and `delete`;
`preset install`, `schedule` and `unschedule`; `webchat open`; `zirkel bind`,
`unbind` and `auth-set`; `proxy token issue` and `revoke`, `proxy archive
redact`, and `proxy identity grant-set set` and `remove`, `map` and `unmap`;
`setup`; `import`. Other reads run, and so does `sessions close`,
which only takes authority away. `sessions search`, `sessions export` and
`sessions verify` are reads and are refused all the same: inside an `exec`
they would read sessions, and an archive's bodies, to the agent that ran
them.

## wirken setup

Interactive wizard: provider, channels, credentials, service, sandbox, audit.

| Option | Description |
|--------|-------------|
| `--install-service` | Install as a systemd (Linux) or launchd (macOS) service |
| `--uninstall-service` | Remove the system service |
| `--org <URL>` | Pull provider, SIEM, MCP and permission config from a company endpoint. See [enterprise.md](enterprise.md) |

## wirken run

Starts the gateway. Spawns adapter processes, serves WebChat, accepts
connections. With a `proxy.json` in the data directory it also serves the
proxy listener, on 127.0.0.1:18791 by default ([proxy.md](proxy.md)).

| Option | Description |
|--------|-------------|
| `-p, --port <PORT>` | WebChat port (default: 18790) |
| `--provider <PROVIDER>` | Run the default agent against this provider for this run only. Changing the provider needs `--model` too |
| `--model <MODEL>` | Run the default agent against this model for this run only |
| `--base-url <BASE_URL>` | API base URL for this run |

### What WebChat serves

Every `/api` route takes a credential before it does anything: the cookie a
login sets, or the gateway's session token as `Authorization: Bearer <token>`
for a non-browser caller. A request with neither, or with a wrong one, is
answered 401; a token in a query string is not a credential. The session
token is made fresh at every start and written, with the port, to
`<data_dir>/webchat.json` at mode 0600; it is never logged and never put in a
URL. Log in with `wirken webchat open` (below). The page itself, `GET /`, holds
no data and is served to anyone; it shows how to log in when the API answers
401. Every response carries `Content-Security-Policy: frame-ancestors 'none'`
and `X-Frame-Options: DENY`.

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

## wirken webchat

```bash
wirken webchat open [--browser]
```

Asks the running gateway for a one-time login token, using the session token
in `webchat.json`, and prints the login URL; `--browser` opens it too. The URL
carries only the login token. `GET /login` exchanges it, once, for an
`HttpOnly; SameSite=Strict` cookie and redirects to the page, so the token
leaves the address bar; a second use, or a use more than 60 seconds after it
was minted, is refused. Run the command again for another login. Each login
has a short public label, and a decision made in that browser is recorded with
the actor `webchat:<label>`; a bearer caller's is `webchat:bearer`. Cookies
last until the gateway restarts.

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

`wirken ask` runs no gateway, so the agent it builds cannot spawn
sub-agents: a `spawn_subagent` call returns an error saying so, naming
`wirken chat` or a channel as the route, and the turn goes on. Children are
woken by the gateway, which is what those routes run under.

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

A message the gateway refuses runs no turn, so no reply comes. The gateway
tells the chat instead, after the row that records the refusal: the
transcript shows the refusal and its reason, `agent_stopped` for a message to
an agent `wirken agents stop` stopped, and the chat takes the next message.

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
| `/help` | The keys screen, as Ctrl+G opens it |
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
else typed, is recorded as the reason. Enter alone refuses, so approving is
never the default. The card is the one every surface renders, line by line:
the request, the action key, the arguments that will run, where an `exec`
runs, the runtime it runs under and the message the turn replies to as the
gateway established them; what the model said beside the call comes last,
under its own rule labeled `model's claim (unverified):`, indented and in the
agent's color. A draft being typed when a card
arrives is set aside and comes back once the cards are answered; cards that
arrive together are asked in order.

While a card is open it spans the window at every width: the sidebar and the
panels are put away, its title rule names the tier and the tool, every field
wraps, the instruction is stated once, and `Closes in Ns.` is on the rule over
the answer. The transcript keeps the rows the card leaves, with the meter in
its top border, or one row saying the conversation is hidden. A card that does
not fit gives up its spacer row, then cuts its long values, the reply-to
first and the arguments last, each with a count such as `… +2 rows`; its title
rule says how many rows were cut, and a two-row notice takes the
instruction's place. A cut card takes a refusal only. Under 15 rows of window
the card is one line, `This request cannot be approved at this size. Enter
refuses.`, and Enter there refuses with no reason. The decision is recorded with
`approved_via` / `denied_via` `{"kind":"channel_adapter","channel":"terminal"}`
and, for an approval, `approved_by` `<user> (operator key <key id>)`.

Cards come one at a time, in the order the gateway asked. While more than
one waits, the card in front says on its bottom border how many more wait
after it, and every waiting call's line in the transcript reads `needs
approval`.

The gateway waits `WIRKEN_TERMINAL_APPROVAL_TIMEOUT_S` seconds (default 300)
for a decision. The card closes a few seconds before that and stays in
front as expired, in a gray single rule titled `approval expired`, its
fields dimmed and no answer field, until Esc puts it away, also when other
cards wait behind it. Enter does nothing there, so a late `y` and Enter
answers nothing and moves nothing on, and the tool's line reads `expired`.
Put away, it leaves a note in the transcript; the chain records the timeout as a `PermissionDenied` with
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
chain, newest first, each with its time in a column at the right. Text is
cut only when it does not fit, with one `…`, and a model name is cut in its
middle so its version stays. Ctrl+F filters it by agent, model or first
message; a search that matches nothing says so and that Esc clears it.
Enter on a conversation resumes it, its messages read back from the
session chain. A conversation of another agent opens a new connection for
that agent. The chat opens no store itself: all of this comes from the
gateway over the terminal connection.

The panels take 36 columns and the sidebar 30, and the transcript keeps
at least 54, so from 120 columns both sit beside the transcript. Both
start shown; Ctrl+B and Ctrl+P hide and show them, and each says so on its
column's bottom border. Ctrl+K sits on the Audit section's rule. Narrower
is the compact layout: the transcript takes the whole width, its top
border carries a meter of three numbers from the panels, the context used,
the audit rows and the refusals when there are any, and its bottom border
reads `Ctrl+B conversations · Ctrl+P panels`. Ctrl+B and Ctrl+F open the agents and
conversations over the transcript, with the search and what is typed in
it, and Ctrl+P opens the panels; Esc closes either. A search open when the
window narrows or widens moves with it.

The transcript and the draft are one box, with the draft under a rule.
Once the conversation is taller than the window, a thumb in the box's right
border shows where the view is, and the rule's right end says how many rows
are above and below, and names End, the key back to the latest row.

The bottom row is the key bar, across the whole width at every size. It shows
the keys for what is on screen, most needed first, and drops them from the
right as the window narrows; Ctrl+G, the keys screen, stays at its right
whatever the width. Scrolled up, End leads; at a card it lists the keys other
than the answer, which the card states.

| Key | Action |
|-----|--------|
| Enter | Send the message, or answer the card |
| Ctrl+J | New line in the message |
| ↑ / ↓, mouse wheel | Scroll the transcript a few rows; in the sidebar search, move the selection. The wheel arrives as ↑ and ↓ (the chat turns on the terminal's alternate scroll), and text can still be selected |
| PgUp / PgDn | Scroll the transcript a screen less two rows, so two rows stay in view; on a Mac laptop, Fn+↑ / Fn+↓ |
| End | Scrolled up, back to the latest row. At the latest row, the end of the draft |
| Home | The start of the draft |
| Ctrl+A / Ctrl+E | The start / the end of the draft |
| ← / → | Move in the draft |
| Backspace / Delete | Delete before / after the cursor |
| Ctrl+U | Clear the draft, or the card's answer |
| Ctrl+F | Search the conversations, in the sidebar from 120 columns and over the transcript under it; arrows select, Enter opens, Esc leaves |
| Ctrl+N | New conversation with the same agent |
| Ctrl+B / Ctrl+P | Show or hide the sidebar / the panels; under 120 columns, open them over the transcript. Inside tmux, Ctrl+B is tmux's prefix by default and the first press does not reach the chat: press Ctrl+B twice, or rebind the prefix |
| Ctrl+K | Verify this conversation's chain |
| Ctrl+G / F1 | The keys screen: every key and command in groups, over the whole screen. Typing filters it, ↑ and ↓ scroll it, Esc or Ctrl+G closes it; keys that do not apply now are dimmed. The key bar keeps Ctrl+G at its right at every width |
| Ctrl+C | Leave the chat |
| Esc | Leave the sidebar search; put away an expired card |
| y | On a card, with Enter, approves; n, a reason or anything else refuses, and Enter alone refuses |

The chat takes no mouse capture, so text is selected and copied as in any
terminal. A selection runs the width of the screen, so it takes in the
sidebar and the panels beside the transcript; hide them with Ctrl+B and
Ctrl+P to copy transcript lines alone.

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
wirken agents stop <ID> [--revoke-all]
wirken agents resume <ID>
wirken agents bind <AGENT> <CHANNEL>
wirken agents set <ID> [--model M] [--base-url U] [--tools-enabled true|false|auto] [--api-key]
                       [--exempt-exec-mcp-output true|false]
wirken agents set-egress <ID> --channel C --mode none|allowlist|open [--domains "a,b"]
wirken agents allow-subagent <PARENT> <CHILD> [--tools T] [--max-tier tier1|tier2|tier3]
                                              [--max-rounds N] [--max-runtime S]
wirken agents deny-subagent <PARENT> <CHILD>
```

`--exempt-exec-mcp-output true` stops `exec` and MCP output from sending the
agent's `http_request` to the operator. It does not change sandbox egress
([egress.md](egress.md#after-a-restricting-read)).

An agent in plan mode (`--auth plan`) runs on a sign-in stored by `wirken
credentials authorize`, named by `--credential` (default `openai-plan`). It
takes no `--api-key-env` or `--base-url`, and `agents set` refuses `--api-key`
and `--base-url` on it; `agents set --model list` lists the signed-in
account's models.

A running `wirken run` keeps the agent config it started with: a change made
with `agents` takes effect at its next start, and `agents set` says so.
`stop` and `resume` are the exception: they write the permission store, which
is read on every check, so they hold at once, with the gateway down and across
restarts. See [permissions-and-identity.md](permissions-and-identity.md#stopping-an-agent).

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
wirken skills sign <DIR> [--key <SEED>] [--root-key <OFFLINE_ROOT_SEED>]
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
signature passed: `delegated`, `shipped` for a bundled preset skill, `staged`,
`self-signed` or `no` in a build without a compiled root. One that did not load shows `refused:` and the reason, and a bundled
copy that `restore-bundled` would fix says so.
`--strict` on `verify` treats a self-signed bundle as a failure and exits 1.
`trust-root` installs an operator root in place of the compiled one. It
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

## wirken proxy

```bash
wirken proxy token issue <NAME> [--upstream U] [--upstream U2] [--model M]
                               [--ceiling-usd N] [--ceiling-calls N] [--window hour|day|week]
                               [--mcp-server S] [--agent A]
wirken proxy token revoke <ID-OR-NAME>
wirken proxy token list
wirken proxy sessions [--token ID-OR-NAME]
wirken proxy archive redact (<SHA256> | --session <LANE>) --reason <WHY>
wirken proxy identity grant-set set <NAME> [--upstream U] [--model M]
                               [--ceiling-usd N] [--ceiling-calls N] [--window hour|day|week]
                               [--mcp-server S] [--agent A]
wirken proxy identity grant-set remove <NAME>
wirken proxy identity map <GRANT-SET> (--claim-value <VALUE> | --subject <SUB>)
wirken proxy identity unmap (--claim-value <VALUE> | --subject <SUB>)
wirken proxy identity list
```

`issue`, `revoke`, `redact` and every `identity` subcommand but `list` run at
a terminal and refuse inside a Wirken `exec`. A token or a grant set needs
`--upstream`, `--mcp-server` or both. See
[inference-proxy.md](inference-proxy.md), for `--mcp-server`
[proxy-mcp.md](proxy-mcp.md), and for `identity`
[proxy-identity.md](proxy-identity.md).

## wirken approvers

Channel-adapter approver allowlist and per-adapter approval chat.

```bash
wirken approvers add <ADAPTER_ID> <USER_ID> [--display NAME]
wirken approvers list [--adapter A]
wirken approvers remove <ADAPTER_ID> <USER_ID>
wirken approvers set-chat <ADAPTER_ID> <CONVERSATION_ID>
wirken approvers show-chat <ADAPTER_ID>
```

The gateway reads the allowlist and the approval chat on every decision, so a
change applies without a restart. Each `add`, `remove` and `set-chat` is an
`approver_added`, `approver_removed` or `approval_chat_set` row on the signed
`gateway-approvers` lane; `set-chat`'s row names the chat it replaced. An add
or a set-chat whose row cannot be written is undone. Every subcommand refuses
inside a Wirken `exec` and records the refusal on that lane.

## wirken senders

The inbound sender allowlist: who may drive an agent through a channel
adapter. A channel with no entries drops every message on it.

```bash
wirken senders add <CHANNEL> <SENDER_ID> [--group] [--label NAME]
wirken senders remove <CHANNEL> <SENDER_ID> [--group]
wirken senders list [CHANNEL]
wirken senders refused [CHANNEL] [-n N]
```

`CHANNEL` is one of `telegram`, `discord`, `slack`, `teams`, `matrix`,
`whatsapp`, `signal`, `google-chat`, `imessage`. With `--group` the id is a
conversation id and admits every member of it. `refused` lists the most recent
messages the gateway dropped, newest first, with the sender and conversation
ids to admit. Changes apply to the next message without a restart. Every
subcommand refuses inside a Wirken `exec` and records the refusal on the
`gateway-senders` lane. See
[channels.md](channels.md#who-reaches-the-agent).

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
wirken sessions verify <SESSION-ID> [--strict] [--with-parent] [--with-children] [--skip-archive]
wirken sessions export <SESSION-ID> --format atif [--output FILE] [--skip-archive]
wirken sessions search <TEXT> [--agent A] [--token T] [--channel C] [--tool T] [--session ID]
                              [--since TS] [--until TS] [-n LIMIT] [--format text|json] [--skip-archive]
```

What `verify` replays and what a `tools_hash` attests:
[audit-cli.md](audit-cli.md#wirken-sessions-verify). A proxy session
(`wirken proxy sessions` lists them) is verified against its chain and its archived bodies,
and `export` writes a session as a trajectory file:
[proxy-archive.md](proxy-archive.md#verifying-a-proxy-session).
`search` finds text in the rows of every session and in archived proxied
bodies, cites each hit by session, row and chain hash, and refuses inside a
Wirken `exec`: [audit-cli.md](audit-cli.md#wirken-sessions-search).

## wirken permissions

```bash
wirken permissions list [--agent A]
wirken permissions approve <KEY> [--agent A] (--channel C | --session ID) [--expires-in-days N]
wirken permissions revoke <KEY> [--agent A] --channel C
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
wirken credentials add <NAME> [--channel C] [--stdin | --value-file FILE] [DESTINATIONS]
wirken credentials grant <NAME> DESTINATIONS
wirken credentials revoke <NAME> DESTINATIONS
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
terminal, except `grant` and `revoke`, which take it at a terminal only.
DESTINATIONS are `--host HOST` (port 443) or `--host HOST:PORT`, `--mcp-server NAME`, `--provider P --base-url
URL`, `--adapter ID`, `--plan` and `--archive HOST` (a proxy archive's bucket
endpoint); `--host`, `--mcp-server`, `--adapter` and `--archive` repeat. See
[credentials.md](credentials.md#where-a-credential-may-go). Scopes and
redaction: [credentials.md](credentials.md).

## wirken vault

```bash
wirken vault reset
wirken vault migrate [--edit FILE]
```

`reset` destroys the device key and all stored credentials. Used after a
forgotten passphrase, where the vault refuses to overwrite a keychain it cannot
unwrap. Requires typing `reset`.

`migrate` re-seals a vault from before destination binding, after a backup and
your `yes`; see [credentials.md](credentials.md#migrating-a-vault-from-2x).

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
wirken lyrik run --target DIR --run RUN_ID [--bench] [--use-fixture FINDINGS_JSON]
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

Checks the data directory, `provider.json`, that `vault.db` exists, the adapter registry,
MCP signing, the audit log and its alarm log, the attestation chain across all
sessions, Docker, and gVisor.
