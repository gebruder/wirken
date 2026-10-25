# Channels

Each channel runs as its own OS process with its own Ed25519 IPC identity. An
adapter can deliver inbound frames and request outbound sends for its own
channel only; it cannot invoke tools, read another channel's sessions, or
reach another channel's credentials through the IPC surface.

```bash
wirken channel add <channel>   # telegram discord slack teams matrix
                               # signal google-chat imessage whatsapp
wirken channel list
wirken channel remove slack
```

`remove` deletes the adapter registration, its Ed25519 keypair, and its vault
credentials.

`list` shows each adapter's state as the audit log records it, with the time
the deciding row was written: `connected`, `disconnected (since <time>)`,
`restarting (attempt n)`, `abandoned (attempts n)`, or `no record`. The state
is the newest `adapter_connect`, `adapter_disconnect`, `adapter_restart` or
`adapter_restart_abandoned` event for the adapter, or, in a log written
before those events existed, the newest legacy row of the same name
(`adapter.connect` and so on), whichever is later. A `gateway.start` or
`gateway.stop` row written after it reads as disconnected since then. A `wirken run` that was killed rather than stopped writes no
`gateway.stop`, so its last recorded states stand until the next start. The
webchat status page shows the same states.

Outbound markdown is rendered per channel by a formatter in
`wirken-adapter-core`. Tables flatten to `Header: value` lines wherever the
platform has no table primitive.

**Limits that hold on every adapter.** One platform workspace, tenant or
homeserver per adapter process; a second needs a second registered channel
with a distinct name. Tokens are loaded once when the adapter process starts,
so a rotated one takes effect at the next start: a restart of `wirken run`, or
an automatic restart after the adapter's gateway connection ends. No command
restarts one adapter on demand. Permissions are scoped per agent, not per
platform user: every admitted sender inherits every Tier 2 approval that agent
already holds. See
[permissions-and-identity.md](permissions-and-identity.md).

**Restarts.** `wirken run` restarts an adapter process when it exits or its
gateway connection ends (see [architecture.md](architecture.md)). A restart
loses what the adapter held in memory, and on some platforms it can forward
a message a second time; the sections below say which. The agent recognizes a
repeat only when it is the latest message in its conversation and carries a
platform message id: it answers from the session log instead of running a
second turn, and the stored reply is sent again. A repeat of an older message
runs a new turn.

## Who reaches the agent

The gateway admits an inbound message only when its sender, or the group it
arrived in, is on the sender allowlist for its channel. It checks before it
scans the message, writes the inbound row, creates a session or routes it, so
a message from anyone else reaches none of those, and no agent. A channel with
no entries drops every message, including on an install upgraded from a
release without the allowlist; `wirken run` warns at startup for each such
channel.

```bash
wirken senders refused telegram          # ids the gateway has dropped
wirken senders add telegram 123456789 --label me
wirken senders add slack C0123ABCD --group --label team-channel
wirken senders add telegram -1001234567890 --group   # a Telegram group
wirken senders list
wirken senders remove telegram 123456789
```

To find your own id, send the bot a message: it is dropped, and
`wirken senders refused` shows the sender and conversation ids it carried.
A sender entry matches the platform sender id the adapter reports, exactly:
a Telegram user id, a Slack or Discord user id, a Teams user id, a Google Chat
`users/<id>` path, a Matrix MXID, the E.164 number (or UUID) on Signal, the number without
`+` on WhatsApp, the iMessage handle. A `--group` entry matches the
conversation id instead (a Telegram group chat id, a Slack or Discord channel,
a Matrix room, a Signal group, a Google Chat space, an iMessage chat) and
admits every member of it; membership of that conversation is then the access
control. An entry applies on its own channel only.

The allowlist is read on every message: an add or a remove applies to the
next message, with no restart. Each change is an `inbound_sender_added` or
`inbound_sender_removed` row on the signed `gateway-senders` lane, and each
drop an `inbound_sender_refused` row on `gateway-inbound`, at most one per
sender a minute and thirty a minute in all, with the rest counted on the next
row ([audit-cli.md](audit-cli.md)). `wirken senders` refuses to run inside a
Wirken `exec`, and records each refusal as an `operator_command_refused` row on
`gateway-senders`.

The sender id is the one the platform reports to the adapter. Wirken does not
authenticate the person behind it; an entry trusts the platform's account.
The terminal (`wirken chat`) and webchat are not channels the allowlist
applies to.

## Telegram

```bash
wirken channel add telegram
```

Get a bot token from [@BotFather](https://t.me/BotFather): `/newbot`, follow
the prompts, paste the token when asked. The adapter long-polls, so there is
no webhook to configure or later clear.

Responds to all private messages; in groups, only when mentioned. Outbound
ships with `parse_mode=HTML`, chosen because the escape surface is three
characters rather than the fifteen-plus with positional rules in MarkdownV2.
Replies target the message the user replied to; root messages are not
auto-replied-to.

**After a restart.** Telegram counts a batch of updates as delivered only when
the next `getUpdates` call passes an offset past it. An adapter killed between
receiving a batch and that next call is sent the batch again after the
restart and forwards it again, approval button presses included.

## Discord

```bash
wirken channel add discord
```

Token from the [Developer Portal](https://discord.com/developers/applications):
create an application, add a bot, copy the token, and enable the **Message
Content** privileged intent. Invite with scope `bot` and permissions
`Send Messages`, `Read Message History`.

In guild channels the bot answers when mentioned; in DMs, every message. The
adapter checks `msg.author.id == bot_id` before forwarding, so it does not
echo-loop on its own DMs. CommonMark passes through unchanged; horizontal
rules collapse to a blank line.

## Slack

Socket Mode. No public URL, no webhook.

```bash
wirken channel add slack
```

Two tokens, both from [api.slack.com/apps](https://api.slack.com/apps):

| Prompt | Where |
|--------|-------|
| `Slack bot token (xoxb-...)` | **OAuth & Permissions** → Bot User OAuth Token |
| `Slack app token (xapp-...)` | **Basic Information** → App-Level Tokens |

Nothing under **App Credentials** (Client ID, Client Secret, Signing Secret,
Verification Token) is used. To skip the prompts, pass the bot token with
`--token` or `WIRKEN_SLACK_TOKEN` and the app token with `--app-token` or
`WIRKEN_SLACK_APP_TOKEN`.

Creating the app: **Create New App** → **From scratch**; enable **Socket
Mode** and generate the app-level token with `connections:write`; bot token
scopes `chat:write`, `app_mentions:read`, `im:history`, `im:read`, `im:write`,
`channels:history`, `channels:read`, `users:read`; subscribe to bot events
`message.im`, `message.channels`, `app_mention`; under **App Home** allow
messages from the messages tab; then **Install to Workspace**.

Vault entries: `slack-token`, `slack-app-token`, `slack-adapter-key`.

In channels the bot answers when mentioned; in DMs, every message. Replies
land in the thread the message came from. The bot's own messages are filtered
by `user_id` and `bot_id`.

The `channel` field on inbound audit events is the channel name (`slack`), not
the Slack workspace ID, so use distinct channel names at setup time to
disambiguate workspaces in the audit log.

Wirken does not participate in Slack's OAuth refresh flow; both tokens are
opaque bearers. Changing app scopes leaves the existing bot token carrying its
original scopes until the app is reinstalled and a new `xoxb-` is issued.
There is no revocation-detection branch: a revoked token surfaces as
`invalid_auth` on outbound calls and a failed WebSocket upgrade inbound.

**After a restart.** The Socket Mode envelope is acknowledged once the adapter
has queued the message, and the message is written to the gateway from that
queue separately, so the two are not ordered. An adapter killed after the
gateway write and before the acknowledgement leaves the envelope
unacknowledged; Slack redelivers it (Slack's behaviour, not checked in the
adapter) and the restarted adapter forwards it again. A message acknowledged
but not yet written is lost instead.

### Approvals

Tool calls that need approval on a Slack session prompt on the CLI, not in
Slack. The request appears in `wirken permissions pending list` and is
decided with `wirken permissions approve <id>` or `wirken permissions deny
<id>`. Nothing is posted in the channel, the agent's turn waits, and a request
nobody decides within the CLI gate's timeout (`WIRKEN_CLI_APPROVAL_TIMEOUT_S`,
300 seconds by default) resolves to deny.

## Microsoft Teams

```bash
wirken channel add teams
```

App ID and App Password from an
[Azure Bot registration](https://portal.azure.com/#create/Microsoft.AzureBot).
Register the bot, note the App ID, create a client secret, and point the
messaging endpoint at your instance (or a tunnel for testing). The adapter
listens on `127.0.0.1:3978`. To skip the prompts, pass the App Password with
`--token` or `WIRKEN_TEAMS_TOKEN` and the App ID with `--app-id` or
`WIRKEN_TEAMS_APP_ID`.

Vault entries: `teams-token` (app password), `teams-app-id`,
`teams-adapter-key`. The adapter exchanges the pair for a Bot Framework access
token at runtime and caches it in memory.

In group chats the bot responds when mentioned; in 1:1 chats, always. Outbound
text ships without channel-specific formatting; the Bot Framework SDK renders
markdown as it sees fit.

The adapter captures the Bot Framework `tenant_id` from each activity into the
IPC frame's metadata. The gateway does not act on it: there is no per-tenant
routing and no per-tenant policy, but the value is preserved in the audit
trail.

Two revocation cases behave differently. On HTTP 401 from the outbound API the
adapter clears its cached access token and re-acquires from the App ID and
password, which is the handled case. If the client secret is rotated in Azure
while the vault holds the old one, acquisition fails and every outbound loops
on 401 until the vault holds the new secret and `wirken run` is restarted. The
401 loop does not end the adapter's gateway connection, so the automatic
restart does not cover it.

## Matrix

```bash
wirken channel add matrix
```

Create a bot account on your homeserver, then supply the homeserver URL,
username and password. HTTPS is enforced for every non-localhost homeserver:
an `http://` URL outside localhost fails at adapter startup with an explicit
error. The adapter uses the Client-Server API with long-polling sync and
performs `m.login.password` at startup, caching the access token in memory;
the password stays in the vault. To skip the prompts, pass `--homeserver`,
`--username` and `--token` (the password), or set `WIRKEN_MATRIX_HOMESERVER`,
`WIRKEN_MATRIX_USERNAME` and `WIRKEN_MATRIX_TOKEN`.

Vault entries: `matrix-token` (the password), `matrix-homeserver`,
`matrix-username`, `matrix-adapter-key`.

In rooms the bot responds when mentioned by display name or MXID; in DMs,
always. Outbound carries both fields of `m.room.message`: `body` as
plain-text-from-markdown for clients that ignore HTML and for accessibility
tooling, `formatted_body` as semantic HTML with `format:
"org.matrix.custom.html"`.

**E2EE is not supported**, blocked on a dependency version conflict. Rooms the
bot participates in must be unencrypted.

There is no `M_UNKNOWN_TOKEN` detection branch: an invalidated access token
surfaces as generic sync errors. Restart `wirken run` to log in again from the
vault-stored password. Sync errors do not end the adapter's gateway
connection, so the automatic restart does not cover them.

**After a restart.** The sync token is held in memory only, so every start of
the adapter, a restart included, begins with an initial sync, and its
timeline events are forwarded like any others. Recent DMs and mentions in
each joined room reach the agent again; how many depends on the homeserver's
default timeline limit, which the adapter does not set. Each start also logs
in without a device id, which creates a new device on the homeserver.

**Approvals.** Tool calls that need approval on a Matrix session prompt on
the CLI, not in the room. The request appears in `wirken permissions pending
list` and is decided with `wirken permissions approve <id>` or `wirken
permissions deny <id>`. `wirken run` attaches no Matrix approval gate, so the
adapter's reaction handling is never reached; a request nobody decides within
the CLI gate's timeout resolves to deny.

## Signal

**Linux and macOS only.** The adapter speaks newline-delimited JSON-RPC over a
Unix socket to a local `signal-cli` daemon, and is excluded at compile time on
the Windows build.

Signal has no bot API. You run signal-cli as a real Signal client under your
own identity, which is what makes this channel different from every other one
here.

### Setup

Install [signal-cli](https://github.com/AsamK/signal-cli) from its release
page, using the `Linux-native` tarball. That build is GraalVM-compiled and has
no JRE dependency. Check the `.asc` signature against the maintainer's key
before you unpack it. Put the binary on your `PATH`, for example in
`~/.local/bin`. The native build reads the working directory at startup, so
run it from a directory that exists; otherwise it fails with `Could not
determine current working directory`.

Then link it as a secondary device, which keeps your phone primary and needs
no new number:

```bash
signal-cli link -n "wirken"
```

Scan or paste the printed `tsdevice://` URL from Signal on your phone under
Settings → Linked devices. A linked device sees only messages that arrive
after the link; prior history stays on the phone, and group metadata syncs in
the background over a few minutes. Registering a new number instead makes
signal-cli the primary device for it, which kicks any existing install on that
number offline.

Run the daemon on a socket:

```bash
signal-cli -a +15551234567 daemon --socket /tmp/signal-cli.sock
ls -l /tmp/signal-cli.sock   # srw------- , owned by you
echo '{"jsonrpc":"2.0","method":"version","id":1}' | socat - UNIX-CONNECT:/tmp/signal-cli.sock
```

Keep it under a supervisor such as systemd or launchd: `wirken run` restarts
its own adapter processes, not signal-cli. Then:

```bash
wirken channel add signal
```

You are prompted for the registered E.164 number, the socket path (bare path
or `unix:///absolute/path`; HTTP URLs are rejected), and the sender allowlist.
To skip the prompts, pass `--phone-number`, `--endpoint` and
`--allowed-senders`, or set `WIRKEN_SIGNAL_PHONE_NUMBER`,
`WIRKEN_SIGNAL_ENDPOINT` and `WIRKEN_SIGNAL_ALLOWED_SENDERS`. With no terminal,
an endpoint not given is `/tmp/signal-cli.sock` and an allowlist not given is
empty, which drops every inbound message.

### Approvals

Tool calls that need approval are answered in Signal, not with buttons. Two
settings control where and by whom:

```bash
wirken approvers set-chat signal +15551234567          # where prompts render
wirken approvers add signal +15551234567 --display "Name"   # who may approve
```

`set-chat` takes your E.164 number for a 1:1 DM, or a base64 group ID for a
group. `approvers add` takes the E.164 number of each operator allowed to
approve or deny. A reply from anyone else is logged as an unauthorized actor
and dropped, and so is a reply from an approver anywhere but the approval chat
the prompt was posted in (`wrong_conversation`). The gateway reads both settings on every request and decision,
so a change applies to the next one without a restart: an approver removed
while `wirken run` is up cannot answer the next prompt.

The prompt shows a prefix. Reply in the approval chat with `!approve <prefix>`
or `!deny <prefix> [reason]`.

To talk to the agent from your own number, message yourself (Note to Self).
signal-cli, linked to your number, sees those as sync messages from your phone
addressed to your own number, and forwards them as messages from that number,
which then has to be on both allowlists like any sender. A message you send
from your phone to anyone else also reaches signal-cli as a sync message; it is
dropped unless `WIRKEN_SIGNAL_FORWARD_LINKED_DEVICE_SENDS=1` is set on
`wirken run`, and the first one dropped in a run is logged at `warn` naming
that variable.

### The allowlist is the perimeter

Signal has two allowlists, and a message must pass both. The adapter's own
(`signal-allowed-senders`, below) drops a message before it leaves the
adapter process; the gateway's sender allowlist
([Who reaches the agent](#who-reaches-the-agent)) drops it before anything
else happens to it. Both are fail-closed: an empty one drops every inbound
message. There is no per-sender authentication in Signal, so anyone who has
your linked number can send to it, and these allowlists are the entire
authorization boundary. Everything past them is inside the trust boundary.

- **1:1 DMs**: the sender's E.164 number must be listed.
- **Group messages**: the Signal group ID must be listed. The sender inside
  the group is not checked; group membership is your access control. Find ids
  with `signal-cli -a +1555... listGroups`.

There is no one-shot set command; rotate the vault entry to change the list,
then restart `wirken run` so the adapter re-reads it:

```bash
echo "+15551234567,+15559876543,group-abc-xyz=" \
  | wirken credentials add signal-allowed-senders --channel signal --stdin
```

### Signal-specific exposure

- **The signal-cli socket is unauthenticated.** Any local process that can
  open it sends Signal messages as you. Filesystem permissions do the work:
  keep the socket in a directory you own, `chmod 700` on shared hosts, or run
  signal-cli as a dedicated user.
- **signal-cli stores your Signal identity in cleartext** at
  `~/.local/share/signal-cli/data/`. Whoever holds that directory can
  impersonate you on Signal until you unlink the device from your phone. Back
  it up only to an encrypted location; a file-sync tool that picks up that
  directory hands over your identity. `chmod 700` is the baseline.
- **Signal's crypto is not what fails here.** An allowlisted message arrives
  authenticated and decrypted, and its text is placed into an LLM prompt. The
  transport is sound; the application layer above it is a classic
  prompt-injection surface.
- **Pre-existing Tier 2 approvals apply.** An `exec` approval granted earlier
  through Telegram or the CLI applies to an allowlisted Signal sender without
  prompting. Review `wirken permissions list --agent <id>` before putting this
  adapter in front of an agent.
- **Injection detection is monitoring, not prevention.** Inbound Signal
  messages are scanned and flagged on the audit row; they are not blocked.
- **Messages are not replayed across a daemon restart.** signal-cli streams
  envelopes to currently-subscribed listeners only, so anything that reaches
  the daemon before the adapter reconnects is written to the daemon's stdout
  and lost to wirken. This is a signal-cli architecture property. Keep the
  daemon supervised so restart windows stay short; the daemon's stdout shows
  `Envelope from:` for the lost message, which distinguishes "adapter never
  saw it" from the adapter's own `not in allowlist or empty`. The same holds
  while the gateway restarts the adapter process: the new process subscribes
  afresh and is not sent what arrived in between, so a restart loses those
  messages rather than forwarding any twice.
- **Approval is coarse.** Tier 2 shell approvals key on the first token of the
  command; finer-grained patterns are not supported.
- **Approvals pending at a restart are lost.** The prefix map behind
  `!approve <prefix>` is held in memory. After the adapter restarts, a prefix
  from an earlier prompt is answered with `no pending request matching
  prefix` and the request waits out its timeout.
- **No rate limiting on the adapter.** An allowlisted sender spamming messages
  spams the LLM and the API bill. Add external rate limiting if more than a
  handful of people can reach it.
- **Not audited.** No third party has reviewed this integration.

Non-text messages (typing indicators, reactions, stickers) are dropped. Own
sends are filtered by timestamp so the agent does not re-process its own
replies. Sends from your other linked devices are forwarded when they are
Note to Self, and otherwise dropped unless
`WIRKEN_SIGNAL_FORWARD_LINKED_DEVICE_SENDS` is set.

## Google Chat

```bash
wirken channel add google-chat
```

Needs a GCP project with the Chat API enabled and three things: a bearer token
so Wirken can reply, your Cloud **project number** (the numeric one, not the
project ID) as the audience the adapter verifies on inbound webhook JWTs, and
a webhook endpoint so Chat can deliver messages.

Configure the Chat app under
[Chat API configuration](https://console.cloud.google.com/apis/api/chat.googleapis.com/hangouts-chat):
app name, avatar, description, and **Connection settings** → **HTTP endpoint
URL**. For a token, `gcloud auth print-access-token` works for testing and
expires after about an hour; do not use `gcloud auth application-default
login`, which needs an OAuth consent screen with test users and otherwise
shows "This app is blocked".

The adapter refuses to start without a project number. Supply it with
`--project-number` or `WIRKEN_GOOGLE_CHAT_PROJECT_NUMBER`.

The adapter listens on `127.0.0.1:3980`. Chat needs to reach that over HTTPS,
so for local testing put `ngrok http 3980` in front and paste the forwarding
URL into the endpoint field.

**After a restart.** Each POST is answered with 200 only after the message is
written to the gateway. An adapter killed between the two leaves the POST
unanswered; if Chat retries it (Chat's behaviour, not checked in the
adapter), the restarted adapter forwards it again.

## iMessage (BlueBubbles)

**Not verified against a live BlueBubbles server.** The adapter's API calls
(the webhook route, the password as a query parameter, the message send) and
its webhook check follow BlueBubbles Server's source, cited below; no run
against a running server has confirmed them. Treat this channel as untested
until one has.

```bash
wirken channel add imessage
```

Needs [BlueBubbles Server](https://bluebubbles.app) on a Mac with iMessage
configured. Supply the server password and URL (default
`http://localhost:1234`). To skip the prompts, pass the password with `--token`
or `WIRKEN_IMESSAGE_TOKEN` and the URL with `--bluebubbles-url` or
`WIRKEN_IMESSAGE_BLUEBUBBLES_URL`; with no terminal and no URL given, the
default is stored. The adapter registers a webhook with BlueBubbles,
sends replies through its REST API, and filters out messages from yourself
(`isFromMe`). It listens on `127.0.0.1:3981`.

**BlueBubbles posts webhook events with no authentication of its own.** Its
webhook service sends a plain `axios.post` with only `Content-Type:
application/json`: no HMAC, no bearer, no signature
([`webhookService/index.ts`](https://github.com/BlueBubblesApp/bluebubbles-server/blob/f2e2286241a7c3b6617a82b37d4afaab4df3a6b9/packages/server/src/server/services/webhookService/index.ts)). What
it does keep is the URL it was given, and it posts to that URL as given. The
adapter therefore registers `http://localhost:3981/webhook?secret=<secret>`,
where the secret is an HMAC-SHA256 keyed by the BlueBubbles server password,
the same on every start, and answers 403 to any POST whose `secret` does not
match, compared in constant time, without reading its body. Rotating the
BlueBubbles password changes the secret. BlueBubbles writes webhook URLs to
its debug log, so the secret is there too; it does not give the password away.

The listener also binds to `127.0.0.1` only, and `wirken run` refuses to start
the adapter if the bound address is not loopback. The realistic deployment is
single-user, single-machine, with BlueBubbles and wirken on the same Mac. To
receive webhooks from another machine, terminate a reverse proxy that adds its
own authentication before the request reaches the loopback listener. Do not
expose the port directly.

The adapter calls BlueBubbles' REST API with the server password as the
`password` query parameter, which is where its authentication reads it
([`authMiddleware.ts`](https://github.com/BlueBubblesApp/bluebubbles-server/blob/f2e2286241a7c3b6617a82b37d4afaab4df3a6b9/packages/server/src/server/api/http/api/v1/middleware/authMiddleware.ts)),
and registers the webhook at `/api/v1/webhook`.

**Upgrading from an earlier version:** that version's webhook registration,
`http://localhost:3981/webhook` with no secret, if BlueBubbles holds one, stays
there and is refused on every message, with a warning in the adapter log.
Delete it in the BlueBubbles server's webhook settings. Uninstalling wirken
does not remove the webhook registration either; delete it there too.

**After a restart.** The adapter registers its webhook on every start, a
restart included. BlueBubbles keeps one registration per URL and returns the
existing one for a URL it already has
([`addWebhook`](https://github.com/BlueBubblesApp/bluebubbles-server/blob/f2e2286241a7c3b6617a82b37d4afaab4df3a6b9/packages/server/src/server/databases/server/index.ts)), and the URL is the same on
every start, so a restart adds none. Each POST is answered with 200 only after
the message is written to the gateway, so a POST cut off by a kill may be
retried and forwarded again.

**Approvals.** Tool calls that need approval on an iMessage session prompt on
the CLI, not in the chat. The request appears in `wirken permissions pending
list` and is decided with `wirken permissions approve <id>` or `wirken
permissions deny <id>`. `wirken run` attaches no iMessage approval gate, so
the adapter's `!approve <prefix>` parsing is never reached; a request nobody
decides within the CLI gate's timeout resolves to deny.

## WhatsApp

Targets the [Meta Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api).
Both `wirken setup` and `wirken channel add whatsapp` collect four
credentials into the vault:

- `whatsapp-token`: system-user access token with
  `whatsapp_business_messaging`
- `whatsapp-phone-number-id`: phone number ID assigned by Meta
- `whatsapp-verify-token`: webhook verify token, any string you choose,
  matching the Meta dashboard
- `whatsapp-app-secret`: Meta app secret, used for HMAC validation of
  inbound webhooks

The adapter listens on `127.0.0.1:3979` for webhook POSTs and replies through
the Cloud API.

**After a restart.** Each webhook POST is answered with 200 as soon as its
signature checks out, before the message is written to the gateway, as Teams
does. An adapter killed between the two loses that message rather than
leaving Meta a POST to retry, so a restart does not forward it twice.

## Platform-side state

Removing a channel locally does not touch what you created at the platform.
Revoke or delete it there: the Slack app and its tokens, the Telegram bot
token at BotFather, the WhatsApp Cloud API app and its webhook URL, the
Discord bot application, the Teams bot registration in Azure, the Matrix bot
account, the Signal linked device, the Google Chat app, and the BlueBubbles
webhook. Rotating these credentials is prudent regardless, since they were
held in the vault.
