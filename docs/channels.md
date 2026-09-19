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

Outbound markdown is rendered per channel by a formatter in
`wirken-adapter-core`. Tables flatten to `Header: value` lines wherever the
platform has no table primitive.

**Limits that hold on every adapter.** One platform workspace, tenant or
homeserver per adapter process; a second needs a second registered channel
with a distinct name. Tokens are loaded once at adapter startup, so rotating
one requires restarting the adapter. Permissions are scoped per agent, not per
platform user: any sender who can reach the bot inherits every Tier 2 approval
that agent already holds. See
[permissions-and-identity.md](permissions-and-identity.md).

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
Verification Token) is used.

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

## Microsoft Teams

```bash
wirken channel add teams
```

App ID and App Password from an
[Azure Bot registration](https://portal.azure.com/#create/Microsoft.AzureBot).
Register the bot, note the App ID, create a client secret, and point the
messaging endpoint at your instance (or a tunnel for testing). The adapter
listens on `127.0.0.1:3978`.

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
on 401 until the adapter is restarted with the new secret.

## Matrix

```bash
wirken channel add matrix
```

Create a bot account on your homeserver, then supply the homeserver URL,
username and password. HTTPS is enforced for every non-localhost homeserver:
an `http://` URL outside localhost fails at adapter startup with an explicit
error. The adapter uses the Client-Server API with long-polling sync and
performs `m.login.password` at startup, caching the access token in memory;
the password stays in the vault.

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
surfaces as generic sync errors. Restart the adapter to re-login from the
vault-stored password.

## Signal

**Linux and macOS only.** The adapter speaks newline-delimited JSON-RPC over a
Unix socket to a local `signal-cli` daemon, and is excluded at compile time on
the Windows build.

Signal has no bot API. You run signal-cli as a real Signal client under your
own identity, which is what makes this channel different from every other one
here.

### Setup

Install [signal-cli](https://github.com/AsamK/signal-cli); the native
GraalVM-compiled build has no JRE dependency. Then link it as a secondary
device, which keeps your phone primary and needs no new number:

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

Keep it under a supervisor. Then:

```bash
wirken channel add signal
```

You are prompted for the registered E.164 number, the socket path (bare path
or `unix:///absolute/path`; HTTP URLs are rejected), and the sender allowlist.

### The allowlist is the perimeter

The adapter is fail-closed: an empty allowlist drops every inbound message.
There is no per-sender authentication in Signal, so anyone who has your linked
number can send to it, and the allowlist is the entire authorization boundary.
Everything past it is inside the trust boundary.

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
  saw it" from the adapter's own `not in allowlist or empty`.
- **Approval is coarse.** Tier 2 shell approvals key on the first token of the
  command; finer-grained patterns are not supported.
- **No rate limiting on the adapter.** An allowlisted sender spamming messages
  spams the LLM and the API bill. Add external rate limiting if more than a
  handful of people can reach it.
- **Not audited.** No third party has reviewed this integration.

Non-text messages (typing indicators, reactions, stickers) are dropped. Own
sends are filtered by timestamp so the agent does not re-process its own
replies; sends from your other linked devices are dropped unless
`WIRKEN_SIGNAL_FORWARD_LINKED_DEVICE_SENDS` is set, which is a test-to-self
affordance.

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

## iMessage (BlueBubbles)

```bash
wirken channel add imessage
```

Needs [BlueBubbles Server](https://bluebubbles.app) on a Mac with iMessage
configured. Supply the server password and URL (default
`http://localhost:1234`). The adapter registers a webhook with BlueBubbles,
sends replies through its REST API, and filters out messages from yourself
(`isFromMe`). It listens on `127.0.0.1:3981`.

**BlueBubbles posts webhook events with no authentication of any kind.** Its
`axios.post` sets only `Content-Type: application/json`: no HMAC, no bearer,
no shared secret, no signed timestamp. The receiving side cannot tell a
BlueBubbles webhook from any process that can reach the adapter port.

The adapter therefore draws its boundary at the socket: the listener binds to
`127.0.0.1` only, and `wirken run` refuses to start the adapter if the bound
address is not loopback. The realistic deployment is single-user,
single-machine, with BlueBubbles and wirken on the same Mac. To receive
webhooks from another machine, terminate a reverse proxy that adds its own
authentication (mTLS, HMAC at the proxy, a bearer header) before the request
reaches the loopback listener. Do not expose the port directly.

Uninstalling wirken does not remove the webhook registration; delete it in the
BlueBubbles server's webhook settings.

## WhatsApp

Targets the [Meta Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api).
Both `wirken setup` and `wirken channel add whatsapp` collect four
credentials into the vault:

- `whatsapp-token` — system-user access token with
  `whatsapp_business_messaging`
- `whatsapp-phone-number-id` — phone number ID assigned by Meta
- `whatsapp-verify-token` — webhook verify token, any string you choose,
  matching the Meta dashboard
- `whatsapp-app-secret` — Meta app secret, used for HMAC validation of
  inbound webhooks

The adapter listens on `127.0.0.1:3979` for webhook POSTs and replies through
the Cloud API.

## Platform-side state

Removing a channel locally does not touch what you created at the platform.
Revoke or delete it there: the Slack app and its tokens, the Telegram bot
token at BotFather, the WhatsApp Cloud API app and its webhook URL, the
Discord bot application, the Teams bot registration in Azure, the Matrix bot
account, the Signal linked device, the Google Chat app, and the BlueBubbles
webhook. Rotating these credentials is prudent regardless, since they were
held in the vault.
