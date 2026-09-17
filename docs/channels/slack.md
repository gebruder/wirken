# Slack

Wirken connects to Slack over Socket Mode. No public URL, no webhook.

## Connect

```bash
wirken channel add slack
```

It asks for two tokens. Both are in your app at [api.slack.com/apps](https://api.slack.com/apps).

| Prompt | Where to get it |
|--------|-----------------|
| `Slack bot token (xoxb-...)` | Left menu **OAuth & Permissions**. Copy **Bot User OAuth Token**. |
| `Slack app token (xapp-...)` | Left menu **Basic Information**, scroll to **App-Level Tokens**, click the token name. Copy it. |

Nothing under **App Credentials** (Client ID, Client Secret, Signing Secret, Verification Token) is used.

## Create the app

Skip this if the app already exists.

1. [api.slack.com/apps](https://api.slack.com/apps), **Create New App**, **From scratch**.
2. **Socket Mode**: enable it. Slack asks you to generate an app-level token with `connections:write`. Generate it. This is the `xapp-` token.
3. **OAuth & Permissions**, Bot Token Scopes: `chat:write`, `app_mentions:read`, `im:history`, `im:read`, `im:write`, `channels:history`, `channels:read`, `users:read`.
4. **Event Subscriptions**: enable, subscribe to bot events `message.im`, `message.channels`, `app_mention`.
5. **App Home**, **Messages Tab**: check "Allow users to send Slash commands and messages from the messages tab".
6. **OAuth & Permissions**: **Install to Workspace**. The **Bot User OAuth Token** appears. This is the `xoxb-` token.

Then run `wirken channel add slack` as above.

## Behaviour

In channels the bot answers when mentioned. In DMs it answers every message.

Replies land in the thread the message came from; root messages stay at the root. The bot's own messages are filtered from the inbound stream by `user_id` and `bot_id`, so DMs do not echo-loop.

## Team deployment notes

### Workspace boundary

One Slack workspace per adapter process. A Wirken instance serving two Slack workspaces requires two registered channels with distinct names (for example `slack` and `slack-eu`), each going through its own `wirken channel add` flow and its own adapter process.

The `channel` field on inbound audit events is the channel name (`slack`), not the Slack workspace ID. To disambiguate workspaces in the audit log and SIEM, use distinct channel names at setup time.

### Tokens and the vault

At adapter startup, the following vault entries are loaded:

| Name | Value |
|------|-------|
| `slack-token` | Bot User OAuth Token (`xoxb-`) |
| `slack-app-token` | App-level token with `connections:write` scope (`xapp-`) |
| `slack-adapter-key` | 32-byte ed25519 secret for IPC handshake to the gateway |

Tokens are loaded once per adapter process, at startup. Rotating a token requires restarting the adapter process. `wirken channel add slack` overwrites existing vault entries via `INSERT OR REPLACE`.

Each forwarded inbound message carries the Slack `user_id` as the `sender_id` on the IPC frame. The gateway writes this to the audit log as the `actor` of the `message.inbound` event.

### OAuth scope rotation

Wirken does not participate in Slack's OAuth refresh flow. The bot and app tokens are treated as opaque bearers. When Slack app scopes are modified in the app console, the existing bot token continues to carry its original scopes until the app is reinstalled to the workspace and a new `xoxb-` is issued. At that point, run `wirken channel add slack` again with the new token and restart the adapter.

### Token revocation

The Slack adapter has no explicit revocation-detection branch. If a bot token is revoked, the Slack API returns `invalid_auth` on subsequent calls. In the current code, this surfaces as a generic error logged at the adapter and a failed `OutboundResult` frame back to the gateway. Inbound Socket Mode delivery stops because the WebSocket upgrade fails. Operator action: check the adapter logs, reissue the token, rerun `wirken channel add slack`, restart.

### Workspace-level trust domain

Process isolation at the Wirken layer does not extend into Slack. Every user in the workspace who can interact with the bot sees the same agent. Permissions are scoped per agent, not per Slack user. See [permissions-and-identity.md](../permissions-and-identity.md) for the exact model and planned work.
