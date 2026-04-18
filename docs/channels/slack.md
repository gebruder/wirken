# Slack

```bash
wirken channel add slack
```

You need two tokens: a bot token (`xoxb-...`) and an app token (`xapp-...`).

1. Create a new app at [api.slack.com/apps](https://api.slack.com/apps) (choose "From scratch")
2. Go to **Socket Mode** and enable it (must be done before configuring Event Subscriptions)
3. Go to **OAuth & Permissions**, add bot scopes:
   - `chat:write`, `app_mentions:read`
   - `im:history`, `im:read`, `im:write`
   - `channels:history`, `channels:read` (for public channels)
   - `users:read`
4. Go to **Event Subscriptions**, enable events, and subscribe to bot events:
   - `message.im` (DMs)
   - `message.channels` (public channels)
   - `app_mention` (mentions)
   - Socket Mode must be on first or this page will require a Request URL and won't save.
5. Go to **App Home** > **Messages Tab**, check "Allow users to send Slash commands and messages from the messages tab" (required for DMs)
6. Go to **Basic Information** > **App-Level Tokens**, create a token with `connections:write` scope, copy it (`xapp-...`)
7. Install the app to your workspace, copy the **Bot User OAuth Token** from OAuth & Permissions (`xoxb-...`)
8. Run `wirken channel add slack` and paste both tokens when prompted

The adapter uses Socket Mode (WebSocket). No public URL or webhook endpoint needed.

In channels, the bot only responds when mentioned. In DMs, it responds to all messages.

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
