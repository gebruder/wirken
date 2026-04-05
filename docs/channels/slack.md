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
