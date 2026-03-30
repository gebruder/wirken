# Channel Setup

Each channel runs as a separate OS process with its own Ed25519 identity. Add channels during `wirken setup` or later with `wirken channel add`.

## Telegram

```bash
wirken channel add telegram
```

You need a bot token from [@BotFather](https://t.me/BotFather).

1. Message @BotFather on Telegram
2. Send `/newbot` and follow the prompts
3. Copy the bot token
4. Paste it when `wirken channel add telegram` prompts

The adapter uses long polling (no webhook URL needed). The bot responds to all private messages and can be added to groups.

## Discord

```bash
wirken channel add discord
```

You need a bot token from the [Discord Developer Portal](https://discord.com/developers/applications).

1. Create a new application
2. Go to Bot settings, click "Add Bot"
3. Copy the bot token
4. Enable the "Message Content" intent under Privileged Gateway Intents
5. Paste the token when prompted

Invite the bot to your server using the OAuth2 URL generator (scopes: `bot`, permissions: `Send Messages`, `Read Message History`).

In guild channels, the bot only responds when mentioned. In DMs, it responds to all messages.

## Slack

```bash
wirken channel add slack
```

You need two tokens: a bot token (`xoxb-...`) and an app token (`xapp-...`).

1. Create a new app at [api.slack.com/apps](https://api.slack.com/apps)
2. Go to OAuth & Permissions, add scopes: `chat:write`, `app_mentions:read`, `im:history`, `im:read`, `im:write`
3. Install the app to your workspace, copy the Bot User OAuth Token (`xoxb-...`)
4. Go to Basic Information > App-Level Tokens, create a token with `connections:write` scope, copy it (`xapp-...`)
5. Enable Socket Mode under Socket Mode settings

The adapter uses Socket Mode (WebSocket). No public URL or webhook endpoint needed.

In channels, the bot only responds when mentioned. In DMs, it responds to all messages.

## Microsoft Teams

```bash
wirken channel add teams
```

You need a Microsoft App ID and App Password from the [Azure Bot registration](https://portal.azure.com/#create/Microsoft.AzureBot).

1. Register a new bot in Azure
2. Note the App ID
3. Create a client secret (App Password)
4. Configure the messaging endpoint to point to your wirken instance (or use a tunnel for testing)

The adapter listens on `127.0.0.1:3978` for webhook callbacks from the Bot Framework.

In group chats, the bot only responds when mentioned. In 1:1 chats, it responds to all messages.

## Matrix

```bash
wirken channel add matrix
```

You need a homeserver URL, username, and password.

1. Create a bot account on your Matrix homeserver (e.g., `@wirken:matrix.org`)
2. Enter the homeserver URL (e.g., `https://matrix.org`)
3. Enter the username and password

HTTPS is enforced for all non-localhost homeservers. The adapter uses the Client-Server API with long-polling sync.

In rooms, the bot responds when mentioned by display name or MXID. In DMs, it responds to all messages.

E2EE is not yet supported (blocked by a dependency version conflict).

## Managing channels

```bash
wirken channel list       # show all registered channels
wirken channel remove slack  # remove a channel and its credentials
```

Removing a channel deletes its adapter registration and Ed25519 keypair. Credentials remain in the vault and can be removed separately with `wirken credentials`.
