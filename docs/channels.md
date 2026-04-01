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

1. Create a new app at [api.slack.com/apps](https://api.slack.com/apps) (choose "From scratch")
2. Go to **OAuth & Permissions**, add bot scopes: `chat:write`, `app_mentions:read`, `im:history`, `im:read`, `im:write`
3. Go to **Socket Mode** and enable it (must be enabled before configuring Event Subscriptions)
4. Go to **Basic Information** > **App-Level Tokens**, create a token with `connections:write` scope, copy it (`xapp-...`)
5. Go to **App Home** > **Messages Tab**, check "Allow users to send Slash commands and messages from the messages tab" (required for DMs)
6. Go to **Event Subscriptions**, enable events, and subscribe to bot events: `message.im`, `app_mention`. Socket Mode must be on first or this page will require a Request URL and won't save.
7. Install the app to your workspace, copy the **Bot User OAuth Token** from OAuth & Permissions (`xoxb-...`)
8. Run `wirken channel add slack` and paste both tokens when prompted

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

## Signal

```bash
wirken channel add signal
```

Signal requires [signal-cli](https://github.com/AsamK/signal-cli) running as a JSON-RPC daemon on the same machine.

1. Install signal-cli and register a phone number
2. Start signal-cli in daemon mode: `signal-cli -u +15551234567 daemon --json-rpc`
3. Enter the registered phone number and signal-cli endpoint when prompted

The adapter polls signal-cli's JSON-RPC interface for incoming messages and sends outbound messages via the `send` method.

## Google Chat

```bash
wirken channel add google-chat
```

You need a Google Workspace service account with the Chat API enabled.

1. Create a Chat bot at [developers.google.com/workspace/chat](https://developers.google.com/workspace/chat)
2. Configure the bot's connection settings to use an HTTP endpoint
3. Create a service account and generate a bearer token
4. Enter the token when prompted

The adapter listens on `127.0.0.1:3980` for webhook POSTs from Google Chat and sends replies via the Chat REST API.

## iMessage (BlueBubbles)

```bash
wirken channel add imessage
```

iMessage requires [BlueBubbles Server](https://bluebubbles.app) running on a Mac with iMessage configured.

1. Install and configure BlueBubbles Server on a Mac
2. Note the server password and URL (default: `http://localhost:1234`)
3. Enter the server password and URL when prompted

The adapter registers a webhook with BlueBubbles for incoming messages and sends replies via the BlueBubbles REST API. Messages from yourself (`isFromMe`) are filtered out.

## Managing channels

```bash
wirken channel list       # show all registered channels
wirken channel remove slack  # remove a channel and its credentials
```

Removing a channel deletes its adapter registration and Ed25519 keypair. Credentials remain in the vault and can be removed separately with `wirken credentials`.
