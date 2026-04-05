# Discord

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
