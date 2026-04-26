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

In guild channels, the bot only responds when mentioned. In DMs, it responds to all messages. The serenity SDK delivers events for the bot's own outbound separately, and the adapter checks `msg.author.id == bot_id` before forwarding, so the bot does not echo-loop on its own DMs.

Outbound markdown is rendered through `DiscordFormatter` from `wirken-adapter-core`. CommonMark passes through unchanged — Discord renders `**bold**`, `*italic*`, `~~strike~~`, `# heading`, fenced code blocks, blockquotes, lists, and links natively. The formatter only diverges on two things: GFM tables flatten to `Header: value` lines per cell (Discord has no table primitive), and horizontal rules collapse to a blank line. Mentions and channel refs (`<@id>`, `<#id>`) pass through unchanged. Replies to a message land as a reply on that message; the gateway dispatcher carries the inbound's reply context through to the outbound, and root messages are not auto-replied-to.
