# Channel Setup

Each channel runs as a separate OS process with its own Ed25519 identity. Add channels during `wirken setup` or later with `wirken channel add`.

- [Telegram](channels/telegram.md)
- [Discord](channels/discord.md)
- [Slack](channels/slack.md)
- [Microsoft Teams](channels/teams.md)
- [Matrix](channels/matrix.md)
- [Signal](channels/signal.md)
- [Google Chat](channels/google-chat.md)
- [iMessage (BlueBubbles)](channels/imessage.md)

## Managing channels

```bash
wirken channel list       # show all registered channels
wirken channel remove slack  # remove a channel and its credentials
```

Removing a channel deletes its adapter registration and Ed25519 keypair. Credentials remain in the vault and can be removed separately with `wirken credentials`.
