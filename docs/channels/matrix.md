# Matrix

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
