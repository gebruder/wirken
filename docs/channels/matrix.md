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

## Team deployment notes

### Homeserver boundary

One homeserver per adapter process. A Wirken instance federating across two homeservers needs two registered channels with distinct names. Federation between homeservers is a Matrix-layer concern, not a Wirken-layer concern: as far as Wirken is concerned, the adapter talks to exactly one homeserver via the Client-Server API.

### Tokens and the vault

At adapter startup, the following vault entries are loaded:

| Name | Value |
|------|-------|
| `matrix-token` | Password for the bot account |
| `matrix-homeserver` | Full homeserver URL (HTTPS enforced outside localhost) |
| `matrix-username` | Bot account username |
| `matrix-adapter-key` | 32-byte ed25519 secret for IPC handshake to the gateway |

The adapter performs `m.login.password` at startup and caches the returned `access_token` in memory. The password itself remains in the vault; the access token is not written back.

Each forwarded inbound message carries the full MXID (for example `@alice:example.com`) as the `sender_id`. The gateway writes this to the audit log as the `actor` of `message.inbound`.

### Token revocation

The Matrix adapter has no explicit `M_UNKNOWN_TOKEN` detection branch. If the access token is invalidated (admin revocation, password change, device logout), subsequent sync calls fail with generic errors. Operator action: restart the adapter process to re-login with the vault-stored password. If the password has been rotated, run `wirken channel add matrix` with the new password and restart.

### HTTPS enforcement

The adapter refuses to send credentials over plain HTTP for any non-localhost homeserver. Attempts to configure an `http://` homeserver URL outside localhost fail at adapter startup with an explicit error.

### Room-level trust domain

Permissions are scoped per agent, not per Matrix user and not per room. Any member of a room who can interact with the bot triggers the same agent under the same approval set. See [permissions-and-identity.md](../permissions-and-identity.md).
