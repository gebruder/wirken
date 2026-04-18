# Microsoft Teams

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

## Team deployment notes

### Tenant boundary

One Teams tenant per adapter process. A Wirken instance covering two tenants needs two registered channels with distinct names, each with its own Azure Bot registration and its own adapter process.

The adapter captures the Bot Framework `tenant_id` from each activity and stores it in the message metadata JSON on the IPC frame. The gateway does not currently act on `tenant_id` (no per-tenant routing, no per-tenant policy), but the value is preserved in the audit trail.

### Tokens and the vault

At adapter startup, the following vault entries are loaded:

| Name | Value |
|------|-------|
| `teams-token` | App password (client secret from Azure) |
| `teams-app-id` | Microsoft App ID |
| `teams-adapter-key` | 32-byte ed25519 secret for IPC handshake to the gateway |

The adapter exchanges the App ID and App Password for a Bot Framework access token at runtime and caches it in memory.

### OAuth scope rotation

Wirken does not participate in Azure AD's OAuth refresh flow beyond the client-credentials grant. App permissions changed in Azure take effect on the next access-token acquisition, which happens at startup or after a 401. If the bot framework scopes are rotated, restart the adapter to force re-acquisition with the new scope set.

### Token revocation and rotation

Two separable revocation cases:

- **Cached access token expires or is rejected.** On HTTP 401 from the Bot Framework outbound API, the adapter clears its cached access token. The next outbound call re-acquires a fresh token from the App ID and App Password. This is the normal, handled case.
- **App Password is rotated out-of-band.** If the client secret is rotated in Azure but the vault still holds the old one, access-token acquisition fails (HTTP 401 on the token endpoint). The adapter has no retry-with-different-secret branch. Symptom: every outbound loops on 401 until the adapter is restarted with the new secret in the vault. Operator action: `wirken channel add teams`, paste the new App Password, restart the adapter.

### Tenant-level trust domain

Permissions are scoped per agent, not per Teams user and not per tenant. A Tier 2 approval granted by any user in the tenant applies to every user in the tenant for the approval window. See [permissions-and-identity.md](../permissions-and-identity.md).
