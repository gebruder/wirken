# WhatsApp

The WhatsApp adapter targets the [Meta Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api) and is built into the workspace (`crates/adapter-whatsapp`). At runtime it expects the following entries in the vault:

- `whatsapp-token` — system-user access token with `whatsapp_business_messaging` permission
- `whatsapp-phone-number-id` — phone number ID assigned by Meta
- `whatsapp-verify-token` — webhook verify token (any string you choose; must match the value configured in the Meta dashboard)
- `whatsapp-app-secret` — Meta app secret, used for HMAC validation of incoming webhooks

The adapter listens on `127.0.0.1:3979` (override with `WIRKEN_WHATSAPP_PORT`) for inbound webhook POSTs from Meta and posts replies through the Cloud API.

Both the interactive `wirken setup` wizard and `wirken channel add whatsapp` collect all four Cloud API credentials (access token, phone-number-id, verify-token, app-secret) and store them in the vault.
