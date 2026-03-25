# Connector Reality Check

For each messaging platform OpenClaw supports: what is the actual connection method, what breaks, what's legally risky, and what could a new product ship with.

---

## Official Bot APIs — Safe to Ship

These connectors use documented, supported bot/app APIs. The platform expects bots to exist. Legal risk is low. Breakage comes from API deprecations, not account bans.

### Telegram

- **Method:** Official Bot API via grammY library. Long polling (default) or webhook mode.
- **What breaks:** IPv6 egress resolution issues on some hosts (mitigated by Node 22+ `autoSelectFamily`). Otherwise rock-solid. Telegram actively supports bots.
- **Legal risk:** None. Bots are a first-class Telegram feature.
- **Ship verdict:** Yes. Day-one channel. Simplest onboarding of any platform.

### Discord

- **Method:** Official Bot API + Gateway WebSocket via Carbon library. Slash commands, guild channels, DMs, threads, voice (opusscript).
- **What breaks:** Discord gateway reconnection edge cases. Rate limits on message sends in busy guilds. Bot token management per-server.
- **Legal risk:** None. Discord's bot ecosystem is mature and encouraged.
- **Ship verdict:** Yes. Day-one channel. Large user overlap with target audience.

### Slack

- **Method:** Official Bolt SDK. Socket Mode (WebSocket, default) or HTTP Events API. Requires Slack app creation.
- **What breaks:** Slack app review for distribution. Socket Mode requires `xapp-*` token. Enterprise Grid has separate permission model.
- **Legal risk:** None for single-workspace. Distribution requires Slack app review.
- **Ship verdict:** Yes, for single-workspace. Distribution adds review burden.

### Microsoft Teams

- **Method:** Official Microsoft Bot Framework + Agents Hosting SDK. Azure Bot Service registration.
- **What breaks:** Azure setup complexity. Teams app sideloading requires admin approval in most orgs. Adaptive cards have rendering inconsistencies.
- **Legal risk:** None. Official channel.
- **Ship verdict:** Yes, but onboarding is heavy (Azure portal, Teams admin). Enterprise feature, not MVP.

### Google Chat

- **Method:** Official Google Chat API via HTTP webhooks + google-auth-library.
- **What breaks:** Workspace admin must enable Chat apps. Webhook URL management. Limited feature set compared to other platforms.
- **Legal risk:** None.
- **Ship verdict:** Post-MVP. Small market outside Google Workspace shops.

### LINE

- **Method:** Official LINE Messaging API. Webhook + REST. Flex messages, rich menus.
- **What breaks:** LINE Developers console setup. Webhook URL must be HTTPS with valid cert. Regional relevance (Japan/Taiwan/Thailand).
- **Legal risk:** None.
- **Ship verdict:** Regional. Ship if targeting APAC market.

### Feishu/Lark

- **Method:** Official Lark SDK (`@larksuiteoapi/node-sdk`). WebSocket events + REST.
- **What breaks:** Enterprise-only platform. Bot Platform setup. China-specific infrastructure considerations.
- **Legal risk:** None.
- **Ship verdict:** Regional. Ship if targeting China enterprise market.

### Mattermost

- **Method:** Official Bot API + WebSocket. Self-hosted.
- **What breaks:** Requires user's own Mattermost instance. WebSocket reconnection.
- **Legal risk:** None.
- **Ship verdict:** Post-MVP. Niche self-hosted audience.

### Nextcloud Talk

- **Method:** Official webhook bot API. Self-hosted.
- **What breaks:** No media upload support (URLs only). Requires Nextcloud instance.
- **Legal risk:** None.
- **Ship verdict:** Post-MVP. Very niche.

### Synology Chat

- **Method:** Incoming + outgoing webhooks. Self-hosted on Synology NAS.
- **What breaks:** Custom rate limiting (30/min). NAS-specific deployment.
- **Legal risk:** None.
- **Ship verdict:** Post-MVP. Tiny market.

---

## Unofficial/Reverse-Engineered — High Risk

These connectors simulate a real user's client. The platform did not design for this. Accounts can be banned. Libraries break without notice when the platform changes its protocol.

### WhatsApp (via Baileys)

- **Method:** Baileys library. Reverse-engineers WhatsApp Web's multi-device protocol. QR pairing links the gateway as a "WhatsApp Web" session on the user's personal phone number.
- **What breaks:** Everything, eventually. WhatsApp actively detects and bans automated clients. Baileys tracks a moving target — protocol changes land without warning. Session state is fragile. Disconnections require re-pairing. Rate limits are shared with the user's real WhatsApp usage.
- **Legal risk:** **High.** WhatsApp ToS Section 2 explicitly prohibits automated or bulk messaging and non-official client software. Meta has sued companies for using unofficial APIs. User's personal account is at risk of permanent ban.
- **Breakage history:** Baileys has gone through multiple major version breaks as WhatsApp changed encryption, device linking, and session management protocols.
- **Why OpenClaw uses it:** WhatsApp is the world's most popular messaging app (~2B users). No official bot API exists for personal accounts. The WhatsApp Business API requires a business verification process and is designed for customer support, not personal assistants.
- **Ship verdict:** **No.** Not for a commercial product. The ban risk falls on the user's personal WhatsApp account. Ship WhatsApp Business API support instead if enterprise demand exists, but it's a different product (business-to-customer, not personal assistant).

### Signal (via signal-cli)

- **Method:** `signal-cli` — a third-party Java CLI that implements the Signal protocol. OpenClaw talks to it over HTTP JSON-RPC + SSE. Setup requires linking as a secondary device (QR code) or registering a new number.
- **What breaks:** `signal-cli` is a large Java dependency. It must track Signal's protocol changes independently. Linking as a secondary device works but Signal has rate-limited and blocked automated linking in the past. The SSE event stream can drop.
- **Legal risk:** **Medium.** Signal's ToS don't explicitly prohibit bots but say the service is for "personal, non-commercial" use. Signal has historically been hostile to third-party clients and could block `signal-cli`'s device fingerprint at any time.
- **Ship verdict:** **Risky.** Works today for power users willing to run Java. Not reliable enough for a product that promises "it just works." If Signal ever ships an official bot API, revisit.

### iMessage (legacy imsg CLI)

- **Method:** Native macOS binary that reads/writes `chat.db` directly. JSON-RPC over stdio.
- **What breaks:** Deprecated by OpenClaw itself. Requires macOS host. Apple can (and does) change the Messages database schema.
- **Legal risk:** **Medium.** Accessing `chat.db` directly may violate Apple's terms. Not App Store eligible.
- **Ship verdict:** **No.** Deprecated. Use BlueBubbles path instead.

### Zalo Personal (via zca-js)

- **Method:** `zca-js` library. Reverse-engineered Zalo personal account protocol. QR code login.
- **What breaks:** Same problems as WhatsApp/Baileys. Reverse-engineered, actively changes.
- **Legal risk:** **High.** Unofficial protocol. Account ban risk.
- **Ship verdict:** **No.**

---

## Bridge/Helper App — Workable but Complex

### iMessage via BlueBubbles

- **Method:** BlueBubbles is a separate macOS app (open source) that exposes iMessage via REST API + webhooks. OpenClaw connects to its HTTP API.
- **What breaks:** Requires a dedicated macOS machine running BlueBubbles. Edit messages broken on macOS Tahoe (26) due to private API changes. Messages.app must stay running (workaround: AppleScript poke every 5 min). Group icon updates inconsistent on Tahoe.
- **Legal risk:** **Low-Medium.** BlueBubbles uses macOS APIs, not direct database access. Not violating Apple ToS in the same way as imsg. But Apple could break the private APIs BlueBubbles depends on at any macOS update.
- **Ship verdict:** **Yes, with caveats.** Works well on macOS Sequoia. Requires user to run a Mac. Document the macOS version dependency. This is the only viable iMessage path.

---

## Decentralized Protocols — Niche but Clean

### Matrix

- **Method:** Official `matrix-js-sdk` + crypto module. Full E2EE support. Connects to any homeserver.
- **What breaks:** E2EE bootstrap state can corrupt (recoverable). Crypto module is a native Node addon (`@matrix-org/matrix-sdk-crypto-nodejs`), which means platform-specific builds.
- **Legal risk:** None. Open protocol. Bots are expected.
- **Ship verdict:** Post-MVP. Strong fit for privacy-focused users. E2EE is a differentiator.

### Nostr

- **Method:** `nostr-tools`. NIP-04 encrypted DMs via relay WebSockets.
- **What breaks:** Relay availability. NIP-04 is considered deprecated in favor of NIP-44 in the Nostr community. Small user base.
- **Legal risk:** None. Decentralized protocol.
- **Ship verdict:** Post-MVP. Tiny market but aligned audience (sovereignty, self-hosting).

### Tlon/Urbit

- **Method:** `@tloncorp/tlon-skill` + Urbit aura. S3 for media.
- **What breaks:** Requires Urbit infrastructure. Extremely niche.
- **Legal risk:** None.
- **Ship verdict:** No. Market too small to justify maintenance.

---

## IRC/Twitch — Simple but Limited

### IRC

- **Method:** Raw TCP socket to IRC server. Standard protocol.
- **What breaks:** Nothing, really. IRC is stable. But it's text-only, no media, no modern features.
- **Legal risk:** None.
- **Ship verdict:** Post-MVP. Easy to build, small audience.

### Twitch

- **Method:** Twurple library. Twitch chat is IRC-based + Twitch-specific extensions. OAuth token auth.
- **What breaks:** Twitch rate limits. Chat-only (no DMs).
- **Legal risk:** None. Official API.
- **Ship verdict:** Post-MVP. Streaming niche.

---

## Summary: What a New Product Can Ship With

| Channel | MVP? | Method | Risk |
|---------|------|--------|------|
| Telegram | Yes | Official Bot API | None |
| Discord | Yes | Official Bot API | None |
| Slack | Yes | Official Bolt SDK | None |
| WebChat | Yes | Built-in | None |
| Matrix | V2 | Official SDK | None |
| BlueBubbles/iMessage | V2 | Helper app REST | Low-Med |
| MS Teams | V2 | Bot Framework | None |
| WhatsApp | **No** | Reverse-engineered | **High** |
| Signal | **No** | Unofficial CLI | **Medium** |

The hard truth: WhatsApp is OpenClaw's most popular channel and the one that cannot be shipped in a commercial product. There is no clean WhatsApp personal-account bot path. This is the single biggest constraint on any replacement product.
