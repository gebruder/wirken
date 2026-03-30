# OpenClaw: Feature Extraction

What OpenClaw lets a user do, extracted from the v2026.3.14 codebase.

## Channels Supported

23 messaging surfaces, plus voice and a web UI.

**Tier 1 — primary channels, heavily maintained:**
- WhatsApp (personal account, QR pairing)
- Telegram (bot account)
- Discord (bot account, guilds + DMs)
- Slack (workspace app, Socket Mode or HTTP Events)
- Signal (linked device via signal-cli)
- iMessage via BlueBubbles (macOS helper app + REST)

**Tier 2 — official-API plugins, community or lightly maintained:**
- Microsoft Teams (Bot Framework)
- Google Chat (Chat API webhooks)
- Matrix (matrix-js-sdk, E2EE)
- LINE (Messaging API)
- Feishu/Lark (Bot SDK)
- IRC (raw TCP)
- Twitch (Twurple/IRC)
- Mattermost (Bot API + WebSocket)
- Nextcloud Talk (webhook bot)
- Synology Chat (webhooks)
- Nostr (NIP-04 relay DMs)
- Tlon/Urbit (Urbit aura + S3)
- Zalo (Bot API, Vietnam market)

**Tier 3 — unofficial/reverse-engineered:**
- Zalo Personal (zca-js, QR login to personal account)
- iMessage legacy (imsg CLI, deprecated)

**Non-messaging surfaces:**
- WebChat (gateway's built-in browser UI)
- Voice calls (WebSocket transport plugin)
- macOS menu bar app (companion)
- iOS and Android companion apps (nodes)
- Voice Wake (wake word on macOS/iOS) + Talk Mode (continuous voice on Android)
- Live Canvas (agent-driven visual workspace, A2UI)

## Agent Actions

What the assistant can do once running:

- **Converse** across any connected channel with session continuity
- **Execute shell commands** on the gateway host (with approval flow or sandbox)
- **Browse the web** via built-in browser tool
- **Search the web** (provider-backed)
- **Read, write, edit files** in the workspace
- **Apply patches** to code
- **Send messages** to other channels/contacts proactively
- **Render Canvas** — live visual workspace controllable by the agent
- **Schedule cron jobs** — recurring agent tasks
- **Manage sessions** — create, list, close, switch
- **Process media** — images, audio, video transcription, TTS
- **Generate images** (via provider skills like DALL-E)
- **Use skills** — extensible tool plugins (see below)
- **Route to other agents** — multi-agent with isolated workspaces

## Skill Categories

~54 bundled skills across these categories:

| Category | Examples |
|----------|----------|
| Development | github, github-issues, coding-agent, skill-creator |
| Communication | discord actions, slack actions, imsg, bluebubbles |
| Productivity | apple-notes, apple-reminders, trello, notion, obsidian, things-mac |
| Media | openai-image-gen, openai-whisper, camsnap, video-frames |
| System | tmux, peekaboo (screen capture), node-connect |
| Search | weather, spotify-player |
| Meta | clawhub (skill marketplace), session-logs |

Three-tier loading: bundled (lowest priority) < managed (`~/.openclaw/skills`) < workspace (`<workspace>/skills`). ClawHub is the marketplace for community skills.

Skills are metadata-gated (required binaries, env vars, config keys). A regex-based security scanner blocks skills that use `eval()`, shell exec, crypto-mining patterns, or env-harvesting-plus-network-exfiltration combos. No code signing. No sandbox by default.

## LLM Providers

Built-in: **OpenAI**, **Anthropic**, **Google Gemini**, **AWS Bedrock**, **Ollama** (local), and any **OpenAI-compatible endpoint**.

Bedrock uses AWS SigV4 request signing (access key + secret key, optional session token). Gemini uses the generateContent API with API key auth. Per-agent model config. Key rotation supported.

## Onboarding

**Two commands to running assistant:**

```bash
npm install -g openclaw@latest
openclaw onboard --install-daemon
```

Interactive onboard walks through:
1. Security notice and trust model acknowledgment
2. Gateway location (local / remote / later)
3. Platform permissions (macOS: AppleScript, notifications, accessibility, mic, camera)
4. Model provider selection + API key entry
5. Workspace setup
6. Optional channel setup

Non-interactive mode exists for scripted installs (`--non-interactive --accept-risk`).

The daemon is installed as a launchd (macOS) or systemd (Linux) user service.

## Daily Interaction Model

1. **User sends message** on any connected channel (WhatsApp, Telegram, Discord, etc.)
2. **Gateway receives**, deduplicates, debounces rapid messages from same sender
3. **Routing** resolves which agent handles the message (via channel bindings)
4. **Session** loaded or created (per-contact for DMs, per-group for groups)
5. **Agent runs** — LLM inference + tool calls, serialized per-session
6. **Reply streams** back (block streaming where supported, chunked to channel limits)
7. **Reply delivered** to the originating channel

**Queue modes** when agent is mid-turn: interrupt (cancel current), steer (inject mid-run), followup (queue for next turn), collect (batch before next turn).

**Group behavior:** mention-gated by default (agent only responds when @mentioned). Configurable per-group activation.

**Proactive actions:** Agent can send messages, run cron tasks, and trigger actions without user prompting.

**Control surfaces:** CLI (`openclaw agent --message "..."`), WebChat UI, companion apps, any connected channel.

## What Makes It Sticky

- One install, every channel the user already uses
- Speaks back where you spoke to it
- Workspace files persist personality and memory across sessions (AGENTS.md, SOUL.md, USER.md)
- Skills extend capability without code (drop a skill folder, it appears)
- Local-first: no cloud account required (Ollama path)
- Voice wake + talk mode make it feel ambient on Apple/Android devices
- Canvas gives the agent a visual output surface beyond chat bubbles
