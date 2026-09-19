# Getting started

Windows users: see [windows.md](windows.md) for the install path and the
operational differences. The instructions below are for Linux and macOS.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/gebruder/wirken/main/install.sh | sh
```

Pin the installer before piping it; the README carries the committed SHA-256
and [signing.md](signing.md#release-signing) describes what the installer
verifies and how to check a release by hand.

Or build from source. The minimum supported Rust version is declared as
`rust-version` in `Cargo.toml` and verified in CI on that exact toolchain. You
also need the Cap'n Proto compiler:

```bash
sudo apt-get install -y capnproto     # or: brew install capnp
cargo install --path crates/cli
```

OpenSSL arrives as a transitive dependency of some channel SDKs but is built
with the `vendored` feature, so it compiles from source: no system OpenSSL
headers are needed and the resulting binary does not link against the host
OpenSSL. Outbound HTTPS uses `rustls`.

## Setup

```bash
wirken setup
```

Six steps, about a minute:

1. **Provider.** Ollama, NIM, Anthropic, OpenAI, Gemini, Bedrock, Tinfoil,
   Privatemode, Infomaniak, Hetzner, or a custom OpenAI-compatible endpoint.
   Your API key is encrypted immediately.
2. **Channels.** Telegram, Discord, Slack, Teams, Matrix, Signal, Google Chat,
   iMessage, WhatsApp. Each token is encrypted separately into the vault.
3. **Credentials recap.** What is now in the vault.
4. **Service install.** Optionally a systemd user unit or launchd agent so
   wirken starts on login. Declined by default.
5. **Sandbox mode.** `exec-only` by default, `gvisor` when `runsc` is
   registered with Docker.
6. **Audit log.** Where the hash-chained log lives and when it is created.

16 bundled skills are installed automatically.

## Run

```bash
wirken run
```

Spawns an adapter process per channel, serves the WebChat UI at
`http://localhost:18790`, and waits for messages. All local services bind to
127.0.0.1.

Send a test message from a configured channel, or open WebChat in a browser.

## Without a channel

```bash
wirken ask -m "what time is it?"
```

Sends a message directly to the agent and prints the response. Run it from a
terminal: the approval gate attaches only when stdin is a TTY.

## Next

```bash
wirken channel add discord        # add channels later
wirken skills search weather      # find and install skills
wirken skills install weather
wirken doctor                     # verify the install
```

Skills that call the `http_request` tool declare the `credentials.allow` and
`http.post_paths` permission fields, which require Wirken 1.10 or later. An
older binary refuses to load such a skill, fail-closed, and the failure reads
as a parse rejection.

- [Configuration reference](configuration.md) for every config file and option
- [Channels](channels.md) for per-channel setup
- [MCP setup](mcp.md) to connect external tool servers
- [Skills](skills.md) to write your own
- [Deploying for a team](enterprise.md) for org config and shared instances

## Coming from OpenClaw

Skills copy over directly; see
[skills.md](skills.md#coming-from-openclaw) for the two steps that follow the
copy.

Credentials do not. Wirken does not import OpenClaw's plaintext credential
files, so re-enter them through `wirken setup`, `wirken channel add
<channel>`, or `wirken credentials add <name>`. Each is encrypted immediately
with XChaCha20-Poly1305 into `<data_dir>/vault.db`.

Configuration has no file to edit by hand. OpenClaw keeps
`~/.openclaw/openclaw.json`; Wirken keeps `provider.json` plus a set of
SQLite databases, all driven through the CLI. See
[configuration.md](configuration.md).

Agent behavior differs in shape. OpenClaw uses bootstrap files (`AGENTS.md`,
`SOUL.md`, `TOOLS.md`, `USER.md`); Wirken uses a built-in system prompt with
skill injection, so customization means writing skills.

| OpenClaw | Wirken |
|----------|--------|
| TypeScript, Node.js runtime | Rust, single static binary |
| Single process, all channels in-process | Separate process per channel |
| Plaintext credentials on disk | Encrypted vault, OS keychain |
| No audit trail | Append-only hash-chained audit log |
| `npm install -g openclaw` | `curl -fsSL .../install.sh \| sh` |
| `openclaw onboard` | `wirken setup` |
| `openclaw gateway` | `wirken run` |

Voice and TTS, mobile companion apps, and Matrix E2EE have no Wirken
equivalent.
