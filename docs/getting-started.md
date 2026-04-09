# Getting Started

## Install

Download the binary:

```bash
curl -fsSL https://raw.githubusercontent.com/gebruder/wirken/main/install.sh | sh
```

Or build from source (requires Rust 1.85+ and the `capnp` compiler):

```bash
# Ubuntu/Debian
sudo apt-get install -y capnproto

# macOS
brew install capnp

cargo install --path crates/cli
```

OpenSSL is pulled in as a transitive dependency of some channel SDKs but is built with the `vendored` feature, so it compiles from source — no system OpenSSL headers are needed and the resulting binary does not link against the host OpenSSL. Outbound HTTPS uses `rustls`.

## Setup

Run the setup wizard:

```bash
wirken setup
```

This walks you through:

1. **Pick a provider.** OpenAI, Anthropic, Gemini, Bedrock, Tinfoil, Privatemode, Ollama, or a custom endpoint. Your API key is encrypted immediately.
2. **Pick your channels.** Telegram, Discord, Slack, Teams, or Matrix. Each bot token is encrypted into the vault.
3. **Service install.** Optionally install as a systemd/launchd service so the gateway starts on login.

15 bundled skills (weather, github, git, tmux, docker, etc.) are installed automatically.

## Run

```bash
wirken run
```

This starts the gateway. It spawns adapter processes for each channel, starts the WebChat UI at `http://localhost:18790`, and waits for messages.

Send a test message from your configured channel, or open the WebChat in a browser.

## Quick test without a channel

```bash
wirken ask -m "what time is it?"
```

This sends a message directly to the agent and prints the response. No channel setup needed.

## Add more channels later

```bash
wirken channel add discord
wirken channel add slack
```

## Install skills from the registry

```bash
wirken skills search weather
wirken skills install weather
```

## Check everything is working

```bash
wirken doctor
```

## Next steps

- [Configuration reference](configuration.md) for all config files and options
- [MCP setup](mcp.md) to connect external tool servers
- [Skills guide](skills.md) to write your own skills
- [Enterprise setup](enterprise.md) for centralized deployment
