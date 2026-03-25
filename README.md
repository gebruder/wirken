# Wirken

Secure personal AI agent gateway. Written in Rust.

See [docs/architecture.md](docs/architecture.md) for the full product specification.

## Build

```bash
cargo build
```

## Test

```bash
cargo test
```

## Workspace Structure

```
crates/
  vault/            - Credential encryption, keychain integration
  audit/            - Append-only hash-chained audit log
  ipc/              - Cap'n Proto schema, UDS transport, Ed25519 adapter auth
  gateway/          - Core routing, sessions, LLM proxy, permissions, rate limiting
  adapter-telegram/ - Telegram Bot API connector
  agent/            - LLM interaction, tool execution, workspace
  cli/              - Setup wizard, channel management, audit queries
  webchat/          - Embedded static HTTP server
```
