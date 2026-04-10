# Configuration Reference

All configuration lives in `~/.wirken/`. There are no hidden config files or environment variables required.

## Files

| File | Purpose | Created by |
|------|---------|-----------|
| `provider.json` | LLM provider, model, and base URL | `wirken setup` |
| `vault.db` | Encrypted credentials (API keys, bot tokens) | `wirken setup` |
| `audit.db` | Session log (`session_events` table, per-session hash chain) + legacy `audit_events` view for SIEM | `wirken run` |
| `sessions.db` | Session metadata (id, channel, conversation_id, timestamps, message count) | `wirken run` |
| `agent_config.db` | Registered agent configs, channel bindings, subagent ceilings | `wirken agents add` |
| `permissions.db` | Tool approval records | `wirken run` |
| `adapters.db` | Registered channel adapters and Ed25519 keys | `wirken channel add` |
| `cron.db` | Scheduled cron jobs | `wirken cron create` |
| `siem.json` | SIEM forwarding config (optional) | Manual or org config |
| `mcp.json` | MCP server config (optional) | Manual or org config |
| `org.url` | Organization config endpoint (optional) | `wirken setup --org` |
| `skills/` | Installed skills (SKILL.md + optional skill.wasm) | `wirken skills install` or setup |
| `sockets/` | Unix domain sockets for IPC | `wirken run` |
| `workspace/` | Default agent workspace (file operations happen here) | `wirken run` |

## provider.json

```json
{
    "provider": "openai",
    "model": "gpt-4o",
    "base_url": "https://api.openai.com/v1"
}
```

Supported providers: `openai`, `anthropic`, `gemini`, `bedrock`, `ollama`, `custom`.

For Bedrock, add a `region` field:

```json
{
    "provider": "bedrock",
    "model": "anthropic.claude-sonnet-4-20250514-v2:0",
    "base_url": "https://bedrock-runtime.us-east-1.amazonaws.com",
    "region": "us-east-1"
}
```

## siem.json

Forward audit events to a SIEM in real time.

### Datadog

```json
{
    "target": "datadog",
    "endpoint": "https://http-intake.logs.datadoghq.com/api/v2/logs",
    "api_key": "your-dd-api-key",
    "service": "wirken",
    "environment": "production"
}
```

### Splunk

```json
{
    "target": "splunk",
    "endpoint": "https://your-splunk:8088/services/collector/event",
    "api_key": "your-hec-token",
    "service": "wirken",
    "environment": "production"
}
```

### Generic webhook

```json
{
    "target": "webhook",
    "endpoint": "https://your-endpoint.example.com/audit",
    "api_key": "optional-bearer-token",
    "service": "wirken",
    "environment": "production"
}
```

## mcp.json

Connect to MCP (Model Context Protocol) servers. Tools discovered from MCP servers are available to the agent alongside built-in tools.

```json
{
    "servers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"],
            "env": {}
        },
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {
                "GITHUB_TOKEN": "vault:github-token"
            }
        }
    }
}
```

The `vault:` prefix resolves values from the encrypted credential vault at runtime.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `WIRKEN_DATA_DIR` | Override the data directory (default: `~/.wirken`) |
| `WIRKEN_SKILLS_INDEX` | Override the skill registry URL |
| `WIRKEN_CACHE_MODE` | `drop` bypasses the agent LRU cache — every inbound message wakes a fresh agent from the session log. Used in CI to assert cache equivalence. Default: `cached`. |
| `WIRKEN_AGENT_CACHE_SIZE` | LRU cache capacity (number of hot sessions). Default: `64`. |
| `RUST_LOG` | Control log verbosity (e.g., `RUST_LOG=wirken=debug`) |
