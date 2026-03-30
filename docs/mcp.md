# MCP Setup

Wirken includes an MCP (Model Context Protocol) client. MCP servers expose tools, resources, and prompts that the agent can use alongside its built-in tools.

## Configuration

Create `~/.wirken/mcp.json`:

```json
{
    "servers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"],
            "env": {}
        }
    }
}
```

Each server entry specifies a command to spawn. Wirken communicates with the server over stdin/stdout using JSON-RPC 2.0.

## Using vault secrets in MCP config

Prefix environment variable values with `vault:` to resolve them from the encrypted credential vault:

```json
{
    "servers": {
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

Store the secret first:

```bash
wirken credentials add github-token
```

## How it works

On startup, wirken:

1. Spawns each configured MCP server as a child process
2. Performs the MCP `initialize` handshake
3. Calls `tools/list` to discover available tools
4. Adds discovered tools to the agent's tool definitions (prefixed with `mcp_{server}_`)

When the LLM calls an MCP tool, wirken routes the call to the correct server via `tools/call` and returns the result.

## Per-agent MCP config

For multi-agent setups, place the config at `~/.wirken/agents/{agent-id}/mcp.json`. If a per-agent config doesn't exist, the shared `~/.wirken/mcp.json` is used.

## Example: Datadog MCP

Connect the agent to Datadog for querying logs, metrics, and incidents:

```json
{
    "servers": {
        "datadog": {
            "command": "npx",
            "args": ["-y", "@datadog/mcp-server"],
            "env": {
                "DD_API_KEY": "vault:datadog-api-key",
                "DD_APP_KEY": "vault:datadog-app-key"
            }
        }
    }
}
```

## Supported transports

Currently supported: **stdio** (spawn process, communicate via stdin/stdout).

SSE transport is planned for connecting to remote MCP servers.
