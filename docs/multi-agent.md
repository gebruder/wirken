# Multi-Agent Setup

Route different channels to different agents, each with its own model, API key, workspace, and skills.

For an operator-facing workflow that bundles agent configuration with a skill preset under a single named handle, see [`personas.md`](personas.md). The `wirken persona` subcommand composes the lower-level `wirken agents` and `wirken preset` surfaces covered on this page.

## Why

You might want separate agents for separate contexts:

- A work agent on Slack and Teams using Claude, with access to GitHub and Datadog MCP servers
- A personal agent on Telegram using GPT, with access to your notes and calendar skills
- A coding agent on Discord using a local Ollama model, sandboxed

Each agent has its own conversation history, workspace directory, and credentials. They don't share state.

## Create an agent

```bash
wirken agents add
```

The wizard prompts for:

1. Agent ID (e.g., `work`, `personal`, `code`)
2. Provider (OpenAI, Anthropic, Gemini, etc.)
3. Model
4. API key (encrypted into the vault)

## Bind channels to agents

```bash
wirken agents bind work slack
wirken agents bind work teams
wirken agents bind personal telegram
wirken agents bind code discord
```

Each channel can only be bound to one agent. Binding a channel to a new agent removes it from the previous one.

## Check your routing

```bash
wirken agents list
```

On `wirken run`, the startup output shows the routing:

```
  Route: slack -> agent:work (anthropic/claude-sonnet-4-20250514)
  Route: teams -> agent:work (anthropic/claude-sonnet-4-20250514)
  Route: telegram -> agent:personal (openai/gpt-4o)
  Route: discord -> agent:code (ollama/llama3)
```

## Per-agent skills

Each agent loads skills from two locations:

1. `~/.wirken/agents/{agent-id}/skills/` (agent-specific)
2. `~/.wirken/skills/` (shared, loaded by all agents)

To give the work agent access to GitHub but not the personal agent:

```bash
mkdir -p ~/.wirken/agents/work/skills/
cp -r ~/.wirken/skills/github ~/.wirken/agents/work/skills/
```

## Per-agent MCP servers

Place an `mcp.json` at `~/.wirken/agents/{agent-id}/mcp.json` to give an agent its own MCP servers. If no per-agent config exists, the shared `~/.wirken/mcp.json` is used.

```bash
# Give the work agent access to Datadog
cat > ~/.wirken/agents/work/mcp.json << 'EOF'
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
EOF
```

## Per-agent workspaces

Each agent's file operations are confined to its own workspace:

- Default agent: `~/.wirken/workspace/`
- Named agents: `~/.wirken/agents/{agent-id}/workspace/`

Files created by the work agent are not visible to the personal agent.

## Send a message to a specific agent

```bash
wirken ask -m "summarize today's PRs" --agent work
wirken ask -m "what's the weather" --agent personal
```

## Default agent

If any channels are not explicitly bound to an agent, they route to the `default` agent. The default agent uses the provider configured during `wirken setup`.

You don't need to create a default agent. It exists automatically from your initial setup.

## Remove an agent

```bash
wirken agents remove code
```

This removes the agent configuration and channel bindings. The workspace directory and skills are not deleted.

## Sub-agent orchestration

A parent agent can delegate bounded subtasks to child agents via the built-in `spawn_subagent` tool. The operator configures which children each parent is allowed to spawn, with a per-child capability ceiling.

The ceiling controls:
- **tool_allowlist** — the child only sees tools in this list (intersection with anything the LLM passes in the spawn call).
- **max_permission_tier** — the child's permission tier is clamped to this level. Anything above is auto-denied with no interactive prompt.
- **max_rounds** — maximum LLM rounds before the parent reports `rounds_exceeded`.
- **max_runtime_secs** — wall-clock timeout for the entire child invocation.

Children run headless — no interactive permission approvals, isolated session logs, and a hard depth cap of 4 to prevent nesting cycles. The parent's LLM sees only a JSON result envelope containing the child's final response and status.

Ceilings are configured in `AgentConfig.allowed_subagents` (stored as JSON in the `agents` table). `wirken agents allow-subagent <parent> <child>` sets a ceiling with `--tools`, `--max-tier`, `--max-rounds`, and `--max-runtime` flags; `wirken agents deny-subagent <parent> <child>` removes a child from a parent's allowed set.

Each child runs under its own session id (`{parent_session_id}#sub-{n}`) so `wirken sessions verify` can audit the parent and child independently.
