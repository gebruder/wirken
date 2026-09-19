# Multiple agents

Route different channels to different agents, each with its own model, API
key, workspace and skills. A work agent on Slack using Claude with GitHub and
Datadog MCP servers; a personal agent on Telegram using GPT with notes and
calendar skills; a coding agent on Discord on a local Ollama model. Each has
its own conversation history, workspace directory and credentials, and they
share no state.

Command syntax is in [cli.md](cli.md#wirken-agents).

## Creating and binding

```bash
wirken agents add          # prompts for id, provider, model, API key
wirken agents bind work slack
wirken agents bind personal telegram
wirken agents list
```

Each channel binds to exactly one agent; binding it to a new agent removes it
from the previous one. Channels not explicitly bound route to the `default`
agent, which exists automatically from initial setup and uses the provider
configured during `wirken setup`. On `wirken run` the startup output shows the
routing:

```
  Route: slack -> agent:work (anthropic/claude-sonnet-4-20250514)
  Route: telegram -> agent:personal (openai/gpt-4o)
```

`wirken agents remove` drops the configuration and channel bindings; the
workspace directory and skills stay on disk.

## Per-agent state

- **Workspace.** `<data_dir>/workspace/` for the default agent,
  `<data_dir>/agents/{id}/workspace/` for named ones. File operations are
  confined to the agent's own; files the work agent creates are not visible to
  the personal agent.
- **Skills.** Loaded from `<data_dir>/agents/{id}/skills/` (agent-specific)
  and `<data_dir>/skills/` (shared by all agents). To give one agent GitHub
  and not another, copy the skill directory into that agent's tree.
- **MCP servers.** `<data_dir>/agents/{id}/mcp.json` when present, otherwise
  the shared `<data_dir>/mcp.json`. See [mcp.md](mcp.md).

Agents can reuse one provider config or override provider, model, API key and
tool settings in `agent_config.db`.

## Personas

A persona is the operator-facing handle for an agent: a named bundle of agent
configuration saved once and referenced by name. Internally it is an
`AgentConfig` row with an optional reference to a `Preset` (a skill bundle).
`wirken agents` is raw config CRUD and `wirken preset` is bundle management;
`wirken persona` composes both and is the entry point for typical workflows.

```bash
wirken persona create alice --preset analyst --provider anthropic \
    --model claude-sonnet-4-5 --channel telegram --channel signal
wirken persona list
wirken persona show alice
wirken persona edit alice --provider openai --model gpt-5
```

Defaults are the `openai` provider, `gpt-4o`, and
`https://api.openai.com/v1`. Channels and the preset reference are unset.

A persona expands at agent construction time into materialized configuration;
the agent carries the materialized state, not a persona reference. Editing or
deleting a persona after an agent has started does not affect the running
agent, and the next invocation picks up the new state.

`wirken ask` accepts a persona name via `--agent` or its alias `--persona`;
both resolve the same row. Adapter-routed sessions use the persona's
configuration when the channel is bound to it, through the same construction
path, so resolution is identical across the interactive and adapter-routed
surfaces.

### Dangling preset references

A persona can be created against a preset that is not installed. The two
surfaces then diverge deliberately.

`wirken persona show` treats it as inspectable: annotates the reference "not
installed" on stdout, warns on stderr, exits zero, and shows the rest of the
fields. Inspection tolerates incomplete state because the operator needs to
see what is broken to fix it.

`wirken ask --agent <name>` and `wirken run` treat it as a configuration
error and hard-fail, naming both recovery paths:

```
persona 'alice' references preset 'analyst' which is not
installed at /home/alice/.wirken/presets/analyst.
Either install the preset:
    wirken preset install analyst
Or clear the reference:
    wirken persona edit alice --clear-preset
```

Execution refuses to run an agent that cannot deliver its promised skills,
because the LLM would otherwise attempt the task without tools the operator
configured, or make calls against the base profile that the preset would have
restricted.

## Sub-agent orchestration

A parent agent delegates a bounded subtask through the built-in
`spawn_subagent` tool. The operator configures which children each parent may
spawn, with a per-child capability ceiling:

- **`tool_allowlist`**: the child sees only tools in this list, intersected
  with whatever the LLM passes in the spawn call. Anything outside is dropped.
- **`max_permission_tier`**: tools above this tier are auto-denied with no
  interactive prompt, because children run headless.
- **`max_rounds`**: LLM rounds before the parent reports `rounds_exceeded`.
- **`max_runtime_secs`**: wall-clock timeout for the whole invocation.

```bash
wirken agents allow-subagent parent child \
    --tools "read_file,web_search" --max-tier tier1 --max-rounds 5 --max-runtime 30
```

The LLM cannot widen these. The parent's harness intersects, clamps and
enforces; the ceiling is stored as JSON in `agents.allowed_subagents`. There
is a hard depth cap of 4 to prevent nesting cycles, and the parent's LLM sees
only a JSON result envelope carrying the child's final response and status.

Delegation works the same on every channel: the streaming dispatch (webchat)
and the non-streaming one (cron, adapters, `wirken ask`) build the offered
tool set from one place, so a configured ceiling reaches the model regardless
of what drove the turn.

Each child runs under its own session id (`{parent_session_id}#sub-{n}`), so
parent and child audit independently. See
[audit-cli.md](audit-cli.md#sub-agent-sessions-and---with-parent).

### A child runs on its own grants

The permission gate takes the session id and the logical agent id as separate
arguments. Session-scoped grants key on the session; persisted grants key on
the agent. A child's session id is its parent's with a `#sub-N` suffix and its
agent id is whatever config it was woken as, so neither kind of grant reaches
it from its caller.

Grants do not compose in the other direction either: a child's grant applies
to the child alone, and a parent gains nothing from what its children are
allowed. There is no intersection logic; each agent is checked against itself.

An agent that was never told which logical agent it is gets no persisted
grants and prompts for every Tier 2 action. That is the safe direction, and it
means a caller building an agent directly must name it (`set_agent_id`) before
attaching a permission store. The factory does this at wake for every agent it
produces, sub-agents included.

Sub-agents run in the parent's process.
