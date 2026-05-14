# Personas

A persona is the operator-facing handle for an agent: a named bundle
of agent configuration that you save once and reference by name on
subsequent commands.

## What a persona is

A persona carries the agent's identity, provider preference, channel
bindings, subagent permissions, and an optional reference to a
`Preset` (skill bundle). The persona expands at agent construction
time into the materialized configuration; the agent carries the
materialized state, not a persona reference. Editing or deleting a
persona after an agent has started running does not affect the
running agent. The next invocation picks up the new state.

Internally a persona is an `AgentConfig` row in the operator's
wirken store with an optional reference to a preset. The lower-level
commands `wirken agents` and `wirken preset` remain available;
`wirken persona` is the operator-facing entry point that composes
both surfaces.

## Creating a persona

```bash
wirken persona create alice \
    --preset analyst \
    --provider anthropic \
    --model claude-sonnet-4-5 \
    --channel telegram \
    --channel signal
```

All flags after the name are optional. The defaults are `openai`
provider, `gpt-4o` model, and `https://api.openai.com/v1` base URL.
Channels and the preset reference are unset by default.

If the named preset is not installed at create time, the persona is
saved with a dangling reference and a warning is printed on stderr.
Install the preset later with `wirken preset install <name>` to
resolve.

## Listing and inspecting personas

```bash
wirken persona list
wirken persona show alice
```

`show` pretty-prints the materialized view: identity, provider,
channels, preset, the skills declared by the preset, and the
subagent allowlist. If the persona's preset reference is dangling
(the named preset is not installed), `show` surfaces the reference
with a "not installed" annotation on stdout, prints a warning on
stderr, and still exits zero so the rest of the persona's fields
remain readable.

## Editing a persona

```bash
wirken persona edit alice --provider openai --model gpt-5
wirken persona edit alice --clear-preset
wirken persona edit alice --preset researcher
```

At least one field flag is required; bare `wirken persona edit
alice` errors and prints the available flags. `--clear-preset`
removes the preset reference (distinct from omitting `--preset`,
which leaves the reference unchanged). `--preset` and
`--clear-preset` are mutually exclusive.

The full edit surface is: `--preset`, `--clear-preset`,
`--provider`, `--model`, `--base-url`, `--credential`, `--channel`
(repeats to replace the channel set), `--display-name`.

## Using a persona

`wirken ask` accepts a persona name via `--agent` or its alias
`--persona`:

```bash
wirken ask -m "what's on my calendar today" --agent alice
wirken ask -m "what's on my calendar today" --persona alice
```

The two flags resolve the same `AgentConfig` row. The persona's
preset (if any) is materialized at construction time and its
declared skills are merged into the agent alongside the per-agent
and shared skill directories.

Adapter-routed sessions (Telegram, Signal, Slack, Discord, etc.)
automatically use the persona's configuration when the channel is
bound to that persona. The same construction path runs server-side
during `wirken run`, so persona resolution is identical across the
interactive and adapter-routed surfaces.

## Dangling preset references

`wirken persona show` treats a dangling reference as inspectable:
warns on stderr, exits zero, shows the rest of the persona's fields.

`wirken ask --agent <name>` treats a dangling reference as a
configuration error: exits non-zero with a structured message
naming both recovery paths. The error reads, for example:

```
persona 'alice' references preset 'analyst' which is not
installed at /home/alice/.wirken/presets/analyst.
Either install the preset:
    wirken preset install analyst
Or clear the reference:
    wirken persona edit alice --clear-preset
```

`wirken run` (the daemon) follows the same hard-fail rule at
startup: a persona with a dangling preset reference blocks the
daemon from starting until the operator resolves it.

The asymmetry between `show` (warn) and the construction surfaces
(hard fail) is intentional. Inspection tolerates incomplete state
because the operator needs to see what is broken to fix it.
Execution refuses to run an agent that cannot deliver its promised
skills, because the LLM would otherwise either attempt the task
without tools the operator configured or make calls against the
base profile that the persona's preset would have restricted.

## Layering with `wirken agents` and `wirken preset`

`wirken agents`: raw `AgentConfig` CRUD. Bypasses the persona
layering. Useful for advanced cases, migration scripts, or partial
edits the persona surface does not expose (`wirken agents
allow-subagent` for detailed subagent ceilings, for example).

`wirken preset`: skill-bundle management. Personas reference
presets by name but do not own them; a single preset can back
multiple personas. Install a preset once with `wirken preset
install <name>`; multiple personas can then reference it.

`wirken persona`: operator-facing entry point that composes the
two. Use this for typical workflows.
