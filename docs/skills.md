# Skills Guide

Skills are instructions and tools that extend what the agent can do. There are three types:

## Markdown skills

A `SKILL.md` file with instructions the agent reads as part of its system prompt. The agent uses its built-in tools (shell exec, file read/write, web search) to carry out the instructions.

Example (`~/.wirken/skills/weather/SKILL.md`):

```markdown
---
name: weather
description: Get current weather and forecasts
metadata:
  wirken:
    requires:
      bins: [curl]
---

# Weather

Get weather using wttr.in.

- Current weather: `curl -s "wttr.in/CityName?format=3"`
- Detailed forecast: `curl -s "wttr.in/CityName"`
```

The frontmatter fields:
- `name`: Skill name (falls back to directory name)
- `description`: One-line description
- `disable-model-invocation`: Boolean. Defaults to `true`. See "Auto-invocation vs explicit invocation" below.
- `metadata.wirken.requires.bins`: Required binaries. The skill is marked unavailable if any are missing. `metadata.openclaw.requires.bins` is accepted as a deprecated alias.

Wirken ships with 16 bundled skills. They are installed to `~/.wirken/skills/` on first setup.

### Auto-invocation vs explicit invocation

Skills are explicit-invocation by default. The agent does not auto-fire a skill from a generic prompt that matches its description; the operator (or the skill's wrapper, like the Lyrik runner) invokes it by name with a slash prefix.

A skill becomes auto-invocable only by declaring `disable-model-invocation: false` in its frontmatter. The auto-pickable set is built at skill-load time and is excluded from the system prompt for any skill where the field is `true` or absent.

Explicit invocation form:

```
/<skill-name> <remainder of the user message>
```

The slash interceptor matches `^/<name>(\s|$)` strictly. A bare `/`, a slash in the middle of a sentence, or a leading-slash URL fragment are not invocations. An unknown skill name with a slash prefix is rejected loudly rather than treated as plain text, so a typo never silently falls through to an LLM that has no skill body for it.

Default-true is Wirken's posture: auto-fire requires explicit author opt-in. Side-effecting skills (state mutation, file writes), resource-expensive skills (long pipelines, large model runs), and command-shaped skills (`/lyrik`, `/<walk-name>`, etc.) are the canonical fits for the default. Add `disable-model-invocation: false` only when a skill is safe to auto-fire on a description match alone.

## Wasm skills

A compiled WebAssembly module that runs as a custom tool inside a Wasmtime sandbox.

Place a `skill.wasm` file alongside the `SKILL.md`:

```
~/.wirken/skills/my-tool/
  SKILL.md       # frontmatter with name, description, parameters schema
  skill.wasm     # compiled Wasm module
```

The module communicates via stdin/stdout:
- **Input**: JSON object with the tool arguments (written to stdin)
- **Output**: JSON object with the result (read from stdout)

The sandbox provides:
- No filesystem access
- No network access
- 64MB memory limit
- Fuel-based CPU limit (prevents infinite loops)

Add a `parameters` field to the SKILL.md frontmatter to define the JSON schema:

```yaml
---
name: hash
description: Compute SHA-256 hash of input text
parameters:
  type: object
  properties:
    text:
      type: string
      description: Text to hash
  required: [text]
---
```

The tool appears to the LLM as `wasm_hash`.

## Installing skills from the registry

```bash
wirken skills search <query>
wirken skills install <name>
```

Skills from the registry are verified against the registry-provided Ed25519 signature before installation.

## Signing skills

```bash
wirken skills sign ./my-skill/
wirken skills verify ./my-skill/
```

The first `sign` generates a signing keypair at `~/.wirken/signing-key.hex`. The public key is printed for inclusion in the skill registry.

## Skill compatibility

Wirken reads the same `SKILL.md` frontmatter format as OpenClaw. Most OpenClaw skills work without modification:

```bash
cp -r ~/.openclaw/skills/* ~/.wirken/skills/
```
