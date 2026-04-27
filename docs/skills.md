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
- `metadata.wirken.requires.bins`: Required binaries. The skill is marked unavailable if any are missing. `metadata.openclaw.requires.bins` is accepted as a deprecated alias.

Wirken ships with 16 bundled skills. They are installed to `~/.wirken/skills/` on first setup.

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
