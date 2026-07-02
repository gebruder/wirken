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
- `metadata.wirken.requires.bins`: Required binaries. The skill is marked unavailable if any are missing. `metadata.openclaw.*` is ignored; an OpenClaw-authored skill needs `wirken skills migrate` to rewrite the key to `metadata.wirken.requires.bins`.

Wirken ships with 16 bundled skills. They are installed to `~/.wirken/skills/` on first setup.

The skills directory is always under `$HOME/.wirken` (from `HOME`, or `USERPROFILE` on Windows), not `WIRKEN_DATA_DIR`. The gateway exports `WIRKEN_DATA_DIR` to the child processes it spawns (MCP proxy, channel adapters) but does not read it for its own data directory, so skill discovery follows `HOME`. Relocating skill discovery means changing `HOME`.

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

## Phase boundaries

Skills can declare phase boundaries during a single agent turn. Each phase carries a deny set across five axes (tools, egress hosts, filesystem read paths, filesystem write paths, inference providers) that narrows what the agent can do for the remainder of the phase. The phase ends when the skill emits `wirken_exit_phase`, when the skill enters a new phase, or when the turn ends and the host auto-clears.

The canonical use case is the recon → framings → scoring shape: a skill that knows its own pass structure can declare "scoring should not write to disk or call `exec`" at the boundary, and the runtime enforces that constraint until the skill exits the phase. Defense against mid-turn drift: even if a later LLM step would otherwise call a denied tool, the gate refuses with a typed `Phase` reason in the audit chain.

### Declaring the phase tools in SKILL.md

The phase tools are LLM-visible only when the skill opts in by listing them in its `permissions.tools.allow`. A skill that does not declare them never sees the tools as available and cannot enter or exit a phase. Legacy mode (no skills attached) does not advertise the phase tools either.

```yaml
---
name: my-skill
description: Skill that runs scoped passes
permissions:
  tools:
    allow:
      - read_file
      - write_file
      - wirken_enter_phase
      - wirken_exit_phase
---
```

### Entering a phase

The LLM calls `wirken_enter_phase` with this argument shape:

```json
{
  "phase_name": "scoring",
  "denied": {
    "tools": ["exec", "write_file"],
    "egress_hosts": [],
    "paths_read": [],
    "paths_write": [],
    "inference_providers": []
  }
}
```

Result: `{"status":"ok"}` on success, or `{"status":"error","reason":"phase_already_active","active_phase":"<name>"}` when a phase is already active. The single-slot invariant is hard: the skill must exit before re-entering. Nested phases are refused so every `PhaseEntered` row in the audit chain pairs cleanly with one `PhaseExited`.

An optional `skill_id` field overrides the audit attribution (defaults to the agent id).

### Exiting a phase

The LLM calls `wirken_exit_phase` with this argument shape:

```json
{"reason": "phase_change"}
```

Accepted reasons: `"phase_change"` (default) when the skill is about to enter a new phase, `"skill_unloaded"` when the skill is finishing. The host-only `"turn_end"` is rejected at the intercept (the host emits it on every turn end; the skill is not allowed to forge it).

Result: `{"status":"ok"}` on success, or `{"status":"error","reason":"no_active_phase"}` when no phase is active.

### Lifecycle and turn-end auto-clear

- Phase enter → the overlay applies to every subsequent tool call
- Skill emits phase exit → overlay clears, next phase can enter
- Turn ends before skill exits → host auto-clears with reason `TurnEnd`

The host clears the overlay on every turn end regardless of whether the skill exited cleanly. A skill that crashes mid-phase does not leave a stale deny set active for the next turn.

### Phase audit chain

Every phase event lands in the per-session hash chain:

- `PhaseEntered { skill_id, phase_name, denied }` on every successful enter
- `PhaseExited { skill_id, phase_name, reason }` on every clear (`PhaseChange`, `TurnEnd`, `SkillUnloaded`)
- `SkillPermissionDenied { ..., denied_reason: Phase { phase_name } }` when the overlay refuses a tool call

The audit chain is replayed on agent wake: an active phase at the time of a crash is re-established on the next wake; a clean exit before the crash leaves the overlay clear. SIEM consumers correlate phase activity via `phase_name`.

### Caveats

The skill cannot read overlay state. There is no host function or tool that returns the current phase. Skills set policy; they do not query it. The audit chain is the operator's view of phase activity; the skill operates on its own pass discipline.

Lyrik's recon → framings → inline-rubric → scoring pass shape is the canonical example use case. The mechanism landed in this release; Lyrik's `SKILL.md` adoption is on a separate track.

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

Wirken reads the same `SKILL.md` frontmatter format as OpenClaw, so the files copy over directly:

```bash
cp -r ~/.openclaw/skills/* ~/.wirken/skills/
```

A copied skill is not loadable as-is; two steps follow the copy:

- **Sign it, or opt into unsigned.** The load-time signature gate refuses unsigned bundles by default. Sign each with `wirken skills sign <dir>`, or set `WIRKEN_ALLOW_UNSIGNED_SKILLS=1` to load unsigned. See [signing.md](signing.md#skill-signing).
- **Migrate the frontmatter.** Run `wirken skills migrate` to rewrite `metadata.openclaw.*` to `metadata.wirken.*` and add a default (deny-all) `permissions` block. Without a wirken `permissions` block a skill loads but has no capability. See [skill-authoring.md](skill-authoring.md#metadataopenclaw-dropped-in-140).
