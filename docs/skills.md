# Skills

A skill is an operator-installable behavior bundle: a directory whose basename
is the skill name, containing `SKILL.md` and optionally a compiled
`skill.wasm` and a `SKILL.sig` / `SKILL.pub` pair.

```
my-skill/
├── SKILL.md     (required)
├── SKILL.sig    (required unless the unsigned bypass is set)
├── SKILL.pub    (pairs with SKILL.sig)
├── SKILL.deleg  (required once an operator registry root is configured)
└── skill.wasm   (optional; loaded by its fixed filename, no frontmatter key)
```

`SKILL.md` is YAML frontmatter followed by a markdown body. The body is what
the LLM reads as the skill's instructions; the frontmatter is what the loader
reads to validate identity and capability.

Skills load from `<data_dir>/skills/` and, for a named agent, from
`<data_dir>/agents/{id}/skills/`. The data directory is `WIRKEN_DATA_DIR` when
set and `~/.wirken` otherwise. The gateway, the CLI and the load-time
signature gate all resolve it the same way, so discovery and the gate never
look in different places.

## Two kinds of skill

**Markdown skills** are the majority: instructions the agent reads as part of
its system prompt, carried out with the built-in tools. Zero compilation, zero
migration.

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

- Current weather: `curl -s "wttr.in/CityName?format=3"`
- Detailed forecast: `curl -s "wttr.in/CityName"`
```

A markdown skill is not itself sandboxed. What confines it is the tools it
drives: `exec` runs in a container ([sandbox-properties.md](sandbox-properties.md))
and every tool call passes the tier gate
([permissions-and-identity.md](permissions-and-identity.md)).

Wirken ships 16 bundled skills, installed to `<data_dir>/skills/` on first
setup. Each arrives with the `SKILL.sig`, `SKILL.pub` and `SKILL.deleg`
committed alongside it in the repo, produced offline by the project
skill-signing key and delegated under the project registry root. Nothing is
signed at install time, so no signing key is needed on the gateway host, and
the bundle you run carries the same signature the project published rather
than one your machine minted for itself.

Skills already on disk are left untouched, since writing a fresh signature
over them would make an edited bundle look authentic.

**To run the bundled set in strict mode**, install the project root:

```bash
wirken skills trust-root 81afdc96e2fde6a371fd114bc6486c7f26a9af4737862de63af97205b02f8f30
```

The same value is in [`skills/REGISTRY-ROOT.pub`](../skills/REGISTRY-ROOT.pub).
Installing it means trusting the project's offline root as the identity anchor
for every skill you load, bundled or not: a root is singular, so this is not a
way to add the project alongside a root of your own. Operators who run their
own root re-sign the bundled set as delegates of it, which is what the
`trust-root` output tells you to do.

Editing a bundled `SKILL.md` invalidates its committed signature until a
maintainer re-signs it offline. A test in the repo fails when that happens, so
it surfaces at build time rather than as a skill that quietly stops loading.

**Wasm skills** are compiled modules that run as a custom tool inside a
Wasmtime sandbox. Place `skill.wasm` beside `SKILL.md` and add a `parameters`
field to the frontmatter defining the JSON schema:

```yaml
---
name: hash
description: Compute SHA-256 hash of input text
parameters:
  type: object
  properties:
    text: { type: string, description: Text to hash }
  required: [text]
---
```

The module reads a JSON object of tool arguments on stdin and writes a JSON
result to stdout. It appears to the LLM as `wasm_hash`. The sandbox gives it
no filesystem access, no network, a 64 MB stdout buffer cap with 4 KB for
stderr, and a fuel-based CPU limit that terminates an infinite loop rather
than hanging the agent. Wasm skills are not a replacement for `exec`
confinement; they are a boundary for trusted-source compiled skills without
the latency of a container.

## Frontmatter rules

**`name`** (optional but auditable). When present it must agree with the
parent directory basename; when omitted the basename becomes the name. Either
way the same validation runs: `^[a-z][a-z0-9-]{0,63}$`, 1 to 64 characters,
lowercase ASCII letters, digits and hyphens only, starting with a letter so a
name cannot be confused with a numeric flag in CLI rendering. No uppercase,
underscores, dots, slashes or non-ASCII, so a name is one token on every
filesystem and in every shell. `crates/agent/src/skill.rs:392-417`.

**`description`** (required). Non-empty, at most 1024 characters, counted by
Unicode scalar rather than bytes. `crates/agent/src/skill.rs:421-435`.

**`permissions`** (optional). When omitted the loader applies
`PermissionProfile::default()`: least-privilege deny-all on every axis, empty
`tools`, deny-all `egress`, empty filesystem read and write paths, empty
`inference.allow`. A skill without the block loads cleanly but cannot do
anything beyond emitting text through the prompt; capability is something the
operator opts into by writing the block.

When present it must conform to `PermissionProfile`
(`crates/agent/src/skill_perms.rs:35-100`). Axes: `tools`, `egress`,
`filesystem`, `inference`, plus `credentials` and `http` for
[`http_request`](egress.md#the-http_request-gate). Wildcard `"*"` is supported
on `tools`, `egress.domains` and `inference.allow`; filesystem wildcards are
rejected, because cap-std workspace confinement is the outer bound and `"*"`
for paths is meaningless inside it.

**`metadata.wirken.requires.bins`** (optional). Host binaries the skill needs
on `PATH`. The loader checks each via `which`; if any are missing the skill is
marked `available: false` and is not exposed to the LLM, but the bundle still
loads so `wirken skills list` shows it. `crates/agent/src/skill.rs:355-383`.

**`metadata.openclaw.*`** continues to load without error but is silently
ignored; `metadata.wirken.*` is the only recognized location. Migrate with
`wirken skills migrate`, which backs each file up to
`SKILL.md.pre-migrate-<utc>` before rewriting.

**Envelope tokens are refused.** The loader refuses any skill whose name,
description or body contains the literal `BEGIN UNTRUSTED SKILL` or
`END UNTRUSTED SKILL`. These mark the trust boundary in the system prompt that
wraps third-party skills. The per-build nonce already defeats literal-marker
collisions in the rendered prompt, but carrying the tokens through to the LLM
still gives the model a confusable surface, and no legitimate field needs to
write them. The name matters because `build_prompt` renders it as a heading
inside the envelope. `crates/agent/src/skill.rs:179-193`, `:444-484`.

## Invocation

Skills are explicit-invocation by default. The agent does not auto-fire a
skill from a generic prompt that matches its description; the operator, or the
skill's own wrapper, invokes it by name with a slash prefix:

```
/<skill-name> <remainder of the user message>
```

The interceptor matches `^/<name>(\s|$)` strictly. A bare `/`, a slash
mid-sentence, and a leading-slash URL fragment are not invocations. An unknown
skill name with a slash prefix is rejected loudly rather than treated as plain
text, so a typo never falls through to an LLM that has no skill body for it.

A skill becomes auto-invocable only by declaring
`disable-model-invocation: false`. The auto-pickable set is built at load time
and excludes any skill where the field is `true` or absent. Default-true is
the posture: auto-fire requires explicit author opt-in. Side-effecting skills,
resource-expensive ones, and command-shaped ones are the canonical fits for
the default.

## Phase boundaries

A skill can declare phase boundaries within a single agent turn. Each phase
carries a deny set across five axes (tools, egress hosts, filesystem read
paths, filesystem write paths, inference providers) that narrows what the
agent can do for the rest of the phase. The phase ends when the skill emits
`wirken_exit_phase`, when it enters a new phase, or when the turn ends and the
host auto-clears.

The canonical shape is recon then framings then scoring: a skill that knows
its own pass structure declares "scoring should not write to disk or call
`exec`" at the boundary, and the runtime enforces that until the skill exits.
This is defense against mid-turn drift. Even if a later LLM step would call a
denied tool, the gate refuses with a typed `Phase` reason on the audit chain.

The phase tools are LLM-visible only when the skill lists them in its
`permissions.tools.allow`. A skill that does not declare them never sees them
and cannot enter or exit a phase; legacy mode, with no skills attached, does
not advertise them either.

```json
{
  "phase_name": "scoring",
  "denied": {
    "tools": ["exec", "write_file"],
    "egress_hosts": [], "paths_read": [], "paths_write": [],
    "inference_providers": []
  }
}
```

`wirken_enter_phase` returns `{"status":"ok"}`, or
`{"status":"error","reason":"phase_already_active","active_phase":"<name>"}`.
The single-slot invariant is hard: the skill must exit before re-entering, and
nested phases are refused so every `PhaseEntered` row pairs cleanly with one
`PhaseExited`. An optional `skill_id` overrides the audit attribution, which
defaults to the agent id.

`wirken_exit_phase` takes `{"reason": "phase_change"}` (the default) or
`"skill_unloaded"`. The host-only `"turn_end"` is rejected at the intercept:
the host emits it on every turn end and the skill is not allowed to forge it.
Result is `{"status":"ok"}` or
`{"status":"error","reason":"no_active_phase"}`.

The host clears the overlay on every turn end whether or not the skill exited
cleanly, so a skill that crashes mid-phase does not leave a stale deny set
active for the next turn. The audit chain is replayed on wake: an active phase
at the time of a crash is re-established, and a clean exit before the crash
leaves the overlay clear.

**The skill cannot read overlay state.** There is no host function or tool
that returns the current phase. Skills set policy; they do not query it. The
audit chain is the operator's view of phase activity.

## Installing and signing

```bash
wirken skills search <query>
wirken skills install <name>
wirken skills sign ./my-skill/
wirken skills verify ./my-skill/
```

Registry skills are verified against the registry-provided Ed25519 key before
installation, and again at every load. What the signature covers, what the
unsigned bypass does and does not admit, and how an operator registry root
changes the gate: [signing.md](signing.md#skill-signing).

## Coming from OpenClaw

Wirken reads the same `SKILL.md` frontmatter format, so the files copy over
directly:

```bash
cp -r ~/.openclaw/skills/* ~/.wirken/skills/
```

Two steps follow the copy. **Sign each one**, or set
`WIRKEN_ALLOW_UNSIGNED_SKILLS=1`, because the load-time gate refuses unsigned
bundles by default. **Run `wirken skills migrate`** to rewrite
`metadata.openclaw.*` and add a deny-all `permissions` block; without a wirken
block a skill loads but has no capability.

Skills on ClawHub that are JavaScript or TypeScript running as a custom tool
do not port. Wirken has no JS or TS skill runtime; its compiled-skill path is
Wasm, described above.
