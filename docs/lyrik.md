# Lyrik

Lyrik is the security-assessment skill bundled with Wirken. It produces red-team and pentest assessments of a codebase in the lyric form: every claim stated in the smallest true number of words, every number disclosed with provenance, every finding traceable to the run's audit log.

The skill text itself lives at `~/.wirken/skills/lyrik/SKILL.md` after `wirken setup`. This page is the team-facing setup and configuration guide.

## What goes where

Lyrik draws a hard line between operator-level state and per-repo state. Operator-level state lives where it already lives in Wirken — the lyrik config does not duplicate or override it. Per-repo state lives in `.lyrik/` in the repo being assessed and is committed to the repo.

| Lives at | What | Updated by |
|---|---|---|
| Wirken vault | provider API keys, channel adapter credentials | `wirken setup`, `wirken channel add`, `wirken credential add` |
| `~/.wirken/sandbox.json` | sandbox mode (`off` / `exec-only` / `gvisor`) | `wirken setup`, manual edit |
| `<repo>/.lyrik/config.json` | scope, model pins per phase, gate destinations, prior-findings path | committed to repo |
| `<repo>/.lyrik/rubric.md` | severity rubric approved at Phase 0 | committed to repo |
| `<repo>/.lyrik/context.md` | project context approved at Phase 0 | committed to repo |
| `<repo>/.lyrik/prior/` | past CVEs, pentest reports, internal disclosures | committed to repo |

`.lyrik/config.json` references operator-level resources by name. `phases.score.provider: "privatemode"` resolves through the Wirken vault; `gates.phase_0_signoff.adapter: "slack"` resolves through Wirken's channel registry. Lyrik never sees a credential.

## First-run setup

1. Install Wirken — see [getting-started.md](getting-started.md). Pick at least one LLM provider and at least one channel adapter that can carry the gates.
2. From the assessed repo, message the agent: *"run a lyrik assessment, full type."*
3. Phase 0 generates the project context and severity rubric, and routes them to `gates.phase_0_signoff`. If `.lyrik/config.json` is missing, Lyrik asks the user to nominate a destination.
4. Review the artifacts in your channel. Approve, amend, or reject. Lyrik does not proceed on silence.
5. On approval, Lyrik writes `.lyrik/rubric.md` and `.lyrik/context.md` to your repo. Commit them. Subsequent runs skip Phase 0 unless the dependency lockfile hash or framework version fingerprint has changed.
6. Optional: populate `.lyrik/prior/` with past CVEs, pentest reports, and internal disclosures. The dedup gate reads this directory recursively. Without it, the regression-finding stream stays empty.
7. Optional: write `.lyrik/config.json`. Without it, Lyrik prompts for routing on each run.

## `.lyrik/config.json` schema

A sample is at [`lyrik.example.json`](lyrik.example.json). Each top-level key:

### `scope`

Object. Paths included in and excluded from the assessment. A user request like *"assess only `src/`"* overrides this for the run.

- `include` — array of glob patterns. Defaults to `["**/*"]` if absent.
- `exclude` — array of glob patterns. Defaults to `["target/**", "node_modules/**", ".git/**"]` if absent.

### `phases`

Object. One entry per phase that makes a model call. Each entry pins the provider and model for that phase. The provider must be a name configured in the Wirken vault; the model must be one supported by that provider.

| Phase | What it does |
|---|---|
| `articulate` | Phase 0 project context generation. Long-context reasoning over the repo. |
| `rubric` | Phase 0 severity rubric derivation from the project context. |
| `recon` | Entry-point and trust-boundary mapping. Cheap pass. |
| `framing` | The eight framings (`auth`, `crypto`, `injection`, `deserialization`, `memory_safety`, `secrets`, `supply_chain`, `race_condition`) and their two sub-passes. The largest token consumer. |
| `score` | Four-axis scoring per finding, multi-instance. The dedup gate's causal tier reuses this pin. |
| `exploit` | Exploit-attempt code generation, run inside the gVisor sandbox. |

Confidentiality is achieved by pinning confidential phases to a Privatemode or Tinfoil provider. Lyrik has no `confidential: true` flag — the pin is the mechanism.

Per-class pinning inside `framing` (`framing.crypto` on a different provider than `framing.injection`) is not supported. If a real engagement needs it, file a `skills/lyrik/FOLLOWUPS.md` entry.

### `gates`

Object. One entry per human gate. Each entry specifies which channel adapter delivers the gate and the adapter-specific target string.

| Gate | When it fires |
|---|---|
| `phase_0_signoff` | Phase 0 artifacts (project context, severity rubric) await approval. |
| `scoring_disagreement` | Two scoring passes disagree by more than one severity tier on any axis. The finding plus all rationales lands here for adjudication. |
| `high_severity_review` | A finding lands at grade 1.0. The reviewer signs off on the delivery destination, redirects, or holds. There is no auto-routing for 1.0-grade findings — encrypted channel or otherwise. |

Each gate entry:

- `adapter` — name of a configured Wirken channel adapter (`slack`, `discord`, `matrix`, `signal`, `telegram`, `imessage`, `teams`, `whatsapp`, `google-chat`).
- `target` — free-form string, parsed by the adapter. See "Channel target syntax" below.

### `prior_findings_path`

String. Path to the directory containing prior CVEs, pentest reports, and internal disclosures. Absolute, or relative to the repo root. Defaults to `./.lyrik/prior` if absent. The dedup gate reads this directory recursively.

## Channel target syntax

The `gates.<gate>.target` string is whatever form the adapter natively addresses a destination by. Verified forms in the bundled adapters:

| Adapter | Target form |
|---|---|
| `slack` | Slack channel ID (`C012ABCDEF`) or `#channel-name`. |
| `matrix` | Matrix room ID, `!roomid:server.tld`. |
| `signal` | E.164 phone number, `+15551234567`. |

Other adapters use their own native conversation IDs. If you're unsure, look at the adapter's source under `crates/adapter-<name>/` — the field is consistently named (`channel_id`, `room_id`, `phone_number`, etc.).

## What gets written to the audit log

Every phase output writes to the Wirken audit subsystem (`crates/audit`). No phase has an opt-out. Each entry carries a run ID; the final report includes the run ID so downstream readers can pull the chain.

The Lyrik report explicitly includes a **funnel disclosure**: candidates generated → after dedup → scored → exploit-verified. The numbers must reconcile. This is the rebuttal to aggregate counts presented without provenance.

## When Phase 0 gets re-run

Lyrik treats the committed `.lyrik/rubric.md` and `.lyrik/context.md` as approved unless invalidated. Invalidation triggers:

- Dependency lockfile hash changes (`Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`, `go.sum`, etc., depending on the project).
- Framework version fingerprint changes (major version bumps of the primary framework).
- The team explicitly asks for a Phase 0 re-run.

When invalidated, Lyrik re-generates and routes through `phase_0_signoff` again. The previous `rubric.md` and `context.md` stay in git history — diff them in PR.

## When the markdown form is not enough

If real use surfaces a boundary that `.lyrik/config.json` plus the SKILL.md can't carry — a state store the agent can't reconstruct from filesystem reads, a typed schema that needs validation at write time, a programmatic dispatch that needs harness support — record it in `skills/lyrik/FOLLOWUPS.md`. Don't grow this guide or the SKILL.md into a substitute for it.
