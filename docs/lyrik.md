# Lyrik

Lyrik is Wirken's security-assessment skill; this page is the setup and configuration guide — for what Lyrik is and why it exists, see [lyrik-overview.md](lyrik-overview.md).

## What goes where

Lyrik draws a hard line between operator-level state and per-repo state. Operator-level state lives where it already lives in Wirken — the lyrik config does not duplicate or override it. Per-repo state lives in `.lyrik/` in the repo being assessed and is committed to the repo.

| Lives at | What | Updated by |
|---|---|---|
| Wirken vault | provider API keys, channel adapter credentials | `wirken setup`, `wirken channel add`, `wirken credential add` |
| `~/.wirken/sandbox.json` | sandbox mode (`off` / `exec-only` / `gvisor`) | `wirken setup`, manual edit |
| `<repo>/.lyrik/config.json` | scope, model pins per phase, gate destinations, prior-findings path, memory path | committed to repo |
| `<repo>/.lyrik/rubric.md` | severity rubric approved at Phase 0 | committed to repo |
| `<repo>/.lyrik/context.md` | project context approved at Phase 0 (with hot zones and per-component history) | committed to repo |
| `<repo>/.lyrik/prior/` | past CVEs, pentest reports, internal disclosures | committed to repo |
| `<repo>/.lyrik/memory/` | ADRs, postmortems, threat models, design docs (markdown) | committed to repo |
| `<repo>/.lyrik/memory/jira.csv` | optional Jira export for project-history enrichment | team policy decides whether to commit |

`.lyrik/config.json` references operator-level resources by name. `phases.score.provider: "privatemode"` resolves through the Wirken vault; `gates.phase_0_signoff.adapter: "slack"` resolves through Wirken's channel registry. Lyrik never sees a credential.

The form of `rubric.md` and `context.md` is whatever the channel renders well — markdown prose, tables, bulleted tiers. The team picks at first sign-off; the chosen form is committed and reviewed in PR like any other artifact. When the team writes the first rubric, include a short "acknowledged tensions" section listing project-level constraints the rubric consciously accepts (e.g. pre-1.0 crypto deps that have no 1.0 alternative); Lyrik can then reference these as INFO-tier lines per run instead of regenerating findings the team will discard.

## First-run setup

1. Install Wirken — see [getting-started.md](getting-started.md). Pick at least one LLM provider and at least one channel adapter that can carry the gates.
2. From the assessed repo, message the agent: *"run a lyrik assessment, full type."*
3. Phase 0 generates the project context and severity rubric, and routes them to `gates.phase_0_signoff`. If `.lyrik/config.json` is missing, Lyrik asks the user to nominate a destination.
4. Review the artifacts in your channel. Approve, amend, or reject. Lyrik does not proceed on silence.
5. On approval, Lyrik writes `.lyrik/rubric.md` and `.lyrik/context.md` to your repo. Commit them. Subsequent runs skip Phase 0 unless the dependency lockfile hash or framework version fingerprint has changed.
6. Optional: populate `.lyrik/prior/` with past CVEs, pentest reports, and internal disclosures. The dedup gate reads this directory recursively. Without it, the regression-finding stream stays empty.
7. Optional: populate `.lyrik/memory/` with ADRs, postmortems, threat models, and design docs (markdown). Add `.lyrik/memory/jira.csv` if you have a Jira export. Both feed Phase 0's hot-zones and per-component history. Without them, the project context still gets built — just without the history layer.
8. Optional: write `.lyrik/config.json`. Without it, Lyrik prompts for routing on each run.

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
| `framing` | The nine framings (`auth`, `crypto`, `injection`, `deserialization`, `memory_safety`, `secrets`, `supply_chain`, `race_condition`, `prompt_injection`) and their two sub-passes. The largest token consumer. |
| `score` | Four-axis scoring per finding, multi-instance. The dedup gate's causal tier reuses this pin. |
| `exploit` | Exploit-attempt code generation, run inside the gVisor sandbox. |

Confidentiality is achieved by pinning confidential phases to a Privatemode or Tinfoil provider. Lyrik has no `confidential: true` flag — the pin is the mechanism.

Per-class pinning inside `framing` (`framing.crypto` on a different provider than `framing.injection`) is not supported. If a real engagement needs it, file a `skills/lyrik/FOLLOWUPS.md` entry.

#### `prompt_injection` activation

`prompt_injection` is the ninth framing class. Recon activates it when the scope contains any of: an LLM client, an agent loop, tool execution, system-prompt construction, retrieval (RAG, embedding lookup, in-context file reads), or an MCP host. Untrusted text reaching a model's context is a distinct trust model from classical SQL/shell/log injection — sanitization shapes from those domains do not apply, and in-context content inherits trust from the surrounding prompt by default. The framing covers system-prompt content under attacker influence, tool-output amplification into context, retrieval payload trust, and cross-tool prompt-relay paths.

For Wirken-internal scopes, this means `crates/agent/`, `crates/mcp-proxy/` (MCP host surface), `crates/cli/src/commands/webchat.rs`, and any skill loader or skill execution path activates `prompt_injection`. For external assessments, the same pattern applies to any LLM-hosting application: agent frameworks, RAG pipelines, retrieval-augmented chat services, MCP servers, and skill/tool/plugin executors all activate it.

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

### `memory_path`

String. Path to the project-memory directory holding ADRs, postmortems, threat models, and design docs (markdown). Absolute, or relative to the repo root. Defaults to `./.lyrik/memory` if absent. Phase 0 reads this directory recursively for project-history enrichment. The Jira CSV, if present, is read at `<memory_path>/jira.csv`.

## Enrichment inputs

Phase 0 reads three kinds of input to give the project context real history. All are opt-in: lyrik runs without them, but the resulting context lacks the hot-zones and per-component-history layers that downstream framing and scoring rely on.

| Source | Where | Used for |
|---|---|---|
| Markdown project memory | `.lyrik/memory/*.md` (recursive) | ADRs, postmortems, threat models, design docs. Filtered to security-relevant content during articulate. |
| Git history | the target repo's `.git/` | Security-keyword commits (`git log --grep`), FIXME density (`git grep -c`), churn over the rubric window (`git log --since=... --name-only`), distinct authors per file (`git blame --line-porcelain`). |
| Jira CSV | `<memory_path>/jira.csv` | Ticket export with required columns `key,summary,description,status,created`; optional `labels,priority,components`. Filtered to security-relevant tickets. |

The articulate phase combines these into two sections of `.lyrik/context.md`:

- **Hot zones.** Files flagged by multiple dimensions (churn × security-keyword commits × Jira tickets × FIXME density). A file flagged on three or four dimensions is a hot zone; one dimension alone is noise.
- **Per-component history.** For each component identified in the software-identity pass, one short paragraph naming relevant ADRs, postmortems, recent Jira tickets, churn rate, FIXME density.

Framing and scoring phases receive a **component-filtered slice** of this enrichment. A finding in `crates/vault/` gets vault-relevant memory and history; a finding in `crates/mcp-proxy/` gets mcp-proxy-relevant. The slicing is by component path, not by global salience.

The smallest-viable enrichment is intentional: filesystem markdown and a CSV file, no API connectors, no live Jira/GitHub/Linear integrations. Operators who outgrow this surface should file a `skills/lyrik/FOLLOWUPS.md` entry with the worked case.

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
