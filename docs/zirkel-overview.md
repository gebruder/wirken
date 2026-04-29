# Zirkel

<img src="img/zirkel-wirken.png" alt="Zirkel" width="400" align="right">

Zirkel is a daily research aggregator that runs on your laptop. You write a small TOML file naming the keywords you care about (and the noise you don't); Zirkel fetches each day's items from a fixed list of public sources — academic preprint servers, journal feeds, regulator press releases, the Federal Register, congressional bill activity — and screens them against your keywords. A short, themed digest arrives in your Signal app at the time of day you set. You reply `keep 1, 3, 5` or `skip all`; the items you keep land in a personal library you can query later by chat — "what did I save this week?", "what have I kept about BIPA?", "what FTC items did I save?"

The threat model is the keyword file itself. The list of things you watch reveals what you're working on, who you're tracking, what enforcement action you're preparing for, what scholar you're following before your paper cites them. Zirkel runs locally so that file — and your kept set, and your chat queries — never leaves your machine. Outbound traffic is restricted to a fixed allowlist of named public sources, enforced at the HTTP transport layer.

## Who it is for

Researchers, lawyers, and policy people who track a specific domain across many sources and currently lose hours each week to manually checking journal RSS feeds, regulator news pages, agency hearing schedules, and the Federal Register. Practitioners who want a research aggregator that runs on their own machine, against sources they control.

It is not for general web monitoring. It is not for users who want an autonomous agent that takes actions on findings. It is not for high-volume scraping of credentialed sources.

## Why it exists

The number of papers, agency actions, hearings, and Federal Register notices in any given research domain exceeds what one person can track. Existing tools are either expensive subscription products that cost hundreds of dollars per month, or cloud aggregators that ship your interest patterns to a third party.

A research aggregator's threat model is the interest pattern itself. The list of keywords you watch reveals what you're working on, who you're tracking, what enforcement action you're preparing for, what scholar you're following before your paper cites them. That data should not leave the machine of the person doing the research.

Zirkel runs locally, fetches from public sources at human pace, scores against a keyword file you edit, and produces a daily digest you control.

## What Zirkel is not

- Not a continuous scraper. Zirkel runs on a schedule (default daily) and respects published rate limits.
- Not a research assistant. The chat surface returns items with citations; it does not summarize, synthesize, or assert claims about what you've kept.
- Not a citation manager. Zirkel surfaces what you might want to read; tools like Zotero handle what you do read.
- Not a cloud service. Zirkel is a local CLI plus a Signal channel binding. There is no Zirkel server.
- Not an autonomous agent. The keep/skip decision is yours, every time. Zirkel does not auto-categorize items into your kept library based on past behavior.

## What Zirkel will not do

- Will not exceed the configured rate limit on any source. The limit is enforced in the HTTP transport layer, not as a polite request to the model.
- Will not edit your interests file. Skip patterns are recorded for future scoring inputs but the file itself is yours.
- Will not synthesize claims about kept items. The librarian returns titles, sources, dates, and URLs verbatim; the LLM is constrained by the skill body to render results without paraphrase or commentary.
- Will not fetch from sources that require a browser to render. SPA-only committee schedule pages and similar JavaScript-rendered content are out of scope by deliberate architectural commitment, documented in `docs/zirkel.md`.
- Will not auto-route digests beyond the bound channel. Bind happens once via `wirken zirkel bind`; rebinding to a different target requires `--force`.

## What it does

### You write the interests file

Your interests live in a TOML file at `~/.wirken/zirkel/interests.toml`. Two lists: `keywords` (case-insensitive substring match against title and abstract) and `exclusions` (any match drops the candidate before scoring). Pinboard-shaped: you read the file, you edit the file, you trust the file.

```toml
keywords   = ["BIPA", "Section 5 unfairness", "data broker"]
exclusions = ["cookie banner", "GDPR fines under €1M"]
```

The file is snapshotted on every run for reproducibility. The interests that produced any given digest are recoverable later via the `interests_snapshots` table.

### Sources are public and named

Zirkel fetches from a fixed allowlist declared in `presets/zirkel/sources.toml`. The shipped set covers:

**Papers** — SSRN, arXiv (cs.CY and cs.CR).

**Regulators** — FTC, FCC, CFPB, HHS OCR, EDPB, ICO, CNIL. Other RSS-publishing regulators or state attorneys general (e.g. California's `oag.ca.gov/news/feed`, Washington's `atg.wa.gov/news/news-releases-rss`) add at the operator's discretion by editing `sources.toml`.

**Federal rulemaking, congressional bills, and hearings** — Federal Register API, congress.gov API, govinfo.gov API. The two keyed APIs require a free key from api.data.gov, set via `wirken zirkel auth-set --source congress-gov` (or `govinfo-gov`).

The allowlist is the egress allowlist. Aggregator runs cannot reach hosts outside it; the permission system rejects the request before the connection is opened.

### Rate limits are enforced in transport

Each fetcher declares its rate limit per host. Unauthenticated sources default to two requests per day, jittered, simulating human pacing. Documented APIs run within their published budgets — Federal Register's API is open with no published per-key limit, so Zirkel self-caps at 1,000/day for politeness; congress.gov publishes 5,000/hr and govinfo.gov publishes 36,000/hr (and 1,200/min, 40/sec), but Zirkel self-caps both at 5,000/day, well below the per-hour ceiling and oversized for the daily-fire pattern.

The limit is enforced in the HTTP client, not in instructions to the model. Hitting the limit produces a structured failure, not a polite delay request the LLM might ignore.

### Scoring is two-axis

Each candidate is screened against the interests file (exclusion drops, keyword matches recorded). Survivors are scored a second time by a local LLM via a structured tool call returning a 0–100 relevance score and a one-line "why surfaced" string pointing to the matched keyword.

The two scores coexist as separate columns. A failed LLM pass leaves the keyword score intact; the candidate still surfaces, just without the LLM-derived nuance.

### Themes emerge per run

Candidates that cross the relevance threshold are embedded with a local model and clustered with HDBSCAN. Themes are named by a second LLM call. Low-density days fall back to a single ungrouped section rather than forcing themes that don't exist. Themes are per-run; cross-run theme stability is a future iteration.

### The digest delivers via Signal

A Markdown message arrives on the Signal target you've bound. Items are grouped by theme, numbered within each section, and carry title, source, date, citation, and the why-surfaced line. The single-section rule drops the theme header when there's only one group.

You reply with `keep 3, 5, 7` or `skip all` or any combination of comma-separated 1-indexed lists. The reply parser is deterministic, scoped to the digest's run identifier, and runs before any LLM call.

### The librarian retrieves, it does not synthesize

The kept set is queryable by `/librarian` slash command on the bound channel. Six named queries:

- `kept_recent` — items from the last N days
- `kept_by_keyword` — items whose title or abstract contains a term
- `kept_by_theme` — items in a named theme
- `kept_by_source` — items from a specific source
- `kept_in_run` — all kept items from a specific run
- `recent_themes` — themes from recent runs with member counts

The LLM picks a query and fills parameters from the natural-language question. It cannot construct free-form SQL — the query name is a JSON-schema enum on the tool definition, so the function-calling layer rejects invalid names at the SDK level. The skill body constrains rendering: titles, URLs, sources, and dates appear verbatim. No paraphrase, no summary, no commentary.

### Audit trail is tamper-evident

Every fetch, every LLM call, every keep, every skip, every interests edit, every permission denial is logged to a hash-chained audit log. `wirken audit log --action <event>` filters by event type; `wirken audit verify` walks the chain and surfaces any tamper. If you need to reconstruct what Zirkel did and when, the record is there.

## Trust posture

Zirkel inherits Wirken's per-skill permissions block. The aggregator and librarian each declare their own:

- **Tools** — aggregator gets none (orchestrator-driven, not agent-attached); librarian gets `sqlite_query` only.
- **Egress** — aggregator's allowlist is the source list plus `127.0.0.1` for local LLM and embedding calls; librarian denies egress entirely.
- **Filesystem** — aggregator writes to `~/.wirken/zirkel/`; librarian reads the same path, writes nowhere.
- **Inference** — both allow Ollama (local) and Privatemode (confidential remote). No path ships interests, candidates, scores, or queries to a non-confidential provider.

The permissions block is signed as part of the skill's frontmatter. Default-deny on every axis.

API keys for credentialed sources live in the Wirken vault, resolved by the orchestrator at fetch time, injected as headers. Keys never reach the agent or the LLM.

## What ships today

All of the above. Zirkel v1 is end-to-end: keyword screening, two-axis scoring, embedding, clustering, theme naming, daily digest to Signal, keep/skip via reply, kept-set query via `/librarian`, four fetcher families, vault-isolated API keys, full permissions integration, hash-chained audit.

## Setup and use

For setup, the source allowlist, and the channel binding syntax, see [`docs/zirkel.md`](zirkel.md).

For the architectural commitment on browser scraping, see [`docs/zirkel.md`](zirkel.md).

## See also

- [`docs/zirkel.md`](zirkel.md) — setup, configuration, the no-headless-browser commitment.
- [`presets/zirkel/`](../preset/zirkel/) — the preset itself, including `sources.toml` and per-skill SKILL.md frontmatter.
