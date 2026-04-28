---
name: aggregator
description: Daily fetch from a fixed public allowlist; score against the user's interests file; cluster into themes; push the digest to the configured channel
disable-model-invocation: true
# This skill is never agent-attached. It is loaded by PresetLoader for
# its permissions block, which the `wirken zirkel run` orchestrator
# applies to its own policed HTTP and SQLite clients. The tools.allow
# list below is dead surface from the agent-loop perspective — there
# is no agent that exposes these tools to an LLM for this skill.
# The permissions block exists as the orchestrator's policy source,
# not as an attach manifest. See crates/zirkel/src/orchestrator.rs.
permissions:
  tools:
    allow: [exec, read_file, write_file, list_files]
  egress:
    mode: allowlist
    domains:
      # The egress allowlist is the same set as sources.toml. Until the
      # loader derives one from the other, both are maintained by hand
      # in this preset. Adding a source means editing both files in the
      # same commit. Mismatch is an attach-time error in a later scope.
      - export.arxiv.org
      - papers.ssrn.com
      - www.ftc.gov
      - www.fcc.gov
      - www.consumerfinance.gov
      - www.hhs.gov
      - edpb.europa.eu
      - ico.org.uk
      - www.cnil.fr
      - api.congress.gov
      - api.govinfo.gov
      - www.federalregister.gov
      - api.federalregister.gov
  filesystem:
    read_paths: ["<workspace>", "~/.wirken/zirkel"]
    write_paths: ["~/.wirken/zirkel"]
  inference:
    allow: ["ollama", "privatemode"]
    default: "ollama"
---

# Aggregator

Fires once per day on a cron the operator configures. Performs a strict-pipeline run over the source allowlist:

1. Fetch each source in `sources.toml` via the declared method (RSS / API / rate-limited scrape). The HTTP wrapper enforces the egress allowlist and (in a later scope) the per-host rate limit.
2. Normalize fetched items into candidate records: `title`, `source`, `date`, `url`, `body_excerpt`, `citation_json`.
3. Skip if the candidate's content hash is already in the seen set.
4. Score the candidate's relevance against the user's interests file (`~/.wirken/zirkel/interests.toml`). Output: a float in `[0, 1]` plus a one-line `why_surfaced` rationale that names the matched interest.
5. If the score crosses the keep threshold and no skip pattern matches, write the candidate to the local SQLite store. Otherwise, log the skip with reason.
6. After all sources fetched, cluster the run's kept candidates into emergent themes using a small local embedding model.
7. Render the digest as plain prose with footnote-ready citations on every item. Push to the configured channel adapter.

Aggregator does not synthesize claims about the world. The digest reads as *"N items kept, M skipped. Today's themes: [theme A: items 1, 4; theme B: items 2, 3, 7]. Each item links to its source with a one-line why-surfaced explanation."* No "today the regulators are saying X" prose.

This skill is `disable-model-invocation: true`. Reach it via `/aggregator` (manual run) or via the operator's cron that calls the underlying CLI command directly.

## State

- `~/.wirken/zirkel/zirkel.db` — SQLite database holding candidates, seen, themes, skipped_log, runs, and the cached interests snapshot per run.
- `~/.wirken/zirkel/interests.toml` — user-editable; reloaded at the start of every run; a hash of the file is recorded in the audit log so changes are visible run-to-run.
- `~/.wirken/zirkel/bodies/` — full bodies referenced by `candidates.body_full_path` for items where the excerpt is too small for retrieval.

The aggregator and librarian share this state; both skills are scoped to the same `~/.wirken/zirkel/` directory by their permissions blocks.

## Inputs the operator provides

- `sources.toml` (preset-level, alongside `preset.toml`) — the addressable public set of sources.
- `interests.toml` (per-user, in `~/.wirken/zirkel/`) — concepts, keywords, exclusions, optional source weight tweaks.
- Channel adapter pin and target (configured at preset install).

## What runtime pieces are not yet implemented

The runtime fetcher, scheduled-run wiring, SQLite schema, and clustering integration are deferred to follow-up scopes. This skill declares the contract; the agent attaches it as part of the Zirkel preset; a later scope makes the daily run actually fire.
