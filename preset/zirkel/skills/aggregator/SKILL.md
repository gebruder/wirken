---
name: aggregator
description: Daily fetch from a fixed public allowlist; score against the user's interests file; cluster into themes; push the digest to the configured channel
disable-model-invocation: true
# The permissions block below is the orchestrator's policy source,
# not an attach manifest. `wirken zirkel run` is a pure-Rust pipeline
# that loads this skill via PresetLoader, reads the permissions block,
# and applies it to its own policed HTTP and SQLite clients. The
# orchestrator never calls Agent::attach_skills for this skill — the
# LLM is not in the fetch loop, so there is no agent surfacing tools
# from an attached aggregator. The tools.allow list below is dead
# surface from the agent-loop perspective; it stays declared so the
# permissions block is a complete, signed policy descriptor.
# See crates/zirkel/src/orchestrator.rs.
permissions:
  tools:
    allow: [exec, read_file, write_file, list_files]
  egress:
    mode: allowlist
    domains:
      # The egress allowlist is the same set as sources.toml. Both are
      # maintained by hand in this preset. Adding a source means editing
      # both files in the same commit.
      #
      # Ollama embedding endpoint: 127.0.0.1 is in the allowlist
      # specifically so the orchestrator's POST to <ollama>/api/embed
      # passes the policed transport. This is NOT a generic
      # local-network exception — only the orchestrator's embedding
      # pass uses it (per the C-LLM pre-checks Path C decision).
      - 127.0.0.1
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

1. Fetch each source in `sources.toml` via the declared method (RSS / API / rate-limited scrape). The HTTP wrapper enforces the egress allowlist.
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
