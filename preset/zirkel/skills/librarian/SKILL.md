---
name: librarian
description: Retrieval-only chat over the kept set in SQLite — no live fetch, no synthesized factual claims about the world
disable-model-invocation: true
permissions:
  tools:
    allow: [exec, read_file]
  egress:
    mode: deny
  filesystem:
    read_paths: ["~/.wirken/zirkel"]
    write_paths: []
  inference:
    allow: ["ollama", "privatemode"]
    default: "ollama"
---

# Librarian

Answers chat queries against the kept set of candidates in `~/.wirken/zirkel/zirkel.db`. Retrieval-only. No live fetch — that's the aggregator's job. No synthesized factual claims about the world.

Reach this skill via `/librarian <query>`.

## What it returns

For each query the librarian:

1. Looks up matching candidates in SQLite by interest-match, keyword, or theme.
2. Returns the matched candidates: `title`, `source`, `date`, `url`, `why_surfaced`.
3. If asked to characterize *what the matched documents say*, answers strictly with attribution: *"per the FTC press release of 2026-04-12: …"*. Never as the librarian's own claim.
4. When no kept candidate matches, refuses the question with a clear message: *"the kept set has nothing on this. Suggest you broaden the interests file or wait for tomorrow's run."* No guess, no fall-through to the LLM's training-set knowledge.

## What it will not do

- Reach the network. The `permissions.egress.mode = deny` block ensures this is enforced in code, not just prose.
- Answer based on the LLM's training set rather than the retrieval result.
- Aggregate a "summary of what the regulators said this month" that goes beyond paraphrase of specific kept items with attribution.
- Write to the kept set. The `permissions.filesystem.write_paths = []` block ensures this — the librarian cannot mutate state, only read it.

## Sharing state with the aggregator

The librarian reads the same `~/.wirken/zirkel/` directory the aggregator writes. The aggregator declares write access; the librarian declares read access; the agent's effective filesystem profile (union) covers both.

## What runtime pieces are not yet implemented

The SQLite retrieval surface, query parser, and feedback-mark commands are deferred to follow-up scopes. This skill declares the contract; the agent attaches it as part of the Zirkel preset; a later scope wires it to actual database queries.
