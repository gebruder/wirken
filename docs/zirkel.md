# Zirkel

**Zirkel**: German, *circle*, *cycle*, also a draughtsman's compass. The Wirken preset that fetches a daily corpus of policy and research material, scores it against the operator's interests file, and pushes a numbered digest the operator resolves with one short reply.

This document covers Zirkel's source-fetching architecture and the architectural commitments that constrain what Zirkel can ship as a v1 source. The user-facing CLI surface (`wirken zirkel run`, `wirken zirkel bind`, `wirken zirkel auth-set`) is documented in [cli.md](cli.md); the data flow through the per-skill SQLite, screening, LLM relevance scoring, clustering, theme naming, and digest delivery is documented inline in `crates/zirkel/src/`.

---

## What Zirkel fetches today

Zirkel's `sources.toml` enumerates each source the operator wants polled. Every entry pins a `method` that selects the fetcher implementation. The supported method kinds:

| Method                          | Auth                          | Example sources                                  |
|---------------------------------|-------------------------------|--------------------------------------------------|
| `rss`, `atom-api`               | None                          | FTC, CFPB, EDPB, ICO, CNIL, arXiv, SSRN          |
| `json-federal-register`         | None                          | federalregister.gov                              |
| `json-congress-bill`            | api.data.gov key (X-Api-Key)  | api.congress.gov                                 |
| `json-govinfo-bills`            | api.data.gov key (X-Api-Key)  | api.govinfo.gov                                  |

API keys live in the wirken vault (`zirkel-<source>-api-key` slot, written via `wirken zirkel auth-set`). The orchestrator reads the vault at startup, passes resolved keys to the fetcher's constructor, and the fetcher injects them into the `X-Api-Key` header at request time. Keys never cross the agent or LLM boundary; only the parsed `FetchedItem` flows downstream.

Each fetcher declares a per-host daily request budget via `Fetcher::default_rate_limit_per_day`. The orchestrator merges these into `RateLimitConfig.per_host_overrides` at startup, so authenticated APIs run within their published quotas while unauthenticated hosts stay at the polite 2/day default.

---

## What Zirkel does not fetch: SPA-rendered sources

A growing share of public-policy surfaces (many congressional committee schedule pages, several state attorney general news pages, the consumer-facing federalregister.gov pages, though the API itself is unaffected) render their content from JavaScript at view time. Scraping them requires a headless browser (Chrome, Firefox via Playwright, etc.).

**Wirken does not manage a browser process. This is an architectural commitment, not a backlog item.**

### Why

Three specific reasons, each of which would be sufficient on its own:

**1. A browser bypasses the EgressClient.** Wirken's HTTP transport runs through `wirken_agent::egress::EgressClient`, which enforces the per-skill egress allowlist and the per-host rate-limit budget. Both of those are structural: a fetcher cannot accidentally route around them, because there is no other HTTP client available at the trait layer. A headless Chrome process makes its own outbound requests via its own networking stack. Every guarantee that EgressClient currently holds for free becomes a runtime concern that Wirken would have to enforce by inspecting Chrome's behaviour, which is not something Wirken can do.

**2. SPA-scraping fails silently.** When a documented JSON API changes its response shape, our typed deserialiser surfaces a `Parse` error at the next fetch. The audit chain has the failure; the operator sees it in `wirken zirkel run`'s summary. When a SPA changes its CSS class names or DOM structure (which it does monthly, on average, at the kind of frontend-developer-led organisations that ship SPAs), a scraper either breaks loudly (best case) or quietly returns nothing for that source until someone notices the absence. Silent absences in a daily digest are exactly the failure mode the lawyer audience can least afford: they don't know what they didn't see.

**3. Adding a browser is a category-of-dependency change.** Wirken's runtime dependencies today are: the Rust toolchain, SQLite (bundled), and Ollama (optional, for the LLM passes). A self-contained binary plus a single optional sidecar. Adding Chrome means: a 200MB+ binary that has to be installed and updated separately, a sandbox interaction that is operator-platform-specific (especially on macOS), a lifecycle Wirken has to manage (start, monitor, restart on crash, kill on shutdown), and an attack surface that is roughly the size of the open web. None of that is local to Zirkel; it would change Wirken's deployment model for every operator, including those who never wanted a SPA scraped.

### What this means for sources

Sources in scope for Zirkel:

- RSS / Atom feeds, regardless of host.
- JSON APIs with documented schemas, with or without auth.
- Static HTML pages with stable semantic markup (a fetcher that uses `scraper` or `select` against a known DOM is in scope; this is what `class = "scrape"` will mean when the C-scrape slice ships).

Sources out of scope for Zirkel v1, by virtue of this commitment:

- Any committee schedule page that renders from JavaScript and has no API or RSS alternative.
- Any state AG news page that is JS-rendered and offers no feed.
- Any source that requires logging in via a real browser session.

If an operator names a SPA-only source they consider important, the answer is: that source is not in scope for Zirkel v1, and likely not in scope for any version, because **the conversation is "should Wirken's architecture change?" rather than "can we add Chrome to Zirkel?"** Wirken's architecture should not change to accommodate a single source. If a category of sources moves universally to SPA-only delivery and Wirken's value proposition demands them, that triggers a re-examination of all four reasons above. Until then, the manual workflow (the operator visits the site themselves on the days they care about it) is the v1 answer.

The constrained source list is not a limitation Zirkel has on the way to becoming a more general scraper. It is the source list Zirkel can deliver against the trust posture Wirken commits to: every fetched byte traversed the policed transport, every secret stayed in the vault, every failure mode is observable in the audit chain. That posture is incompatible with a browser process, and the posture is the product.
