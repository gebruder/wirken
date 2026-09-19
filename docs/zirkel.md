# Zirkel

<img src="img/zirkel-wirken.png" alt="Zirkel" width="360" align="right">

**Zirkel**: German, *circle*, *cycle*, also a draughtsman's compass. A daily
research aggregator that runs on your machine. You write a small TOML file
naming the keywords you care about and the noise you do not; Zirkel fetches
each day's items from a fixed list of public sources, screens them against
your keywords, and pushes a numbered digest you resolve with one short reply.

## Who it is for

Researchers, lawyers and policy people who track a specific domain across many
sources and currently lose hours a week checking journal feeds, regulator news
pages, hearing schedules and the Federal Register. Not for general web
monitoring, not for users who want an agent that takes actions on findings,
not for high-volume scraping of credentialed sources.

**The threat model is the keyword file itself.** The list of things you watch
reveals what you are working on, who you are tracking, what enforcement action
you are preparing for, what scholar you are following before your paper cites
them. Zirkel runs locally so that file, your kept set and your queries never
leave the machine. Outbound traffic is restricted to a fixed allowlist of
named public sources.

## What it is not

- Not a continuous scraper. Each source is polled once per scheduled run,
  daily by default.
- Not a research assistant. The chat surface returns items with citations; it
  does not summarize, synthesize or assert claims about what you kept.
- Not a citation manager. Zirkel surfaces what you might want to read.
- Not a cloud service. A local CLI plus a channel binding. There is no server.
- Not an autonomous agent. The keep/skip decision is yours every time; Zirkel
  does not auto-categorize based on past behavior.

It will not exceed the configured rate limit on any source, will not edit your
interests file, will not synthesize claims about kept items, and will not
auto-route digests beyond the bound channel.

## The interests file

`<data_dir>/zirkel/interests.toml`. Two lists: `keywords`, matched
case-insensitively as substrings against title and abstract, and `exclusions`,
where any match drops the candidate before scoring.

```toml
keywords   = ["BIPA", "Section 5 unfairness", "data broker"]
exclusions = ["cookie banner", "GDPR fines under 1M"]
```

Pinboard-shaped: you read the file, you edit the file, you trust the file. It
is snapshotted on every run, so the interests that produced any given digest
are recoverable later from the `interests_snapshots` table.

## Sources

A fixed allowlist in `preset/zirkel/sources.toml`. Every entry pins a `method`
that selects the fetcher:

| Method | Auth | Sources |
|--------|------|---------|
| `rss`, `atom-api` | none | FTC, FCC, CFPB, HHS OCR, EDPB, ICO, CNIL, arXiv (cs.CY, cs.CR), SSRN |
| `json-federal-register` | none | www.federalregister.gov |
| `json-congress-bill` | api.data.gov key | api.congress.gov |
| `json-govinfo-bills` | api.data.gov key | api.govinfo.gov |

Other RSS-publishing regulators or state attorneys general are added at the
operator's discretion by editing `sources.toml`. **The allowlist is the egress
allowlist:** a run cannot reach a host outside it, and the permission system
rejects the request before the connection opens.

Keys live in the vault under `zirkel-<source>-api-key`, written by
`wirken zirkel auth-set --source congress-gov`. The orchestrator reads the
vault at startup, passes resolved keys to the fetcher's constructor, and the
fetcher injects them into the `X-Api-Key` header at request time. Keys never
cross the agent or LLM boundary; only the parsed `FetchedItem` flows
downstream.

A scheduled run has nobody to prompt, so it reads the vault passphrase from
`WIRKEN_VAULT_PASSPHRASE` and never asks. Credential names are readable
without the passphrase, which is how the run tells two cases apart: a source
with no key stored is reported unsupported in the summary and the run stands;
a source whose key is stored but cannot be read is named at warn level and the
run refuses with a non-zero exit, rather than reporting itself complete while
missing something configured. Set the variable in the cron entry's
environment.

### Rate limits are enforced in transport

Each fetcher declares a per-host daily budget via
`Fetcher::default_rate_limit_per_day`, merged into
`RateLimitConfig.per_host_overrides` at startup. Unauthenticated hosts default
to two requests per day, jittered, simulating human pacing; authenticated APIs
run within their published quotas. Federal Register's API is open with no
published per-key limit, so Zirkel self-caps at 1,000/day for politeness.

The limit is enforced in the HTTP client, not in instructions to the model.
Hitting it produces a structured failure, not a polite delay request an LLM
might ignore.

## What Zirkel does not fetch: SPA-rendered sources

A growing share of public-policy surfaces render their content from JavaScript
at view time: many congressional committee schedule pages, several state
attorney general news pages, the consumer-facing federalregister.gov pages
though the API itself is unaffected. Scraping them requires a headless
browser.

**Wirken does not manage a browser process. This is an architectural
commitment.** Three reasons, each sufficient alone:

1. **A browser bypasses the `EgressClient`.** Wirken's HTTP transport runs
   through a client that enforces the per-skill allowlist and the per-host
   rate-limit budget, and a fetcher cannot accidentally route around it
   because there is no other HTTP client at the trait layer. A headless Chrome
   makes its own outbound requests through its own networking stack. Every
   guarantee `EgressClient` holds for free becomes a runtime concern wirken
   would have to enforce by inspecting Chrome's behaviour, which it cannot do.
2. **SPA scraping fails silently.** When a documented JSON API changes shape,
   the typed deserializer surfaces a `Parse` error at the next fetch, the
   audit chain has the failure, and the operator sees it in the run summary.
   When a SPA changes its CSS class names or DOM structure, which it does
   about monthly at the kind of organization that ships SPAs, a scraper either
   breaks loudly or quietly returns nothing until someone notices the absence.
   Silent absences in a daily digest are exactly what the audience can least
   afford: they do not know what they did not see.
3. **It is a category-of-dependency change.** Wirken's runtime dependencies
   are the Rust toolchain, bundled SQLite, and optionally Ollama. Adding
   Chrome means a 200MB+ binary installed and updated separately, a
   platform-specific sandbox interaction, a lifecycle to manage, and an attack
   surface roughly the size of the open web. None of that is local to Zirkel;
   it changes the deployment model for every operator, including those who
   never wanted a SPA scraped.

In scope: RSS and Atom feeds regardless of host, JSON APIs with documented
schemas with or without auth, and static HTML with stable semantic markup. Out
of scope: any committee schedule page or state AG news page that is JS-rendered
with no API or feed, and any source requiring a real browser login.

If an operator names a SPA-only source they consider important, the question
is "should Wirken's architecture change?" rather than "can we add Chrome to
Zirkel?" The constrained source list is not a limitation on the way to
becoming a general scraper; it is the list Zirkel can deliver against the
trust posture Wirken commits to. Every fetched byte traversed the policed
transport, every secret stayed in the vault, every failure mode is observable
in the audit chain. That posture is incompatible with a browser process, and
the posture is the product.

## The pipeline

**Screening is two-axis.** Each candidate is screened against the interests
file, with exclusions dropping and keyword matches recorded. Survivors are
scored again by a local LLM through a structured tool call returning a 0-100
relevance score and a one-line "why surfaced" string naming the matched
keyword. The two scores live in separate columns, so a failed LLM pass leaves
the keyword score intact and the candidate still surfaces, just without the
LLM-derived nuance.

**Themes emerge per run.** Candidates over the relevance threshold are
embedded with a local model and clustered with HDBSCAN, and a second LLM call
names the clusters. Low-density days fall back to a single ungrouped section
rather than forcing themes that do not exist. Themes are per-run.

**The digest delivers to a bound channel.** A markdown message arrives on the
target you bound, items grouped by theme, numbered within each section,
carrying title, source, date, citation and the why-surfaced line. The
single-section rule drops the theme header when there is only one group.

Reply with `keep 3, 5, 7`, `skip all`, or any combination of comma-separated
1-indexed lists. The reply parser is deterministic, scoped to the digest's run
identifier, and runs before any LLM call.

**The librarian retrieves, it does not synthesize.** The kept set is queryable
by `/librarian` on the bound channel, through six named queries:
`kept_recent`, `kept_by_keyword`, `kept_by_theme`, `kept_by_source`,
`kept_in_run`, `recent_themes`. The LLM picks a query and fills parameters
from the natural-language question; it cannot construct free-form SQL, because
the query name is a JSON-schema enum on the tool definition and the
function-calling layer rejects invalid names at the SDK level. The skill body
constrains rendering: titles, URLs, sources and dates appear verbatim, with no
paraphrase, summary or commentary.

## Binding and running

```bash
wirken zirkel bind --channel signal --conversation +15551234567
wirken zirkel run
wirken zirkel status
```

`bind` is once; rebinding to a different target requires `--force`. See
[cli.md](cli.md#wirken-zirkel) for the full flag set.

`wirken zirkel calibrate` computes discrimination (AUC) and reliability
calibration of the LLM relevance score against your keep/skip labels, reading
the local aggregator database. Computation only; the corpus never leaves the
machine.

The orchestrator digest push is Linux and macOS only: it goes over the
orchestrator push socket, a same-user JSON-line boundary with no Windows
analog. On Windows the run completes and reports the push as skipped.

## Trust posture

Zirkel inherits Wirken's per-skill permissions block. The aggregator and
librarian each declare their own, default-deny on every axis, signed as part
of the skill frontmatter:

- **Tools**: aggregator none (it is orchestrator-driven, not agent-attached);
  librarian `sqlite_query` only.
- **Egress**: aggregator's allowlist is the source list plus `127.0.0.1` for
  local LLM and embedding calls; librarian denies egress entirely.
- **Filesystem**: aggregator writes to `<data_dir>/zirkel/`; librarian reads
  the same path and writes nowhere.
- **Inference**: both allow Ollama and Privatemode. No path ships interests,
  candidates, scores or queries to a non-confidential provider.

Every fetch, LLM call, keep, skip, interests edit and permission denial is
logged to the hash-chained audit log. See [audit-cli.md](audit-cli.md).

The preset itself, including `sources.toml` and the per-skill frontmatter, is
[`preset/zirkel/`](../preset/zirkel/).
