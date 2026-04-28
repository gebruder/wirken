# Lyrik FOLLOWUPS

Boundaries surfaced by real use that need design work beyond what the SKILL.md form can carry. Each entry pairs the boundary with the worked example that surfaced it, so a future decision starts with data instead of speculation.

## 1. Latent / config-dependent finding bucket

Surfaced 2026-04-28 during dogfood on `crates/cli/src/commands/webchat.rs`.

The lyrik report has two streams: `novel` and `regression`. There is no place for a finding that is **dormant under current configuration but live under a plausible config change.**

Worked example: `crates/cli/src/commands/webchat.rs:212-218`. The Origin header strip-prefix is case-sensitive — `Origin: ` and `origin: ` only. Today the bind is `127.0.0.1` (loopback), so the Origin defence has no real network role and the case-sensitivity is moot. A future operator who flips `TcpListener::bind("127.0.0.1:...")` to `0.0.0.0` (one-line change) removes the loopback defence; the case-sensitivity then becomes a CSRF bypass. A client sending `ORIGIN: https://attacker.com` (uppercase) evades the check entirely because `strip_prefix("Origin: ")` and `strip_prefix("origin: ")` both miss; the parser yields `None` and the request proceeds.

In today's report this finding scores 0 ("not a real bug now"). That under-reports the real concern: the only thing keeping it from being a HIGH-severity finding is one git diff line elsewhere in the same file.

**Second case**, surfaced 2026-04-28 during dogfood on `crates/vault/src/crypto.rs`.

The `decrypt` function returns plaintext via `cipher.decrypt` as `Vec<u8>` that lives unzeroed for a brief window before being wrapped in `VaultSecret`. The chacha20poly1305 internal stack state inside that call is also not zeroed by the crate. Today this is graded 0 — defence-in-depth, not exploitable without an additional capability (memory read on the live operator process). Under "operator's machine compromised but keychain entry not yet read" — a real post-compromise lateral-movement threat — the residual key material in stack/heap *is* exploitable via process memory dump or core file. Same shape: graded 0 against the named threat model, would be HIGH in a slightly expanded one.

**Third case**, surfaced 2026-04-28 during dogfood on `crates/agent/src/skill.rs`.

`SkillLoader::load_dir` reads `~/.wirken/skills/*/SKILL.md` at start-up and concatenates each `body` verbatim into the agent's system prompt via `build_prompt`. Signature verification happens at install time (`wirken skills install`) but **not at load time**. Today, FS permissions on the home directory gate this — the threat model assumes "trusted operator on a single-user machine." Under any expansion of that threat model — a same-UID compromised process, a multi-user host, a shared dev environment, a relaxed-permissions deployment — the same code becomes prompt-injection-as-a-feature: any process with same-UID write to the skills dir gets its content delivered as system prompt content. Graded 0 today, HIGH in expanded threat model.

**Fourth case**, also from `crates/agent/src/bundled_skills.rs` and `crates/cli/src/commands/setup.rs`.

`install_bundled_skills` skips skills whose path already exists. An attacker who plants `~/.wirken/skills/<name>/` *before* the operator's first `wirken setup` run keeps their version forever — subsequent setups skip the directory unconditionally. Realistic attacker-precedes-operator scenarios (compromised CI image, shared machine, restored-from-backup state). Graded 0 today (atypical threat model), HIGH if attacker-precedes-operator is in scope.

Schema questions for whoever picks this up:

- Does `latent` get its own report stream, or extend the existing grade scheme (e.g. `0/H` — "graded zero now, would be H if condition X")?
- How does the agent identify the "condition X" that flips a finding live? Pattern-match on bind addresses, install-time checks, hardcoded permissions assumptions? Explicit operator-named threat models in the rubric?
- How does latent interact with regression? A latent finding later realized by a config change is structurally similar to the reintroduction case the regression stream already names.
- What's the dedup story across runs? If the same latent finding is rediscovered every assessment until the underlying code is fixed, does it suppress after first sighting, or does it keep appearing as a steady-state warning?

Four cases now across three threat models (network surface config, crypto memory hygiene, skill-loader trust timing). Pattern is consistent: graded 0 against the named threat model, HIGH in a single-step expansion. One or two more cases before the design question is ripe.

## 2. Hardening stream alongside novel and regression

Surfaced 2026-04-28 during dogfood on `crates/vault/src/crypto.rs`.

Several findings from this assessment were not vulnerabilities but API-hardening suggestions: `derive_key_from_passphrase` accepts `&[u8]` salt without enforcing entropy or length; `passphrase: &str` (not `VaultSecret`) means the function can't participate in zeroing the buffer; the `argon2` zeroize feature is not visibly enabled in the vault's `Cargo.toml`. None of these are exploitable today. They are API shapes that make misuse possible.

The four-axis scorer is built for vulnerability findings — *is this a real bug / is the code path reachable / can attacker reach entry / blast radius*. Applied to API-hardening suggestions, the answers come out awkward ("depends on caller" / "yes always" / "depends on caller" / "depends on caller"). The scorer's signal-to-noise drops on these.

**Two more cases**, surfaced 2026-04-28 during dogfood on `crates/mcp-proxy/src/server.rs` and `crates/mcp-proxy/src/wire.rs`:

- `MAX_FRAME_BYTES = 16 * 1024 * 1024` (16 MB) is generous for an NDJSON protocol where real frames are kilobytes. A 256 KB or 1 MB cap would catch DoS earlier without affecting legitimate traffic. Not exploitable today (caller is same-UID gated). The API shape — a hardcoded constant rather than a config-tunable limit — makes the choice a recompile rather than an operator dial.
- The accept loop has no per-process connection cap. A same-UID attacker opens many connections; each spawned task can grow its read buffer to `MAX_FRAME_BYTES`. Memory-pressure DoS at modest connection counts. Same threat-model gating as above. Absence of a connection limit is API/config shape that makes misuse possible.

**One more case**, surfaced 2026-04-28 during dogfood on `crates/agent/src/skill.rs`:

- `parse_frontmatter` reads the entire SKILL.md and runs `serde_yaml::from_str` on the frontmatter slice with no size cap. A 100 MB SKILL.md or a YAML bomb DoSes the loader. Same shape as the mcp-proxy `MAX_FRAME_BYTES` finding: a hardcoded-or-absent input size cap on a parser that should refuse oversized input early.

Schema questions:

- Should the report carry a third `hardening` stream alongside `novel` and `regression`?
- If yes, what scoring shape applies? Hardening findings don't have a "real bug" axis; they are proposals.
- Does the dedup gate apply? Across runs, the same hardening finding rediscovered every assessment until the underlying API is fixed is still useful as a steady-state warning, but at lower volume than novel findings.
- How is hardening prioritised in the report? Vulnerabilities first is obvious; hardening clusters second, ordered by what?

Six worked cases now across three threat models (vault crypto, mcp-proxy protocol, skill loader). The pattern is consistent — *API/config shape that makes misuse easy, not exploitable today* — and is distinct from both novel-vulnerability and latent-config-dependent. Decision threshold solidly passed: schema design can be made cleanly in a single session of design work when picked up.

## 3. Intra-run clustering for related-by-root-cause findings

Surfaced 2026-04-28 during dogfood on `crates/vault/src/crypto.rs`.

The vault assessment produced four LOW-tier findings, all variants of "key material may persist in memory after use" (decrypt buffer not zeroed pre-wrap; stack residue from chacha20poly1305 internals; passphrase buffer not zeroable from inside the function; argon2 zeroize feature possibly off). Different code locations, single shared root cause: memory hygiene around key material is partial.

The current dedup gate runs against `.lyrik/prior/` only — historical findings, not other candidates from the same run. Intra-run clustering does not happen. The report renders four separate items where one umbrella finding plus three concrete locations would be cleaner.

Schema questions:

- Should there be a same-run causal grouping pass before the report renders?
- If yes, where in the pipeline — before scoring (so all members of a cluster score together), after scoring (so the cluster's representative score is the max), or render-only (so the report shows umbrella + members but the audit log preserves individual findings)?
- How does the agent decide what is "same root cause" versus "different bugs of the same class"? A causal-tier model call shaped like the dedup causal tier?
- Does the umbrella inherit the highest member's grade, or get its own?

**Second case**, surfaced 2026-04-28 during the FreeBSD RPCSEC_GSS assessment (run-001).

The kernel-side scope produced 9 distinct candidates with 3 cross-framing pairs folded: `A1/M1` (stack overflow surfaced under both `auth` and `memory_safety`), `A2/R1` (`next_clientid++` race surfaced under both `auth` and `race_condition`), `A6/X3` (service-switch surfaced under both `auth` and `crypto`). Same shape as the vault assessment's pattern — different code-locations of the same root cause, different framings catching the same finding from different angles.

Two cases now across two threat models (vault crypto memory hygiene; FreeBSD kernel RPC handler). The pattern is consistent: cross-framing convergence is the dominant intra-run duplication shape, not different-code-locations-same-root-cause-within-one-framing. That distinction matters for the schema decision: the dedup unit should be the framing-pair fold, not finding-cluster-detection at the post-scoring stage.

Two cases so far. Look for the pattern again on a third surface before locking in the schema.

## 4. Cross-surface / codebase-wide pattern recognition

Surfaced 2026-04-28 across two dogfood sessions: `crates/cli/src/commands/webchat.rs` and `crates/mcp-proxy/src/server.rs`.

Two findings, one root cause across surfaces. Webchat's "no per-call rate limit on local POSTs" and mcp-proxy's "no per-tool-call rate limit on authenticated agents" are structurally the same finding: **Wirken's resource-bounding posture is per-surface, not codebase-wide.** Each individual surface has decided locally whether to bound resource consumption; there is no project-level invariant that all trust-crossings carry resource bounds.

This is a real finding *about Wirken*, not about webchat or mcp-proxy individually. It is higher-value than any individual vulnerability because it is structural to how the codebase thinks. A scanner that surfaces these patterns is meaningfully different from one that does not.

A lyrik report that surfaces a structural finding requires lyrik to **keep state across assessments of the same codebase** — and to compare candidate findings against past findings *for clustering by structural similarity*, not just for suppression-or-routing as the dedup gate currently does. This is distinct from intra-run clustering (item 3) — the lifecycle and storage are different.

Schema questions:

- Where does cross-assessment state live? `.lyrik/` per-repo already carries rubric and context; a `patterns/` subdirectory holding previously-observed structural findings is plausible.
- How does the agent decide a new finding matches a structural pattern? Causal-tier model call against past structural findings, similar in shape to the dedup causal tier but with different intent.
- Should the report carry a fourth stream (`structural`) alongside `novel`, `regression`, and (eventually) `hardening`? Or should structural findings be a tag on existing-stream findings ("this novel finding is the third instance of pattern X across this codebase")?
- Cadence: structural findings tend to be slow-moving — the "rate-bound every trust-crossing" pattern won't be fixed in one PR. Does each assessment re-surface them at full salience, or do they decay to a steady-state warning?

Two cases so far. Three or four more before the design question is ripe. The shape is the highest-value capability the lyrik form can plausibly carry — worth more design weight than any of items 1–3.

## 5. Live ticket-tracker integration beyond CSV

Surfaced 2026-04-28 during enrichment-path build.

The current Jira ingest reads `<memory_path>/jira.csv` — a one-shot export. That intentionally avoids API credentials, OAuth flows, and the runtime cost of fetching ticket state per assessment. It also means lyrik's view of operational signal is as stale as the operator's last export.

Live integrations (Jira REST API, GitHub Issues API, Linear API, etc.) would let lyrik query current ticket state at assessment time and pick up tickets opened between exports. They also introduce: credential storage (which would route through the Wirken vault same as LLM provider keys), rate-limit handling, multi-tenancy on shared accounts, and the question of whether lyrik should ever write back (e.g., creating a Jira issue per finding — its own can of worms).

Schema questions:

- Where do API credentials live? Wirken vault (operator-level) is the obvious answer; lyrik references by name as for LLM providers and channel adapters.
- One connector per system, or a generic "ticket source" abstraction with adapters?
- Read-only by default, or allow lyrik to create tickets for high-severity findings (gated by a human gate, similar to `high_severity_review`)?
- Does CSV stay as a fallback / disconnected-mode option, or get retired once API connectors land?

CSV ingest covers the demo case. API integration is real demand from teams running lyrik at any cadence faster than weekly.

## 6. Embedding-backed retrieval over `.lyrik/memory/`

Surfaced 2026-04-28 during enrichment-path build.

The current Phase 0 enrichment reads `.lyrik/memory/*.md` files into the agent's context directly. For small project memory (tens of markdown files, single-digit MBs total), that scales fine. For mature codebases — a decade of ADRs, dozens of postmortems, hundreds of design docs — the markdown dump approaches the model context window and pushes out other Phase 0 work.

Embedding-backed retrieval over the memory corpus would let the agent fetch only the top-K relevant docs per component, scaling project memory size independently of context window. It introduces an embedding model (operator decision; another provider pin), an embedding store (FAISS, sqlite-vec, etc.), an indexing step (when does lyrik regenerate the index?), and the question of whether the index lives in `.lyrik/` (committed, but binary-ish) or `~/.wirken/lyrik/index/` (operator-local, not committed).

Schema questions:

- Where does the index live? Per-repo committed (everyone gets the same retrieval) versus operator-local (each operator's index is fresh)?
- Which embedding provider? Same pin shape as `phases.<phase>.provider`, or distinct?
- Re-index trigger: dependency-lockfile-hash change (same as Phase 0 invalidation), explicit `wirken lyrik reindex`, or on every run?
- Smallest-viable form — sqlite-vec inline, or pull in a real vector store?

Real demand for indexed memory will come from teams whose `.lyrik/memory/` exceeds roughly 100 KB.

## 7. Memory relevance filtering as a phase

Surfaced 2026-04-28 during enrichment-path build.

The current SKILL.md tells the articulate phase to "filter to security-relevant content; do not dump every ADR into the context regardless of topic." That filtering happens implicitly inside articulate's own reasoning — same model call, same context, no separate pass.

For small memory directories this is fine. For larger ones, the articulate model is doing two distinct jobs: read everything, decide what is relevant, then synthesize the project context using only the relevant subset. A cheap-class pre-filter pass (similar in shape to recon) would let articulate receive only pre-filtered memory and focus its context budget on synthesis.

Schema questions:

- Separate phase (`memory_filter` between recon and articulate), or sub-pass inside articulate?
- Dedicated model pin? Cheap class, similar to recon.
- "Security-relevant" defined by keyword, model judgement, or operator tags in the memory file frontmatter?
- Does the filtered-out set get reported? Operator visibility into "lyrik decided these ADRs were not security-relevant" matters for trust.

Becomes worth building when articulate's context budget is materially eaten by memory content.

## 8. Per-skill `allowed-tools` frontmatter (wirken-level)

Surfaced 2026-04-28 during a scan of the OpenClaw skill registry. OpenClaw skills can declare in their frontmatter:

```yaml
allowed-tools: Read, Glob, Grep, Bash
```

This restricts the agent's tool surface during that skill's execution to the named set. A skill that should only read files and run shell commands cannot reach for `web-fetch`, `file-write`, or other tools the agent normally has, even if asked.

Wirken has no equivalent. Today, when the agent runs any bundled skill (lyrik, git, web-fetch, etc.), the full tool surface is available regardless of what the skill needs. For a security-scanning skill that should only read + git-log + dispatch sandboxed scanners, this is a defence-in-depth gap: a malicious skill loaded into `~/.wirken/skills/` (per item 1's load-time-trust gap) could leverage tools the operator didn't expect that skill to use.

**Worked example.** If `~/.wirken/skills/<malicious-skill>/SKILL.md` instructs the agent to web-fetch a remote payload and write it to disk, today the agent complies because both tools are unrestricted. With `allowed-tools: Read, Bash` declared in that skill's frontmatter, the harness would refuse the unexpected `web-fetch` and `file-write` calls.

Schema questions:

- Where does the allowlist live? Per-skill frontmatter is the OpenClaw shape — declared by the skill author. Wirken could mirror that, or could move it to a separate `~/.wirken/skill-policies.json` operator-controlled file (less visible per-skill, but operator can override skill author).
- What's the default for skills that don't declare? OpenClaw appears to default to all-tools. Wirken could choose to default-deny once skills opt in, but that's a migration burden on the existing 16 bundled skills.
- How does it interact with bundled skills? Bundled skill frontmatter is signed-into-the-binary; updating frontmatter is a release-cycle change.
- What's the failure mode? Agent attempts a denied tool — refuse silently, log to audit, surface to operator, hard fail?
- How does it interact with the SKILL.sig signing flow? The `allowed-tools` declaration is part of the skill content covered by the signature, so there's no extra signing surface.

Concrete and shippable. Affects every skill, not just lyrik. Item 1's load-time-trust-gap and TOCTOU-first-setup cases (latent bucket) reach a different mitigation when this lands: even an attacker-planted skill file is bounded by what its declared `allowed-tools` permit.

**Investigation tickets, not yet FOLLOWUPS items:**

- `disable-model-invocation: true` — OpenClaw frontmatter primitive that prevents auto-invocation from generic prompts. May not be needed in wirken given how invocation works (operator messages a configured channel; agent picks a skill from the system prompt rather than auto-routing). Investigate first before deciding whether to add.
- `context: fork` — OpenClaw frontmatter that appears to fork a sub-context for skill execution. Speculative; semantics not documented in the OpenClaw skills I read. Investigate first before adding.

## 10. Capability tokens for skills (wirken-level; research-shaped, distinct from item 8)

Surfaced 2026-04-28 from the broader OpenClaw scan. OpenClaw's `tuanziguardianclaw` skill describes *"skill sandboxes, capability tokens, and real-time auditing"* as a runtime defence layer. The capability-token primitive is structurally distinct from item 8 (allowed-tools) and addresses a different threat model.

**Item 8 (allowed-tools)** is declarative: skill author specifies a tool whitelist in frontmatter, loader enforces at skill-load time. Static binding. Threat model: detect-and-refuse skills that try to use undeclared tools.

**Capability tokens** are runtime-issued, scoped, possibly revocable. The skill receives them at invocation; the skill cannot escalate beyond its capability set, cannot persist tokens across invocations, and the harness can revoke tokens mid-execution if a runtime check fails. Threat model: skill author cannot lie about needs because runtime enforces *what the skill actually does* against a per-invocation capability set.

These are different attacks:

- A skill that lies in its declared `allowed-tools` (item 8) is detected only at install/audit time. Item 10 makes the runtime verify per-call.
- A skill that needs a privileged capability for a specific operator request can request it dynamically; operator approves; harness issues a scoped token; skill uses; token expires. Item 8 is static — it can't grant something not pre-declared.

Capability-token systems are well-precedented (capability-based OS security, OAuth scopes, AWS IAM session tokens). The design space is large.

Schema questions:

- **Token shape.** Per-invocation? Per-tool-call? Smallest meaningful unit?
- **Token issuance.** Operator-approval-gated for sensitive capabilities? Auto-issued for declared `allowed-tools` (item 8) overlap?
- **Revocation.** Mid-execution revocation requires the harness to interrupt running tool calls. Hard. Or revoke-on-next-call only?
- **Audit.** Every issuance, use, and revocation logs to audit. Token IDs in audit log let post-hoc analysis correlate.
- **Composition with item 8.** Item 8 is the cheap concrete win; item 10 is the runtime layer atop it. Order: item 8 first, item 10 after item 8 lands and has real adoption.

This is **research-shaped**, not item-8-shaped. Don't bundle into item 8's roadmap. Don't let item 10's existence delay item 8 shipping. Fund a research week separately when prioritised.

## 9. JSON output schema preserving funnel discipline

Surfaced 2026-04-28 from a scan of OpenClaw's audit-skill ecosystem. Several skills emit structured output in JSON or CSV (`auditing-appstore-readiness`, `securityclaw`, `coin-news-openclaw`); none preserve a multi-stage assessment funnel as first-class fields.

The lyrik report's structural argument is funnel disclosure: *candidates → deduped → scored → exploit-verified*, with explicit categories for stages where verification was not attempted (`stopped_at_0_5`) and routings that aren't tier-invented (`gate_routed_disagreement`, `gate_routed_scope_bound`). When the report is markdown the structure is visible to a human reader. When the report becomes JSON, the structure has to survive flattening by ingestors that don't know about funnel discipline. A SIEM ingesting `findings[]` will treat lyrik output as a list of vulnerabilities and the structural argument evaporates at the API boundary.

### Two design constraints

1. **Funnel block at top level, not nested under findings.** Every category is a first-class field. Reporting tools, CI/CD gates, and trend dashboards read `funnel.*` directly.
2. **Each finding carries its own routing metadata.** Stream, stop reason, gate routing, dedup match, stable ID. Even if a SIEM flattens to `findings[]`, per-finding routing facts survive.

### Pipeline (strict, anchors the invariants)

```
Stage 1 — Framings produce raw candidates
Stage 2 — Cross-framing pairs fold → candidates_generated
Stage 3 — Dedup gate routes each → regression OR novel
Stage 4 — Scoring runs on regression + novel; produces tier+grade OR routes to gate (disagreement / scope_bound)
Stage 5 — Tier-assigned go to exploit phase; gate-routed leave the funnel here without tier
Stage 6 — Exploit phase outcomes: exploit_attempted, stopped_at_0_5 (with reason), grade_0_no_runtime_needed
Stage 7 — exploit_attempted resolves to: exploit_promoted_to_1_0 OR exploit_failed_in_budget
```

`scored` in the funnel means *"produced a tier"* (Stage 5 tier-assigned), **not** *"scoring was attempted"* — gate-routed items had scoring passes run but no tier emitted, and they leave the funnel at Stage 4 without entering `scored`.

### Top-level shape

```json
{
  "$schema": "TO BE LANDED — 1.0 blocker; placeholder will fail to resolve",
  "schema_version": "1.0",
  "run_id": "run-001",
  "produced_at": "2026-04-28T03:50:43+02:00",

  "target": {
    "scope": ["sys/rpc/rpcsec_gss/**/*"],
    "source_state": {
      "git_url": "https://github.com/freebsd/freebsd-src.git",
      "sha": "1fddb5435315ca44c96960b16bdda8338afd15a1",
      "qualifier": "pre_fix"
    }
  },
  "rubric": { "path": ".lyrik/rubric.md" },

  "funnel": {
    "candidates_generated":          9,
    "cross_framing_pairs_folded":    3,
    "deduped_to_regression":         1,
    "deduped_to_novel":              5,
    "gate_routed_disagreement":      1,
    "gate_routed_scope_bound":       2,
    "scored":                        6,
    "exploit_attempted":             0,
    "exploit_promoted_to_1_0":       0,
    "exploit_failed_in_budget":      0,
    "stopped_at_0_5":                4,
    "stopped_at_0_5_reasons":        { "kernel_runtime_oos": 4 },
    "grade_0_no_runtime_needed":     2
  },

  "concentration": {
    "method": "leave-top-N-out severity-weight aggregation",
    "weights": { "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0.1, "hardening_grade_0": 0.5 },
    "aggregate_full":             7.6,
    "aggregate_top_1_removed":    3.6,
    "aggregate_top_5_removed":    0.1,
    "aggregate_top_10_removed":   0,
    "concentration_index_top_5": 0.99
  },

  "findings": [
    {
      "id": "A1",
      "stable_id": "sys/rpc/rpcsec_gss::sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1158:svc_rpc_gss_validate",
      "stream": "regression",
      "framing": ["auth", "memory_safety"],
      "location": { "file": "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c", "line_start": 1158, "line_end": 1215, "function": "svc_rpc_gss_validate" },
      "title": "Stack overflow in svc_rpc_gss_validate()",
      "summary": "...",
      "tier": "CRITICAL",
      "grade": 0.5,
      "stop_reason": "kernel_runtime_oos",
      "tier_drop_applied": false,
      "dedup_match": {
        "tier_used": "exact",
        "prior_path": ".lyrik/prior/CVE-2026-4747.md",
        "match_keys": ["file", "function", "root_cause"]
      },
      "scoring_passes": [
        {"real_bug": "yes", "reachable": "yes", "attacker_reach": "yes", "blast_radius": "kernel-RCE"},
        {"real_bug": "yes", "reachable": "yes", "attacker_reach": "yes", "blast_radius": "kernel-RCE"}
      ]
    },
    {
      "id": "A5",
      "stable_id": "sys/rpc/rpcsec_gss::sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:651:svc_rpc_gss_init",
      "framing": ["auth"],
      "title": "INIT-storm legitimate-client eviction",
      "gate_routed": {
        "gate": "scoring_disagreement",
        "tag": "rubric_clarification",
        "rubric_refinement_question": "..."
      },
      "scoring_passes": [
        {"real_bug": "MEDIUM-shape: authn-state-displacement"},
        {"real_bug": "LOW-or-0-shape: LRU-cap-by-design"}
      ]
    }
  ],

  "audit": {
    "log_path": ".lyrik/state/runs/run-001/audit.log",
    "log_format": "iso8601 phase=<x> event=<y> [k=v ...]"
  },

  "observations": {
    "defensive_choices": [
      { "observation": "...", "evidence_path": "..." }
    ]
  }
}
```

Optional top-level fields, omitted when absent (no null literals): `comparison`, `cost`, `reproducibility`. When `cost.methodology == "estimated"`, the `tokens_in` / `tokens_out` fields are omitted, not set to null.

### Schema invariants (reconcile against serialized fields only)

```
funnel.candidates_generated  ==  funnel.deduped_to_regression
                               + funnel.deduped_to_novel
                               + funnel.gate_routed_disagreement
                               + funnel.gate_routed_scope_bound

funnel.scored                ==  funnel.deduped_to_regression + funnel.deduped_to_novel

funnel.scored                ==  funnel.exploit_attempted
                               + funnel.stopped_at_0_5
                               + funnel.grade_0_no_runtime_needed

funnel.exploit_attempted     ==  funnel.exploit_promoted_to_1_0 + funnel.exploit_failed_in_budget

sum(funnel.stopped_at_0_5_reasons.values())  ==  funnel.stopped_at_0_5

# General principle: any parent/sub-map pair where the sub-map enumerates
# named sub-counts MUST have a sum-to-parent invariant. Adding a new
# parent/sub-map pair without the corresponding invariant is a schema
# regression — the producer can populate the sub-map without updating
# the parent, and the report passes JSON Schema validation but fails
# reconciliation. Today the only such pair is stopped_at_0_5_reasons /
# stopped_at_0_5; any future sub-map must add its own invariant here.

count(findings where stream == "regression")           == funnel.deduped_to_regression
count(findings where stream == "novel")                == funnel.deduped_to_novel
count(findings where gate_routed.gate == "scoring_disagreement") == funnel.gate_routed_disagreement
count(findings where gate_routed.gate == "scope_bound")          == funnel.gate_routed_scope_bound
```

Every equation references serialized fields only. An ingestor can validate any report by computing these. A producer that fails reconciliation is broken.

### Stable IDs

Primary form: `findings[].stable_id` is canonical `"<scope_path>::<file>:<line_start>:<function>"`. Sufficient for ticketing dedupe within a single source state.

For cross-SHA diffs (the report-to-report diff ingestion behavior), pair runs by `target.source_state.git_url + target.scope` and match findings by fuzzy `(file, function)` with line-shift fallback. **A `root_cause_hash` was considered and rejected** — hashing LLM-generated description text means the ID changes when the model rewords the same finding, breaking ticketing dedupe. Function-name + AST-shape hash is more robust but heavyweight; defer to consumer side rather than producer side, since AST analysis at producer time is expensive and cross-SHA diff is a less common ingestion path than within-SHA ticketing.

**Brittleness annotation for consumer-side fuzzy matchers.** `line_start` is the brittle component of the stable ID — a finding at line 1158 in run N can be at line 1162 in run N+1 after an unrelated comment block is added above it, even though it's the same finding. Consumer-side fuzzy matchers must weight `function` heavier than `line_start`. The `function` field carries most of the stability; `line_start` is for disambiguation when two findings sit in the same function. Schema-doc consumers writing diff tools should be told this explicitly — the recommended match is `(file, function)` exact + `line_start` proximity within ±N lines for tie-breaking, where N is consumer-tuned.

For 1.0: ship the primary stable ID. Document the cross-SHA diff strategy and the line_start brittleness annotation. Don't bake AST hashing into the schema.

### `findings[].triage_status` reserved

Reserved as an optional string field, empty in 1.0. The CI/CD gating semantics question — *can a regression finding be marked "acknowledged, do not gate"?* — is a separate design turn; the schema leaves the field reserved so a gating-semantics design can populate it without bumping major version.

### `target.source_state.qualifier` enum

Closed:

- `current` — HEAD of working branch, mutable
- `pre_fix` — pinned SHA known to be before a specific patch
- `post_fix` — pinned SHA known to be after a specific patch
- `pinned` — pinned SHA, no fix relationship implied

Required for the report-to-report diff ingestion behavior: tools pair runs by `(git_url, scope, qualifier)` and `pre_fix` precedes `post_fix` for the same target.

### Six ingestion behaviors the schema must support

| Behavior | What it reads | How the schema supports it |
|---|---|---|
| **SIEM, takes findings[] only** | per-finding `stable_id`, `stream`, `tier`, `grade`, `stop_reason`, `gate_routed`, `dedup_match` | per-finding routing tags survive flattening |
| **SIEM with metadata** | top-level `funnel`, `concentration`, `target` + `findings[]` | full structure preserved |
| **Trend reporting (multi-run)** | `funnel.*` per run for time series; `concentration` per run | first-class funnel fields |
| **Ticketing (one ticket per finding)** | per-finding `stable_id`, `tier`, `location`, `summary`, `stream` | stable ID + per-finding self-sufficiency |
| **CI/CD gating** | `funnel.deduped_to_regression > 0` (block); `funnel.gate_routed_disagreement > 0` (require human review); `findings[].triage_status` (override) | direct field reads + reserved triage field |
| **Report-to-report diff** | pair runs by `target.source_state.{git_url, qualifier}`; match findings by `stable_id` (within source state) or fuzzy `(file, function)` (cross source state) | qualifier enum + stable_id + sort by `(file, line_start, function)` |

### Sort order for `findings[]`

`(location.file, location.line_start, location.function)`. Stream is a field, not a sort key. Stable diffing across runs of the same scope requires sort independence from stream classification — a finding moving from novel to regression must not jump positions in the sorted output.

### 1.0 blockers (must resolve before this schema ships)

1. **Schema URL.** `$schema` must resolve. Self-host on a wirken-controlled domain, register with JSON Schema Store, or embed in the wirken binary served via `wirken schema`. Decision required before customers pin.
2. **Stable ID canonicalization.** Define exact escaping for `<scope_path>::<file>:<line_start>:<function>` (colons in file paths, special characters in function names). Edge cases break ticketing dedupe.
3. **Invariant validator.** Ship a reference validator (`wirken lyrik validate <report.json>`) that any consumer or producer can run to verify reconciliation. Without it, the invariants are documentation, not enforcement.

### 1.0 deferrals (resolved as defer-to-1.x; not unresolved)

- **`comparison` block stays optional with documented MAY-include.** Conditional-required fields (e.g., "required when assessing against a public claim") are an ingestion nightmare — every consumer has to implement the conditional logic to validate. Optional with omission is correct. If the public-claims-comparison use case proves load-bearing, 1.1 can promote.
- **`audit.events[]` inline stays out.** Audit log is referenced via `audit.log_path`. Inlining events would explode payload size for any non-trivial run, and most consumers won't read them. Consumers needing the events fetch the log. 1.1 can add inline events as an optional flag-controlled field.
- **`observations.*` ships in 1.0 with only `defensive_choices`.** Adding `observations.anti_patterns_avoided` or `observations.design_rationale_inferred` speculatively means committing to a shape before seeing it twice. Document `observations.*` as a reserved namespace; ship 1.0 with only `defensive_choices`. New sub-arrays in 1.x are minor-version bumps.

### Revisions made in this draft (against an earlier version)

- Pipeline stages explicit, so invariants anchor to a strict flow. Earlier "items routed to gate after scoring" was an unserialized parenthetical; the model now is gate-routing happens *during* scoring (Stage 4) and gate-routed items leave the funnel without entering `scored`.
- `extensions` removed. Stop-reason categories first-class; closed enum for `stopped_at_0_5_reasons` keys (open list of named reasons that all sum to the parent count).
- Null literals removed. Optional fields are omitted, not null.
- `defensive_choices_observed` namespaced to `observations.defensive_choices`. Reserves `observations.*` for future expansion.
- Sort order `(file, line_start, function)`; stream is a field.
- Stable ID composite simplified to `(scope_path, file, line_start, function)`. `root_cause_hash` rejected.
- Sixth ingestion behavior added: report-to-report diff. `qualifier` enum required.
- `findings[].triage_status` reserved for the CI/CD gating semantics design.
- Schema URL marked as 1.0 blocker explicitly, not "open question."

## 11. Runtime-watchdog mode (wirken-side roadmap pointer, not lyrik design)

Surfaced 2026-04-28 from the OpenClaw scan. `skillfence` ("Runtime security monitor for OpenClaw skills. Watches what your installed skills actually DO — network calls, file access, credential reads, process activity. Not a scanner. A watchdog.") is a complementary posture to lyrik: lyrik audits *target code*; a runtime-watchdog mode would audit *running skill behavior*. Two postures, both legitimate.

**Roadmap pointer, not a design item.** Research item, not roadmap. Don't expand into a design until there's a concrete user pulling for it.
