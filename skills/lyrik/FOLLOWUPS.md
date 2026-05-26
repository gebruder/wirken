# Lyrik FOLLOWUPS

Boundaries surfaced by real use that need design work beyond what the SKILL.md form can carry. Each entry pairs the boundary with the worked example that surfaced it, so a future decision starts with data instead of speculation.

Active design questions — see GitHub Issues. Items here are case-accumulating records: each entry pairs a boundary surfaced by real use with the worked cases that surfaced it, so a future design decision starts with data, not speculation.

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

Two cases so far. Three or four more before the design question is ripe. The shape is the highest-value capability the lyrik form can plausibly carry — worth more design weight than any of items 1–3.

## 5. Streaming token-usage capture (wirken-streaming-token-usage)

Surfaced 2026-05-03 by the `wirken-anthropic-token-usage-capture` slice.
Wirken's non-streaming dispatch now captures the provider's `usage`
block (input/output tokens, plus anthropic-specific cache fields) and
records it in `SessionEvent::LlmResponse`. The streaming dispatch
(`LlmClient::complete_stream`) does not — it returns
`LlmResponse` only and writes `Usage::default()` (zeros) into the log.
Each provider's streaming protocol carries usage in different events
(anthropic in the final `message_delta`, OpenAI in the final SSE chunk
when `stream_options.include_usage = true`); capturing it requires
provider-specific event parsing.

**Constraint until this slice ships**: bench mode and
economics-reporting runs must use non-streaming dispatch. Streaming
returns `Usage::default()` and would silently under-report token cost;
any cost number computed off a streaming session is wrong by the full
input/output count.

## 6. Per-finding field caps (lyrik-skill-per-finding-field-caps)

Surfaced 2026-05-03 during the `lyrik-skill-staged-emission` audit.

The staged-emission slice bounds *the assessment* by writing one
finding per file. It does not bound *one finding*. Per-finding fields
that can grow without an explicit cap:

- `scoring_passes[*].rationale` — one paragraph per pass; with three
  passes on a high-severity disagreement candidate, ~500–1500 tokens.
- `patch_localized.hunks[*].insertedContent` — multi-line patches; a
  finding that proposes a non-trivial fix can carry ~500–2000 tokens
  here.
- `summary` — one-paragraph; well-bounded in practice.
- `property_template.proposition` + `slots` — small, well-bounded.

A finding stacking three scoring rationales plus a multi-hunk patch
plus a long summary can reach 2–3K tokens of JSON. Within the staged
write that is one `content` argument, still bounded but on the upper
end of what providers reliably construct.

Trigger condition for the slice: at least one observed run where a
single finding exceeds 2K tokens in JSON form. Then:

- Cap each `scoring_passes[*].rationale` to ~500 tokens; longer goes
  to a side file (`staging/findings/finding-NNN.rationale-K.md`) and
  the JSON references the path.
- Cap each `patch_localized.hunks[*].insertedContent` over a threshold
  to a side file (`staging/findings/finding-NNN.patch-K.diff`) and the
  JSON references the path.
- Runner aggregator copies side files alongside the run dir at
  aggregation time.

Worked example: queue when observed. The `lyrik-skill-staged-emission`
slice does not address this; the per-finding write itself is already
bounded enough that this is a second-order concern.

## 7. Ollama 7B-class models cannot validate multi-framing emission

Surfaced 2026-05-03 during the `lyrik-add-second-framing` slice.

`qwen2.5:7b` (via ollama native `/api/chat`) cannot reliably emit
multi-finding tool-call sequences under the multi-framing skill body.
Two failure modes were observed back-to-back on the same target (AVB
`sample-paper-listing-1/source`, agent.py with V1 injection + V2 auth):

- **Soft skill wording** ("identify each vulnerability per applicable framing"):
  model emitted the findings as a markdown-formatted assistant message
  with `### Auth Framing\n1. **Vulnerability:** …` shape and made
  zero `write_file` calls. Run output: 8600-char prose response, no
  staging files, runner bails.

- **Strong tool-call-only discipline** ("your assistant message contains
  only a terminal sentence; every vulnerability is a `write_file`
  call, no exceptions"): model overcorrected and emitted neither
  prose nor tool calls. Run output: 13-char acknowledgment-shaped
  response ("no response" head), no staging files, runner bails.

The discipline language calibration that produces tool-call output on
multi-finding scenarios appears narrower than 7B parameter models can
reliably target. Single-finding cases work in either setting (the
prior `lyrik-add-scoring` slice validated cleanly because one finding
maps unambiguously to one `write_file`). Multi-finding requires the
model to enter a loop of tool calls without describing the loop in
prose; 7B models drop one of the two channels entirely.

**Trigger:** drop ollama qwen2.5:7b (and presumably similar-sized
local models) as a *multi-framing* validation surface. Single-framing
ollama validation still works and is the baseline gate. Multi-framing
validation runs against frontier providers (anthropic sonnet, openai
gpt-5) on small targets like the AVB sample for cost.

**Possible fixes** (ordered by likely effectiveness, none committed):

- Frontier-only multi-framing for now. Doc-level fix.
- One framing at a time: invoke the agent twice, once per framing,
  with framing-specific prompts. Loses the cross-framing coupling
  (same line under two framings emitting two findings) but gives 7B
  models a tractable shape.
- Per-finding sub-agents: spawn a child agent per identified
  vulnerability whose only job is "emit one finding." Removes the
  multi-call loop from the parent's responsibility. Heavier
  infrastructure; only worth it if there's another driver.

## 8. Multi-run aggregation for local-model intrinsic drift

Surfaced 2026-05-26 during the qwen3-coder:30b single-framing probe
on `crates/adapter-signal`. Bench writeup at
`~/code/lyrik-bench/local-emit-test/qwen3-coder-30b-stability.md`.

Seven runs of the same target on the same model, same context
budget, same commit, varying only the framing scope (3 multi-framing
+ 4 single-framing). The single-framing probe discriminated two
phenomena that were tangled in the multi-framing baseline:

- **Convergence is a load knob.** Multi-framing: 2 of 3 converged.
  Single-framing: 4 of 4 converged. The non-convergence under
  multi-framing was the model failing to terminate the multi-finding
  loop, not the model fundamentally broken.
- **Bug selection is intrinsic to the model.** Single-framing did
  not reduce wandering at all. Within `auth`: run 1 found a
  hardcoded phone number at line 265, run 2 found a missing auth
  check at line 210. Different *bugs*, not different lines for the
  same bug. Within `injection`: run 3 found `eval`-like functionality
  at line 103, run 4 found command injection via socket path at
  line 273. Same model, same code, same framing, only the sampling
  seed varied. The model is sampling from a distribution of
  plausible vulnerability stories about the code, not enumerating
  the actual vulnerabilities.

A single local run is therefore one snapshot from a distribution of
N plausible stories, not an enumeration. That is disqualifying for
Lyrik's defensible-report goal on the merits, not on a tuning
failure.

**Design question, distinct from #1's new/repeat-stream item:** the
new/repeat-stream design compares findings against a `.lyrik/prior/`
history (across-run-history dedup). Multi-run aggregation runs the
same framing N times in one assessment, aggregates by recurrence
frequency, and reports frequency as a confidence signal. A bug
found in 5 of 5 runs is qualitatively different from one found in
1 of 5. Same axis is recurrence, but the storage and lifecycle are
different (within-assessment, not across-assessment).

**Dependency on #143, identity not just verification.** Aggregation
counts recurrence by `stable_id` (`framing::file:line`). The intrinsic
drift this entry exists to handle breaks that identity directly: the
same vulnerability cited at line 265 in one run and line 210 in
another gets two different stable_ids and looks like two findings,
while two genuinely different bugs at a coincidentally-shared line
look like one. Aggregating by `stable_id` will mismeasure recurrence
in exactly the dimension drift introduces noise. The bench data is
already this shape: `auth-r1` and `auth-r2` describe two different
bugs at two different lines, but a recurrence aggregator built on
positional identity would count them either as zero matches
(reporting "no overlap, low confidence") or two separate single-shot
findings (reporting "two distinct 1-of-2 findings"), neither of which
matches what the model is actually doing.

A useful notion of "same finding" is class-shape-aware: two findings
are the same when they describe the same vulnerability class at code
that does the same thing, not when their citation numerics match.
That is the same work that #143 needs for its non-literal claim-shape
detectors. The two items share the identity-of-a-finding question;
design them together, not sequentially. Building aggregation on top
of `stable_id` first and revisiting identity later means measuring
recurrence on a key the drift breaks, then having to migrate the
schema.

Schema questions:

- Where in the pipeline does aggregation run? Per-run staged findings
  feed into an aggregator that emits a single `findings.json` per
  assessment, with a `recurrence` field on each finding (`{seen_in:
  N, of_runs: M}`).
- How is N chosen? Operator config, with a default that trades cost
  for confidence. Five runs is a reasonable starting point; the
  bench can refine.
- How are findings clustered across runs into "same bug"? The
  citation gate's gap (#143) bites here: same-bug detection has to
  bridge "same claim at slightly different line" without using
  literal-claim heuristics that don't fire for most findings.
- How does this compose with the per-walk dispatch path? Each walk
  could itself be aggregated, or the union of N runs across walks
  could form the corpus.

**Trigger:** the single-framing probe is one data point that drift
is intrinsic. One more local-model bench on a different target
(say, `crates/mcp-proxy` or a sibling repo) would confirm the
shape generalizes. Once confirmed, multi-run aggregation is the
path to a defensible local report and is worth design weight.

**Worked case:** see the writeup at
`~/code/lyrik-bench/local-emit-test/qwen3-coder-30b-stability.md`
for the full 7-run table and the convergence-vs-drift split.
