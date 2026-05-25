# Changelog

All notable changes to Wirken are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [semver](https://semver.org).

The `release-process.md` runbook covers how versions get cut and
signed. Unreleased changes accumulate at the top until a release is
tagged.

## Unreleased

### Lyrik Semgrep-seed pass + schema-v1.1

- Pre-LLM Semgrep dataflow pass, opt-in via
  `.lyrik/config.json::scanner.semgrep.enabled`. Pinned binary
  version + bundled ruleset (sha computed at first use).
  Taint/dataflow candidates materialise as seeds under
  `.lyrik/state/runs/<run-id>/seeds/seed-NNN.json`; the model
  rules on each. Explicit decline files (`staging/<walk?>/declines/decline-NNN.json`,
  `{seed_id, reason}`) separate "considered and rejected" from
  "never ruled." Binary absent, version mismatch against the
  runner's pin, or invocation failure degrade-and-log via
  `lyrik.scanner.unavailable` and proceed LLM-only. Default off:
  absent the config block, zero behavioural change.
- New per-run audit events: `lyrik.scanner.dispatched`,
  `lyrik.scanner.unavailable`, `lyrik.candidate.declined`,
  `lyrik.candidate.unaddressed`. Per-run NDJSON only; no
  signed-`SessionLog` typed variant in this slice.
- **Lyrik JSON schema bumps to 1.1.** `detection_source` is
  promoted from the allowed-extras band to an enforced-when-present
  closed enum (`static_prescreen`, `model_reasoning`, `both`).
  `both` is produced only by per-walk dedup convergence between a
  scanner-seeded finding and a model-native finding at the same
  location; single-call mode has no aggregator and never emits
  `both`. The validator strictly accepts `schema_version: "1.1"`;
  pre-1.1 archives stay readable by a pre-1.1 binary. New git tag
  `schema-v1.1` anchors the `$id` URL. See
  [`docs/lyrik-json-schema.md`](docs/lyrik-json-schema.md) and
  [`docs/lyrik.md`](docs/lyrik.md).

### OpenTelemetry projection

- New `wirken_audit::otel_*` modules. Project session events into
  OpenTelemetry GenAI semantic-convention spans and ship
  OTLP/HTTP+JSON to any OTLP-compatible backend. Microsoft documents
  a direct OTLP contract for non-SDK Agent 365 integration, which
  this projection implements. See
  [`docs/integrations/agent365.md`](docs/integrations/agent365.md).
- Pluggable `FederatedIdentity` trait with `KeycloakFederatedIdentity`
  on `main`. The Microsoft Entra identity, conformance suite, and
  Graph registration are consolidated under
  [#135](https://github.com/gebruder/wirken/issues/135) and deferred
  pending a licensed tenant fixture.

## [1.7.1] - 2026-05-20

### Subscription surface

- New `docs/external-consumers.md` describes the two existing
  surfaces an out-of-process consumer can use to tail the audit
  chain: the observe-hook Cap'n Proto IPC pipe (Ed25519 handshake,
  pull cursor) and the SIEM webhook (HTTPS, optional HMAC). Code
  was already in place; this page is the operator-facing contract.

### MCP signing anchor

- `mcp.json` entries can carry an Ed25519 signature over a
  canonical hash of the entry's load-bearing fields. The proxy
  refuses entries that fail verification; default builds ship
  `wirken-mcp-pubkey.pub` empty, which keeps pre-anchor behavior
  intact. Anchored builds (operator populates the file before
  compile) refuse unsigned entries unless
  `WIRKEN_ALLOW_UNSIGNED_MCP=1` is set. `wirken mcp sign <server>`
  and `wirken mcp verify [<server>]` are the operator surfaces.
- Env values and OAuth credential refs are excluded from the
  signed surface so vault rotation does not invalidate
  signatures.
- `SessionEvent::McpEntryVerified` and `McpEntryRefused` land on
  the `gateway-mcp` sentinel session and are in the default
  typed-SIEM forwarded set.
- `wirken doctor` reports MCP signing posture.

### Same-row attribution on policy rows

- `PermissionDenied`, `PermissionApproved`, and `HookDispatched`
  gain optional `adapter_id` and `sender_id` fields populated
  from `current_inbound` at every emit site. SIEM detections on
  policy decisions pivot on one row instead of joining back to
  the sibling tool-call row. `#[serde(default,
  skip_serializing_if = "Option::is_none")]` keeps pre-upgrade
  rows byte-identical on disk so the per-session leaf hash still
  verifies.

### Egress hook dispatcher

- Twin of the veto-hook dispatcher on the post-execution path.
  After a tool returns and before its output enters the LLM
  conversation, the runtime calls
  `EgressDispatcher::dispatch(tool_name, output_bytes,
  session_id)`. Hooks run in registration order under
  `WIRKEN_EGRESS_BUDGET_MS` (1000ms default) with a 500ms
  per-hook cap and return `Allow`, `Replace { bytes }`, or
  `Refuse { reason }`. Replace mutates the working bytes for the
  next hook; Refuse short-circuits the pipeline.
- `HookType::Egress` joins `Observe` and `Veto`; register with
  `wirken hooks register <id> <pubkey-hex> --type egress`. Same
  Ed25519 handshake the other types use.
- `SessionEvent::EgressHookDispatched` and `ToolOutputRedacted`
  land on the chain. The original output bytes are not on the
  chain by design; `ToolOutputRedacted` carries
  `original_sha256` and `redacted_sha256` only. `ToolResult.output`
  is the post-mediation bytes verbatim, which is what the
  conversation surfaces and what `messages_hash` verifies against.
- Deterministic-tool re-execution divergence checks
  (`wirken session verify`) skip rows that have a paired
  `ToolOutputRedacted` row: the redaction is operator policy,
  not wirken behavior, and re-execution would compare freshly
  produced source bytes against operator-redacted bytes.

### Dependencies

- Bumped `openssl` 0.10.79 to 0.10.80 to clear
  `GHSA-phqj-4mhp-q6mq` (CVE-2026-45784). The vulnerable
  `CipherCtxRef::cipher_update_inplace` path is not reachable in
  wirken: no workspace code calls `openssl::*`, and the
  transitive dependency through `native-tls` exercises only TLS
  record encryption, not AES key-wrap-with-padding. Lockfile-only
  change.

## [1.7.0] - 2026-05-17

### Audit trust model

- Verify failures discriminate schema-class (warn, continue) from
  tamper-class (halt, surface). Three consecutive tamper failures still
  cross `MAX_INTEGRITY_FAILURES` into halt; schema-class failures
  accumulate on a separate counter and do not halt the writer. A
  rename of an enum variant or a new optional field on
  `SessionEvent` is no longer indistinguishable from a hash-chain
  break. Closes #115.
- Channel-routed verify events drain before the halt boundary
  completes, so the operator's last view through any in-flight
  surface (SSE, CLI permissions stream) sees the failure before the
  writer goes dark. Earlier behavior could drop the verify event
  mid-flush. Closes #107.
- Boot-time refusal: if the audit chain finds an unacknowledged
  alarm record from a prior session, `wirken run` fails closed at
  boot rather than starting on top of an unobserved tamper signal.
  Operator acknowledges via `wirken audit ack <event_id>`. Closes
  #118.

### Approval gates (cross-adapter umbrella)

All nine channel adapters now carry an approval gate. The seven that
had none (Discord, Slack, Teams, WhatsApp, Google Chat, Matrix,
iMessage) gained one; the two that did (Telegram, Signal) realign on
a shared payload contract.

- `wirken-adapter-core::approval` adds a shared payload encoding
  (`req:<uuid8>:allow|deny[:reason]`) consumed by every adapter that
  emits an `ApprovalDecision` frame. One parser instead of nine
  forks. Telegram retrofit moves to the shared encoding (previously
  had an adapter-local shape).
- Discord, Slack, Teams, WhatsApp, Google Chat: approval gate via
  the platform's native interactive component (button / action /
  interactive-button / chip / card-action). Approval press resolves
  the pending request without an additional message round-trip.
- Matrix: approval gate via `m.reaction` events against a
  correlation table mapping `(room_id, event_id)` to request UUID.
  `m.reaction` is the closest federated equivalent to a button on a
  protocol with no vendor-specific interactive components.
- iMessage: text-command approval gate (`!approve <prefix>` /
  `!deny <prefix> [reason]`), same shape as Signal. Two of nine
  adapters now use the text-command shape; the parser is factored
  into `wirken-adapter-core::text_command` and consumed by both.

### Lyrik output schema

- `LYRIK_OUTPUT_SCHEMA.md` documents the JSON output contract at
  version `1.0` and ships a reference validator (`lyrik-validate`).
  Lyrik output consumers can pin to the schema version and detect
  drift independent of the binary's release cadence. Closes #80.

### Smaller fixes

- Signal `ApprovalRequest` prompt normalized to the umbrella majority
  shape (header, requested-by, request-id prefix). Removes a
  Signal-only trailing `Request: <full-uuid>` line that did not
  match the prompt convention used by the other adapters. Closes
  #122.
- Google Chat `MessageEvent::receive_text` derives `user_id` from
  the canonical path identifier (`users/<id>`) consistent with the
  approval-press path. Previously diverged: text events carried the
  display-name path, approval-press events the canonical path.
  Closes #120.
- `wirken-adapter-core::text_command` module: the verbatim-clone
  text-command parser previously duplicated across `adapter-signal`
  and `adapter-imessage` is factored out of both. Closes #121.

## [1.6.0] - 2026-05-17

### Approval gates

- New `ApprovalGate` trait gating `NeedsApproval` tool-call requests
  out-of-band rather than failing terminally at the agent. Five
  surfaces: stdin (interactive `wirken ask`), CLI (`wirken
  permissions pending approve|deny` over the permissions IPC socket
  for daemon mode), Telegram (inline-keyboard approve/deny button),
  SSE (webchat browser-side card), and Signal (first text-command
  channel adapter: `!approve <prefix>` / `!deny <prefix> [reason]`,
  prefix is the first 8 hex characters of the request UUID).
- Wire-breaking schema rename on the channel-adapter approval frames:
  `ApprovalRequest.targetChatId :Int64` -> `targetConversationId
  :Text`; `ApprovalDecision.telegramUserId :Int64` -> `actorUserId
  :Text`; `ApprovalDecision.telegramUserDisplay :Text` ->
  `actorDisplay :Text`; `ApprovalDecisionKind.deny :Void` -> `:Text`
  carrying the operator-supplied reason (Telegram writes empty; Signal
  writes the text after the prefix). The rename generalizes the
  frames off Telegram-specific naming so non-numeric conversation ids
  (Signal base64 group ids, UUID/E.164 for DMs) work without
  per-adapter shape forks.
- SQLite schema: `adapter_approval_chats` table renamed to
  `adapter_approval_conversations`; column type `INTEGER` ->
  `TEXT` for the same conversation-id-string contract.
- `wirken approvers set-chat <adapter_id> <conversation_id>` now
  accepts a String (was i64), so Signal group ids configure the same
  way Telegram chat ids always did.
- Gateway-side authorization is centralized: every `ApprovalDecision`
  frame is verified against `approver_registry::verify(adapter_id,
  &actor_user_id)` before the queue resolves. Unauthorized actions
  are silently dropped with a warn-level log; the queue stays open
  until an authorized action arrives or the gate times out.

### Hooks

- New hook subsystem. Ed25519 handshake distinct from the adapter
  handshake (domain-separated signing payloads); registry with
  `wirken hooks register|list|unregister` CLI; audit events for
  handshake accept/reject, dispatch, and response.
- Two hook types selected at handshake time: `observe` (pull-cursor
  batches of `SessionLogTail` events with a hook-supplied
  `sinceSeq` cursor) and `veto` (synchronous `VetoRequest` /
  `VetoResponse` exchange before each tool dispatch, with a serial
  cumulative budget across all attached veto hooks).
- Wire-level routing is handshake-derived, not payload-derived.
  `tests/no_payload_routing.rs` pins the banned-field set so a
  future schema addition cannot accidentally introduce an
  `agent_id`-typed field on a wire frame.

### Cost attribution

- Per-call cost on `LlmResponse`, computed from a baked pricing
  table keyed by `(provider, model)`. Records `input_cost_usd_micros`,
  `output_cost_usd_micros`, and `total_cost_usd_micros` on every
  `SessionEvent::LlmResponse` row.
- Streaming cost attribution: the OpenAI-compat consumer reads the
  trailing usage chunk that vLLM-backed servers (NIM, Privatemode,
  Tinfoil) emit after the `finish_reason` chunk and before
  `data: [DONE]`. The consumer never short-circuits on
  `finish_reason`. New stub-server test pins the contract so a
  future refactor cannot silently zero-count streaming tokens.

### Providers

- NIM as a new option in `wirken setup`, positioned next to Ollama.
  Default endpoint `http://localhost:8000/v1` with optional bearer
  auth (blank for local containers, `nvapi-...` keys for
  `https://integrate.api.nvidia.com/v1`). Stored as
  `provider="custom"`; the runtime's existing OpenAI-compat dispatch
  handles it without a new match arm or cost-table entry.
- New `list_openai_compatible_models` helper that lists models
  without the OpenAI-name filter (so NIM's `meta/llama-*` and
  `nvidia/...` model ids appear in the picker) and omits the
  Authorization header when the key is empty (no malformed `Bearer `
  with trailing space for proxies in front of NIM).
- The helper surfaces three distinct failure modes -
  `AuthRequired` (401/403), `Unreachable` (anything below HTTP,
  collapsed because reqwest's taxonomy isn't reliable across
  platforms), `OtherHttp(status)` - so a wrong-endpoint typo isn't
  masked as "no models found, enter manually". NIM branch loops on
  failure with re-enter-or-manual-fallback choice.

### Signal adapter

- Connect-before-send: first signal-cli connect completes before the
  outbound handler is spawned. Gateway frames arriving in the
  cold-start window no longer surface as `ApprovalRequestFailed`
  with `channel_not_accessible`. First-attempt connect failure
  exits `run()` with a clear error instead of looping in a degraded
  state where every outbound frame fails.
- Mid-session reconnect window: `send_message` parks on a
  `Notify`-driven `wait_for_connection` cap (default 30s, override
  via `WIRKEN_SIGNAL_RECONNECT_WAIT_S`) when `self.inner` is None.
  Cap exceeded -> `ApprovalRequestFailed` with reason
  `reconnect_timeout`, distinct from the cold-start
  `channel_not_accessible` label.
- Allowlist classifier checks canonical UUID layout before the
  phone-shape heuristic. All-numeric ACI UUIDs
  (`00000000-0000-4000-8000-000000000001`) now parse as UUIDs;
  previously misclassified as malformed phones and rejected at
  startup.

### Audit chain

- New `ApprovalSource` enum on `PermissionApproved` /
  `PermissionDenied` rows: `Stdin`, `Cli`, `Sse`, and
  `ChannelAdapter { channel: String }`. The operator-vs-surface
  split (`approved_by` carries actor identity; `approved_via`
  carries the surface enum) lets SIEM detections group by surface
  without parsing free-text actor labels.
- Channel-keyed approval-gate routing at the factory wake site:
  sessions whose canonical id parses with channel
  `telegram|signal|webchat` route through the matching gate;
  everything else falls back to the default.

### Notes

- The approval-frame schema rename is coordinated across the adapter,
  gateway, and gate at the same commit. Nothing reads the legacy
  field names.
- A small audit-chain race in `PendingApprovalQueue::resolve` is
  documented in code: a `tx.send` that lands microseconds before the
  receiver drops can return `Accepted` to the operator's HTTP path
  while the gate already returned `Timeout`. Sub-millisecond window;
  audit chain is authoritative.

## [1.5.3] - 2026-05-15

### OAuth

- Typed `McpToolError::ScopeNotGranted` variant in
  `wirken-mcp-proxy`, closing the gap left in v1.5.0's OAuth
  scope picker. Detection wired for Linear, GitHub, and Google
  via per-provider detectors that match documented REST / GraphQL
  error shapes (GitHub REST "Resource not accessible by ..." and
  related 403 phrases, Linear GraphQL `FORBIDDEN` /
  `AUTHENTICATION_ERROR` extensions combined with insufficient-
  permissions wording, Google REST `insufficientPermissions`
  reason / "Request had insufficient authentication scopes"
  envelope). Notion does not use OAuth scopes and has no
  detector. Detectors are conservative: ambiguous shapes return
  `None` and fall through to the generic error path. `McpToolResult`
  gains an `error_kind` discriminator and substitutes the typed
  `Display` text (`"Tool call refused: credential '<name>'
  missing scope <hint>. Run: wirken credentials rescope <name>"`)
  into `output` when a detector matched, so the operator sees the
  rescope command in the agent's response without dispatching on
  the typed variant. `AuthProvider` gains an `oauth_context()`
  method and the `Transport` enum exposes it on the call path so
  detection runs only when the credential is OAuth-managed.
  Source-derived detection: the first real-world failure either
  confirms each parser's shape or refines it. See
  `docs/credentials.md` for the updated operator narrative.

## [1.5.2] - 2026-05-15

Audit chain halt on first run against any pre-1.2.0 audit.db.
`SessionEvent::AuditLegacy` required `actor_kind` without a default;
pre-1.2.0 rows in `session_events` lacked the field, deserialization
failed, three consecutive chain-verify passes crossed
`MAX_INTEGRITY_FAILURES`, the writer halted silently. The audit chain
went dark on first run of 1.5.1 against any database written by an
earlier version. The variant now defaults `actor_kind` to `Service`
and aliases `actor_id` to accept the legacy `actor` field.

Default `wirken run` boot output cleaned up. The tracing filter
flipped from `wirken=info` to `wirken=warn`, so INFO from any wirken
crate is now opt-in via `RUST_LOG=wirken=info`. Three escaped
`println!` lines handled: `Audit log:` dropped entirely (Step 6 of
`wirken setup` owns the audit-path surface with full crypto framing);
`Host exec shell:` split (none-found stays as a warn, happy-path
goes to info); `Orchestrator socket:` demoted to info.

Issue #115 tracks the deferred halt-policy work distinguishing
tamper-class verification failures (halt and surface) from
schema-class failures (warn and continue). 1.5.2 restores
deserialization for the immediate gap; the policy redesign is its
own slice.

## [1.5.1] - 2026-05-15

Install experience overhaul. Setup wizard and run banner restructured;
"gateway" is gone from user-facing surfaces (internal IPC role unchanged).

Default `wirken run` output drops three lines (IPC socket path, SIEM
forwarder spawn, single-agent list); set `RUST_LOG=info` to surface them.
Channel display names in the run banner's Route: line and the setup outro
use brand-canonical casing (Telegram, iMessage, WhatsApp); internal ids in
config files and audit events stay lowercase.

## [1.5.0] - 2026-05-14

### Known security findings (deferred)

- Scorecard / `cargo audit` reports 7 outstanding advisories on
  transitive dependencies, all carried from before the 1.5 cycle
  and not introduced by 1.5 changes:
  - `rsa 0.9.10` (RUSTSEC-2023-0071, Marvin timing sidechannel) via
    `tinfoil → sev`. No upstream fix is available; the affected
    operation is not in a remote-attacker-reachable timing-sensitive
    path. Tracked for fold-in when `rsa` upstream ships a
    constant-time implementation.
  - `rustls-webpki 0.102.8` (RUSTSEC-2026-0049, -0098, -0099, -0104)
    via `serenity 0.12.5 → tokio-tungstenite 0.21.0 → rustls 0.22.4`.
    Fixes are on the `rustls-webpki 0.103.x` line, which requires
    `rustls 0.23.x`; `serenity 0.12.5` (current stable) pins
    `rustls 0.22.4`. Tracked for fold-in when serenity bumps or the
    Discord adapter is swapped. The affected code paths (CRL
    handling, URI name constraints, wildcard name constraints) are
    not exercised by the Discord adapter's traffic against
    `discord.com`.
  - `backoff 0.4.0` (RUSTSEC-2025-0012, unmaintained) and
    `instant 0.1.13` (RUSTSEC-2024-0384, unmaintained) via
    `tinfoil → async-openai 0.36.1`. Tracked for fold-in when the
    `tinfoil` pin bumps to a build that uses `async-openai 0.38+`.

### OAuth

- Interactive OAuth scope picker. `wirken mcp authorize <server>`
  invokes a `dialoguer::MultiSelect` listing the scopes the
  provider's catalog supports (Linear, GitHub, Google; Notion
  short-circuits because it grants permissions per workspace
  outside the OAuth scope mechanism). Required scopes are
  auto-included and never de-selectable; the picker shows only
  optional scopes for operator toggle. Non-interactive flags
  `--scope <id>` (repeatable), `--no-scopes`, and `--all-scopes`
  skip the picker for scripted use; required scopes are still
  unconditionally included regardless of which path the operator
  takes. `wirken credentials show <name>` displays non-secret
  metadata and the granted scope list; `wirken credentials list`
  gains a SCOPES column showing the scope count per row;
  `wirken credentials rescope <name>` re-runs the OAuth flow with
  a picker pre-seeded from the credential's current scopes and
  atomically replaces the vault row on success. Type-enforced
  redaction: a new `PublicOAuthCredential` view carries only the
  non-secret fields and is the type all CLI display paths consume;
  `OAuthCredential` itself gains a hand-written `Debug` impl that
  redacts bearer tokens so accidental tracing or `dbg!` calls
  cannot leak them. The typed `ScopeNotGranted` tool-error variant
  and transport-layer detection of missing-scope failures are
  deferred to a follow-up slice pending verification against real
  MCP-server auth-error formats; until that lands, operators see
  the provider's raw auth-error response and must run
  `wirken credentials rescope <name>` themselves. See
  `docs/credentials.md`.

### Personas

- Named persona bundling. `wirken persona create / list / show /
  edit / delete` subcommands provide an operator-facing handle for
  an `AgentConfig` row plus an optional reference to a `Preset`
  (skill bundle). The schema gains a nullable `AgentConfig.preset`
  column via additive migration, so existing rows continue to
  round-trip as `preset = None`. `wirken ask --agent <name>` (alias
  `--persona <name>`) materializes the persona at construction
  time: identity, provider, channels, and subagent permissions
  come from the `AgentConfig` row, and the preset's declared
  skills are merged into the agent alongside the per-agent and
  shared skill directories. The daemon-side `AgentStaticConfig`
  build path picks up the same materialization so adapter-routed
  sessions (Telegram, Signal, etc.) resolve personas identically.
  A dangling preset reference surfaces differently per surface:
  `wirken persona show` prints a stderr warning and exits zero
  (inspection tolerates incomplete state); `wirken ask` and
  `wirken run` exit non-zero with a structured error message
  naming both recovery paths (execution refuses to run an agent
  that cannot deliver its promised skills). See
  `docs/personas.md`.

### Permissions

- Session-scoped approval allowlist. `wirken permission approve
  <action-key> --session <session-id>` grants an approval that
  lives in-memory for the named agent session only and is cleared
  on session end (the `factory.evict` path; a production caller
  will follow when "wirken sessions close" wiring lands). Without
  `--session` the command keeps its existing 30-day persisted
  behaviour. Session-scoped grants are recorded in the per-session
  hash chain as `SessionEvent::PermissionApproved` with
  `scope: Session` and replayed from the log on next agent wake,
  so an active grant survives a crash and a clean
  `SessionScopedApprovalsCleared` tombstone is respected on
  replay. `PermissionCheck` consults the in-memory cache before
  the SQLite lookup; a session-scoped grant overrides any tier
  for the duration of its session. The CLI persisted path stays
  silent on the audit chain by design (operator-initiated
  persisted grants are out of band of any single session log; a
  non-session operator-action audit channel is the future home
  for those).
- Per-pass tool-call denylist. Skills can declare phase
  boundaries via synthetic `wirken_enter_phase` /
  `wirken_exit_phase` tool calls, LLM-visible only when the skill
  declares them in its `SKILL.md` `permissions.tools.allow`. Each
  phase carries a deny set across five axes: tools, egress hosts,
  filesystem read paths, filesystem write paths, inference
  providers. Enforced at the tool-call gate overlay-first /
  base-fallthrough, returning typed
  `GateDecision::DeniedByPhase { phase_name, axis }`. Egress-axis
  enforcement runs through `EgressClient`'s parallel
  overlay-deny slot, consulted before the base
  `EgressEnforcement`; an `EgressDenied` carries an
  `EgressDenyReason` (`Profile` vs `Phase { phase_name }`) that
  translates into the same `SkillDeniedReason` shape the other
  axes use on the `SkillPermissionDenied` audit row. The audit
  chain records `PhaseEntered` / `PhaseExited` rows with typed
  reasons (`PhaseChange`, `TurnEnd`, `SkillUnloaded`);
  `SkillPermissionDenied` rows whose `denied_reason` is
  `Phase { phase_name }` correlate with the triggering
  `PhaseEntered` for SIEM consumers. Replayed from the session
  log on wake: an active phase survives a crash, a clean exit
  tombstones the overlay. Single-slot invariant: nested phases
  are refused so every `PhaseEntered` pairs cleanly with one
  `PhaseExited`. See `docs/skills.md` for skill-author docs.

## [1.4.0] - 2026-05-12

### Skill loading

- Signature verification wired into `SkillLoader::load_file`.
  `WIRKEN_ALLOW_UNSIGNED_SKILLS` bypass preserved with the same
  install-time semantics, now applied at load.
- `permissions:` optional with a least-privilege default
  (deny-all). Spec-conformant skills load without an explicit
  `permissions` block.
- Name validation: lowercase `a-z` + digits + hyphens, starts
  with a letter, max 64 chars, must match parent directory name.
- Description validation: required, 1 to 1024 characters.
- `metadata.openclaw.*` deprecated alias dropped.
- `skill.wasm` covered by the composite signature scope
  alongside `SKILL.md`.

### Audit forwarder

- Typed-event SIEM forwarder (hybrid path: webhook, Splunk HEC,
  Datadog accept mixed batches at one endpoint; Sentinel takes a
  separate stream by DCR column-pinning constraint).
- Polling seam via `SessionLog::get_since` against
  `session_events`; zero-touch on the typed-event append path.
- `SiemConfig.typed_forwarding_enabled` opt-in; default-off,
  back-compatible with 1.3.0 `siem.json`.
- `audit.chain_broken` routed through the `AuditWriter` mpsc
  channel so the SIEM forwarder receives chain-tamper events.
- `AssistantToolCalls` and `ToolResult` carry `adapter_id` and
  `sender_id` from the active inbound context (additive,
  defaultable).
- `LlmRequest` and `LlmResponse` carry `credential_id` (the
  vault entry name, never the raw secret).

### Permissions

- `Action::SkillInstall` variant removed; install gating remains
  signature verification + `WIRKEN_ALLOW_UNSIGNED_SKILLS`.

### Terminal output

- ANSI/CSI escape sequences stripped from model output before
  `println` at the CLI boundary.
- ANSI/CSI sequences stripped from `exec` captured stdout/stderr
  before the bytes re-enter the model context.

### Tests and infrastructure

- `schema_v1_2.rs` renamed to `schema_v1_3.rs`; test prefix
  convention documented inline.
- `precreate_owner_only` race on concurrent `AuditWriter` +
  `TypedEventForwarder` open resolved.

### Notes

- No wire-breaking changes against 1.3.x readers. Every new
  field is additive with serde defaults; readers that do not
  expect the new fields ignore them.
- `credential_id` on `LlmRequest` and `LlmResponse` was added in
  the same release as its plumbing; pre-1.4.0 audit databases
  remain readable.
- OCSF projection at the forwarder boundary deferred to a
  future release.

## [1.3.0] - 2026-05-11

### Audit schema

Audit schema 1.3.0; identity correlation, field renames, webhook
HMAC. Pre-1.3.0 audit databases remain readable; chain verification
hashes the stored payload bytes, not a re-serialized event.

**Schema-breaking**

- `AuditEvent.actor` split into `actor_kind: ActorKind` (`User` /
  `Agent` / `Service`) and `actor_id: String`. `channel` and
  `session` become `Option<String>`. A custom deserializer accepts
  the pre-1.3.0 single-`actor` shape; known service literals
  (`gateway`, `orchestrator`, `audit`, `webchat-user`) classify as
  `Service`, everything else as `User`.
- `LlmResponse.tokens_in` / `tokens_out` renamed to `input_tokens` /
  `output_tokens`. No alias; see notes.
- `HttpFetch.outcome: String` replaced with the `HttpFetchOutcome`
  enum (`Success` / `EgressDenied` / `RateLimited` / `HttpError` /
  `NetworkError`); the HTTP status code moves to a sibling
  `http_status_code: Option<u16>` field.
- `CandidateScored.matched_keywords` is now `Vec<String>` (was a
  JSON-encoded string).
- `SubagentResult.status: String` replaced with the `SubagentStatus`
  enum (`Ok` / `Error` / `RoundsExceeded` / `DepthExceeded` /
  `Timeout`).
- `ChainHead.signing_key_id` renamed to `signing_pubkey`.
- `PermissionDenied` gains `denial_source: DenialSource` (`Tier` /
  `OrgPolicy`); `tier` becomes `Option<String>` populated only for
  tier-source denials. The pre-1.3.0 `"tier":"org_policy"` sentinel
  is retired.
- `AuditEvent.target` no longer carries inbound/outbound message
  bodies. The body moves to `detail.content`; `target` becomes a
  stable resource id (`<channel>:<platform-msg-id>` for inbound,
  `<channel>:out:<uuid>` for outbound).
- `SessionEvent::DigestPushed` and `SessionEvent::SandboxProvisioned`
  removed; neither had a producer.

**Schema-additive**

- `UserMessage` gains `adapter_id: Option<String>` and
  `sender_id: Option<String>`; populated by adapter-driven and
  webchat-driven callers, `None` for CLI / cron / subagent paths.
  New `wirken_agent::InboundContext` carries the pair; new
  `Agent::process_inbound` and `Agent::process_message_stream_with`
  accept it.
- `AssistantMessage`, `AssistantToolCalls`, `ToolResult`,
  `LlmRequest`, `LlmResponse`, `SystemPromptSet` gain
  `agent_id: String`.
- `HttpFetch` gains `agent_id: Option<String>` and
  `skill_name: Option<String>`; the zirkel orchestrator threads both
  through `OrchestratorConfig`.
- `Compaction` gains `agent_id: String`, `provider: Option<String>`,
  `model: Option<String>`. `ContextEngine::fit()` now takes the
  agent id.
- `adapter.connect` and `adapter.disconnect` legacy-audit events
  carry `detail.adapter_pubkey_fingerprint` (first 16 hex chars of
  the handshake key).

**Infrastructure**

- Webhook SIEM target adds `X-Wirken-Signature: sha256=<hex>` when
  `siem.json.hmac_secret` is set. HMAC-SHA-256 over the exact
  serialized request body bytes.
- `wirken_gateway::permissions::Action` gains a `Display` impl
  emitting stable snake_case labels; the audit event for a denied
  tool now records the label plus the canonical `approval_key`
  instead of the debug shape.
- New pure builders `build_datadog_payload`, `build_splunk_body`,
  `build_sentinel_payload`, `build_webhook_request`, and
  `compute_webhook_signature` exposed from `wirken_audit::siem` so
  the SIEM wire envelopes are assertable without an HTTP server.
- Wire-format regression suite at `crates/audit/tests/schema_v1_3.rs`
  covers every changed variant: pre-1.3.0 row deserialisation,
  presence of new fields, absence of removed fields, and HMAC over
  the exact body bytes.

**Notes**

- `LlmRequest.credential_id` / `LlmResponse.credential_id` (the
  vault-entry-name correlation originally specified for this PR) is
  deferred. Threading the entry name requires changes to
  `AgentStaticConfig`, `ChannelOverride`, `Agent`, and the
  `wirken ask` / factory constructors; tracked separately so the
  schema work and the credential-plumbing work stay reviewable in
  isolation.
- `LlmResponse.input_tokens` and `output_tokens` carry
  `#[serde(default)]`. A pre-1.3.0 row carrying `tokens_in` /
  `tokens_out` deserializes to zero rather than failing; the legacy
  values are silently dropped. There is no serde alias by design.
  The regression fixture
  (`pre_1_2_0_llm_response_drops_renamed_token_fields_to_zero`)
  pins this so a future revert that re-introduces the alias fails
  the suite.

## [1.2.0] - 2026-05-07

### Skill loader

- New `wirken skills migrate [path] [--dry-run]` subcommand.
  Renames `metadata.openclaw` to `metadata.wirken` when the
  `wirken` key is absent. Appends a deny-everything `permissions:`
  block when the top-level block is missing. Each rewrite is
  preceded by a copy to `SKILL.md.pre-migrate-<UTC>`. The rewrite
  is a `serde_yaml::Value` round-trip so unknown frontmatter keys
  are preserved (YAML comments are not). Default scan path is
  `<data_dir>/skills/`. `--dry-run` reports changes without
  writing.

- `SkillLoader::load_dir` per-skill load failures log at `debug!`;
  a single aggregate `warn!` fires per directory listing the
  failed skill names and pointing at
  `RUST_LOG=wirken_agent::skill=debug` for per-skill detail. The
  `openclaw` deprecated-metadata-key warning fires once per
  process via a `OnceLock` gate (`2d35f63`).

### Agent runtime

- Tinfoil provider arm now dispatches through the
  [tinfoil-rs SDK](https://github.com/tinfoilsh/tinfoil-rs) instead
  of treating `inference.tinfoil.sh/v1` as a generic OpenAI-compat
  endpoint. Each session gates on the SDK's three-step verification
  (AMD SEV-SNP hardware attestation, Sigstore code-provenance check
  against the published enclave repo, measurement comparison), and
  chat traffic flows over a `reqwest::Client` pinned to the attested
  TLS certificate. The verified client is cached for the gateway's
  process lifetime; the first inbound message after start pays the
  attestation cost (one-time per process), subsequent calls reuse
  the pinned transport. Connect-level errors (TLS-pinning rejection,
  cert rotation) drop the cache so the next call re-attests against
  fresh attestation material. Tool calling supported; streaming and
  the `chat_relaxed` vendor-extension escape hatch are deferred.
  `LlmConfig::tinfoil` now sets `provider: "tinfoil"`; the
  `wirken setup` Tinfoil arm stores the API key under
  `tinfoil-api-key` and writes `provider: "tinfoil"` to
  `provider.json`. Operators upgrading from 1.1.0 must re-run
  `wirken setup` for the Tinfoil arm: the prior version stored the
  key under `openai-api-key` and routed through the OpenAI-compat
  shim, which never reached the new dispatch. See
  [docs/reference/tinfoil.md](docs/reference/tinfoil.md) for the
  trust model and deployment recipe (`597e4a1`).

### Dependencies

- `tokio-tungstenite` 0.28.0 to 0.29.0 (#100). Pulled in via slack-morphism;
  the upstream tungstenite 0.29 release is two changes (MSRV bump to 1.71
  and header values can include non-visible ASCII) with no API breaks
  and no behavioral changes in the WSS handshake path
  adapter-slack uses (`4b08347`).

- Added `tinfoil = { git = "https://github.com/tinfoilsh/tinfoil-rs",
  tag = "v0.0.4" }` to the agent crate. Crate is git-only; no
  crates.io publication exists yet. AGPL-3.0; carve-out lives in
  `deny.toml` scoped to the `tinfoil` crate. Workspace
  `[patch."https://github.com/tinfoilsh/tinfoil-rs"]` redirects to
  a fork branch that drops the `time = "<0.3.46"` upper bound while
  upstream PR <https://github.com/tinfoilsh/tinfoil-rs/pull/19> is
  pending; the patch comes out and the original tag pin is restored
  when upstream merges.

## [1.1.0] - 2026-05-07

Minor bump. Audit gains per-gateway chain-head signing. Lyrik gains
concurrent walk dispatch with per-walk dedup against a single signed
session. Zirkel gains perspective-guided query expansion, on by
default at the CLI surface. The session-log wire format gains new
variants and optional fields, all forward-compat under the existing
serde envelope.

### Audit

- Chain-head signing wired through the session log. New
  `SessionEvent::ChainHead` variant carries the sequence range,
  prev and current chain hashes, an Ed25519 signature, and the
  hex-encoded signing public key. Signatures bind the
  schema-version-1 layout under the `wirken/audit-chain-head/v1`
  domain. A per-gateway Ed25519 identity lives at
  `<data_dir>/audit/audit-signing.{key,pub}` (mode 0600 on Unix);
  it is distinct from the IPC handshake keypair and the per-agent
  attestation identity so a compromise of one does not invalidate
  the others. `SqliteSessionLog::open_with_signer` writes a
  `SessionStart` head on the first append to a fresh session and
  a `Checkpoint` head every 1000 appends or 5 minutes of
  wall-clock since the last head, whichever comes first. The
  gateway emits an explicit `SessionEnd` head on graceful
  shutdown via `emit_chain_head(SessionEnd)`. Callers without a
  signer write no head rows; existing logs accumulated before
  signing land as transition-era and continue to verify under the
  default `verify` (`5101a6b`).

- Verification surface and CLI flag. `SqliteSessionLog::verify_signatures`
  walks every `ChainHead` row in a session and checks four
  properties: schema version matches the verifier, claimed
  `current_chain_hash` matches the stored hash at
  `sequence_range_end`, claimed `prev_chain_hash` matches the
  stored hash at `sequence_range_start - 1`, and the embedded
  Ed25519 signature verifies under the embedded `signing_key_id`.
  Two new `VerifyResult` variants: `SignatureInvalid` (always
  hard fail) and `MissingChainHead` (hard fail under
  `--require-signed`). `wirken audit verify` takes
  `--require-signed`. Without it, sessions that have zero
  `ChainHead` rows are counted as transition-era and verify
  exits zero; with it, sessions missing heads hard-fail. Invalid
  signatures are always hard fail. JSON output `schema_version`
  bumps to 2 and adds `signed_heads_count`, `unsigned_heads_count`,
  `invalid_signatures_count`, `signing_key_ids_seen`,
  `sessions_with_no_signed_heads`, `unsigned_tail_max_len`
  (`afad069`).

- `docs/enforcement-model.md` describes what chain-head signing
  protects against (a writer rewriting history, storage tampering)
  and what it does not (a malicious gateway signing a fabricated
  chain in real time is not detectable from the signature alone).
  `docs/audit-cli.md` documents the v2 schema fields, the two new
  result values, and the `--require-signed` flag (`b5f8365`).

### Lyrik

- Per-walk dispatch. `walks: [...]` in `.lyrik/config.json` opts
  a run into per-walk operation. The validator runs at parse
  time: each named walk must appear in the canonical
  `KNOWN_WALKS` set and each must exist as
  `~/.claude/skills/<walk>/SKILL.md`. Empty arrays, unknown
  names, and missing skill files all hard-fail before any LLM
  call. Walk skills are operator-installed in the Claude-style
  tree without a wirken permissions block, so the runner stages
  them at `<run-dir>/walks-skills/<walk>/SKILL.md` with
  synthesized wirken-shaped frontmatter wrapping the original
  body; the agent loads them via the new `Agent::extend_skills`
  surface so `/<walk-name>` becomes a first-class slash
  invocation alongside `/lyrik`. `walks: []` and the absence of
  the field both retain the legacy single-call behaviour
  (`9b16da0`).

- Concurrent walk dispatch. `dispatch_walks_concurrent` replaces
  the serial baseline. Each selected walk constructs its own
  `Agent` (separate LLM conversation, separate tool state)
  inside a `tokio::spawn` task gated by a `Semaphore` with
  `max_concurrent_walks` permits (default 4, parse-rejected at
  zero). Every Agent shares the same `agent_id`, which is the
  `SessionLog` `session_id`, so all walks land in one signed
  chain even though they run as N concurrent appenders;
  rusqlite's interior connection mutex serializes writers, so
  concurrent appends interleave at the seq level without
  breaking the chain. The Lyrik runner now opens the session log
  via `SqliteSessionLog::open_with_signer` against the gateway's
  audit signing key (`load_or_create` at
  `<data_dir>/audit/audit-signing.key`); a key load failure logs
  a warn and runs unsigned. After dispatch and aggregation the
  runner emits an explicit `SessionEnd` `ChainHead` so the chain
  caps on a signature rather than the last walk's tool result.
  Exit-code policy: any walk that hit a permission denial routes
  the run to non-zero (operator intent, not a transient
  failure), even when other walks succeeded; all walks failing
  transient is also non-zero; at least one success and zero
  denials returns zero. Permission denial does not skip
  aggregation; the dedup pass writes whatever the run produced
  (`bbef112`).

- Dedup pass on per-walk findings. `aggregate_findings_multi`
  takes `(walk_name, source_dir)` pairs and runs a dedup pass
  when per-walk dispatch is active. Findings sharing
  `(location.file, location.line_start)` collapse into one
  merged record per location. On collision: framings union to a
  sorted unique set, tier rises to the highest of the inputs
  (`CRITICAL > HIGH > MEDIUM > LOW > INFO`),
  `dedup_disagreement: true` when input tiers differ, and
  `dedup_sources` lists each contributing walk in first-seen
  order so a reviewer can trace which walks surfaced a given
  finding. A solo finding from a known walk also gets a
  single-element `dedup_sources` for traceability. Findings
  without a usable location key (missing file or line_start)
  pass through unchanged so a malformed input does not collide
  with everything else under a shared default key. The one-call
  path keeps verbatim concatenation so legacy operators see the
  pre-walk behaviour (`c223b42`, `c32bf67`).

- `docs/lyrik.md` covers the `walks` and `max_concurrent_walks`
  schema, the validator's parse-time hard fails, the dispatch
  shape, the dedup contract, and the exit-code rules
  (`2f14ac1`).

### Zirkel

- Perspective-guided query expansion (front-half of Stanford
  STORM, retrieval-only; the librarian remains
  retrieval-only and the LLM produces perspective labels, never
  user-facing prose). Given a topic, the librarian runs a
  Wikipedia opensearch for related titles, fetches section
  headings via the MediaWiki Action API, and makes a single
  structured-output LLM call to a new
  `zirkel_emit_perspectives` synthetic tool that returns short
  noun-phrase perspective labels grounded in those headings.
  The orchestrator then dispatches the existing retriever path
  once per label via synthetic `SourceConfig`s through the
  existing `FetcherRegistry` (no manifest extension, no registry
  surface change). Synthetic source names carry a `::p=<slug>`
  suffix so the candidates table groups by perspective on read.
  Labels are ephemeral: they live in `run()` scope and the audit
  chain only and are not persisted past the turn. Slug-collision
  dedup runs over the LLM output before any `SourceConfig` is
  built; first occurrence wins, later collisions drop. Pre-flight
  cap (`max_perspectives * sources <= per_topic_fanout_cap`)
  rejects over-budget expansions before any HTTP goes out
  (`6609d62`, `b4b2af3`).

- Audit-chain plumbing for the expansion turn.
  `SessionEvent::PerspectiveExpansion` records the run id, the
  topic, the emitted perspective labels, a fresh `expansion_id`
  UUID, and any labels dropped for slug collision.
  `SessionEvent::PerspectiveSkipped` is the sibling variant
  emitted on the over-budget cap path with a stable snake_case
  `reason` (today: `"over_budget"`). `HttpFetch` and
  `CandidateScored` gain an optional
  `expansion_id: Option<String>` with `serde(default,
  skip_serializing_if = "Option::is_none")`; rows written under
  `perspectives_enabled = false` serialize byte-identical to a
  pre-perspective build. The expansion id threads through every
  fetch and candidate event the turn caused, so a downstream
  auditor reconstructs the turn rather than seeing one event
  hide the fan-out (`6609d62`, `6ba18a4`).

- Default flipped at the CLI surface.
  `perspectives_enabled` defaults to `true` in
  `crates/cli/src/commands/zirkel.rs`. With `topic` unset and
  the cap params at zero, `build_perspective_passes` treats the
  planned fan-out as a skip and falls through to the default
  fetch loop; no `PerspectiveExpansion`, no
  `PerspectiveSkipped`, and no `expansion_id` field on any
  audit row. The flag flip is the predicate for the follow-up
  that surfaces topic + cap configuration to the operator
  (`2c6f703`).

### Agent runtime

- Subagent tier-clamp regression pinned. The
  `auto_deny_above_tier` ceiling overrides per-agent approval,
  the clamp is parent-defined per child `agent_id` rather than
  inherited from caller state, and Tier 3 actions are denied
  even when the clamp is set to Tier 2 (`d2b07f6`).

### Gateway

- Workspace `.env` cannot steer `GatewayConfig`. Three checks:
  no dotenv-shaped crate in `Cargo.lock`, no source line calls a
  dotenv reader, and a behavioural cross-check that planting a
  `.env` in cwd does not influence `GatewayConfig::default()`.
  Maps to the qclawer-credited cluster against OpenClaw
  (CVE-2026-43531 and the GHSA shapes around `.env` overriding
  hooks root, runtime control vars, connector hosts, and MiniMax
  host) (`0b9d016`).

- Per-sender scope isolation pinned. No per-sender context
  exists; permissions are agent-scoped via `canonical_agent_id`.
  The injection detector's tag-not-block contract is pinned in
  the same module (`5f6266b`).

### IPC

- No payload field can reroute inbound frames. Schema-level
  guard against future `host` / `target` / `route` / `sandbox`
  fields, a field-set pin on `InboundMessage` so a
  routing-relevant addition has to update the test alongside the
  schema, and an end-to-end build of a forged-channel frame
  confirms `AuthenticatedChannel::require_match` rejects it.
  Maps to CVE-2026-42434 (sandbox escape via `host=node`) and
  the device-pairing scope-skip GHSA cluster (`6039450`).

### Adapters

- Slack thread mention-gate pinned. Mixed-sender thread
  regression: only the bot-mentioning message in a thread
  reaches the gateway; non-mentioning content from other senders
  is dropped at the adapter and never enters the model context.
  Maps to CVE-2026-41358 (Slack thread sender allowlist bypass),
  CVE-2026-43535 (collect-mode context reuse), and the GHSA
  cluster around subagent fallback synthetic admin and ACP child
  envelope inheritance (`3a6b7b9`).

### MCP-proxy

- `SAFE_ENV_PASSTHROUGH` contents pinned against silent
  expansion. The previous test iterated the constant, so a new
  key would have silently received pass-through coverage. The
  contents-equality test forces additions to update the test in
  the same commit and argue for the new key in review
  (`f51ba29`).

### Skills docs

- `disable-model-invocation` documented in the skill frontmatter
  table with its default-true posture. New "Auto-invocation vs
  explicit invocation" section spells out the contract: skills
  are explicit-only by default, auto-firing requires
  `disable-model-invocation: false` in frontmatter, the slash
  interceptor matches `^/<name>(\s|$)` strictly, and an unknown
  slash invocation rejects loudly rather than falling through to
  the LLM as plain text (`533c5e7`).

### Tooling

- Pre-commit hook scans for filename and `.gitignore` leaks; the
  commit-msg attribution-pattern rejection list is extended
  (`86f7026`).

### Dependencies

- `openssl` 0.10.78 to 0.10.79 (#104) closes GHSA-xp3w-r5p5-63rr,
  a high-severity rust-openssl undefined-behaviour bug in
  `X509Ref::ocsp_responders` for certificates with non-UTF-8 OCSP
  URLs.
- `windows-sys` 0.52.0 to 0.61.2 (#102). The 0.61 line changes
  `HANDLE` and `HLOCAL` from `isize` / `usize` to `*mut c_void`;
  the named-pipe peer-credential check in `crates/ipc/src/stream.rs`
  is ported to pointer-shaped semantics (`is_null` checks,
  `ptr::null_mut` initializers, dropped redundant `isize` casts).
  Windows-only path; the unix-domain-socket path is unchanged.
- `clap` 4.6.0 to 4.6.1 (#99), `libc` 0.2.183 to 0.2.186 (#101),
  `clap_derive` 4.6.0 to 4.6.1, `openssl-sys` 0.9.114 to 0.9.115
  (transitive on the openssl bump). Patch within range.
- `github/codeql-action` 4.35.2 to 4.35.3 (#98) in the scorecard
  workflow.
- `tokio-tungstenite` 0.28.0 to 0.29.0 (#100) deferred to the next
  release cycle for one-cycle soak; the upstream changelog is just
  "update tungstenite to 0.29.0" and the substantive breaking
  surface in tungstenite 0.29 has not been read yet.

## [1.0.2] — 2026-05-04

### Agent runtime

- 429 backoff with jitter on `LlmClient`; max 5 retries, honors `Retry-After`. Tool-validation errors return a synthetic non-success `ToolResult` to the agent; max 3 retries per tool name per turn. `RecoveryObserver` trait surfaces both behaviors. New `AgentError::RateLimitExhausted` on exhaustion.

### Lyrik

- findings.json, `.lyrik/context.md`, and `.lyrik/rubric.md` are emitted as per-section staged writes under `<run-dir>/staging/findings/`, `staging/context/`, and `staging/rubric/`; the runner aggregates and removes the staging dirs.

- Skill activates two framings (`auth`, `injection`) selected by recon. Two-pass scoring with axes `real_bug`, `reachable`, `attacker_reach`, `blast_radius`, plus an inline 5-tier rubric. `scoring_disagreement: true` when passes diverge by more than one step on any axis.

- Recon mandatory before emission: the path cited in `location.file` must be one the agent opened in the turn.

### Provider configuration

- Default `base_url` per provider when `phases.<phase>.base_url` is unset: `openai`, `anthropic`, `gemini`, `ollama`, `tinfoil`, `privatemode`. `bedrock` still requires `region`.

- Ollama dispatch uses native `/api/chat` and sends `options.num_ctx`. Default ollama `context_window` bumped from 8192 to 32768. Optional `phases.<phase>.context_window` override in lyrik config.

- Ollama `tool_calls[].function.arguments` is sent as a JSON object (the native shape), not a JSON-encoded string.

### Fixed

- `wirken --version` reports the actual built version. The v1.0.1 binaries reported `1.0.0` because Cargo.toml was not bumped before tagging.

- wirken-zirkel orchestrator e2e mock now serves both `/v1/chat/completions` and `/api/chat` so the ollama-native dispatch path resolves under the test (`d14dc5a`).

## [1.0.1] — 2026-05-03

### Audit

- LLM-response events in the session log now carry token-usage
  metadata. `SessionEvent::LlmResponse` records `tokens_in`,
  `tokens_out`, plus two new optional fields
  `cache_creation_input_tokens` and `cache_read_input_tokens`
  (anthropic prompt-cache fills only). Each provider's
  non-streaming completion path extracts the usage block from the
  HTTP response: anthropic from `usage.{input_tokens,
  output_tokens, cache_creation_input_tokens,
  cache_read_input_tokens}`, OpenAI-compat from
  `usage.{prompt_tokens, completion_tokens}`, gemini from
  `usageMetadata.{promptTokenCount, candidatesTokenCount}`,
  bedrock from `usage.{inputTokens, outputTokens}`. Endpoints that
  do not populate a usage block — including the ollama
  OpenAI-compat path — record zeros and do not error. Old logs
  written before this change continue to deserialize cleanly; the
  cache fields default to zero. The streaming dispatch does not
  yet capture usage and writes zeros; bench mode and
  economics-reporting runs must use the non-streaming path until
  the `wirken-streaming-token-usage` follow-up ships (see
  `skills/lyrik/FOLLOWUPS.md` §5). This closes the gap surfaced by
  run-005 against the canonical AVB pin where the session log
  recorded `tokens_in: 0, tokens_out: 0` for every anthropic
  response.

### Lyrik

- The findings.json shape Lyrik runs emit is now pinned. The skill
  prompt requires `schema_version: "1.0"` at the top level, a flat
  `findings` array (stream membership lives on each finding under
  `stream`), an object-shaped `location`, and uppercase `tier`
  values (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`). The
  full schema lives in `lyrik-bench/avb/SCHEMA.md`; the skill
  references it and shows a worked example. Run-005 was caught
  emitting a nested `findings: {novel/regression/gate_routed}`
  shape with string-form locations and capitalized severity
  strings; the SARIF emitter expects the canonical shape and
  failed to deserialize. Pinning closes that gap. The emitter is
  unchanged in this slice — it already accepted the canonical
  shape — and now dispatches on `schema_version` for future
  schema bumps.

### Security

- Vault no longer silently seals under empty passphrase. Setup
  commands now fail-closed when stdin is not a TTY and
  `WIRKEN_VAULT_PASSPHRASE` is unset, instead of caching an empty
  string. The credential store refuses to initialize a keychain
  under an empty passphrase. The auto-create branch in
  `CredentialStore::open` is narrowed to only the
  keychain-not-initialized case, surfacing other errors instead of
  masking them with a silent re-seal. Found via Lyrik dogfooding
  during slice 7b2.5b bench validation.

- Lyrik core runs now cap findings at grade 0.5. Grade 1.0
  requires evidence at rung 7 (`crash_reproduced`) or higher,
  which only the optional sandboxed exploit adapter produces. A
  core run that emits grade 1.0 without an adapter artifact
  (`exploit_artifact` field) is a finding-shape error; the grade
  is corrected at report-render time and the rationale is
  preserved so the operator can see what the model claimed vs
  what it could actually defend. Found in run-005 against the
  canonical AVB pin: claude-sonnet-4 emitted "PoC succeeded —
  arbitrary code execution confirmed" rationales on three
  findings without ever running a PoC, because the rationale is
  text and the model's training favors decisive language. The
  grade field is the load-bearing column and now caps to what the
  run can actually defend.

### Fixed

- Binary version string read 1.0.0 in the v1.0.1 release
  artifacts. Cargo.toml package version was not bumped before
  tagging. Corrected in subsequent builds. The released v1.0.1
  binaries and signatures are immutable; users running
  `wirken --version` against the released artifacts will see
  1.0.0 until they upgrade past the next release.

## 1.0.0 — Windows 11; audit CLI user-grade; cross-platform IPC trait surface

The cross-platform release. Wirken now ships a native Windows 11 binary alongside the existing Linux and macOS builds. The audit CLI is user-grade across all three platforms: structured JSON output, citable session IDs, schema versioning, the verify command emits typed failure data. The IPC layer is now expressed as the `wirken_ipc::Stream` and `wirken_ipc::Listener` trait surface; production code talks through the trait, with unix-domain sockets on Linux/macOS and named pipes on Windows behind it.

This is the first release with semver stability commitments. The surfaces called out in [docs/audit-cli.md](docs/audit-cli.md) (`schema_version: 1` JSON shape, `wirken_version` field, session-ID format, `Principal` tagged-string form), in [docs/architecture.md](docs/architecture.md) (the `wirken_ipc` trait surface), and in [docs/cli.md](docs/cli.md) (the command-line surface) are stable within 1.x. Additive changes (new fields, new optional flags, new subcommands) are non-breaking; field removals or shape changes bump the major.

### Windows 11 support

- **Native `wirken-x86_64-pc-windows-msvc.exe`.** Single binary, no installer dependencies beyond Cap'n Proto at build time. Ships in the same release artifacts as the Linux and macOS builds (`b886984`, `a718eaf`). See [docs/windows.md](docs/windows.md) for the install path, SmartScreen behavior, and the documented feature deltas.
- **Named-pipe IPC with peer-SID enforcement.** The gateway↔adapter and gateway↔mcp-proxy paths use `tokio::net::windows::named_pipe` on Windows behind the same `wirken_ipc::Stream` interface as unix-domain sockets on Linux/macOS. Peer identity at accept time goes through `GetNamedPipeClientProcessId` → `OpenProcessToken` → `GetTokenInformation(TokenUser)` → `ConvertSidToStringSidW`, returning a `Principal::Sid("S-1-5-21-...")`. The check happens in gateway code (audit-witnessable), not at the named-pipe DACL level. See [docs/enforcement-model.md §Orchestrator Push Peer-Credential Check](docs/enforcement-model.md) for the cross-platform principal model. (`9fcde27`, `e88dc22`, `5d7f2c3`)
- **`exec.shell` config knob.** When `sandbox.json` is set to `mode: off` on any platform, the host-exec fallback resolves a shell at gateway startup. Auto-detect order: `sh` → `powershell` → `cmd`. Operators on Windows who install Git for Windows get POSIX-shell semantics for cross-platform skill portability without configuration. The resolved shell is logged at gateway startup. (`d09c106`)
- **Documented platform deltas on Windows:** Signal adapter, `wirken zirkel push` (orchestrator-push API), the `wirken service` installer, and `wirken cron` preset installer are Linux/macOS only at compile time. Vault uses the age-encrypted-file backend (native Credential Manager / DPAPI on the roadmap). The Windows binary is unsigned; SmartScreen warns on first run. ([docs/windows.md](docs/windows.md))
- **CI matrix extended.** A `windows-smoke.yml` workflow exercises the named-pipe Stream impl on every push to main; `release.yml` builds the Windows .exe on every release tag.

### Audit CLI user-grade across all platforms

The audit log was always hash-chained, but the CLI surface was developer-debug shape. This release makes it citable in research and scriptable in compliance pipelines.

- **`wirken audit log` flags.** New flags: `--session <id>`, `--actor <name>`, `--since <iso8601>`, `--until <iso8601>`, `--format human|json`. The underlying `AuditQuery` already supported actor/since/until; this exposes them at the CLI. When `--session <id>` is provided, human output prints a structured session header decomposing the `{agent}/{channel}/{id}` form. (`5273efa`)
- **JSON schema with versioning.** Both `wirken audit log --format json` and `wirken audit verify --format json` emit a top-level `schema_version: 1` and `wirken_version` field. Session IDs in JSON are objects (`full`, `agent`, `channel`, `id`) — `full` is the canonical round-trippable form, the decomposed fields are convenience. Unknown future fields may be added; consumers should ignore them. ([docs/audit-cli.md](docs/audit-cli.md))
- **`VerifyResult::Broken` restructured.** The variant now carries typed fields: `session_id: SessionId`, `seq: u64`, `expected_hash: String`, `actual_hash: String`, `verified_count: u64`. Replaces the prior free-form `(row_id, expected, found)` shape. `wirken audit verify` failure output names the session, the seq, the verified-count up to the break, and exits 1. (`c233199`)
- **Per-session chains documented.** The verify pass walks every session's chain independently; a break in one session is reported with the verified count summed across complete sessions plus the per-session count up to the break.

### IPC trait surface and production migration

- **`wirken_ipc::Stream` and `wirken_ipc::Listener`.** New trait surface. `Stream` composes `AsyncRead + AsyncWrite + Send + Unpin` plus `peer_principal() -> Result<Principal, IpcError>`; `Listener` is async-trait with an `accept() -> BoxStream` method. Implementations for `tokio::net::UnixStream`/`UnixListener` on unix and the named-pipe types on windows live in the IPC crate. (`3ca3f3c`, `9fcde27`)
- **`wirken_ipc::bind(path)` and `connect(path)` helpers.** Path-based listener and client construction; on Windows the path is mapped to a deterministic pipe name (last-segment + 16-hex-digit hash of full path) so multiple gateways with different data dirs don't collide.
- **Generic `FrameReader<R>` and `FrameWriter<W>`.** The capnp framing layer is now generic over `AsyncRead + Unpin` / `AsyncWrite + Unpin`. Production code uses the `IpcFrameReader` / `IpcFrameWriter` aliases over `ReadHalf<BoxStream>` / `WriteHalf<BoxStream>`. (`b886984`)
- **All ten channel adapters migrated.** The gateway accept loop, mcp-proxy server, outbound dispatcher, and `McpProxyClient` all use the trait surface. Tests stay unix-only; the windows-smoke workflow proves the named-pipe path on every CI run.

### Orchestrator-push audit reconciliation

- **Refused pushes are now witnessed by the audit log.** Prior behavior: cross-uid push refusals on the orchestrator socket emitted a `tracing::warn!` line that was not recorded in the hash-chained log. New behavior: every refusal emits an `orchestrator.push.refused` audit event with structured detail (`reason`, `expected`, `actual`, plus `error` for the unavailable-credential case). Two reason variants today: `principal_mismatch` and `peer_principal_unavailable`. Closes the existing tracing-only gap on Linux/macOS and applies the same shape on Windows. (`5d7f2c3`)
- **Peer-identity check expressed as `Stream::peer_principal()`.** The orchestrator accept loop in `wirken-cli` uses the trait method instead of the direct `peer_cred()` call; the result is a `Principal` enum that displays as `uid:N` on unix and `sid:S-1-5-...` on windows. The audit event detail uses the tagged-string form so consumers parse one schema regardless of platform.

### File-permission posture

- **Operator-visible warning on platforms without 0o600.** Vault device key writes, agent identity-key writes, and skill-signing-key writes emit a `tracing::warn!` on platforms (Windows, primarily) where the unix `chmod 0o600` step is unavailable. The keys rely on user-profile isolation of the data directory for confidentiality. Native ACL-on-write is on the roadmap. (`556b4c1`)

### Other

- **Gateway session-ID format normalized to UUID.** The gateway's `generate_session_id()` previously emitted 32-char hex from `rand::rng().fill_bytes`; now it emits `Uuid::new_v4().to_string()` for visual consistency with zirkel-issued session IDs. Existing audit-log entries under hex IDs remain queryable as opaque strings — the change is forward-only. (`9b42217`)
- **Dependency bumps.** `reqwest` 0.13.2 → 0.13.3 (#90), `slack-morphism` 2.19.0 → 2.20.0 (#91), `open` 5.3.3 → 5.3.4 (#92), `lru` 0.16.3 → 0.18.0 (#94, validated against the agent-factory cache). `cap-std` 4.x bump (#93) deferred — pinned by `wasmtime-wasi 43.0.1`.

### Not committed in 1.0 — explicit roadmap items

These are out-of-scope for the tier-2 Windows release and noted here for completeness:

- DPAPI / native Windows Credential Manager vault backend
- Code-signed Windows binary
- Windows service installer (parallel to systemd/launchd)
- gVisor sandbox on Windows (gVisor doesn't run on Windows)
- Signal adapter on Windows (signal-cli's transport is unix-only)

## 0.9.1 — Audit-pass security fixes; doc accuracy

No breaking changes. Five real fixes, all from a single security-audit pass against `437ed2c`. Operators upgrading from 0.9.0 should pull this release; the env-passthrough escape closed in `c5337b4` was a real privilege escalation path.

- **mcp-proxy: env-passthrough escape closed** (`c5337b4`). Prior behavior: `wirken-mcp-proxy` reads `WIRKEN_VAULT_PASSPHRASE` on startup (`crates/mcp-proxy/src/runner.rs::open_vault`) and the variable stays in the proxy's environ for the proxy's lifetime. `StdioTransport::spawn` did not call `env_clear()`, so every spawned MCP server inherited the parent's full environ — including the vault passphrase. A compromised MCP server could read it from its own env, open `~/.wirken/vault.db` at the operator UID, and decrypt every credential (provider API keys, adapter Ed25519 secrets, channel tokens). Fix: `StdioTransport::spawn` now calls `env_clear()` first and re-adds only an explicit allowlist (`PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_*`, `TERM`, `TZ`, `TMPDIR`, `XDG_*`) plus the per-MCP `env` from `mcp.json`. Belt-and-suspenders: `open_vault` now removes `WIRKEN_VAULT_PASSPHRASE` from the proxy's environ immediately after `probe_keychain` reads it, so a `/proc/<mcp-proxy-pid>/environ` read by another same-UID process turns up nothing. 7 new tests in `mcp_transport::env_isolation_tests` lock in the property.
- **WebChat: CSRF defence + rate limit** (`2b011c7`). Prior behavior: `POST /api/chat` accepted any request that reached `127.0.0.1:18790` — no `Origin` check, no rate limit. A page the operator visits in the browser could drive the agent unbounded; same-origin policy stops the attacker reading the SSE response, but the agent runs the prompt anyway and bills the operator's API key. Fix: explicit `Origin:` header allowlist matched against `http://127.0.0.1:<port>`, `http://localhost:<port>`, `http://[::1]:<port>` for the bound port (rejects `https://`, non-loopback hosts, and port mismatches; missing Origin allowed for non-browser clients). GCRA rate limit at 60 POSTs / minute via the existing `wirken-gateway::rate_limit::ControlPlaneRateLimiter`. 4 new tests on the Origin matcher.
- **Agent: SSE buffer cap** (`872e0e9`). Prior behavior: `crates/agent/src/llm_stream.rs` accumulated SSE chunks into a `String::new()` buffer until a `\n\n` separator arrived. A hostile or buggy LLM endpoint that sends bytes without separators (intentionally or via a misconfigured proxy) made the buffer grow unbounded → gateway OOM. Real for self-hosted vLLM, relays, and TEE-mediated proxies. Fix: hard cap at 1 MB (two orders of magnitude above any plausible single SSE event); error returned cleanly when exceeded.
- **Vault: dead `unsafe` block deleted** (`b33198b`). `pub fn write_to_fd` (`File::from_raw_fd` + `mem::forget` for an unimplemented "vault export over fd" path) had no callers outside its own test. The only `unsafe` block in `wirken-vault` removed; future fd-write paths must restore the function with the safety contract documented at each call site.
- **docs/architecture.md, docs/mcp.md** (`437ed2c`, `0521ec8`). The architecture doc previously described the agent as running in a separate process from the gateway; the actual layout has them in one address space (`crates/cli/Cargo.toml` pulls `wirken-agent` as a path dep). The `architecture.md` §6 ("Direct LLM calls") now describes the single-process reality and lists subprocess isolation as a future architectural option, not an in-flight roadmap item. `docs/mcp.md` gained a "Trust boundary" section that enumerates what is and is not protected by the existing process topology after the env-isolation fix above.

## 0.9.0 — Channel formatters cohort; Sentinel SIEM; Slack live transport; pipeline-laundering hardening

No breaking config changes. Operators upgrading from 0.8.0 keep their
existing `~/.wirken/` layout; the changes are all additive on the wire
(new formatters, new SIEM target) or hardening on the runtime
(pipeline metacharacters, Slack echo and thread fixes).

- **Per-channel outbound formatters in `adapter-core`** (closes #71).
  Slack (`mrkdwn`: `<url|text>` links, `*bold*` collapse, GFM tables
  flattened), Discord (CommonMark pass-through; only tables flatten,
  `<hr>` collapses), Telegram (HTML mode with bounded escape surface
  `<>&`, single-pass tokenizer that shields markdown markers inside
  inline code from re-tokenization, `<pre><code class="language-…">`
  for fenced blocks), Matrix (`org.matrix.custom.html` with real
  `<h1>`–`<h6>`, native `<ul>`/`<ol>`/`<li>`, real `<table>`,
  `<strong>`/`<em>`/`<del>`, dual-field `body` + `formatted_body` on
  `m.room.message`). Each formatter wired into its adapter's send
  path with a regression-test bar of UTF-8 parity (Devanagari, CJK,
  emoji, smart quotes) plus a full round-trip test. The Telegram
  inline tokenizer is parameterised on a tag set; Matrix reuses it
  with semantic tag pairs.
- **Microsoft Sentinel SIEM target** on the audit forwarder. POST to
  the Logs Ingestion API endpoint (`<dce>/dataCollectionRules/<dcr>/
  streams/Custom-…`) with an Azure-AD bearer token in `api_key`. JSON
  record body uses the Custom-table column convention (`TimeGenerated`,
  `Actor`, `Action`, …) so a DCR transform can map straight into the
  operator's table without renaming. Joins existing Datadog Log
  Intake, Splunk HEC, and generic webhook. Wirken does not refresh
  the bearer token; the operator's responsibility (typically a
  sidecar that rewrites `~/.wirken/siem.json` before expiry).
- **Slack adapter live transport.** Two upstream issues that
  previously blocked any real Slack round-trip, both fixed:
  `slack-morphism 2.19`'s `SlackClientSocketModeListener::listen_for`
  only registers an app token; the WSS handshake comes from
  `start()`/`shutdown()`. The adapter now drives that explicitly,
  with the misleading "connected and listening" log line replaced
  by truthful "WSS connection started" / "shutdown initiated"
  markers. And `slack-morphism`'s `hyper` feature activates
  `tokio-tungstenite/rustls-native-certs` — an optional-dep name in
  `tokio-tungstenite 0.28`, not the feature that activates
  `__rustls-tls`. Workspace feature unification fixes it via a
  feature-only direct dep on `tokio-tungstenite` with
  `features = ["rustls-tls-native-roots"]`. Tungstenite now compiles
  with rustls 0.23 + the patched rustls-webpki 0.103.13.
- **Slack echo loop closed; thread_ts preserved.** The bot's own
  outbound used to come back through `message.im` and re-enter the
  agent as fresh user input, generating an autoresponse, repeating
  indefinitely. The slack-adapter event filter now drops messages
  whose `sender.user` matches `bot.user_id`, whose `sender.bot_id`
  matches `bot.bot_id`, or whose subtype is `bot_message` /
  `message_changed` / `message_deleted` / any of the
  membership/system variants. The conversion lives in
  `convert::from_push_event` so the filter is unit-testable; 14 new
  tests cover each drop case plus the thread_ts pass-through.
  Separately, the gateway dispatcher in `cli/src/commands/run.rs`
  used to set `outbound.reply_to_id = inbound.id` (the inbound's own
  message ts), which auto-threaded every root message off itself.
  It now propagates `inbound.reply_to_id` (the inbound's thread
  root) — empty string for root inbounds, the thread root for
  thread inbounds. Bot replies land in the same thread as the
  question; root messages don't auto-thread.
- **Pipeline-laundering hardening on shell exec** (closes #36). The
  Tier 2 allowlist for shell verbs lets `ls`, `cat`, `pwd`, etc.
  through with first-use approval. Without metacharacter awareness,
  an agent could lead with an allowlisted verb and chain to a
  non-allowlisted one: `echo "rm -rf /" | bash`, `pwd && curl evil`,
  `cat /etc/passwd > /tmp/leak`, multi-line bodies fed to a shell.
  `tool_to_action` now scans the raw command for shell
  metacharacters (`| ; & $( ` `` ` ` `` `> < \n`) before splitting
  on whitespace; any presence forces a sentinel pattern
  (`:pipeline:`) that cannot match the allowlist, landing the
  action on Tier 3.
- **`docs/sandbox-properties.md` and code-anchored RMF mapping.** New
  `docs/sandbox-properties.md` enumerates the three `SandboxMode`
  values, container hardening (`cap_drop=ALL`,
  `no-new-privileges:true`, `readonly_rootfs`, `network_mode=none`,
  512 MB memory, 256 PID, non-root UID, 300 s timeout), Docker
  default seccomp coverage, gVisor (`runsc`) syscall-trap delta,
  and the Wasmtime WASI surface for skills. Every property cites
  the source line that implements it; six verification commands an
  operator can run to confirm each claim. `docs/security-properties.md`
  NIST AI RMF rows now carry file:line citations on every
  implementation reference instead of the previous crate-name-only
  form.

## 0.8.0 — Signal socket transport; adapter-core formatters; audit concurrency

Breaking-on-upgrade for Signal operators: the adapter no longer speaks
HTTP to signal-cli. The daemon must run with `--socket <path>` and the
endpoint stored in the vault must be a filesystem path (or
`unix:///path`). Pre-0.8.0 installs with an `http://` endpoint get a
clear migration error at startup and must re-run `wirken setup` or
`wirken channel add signal`. Every other provider and channel is
unchanged.

- **Signal adapter rewritten to `--socket` JSON-RPC.** signal-cli
  0.14.x's HTTP daemon auto-consumes inbound messages in the
  background and rejects concurrent `receive` RPCs, which broke
  every tick of the previous polling loop with `"Receive command
  cannot be used if messages are already being received."` The
  adapter now calls `subscribeReceive` once and consumes push
  notifications over a Unix socket. Reader-side subscription-id
  interception so no race between subscribe response and first
  notification. Reconnect-with-exponential-backoff around
  connect + subscribe + read_loop. Bounded inbound channel (256)
  for backpressure. Self-echo LRU (1024 entries) keyed on the
  timestamp signal-cli returns from `send` so Signal's
  multi-device mirror does not re-enter the agent as fresh
  inbound. End-to-end test against a fake Unix socket; byte-accurate
  captured envelopes from a real signal-cli 0.14.2 daemon land
  as the authoritative parse fixture.
- **Signal envelope coverage expanded.** `dataMessage.groupV2.id`
  (modern signal-cli) reads before legacy `groupInfo.groupId`.
  `sourceUuid` is surfaced on `SignalInbound` and the allowlist
  accepts UUID entries alongside E.164 phone numbers, so contacts
  using Signal's phone-privacy feature can reach the agent.
  Outbound sends to a group route via the `groupId` RPC param
  instead of always using `recipient` — group replies used to be
  silently rejected by signal-cli.
- **`wirken channel add signal`.** Signal has its own arm that
  collects phone, socket path, and allowlist through the same
  helper the setup wizard uses. Previously it went through the
  generic bot-token prompt and produced a half-populated vault
  state that crashed the adapter at startup.
- **`adapter-core` crate.** Channel-specific outbound formatting
  has a typed home: `OutboundFormatter` trait, `PlainFormatter`
  (explicit pass-through so "no formatter" stops being
  accidental), `SignalFormatter` (renders markdown to Signal's
  `*bold*` / `_italic_` dialect and flattens GFM tables to
  `header: value` per cell). Wired into the signal adapter's
  `send_message`. Slack / Discord / Telegram / Matrix formatters
  are tracked in #71.
- **UTF-8 correctness in cli and formatter.** Three `truncate(&str,
  max)` helpers in `run.rs`, `audit.rs`, `skills.rs` were slicing
  `&s[..max]` on byte offsets, which panics when the offset falls
  inside a multi-byte UTF-8 scalar — `byte index 80 is not a char
  boundary; it is inside 'ा'` crashed the gateway on a Hindi LLM
  reply during live testing. All three walk back to the nearest
  `is_char_boundary` now. `SignalFormatter::replace_links` had the
  same bug (`bytes[i] as char` per non-bracket byte) and now
  copies full codepoints via `&str` slicing.
- **Agent error text no longer leaks to the end user.** When
  `agent.process_message` returned `Err`, the raw error string
  (database paths, session-log locks, provider stack traces) was
  formatted and sent back through whatever channel the sender
  reached us on. Outbound reply is now a generic apology; the
  full error still lands in the operator log and the audit trail.
- **Audit writer serializes concurrent writers.** Two inbound
  messages arriving within seconds of each other produced
  `database error: database is locked` on the session log.
  `SqliteSessionLog::init_schema` now sets `busy_timeout=5000` and
  `synchronous=NORMAL` on every open alongside the existing WAL;
  `append_inner` uses `BEGIN IMMEDIATE` instead of the default
  DEFERRED so the write lock is claimed up front where
  `busy_timeout` applies. Concurrent writers serialize instead of
  erroring. Regression test: 100 concurrent appends across two
  `SqliteSessionLog` instances on the same file, all succeed.
- **AuditWriter connection reuse.** `flush` was reopening the
  SQLite connection on every 50ms tick, paying the full
  pragma + migration cost for nothing. `flush_loop` now opens
  once at startup and threads the `Arc<AuditLog>` through.
- **`wirken sessions list` / `verify` id mapping.** `list` prints
  both the `STORE ID` (hex primary key in `sessions.db`) and the
  `LOG ID` (composite `{agent}/{channel}/{conversation}` keyed by
  the audit log). Operators copying either into the right command
  works; previously the hex id from `list` produced `No events for
  session …` on `verify`. `verify` also translates a bare hex id
  to the composite via a SessionStore lookup, so pre-0.8.0 scripts
  that passed the `list` output keep working.
- **Privatemode reference doc rewritten.** `docs/reference/privatemode.md`
  drops the `_Target_` sections describing work that was never
  built (packaged `deploy/privatemode/` sidecar recipes, direct
  proxy sidecar spawning, an Anthropic-shape provider switch). The
  doc now describes only what works on the current binary.
  Tracking issue #57 closed; remaining CI-stub work relocated to #72.

## 0.7.8 — Setup-time vault corruption fix; credential CLI gaps

Headline is a setup-time data-loss bug: every multi-step channel setup
(signal, slack, teams, matrix, imessage, whatsapp) reopened the
keychain with an empty-passphrase fallback after the first real prompt,
which silently re-keyed the AgeFile keychain and made every row written
under the original passphrase undecryptable. User-visible symptom was
`aead::Error` at `wirken run` time complaining the channel token would
not decrypt.

- **Setup-time vault corruption (cli).** Each `probe_keychain(data,
  String::new)` after `register_channel` constructed an `AgeFileKeychain`
  with an empty passphrase. `CredentialStore::open` then fell into its
  "first run" branch, generated a fresh device key, and overwrote the
  keychain file with that key under empty passphrase — orphaning the
  rows from the first open. Same pattern bit `register_channel`, the
  org-config arm, `store_key_and_pick_model` (cloud providers), the AWS
  Bedrock arm, and `configure_channel_overrides` from #68. New
  `cached_vault_passphrase()` helper prompts once per process and
  stashes the result in `WIRKEN_VAULT_PASSPHRASE` (the env var
  `wirken run` already propagates to spawned adapters), so every
  keychain open in the same invocation derives the same wrapping key.
- **`CredentialStore::open` hardened (vault).** Previously any
  `retrieve_device_key` failure was treated as "first run" and triggered
  an auto-generate-and-overwrite. `open` now distinguishes
  `VaultError::Decryption` (existing keychain that will not unwrap —
  hard error) from other errors (no keychain yet — auto-generate).
  Defense in depth: even if a future call site reintroduces a
  passphrase-mismatch open, the vault layer surfaces it instead of
  silently corrupting.
- **`wirken credentials remove <name>` (cli).** New subcommand. The
  vault layer already exposed `CredentialStore::delete`; only the CLI
  was missing. Errors with `VaultError::NotFound` if no row matches.
- **`wirken channel remove <ch>` clears every per-channel row (cli).**
  Previously deleted only `<channel>-token`, with a hardcoded fallback
  for the four whatsapp keys, leaving entries like `signal-adapter-key`,
  `signal-endpoint`, `signal-allowed-senders`, and `slack-app-token`
  orphaned. Now calls a new `CredentialStore::delete_by_channel` that
  removes every row tagged with the channel in one statement, and
  reports the cleared count.

## 0.7.7 — Security audit fix (generate_image)

Single finding from the Round 2 audit.

- **Vuln 9 — generate_image path traversal (agent).** The
  `generate_image` tool read `filename` directly from LLM-controlled
  tool args and built the output path with
  `images_dir.join(format!("{filename}.png"))` with no validation.
  `PathBuf::join` with an absolute path replaces the base, and
  `..` components walk out of the workspace. The Vuln 2 fix did
  not cover this call site (it guarded `write_file` via
  `resolve_path_for_write`; `generate_image` built its path
  directly). New `sanitize_image_filename` strips `/`, `\`, and
  null bytes to `_` and refuses empty / `.` / `..`; the write now
  routes through `resolve_path_for_write` so the leaf-symlink
  refusal that protects `write_file` also guards this path.

## 0.7.6 — Security audit fixes

Eight findings from the security audit. Numbered to match the audit
report; HIGH unless otherwise noted.

- **Vuln 1 — shell-exec Tier 3 bypass (permissions).** Tier 3
  classification for high-risk commands used a case-sensitive
  contains check on the raw first token, so `/usr/bin/curl`,
  `./curl`, `CURL`, and shell wrappers like `sh -c 'curl ...'` all
  bypassed the gate. `Action::tier` and `Action::approval_key` now
  canonicalize via `Path::file_name()` + `to_ascii_lowercase`, and
  `HIGH_RISK_PREFIXES` is expanded with shell and process wrappers
  (`sh`, `bash`, `dash`, `zsh`, `env`, `xargs`, `nohup`, `timeout`,
  `nice`, `ionice`, `setsid`, `stdbuf`).
- **Vuln 2 — broken-symlink write (agent).** `resolve_path_for_write`
  returned an uncanonicalized path; a dangling symlink inside the
  workspace passed ancestor validation, and `tokio::fs::write`
  then created the target at the symlink destination, possibly
  outside the workspace. A `symlink_metadata` check on the leaf
  now refuses any symlink target. Separately, the `exec` sandbox
  no longer falls back silently to host execution when Docker is
  unreachable — that amplified this vuln. `SandboxMode::Off` is
  the only mode that permits host exec; `ExecOnly` / `GVisor`
  return a clear error when the sandbox is unavailable.
- **Vuln 3 — audit buffer loss on flush failure (audit).** The
  flush loop cleared the in-flight batch unconditionally, so any
  transient SQLite write error dropped the events that recorded
  activity in that window. Flush now retains the buffer on error
  and the loop halts after persistent failure, closing the mpsc
  channel so callers observe `ChannelClosed` instead of
  continuing with silent audit loss.
- **Vuln 4 — WhatsApp HMAC timing (adapter-whatsapp, MEDIUM).**
  `verify_signature` compared HMAC-SHA256 results with
  short-circuiting string equality. Now hex length is checked
  before decode, and `Mac::verify_slice` performs the
  constant-time comparison on decoded bytes. A misleading
  `// Constant-time comparison` comment is removed.
- **Vuln 5 — Teams webhook had no auth (adapter-teams).** The
  webhook accepted any POST matching the Activity shape. New
  `auth` module fetches Microsoft's JWKS through the Bot
  Framework OpenID config, caches by `kid` with rotation refresh,
  and validates inbound JWTs: RS256 signature, issuer equals
  `https://api.botframework.com`, audience equals the bot's
  configured app id, `exp` in the future. `TeamsAdapter::new`
  now returns `Result` and refuses empty `app_id` or
  `app_password`.
- **Vuln 6 — Google Chat webhook had no auth (adapter-google-chat).**
  Same class as Vuln 5. New `auth` module validates inbound JWTs
  against Google's Chat service-account JWKS: issuer equals
  `chat@system.gserviceaccount.com`, audience equals the bot's
  Cloud project number. `GoogleChatAdapter::new` now returns
  `Result` and requires both `service_account_token` and
  `app_project_number`. CLI now reads `{channel}-project-number`
  from the vault.
- **Vuln 7 — iMessage BlueBubbles webhook had no auth
  (adapter-imessage).** The `server_password` was stored at
  registration but never checked on inbound. Now extracted from
  the JSON body `password` field (matches the outbound flow) or
  the `X-BlueBubbles-Password` / `X-BB-Password` headers, and
  compared constant-time. `IMessageAdapter::new` returns `Result`
  and refuses empty `server_password`.
- **Vuln 8 — WhatsApp fail-open on empty secret
  (adapter-whatsapp, MEDIUM).** `verify_signature` was gated
  behind `if !app_secret.is_empty()`, so an empty secret silently
  disabled HMAC verification. `WhatsAppAdapter::new` now returns
  `Result` and refuses empty `app_secret`; the webhook handler
  always requires the signature.

### Deployment impact

Self-hosted deployments that previously relied on missing or empty
secrets to skip auth will fail to start on upgrade. Provision the
required config:

- `{channel}-app-id` and `{channel}-app-password` for Teams.
- `{channel}-project-number` in addition to the service account
  token for Google Chat.
- `{channel}-bluebubbles-password` (non-empty) for iMessage.
- `{channel}-app-secret` (non-empty) for WhatsApp.

Deployments running `sandbox_mode = "exec-only"` or `"gvisor"` on
hosts without Docker will fail at first `exec` call rather than
silently using host execution. Either install Docker/gVisor or
set `"mode":"off"` explicitly in `sandbox.json`.

## Unreleased

### Sandbox defaults, configuration plumbing, hardening, and exec tier granularity

Four changes that together close the gaps documented in the 0.7.4
verification report:

- **Wire `sandbox_mode` config through to the runtime.** `OrgPermissions.sandbox_mode` now writes `sandbox.json` in the data dir via `apply_org_config`, and the CLI reads it at gateway start. `AgentStaticConfig` carries a `sandbox` field that the factory clones into every waked agent. `Agent::new_with_sandbox` is the new explicit constructor; `Agent::new` becomes a shim that uses the default. `Agent::from_session_log` takes a `SandboxConfig` parameter. Precedence: org config (force-overwrite on `wirken run`) > local `sandbox.json` > default.
- **Flip the default sandbox mode from `Off` to `ExecOnly`.** Fresh installs sandbox shell exec in an ephemeral Docker container by default. `SandboxMode::from_str_config` unknown/empty values now fall back to the current default rather than silently stripping the sandbox. `ToolRegistry::sandbox` probes Docker first and emits a distinct warning if Docker is unreachable; if `gvisor` is configured but `runsc` is not registered, the warning names `runsc` specifically. Both fall through to host execution with the existing sticky-failure semantics. `wirken setup` adds a fourth step that detects `runsc` and offers to upgrade to `gvisor`, writing `sandbox.json` either way.
- **Harden the sandbox container.** `cap_drop=ALL`, empty `cap_add`, `security_opt=["no-new-privileges:true","seccomp=default"]`, `readonly_rootfs=true`, and a 64 MB `tmpfs` at `/tmp` with `mode=1777`. Workspace stays bind-mounted RW at `/workspace`. Memory, PID, no-network, and non-root user settings are unchanged. Structural unit tests assert each field, and Docker-backed integration tests (skipped when Docker is absent) verify the kernel-level effect: write to `/` fails, writes to `/workspace` and `/tmp` succeed, `chown` fails under `cap_drop`, and setuid binaries fail to elevate under `no-new-privileges`.
- **Promote high-risk shell exec prefixes to Tier 3.** `curl`, `wget`, `ssh`, `scp`, `sftp`, `sudo`, `su`, `doas`, `kubectl`, `helm`, `docker`, `podman`, `nc`, `ncat`, `socat`, and `git` now always prompt instead of remembering a single approval for 30 days. Other `exec` prefixes keep the Tier 2 first-use-approval behaviour. No `permissions.db` schema change; existing Tier-2-style approvals for newly-Tier-3 prefixes are ignored by the tier lookup rather than migrated.

### Docs

- `docs/permissions-and-identity.md` no longer says `sandbox_mode` is parsed-but-not-enforced. `allowed_tools` and `blocked_tools` remain in the "parsed, not enforced" set.
- `docs/enforcement-model.md` describes the new default, the fallback warning paths, and the `sandbox.json` override.
- `README.md` Status section describes the new default and container hardening.

### Version

No version bump in these commits. The next release will be tagged
`0.7.5` per the maintainer runbook, with the bump in its own commit
at release time.
