# SIEM forwarder

Wirken pushes audit events to an operator-configured SIEM endpoint over HTTPS. Two pipes run in parallel: a legacy pipe carrying `AuditEvent` flat-tuple rows, and a typed pipe carrying `SessionEvent` rows polled from `session_events`. Both pipes share one `SiemConfig`; the typed pipe is opt-in.

The webhook target documented here is one of two subscription surfaces for external consumers; for a same-UID consumer the observe-hook IPC pipe in [`external-consumers.md`](external-consumers.md) carries the same `SessionEvent` payloads under an Ed25519 handshake.

## Two pipes

### Legacy pipe

The `AuditWriter`'s flush loop batches `AuditEvent` rows every 50 ms or every 100 events and forwards each batch to the configured target. Always on when any endpoint is configured in `siem.json`. Carries gateway-level events (`gateway.start`, adapter handshake records, MCP proxy registration, permission denials, `audit.chain_broken`, etc.).

Source: `crates/audit/src/writer.rs:426-577` (flush loop), `crates/audit/src/siem.rs:147-231` (per-target forward).

### Typed pipe

A polling worker reads `session_events` via `SqliteSessionLog::get_since` at a fixed cadence and forwards new rows to the typed transport. Opt-in: spawned only when at least one of the following is set in `siem.json`:

- `typed_forwarding_enabled: true` (explicit opt-in to the default forwardable-variant set).
- `typed_include_variants` (operator-provided allowlist).
- `typed_exclude_variants` (operator-provided denylist over the default set).
- `sentinel_typed` (Sentinel parallel-pipe configuration).

`typed_forwarding_enabled: false` is an explicit off switch that overrides every other typed field; the worker is not spawned even when those are set. Use this to test the legacy-only path against a `siem.json` that already has the typed fields populated.

The worker never writes to `session_events`, so the audit hash chain is unaffected regardless of forwarder activity.

Source: `crates/audit/src/siem_typed.rs:250-310` (worker `spawn` + `run_one_pass`), `crates/audit/src/siem.rs:57-103` (`SiemConfig.typed_forwarding_enabled`, `typed_forwarding_opted_in`).

## Hybrid transport path

| Target | Typed envelope | Endpoint shape |
|--------|----------------|----------------|
| Webhook | Mixed-shape batches at one endpoint | Single POST per flush, body is a JSON array of mixed legacy + typed entries when typed is enabled |
| Splunk HEC | Mixed-shape batches at one endpoint | NDJSON body, one event per line; legacy and typed events both land in the same HEC token |
| Datadog | Mixed-shape batches at one endpoint | JSON array per POST; typed entries distinguished by `ddtags: kind:<variant>` |
| Sentinel | Two endpoints (DCR streams are column-pinned) | Legacy goes to `Custom-WirkenAudit`; typed goes to the operator-configured `sentinel_typed.endpoint` (typically `Custom-WirkenSession`) |

The Sentinel split is a Sentinel DCR constraint, not a wirken design choice: the legacy stream's DCR pins specific columns and rejects rows that don't match. The typed pipe needs its own stream with its own column schema.

Source: `crates/audit/src/siem_typed.rs:375-405` (`TypedTransport::for_config` selecting Shared vs SentinelSeparate).

## Variant include/exclude policy

The default forwardable variant set covers the audit events most useful for detection without leaking PII or token-accounting noise:

**Default forward:** `AssistantToolCalls`, `ToolResult`, `HttpFetch`, `PermissionDenied`, `SkillPermissionDenied`, `SubagentSpawned`, `SubagentResult`, `ChainHead`.

**Default exclude (opt-in via `typed_include_variants`):** `UserMessage`, `AssistantMessage` (carry message bodies, PII), `LlmRequest`, `LlmResponse` (token accounting), `SystemPromptSet`, `Compaction`, `Rewind`, `Attestation`, `AuditLegacy` (already on the legacy pipe), and the Zirkel pipeline variants (`CandidateScored`, `CandidateLlmScored`, `CandidateKept`, `CandidateSkipped`, `ThemeNamed`, `InterestsEdited`, `PerspectiveExpansion`, `PerspectiveSkipped`).

`typed_include_variants` wins over `typed_exclude_variants` when both are set; the include list is treated as the canonical allowset and the exclude list is ignored.

Source: `crates/audit/src/siem_typed.rs:71-97` (`should_forward`).

## Per-target envelope shapes

| Target | Legacy builder | Typed builder | Wire shape |
|--------|----------------|---------------|------------|
| Datadog | `build_datadog_payload` (`crates/audit/src/siem.rs:260-290`) | `build_datadog_typed_payload` (`crates/audit/src/siem.rs:427-441`) | JSON array of log entries with `ddsource: "wirken"`, `ddtags: "service:..,env:..,kind:.."` |
| Splunk HEC | `build_splunk_body` (`crates/audit/src/siem.rs:292-317`) | `build_splunk_typed_body` (`crates/audit/src/siem.rs:441-465`) | NDJSON; legacy `sourcetype: "wirken:audit"`, typed `sourcetype: "wirken:session"` |
| Sentinel | `build_sentinel_payload` (`crates/audit/src/siem.rs:319-353`) | `build_sentinel_typed_payload` (`crates/audit/src/siem.rs:467-493`) | PascalCase columns matching the DCR stream; legacy carries `Action`/`Target`, typed carries `Kind`/`AgentId`/`AdapterId`/`SenderId`/`Event` |
| Webhook | `build_webhook_request` (`crates/audit/src/siem.rs:353-397`) | `build_webhook_typed_request` (`crates/audit/src/siem.rs:496-525`) | JSON array of flat objects; typed wrapper adds `session_id`, `seq`, `kind`, `trust` |

## HMAC

When `siem.json.hmac_secret` is set, the webhook target (and the typed webhook pipe) carry `X-Wirken-Signature: sha256=<hex>` over the exact serialized body bytes. The `(body, signature)` factoring uses a single `serde_json::to_vec` call so the signed bytes are the bytes that go on the wire; field-ordering drift between a re-serialized envelope and the wire body would otherwise produce a different signature than the receiver computes.

Receivers verify by recomputing `HMAC-SHA-256(hmac_secret, raw_request_body)` and comparing constant-time against the header value. Verifying over a re-parsed JSON envelope is incorrect: re-serializing through a different language's JSON encoder will reorder fields and break the signature.

A shared `hmac_secret` produces distinct signatures on the legacy and typed pipes because the body shapes differ. Operators verifying both pipes must run the recompute per pipe.

Source: `crates/audit/src/siem.rs:353-397` (legacy webhook + HMAC), `crates/audit/src/siem.rs:496-525` (typed webhook + HMAC), `crates/audit/src/siem.rs:574-588` (`compute_webhook_signature`).

## Retries

There are no retries. A forward failure logs a `tracing::warn!` and drops the batch; the next flush carries new events forward. Operators own retry at the receiver (Splunk HEC indexer-acknowledgement, Datadog backlog, etc.).

The typed pipe's cursor advances per session **only** after a successful POST: if the typed transport returns `Err`, the cursor for that session does not move and the next polling pass re-reads the same rows. This is the polling pipe's analogue of receiver-side ack and gives bounded duplicate delivery during transient failure rather than silent loss.

Source: `crates/audit/src/siem_typed.rs:310-340` (`run_one_pass` cursor advance gated on `forward` success).

## Tuning gaps

Two issues track typed-forwarder operational concerns:

- [gebruder/wirken#105](https://github.com/gebruder/wirken/issues/105): `TypedEventForwarder` polling cost scales linearly with session count. A high-session-count deployment pays an `O(sessions)` SQL scan every `TYPED_POLL_INTERVAL`; the right fix is per-session cursoring outside the worker's in-memory `HashMap`.
- [gebruder/wirken#106](https://github.com/gebruder/wirken/issues/106): `TYPED_POLL_INTERVAL` is hardcoded to 50 ms. A high-latency target with tight ingest SLAs may want to slow the loop; a low-latency target with bursty traffic may want faster ticks.

## Source references

- Two-pipe topology: `crates/audit/src/writer.rs:426-577` (legacy), `crates/audit/src/siem_typed.rs:250-340` (typed).
- Variant policy: `crates/audit/src/siem_typed.rs:71-97`.
- Per-target builders: `crates/audit/src/siem.rs:260-525`.
- HMAC: `crates/audit/src/siem.rs:574-588` (`compute_webhook_signature`).
- Spawn-guard: `crates/audit/src/siem.rs:75-103` (`SiemConfig::typed_forwarding_opted_in`).
- Operational issues: [gebruder/wirken#105](https://github.com/gebruder/wirken/issues/105), [gebruder/wirken#106](https://github.com/gebruder/wirken/issues/106).
