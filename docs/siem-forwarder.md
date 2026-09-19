# Getting the chain out

Four ways an out-of-process consumer reads the audit chain: two SIEM pipes
over HTTPS, an observe hook over local IPC, and an OpenTelemetry projection.
All four read the same source events. The chain itself is owned by
[audit-cli.md](audit-cli.md).

The local hash-chained log stays primary. Every surface here is additive to
it, not a replacement: `wirken sessions verify` verifies the chain and the
Ed25519 attestation offline, independent of any consumer.

## Choosing a surface

| | Observe hook (IPC) | Webhook and SIEM targets (HTTPS) |
|---|---|---|
| Transport | Cap'n Proto over Unix domain socket, or a named pipe on Windows | HTTPS POST out from wirken |
| Authentication | Ed25519 challenge-response; the hook holds the keypair | Optional HMAC-SHA-256 over the request body |
| Direction | Pull; the consumer drives the cursor | Push; wirken polls `session_events` and posts batches |
| Replay control | Consumer-held `sinceSeq` per session | One global cursor over `session_events.id`, one indexed range query per poll across all sessions |
| Co-location | Must run at the wirken UID | Anywhere reachable from the gateway |
| Filtering | None; the hook receives every event in every session it tails | The default-forward variant set, overridable |

Pick the hook for a same-UID consumer that wants Ed25519 authentication,
pull-based backpressure and cursor-driven replay. Pick the webhook for a cloud
SIEM that cannot run a local connector at the wirken UID.

**Neither defends against a same-UID attacker.** The hook's secret key is a
file on disk at the wirken UID and the HMAC secret lives in `siem.json` at the
same UID; whoever can read those can produce indistinguishable subscription
clients. Detecting mid-stream tampering means verifying the chain offline, not
trusting the wire.

## The two SIEM pipes

Both share one `SiemConfig` in `<data_dir>/siem.json`. The typed pipe is
opt-in.

**Legacy pipe.** The `AuditWriter` flush loop batches `AuditEvent` rows every
50 ms or every 100 events and forwards each batch. Always on when any endpoint
is configured. Carries gateway-level events: `gateway.start`, adapter
handshake records, MCP proxy registration, permission denials,
`audit.chain_broken`. Source: `crates/audit/src/writer.rs:591-704`,
`crates/audit/src/siem.rs:178-261`.

**Typed pipe.** A polling worker forwards new `session_events` rows. Each pass
is one indexed sweep (`get_events_after`) for rows past a global cursor across
all sessions, so poll cost does not scale with session count. Spawned only
when at least one of these is set: `typed_forwarding_enabled: true`,
`typed_include_variants`, `typed_exclude_variants`, or `sentinel_typed`.
`typed_forwarding_enabled: false` is an explicit off switch that overrides
every other typed field, so the legacy-only path can be tested against a
config that already has them populated.

Cadence is `typed_poll_interval_ms` (default 50 ms, clamped up to a 10 ms
floor against busy-spin). It is a tuning knob, not an opt-in trigger: setting
it alone does not spawn the worker. The worker never writes to
`session_events`, so the hash chain is unaffected regardless of forwarder
activity.

### Variant policy

Default forward: `AssistantToolCalls`, `ToolResult`, `HttpFetch`,
`PermissionDenied`, `PermissionGrantExpired`, `PermissionGrantPruned`,
`SkillPermissionDenied`, `SubagentSpawned`, `SubagentSessionBound`,
`SubagentResult`, `ChainHead`, `McpEntryVerified`, `McpEntryRefused`,
`EgressHookDispatched`, `ToolOutputRedacted`, `BudgetExceeded`,
`SandboxEgressVerdict`, `SandboxEgressUnsupported`, `MemoryEntryWritten`,
`CrossChannelMemoryRead`, `ImportStarted`, `ImportCompleted`,
`ImportedChatRead`, `ImportedChatSearched`.

Default exclude, opt-in only: `UserMessage` and `AssistantMessage` (message
bodies, PII), `LlmRequest` and `LlmResponse` (token accounting),
`SystemPromptSet`, `Compaction`, `Rewind`, `Attestation`, `AuditLegacy`
(already on the legacy pipe), and the Zirkel pipeline variants.

`typed_include_variants` is a full allowset rather than an addition: when set,
only what it lists is forwarded and the default set is ignored. It wins over
`typed_exclude_variants` when both are set. Source:
`crates/audit/src/siem_typed.rs:105-135` (`should_forward`).

### Per-target wire shape

| Target | Envelope | Endpoint |
|--------|----------|----------|
| Webhook | Mixed legacy and typed entries in one JSON array | Single POST per flush |
| Splunk HEC | NDJSON, one event per line; legacy `sourcetype: "wirken:audit"`, typed `wirken:session` | One HEC token for both |
| Datadog | JSON array per POST; typed entries carry `ddtags: kind:<variant>`, all carry `ddsource: "wirken"` | One endpoint |
| Sentinel | PascalCase columns matching the DCR stream; legacy carries `Action`/`Target`, typed carries `Kind`/`AgentId`/`AdapterId`/`SenderId`/`Event` | Two: legacy to `Custom-WirkenAudit`, typed to the configured `sentinel_typed.endpoint` |

The Sentinel split is a DCR constraint, not a design choice: the legacy
stream's DCR pins specific columns and rejects rows that do not match, so the
typed pipe needs its own stream with its own column schema. Builders:
`crates/audit/src/siem.rs:267-534`; transport selection at
`siem_typed.rs:476-520`.

Sentinel ingestion uses the Logs Ingestion API over a Data Collection Rule.
The operator configures DCE, DCR and custom table out of band; `api_key` must
be an Azure AD bearer token scoped for `https://monitor.azure.com/.default`.
Wirken does not refresh it, so it expires on Azure AD's normal cadence,
typically one hour; refresh by rewriting `siem.json` from a sidecar before
expiry.

### HMAC

With `siem.json.hmac_secret` set, the webhook target and the typed webhook
pipe carry `X-Wirken-Signature: sha256=<hex>` over the exact serialized body
bytes. The `(body, signature)` factoring uses a single `serde_json::to_vec`
call so the signed bytes are the bytes on the wire.

Receivers recompute `HMAC-SHA-256(hmac_secret, raw_request_body)` and compare
constant-time. Verifying over a re-parsed JSON envelope is incorrect:
re-serializing through a different language's encoder reorders fields and
breaks the signature. A shared secret produces distinct signatures on the two
pipes because the body shapes differ, so verify per pipe. Source:
`crates/audit/src/siem.rs:745-752` (`compute_webhook_signature`).

### Retries

There are none. A forward failure logs a `tracing::warn!` and drops the batch;
the next flush carries new events forward. Operators own retry at the receiver
(Splunk HEC indexer acknowledgement, Datadog backlog).

The typed pipe is the exception, and only partly: its global cursor advances
**only** after a successful POST, so a transport error means the next pass
re-reads every row since. Because a pass batches across sessions, that replay
spans sessions. This gives bounded duplicate delivery during transient failure
rather than silent loss.

## Observe hook

Register the hook's public key, then connect.

```bash
wirken hooks register <hook-id> <pubkey-hex> --type observe
```

The hook id is operator-chosen and appears on every audit row the hook
produces. The pubkey is the 32-byte Ed25519 public key, hex-encoded.

**Handshake.** The hook connects to `<data_dir>/sockets/gateway-hooks.sock`,
or the equivalent named pipe on Windows. The gateway sends an `AuthChallenge`;
the hook responds with
`HookAuthResponse { publicKey, signature, hookId, hookType }`. The signature is
Ed25519 over `HOOK_HANDSHAKE_DOMAIN || hookId || 0x00 || nonce`, where
`HOOK_HANDSHAKE_DOMAIN = b"wirken-ipc-hook-handshake-v1\x00"`. The gateway
looks `hookId` up in the `hooks` table of `<data_dir>/hooks.db`, verifies with
`verify_strict`, and accepts or rejects. The domain separator means an adapter
signature can never replay against the hooks acceptor, or the reverse.

**Subscription.** A pull loop: one `SessionLogTail` frame out, one
`SessionLogTailResponse` back.

```
SessionLogTail          sessionId: Text, sinceSeq: UInt64, maxRows: UInt32
SessionLogTailResponse  events: List(SessionLogTailEvent), nextSeq: UInt64
SessionLogTailEvent     seq: UInt64, payload: Text
```

`payload` is `Text` carrying a JSON-serialized `SessionEvent`, which the hook
deserializes against its own copy of the enum. The JSON wire keeps the capnp
schema independent of audit-side variant churn: a new `SessionEvent` variant
does not change the schema.

**Cursor.** The hook owns it. On a non-empty response it persists `nextSeq`
and passes it as the next `sinceSeq`; on an empty response `nextSeq` equals
the request's `sinceSeq`. Wirken keeps no per-hook cursor state.

**Delivery is at-least-once.** A hook that receives a batch and crashes before
persisting the cursor sees the same rows on its next connection. The
per-session `seq` is the dedup key: treat `(sessionId, seq)` as a primary key
and ignore duplicates. The chain is append-only and per-session monotonic, so
the dedup is unambiguous.

**Multi-session.** The hook requests each session id independently. To
discover sessions it can poll a known id (the `gateway-hooks` and
`gateway-mcp` sentinel sessions exist for cross-cutting events) or maintain a
list out of band; wirken pushes no session-list endpoint over IPC.

One hook process can register under different ids for any combination of
`observe`, `veto` and `egress` roles. The veto and egress roles are described
in [enforcement-model.md](enforcement-model.md#veto-and-egress-hooks).

**Building one.** Depend on `wirken-ipc` for the frame types and handshake
helpers, point at `gateway-hooks.sock`, drive `SessionLogTail` in a loop.
`serve_observe_loop` in `crates/cli/src/commands/run.rs` is the server side of
the same protocol and reads as a reference implementation. Non-Rust consumers
implement from `crates/ipc/schema/wirken.capnp` and the domain separator
constant.

## OpenTelemetry projection

Wirken projects the chain to OpenTelemetry GenAI semantic conventions over
OTLP/HTTP+JSON. The same spans land in Datadog, Honeycomb, Jaeger, Splunk
Observability, Microsoft Agent 365, or any OTel-aware backend with no change
beyond endpoint and bearer auth.

Encoding choices the exporter makes, several of which are the difference
between landing and being silently filtered:

- OTLP/HTTP+JSON, not the gRPC variant.
- Trace and span ids as hex, timestamps as string-encoded nanoseconds, `kind`
  and `status.code` as integers.
- **Every attribute value as `stringValue`, including numeric fields like
  token counts.** A naive OTel SDK exporter emits `intValue` or `doubleValue`
  and those spans are rejected at Agent 365 ingestion.
- `parentSpanId` on every non-root span.
- A single-root tree per run: one `invoke_agent` root with `chat`,
  `execute_tool` and `output_messages` parented directly to it.
- Lowercase operation-name literals: `invoke_agent`, `chat`, `execute_tool`,
  `output_messages`. Spans carrying anything else are filtered at ingestion.
- Batches split when a response indicates the 1 MB body limit is exceeded;
  single spans above 1 MB after split are dropped with an audit row noting it.
- `Retry-After` honored on 429 with jittered exponential backoff.

Run-wide attributes stamped on every span: `microsoft.tenant.id`,
`gen_ai.agent.id`, `gen_ai.agent.name`, `microsoft.a365.agent.blueprint.id`,
`microsoft.channel.name`, `gen_ai.conversation.id`, `microsoft.session.id`.
Tool spans add `gen_ai.tool.name`, `gen_ai.tool.type`, `gen_ai.tool.call.id`,
`gen_ai.tool.call.arguments`, `gen_ai.tool.call.result`. Chat spans add
`gen_ai.request.model` and `gen_ai.provider.name`. Root spans add `user.id`.

### Microsoft Agent 365

Wirken is not affiliated with or endorsed by Microsoft Corporation. The names
below are used for compatibility documentation only.

Endpoint:

```
https://agent365.svc.cloud.microsoft/observabilityService/tenants/{tenantId}/otlp/agents/{agentId}/traces?api-version=1
```

with `Authorization: Bearer <token>` and `Content-Type: application/json`.
Tokens come from Microsoft Entra via OAuth2 client credentials; the scope is
`9b975845-388f-4429-889e-eab1ef63949c/.default`, and the issued token must
carry `roles` containing `Agent365.Observability.OtelWrite` with `aud`
matching the resource. That needs a standard Entra app registration with the
role granted and admin-consented.

**Ingestion also requires an M365 E7 or Agent 365 license assigned to at least
one user in the tenant.** The SKU being present in the directory is not
enough: without an assignment the endpoint returns 200 OK with
`partialSuccess` null and the spans are silently dropped.

Hook roles map onto three Microsoft pillars: `egress` onto Purview DLP
(inspect, redact or block tool output before it returns to the assistant),
`veto` onto Entra Conditional Access on agent identity (allow or deny a tool
invocation before dispatch), `observe` onto Sentinel and Defender XDR (stream
the typed chain).

`gen_ai.tool.type` takes two values: MCP server tools emit `MCP Server`, and
everything else (built-ins, Wasm skills, `exec`, `web_search`,
`generate_image`) emits `function`. Microsoft derives `ExecuteToolByGateway`
and `ExecuteToolByMCPServer` from these. Wasm skills emit `function` because
Microsoft's enumeration has no Wasm entry and that is the closest match for a
runtime-executed tool.

`channel.name` pivots on a canonical set. The Teams adapter emits literal
`msteams` to land in the native pivot; `outlook` is the other documented
value. The other eight adapters emit their own name (`telegram`, `discord`,
`slack`, `matrix`, `whatsapp`, `signal`, `googlechat`, `imessage`), which is
accepted but appears in raw channel data rather than the default filter.

**Identity.** The per-agent Ed25519 keypair stays the local attestation root;
federation is additive. A pluggable `FederatedIdentity` trait covers Entra and
Keycloak, differing only in claim validation and the run-wide attributes
stamped. `EntraFederatedIdentity` validates the
`Agent365.Observability.OtelWrite` role and stamps Microsoft-namespaced
attributes; `KeycloakFederatedIdentity` does OIDC client credentials against a
realm and stamps vendor-neutral ones.

**User identity.** Chat-platform callers have no Entra identity by
construction; Teams is the exception, carrying `from.aadObjectId` natively. A
standalone `UserResolver` consults sources in order: an adapter-supplied real
Entra object id, then an operator-supplied `user_map.json` overlay (a
Slack-email-to-Entra mapping is the canonical case), then a keyed synthetic
GUID derived from a vault-held salt over `(tenant_id, adapter_id, sender_id)`.
The synthetic is shaped like an Entra object id and pivots stably per
channel-and-sender pair while remaining non-reversible to a phone number or
handle by anyone outside the deployment. **The salt is
per-deployment-forever:** rotating it re-pseudonymizes every external caller
and breaks longitudinal pivot in Defender across the rotation.

**What this does not cover.** Conditional Access policy evaluation, content
classification, Defender XDR correlation across user, device and network
signals, and lifecycle workflows are Microsoft's data plane. Wirken honors a
denial arriving as a 403 and projects it onto the chain as a
`PermissionDenied` row; it does not evaluate the policy. The `egress` hook
delivers tool output to whatever classifier the operator wires up; wirken does
not classify content. `wirken setup --org` invokes the documented Agent 365
registration flow for operators who want the agent in the M365 admin center
inventory, but the telemetry path does not require a Graph-registered agent.

This page describes the integration surface against Microsoft Learn
documentation verified on 2026-05-22. It is not evidence that emissions
currently land in any particular tenant: the Microsoft surfaces are under
active migration and the ingestion-side filter set can tighten between
releases, so a claim that emissions land is dated and tenant-bound.

## Source references

- Two-pipe topology: `crates/audit/src/writer.rs:591-704` (legacy),
  `crates/audit/src/siem_typed.rs:349` (`spawn`) and `:415` (`run_one_pass`).
- Variant policy: `crates/audit/src/siem_typed.rs:105-135`.
- Per-target builders: `crates/audit/src/siem.rs:267-534`.
- HMAC: `crates/audit/src/siem.rs:745-752`.
- Spawn guard: `crates/audit/src/siem.rs:97-110`.
- Hook handshake: `crates/ipc/src/auth.rs` (`HOOK_HANDSHAKE_DOMAIN`,
  `perform_hook_handshake`, `perform_gateway_hook_handshake`).
- Hook registry: `crates/gateway/src/hook_registry.rs`.
- OTel exporter and projector: `crates/audit/src/otel_exporter.rs`,
  `crates/audit/src/otel_projector.rs`.
