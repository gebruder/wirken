# Integrating with Microsoft Agent 365

Verified against Microsoft Learn documentation on 2026-05-22. The Microsoft surfaces this page describes are under active migration: the agent registration surface in Microsoft Graph is being migrated, and Microsoft can tighten the ingestion-side filter set between wirken releases. The references at the bottom of this page name the specific Learn pages the verification was made against.

Wirken is not affiliated with or endorsed by Microsoft Corporation. References to Microsoft Agent 365, Microsoft Entra, Microsoft Purview, Microsoft Defender, and Microsoft Sentinel are made for compatibility-documentation purposes only.

## Overview

Wirken's audit chain projects to OpenTelemetry GenAI semantic conventions over OTLP/HTTP+JSON. Microsoft Agent 365's ingestion endpoint accepts this contract, as do generic OpenTelemetry collectors and other OTLP-compatible backends. This page documents the wire-level specifics for emitting telemetry that lands in a licensed Agent 365 tenant.

## Three layers

- **Runtime** (wirken). Executes the agent loop. Owns sandboxed tool execution, credential isolation, the per-session hash-chained audit log, and per-channel adapter processes.
- **Wire** (OpenTelemetry GenAI semantic conventions over OTLP/HTTP+JSON). Vendor-neutral. The same spans wirken emits to Agent 365 also land in Datadog, Honeycomb, Jaeger, Splunk Observability, or any OTel-aware backend with no code change beyond endpoint and bearer auth.
- **Governance plane** (Agent 365 is one option). Consumes the wire and adds identity-anchored policy, lifecycle workflows, and cross-signal correlation across the Microsoft security stack.

## Hook role correspondence

Wirken's hook surface maps onto three Microsoft governance pillars.

| Wirken hook role | Microsoft surface | Function |
|---|---|---|
| `egress` (post-execution tool output) | Microsoft Purview DLP | Inspect, redact, or block tool output before it returns to the assistant |
| `veto` (pre-dispatch tool gate) | Microsoft Entra Conditional Access on agent identity | Allow or deny a tool invocation before it dispatches |
| `observe` (audit chain tail) | Microsoft Sentinel and Microsoft Defender XDR | Stream the typed session event chain to a security backend |

A Purview-side DLP consumer registers as an `egress` hook against the gateway over the documented IPC handshake. A Conditional Access-style policy consumer registers as a `veto` hook. A Defender or Sentinel forwarder registers as an `observe` hook or consumes the OTel stream directly. All three hook surfaces are documented in [`docs/external-consumers.md`](../external-consumers.md).

## Wire shape

Wirken's exporter targets the URL Microsoft documents for service-to-service non-SDK runtimes:

```
https://agent365.svc.cloud.microsoft/observabilityService/tenants/{tenantId}/otlp/agents/{agentId}/traces?api-version=1
```

with `Authorization: Bearer <token>` and `Content-Type: application/json`.

Bearer tokens are acquired from Microsoft Entra via OAuth2 client credentials. The configured scope is `9b975845-388f-4429-889e-eab1ef63949c/.default`, and the issued token must carry `roles` containing `Agent365.Observability.OtelWrite` and `aud` matching the resource. A wirken installation that targets Agent 365 therefore needs a standard Entra app registration with that app role granted and admin-consented.

Ingestion also requires a Microsoft 365 E7 or Microsoft Agent 365 license to be **assigned to at least one user** in the tenant. The SKU being present in the tenant directory is not sufficient; without an assignment, the endpoint returns 200 OK with `partialSuccess` null and the spans are silently dropped. This is a setup precondition on the operator side, distinct from the dated-verification framing in the Verification status section below (which covers Microsoft tightening their ingestion-side filters over time).

Encoding choices wirken's exporter makes:

- Targets OTLP/HTTP+JSON, not the gRPC variant.
- Emits trace and span identifiers as hex, timestamps as string-encoded nanoseconds, `kind` and `status.code` as integers.
- Emits every attribute value as `stringValue`, including numeric fields like token counts. A naive OTel SDK exporter emits `intValue` or `doubleValue` for numeric fields and those spans are rejected at ingestion.
- Sets `parentSpanId` on every non-root span.
- Constructs a single-root tree per run: one `invoke_agent` root, with `chat`, `execute_tool`, and `output_messages` parented directly to it.
- Uses lowercase operation-name literals: `invoke_agent`, `chat`, `execute_tool`, `output_messages`. Spans carrying anything else are filtered at ingestion.
- Splits batches when a response indicates the 1 MB body limit is exceeded, and drops single spans above 1 MB after split with an audit-row noting the drop.
- Honors `Retry-After` on 429 responses with jittered exponential backoff.

Wirken's exporter stamps the same set of run-wide attributes on every span emitted in a given run: `microsoft.tenant.id`, `gen_ai.agent.id`, `gen_ai.agent.name`, `microsoft.a365.agent.blueprint.id`, `microsoft.channel.name`, `gen_ai.conversation.id`, and `microsoft.session.id`. Tool spans additionally carry `gen_ai.tool.name`, `gen_ai.tool.type`, `gen_ai.tool.call.id`, `gen_ai.tool.call.arguments`, and `gen_ai.tool.call.result`. Chat spans additionally carry `gen_ai.request.model` and `gen_ai.provider.name`. Invoke-agent root spans additionally carry `user.id`. The exporter source is the authoritative reference for the per-class invariants and the full attribute construction.

## gen_ai.tool.type and Defender ActionType

Wirken maps its tool surface onto two values from Microsoft's `gen_ai.tool.type` enumeration:

- MCP server tools emit `MCP Server`.
- All other tools (built-in tools, Wasm skills, `exec`, `web_search`, `generate_image`) emit `function`.

Microsoft derives distinct ActionType values from these. A gateway-executed `function` tool surfaces in Defender as `ExecuteToolByGateway`; an MCP-routed tool surfaces as `ExecuteToolByMCPServer`. Wirken is a gateway by construction, so this two-bucket mapping produces the correct gateway-versus-MCP pivot without further wiring.

Wasm skills emit `function`. Microsoft's enumeration has no Wasm-skill entry; `function` is wirken's closest match for runtime-executed tools.

## channel.name

Microsoft's built-in channel filter pivots on a canonical set of strings. As of the verification date, `msteams` and `outlook` are the documented values that pivot in the default filter; other strings are accepted but do not pivot there.

- Wirken's Microsoft Teams adapter emits literal `msteams` to land in the native pivot.
- The other eight adapters emit their own adapter name (`telegram`, `discord`, `slack`, `matrix`, `whatsapp`, `signal`, `googlechat`, `imessage`). Operators see them in raw channel data rather than in the default filter.

An operator-supplied channel-pivot override is a planned enhancement.

## Identity

Wirken's per-agent Ed25519 keypair stays as the local attestation root for the session hash chain. Federation against an external identity provider is additive, not a replacement.

A pluggable `FederatedIdentity` trait covers both Microsoft Entra and Keycloak. The trait is IdP-agnostic; both implementations use client credentials and differ only in claim-validation specifics and the run-wide attributes stamped on outbound spans.

When targeting Agent 365, `EntraFederatedIdentity` validates that the issued token carries the `Agent365.Observability.OtelWrite` role and stamps Microsoft-namespaced attributes such as `microsoft.tenant.id` and `microsoft.a365.agent.blueprint.id`. When targeting a non-Microsoft backend, `KeycloakFederatedIdentity` performs OIDC client credentials against a configured realm and stamps vendor-neutral attributes. The same exporter, projector, and run-wide invariants apply across both.

### User identity

Wirken's chat-platform callers (Telegram, Discord, Signal, WhatsApp, Matrix, Google Chat, iMessage) have no Microsoft Entra identity by construction. Microsoft Teams is the exception: inbound Teams activities carry a `from.aadObjectId` natively.

A standalone `UserResolver`, separate from `FederatedIdentity`, consults sources in order: adapter-supplied real Entra object id (the Teams case, with no operator configuration), then an operator-supplied `user_map.json` overlay for correlations the adapter cannot extract on its own (a Slack-email-to-Entra mapping is the canonical example), then a keyed synthetic GUID derived from a vault-held salt over `(tenant_id, adapter_id, sender_id)`. The keyed synthetic is shaped like an Entra object id and pivots stably per channel-and-sender pair, while remaining non-reversible to the sender's phone number or platform handle by anyone outside the deployment.

The salt is per-deployment-forever. Rotating it re-pseudonymizes every external caller and breaks longitudinal pivot in Defender across the rotation.

## What this integration does not cover

These are surfaces Microsoft owns and wirken does not replicate:

- **Conditional Access policy evaluation**. Wirken honors a tool-call denial that arrives as a 403 on a federated token call and projects it onto the audit chain as a `PermissionDenied` row, but the policy evaluation itself is Microsoft's data plane.
- **Content classification (Purview DLP labels)**. Wirken's `egress` hook delivers tool output to whatever classifier the operator wires up; wirken does not classify content.
- **Defender XDR correlation** across user, device, and network signals. That correlation runs on the consumer side; wirken's responsibility ends at emitting the span with the right attributes and bearer token.
- **Lifecycle workflows tied to HR or employee processes**. Microsoft Entra surface.
- **Agent registration in Microsoft Graph**. Wirken's `wirken setup --org` invokes the documented Agent 365 registration flow (delegated permissions, interactive consent, admin approval) for operators who want the agent in the M365 admin center inventory, but the telemetry path does not require a Graph-registered agent.

## Audit chain stays primary

Wirken's hash-chained session log is the local source of truth and the offline-verifiable artifact. The OTel projection is additive to that chain, not a replacement. `wirken sessions verify` continues to verify the hash chain and Ed25519 attestation offline, independent of any cloud governance plane.

A consumer that wants the full event stream with cryptographic integrity verifies it against the chain. A consumer that wants OTel-shaped projection for cross-signal correlation in Defender or another OTel-aware backend reads the OTel stream. Both come from the same source events.

## Verification status

Wirken implements the wire contract Microsoft documents for non-SDK runtimes emitting telemetry into Agent 365. The exporter, projector branch coverage, `FederatedIdentity` trait, and `UserResolver` described above are the integration surface.

A dedicated conformance suite verifies that wirken's emissions land in a licensed Agent 365 tenant end-to-end. Releases that assert wirken's emissions land in a licensed Agent 365 tenant record the date of the last green run in the release notes. The verification is dated and tenant-bound: it certifies a release against the tenant's filter state on the run date, not in perpetuity, since Microsoft's ingestion-side filters can change between dated verifications.

Until that suite is wired and a green run is recorded, this page describes the integration surface and is not evidence that emissions currently land downstream.

## References

Verified on 2026-05-22 against the following Microsoft Learn pages and wirken internal documents:

- Microsoft Learn, direct OpenTelemetry integration: https://learn.microsoft.com/en-us/microsoft-agent-365/developer/direct-open-telemetry-integration
- Microsoft Learn, Agent 365 observability overview: https://learn.microsoft.com/en-us/microsoft-agent-365/developer/observability
- Microsoft Learn, Agent 365 third-party agents: https://learn.microsoft.com/en-us/microsoft-agent-365/third-party-agents
- Microsoft Learn, Entra Agent ID configure third-party agents: https://learn.microsoft.com/en-us/entra/agent-id/configure-third-party-agents
- Microsoft Learn, Agent 365 get-started: https://learn.microsoft.com/en-us/microsoft-agent-365/developer/get-started
- Wirken external consumers (hook surfaces): [`docs/external-consumers.md`](../external-consumers.md)
- Wirken security properties: [`docs/security-properties.md`](../security-properties.md)
- Wirken SIEM forwarder: [`docs/siem-forwarder.md`](../siem-forwarder.md)
