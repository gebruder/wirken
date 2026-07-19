# Cost monitoring

Wirken records the cost of every large language model (LLM) call on the audit chain. This page covers what is metered, how to forward it to a security information and event management (SIEM) system, and how to query per-agent spend. It is a metering surface, not a billing system.

## What is metered

Every LLM call appends an `llm_response` row (`SessionEvent::LlmResponse`) to the session's audit chain. The row carries token counts, latency, and per-call cost, keyed by the agent and the credential that made the call. No prompt or completion text is on the row; cost monitoring reads accounting fields only.

Fields on each `llm_response` row (`crates/audit/src/session_log.rs:541-583`):

| Field | Meaning |
|-------|---------|
| `agent_id` | Agent whose runtime made the call. |
| `credential_id` | Vault slot name the API key resolved from. Absent when the key was passed directly (raw value in `provider.json`, environment override). Never the secret. |
| `input_tokens` / `output_tokens` | Prompt and completion token counts from the provider usage block. |
| `cache_creation_input_tokens` / `cache_read_input_tokens` | Anthropic prompt-cache counters; zero for other providers. |
| `latency_ms` | Wall-clock latency of the call. |
| `input_cost_usd_micros` / `output_cost_usd_micros` | Per-call input and output cost in USD micros (1 USD = 1,000,000 micros), floor-rounded from a baked pricing table keyed by (provider, model). |
| `total_cost_usd_micros` | `input_cost_usd_micros + output_cost_usd_micros`, computed once at emit time. |

Prefer `total_cost_usd_micros` over summing the two operands yourself. It is computed once from the same pricing table, so a query that reads it does no arithmetic and cannot double-round. The three cost fields are absent when the (provider, model) pair is missing from the pricing table; `total_cost_usd_micros` is absent exactly when either operand is absent, so summing input and output would only ever match the total or propagate a null. A call whose model is not in the pricing table records tokens and latency but no cost, so it is invisible to spend queries; the gateway logs a warning at emit time so a stale binary against a new model is visible.

Cost is metered per `agent_id` and per `credential_id`, so spend attributes to a specific agent or a specific credential. The pricing table is `crates/audit/src/pricing.toml`, compiled into the binary at build time; cost reflects that table's rates, not an invoice.

## Forwarding cost rows to a SIEM

`LlmResponse` is excluded from typed SIEM forwarding by default, along with `LlmRequest`, because token accounting is noise for most detections (`crates/audit/src/siem_typed.rs:74-83`). To forward it, set `typed_include_variants` in `siem.json`.

`typed_include_variants` is a full allowset, not an addition to the defaults: when it is set, only the variants it lists are forwarded and the default set is ignored (`crates/audit/src/siem_typed.rs:92-94`). To keep the default detection feed and add cost rows, list the default-forward set plus `llm_response`:

```json
{
    "target": "splunk",
    "endpoint": "https://your-splunk:8088/services/collector/event",
    "api_key": "your-hec-token",
    "service": "wirken",
    "environment": "production",
    "typed_include_variants": [
        "assistant_tool_calls",
        "tool_result",
        "http_fetch",
        "permission_denied",
        "skill_permission_denied",
        "subagent_spawned",
        "subagent_result",
        "chain_head",
        "mcp_entry_verified",
        "mcp_entry_refused",
        "egress_hook_dispatched",
        "tool_output_redacted",
        "llm_response"
    ]
}
```

The twelve entries above `llm_response` are the default-forward set (`crates/audit/src/siem_typed.rs:95-109`); drop any you do not want, and dropping one stops forwarding it. `LlmResponse` rows carry no message bodies, so forwarding them adds per-call token and cost accounting to the feed, not personally identifiable information (PII).

## Per-agent daily spend queries

Both queries sum `total_cost_usd_micros` by `agent_id` over a day and convert micros to USD. Rows with no cost (model absent from the pricing table) contribute nothing.

### Splunk

```
`wirken_session_event` event.event.kind="llm_response" earliest=-1d@d latest=@d
| eval cost_micros = 'event.event.total_cost_usd_micros'
| where isnotnull(cost_micros)
| eval agent_id = 'event.event.agent_id'
| stats sum(cost_micros) as micros by agent_id
| eval usd = round(micros / 1000000.0, 2)
| sort - usd
```

`wirken_session_event` is the base macro shipped in the wirken-siem repo (`splunk/macros.conf`); it selects `sourcetype="wirken:session"` and lifts the nested event fields so `event.event.*` paths resolve.

### Datadog

Define a log-based metric `wirken.llm.cost_usd_micros` over `@ddsource:wirken @wirken.kind:llm_response` with measure `@wirken.event.total_cost_usd_micros`, tagged by `agent_id` from `@wirken.event.agent_id`. Then query daily spend per agent:

```
sum:wirken.llm.cost_usd_micros{*} by {agent_id}.rollup(sum, 86400) / 1000000
```

The `/ 1000000` converts USD micros to USD.

## Boundary

Wirken meters the LLM traffic it routes through Wirken. It does not meter a vendor's software-as-a-service (SaaS) seat usage, a subscription plan, or spend from calls made outside Wirken. `total_cost_usd_micros` is derived from the baked pricing table (`crates/audit/src/pricing.toml`), so it is an estimate at those rates, not a reconciled invoice. Treat it as an operator-side view of routed-through-Wirken spend, useful for attribution and anomaly detection, not as a billing record.

## Related

- Pinning the model that cost is metered against is operator config, not a chat setting. See [Model governance](enforcement-model.md#model-governance); model pinning and these cost rows are one control pair.
- The per-agent cost-anomaly detection built on these fields ships in the wirken-siem repo as detection 9.
- Variant forward and exclude policy: [SIEM forwarder](siem-forwarder.md).
