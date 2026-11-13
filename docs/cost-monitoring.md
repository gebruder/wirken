# Cost monitoring

Wirken records the cost of every large language model (LLM) call on the audit chain. This page covers what is metered, how to forward it to a security information and event management (SIEM) system, and how to query per-agent spend. It is a metering surface, not a billing system.

## What is metered

Every LLM call appends an `llm_response` row (`SessionEvent::LlmResponse`) to the session's audit chain. The row carries token counts, latency, and per-call cost, keyed by the agent and the credential that made the call. No prompt or completion text is on the row; cost monitoring reads accounting fields only.

Fields on each `llm_response` row (`crates/audit/src/session_log.rs:857-904`):

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

`LlmResponse` is excluded from typed SIEM forwarding by default, along with `LlmRequest`, because token accounting is noise for most detections (`crates/audit/src/siem_typed.rs:105-135`, `should_forward`). To forward it, set `typed_include_variants` in `siem.json`.

`typed_include_variants` is a full allowset, not an addition to the defaults: when it is set, only the variants it lists are forwarded and the default set is ignored (`crates/audit/src/siem_typed.rs:107-110`). To keep the default detection feed and add cost rows, list the default-forward set plus `llm_response`:

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
        "permission_grant_expired",
        "permission_grant_pruned",
        "skill_permission_denied",
        "subagent_spawned",
        "subagent_session_bound",
        "exec_location_disagreement",
        "binary_installed",
        "subagent_result",
        "chain_head",
        "mcp_entry_verified",
        "mcp_entry_refused",
        "mcp_server_sandboxed",
        "mcp_server_unsandboxed",
        "mcp_server_exited",
        "mcp_server_restart",
        "mcp_server_restart_abandoned",
        "mcp_credential_refetched",
        "leak_refused",
        "egress_hook_dispatched",
        "tool_output_redacted",
        "budget_exceeded",
        "sandbox_egress_verdict",
        "sandbox_egress_unsupported",
        "exec_runtime_at_start",
        "exec_runtime_unavailable",
        "memory_entry_written",
        "cross_channel_memory_read",
        "import_started",
        "import_completed",
        "imported_chat_read",
        "imported_chat_searched",
        "adapter_connect",
        "adapter_disconnect",
        "adapter_restart",
        "adapter_restart_abandoned",
        "llm_response"
    ]
}
```

The thirty-nine entries above `llm_response` are the default-forward set (`should_forward` in `crates/audit/src/siem_typed.rs`); drop any you do not want, and dropping one stops forwarding it. `LlmResponse` rows carry no message bodies, so forwarding them adds per-call token and cost accounting to the feed, not personally identifiable information (PII).

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

## Enforcement

Metering answers "what did each agent spend"; enforcement caps it. A per-agent budget sets a ceiling over a fixed calendar window and, on breach, alerts or blocks the next call. A budget can hold two ceilings: one in USD, and one in [model time](#model-time), which bounds an agent on a provider with no price. Enforcement is off by default and never activates on upgrade; alert is the recommended starting posture.

### Modes

- **off** (the default): no enforcement.
- **alert**: when the window reaches a ceiling, emit a `budget_exceeded` audit event once per window for that ceiling and let the call proceed.
- **block**: when the window reaches a ceiling, emit a `budget_exceeded` event and refuse the call. The refusal returns a plain channel message (that the agent has reached its spending limit, or its model-time limit, for the window), not a silent failure. A block can end a turn midway: the check runs before every model call, so a turn that reaches the ceiling between two tool rounds stops there with that message. The check runs before the `LlmRequest` is written, so a block never leaves an orphaned request on the chain: every `LlmRequest` has a paired `LlmResponse` or a call error, never a budget block between them.

Spend is read from `total_cost_usd_micros` (the same precomputed field the metering queries use) and accumulated, with model time beside it, in a durable per-agent ledger (`budget.db`) keyed by the base agent id, so it aggregates across an agent's channels and conversations and survives a gateway restart. A sub-agent's calls are checked and charged against the budget of the agent at the top of its spawn chain, at any depth; the child's own `budget.json` entry applies only when that agent is addressed directly.

### Model time

`ceiling_model_seconds` caps the wall-clock seconds an agent's model calls take in the window. The gateway times each call itself, from sending the request to the end of the response, the interval the `llm_response` row records as `latency_ms`. Nothing is needed from the provider: a model with no price, or one that reports no token usage, is timed like any other. This is the ceiling to set for a local model.

- **What is charged.** Every model call the agent makes while its budget sets this ceiling: a turn's calls, a compaction summary, a call that failed or timed out (for the time it took to fail), and a call cut off with its turn, as a sub-agent's wall-clock limit does. Under a budget with no model-time ceiling nothing is timed into the ledger, so adding the ceiling starts the count from that point.
- **What it gates.** Model calls. A costed MCP tool call spends USD and no model time, and is not refused by this ceiling.
- **Overshoot.** The check runs before a call and the charge lands after it, so the call in flight when the window crosses the ceiling completes. One call can run up to the 300-second request timeout.
- **What the number includes.** Wall-clock time as the gateway sees it: time the provider spent loading the model and time the request waited behind other clients of the same server count. On a shared model server, contention is charged to the agent that waited.
- **Plan sign-in.** A plan call can be timed, so a budget that sets only `ceiling_model_seconds` holds for an agent in plan mode. A block-mode budget with a USD ceiling still refuses a plan agent's calls outright, as below.
- **On the record.** A `budget_exceeded` row for this ceiling carries `model_time` with `window_model_seconds` and `ceiling_model_seconds`. Its USD fields hold the window's USD spend and the USD ceiling, `0` where the budget sets none, and are not what was reached. A row for the USD ceiling has no `model_time` and is written as it was before this ceiling existed. When both ceilings are reached under block mode, the one row written is the USD row. A query or detection that reads `budget_exceeded` as a USD breach should leave out rows that carry `model_time`.

### Configuration

Budgets live in `budget.json` in the data directory: a global `default` applied to every agent, plus per-agent overrides keyed by agent id.

```json
{
    "default": { "mode": "alert", "ceiling_usd_micros": 5000000, "window": "day" },
    "agents": {
        "work": { "mode": "block", "ceiling_usd_micros": 10000000, "window": "day" },
        "local": { "mode": "block", "ceiling_model_seconds": 3600, "window": "day" },
        "scratch": { "mode": "off", "ceiling_usd_micros": 0, "window": "day" }
    }
}
```

`window` is `hour`, `day` (the default), or `week`; `ceiling_usd_micros` is USD micros (1 USD = 1,000,000); `ceiling_model_seconds` is whole seconds of model time. An entry may set either ceiling or both, and each is checked on its own. An entry that omits `ceiling_usd_micros` has no USD ceiling; an `alert` or `block` entry that sets neither ceiling is refused at gateway start, by name. A per-agent entry overrides the default, and an explicit per-agent `"mode": "off"` opts a single agent out even when a global default is set. An absent `budget.json` means no enforcement.

### Fail-closed and the uncosted-provider gap

In block mode, a ledger error (the spend ledger cannot be read) fails closed: the call is refused and a `budget_exceeded` event is written. In alert mode a ledger error is logged and the call proceeds, because alert's contract is non-blocking.

At gateway start the posture is the same. If `budget.db` cannot be opened while any block-mode budget is configured, the gateway refuses to start, so a wedged ledger file cannot silently convert block into off. If only alert-mode budgets are configured, startup continues but emits a `budget.control_offline` audit event (on the audit chain, so a SIEM or dashboard sees the control is down), not just a stderr warning. A present-but-malformed `budget.json` is a hard startup error for the same reason.

A call whose (provider, model) pair is absent from the pricing table records no cost, so it does not advance the USD ledger. The USD ceiling is blind to it: a USD block plus a costless provider is no protection. Set `ceiling_model_seconds` for such an agent; that ceiling does not depend on a price. The first uncosted call in a session whose budget sets a USD ceiling logs a warning that the USD ceiling is pass-through for that provider, and says whether a model-time ceiling still applies or names the key to set. Keep the pricing table current for the models you meter in USD.

An agent in plan mode (`"auth": "plan"`, see [configuration.md](configuration.md#providerjson)) is never priced: its `llm_response` rows carry token counts and null cost fields, whatever the pricing table lists for the same model at the API. A block-mode budget with a USD ceiling therefore refuses each of its calls before the request row, writes a `budget_exceeded` row with action `blocked`, and returns an error that names the budget (`budget.json` `agents.<id>` or the default) and says plan requests cannot be priced. An alert-mode budget does not refuse it, and neither does a block-mode budget that sets only `ceiling_model_seconds`. The plan's own usage limits are set and shown at https://chatgpt.com/settings/usage.

## Boundary

Wirken meters the LLM traffic it routes through Wirken. It does not meter a vendor's software-as-a-service (SaaS) seat usage, a subscription plan, or spend from calls made outside Wirken. `total_cost_usd_micros` is derived from the baked pricing table (`crates/audit/src/pricing.toml`), so it is an estimate at those rates, not a reconciled invoice. Treat it as an operator-side view of routed-through-Wirken spend, useful for attribution and anomaly detection, not as a billing record.

## Related

- Pinning the model that cost is metered against is operator config, not a chat setting. See [Model governance](enforcement-model.md#model-governance); model pinning and these cost rows are one control pair.
- The per-agent cost-anomaly detection built on these fields ships in the wirken-siem repo as detection 9; the per-agent budget-breach detection ships as detection 10.
- Variant forward and exclude policy: [SIEM forwarder](siem-forwarder.md).
