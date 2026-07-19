# Design: per-agent budget enforcement

Status: proposal, not shipped behavior. Nothing described below is implemented. Wirken today meters cost but does not enforce a limit; this note sketches what enforcement would look like if added.

## Problem

Wirken records per-call cost on every `llm_response` row (see [Cost monitoring](../cost-monitoring.md)) and can forward it to a security information and event management (SIEM) system, where the cost-anomaly detection (wirken-siem detection 9) alerts on a spend spike. That is metering plus detection: it tells an operator, after the fact, that an agent spent more than its baseline. It does not stop the spend. A compromised skill, a runaway retry loop, or a prompt-injection that turns an agent into a token pump keeps calling the provider until an operator reads the alert and intervenes by hand. The gap is a control, not a signal: a way to cap what an agent can spend before the money is gone.

## Proposed control

A per-agent cost ceiling, evaluated in the agent runtime before each large language model (LLM) call:

- A budget is configured per agent (for example, a rolling USD-per-window ceiling), alongside the existing per-agent `LlmConfig`.
- The runtime tracks spend per agent over the window, summing `total_cost_usd_micros` from the rows it already emits.
- On the next call that would cross the ceiling, the runtime takes a configured action:
  - **block**: refuse the call, surface a typed error to the agent, and append an audit row recording the refusal.
  - **alert**: allow the call but emit a distinct audit event so a SIEM rule can escalate immediately rather than waiting for the rolling-window detection to catch up.

Block is the enforcement mode; alert is a softer mode for operators who want a hard signal without failing calls.

## Where it would live

In the agent runtime, at the same pre-call point where the `llm_request` row is already appended (`crates/agent/src/runtime.rs`). That site already has the agent identity, the resolved config, and the cost of prior calls in the same session, so it is the natural place to check a running total against a ceiling and to short-circuit before the provider call goes out. A refusal would ride an audit event so the decision is on the hash-chained record, consistent with how permission denials are logged today.

## Open questions

- **Window and accounting.** Rolling window versus fixed calendar period; per-session, per-agent, or per-credential accounting. Cost attributes to both `agent_id` and `credential_id` today, so either key is available.
- **Spend source of truth.** Summing emitted rows in-process is simple but resets on gateway restart. A durable per-agent counter (SQLite) survives restart at the cost of a write on the hot path.
- **Uncosted calls.** A model absent from the pricing table emits no cost. A budget check must decide whether to fail open (allow, since cost is unknown) or fail closed (block until the model is priced). Fail-open leaks spend; fail-closed breaks any agent on a new model until the pricing table catches up.
- **Multi-agent and subagents.** Whether a child agent draws against its own ceiling, the parent's, or both.
- **Shared credentials.** Two agents on one credential can each stay under their ceiling while the credential's total exceeds any single budget.
