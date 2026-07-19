# Design: per-agent budget enforcement (superseded)

Status: shipped. This proposal has been implemented; it is no longer a design note.

The behavior lives in [Cost monitoring: Enforcement](../cost-monitoring.md#enforcement): a per-agent ceiling over a fixed calendar window, `off` / `alert` / `block` modes, a durable spend ledger keyed by the base agent id, the `budget_exceeded` audit event, fail-closed on ledger errors, and the uncosted-provider gap. Configuration is `budget.json` (see [Configuration](../configuration.md#budgetjson)). The matching SIEM detection ships in the wirken-siem repo as detection 10.

This file is kept as a redirect so existing links resolve.
