# Design: on-behalf-of identity for downstream calls

Status: proposal, not shipped behavior. Nothing described below is implemented. This note describes a gap in downstream identity propagation and sketches a direction; it does not describe current behavior.

## Problem

When an agent acts on a downstream system through a dedicated connector identity, the human who triggered the action is lost at the connector boundary. The downstream sees the connector's identity (a service account, an API key, a vault-held credential) and not the person whose message set the action in motion. For audit and least-privilege, that is a loss: the downstream cannot attribute the call to a principal, cannot apply that principal's authorization, and cannot record who really acted.

## Current state

Wirken carries a human sender identity partway through the chain and then stops.

`sender_id` (the platform-side sender: a Telegram user id, a Slack uid, the literal `webchat-user`) is present on the inbound and tool-facing audit variants: `UserMessage` (`crates/audit/src/session_log.rs:433`), `AssistantToolCalls` (`:459`), and `ToolResult` (`:476`). So an operator reading the audit chain can see which human drove a tool round.

Propagation stops at the large language model (LLM) and credential boundary. `LlmRequest` (`crates/audit/src/session_log.rs:512-522`) and `LlmResponse` (`:541-583`) carry `agent_id` and `credential_id` but no `sender_id`. The credential-bearing call identifies the agent and the vault slot the key came from; it does not identify the human. Nothing on the wire to the provider, or to any system reached with a vault-held credential, carries the originating principal. The connector identity is the whole identity the downstream sees.

## Proposed direction

Adopt a token-exchange pattern so a downstream call can carry two identities: the connector (what holds the credential) and the human principal (on whose behalf the call is made).

- Follow RFC 8693 (OAuth 2.0 Token Exchange): the gateway exchanges the human principal's identity for a downstream token that names both the acting party and the principal, rather than presenting only the connector credential.
- Present dual identity on the downstream call: the connector as the actor, the human as the subject, so the downstream can log both and apply the principal's authorization where it supports delegated access.
- Thread the principal through the call path the same way `sender_id` already reaches the tool variants, extending it to the credential-bearing egress that today carries only `credential_id`.

This keeps the connector model (agents hold scoped, vault-backed credentials) and adds the missing subject, rather than replacing connector identities with per-user credentials.

## Open questions

- **Downstream support.** Token exchange and on-behalf-of flows require the downstream to accept a delegated token. Systems that only take a static API key cannot consume dual identity; for those, the connector identity plus an audited `sender_id` on the egress row may be the most that is achievable.
- **Principal shape.** `sender_id` is a platform-scoped id (Telegram user id, Slack uid), not a federated identity. Mapping it to a principal the downstream recognizes needs an identity source; the raw platform id is unlikely to be meaningful downstream.
- **Trust boundary.** The gateway would mint or exchange tokens carrying a human principal, making it a delegation authority. That is a larger trust role than holding connector credentials, and needs its own threat model.
- **Non-adapter callers.** CLI, cron, and subagent recursion have no `sender_id` (it is `None` for those paths today). A dual-identity call from an unattended context has no human principal to carry.
- **Audit shape.** Whether the principal joins the existing `LlmRequest` / `LlmResponse` and egress rows as a new field, or rides a separate delegation event.
