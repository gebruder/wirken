# Design: on-behalf-of identity for downstream calls

Status: Part A (audit-chain attribution) is shipped as of 1.12.0. Part B (a delegated token on the downstream wire) is a proposal, not shipped behavior, and nothing in Part B is implemented, not even a trait or feature flag, until an external security token service (STS) is chosen.

## Problem

When an agent acts on a downstream system through a dedicated connector identity, the human who triggered the action is lost at the connector boundary. The downstream sees the connector's identity (a service account, an API key, a vault-held credential) and not the person whose message set the action in motion. For audit and least-privilege, that is a loss: the downstream cannot attribute the call to a principal, cannot apply that principal's authorization, and cannot record who really acted.

The problem has two layers: attribution on Wirken's own audit chain, and identity on the wire to the downstream. Part A addresses the first; Part B addresses the second.

## Part A: audit-chain attribution (shipped)

`sender_id` (the platform-side sender: a Telegram user id, a Slack uid, the literal `webchat-user`) now rides the LLM call boundary. Alongside the inbound and tool-facing rows that already carried it (`UserMessage`, `AssistantToolCalls`, `ToolResult`), the runtime threads it onto `LlmRequest` and `LlmResponse` (`crates/audit/src/session_log.rs`), from the same `current_inbound` identity the sibling rows use. An operator reading the audit chain can now follow the human principal from the inbound message through the credential-bearing LLM call, rather than losing it at `agent_id` / `credential_id`.

`sender_id` is an `Option`, `None` for operator-originated sessions (CLI, cron, subagent recursion), never an empty string. The wirken-siem field index records it on the `LlmResponse` row, and the Sentinel forwarder populates the `SenderId` column from it.

Part A closes the attribution gap on Wirken's own record. It does not change what the downstream sees.

## Part B: delegated identity on the wire (proposed)

The downstream still sees only the connector credential. Nothing on the wire to the provider, or to any system reached with a vault-held credential, carries the originating principal, so the downstream cannot apply that principal's authorization.

Proposed direction, when an STS is chosen:

- Follow RFC 8693 (OAuth 2.0 Token Exchange): the gateway exchanges the human principal's identity for a downstream token that names both the acting party and the principal, rather than presenting only the connector credential.
- Present dual identity on the downstream call: the connector as the actor, the human as the subject, so the downstream can log both and apply the principal's authorization where it supports delegated access.
- This keeps the connector model (agents hold scoped, vault-backed credentials) and adds the missing subject, rather than replacing connector identities with per-user credentials.

No trait or interface for this ships now. A trait would already encode token-model assumptions (subject and actor token types, audience) that differ across Okta, Entra, and SPIFFE, so it stays doc-only until the STS decision is made.

## Open questions (Part B)

- **Downstream support.** Token exchange and on-behalf-of flows require the downstream to accept a delegated token. Systems that only take a static API key cannot consume dual identity; for those, the connector identity plus the audited `sender_id` from Part A may be the most that is achievable.
- **Principal shape.** `sender_id` is a platform-scoped id (Telegram user id, Slack uid), not a federated identity. Mapping it to a principal the downstream recognizes needs an identity source; the raw platform id is unlikely to be meaningful downstream.
- **Trust boundary.** The gateway would mint or exchange tokens carrying a human principal, making it a delegation authority. That is a larger trust role than holding connector credentials, and needs its own threat model.
- **Non-adapter callers.** CLI, cron, and subagent recursion have no `sender_id` (it is `None` for those paths). A dual-identity call from an unattended context has no human principal to carry.
- **Token model.** The subject and actor token types and the audience differ across identity providers (Okta, Entra, SPIFFE); the exchange interface cannot be fixed until the target is known.
