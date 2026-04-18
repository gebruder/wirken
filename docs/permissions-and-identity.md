# Permissions and Identity

How Wirken maps platform user identity to authorization decisions. This doc is split into two sections: **What exists today** describes current code behavior, **Planned** describes the intended direction that is not yet implemented.

If you are deploying Wirken for a team, read both sections before designing your authorization model. The gap between them is load-bearing.

## What exists today

### Three-tier permission model, scoped per agent

Every tool action falls into one of three tiers:

- **Tier 1, always allowed.** Workspace file access, channel converse, web search.
- **Tier 2, first-use approval with a 30-day expiry.** Shell exec (per pattern), external file access (per path), cross-conversation message.
- **Tier 3, always prompt.** Destructive file operations, network requests (per domain), credential access, cron create, skill install.

Approvals are stored in `~/.wirken/permissions.db` keyed on `(action_key, agent_id)`. The `action_key` is derived from the action variant: for example, a `ShellExec { pattern: "kubectl *" }` approval stores `shell:kubectl *` against the agent that requested it.

`wirken permission list --agent work` prints all approvals for an agent. `wirken permission revoke <key> --agent work` removes one.

### Platform sender identity is audited, not authorized

Each channel adapter extracts the platform sender identity on every inbound message and forwards it to the gateway over the IPC frame:

- **Slack**: `user_id` (e.g., `U04ABCD9`).
- **Teams**: Bot Framework activity sender id. The `tenant_id` is also captured in the message metadata JSON.
- **Matrix**: MXID (e.g., `@alice:matrix.example.com`).

The gateway writes this to the audit log as the `actor` field of the `message.inbound` event. The full event carries actor, action, target, channel, conversation id (as session), and a detail payload.

The sender id does not flow into the permission check. Permission lookups key on `(action_key, agent_id)` only. Consequence: **a Tier 2 approval granted when any user on a channel first triggers an action applies to every user on that channel until the approval expires.** If Alice first runs a `shell:terraform apply` pattern on Slack and approves it, Bob gets the same tool-call approval without being prompted, for 30 days.

This is a real gap if the deployment uses one shared agent across a team. Workarounds today:

- Run separate agents per sensitive user and bind them to per-user conversations (requires manual routing, not intended as a primary model).
- Keep high-blast-radius actions at Tier 3 so every invocation prompts, regardless of prior approval.

### Sub-agent ceilings

When a parent agent is allowed to spawn a child via `spawn_subagent`, the parent's registration declares a `SubagentCeiling` per allowed child:

- `tool_allowlist`: child only sees tools in this list. Intersected with whatever the LLM passes in the spawn call. Anything outside is dropped.
- `max_permission_tier`: child's tools above this tier are auto-denied. No interactive approval flow (children run headless).
- `max_rounds`: max LLM rounds before the parent reports `rounds_exceeded`.
- `max_runtime_secs`: wall-clock timeout.

The LLM cannot widen these caps. The parent's harness intersects, clamps, and enforces. Configure via:

```bash
wirken agents allow-subagent parent child --tools "read_file,web_search" --max-tier tier1 --max-rounds 5 --max-runtime 30
```

The ceiling is stored as JSON in the `agents.allowed_subagents` column.

### Org-level tool policy (partially enforced)

The pulled org config (`wirken setup --org <url>`) deserializes `permissions.allowed_tools`, `permissions.blocked_tools`, and `permissions.sandbox_mode` into `OrgPermissions`. Of these:

- `sandbox_mode` is enforced. When present on the pulled config, `apply_org_config` writes `sandbox.json` in the data directory, and `wirken run` re-reads it on every gateway start. Valid values are `off`, `exec-only`, and `gvisor`; unknown values fall back to the default (`exec-only`) with a warning.
- `allowed_tools` and `blocked_tools` are still parsed but not read by the permission check. A config that sets `blocked_tools: ["generate_image"]` will not prevent the agent from invoking `generate_image`. Tracked in `BACKLOG.md` under "Org-level tool allow/deny lists."

### Channel process isolation

Each adapter runs in its own OS process with a distinct ed25519 IPC identity. A compromised adapter can only deliver inbound frames for its own channel and request outbound sends for its own channel. It cannot invoke tools directly, cannot read other channels' sessions through the IPC surface, and cannot request other channels' credentials through the IPC surface.

Process isolation is not credential ACL. The vault itself does not enforce per-process access: a process with access to `~/.wirken/vault.db` and the device key can retrieve any credential by name. The isolation is that adapters are spawned with a narrow retrieval pattern (only entries named `{channel}-*`) and run under the wirken daemon's boundary.

## Planned

These items are not implemented. They are documented here so deployers can plan around them. No timeline is promised.

### Per-user permission scoping

Permission approvals would key on `(action_key, agent_id, principal_id)`, where `principal_id` is a Wirken-internal identifier that the platform sender id resolves to. Alice approving `shell:kubectl *` would not approve it for Bob.

Open design questions: how the principal is named (platform id, an internal UUID, both), how a new sender on a channel is introduced, how revocation propagates.

### Per-channel scoping within an agent

Permission approvals would key on `(action_key, agent_id, channel)`. An agent bound to both `slack` and `matrix` would not have its Slack approvals leak to Matrix.

### Role-based access control

Named roles (`admin`, `approver`, `user`) with per-role tier caps. Admin users could approve Tier 3 actions on behalf of others without triggering an interactive prompt for every invocation.

### Platform-to-principal identity mapping

A configurable mapping from `(channel, platform_id)` to an internal principal. For example, `(slack, U04ABCD9)` and `(matrix, @alice:example.com)` both resolve to principal `alice`. Permissions and audit records would be attributed to `alice` across channels.

### Attestation workflow

`SessionEvent::Attestation` already carries an ed25519 signature over the per-session chain head. Two pieces are not yet in place: a CLI command to emit attestations on a schedule, and a documented external verifier workflow against a published signing key.

### IdP / SSO integration

Not planned in the short term. Wirken is not an IdP and is not intended to become one.
