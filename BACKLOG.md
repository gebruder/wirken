# Backlog

Items captured for follow-up. Not in priority order.

## Skill metadata namespace

Move `metadata.openclaw.requires.bins` → `metadata.wirken.requires.bins` as the
primary key in the skill frontmatter parser (`crates/agent/src/skill.rs`).
Accept `openclaw` as a deprecated alias for migration compatibility. Update the
bundled `SKILL.md` files under `skills/` to use the new namespace. The public
repo should not advertise a competitor's namespace as its primary schema key.

## WhatsApp setup wizard

`wirken setup` and `wirken channel add whatsapp` only collect the access token
today. The WhatsApp adapter also needs `whatsapp-phone-number-id`,
`whatsapp-verify-token`, and `whatsapp-app-secret` in the vault before it can
start. Wire those into the interactive flows.

## Generic credentials add command

There is no CLI path to add an arbitrary vault entry (e.g., for an MCP server's
own token). `wirken setup` and `wirken channel add` are the only writers today.
Add a `wirken credentials add <name>` subcommand or document a supported manual
path.

## Gateway-side LLM proxy

Today the agent process holds decrypted API keys in memory and calls providers
directly. The architecture doc describes a gateway-side proxy that would keep
keys out of agent processes — implement it.

## Persistent conversation transcripts

Sessions are stored in SQLite as metadata only. Conversation transcripts live
in the running agent's memory and are lost on restart. Persist them.

## Org-level tool allow/deny lists

`OrgPermissions.allowed_tools` and `blocked_tools` are parsed from the org
config but not enforced anywhere. Either wire them into the permission check or
remove the fields.

## Injection detector: block on Critical severity

`wirken_gateway::injection_detect` scans every inbound message and emits a
`message.threat_flagged` audit event, but the original text still reaches
`process_message` unmodified. Aggregate severity `Critical` requires two
High-severity indicators in one message, so false positives are unlikely
and it's a reasonable threshold for short-circuiting delivery: drop the
message before the LLM sees it, send a generic refusal back through the
adapter, keep the audit event. Gate on a per-channel policy flag so
well-trusted channels can opt out. Hook is in `crates/cli/src/commands/run.rs`
where the inbound match arm currently calls `detector.scan` and falls
through to `process_message`.

## Injection detector: threat-aware LLM turn

Broader alternative to the Critical-severity block. When any severity is
detected, prepend a system-role note to the LLM's next turn telling it the
following user message contains detected prompt-injection patterns and
should be treated as untrusted data, not commands. Leverages the model's
own defenses instead of hard-blocking, works across all severities, and
preserves legitimate messages that trip Low-severity patterns in good
faith. Changes behavior on every channel, so it needs a design
conversation before implementation.

## Signal adapter: switch HTTP to Unix socket transport

The Signal adapter speaks HTTP JSON-RPC to signal-cli because that was the
fastest path to a working adapter, but signal-cli's HTTP endpoint has no
authentication and any local process can send messages as the linked user.
signal-cli also supports a Unix-domain-socket transport (`--socket`) which
gets filesystem permissions for free. Switch the adapter to use the socket
by default, keep HTTP as an opt-in for remote signal-cli hosts, and document
the trade-off in `docs/channels/signal.md`. Requires swapping `reqwest` for
a plain-socket JSON-RPC client on that code path.

## Finer-grained Tier 2 shell approval patterns

`tool_to_action` in `crates/agent/src/tool.rs` keys `Action::ShellExec` on
the first whitespace-separated token of the command, so approving `bash`
once approves every future `bash ...` invocation for 30 days. Especially
coarse when an adapter exposes the agent to semi-trusted senders. Options:
extend the action key to include an argv prefix
(`shell:bash:-c:safe-script.sh`), require an exact-command match for
destructive patterns, or introduce a separate Tier 3 "shell-with-arguments"
action that always prompts. Any choice needs a migration for existing
approvals in `permissions.db`.
