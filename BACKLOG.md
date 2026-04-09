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
