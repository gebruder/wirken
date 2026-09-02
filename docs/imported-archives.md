# Imported archives

Wirken can import a data export from a hosted assistant account and
keep it as a local, read-only record. You can read it in the web UI,
and your agent can read and search it when you approve each access.

An import is not a restore. Nothing you import becomes a live
conversation. Imported records are sealed history: the store never
writes to them after import, the web view has no way to send to them,
and the agent reaches them only through two tools that ask you first.
Continuing a past thread means starting a new conversation with your
agent and letting it read the old one under your approval.

## Getting the export

The export is requested from your claude.ai account settings. It covers
the whole account rather than a single conversation or project. It
arrives as an emailed download link, and the link expires, so download
it before it does.

What you download is a zip of JSON files at the top level. Wirken reads
two of them, `conversations.json` and `projects.json`. The rest stay in
the archive untouched.

## Running the import

Point `wirken import` at the zip:

```
wirken import ~/Downloads/data-export.zip
```

```
Import store: /home/you/.wirken/imported.db
Migrations applied this run: 5
Source: src-e1f37ece-6edf-429f-bd24-2bd360cb7b24 account=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
Archive: 878d37bfa0758de5c6bfe42596699952ab3ab311ad68bfc749ba580180991e8f
Conversations: added=5 updated=0 unchanged=0 unorderable=0 skipped=2
Projects: added=3 updated=0 unchanged=0 unorderable=0 skipped=1
Stored: conversations=5 messages=10 projects=3 project_docs=3
```

### Sealing

Add `--sealed` when the account the archive came from is closed:

```
wirken import ~/Downloads/data-export.zip --sealed
```

The last line then reads:

```
This source is sealed and will refuse further imports.
```

Sealing is final. A sealed source rejects every later import, whatever
archive you present:

```
Error: source 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' is sealed and refuses further
imports. It was declared a closed account when it was first imported, so its
records are final. There is no unseal; importing a different archive means a
different source account.
```

There is no unseal. An archive from a different account is a different
source and imports on its own terms.

### Live sources

Without `--sealed` the source stays live and accepts later exports from
the same account. Re-importing matches records by their identity in the
archive. Where the incoming record is a newer snapshot, it replaces the
stored conversation whole. Presented with the archive it already holds,
a live source does nothing:

```
This archive is already imported. Nothing to do.
  conversations=5
```

A later export of the same account updates what changed:

```
Conversations: added=0 updated=1 unchanged=4 unorderable=0 skipped=2
Projects: added=0 updated=0 unchanged=3 unorderable=0 skipped=1
```

### The counts

**added** is a record the store did not have.

**updated** is a record the store had, where the incoming one is newer
and replaced it.

**unchanged** is a record the store had, where the incoming one is not
newer and nothing was written.

**unorderable** is a record whose timestamps could not be compared with
the stored one, so nothing was written and the stored record was left
alone. The run says so:

```
1 records could not be ordered against what is stored and were left alone. A whole
archive here means the export's timestamp format has changed.
```

**skipped** is a record that did not match the shape the importer
parses. Each skip is logged with the record's identifier where it has
one. The rest of the archive still imports.

## What is stored and what is not

Message text is stored.

Attachment text is stored, including the text of files that arrived as
attachments.

Projects are stored, with their documents.

Each message's structured content blocks are stored exactly as they
arrived in the archive, byte for byte. The views and the agent's read
tool do not render them.

The archive's user roster file is not imported.

Project creator names are not imported. A project's creator is stored
as an identifier only.

The archive's memory entries are not imported.

## Viewing archives

The web UI sidebar has an **Archives** section below your sessions. It
lists each imported source, then that source's conversations, then one
conversation at a time.

An archive view is read-only. The composer is replaced by a notice:

```
Imported archive: a stored record, shown read-only. There is nothing to send to here.
```

Beside the notice is a **Back to the live session** button, which
returns you to the conversation you were having.

A message the store holds no text for is labelled rather than drawn
blank:

```
no text stored for this message
```

That label means the archive carried no text for that message, in
either the message's own text field or its content blocks. Real
archives contain these. Where such a message has an attachment, the
attachment still shows its content.

Where a message has content blocks the view does not render, it says
how many:

```
stored content blocks are not shown here.
```

## The agent and your archive

Your agent has two tools for imported archives:

- `read_imported_chat` reads one conversation.
- `search_imported_chats` searches for a term.

Every call to either one asks you first. Both are Tier 3, which always
prompts. There is no setting that makes them stop asking, and approving
one call does not approve the next.

The prompt arrives as a card in the web UI. Its fields:

```json
{
  "type": "approval_request",
  "request_id": "c85418bf-9acf-45b0-9c5a-68c1404cf7e7",
  "tool_name": "read_imported_chat",
  "action_key": "imported_chat:src-e1f37ece-6edf-429f-bd24-2bd360cb7b24",
  "requested_tier": "tier3",
  "triggering_agent": "default/webchat/webchat-default",
  "trigger_message": "look through my imported archive"
}
```

`action_key` names what you are being asked about. `trigger_message` is
the message of yours that led the agent here. The card carries Approve
and Deny, and a box for a reason recorded on a denial.

A search can be scoped to one source or run across every source you
have imported. These are separate approvals with separate keys:

```
imported_chat:<source>          reading one conversation from that source
imported_search:<source>        searching within that source
imported_search_corpus          searching across every imported source
```

Approving a search of one archive does not approve a search of all of
them.

## Search

Search covers message text, attachment text, and project documents.

It does not cover the stored content blocks.

Results are bounded. Each hit is a short window of text around the
match, and a search returns a limited number of hits. A search is not a
way to read a conversation; reading one is the other tool, with its own
approval.

Every search is recorded with one of three outcomes, and each means
only itself:

- **hits**: the search ran and matched.
- **empty**: the search ran and matched nothing.
- **refused**: the search did not run. A malformed query lands here.

An empty result means the term is not in what was searched. A refused
result means nothing about the corpus at all.

## Sandbox and egress

Reading or searching an archive marks the session as having seen
imported content.

That mark restricts one outbound path: network egress from a sandboxed
`exec`. On a channel with an allowlist egress policy, an `exec` that
tries to reach the network after the session has read an archive
prompts you for the destination. The prompt names the basis. The
decision is recorded with the basis on it.

That mark does not restrict the `http_request` tool, the `web_search`
tool, or what your agent writes back to you in chat. An agent that has
read an archive can repeat its contents in a reply, and nothing here
stops that. Issue #230 tracks `http_request`.

## Operational notes

**The query digest needs an unlocked vault.** Search records a keyed
digest of the query instead of the query text. The key is loaded at
gateway start. If the vault is locked then, searches still run and
their records carry no digest. The audit log records that this
happened, so a record without a digest can be traced to a start that
said why. Unlock the vault at start to get digests.

**The default sandbox image ships no HTTP client.** An `exec` asked to
fetch a URL with a common client tool will not find one unless
`sandbox.json` sets `image` to an image that carries one.

**A search index migration runs on the first start after upgrading.**
It builds the search index over archives imported before the index
existed. `wirken import` prints how many migrations ran. Starting the
gateway does not print anything about it. The store grows by the size
of the index.

## Exports from other assistants

A source records which provider it came from, so archives from
different assistants stay separate and are never merged.

Only the claude.ai export format is parsed today. An archive from
somewhere else is refused rather than partly read.

A zip with no `conversations.json` is refused for not being an export:

```
Error: archive has no conversations.json; it does not look like an export
```

A zip that has the member but whose records are a different shape gets
as far as looking for the account every record is keyed by, finds none,
and stops:

```
Error: no conversation in the archive names an account; the account label is half
of every natural key
```

Skipping applies within an archive that does parse. Individual records
that do not fit are skipped by identifier, counted, and the rest of the
archive imports.

Two tools under `scripts/` exist for characterizing a format that has
no parser yet. `anthropic-export-schema.py` reports an archive's
structure. `anthropic-export-message-fields.py` reports which fields
one message carries and which of them the importer reads. Both print
shapes and sizes rather than content, so their output can be shared
while deciding whether a format is worth parsing.
