# Design: imported assistant archives

Citations verified against 73dcdd7. They are a record of a check
made against that tree, not a live index: a file that grows moves
every line below the change, and a citation cannot know that. The
repo is authoritative for the live question; these say what was
true when someone looked, and when.

Status: in progress. The store, the archive reader, the parser, the
write path, the audit events, the `wirken import` command, the
read-only web views, the search index, and both gated agent tools are
built. One slice remains open. Tools is open on one condition of four:
the gating and the denial record are closed on chain evidence, the
replay-verifier condition is held by a test rather than an observation,
and the egress condition is runnable rather than deferred, on a rootful
runtime this workstation does have once the sidecar is given a
statically linked binary. Search is closed. Every claim about current
behaviour is settled against the repo and carries a file reference; the
data model is derived from structure extracted from a real archive.

## What this is

An operator holds data-export archives from a hosted assistant account.
This feature imports those archives into a local store, renders them
read-only in the web UI, and exposes them to the agent behind gated
tools.

An archive is a **provenance-scoped dataset**, not an identity. The
account named inside an archive is a label on rows. It does not enter
`FederatedIdentity` (`crates/audit/src/otel_exporter.rs`, re-exported
at `crates/audit/src/lib.rs:25`), which answers a different question:
who this wirken instance is when it forwards telemetry. The separation
already has a precedent in the tree; `crates/audit/src/user_resolver.rs:11-17`
records why resolving a human is kept apart from that machinery.

## Ground this design rests on

Verified in the repo, with references, because several of the claims
below would otherwise be assumptions.

**Storage.** SQLite through `rusqlite`, one database file per concern,
each reached by an accessor on `GatewayConfig`
(`crates/gateway/src/config.rs:44-90`). FTS5 is compiled into the
bundled SQLite this workspace links, confirmed by building against the
workspace dependency line and creating a virtual table, so native
full-text search is available rather than assumed.

**Migration.** The repo carries more than one shape. Core gateway
stores have no versioning: `open()` runs `execute_batch` with
`CREATE TABLE IF NOT EXISTS` (`crates/gateway/src/memory.rs:104-120`),
so a later column addition never reaches a database that already
exists. `wirken-skill-store` carries a real runner:
`SkillStore::migrate` applies migrations by slice index, records them
in a `_migrations` table, and is idempotent
(`crates/skill-store/src/lib.rs:130-163`).

**The permission gate.** `tool_to_action`
(`crates/agent/src/tool.rs:1708`) classifies a tool name into an
`Action`. A `None` return does **not** skip the gate. The runtime maps
`None` to `WasmSkillCall` for a known Wasm skill and otherwise to
`UnknownTool` (`crates/agent/src/runtime.rs:2885-2896`), and both
resolve to Tier 3 (`crates/gateway/src/permissions.rs:255-262`). Tier 3
is always-prompt; it refuses outright only where no approval surface is
reachable. So omitting a classifier arm for a new tool denies it rather
than admitting it ungated.

**Where the gate applies.** Every production entry point attaches a
permission store, so the gate runs on every path this feature is
reachable from (`crates/agent/src/runtime.rs:2873`, field at `:165`).
Enumerated under "Permission attachment" below.

**Confidentiality labels.** `ReadSensitivity`
(`crates/agent/src/tool.rs:1641-1675`) marks what a session has read.
The variants are unordered by construction and `Ord` is deliberately
not derived. `restricts_egress()` is true for every variant except
`AggregatedExternal`. Registration is `tool_to_read_sensitivity`
(`crates/agent/src/tool.rs:1691-1706`); a tool the classifier cannot
place is labelled `Workspace`, the most restricting value
(`crates/agent/src/runtime.rs:2908-2916`).

**Cross-channel memory, the pattern this feature copies.**
`crates/gateway/src/memory.rs` stamps provenance labels `NOT NULL` in
the DDL (`:104-120`), carries them in an `OriginLabels` struct with no
`Default` so a write cannot be constructed without them (`:61-68`), and
refuses a write naming the missing label (`:132-148`). Its read tool is
gated at Tier 3 keyed by the channel read from, so approving one
channel approves no other
(`crates/agent/src/tool.rs:1760`,
`crates/gateway/src/permissions.rs:261,281-283`).

**Audit events.** `SessionEvent` is `#[serde(tag = "kind", rename_all = "snake_case")]`
(`crates/audit/src/session_log.rs:419-421`); additive variants are
forward-compatible. Exactly one registration site is compiler-forced:
`variant_kind` (`crates/audit/src/siem_typed.rs:154-203`) is exhaustive
with no catch-all. Two are silent and must be edited deliberately: the
default-forward list (`crates/audit/src/siem_typed.rs:111-133`) omits a
new variant, and the actor-field extractor
(`crates/audit/src/siem.rs:655`) has a catch-all that yields no
attribution.

## Permission attachment

Every production entry point attaches the permission store. The sole
caller that passes none is the replay verifier.

`wirken run` builds one `AgentFactory` carrying the store
(`crates/cli/src/commands/run.rs:1153`) and clones it to the webchat
server (`:1378`), the cron scheduler (`:1418`), and the adapter accept
loop (`:1512`). The factory attaches it to each agent it wakes
(`crates/agent/src/factory.rs:596-597`). Subagents wake through the same
factory (`crates/agent/src/runtime.rs:3711`) and inherit it; an agent
with no factory bound cannot spawn children at all (`:4083-4089`). The
direct CLI agent paths attach their own
(`crates/cli/src/commands/agent.rs:118,220`), as do the lyrik paths
(`crates/cli/src/commands/lyrik.rs:472,1025`).

`wirken sessions verify` passes none
(`crates/cli/src/commands/session.rs:443`, inside `verify` at `:302`).
It re-executes deterministic read-only tools to check a recorded
transcript against the current workspace and never replays shell exec,
which its own comments state. It is a replay verifier, not an
interactive agent, and the imported-chat tools are not in its tool set.
The tool slice confirms that rather than assuming it.

Whether a bare agent should be constructible at all is out of scope
here and carried as a follow-up.

## Migration runner placement

**Decision: the import store lives in the gateway crate and carries its
own runner there. It does not depend on `wirken-skill-store`.**

The import store is a core store: its path comes from `GatewayConfig`
alongside the others, and it has no skill, no frontmatter, and no
permission profile. `wirken-skill-store` is not a generic migration
crate. Its purpose is path resolution against a skill's declared
write-path allowlist; `SkillStore::open` refuses a path outside that
allowlist and requires a `PermissionProfile`
(`crates/skill-store/src/lib.rs:1-27`). Using it for the import store
would mean fabricating a profile to satisfy `open`, or calling
`migrate` while bypassing the part that carries the crate's reason to
exist.

The dependency graph settles it independently. `wirken-skill-store`
depends on `wirken-agent`, which depends on `wirken-gateway`. A gateway
dependency on `wirken-skill-store` closes a cycle that Cargo rejects.

Lifting the runner into a new shared crate is the move if and when a
third user appears. It is not the move now: a crate extracted for a
second user is shaped by whichever of the two was written first, and
`wirken-skill-store`'s own module doc argues exactly this point about
premature API shape. The runner is small enough that carrying it beside
the store it serves costs less than the coupling.

Migrations are append-only and addressed by slice index. Reordering or
replacing an entry repoints a recorded index at different SQL, which
the skill-store doc already warns about and which applies unchanged
here.

## Data model

Derived from structure extracted locally from the closed-account
archive by `scripts/anthropic-export-schema.py`. That tool emits key
paths, types, nullability, and value shapes, and suppresses values that
are content-shaped or identifying. Its gate has been corrected twice
against real output, once for phone numbers reaching the closed-set
path and once for record identifiers reaching it as the bounds of a
numeric range, so treat it as a control with a record of having been
incomplete rather than as a guarantee.

The reference is the extraction taken with the current gate.
Reconciling the model against a regenerated extraction is done by
running the prior extraction's emitted values back through the current
gate, which distinguishes a newly suppressed value from a changed
field. Reading two outputs side by side does not.

### What the archive holds

Four datasets: conversations, projects, memories, users. Each is a
top-level JSON array except the memories entries, whose
`project_memories` is a map keyed by project uuid rather than a list.

### What is imported, and what is not

**Conversations and their messages are imported.** They are the subject
of the feature.

**`users.json` is not imported.** It carries full names, email
addresses, and phone numbers for many people, not only the account
holder: collaborators, project members, anyone the account touched.
Nothing in viewing or searching conversations needs it, because
`conversations[].account.uuid` already supplies the provenance label
the natural key wants. Importing it would stand up a store of
third-party personal data with no consumer in this feature and put it
behind tools an agent can reach. The file stays in the archive,
unparsed.

**Projects are imported. Memories are deferred.** Both carry
substantive content and neither was in the entity list this design was
first asked for, so both are decided here rather than left implied.
Project documents are the context conversations refer to, and a
conversation view without them is missing what it cites. The memories
entries are the assistant's retained notes about the account holder, a
different kind of artifact, and they want their own provenance
question answered before they are stored.

**A project's creator is stored as an identifier, never a name.** The
archive carries the creator's `full_name` beside their uuid. That is
the same category `users.json` is excluded for, and the same reasoning
applies at a smaller scale: nothing in viewing or searching a project
needs the name, so storing it would put third-party personal data
behind the agent's tools with no consumer. The exclusion is a property
of the parsed type, which has no field for the name, rather than a
rule the insert site has to remember. So a comparison of the parser
against the archive reads as a decision, not a gap.

### Entities

`import_source` carries the provider, the source account, the archive
hash, the import timestamp, and an immutability flag.

`imported_conversation`, `imported_message`, `imported_project`, and
`imported_project_doc` carry provenance columns `NOT NULL` on the
cross-channel memory pattern: source identifier, source account, and
provider on every row, with `imported_message` also carrying its
conversation uuid. A labels struct with no `Default` constructs them,
so a row cannot be written without complete provenance, and there is
no other insert path.

Natural keys: `(source_account, conversation_uuid)` for a conversation,
`(source_account, message_uuid)` for a message, `(source_account,
project_uuid)` for a project, and `(source_account, doc_uuid)` for a
project document. Every one of those uuids is present on every record
in the extracted structure.

A uuid collision inside one source account aborts the import loudly
rather than being resolved. Keeping the first record drops the second's
message, keeping the second rewrites history under the first parent,
and scoping the key per conversation would let one message exist twice
with different parents. Which is right depends on why the archive
contains the collision, so it is not guessed at: the error names the
uuid, both parents, and the fact that conversations imported before it
are committed and remain.

Projects inherit the conversation semantics whole: the same natural-key
scoping, the same sealed refusal through the same source path, the
same wholesale snapshot replacement with a project's documents deleted
and rewritten alongside it, and the same ordering decision, which is
one function both record types call rather than a rule written twice.

**A project document's text is content**, for gating, for sensitivity,
and for rendering alike. It is among the largest text an archive
carries, it is read through the same Tier 3 gate as a message body, a
read of it enters the observed-sensitivity set the same way, and it is
encoded at render like any other stored text. Nothing about arriving
as a project attachment rather than a chat turn makes it less than
conversation content.

The store file is owner-only, converged on every open rather than set
once at creation, so a database left loose by an earlier run does not
stay loose. The data directory already restricts it; this is the
posture the vault takes for the other file in that directory holding
something confidential, and an imported corpus is that.

### Timestamps

Conversation and project timestamps are both ISO 8601 in this archive
but not the same string form; the project values are longer. Each
timestamp is stored twice: the original string verbatim, and a
normalized integer for ordering and for the upsert comparison. Storing
only the normalized value would discard bytes the record actually
carried, and comparing the raw strings across two differently shaped
forms would be wrong.

### Message body and content blocks

A message carries a flattened text body alongside a structured content
array. The flattened body is the column the detail view renders and the
search index covers.

The content array is stored verbatim as JSON text and is not
decomposed. Its blocks are a union whose type is a closed set in this
archive, and its tool-use blocks carry an input object whose keys are
whatever parameters the invoked tool took. That key set is open by
construction: it is the parameter surface of every tool the assistant
ever called, and the extracted structure shows it sprawling across
unrelated integrations. Typed columns cannot cover it and should not
try. Verbatim storage is also what the no-mutation-at-import rule
requires.

### Attachments

Message attachments carry a file name, size, type, and extracted text.
That extracted text is among the larger values in the archive and is
message content by any reading, so attachments are their own table and
their extracted text is indexed alongside message bodies. A message
also carries a thinner file list holding names only, with no content;
that is separate and carries no body.

Attachment extracted text is message content for gating purposes.
Search over it and reads of it sit behind the same Tier 3 gate as
message bodies, and a read of it enters the observed-sensitivity set
the same way, because it is conversation content that happened to
arrive as a file.

### Closed sets are observed, not contractual

The extraction shows closed sets for message sender, content block
type, tool-result content type, display-content type, and citation
detail type. They are stored as TEXT with no `CHECK` constraint and no
Rust enum at the storage boundary. A value outside the observed set is
stored rather than rejected: the format is not a published interface,
and turning an unremarkable upstream addition into a failed import
would trade a cosmetic problem for a total one.

### Fields present but never populated in this archive

These appear on every record that has them and are null in all of them,
so their type is unverified. The structs tolerate them per the
unknown-fields rule, and nothing downstream may assume a type for them:
content-block `flags`, `approval_key`, `approval_options`, and
`context`; the tool-result content entry's `mime_type`; within
tool-use citation sources, `content_body`, `resource_type`, and
`subtitles`; and within display content, the link's `resource_type`
and `subtitles` and the content entries' `subtitles`.

They are recorded rather than omitted because an absent field and a
field that is always null are different facts, and only the second one
tells a later reader that the field exists and this archive had nothing
in it.

Two more are present and non-null but carry the same value in every
record: the tool-result content entry's `ingestion_date` is the empty
string throughout, and its `start` offset is zero throughout. Neither
is null, so neither appears above, and neither is a closed set worth
trusting: one archive holding one value says nothing about the range
the field can take. They are stored like any other field and nothing
reads meaning into their constancy.

### The schema stays strictly linear

No branch columns, no parser trait, no vendor-shaped indirection. The
`provider` enum is the single reserved seam, and it reserves a name
rather than a structure. Another assistant's export format is an
uncommitted boundary, and an abstraction shaped by an uncommitted
boundary is shaped by a guess. When a second format is actually
implemented the shape of the seam will be known, and it can be cut
then against something real.

### Multi-source

Many sources per instance. Sealing is an operator declaration at import
time: a source declared sealed is a closed account, imports once, and
refuses whatever archive is presented afterwards, matching hash or not.
The refusal names the sealed state, and there is no unseal.

A live source re-imports with upsert on the natural key, replacing a
record when the incoming updated timestamp is demonstrably newer than
the stored one. Presented with the archive it already holds, a live
source does nothing. The source row carries the most recent archive
hash; the hash of any individual run rides that run's audit event.

### Text a message does not carry, and where a derivation would live

A real archive turns out to hold messages with no text at all: an empty
flattened `text` field, and a `content` array holding one text block
whose own text is also empty. In the store this was measured in, 15506
of 43807 messages had that shape, almost all of them in conversations
whose name is also empty. There is nothing to recover from the stored
blocks for those rows, because the blocks are empty too. Whether the
archive itself carries that text under some field the parser does not
read is a question about the archive, not about the store, and is not
answered here.

The decision, should a message ever be found whose text is present in
its blocks and absent from the flattened field: the derived text is a
column of its own, written beside the archive's `text` and never over
it. The archive's own bytes stay verbatim, `content_json` included, and
`text` continues to hold exactly what the export put there, empty
included. Re-deriving a projection from bytes already stored is not an
import and does not touch the seal, but a derivation that silently
replaced the archive's field would make the store stop answering what
the archive said, which is the one thing it exists to answer. Two
columns, and the reader is told which it is looking at.

No such column exists, because in the corpus that raised the question a
derivation recovers zero rows. What the views and the read tool do
instead is label the absence: a message the store holds no text for
renders as a labelled record rather than a blank turn, and the label
claims only what is checkable from the store -- that no text is stored
-- not that the archive carried none.

Replacement is wholesale. A record whose incoming snapshot is newer has
its dependent rows deleted and rewritten as a unit rather than merged.
An export is a snapshot, so a child absent from the newer archive is
absent from the history, and merging would resurrect it into a record
that existed in neither archive.

The completion event reports added, updated, unchanged, unorderable,
and skipped counts. Unorderable is kept apart from unchanged
deliberately. Both write nothing, but unchanged is a comparison that
happened and came out not-newer, while unorderable is a comparison that
could not happen because a timestamp on one side would not parse.
Folding them together would let an upstream timestamp format change
land as a quiet archive of unchanged records while the store went
stale; kept apart, the same break reports a whole archive unorderable,
which is a signal.

### One source, and no assumption of a second

This archive is the closed-account source: it imports once and is
marked immutable. Nothing in the schema assumes another source exists.
There is no cross-source join, no primary-source concept, and no
identity linking between source accounts, which would be the same
mistake the cross-channel memory module refuses when it declines to
join a Slack uid to a Signal number. When the live-account export
arrives it becomes another `import_source` row with its own
conversations, and the upsert path runs for the first time then.

### Scale

The conversation file is the large member of the archive and message
text dominates it. The parse streams rather than loading the member,
and the import commits per conversation rather than accumulating a
transaction across the run, so a failure partway leaves the completed
conversations durable and the audit counts truthful.

## Ingest

A CLI subcommand, `wirken import`, streaming the archive. The web
surface stays display-only: it has no upload route and gains none.

Output is counts only. No title, no message text, and no conversation
excerpt reaches stdout, the tracing log, or an audit event payload.
Stable identifiers are permitted: archive hash, source account,
conversation uuid.

The serde structs tolerate unknown fields, because the archive format
is not contractual and is not published as a stable interface. A
conversation that fails to deserialize is skipped and logged by
identifier, and the import continues. A malformed record never aborts
the run.

## Web UI

Read-only, on the existing hand-rolled server
(`crates/cli/src/commands/webchat.rs:527`). Archive list grouped by
source, conversation list per source, and a detail view per
conversation. The views read the import store the same way the session
sidebar and transcript read theirs
(`crates/cli/src/commands/webchat.rs:413,427`).

The server binds loopback only, hardcoded, with the port configurable
(`:535`). The new routes are reads and take the same preflight posture
as the existing read routes: `Host` is checked against loopback names
on every route, which is what closes DNS rebinding, and a present
`Origin` is validated on reads even though browsers omit it on a
same-origin GET (`:1008-1047`).

Every value that comes from a store reaches the DOM through one
helper, `setText` (`:123-126`), which assigns `textContent` and
nothing else. `textContent` is assigned in exactly that one place in
the page, so "everything goes through the helper" is a fact a test can
check rather than a discipline someone has to remember. `innerHTML` is
written only with an empty literal to clear a container, and
`insertAdjacentHTML`, `outerHTML` and `document.write` appear nowhere.

## Agent tools

Two tools: `search_imported_chats` and `read_imported_chat`. Both are
registered in `tool_to_action`, both get an `Action` variant, both get
an audit event variant, and both are registered in
`tool_to_read_sensitivity`. Registration is not optional in practice:
an unregistered name lands on `UnknownTool` at Tier 3 and is denied.

### Tier: Tier 3 for both

The argument is what the corpus reveals, not that its contents are
untrustworthy. Injectability is a separate axis handled by
`ReadSensitivity` like any other foreign text entering context;
`crates/agent/src/tool.rs:1627-1634` states explicitly that
`ReadSensitivity` is a confidentiality axis and deliberately not a
trust axis.

`CrossChannelMemoryRead` sets the precedent and the floor. It gates a
read of one other channel's deliberately labelled memory entries for
the same agent at Tier 3, on the reasoning that channels are distinct
trust zones. An imported archive is a strictly larger disclosure: the
complete conversation history of an account, across every conversation
it ever held, written without any expectation that an agent would read
it. Gating the smaller disclosure at Tier 3 and the larger one lower
would invert the model.

`search_imported_chats` is also Tier 3, and this is the case that could
be argued down, so the argument is recorded rather than assumed. Search
returns matching content, which is a read. Even a shape that returned
no content would answer whether a term appears anywhere in an account's
history, which is an oracle over the same corpus. A lower tier would
need a search shape that returns neither content nor presence, and that
is not a useful tool.

The tier does not rest on search disclosing less than a read, and it is
worth being explicit that it does not, because the shapes differ in
kind rather than in size. A read returns one conversation entire. A
search returns a bounded number of hits, each a short window around the
match, drawn from wherever in the corpus they fall — so a single search
can characterise many conversations at once while a single read
characterises one deeply. Measured against a real archive, one search
returns well under the text of one average conversation in total, and
touches an order of magnitude more conversations. Neither shape
dominates the other, which is exactly why the smaller-looking one is
not gated lower.

The bound and the window are constants in
`crates/agent/src/imported_tool.rs` (`SEARCH_LIMIT`) and the snippet
call in `ImportStore::search_messages`. They are disclosure surface,
not tuning: widening either widens what one approval buys, so they
belong in this argument rather than in a config file where they would
be changed without one.

### The approval key, and why it is shaped this way

`imported_chat:{source_id}`, beside `cross_channel_memory:{from_channel}`,
which it copies deliberately.

The cross-channel key names the channel read *from* rather than the
pair of channels, because the destination is the channel the turn is
already on and putting it in the key would fragment one decision into
many. An imported read is the same shape: the source is what the
operator is being asked about, and the agent doing the asking is
already known. So the key names the source and nothing else, and
approving one archive approves no other, exactly as approving one
channel's history approves no other channel's.

A missing or empty source argument yields `imported_chat:`, a key no
source carries, so such a call cannot ride an approval granted for a
real archive. It denies rather than widening, which is the behaviour
the cross-channel key already relies on.

The key is built in the classifier arm, at the same site that decides
the tier, and the tool body checks neither. A tool that re-checked
would hold a second copy of a rule the runtime never consults, and the
copy that is not consulted can be wrong for a long time without
anything failing.

Search takes an optional scope, and the two forms take different keys
rather than two values of one key. A scoped search is
`imported_search:{source_id}`. An unscoped one reaches every archive
on the instance, which is a wider question, and takes
`imported_search_corpus`, a key outside the scoped namespace that no
source id can produce. A blank scope is no scope rather than a source
named by the empty string.

**Search and read approvals never imply each other, in either
direction.** They are separate key namespaces, and the separation is
the point rather than a side effect. Approving a read of a
conversation the operator named is not approving a sweep for
conversations they have not named: the read discloses one thing
already identified, and the search discloses what exists. Approving a
sweep is not approving reads of what it turns up either, because
knowing a term appears somewhere is a smaller disclosure than the
conversation around it. Each is asked once and answered on its own
terms.

### Read sensitivity

A new `ReadSensitivity` variant for imported archive content.
`restricts_egress()` is true for it, since it is not
`AggregatedExternal`. Registered in `tool_to_read_sensitivity` for both
tool names, so a read enters the session's observed-sensitivity set at
the same dispatch site that classifies the call for tiering.

## Egress scope

Stated narrowly, because the mechanism is narrower than the word
egress suggests.

A read of imported content adds a restricting label to the session's
observed-sensitivity set. That set is consulted at exactly one place:
`SandboxEgressContext::restricting_basis`
(`crates/agent/src/sandbox_egress.rs:371-387`), reached from
`exec_command` where the context is handed to `sandbox.exec`
(`crates/agent/src/tool.rs:695-704`). So the effect is on **network
egress attempted from inside a sandboxed `exec`**, and the audit row
that carries the basis is `SandboxEgressVerdict`
(`crates/audit/src/session_log.rs:1408`).

With a restricting label present
(`crates/agent/src/sandbox_egress.rs:469-520`): `open` mode refuses;
`allowlist` mode puts the destination to the operator at Tier 3; and
where no approval surface is reachable, which is the cron and headless
subagent case, it refuses.

**Paths that are not checked against observed sensitivity**, named so
the threat model does not overclaim:

- `http_request`, `web_search`, and `generate_image`, which go through
  `EgressClient`. It does not read the observed-sensitivity set.
- `exec` where the sandbox is configured off, where egress is decided
  by the operating system.
- MCP children, which open their own connections.
- LLM HTTP, which constructs its own client.
- The agent's reply to its channel, which is the normal response path
  and not an egress checkpoint at all.

`crates/agent/src/egress.rs:19-43` documents the bypass set for
`EgressClient` and states that the skill-side egress allowlist is a
defense-in-depth control on the built-in tools, not a network boundary.
This design adds nothing to that boundary and does not claim to.

Making `EgressClient` consult observed sensitivity is out of scope and
carried as a follow-up.

## Audit

New variants, all counts and stable identifiers, never a title and
never message content:

- import started, carrying source identifier, provider, source
  account, and archive hash.
- import completed, carrying the same identifiers plus added,
  updated, unchanged, unorderable, and skipped counts.
- an imported-chat read, carrying source identifier, conversation
  uuid, and the number of messages returned.
- an imported-chat search, carrying source identifier, match counts,
  and a keyed digest of the query.

Denials need no new variant. `SessionEvent::PermissionDenied` already
carries tool, action key, denial source, tier, agent, trigger, the
approval route, the denial reason, and the adapter and sender pair.
Reusing it keeps imported-chat denials in the same stream and the same
SIEM detections as every other denial.

**Attribution on the import events is operator-CLI, on the convention
already in the tree rather than a new one.** An import runs from the
CLI, not from an agent turn, so there is no agent id and none is
invented. The events carry an actor label populated the way a CLI
approval populates `approved_by`: the operator's `$USER`, falling back
to the literal `cli`, which is the actor half of the actor-versus-
surface split the approval path already documents.

The field is required rather than optional. An import row always has
an actor, so a row that reaches a SIEM without one can only mean the
extractor was never taught the variant. Making the field optional
would make a genuinely unattributed event indistinguishable from a
registration someone forgot.

The search event records a keyed digest of the query, never the query
text. HMAC-SHA256 on the pattern already in the tree
(`crates/audit/src/alarm_log.rs:350-355`), keyed by a dedicated
pseudonymization key held in the data directory and never forwarded.

Keyed rather than a plain content hash, because an agent under
injection can echo archive content into a query. That makes the query a
content path out of the corpus into audit rows and into every SIEM the
forwarder feeds. An unkeyed sha256 does not close it: the space of
plausible queries is small enough to enumerate, so the digest is
recoverable by anyone holding the rows. A keyed digest is not, and it
still compares equal for the same query, which is what preserves
repetition and correlation for an auditor.

A dedicated key rather than the alarm signing key, because that key
exists to be shared. `AlarmLog::read_all` returns a per-record
verification status so a reviewer holding the key can separate
signed-and-verified records from tampered ones
(`crates/audit/src/alarm_log.rs:15-21`). Giving a reviewer the key that
also pseudonymizes queries would give them the queries.

Key residence. The pseudonymization key is an aux key held in the
keychain and loaded through the vault crate, on the pattern
`load_or_create_alarm_log_key` already uses for the alarm-log HMAC key
(`crates/vault/src/keychain.rs:115`): random bytes, hex-encoded at rest,
wrapped by the OS keychain or, on the age-file backend, by the
operator's passphrase. It is never forwarded to a SIEM and never
included in a reviewer handout. Note that this is the custody path for
the existing HMAC key specifically; agent identity keys take a
different one, as files at `agents/<id>/identity.key` with mode 0600
(`crates/agent/src/identity.rs:13,71`), so "the same as other signing
material" is not uniformly true and the keychain path is what this
follows.

Where the key is unavailable, the digest field is omitted and the event
records match counts alone. It does not fall back to an unkeyed hash.
The alarm log degrades to unsigned in that state and stays readable,
which is the right trade for an integrity tag; the equivalent trade
here would emit exactly the recoverable digest the keying exists to
prevent.

Searching still runs in that state. The alternative, refusing the tool
until the key is reachable, was considered and rejected: the tier gate
is the enforcement boundary for reaching a corpus at all, and it runs
either way, per source, every time. A row written without the digest
still names the agent, the adapter, the sender, the source scope, the
outcome and the match count. What is lost is the ability to prove which
term was searched. Refusing would make a locked vault a denial of the
operator's own archives, which trades a large functional loss for a
smaller forensic one.

The degrade is recorded rather than inferred. A row carrying no digest
is ambiguous on its own -- no key at the time, or a build that never
wrote one -- so the gateway puts an
`imported-search.digest-unavailable` event on the chain at startup
naming the reason. A reviewer holding only the rows can date the window
in which digests were off instead of correlating against a log line
that may not have been captured.

Each new variant is registered in three places: `variant_kind`, which
the compiler forces; the default-forward list, which does not; and the
actor-field extractor, whose catch-all otherwise leaves the row without
agent attribution.

## Threat model

**Prompt injection from imported content.** Imported messages are
foreign text authored by anyone who ever got text into that account's
conversations, and reading one puts it in the agent's context. There is
no control here that prevents an imported message from steering the
agent, and this document does not claim one. What exists: the Tier 3
gate in front of the read, so the content does not enter context
without an operator answering for it, and the confidentiality label
after the read, whose reach is bounded as described under Egress scope.
The injection detector is a separate mechanism on a separate axis.

**Exfiltration by read-then-egress.** Partially controlled, and only on
the sandboxed `exec` path. Every other outbound path listed under
Egress scope is unaffected by the read. The honest summary is that the
label raises the cost of one exfiltration route and leaves the others
where they already were.

Fixed condition, recorded because it was true of every build before the
commit that installs the per-turn contexts on the streaming path: the
web surface installed no sandbox-egress context at all, so `exec`
launched from it resolved its network from the legacy `network` flag in
`sandbox.json` rather than from the channel's egress policy. With that
flag at its default the container got no network and the gap was
closed; with an operator having set it true the container joined
Docker's default bridge instead of the internal network the egress
proxy fronts, and neither the allowlist nor the observed-sensitivity
restriction applied to it. The one controlled route was therefore
uncontrolled from the web surface under that setting, and the label's
reach was narrower than this section described.

A second fixed condition, on the same setting and from the same
mismatch between an egress decision and the network the container got:
a channel whose policy granted no egress at all produced no proxy and
no network name, which was indistinguishable from an exec that no
policy had reached, so the legacy flag decided and the container joined
the default bridge. Under that setting the strictest of the three
policies gave a sandbox more network than the allowlist did, and the
label's restriction had nothing to act on because the proxy it acts
through was never provisioned.

**Stored cross-site scripting.** A property of the transcript rendering
path generally rather than of this feature, but this feature raises
exposure to corpus scale: not just text the operator's own agent
produced, but text from any party who ever got a message into the
imported account. The escalation target is concrete, since the UI
serves an approval surface at a same-origin `POST /api/approvals/{id}`;
script running in that origin could answer a Tier 3 prompt for itself.

The control is output encoding at render, and only that. One helper
implements it for the whole page: `setText`
(`crates/cli/src/commands/webchat.rs:123-126`) assigns `textContent`,
and it is the only place in the page that assigns it. Structural tests
hold that, and hold that no markup sink ever receives a value. The
view slice closed on an operator seeing the markup render as inert
text, because a structural test cannot prove what a browser does.

The control is **not** sanitizing at import. Imported records stay
byte-faithful. An archive may legitimately contain a script tag or an
injection string as the subject of a conversation, and rewriting stored
content would corrupt the record to compensate for a rendering bug that
belongs in the renderer.

**Zip path traversal.** Removed as a class rather than filtered:
nothing is extracted to a filesystem path derived from an archive entry
name. Members are opened by name through the archive reader and parsed
in memory. If storing attachments to disk is ever added, that decision
reopens this and needs its own containment.

**Oversized and malformed archives.** Streaming parse so the whole
archive is never resident. Caps on per-member uncompressed size, total
uncompressed size, and member count, with a compression-ratio ceiling
so a zip bomb is refused rather than expanded. A member that fails to
parse is skipped by identifier and the run continues.

## Search

FTS5, natively, since the bundled SQLite this workspace links has it
compiled in. External indexes over flattened message text, attachment
text, and project-document text, with the substantive rows kept in
their base tables. Those three are what the gate covers, so indexing
anything else would make the search surface wider than the control
over it. Stored content blocks are not indexed: they are never parsed
for meaning, and a term found only inside one would be a hit no reader
could place. No embeddings in this scope.

The indexes are maintained by trigger rather than by the write path.
Replacement is wholesale, and an index kept beside that by hand would
drift the first time a new delete path forgot it.

### Three outcomes, each meaning only itself

A search returns hits, returns nothing, or refuses. The three are kept
distinct because collapsing any two of them makes the tool lie.

**Hits** mean the term is in the corpus.

**Empty** means the term is not in the corpus. It is a fact about the
archive, and a caller may act on it.

**A refusal** means the query was not run: it was not valid match
syntax, or the store could not be reached. Returning empty here would
report absence the search never established, and a caller acting on
that would be acting on a fact nobody checked.

The audit event follows the same rule. Every attempt that reaches the
tool emits one, whether it found hits, found nothing, or was refused,
so the trail records attempts rather than survivors. A trail that
recorded only successful searches would answer "what was looked for"
with a filtered version of the truth.

The query itself never appears; the event carries a keyed digest of it
instead. The digest is over the query bytes exactly as issued, with no
trimming, case folding, or normalization, because two queries that
differ by a byte are two queries and folding them would claim a
repetition that did not happen.

## Slices

One concern per slice. A closing condition is behaviour someone
observed, not code that landed.

**Store and migration runner.** Closes when the operator runs the
import against a fresh data directory and again against the same
directory, and the second run applies no migration while the first
applies all of them.

**Ingest.** Closes when the operator reports a successful end-to-end
import of a real archive with the counts they expected. The agent never
reads the archive at any point in this slice.

**Re-import.** Closes when the operator re-imports a live-account
archive and the completion event reports added, updated, and unchanged
counts matching what actually changed between the archives, and when a
closed-account source refuses a second import.

**Views.** Closes when the archive list, conversation list, and detail
view render from the store, and a synthetic conversation carrying a
script-bearing message renders as inert text in the detail view.

**Tools.** Closes when a read prompts at Tier 3, a denial is recorded
with its context, and a taint-carrying egress verdict for imported-chat
content is observed on network egress from a sandboxed `exec`. Also
closes on confirming the tools are unreachable from the replay verifier
path that attaches no permission store.

Open on one condition. Condition by condition:

*A read prompts at Tier 3.* Closed on chain evidence. The card renders
in the browser carrying the agent, tool, action key, tier and the
triggering message; approving it lets the read execute. Two consecutive
reads of the same source each produced their own card and their own
approval row, so the persisted scope a Tier 3 approval writes is never
consulted on the next call, which is what "always prompt" has to mean
to be worth anything. Searches prompt per attempt on the same terms.

It could not be observed before: the gate looked the browser's stream
up under a session id it derived by appending the channel and
conversation segments to a value that already carried them, so no event
was ever pushed and the only trace an operator got was a denial reading
"approval timeout".

*A denial is recorded with its context.* Closed. The row names the
tool, the action key, the denial source and tier, the agent, the
triggering message, the route the approval took, and the adapter and
sender.

*A taint-carrying egress verdict on egress from a sandboxed `exec`.*
Open, and runnable. The rootful runtime it needs is present; the
environment's `DOCKER_HOST` points at a socket that is not, which is
what made it look absent. The sidecar runs the gateway binary inside
the sandbox image and so needs the statically linked build, and the
image carries no HTTP client, both of which the runbook works around.

Independently of the infrastructure, it could not have been observed
from the web surface at all, because the streaming turn installed no
sandbox-egress context: `exec` there resolved its network from the
legacy `network` flag rather than from the channel's egress policy, so
the allowlist and the observed-sensitivity restriction were both out of
the path. Both turn paths install it now, which makes the condition
observable rather than observed.

*Unreachable from the replay verifier path.* Held by a test, not by an
observation. Recorded as such rather than counted as closed.

**Search.** Closes when a query returns matches from the imported
corpus through the gated tool at its assigned tier.

Closed. A scoped search over a real archive returned matches through
the gated tool, prompting at Tier 3 like any other call into a corpus,
and its row carries the keyed digest of the query and no plaintext.

The digest half of that could not be observed until the key was
reachable. Two earlier boots each recorded a
`imported-search.digest-unavailable` attestation and then wrote
searches with the field absent, which is the degrade behaving as
designed and saying so. The boot this closed on recorded no
attestation, and its search row carries the digest. The three boots
together are the evidence: the attestation and the absent field appear
and disappear as a pair, so a row without a digest can be dated to a
boot that said why.

Index behaviour under re-import is not part of this condition and was
not observed. It belongs to the Re-import slice, and the source it
would be observed against is sealed, so it cannot be observed there
either without a second archive.

## Out of scope, carried as follow-ups

- Whether an agent should be constructible with no permission store
  attached.
- Whether `EgressClient` should consult the observed-sensitivity set.
