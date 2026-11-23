# Proxy archive, redaction and export

What a proxy client exchanged, kept and taken out again: the write-once
archive, redaction, verification and the trajectory export. The mode as a
whole starts at [proxy.md](proxy.md).

## Write-once archive

The chain holds a hash of each body a proxy client exchanged. With `archive`
in `proxy.json`, the bodies themselves are written to an S3-compatible bucket
under Object Lock:

```json
"archive": {
    "endpoint": "https://s3.eu-central-1.amazonaws.com",
    "bucket": "inference-archive",
    "region": "eu-central-1",
    "prefix": "wirken/",
    "retention_days": 365,
    "mode": "compliance",
    "credential": "proxy-archive-credentials"
}
```

| Field | Default | Meaning |
|---|---|---|
| `endpoint` | required | The bucket's endpoint. HTTPS, or plain HTTP on loopback. Requests are path-style: `<endpoint>/<bucket>/<key>`. |
| `bucket` | required | A bucket created with Object Lock enabled. Wirken does not create it. |
| `region` | `us-east-1` | The region requests are signed for. |
| `prefix` | none | Put before every object key. |
| `retention_days` | required | How long each object is locked for. |
| `mode` | `compliance` | `compliance`, or `governance`, which a principal with the bypass permission can lift. |
| `credential` | required | The vault entry holding `access_key_id:secret_access_key`. |
| `key` | `proxy-archive-key` | The vault entry holding the archive key. |

The bucket credentials are bound to the endpoint's host as an archive, and
are not read for another host:

```bash
wirken credentials add proxy-archive-credentials --archive s3.eu-central-1.amazonaws.com
```

`--archive` is a destination of its own. A `--host` binding does not open an
archive, and an `--archive` binding does not let `http_request` send the
credentials anywhere, that host included. A host on a port other than 443 is
named with it (`--archive 127.0.0.1:9000`).
An archive that is configured and cannot be opened stops `wirken run`.

**Keys.** A request body is stored at `<prefix>request/<sha256>` and a
response at `<prefix>response/<sha256>`, the hashes on the rows, so a row
finds its object.

**Encryption.** The bucket never holds plaintext. Each body is encrypted
before upload with XChaCha20-Poly1305 under a key of its own, with its kind
and hash bound in. That key is kept in `proxy_archive_keys.db` in the data
directory, wrapped under the archive key, which the vault holds and which is
made on first use. Reading a body back takes the bucket, the vault and
`proxy_archive_keys.db`: back the last two up together. A body whose key is
lost cannot be read.

**What is archived.** For a model call, the request as the client sent it and
the response as the provider sent it. For an MCP session, the tool list the
session was shown, and for each tool call the request and the answer as
exchanged with the client. A body sent again is not written again: it is one
object, and keeps the lock of its first write.

**Order.** A request body is archived before the call is forwarded or the
tool is run, and a call whose body cannot be archived is refused; an MCP
session whose tool list cannot be archived does not open. A response body is
archived when the response ends; if that write fails the call has already
been answered, the failure is logged, and the row says `archived: false`.

## Redacting a session

An object under Object Lock cannot be deleted or changed. A body is made
unreadable by destroying its key:

```bash
wirken proxy archive redact --session <lane> --reason "customer request"
wirken proxy archive redact <sha256> --reason "customer request"
```

The first form redacts one session: every archived body of it, and every row
of it that holds what a tool call said. The second redacts one body. The
command runs at a terminal and refuses
inside a Wirken `exec`. For each body it destroys the key held for that hash
in `proxy_archive_keys.db`, overwrites the freed pages, and writes a
`proxy_archive_redacted` row with the hash, the operator, the reason and,
for the first form, the session. The object stays in the bucket until its retention
ends and nothing can decrypt it. A hash that is redacted takes no new key: the
same body sent again is not archived, and its row says `archived: false`. It cannot be undone. The
[search text](#search-text-at-rest) kept for the body is deleted with it.

**The rows of a tool call.** A model call's rows hold hashes, so destroying
the keys is all there is to remove. A tool call made at the
[MCP endpoint](proxy-mcp.md#what-is-recorded) is on the chain itself: its
`assistant_tool_calls` row holds the arguments and its `tool_result` row the
output. `--session` rewrites those rows. The arguments become
`{"redacted":true}` and the output `[redacted]`; the call's id, tool, sender
and outcome stay. Each rewrite goes through the session log's
[redaction](audit-cli.md#redaction): the chain is resealed over the row, and
a signed `chain_head` with `reason: redaction` records the row's number, the
hash it had, the operator and the reason. The session still verifies, and
the rewrite is on the record. Afterwards `wirken sessions search` and
`wirken sessions export` find nothing of what the rows held.

What it does not do:

- A body is redacted by its hash. Redacting one body leaves the others of
  its conversation: an answer can quote its prompt, and a later request
  repeats the conversation before it. `--session` takes them all.
- Two sessions that exchanged the same bytes share that object. Redacting it
  for one makes it unreadable for the other.
- It does not remove the rows. The chain still shows that each call was
  made, with its hashes, its tool and its outcome.
- The form that takes one hash touches no row.
- It does not reach rows already forwarded to a SIEM, or a copy of
  `audit.db` made earlier.
- A copy of `proxy_archive_keys.db` made before the redaction still holds the
  key.

## Search text at rest

`wirken sessions search` ([audit-cli.md](audit-cli.md#wirken-sessions-search))
reads archived bodies. A body is fetched from the bucket and decrypted with
its own key. The first search that reads a body keeps the text it extracted
in `proxy_archive_keys.db`, encrypted under that same key and bound to the
body's kind and hash, so a later search does not fetch it again.

- The file holds no text in the clear. An entry opens only with the body's
  key, which is itself wrapped under the archive key in the vault.
- Redacting a body destroys that key and deletes the entry, with the freed
  pages overwritten. Nothing kept for the body can be read afterwards, by a
  search or from the file.

## Verifying a proxy session

```bash
wirken sessions verify <lane>
```

For a proxy lane, `sessions verify` checks the hash chain and prints how many
calls were forwarded, answered and refused, and the lane's tool calls. With an archive configured it
then reads each archived body back: the object is in the bucket under the
row's hash, it is under a lock that has not ended, and what it decrypts to
hashes to the row's hash. A redacted body is checked for being there and
locked, and counted as redacted. An object whose retention has ended is
reported as not under a lock.

| Exit | Meaning |
|---|---|
| 0 | The chain verifies and every archived body matches its row or is redacted. |
| 3 | The chain is broken. |
| 4 | The session has no rows. |
| 7 | An archived body is missing, altered, unlocked, or has no key here. |

Without an archive in `proxy.json` only the chain is checked and nothing is
read from anywhere else. `--skip-archive` does the same with one configured.
Checking the archive opens the vault, so it takes the vault passphrase.

## Exporting a session

```bash
wirken sessions export <session id> --format atif --output session.json
```

`sessions export` writes one session as an ATIF trajectory, version 1.8
(`schema_version` `ATIF-v1.8`): to the file, or to stdout. It takes a proxy
session's lane or the id of a session an agent ran. A proxy session is one
conversation, so two conversations on one token are two trajectories. Nothing is sent anywhere; pushing
the file to a tool that reads the format is a separate step.

A session an agent ran is exported from its rows: each user message, each
assistant message with its tool calls and reasoning, each tool result under
the step that made the call, and each model call's token counts and cost on
the step it produced. System prompts and tool definitions are not on the
chain, which holds their hashes, and are not in the document.

A proxied session is exported from its rows and its archived bodies. Each
request repeats the conversation so far; a message is a step once. An
assistant turn the client sent back that this proxy did not see made is
marked `is_copied_context`. Without an archive, or with `--skip-archive`,
each call is one step with its metrics and hashes and an empty message.

Tool calls made at the MCP endpoint are in the trajectory of the lane they
are on. A call the model's answer carries, matched by the id of its tool use,
gets the result the gateway recorded on the model's step, marked
`recorded_by: wirken`, beside the result the client sent its model. A call
with no such id is a step of its own. Both need the model calls and the tool
calls on one lane, which takes a shared `X-Wirken-Session` label.

Each step carries `extra.stable_step_id`, the same for every export of the
same session, and the proxied steps carry the request and response hashes in
`extra.wirken`.

Redaction is honored. Rows are exported as the chain holds them now, so a row
that was rewritten ([audit-cli.md](audit-cli.md#redaction)) is exported as
rewritten and marked `extra.redacted`; tool output a hook replaced is exported
as replaced and marked. An archived body whose key was destroyed is left out,
and its step says `redacted`.

The document is checked against the format before it is written: required
fields and types, no unknown fields, sequential step ids, agent-only fields,
and tool results that name a call of their own step. A document that fails
is not written.
