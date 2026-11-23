# Inference proxy

Wirken can stand between a model provider and a client it does not run: a
coding agent, a script, a chat client. The client sets its model base URL to
Wirken and sends what it would send its provider. Wirken forwards the call
with the provider key from the vault, records it on the audit chain, and can
write the full request and response to a write-once bucket.

The client never holds the provider key. It holds a token Wirken issued,
which says which providers and models it may use and how much.

## Turning it on

The listener runs inside `wirken run` when the data directory has a
`proxy.json`:

```json
{
    "upstreams": {
        "local":     { "provider": "ollama",    "base_url": "http://localhost:11434/v1" },
        "anthropic": { "provider": "anthropic", "base_url": "https://api.anthropic.com/v1",
                       "credential": "anthropic-api-key" },
        "openai":    { "provider": "openai",    "base_url": "https://api.openai.com/v1",
                       "credential": "openai-api-key" }
    }
}
```

| Field | Default | Meaning |
|---|---|---|
| `upstreams` | required | The providers calls are forwarded to, by the name tokens are issued for. `provider` is a provider id as in `provider.json`; `credential` is the vault entry holding its key, absent for a provider that takes none. |
| `bind` | `127.0.0.1:18791` | The address the listener binds. |
| `tls` | none | `{ "certificate": "<path>", "private_key": "<path>" }`: PEM files the listener serves TLS with. See [TLS](#tls). |
| `bind_beyond_loopback` | `false` | Allows, as `true`, a `bind` that is not a loopback address with no `tls`. |
| `max_body_bytes` | 33554432 | The largest request body read. A larger one is refused. |
| `idle_timeout_secs` | 300 | How long a forwarded call waits for the provider's next bytes. See [Long answers](#long-answers). |
| `archive` | none | See [Write-once archive](#write-once-archive). |

`wirken run` prints the listener's address at start. A `proxy.json` that
cannot be served, an unknown field included, stops the start.

### TLS

Without `tls` the listener speaks plain HTTP. On loopback that stays on the
host. With `tls` it speaks TLS 1.2 and 1.3 only: a connection that is not a
TLS handshake, or does not finish one in 15 seconds, is closed, and plain
HTTP to the port gets no answer.

```json
"bind": "0.0.0.0:8443",
"tls": { "certificate": "/etc/wirken/proxy.pem", "private_key": "/etc/wirken/proxy.key" }
```

`certificate` is the server certificate followed by any intermediates.
Clients then use `https://` and have to trust the certificate's issuer. The
files are read when `wirken run` starts: a renewed certificate is picked up
at the next start. A file that is missing or empty, or a key that does not
belong to the certificate, stops the start. No client certificate is asked
for; the token is what authenticates a client.

A `bind` that is not a loopback address is refused unless `tls` is set or
`bind_beyond_loopback` is `true`. Binding beyond loopback without TLS puts on
the network, readable and alterable by anything on the path:

- every client's token, on every request, which is enough to make calls as
  that client up to its ceilings;
- every request and response in full: prompts, files a coding agent sends,
  tool output, the model's answers.

Provider keys are not among them: they travel only between Wirken and the
provider. `wirken run` logs a warning at start for such a bind. Use it only
behind something that terminates TLS for the listener.

## Tokens

```bash
wirken proxy token issue laptop --upstream anthropic --upstream local \
    --model some-model --ceiling-usd 20 --ceiling-calls 2000 --window day
wirken proxy token list
wirken proxy token revoke laptop
```

`issue` prints the token once. Only its SHA-256 is stored, in
`proxy_tokens.db`, so a token that is lost is revoked and issued again.

| Flag | Meaning |
|---|---|
| `--upstream` | An upstream from `proxy.json` the token may reach. Repeatable; they are tried in the order given. |
| `--model` | A model the token may ask for. Repeatable. Without it the token may ask for any model. |
| `--ceiling-usd` | Spend ceiling over the window. |
| `--ceiling-calls` | Call ceiling over the window. |
| `--window` | `hour`, `day` (the default) or `week`. |
| `--mcp-server`, `--agent` | MCP servers of an agent whose tools the token may call at the [MCP endpoint](proxy-mcp.md). |

`issue` and `revoke` run at a terminal and refuse inside a Wirken `exec`. Each
is an `operator_command` row on the `gateway-operator` lane, sealed with a
signed chain head, naming the token and what it allows and never the token. A
refusal inside an `exec` is an `operator_command_refused` row. A revoked token stops working at the
next request; the gateway does not need a restart.

## Pointing a client at it

A client sends the token where it would send its provider key: as a bearer
token (`Authorization: Bearer wkp_...`) or as `x-api-key`. With the default
bind:

| Client speaks | Base URL to set | Endpoint served |
|---|---|---|
| OpenAI chat completions | `http://127.0.0.1:18791/v1` | `POST /v1/chat/completions` |
| Anthropic messages | `http://127.0.0.1:18791` | `POST /v1/messages` |

Streaming works for both. `/mcp` is the [MCP endpoint](proxy-mcp.md), for a
token granted MCP servers. Any other path or method is answered 404.

## Sessions

One conversation is one session, and one session is one lane on the chain,
`proxy-<token id>-<label>`. It is what `sessions verify` checks, what
`sessions export` writes as one trajectory, and what `proxy archive redact
--session` redacts.

A client can name its session with `X-Wirken-Session: <label>` (letters,
digits, `-`, `_`): calls with the same token and label are one session.

Most clients send no label, and one token then carries many conversations.
The proxy tells them apart by what each request holds. A request repeats the
conversation so far in its `messages`. One whose messages extend those of an
earlier request of the same token, at any point of it, continues that
request's session; any other starts a new one, labelled `c` and twelve hex
characters. For this the proxy keeps a hash of each request's message list
in `proxy_tokens.db`, for thirty days. No message text is kept.

```bash
wirken proxy sessions [--token <id or name>]
```

lists the sessions: lane, token, start, calls and model.

- Messages are compared without their `cache_control` markers, which clients
  move between turns. A system prompt outside `messages` is not compared.
- A client that rewrites its history, by compacting it or editing an earlier
  message, starts a new session from there. So does the continuation of a
  conversation idle for more than thirty days.
- Two conversations that begin with the same messages are one session until
  they differ, and stay one after: both extend the same request.
- Refusals belong to no conversation. They are on the token's own lane,
  `proxy-<token id>`.

## What is forwarded

A request is forwarded in the shape it arrives in, byte for byte, to the
first of the token's upstreams whose provider takes that shape. The response
is passed back byte for byte, a stream chunk by chunk. Nothing is translated.

| Provider | OpenAI chat completions | Anthropic messages |
|---|---|---|
| `openai`, `custom`, `hetzner`, `infomaniak`, `tinfoil` | yes | no |
| `anthropic` | no | yes |
| `ollama` | yes | yes |
| `gemini`, `bedrock` | no | no |

A request in a shape none of the token's upstreams takes is refused, and the
answer names the shape and the providers.

Of the client's headers, `Content-Type`, `Accept`, `anthropic-version` and
`anthropic-beta` are sent on. Its token and every other header stay behind.
The provider's response headers are passed back except the ones that
describe the connection.

The provider key is read from the vault for each call and put on the
outgoing request in the provider's own header. It goes through the client and
the destination check an agent's calls use
([credentials.md](credentials.md#where-a-credential-may-go)): the key is sent
only to the origin its vault entry allows for that provider, no redirect is
followed, and plain HTTP is used for loopback only. A key that may not be
sent to an upstream refuses the call. A request body that carries a stored
secret is refused, as a request an agent builds is.

## What is refused

Each refusal is a `proxy_refused` row with a `reason`, and an error in the
client's own shape.

| `reason` | When | Status |
|---|---|---|
| `unknown_token` | No token, or one this gateway did not issue. At most one row a second. | 401 |
| `revoked_token` | The token was revoked. | 401 |
| `malformed` | The body is not a JSON object with a `model`, or is over `max_body_bytes`. | 400, 413 |
| `shape_not_spoken` | None of the token's upstreams takes the request's shape. | 400 |
| `model_not_allowed` | The model is not on the token's list. | 403 |
| `budget_exceeded` | A ceiling is reached, the ledger cannot be read, or the token has a spend ceiling and the model has no price. | 429 |
| `leak_refused` | The body carries a stored secret. | 400 |
| `credential_refused` | The upstream's key is gone, or may not be sent to it. | 502 |
| `archive_failed` | The request body could not be archived. | 502 |
| `record_failed` | The `proxy_request` row could not be written. | 502 |

For the last two nothing was sent: a call is not forwarded unless its row,
and with an archive its body, is written first.

## Limits per token

The model list is checked against the `model` in the request body.

A call ceiling counts forwarded calls. A spend ceiling counts what each call
cost at the pricing table's rates ([cost-monitoring.md](cost-monitoring.md)),
kept in `budget.db` under the token's id. A model the table has no price for
cannot be counted, so a token with a spend ceiling is refused such a call; a
token for a local model takes a call ceiling. Both are fixed windows. A
ceiling is checked before a call and charged after it, so calls in flight at
once can pass it by what they cost.

## Long answers

A forwarded call has no limit on how long it takes in all: a stream runs for
as long as it keeps arriving. It is ended when the provider has sent nothing
for `idle_timeout_secs`, which also bounds the wait for the first byte of an
answer that is not streamed. A call ended that way is recorded with what was
exchanged and `complete: false`. Calls an agent makes keep their own
timeout.

## What is recorded

Each forwarded call is two rows on its session's lane:

- `proxy_request`, before the call is sent: `request_id`, `token_id`,
  `token_name`, `upstream`, `provider`, `model`, `shape`, `stream`,
  `request_sha256`, `request_bytes`, the vault entry the key came from, and
  whether the body was archived.
- `proxy_response`, after the last byte went to the client: `status`,
  `latency_ms`, the provider's token counts and the cost where the model is
  priced, `response_sha256`, `response_bytes`, `complete`, and whether the
  body was archived.

The hashes are SHA-256 of the bodies as exchanged: the request as the client
sent it, the response as the provider sent it, for a stream every byte in
order. `complete` is `false` when the exchange ended early, because the
client went away or the connection broke; the hash then covers what was
exchanged. Token counts are read from the provider's answer. An OpenAI-shaped
stream carries them only when the client asked for them
(`stream_options.include_usage`), and without them the row has none and the
call costs nothing against a spend ceiling.

Rows never hold a token, a provider key or a body. Every lane is covered by
signed chain heads like any session ([audit-cli.md](audit-cli.md#chain-head-signing)),
and the rows are forwarded to a SIEM by default.

## Write-once archive

With `archive` in `proxy.json`, the full request and response bodies are
written to an S3-compatible bucket under Object Lock:

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

The bucket credentials are bound to the endpoint's host like any other
destination, and are not read for another:

```bash
wirken credentials add proxy-archive-credentials --host s3.eu-central-1.amazonaws.com
```

A host on a port other than 443 is named with it (`--host 127.0.0.1:9000`).
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

**Order.** A request body is archived before the call is forwarded, and a
call whose body cannot be archived is refused. A response body is archived
when the response ends; if that write fails the call has already been
answered, the failure is logged, and the row says `archived: false`.

### Redacting an archived body

An object under Object Lock cannot be deleted or changed. A body is made
unreadable by destroying its key:

```bash
wirken proxy archive redact --session <lane> --reason "customer request"
wirken proxy archive redact <sha256> --reason "customer request"
```

The first form redacts every archived body of one session, requests and
responses; the second one body. The command runs at a terminal and refuses
inside a Wirken `exec`. For each body it destroys the key held for that hash
in `proxy_archive_keys.db`, overwrites the freed pages, and writes a
`proxy_archive_redacted` row with the hash, the operator, the reason and,
for the first form, the session. The object stays in the bucket until its retention
ends and nothing can decrypt it. A hash that is redacted takes no new key: the
same body sent again is not archived readable. It cannot be undone. The text
`wirken sessions search` kept for the body, encrypted under that key, is
deleted with it ([audit-cli.md](audit-cli.md#wirken-sessions-search)).

What it does not do:

- A body is redacted by its hash. Redacting one body leaves the others of
  its conversation: an answer can quote its prompt, and a later request
  repeats the conversation before it. `--session` takes them all.
- Two sessions that exchanged the same bytes share that object. Redacting it
  for one makes it unreadable for the other.
- It does not remove the rows. The chain still shows that the call was made,
  with its hashes and counts.
- A copy of `proxy_archive_keys.db` made before the redaction still holds the
  key.

## Verifying a proxy session

```bash
wirken sessions verify <lane>
```

For a proxy lane, `sessions verify` checks the hash chain and prints how many
calls were forwarded, answered and refused. With an archive configured it
then reads each archived body back: the object is in the bucket under the
row's hash, it is under a lock that has not ended, and what it decrypts to
hashes to the row's hash. A redacted body is checked for being there and
locked, and counted as redacted.

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

## Limits

- A Tinfoil upstream goes through the attested client, whose timeouts are
  that client's own and not `idle_timeout_secs`.
- Images and other non-text content in a proxied conversation are exported
  as a placeholder naming their type.
- Gemini and Bedrock have request shapes of their own and are not served.
