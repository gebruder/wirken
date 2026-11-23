# Inference proxy

Model calls of a client Wirken does not run: the listener, its tokens, what
is forwarded, refused and recorded. The mode as a whole, with tools, the
archive, search and export, starts at [proxy.md](proxy.md).

The client sets its model base URL to Wirken and sends what it would send its
provider. Wirken forwards the call with the provider key from the vault and
records it on the audit chain. The client never holds the provider key. It
holds a token Wirken issued, which says which providers and models it may use
and how much.

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
| `archive` | none | See [Write-once archive](proxy-archive.md#write-once-archive). |
| `oidc` | none | The identity provider whose JWTs a client may present in place of a token. See [proxy-identity.md](proxy-identity.md). |

`wirken run` prints the listener's address at start. A `proxy.json` that
cannot be served, an unknown field included, stops the start.

### TLS

Without `tls` the listener speaks plain HTTP. On loopback that stays on the
host. With `tls` it speaks TLS only: a connection that is not a TLS handshake
is closed, and plain HTTP to the port gets no answer.

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
provider. Use such a bind only behind something that terminates TLS for the
listener.

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
--session` redacts ([proxy-archive.md](proxy-archive.md)).

A client can name its session with `X-Wirken-Session: <label>` (letters,
digits, `-`, `_`, at most 64 characters): calls with the same token and label
are one session. A label that does not fit is ignored. A client that also
calls tools at the [MCP endpoint](proxy-mcp.md#sessions) has them on the same
lane only when it sends the same label there.

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

lists the sessions: lane, token, start, model calls with their model, and
tool calls.

- Messages are compared without their `cache_control` markers, which clients
  move between turns. A system prompt outside `messages` is not compared.
- A client that rewrites its history, by compacting it or editing an earlier
  message, starts a new session from there. So does the continuation of a
  conversation idle for more than thirty days.
- Two conversations that begin with the same messages are one session until
  they differ, and stay one after: both extend the same request.
- Refusals belong to no conversation. They are on the token's own lane,
  `proxy-<token id>`, or on `gateway-proxy` when no known token came with the
  request.

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
client's own shape. A provider that cannot be reached is not a refusal: the
call has its `proxy_request` row, and its `proxy_response` says status 502
and `complete: false`.

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

A JWT that is refused has its own reasons, `jwt_invalid` to
`jwt_ambiguous_grant`: see
[proxy-identity.md](proxy-identity.md#what-is-recorded).

For the last two nothing was sent: a call is not forwarded unless its row,
and with an archive its body, is written first.

## Limits per token

The model list is checked against the `model` in the request body.

A call ceiling counts forwarded calls. A spend ceiling counts what each call
cost at the pricing table's rates ([cost-monitoring.md](cost-monitoring.md)),
kept in `budget.db` under `proxy-token:<token id>`. A model the table has no price for
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
order. `complete` is `false` when the exchange ended early: the client went
away, the connection broke, the provider went idle or could not be reached.
The hash then covers what was exchanged. Token counts are read from the provider's answer. An OpenAI-shaped
stream carries them only when the client asked for them
(`stream_options.include_usage`), and without them the row has none and the
call costs nothing against a spend ceiling.

Rows of a model call never hold a token, a provider key or a body. With an
[archive](proxy-archive.md) configured the bodies are written there, under
the hashes on the rows. Every lane is covered by
signed chain heads like any session ([audit-cli.md](audit-cli.md#chain-head-signing)),
and the rows are forwarded to a SIEM by default.

## Limits

- A Tinfoil upstream goes through the attested client, whose timeouts are
  that client's own and not `idle_timeout_secs`.
- Images and other non-text content in a proxied conversation are exported
  as a placeholder naming their type.
- Gemini and Bedrock have request shapes of their own and are not served.
