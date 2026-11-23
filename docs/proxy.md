# Proxy mode

Wirken runs agents of its own. In proxy mode it also stands in front of an
agent it does not run: a coding agent, a script, a chat client. That client
points its model base URL and its MCP client at Wirken and holds one thing, a
token the operator issued. It holds no provider key and no MCP server's
credential, and runs no MCP server.

This page is the whole mode in one place. Each part has its own page, linked
where it starts.

## What a client can do

| Through | The client does | Wirken does | Page |
|---|---|---|---|
| `POST /v1/chat/completions`, `POST /v1/messages` | Calls a model, in the OpenAI chat or Anthropic messages shape, streamed or not | Forwards the call as it arrived, with the provider key from the vault | [inference-proxy.md](inference-proxy.md) |
| `POST /mcp` | Lists and calls MCP tools | Runs each call as one of its own agents, in that agent's MCP servers | [proxy-mcp.md](proxy-mcp.md) |

Nothing else is served. The client's own built-in tools, its shell and its
files stay on its side, where Wirken sees and gates nothing: only what goes
through the listener is recorded, and only tools reached at `/mcp` are gated.

## Turning it on

The mode is off unless the data directory has a `proxy.json`, which names the
providers and the listener's address. `wirken run` then serves the listener,
on 127.0.0.1:18791 by default; a bind beyond loopback needs `tls` or an
explicit setting ([inference-proxy.md](inference-proxy.md#turning-it-on)).

```bash
wirken proxy token issue laptop --upstream anthropic --model some-model \
    --ceiling-usd 20 --mcp-server files --agent default
wirken proxy token list
wirken proxy token revoke laptop
```

A token says what its holder may use: which upstreams and models, how many
calls and how much spend in a window, and which MCP servers of which agent.
It is shown once and stored as a digest. Issuing and revoking are operator
commands, each a row on the chain
([inference-proxy.md](inference-proxy.md#tokens)).

## What is gated

- **Who.** Every request needs a token this gateway issued and has not
  revoked. Anything else is refused and recorded.
- **Model calls.** The token's upstreams, its model list and its ceilings. A
  request that carries a secret the vault holds is refused. The provider key
  is sent only to the origin its vault entry allows, and no redirect is
  followed ([inference-proxy.md](inference-proxy.md#what-is-refused)).
- **Tools.** A client is shown only the tools of the signed MCP servers its
  token was granted, and a session's tools are fixed when it opens. Each call
  is then an agent's call: the stored-secret checks on arguments and output,
  the Tier 3 gate, and the operator's approval through `wirken permissions
  pending`, where a request nobody answers is denied
  ([proxy-mcp.md](proxy-mcp.md#the-gate)).

A model call is not asked of the operator. What a model may be told and may
answer is not gated beyond the stored-secret check; it is recorded.

## What is recorded

Everything a client does through the listener is rows on the audit chain, on
a lane of its token, `proxy-<token id>-<label>`, under signed chain heads
like any session.

| What happened | Rows | They hold |
|---|---|---|
| A model call | `proxy_request`, `proxy_response` | Token, upstream, model, timing, token counts and cost, and the SHA-256 of each body as exchanged. No body. |
| A request refused | `proxy_refused` | Token when known, and the reason. |
| An MCP session opened | `proxy_tools_listed` | The tools shown, by name, and the hash of their definitions. |
| A tool call | `assistant_tool_calls`, `permission_approved` or `permission_denied`, `tool_result`, `proxy_tool_call` | The tool, its arguments and its output, the operator's decision, and the hashes of the request and answer. |
| A tool request refused before the gate | `proxy_tool_refused` | The tool and the reason. |

One conversation is one lane. A client that sends the same
`X-Wirken-Session` label on its model calls and its MCP requests has both on
one lane, in order ([inference-proxy.md](inference-proxy.md#sessions),
[proxy-mcp.md](proxy-mcp.md#sessions)). `wirken proxy sessions` lists the
lanes.

The difference between the two kinds of row matters later: a model call's
rows hold hashes, and a tool call's rows hold the arguments and the output
themselves.

## What is archived

The chain holds hashes of model-call bodies, not the bodies. With `archive`
in `proxy.json`, each body is written to an S3-compatible bucket under Object
Lock: the request and response of every model call, the tool list of every
MCP session, the request and answer of every tool call. Each is encrypted
before upload under a key of its own, kept in the data directory and wrapped
under a key in the vault. A call whose request cannot be archived is refused
([proxy-archive.md](proxy-archive.md#write-once-archive)).

Without an archive nothing but the rows is kept.

## Looking at it afterwards

| To | Command | Page |
|---|---|---|
| Check a session against its chain and, with an archive, each body against its row | `wirken sessions verify <lane>` | [proxy-archive.md](proxy-archive.md#verifying-a-proxy-session) |
| Find text across sessions, in rows and in archived bodies | `wirken sessions search <text>` | [audit-cli.md](audit-cli.md#wirken-sessions-search) |
| Write one session as an ATIF trajectory file | `wirken sessions export <lane> --format atif` | [proxy-archive.md](proxy-archive.md#exporting-a-session) |
| Make archived bodies unreadable | `wirken proxy archive redact --session <lane> --reason <why>` | [proxy-archive.md](proxy-archive.md#redacting-an-archived-body) |

Search keeps text it extracted from a body encrypted under that body's own
key, so the index is never a plaintext copy and goes with the key
([proxy-archive.md](proxy-archive.md#search-text-at-rest)).

Redaction destroys a body's key. The object stays locked in the bucket and
nothing can read it. It does not change the chain: the rows of the call
stay, and for a tool call so do the arguments and output they hold.

All four are operator commands. `search` and `redact` refuse inside a Wirken
`exec`.

## What the mode does not do

- It does not make a client's agent one of Wirken's. The client's model loop,
  prompts and built-in tools are its own.
- It does not translate between provider shapes, and serves no Gemini or
  Bedrock shape.
- It does not authenticate a person. A token names a client, not who is at
  it.
- It serves MCP tools only: no resources, prompts or sampling.

The trust boundaries are in [threat-model.md](threat-model.md#proxy-clients).
