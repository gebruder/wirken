# MCP endpoint

Tool calls of a client Wirken does not run: how a token is granted tools,
what a session is shown, the gate each call passes and what is recorded. The
mode as a whole starts at [proxy.md](proxy.md).

The endpoint serves MCP tools on the proxy listener, to the token a client
uses for inference. The client holds no credential of any MCP server and
runs no server. It is shown tools; Wirken runs them.

## Granting a token tools

The tools are an agent's. A token names one agent and some of that agent's
MCP servers from [`mcp.json`](mcp.md):

```bash
wirken proxy token issue laptop --upstream anthropic \
    --mcp-server files --mcp-server notes --agent default
```

| Flag | Meaning |
|---|---|
| `--mcp-server` | An MCP server whose tools the token may list and call. Repeatable. |
| `--agent` | The agent the servers belong to, and whose permission gate the calls run under. `default` without it. |

A server can be granted only if its entry is signed (`wirken mcp sign
<server>`); `issue` refuses any other. The check is made again when a session
opens, so a server whose entry stopped verifying is no longer shown. A token
may have MCP servers and no `--upstream`.

The servers run where they run for the agent: a stdio server in its
container, with [credential injection](mcp.md#injecting-a-credential) where
its entry has an `inject` block, an HTTP server through the MCP proxy. Nothing
about a server changes because a client calls it.

## Pointing a client at it

The endpoint is `POST /mcp` on the proxy listener, MCP over Streamable HTTP.
With the default bind:

```json
{
    "mcpServers": {
        "wirken": {
            "type": "http",
            "url": "http://127.0.0.1:18791/mcp",
            "headers": {
                "Authorization": "Bearer wkp_...",
                "X-Wirken-Session": "my-task"
            }
        }
    }
}
```

The token is the one the client uses for inference, sent the same way.
`X-Wirken-Session` is optional; see [Sessions](#sessions).

A tool is shown as `<server>_<tool>`, with the description the server gave it
after `[<server>] `. On the chain the same tool is `mcp_<server>_<tool>`, the
name it has for the agent.

What is served: `initialize`, `ping`, `tools/list` and `tools/call`, one
JSON-RPC message a request, answered as JSON. A notification is accepted and
ignored. `DELETE /mcp` with the session id ends a session. Any other method
is answered with JSON-RPC error -32601, and `GET /mcp` with 405: the endpoint
sends a client nothing it did not ask for.

## Sessions

`initialize` opens a session and returns its id in `Mcp-Session-Id`, which
the client sends on every later request. A session belongs to the token that
opened it. It ends when the client deletes it, a day after it opened, or when
`wirken run` stops; a request with an id that is not held is answered 404,
and the client opens a new one.

A session's rows are on one lane:

- With `X-Wirken-Session: <label>` on `initialize`, the lane is
  `proxy-<token id>-<label>`. A client that sends the same label on its model
  calls has its inference and its tool calls on one lane, in the order they
  happened.
- Without it, the lane is `proxy-<token id>-m` and twelve hex characters, the
  session's own.

`wirken proxy sessions` lists both.

## The tools a session is shown

The tools are fixed when the session opens: those of the token's granted,
signed servers, as the agent has them then. `tools/list` returns that list
for as long as the session lasts.

A `tools/call` is checked against it before anything else:

- A tool the session was not shown is refused: another server's, one of the
  agent's own tools such as `exec`, anything.
- A tool whose definition is no longer the one shown, in name, description or
  input schema, is refused. A new session is shown the new definition.
- A tool the agent no longer has is refused.

## The gate

A call that passes those checks is run by the token's agent, as that agent's
own call:

1. Arguments carrying a secret the vault holds are refused.
2. The call is classified by `tool_to_action`. An MCP tool is Tier 3.
3. The operator is asked. Tier 3 is asked every time; no approval is stored.
4. The tool runs in its server.
5. Output carrying a secret the vault holds is replaced with a refusal.

The approval route is the operator's pending queue:

```bash
wirken permissions pending list
wirken permissions pending approve <id>
wirken permissions pending deny <id> [reason]
```

A client has no channel of its own to be asked on, and the person at the
client is not the approver. The call waits while the request is pending. One
nobody answers is denied after 300 seconds
(`WIRKEN_CLI_APPROVAL_TIMEOUT_S` on `wirken run`). A denied call is answered
to the client as a tool result with `isError: true` and the refusal as its
text.

## What is recorded

When a session opens, on its lane:

- `proxy_tools_listed`: `token_id`, `agent_id`, `mcp_session`, `servers`,
  the `tools` by name, `tools_sha256`, the SHA-256 of the list as the client
  gets it, and whether the list was archived.

For each call, in order:

- `assistant_tool_calls`, with the tool and its arguments, `sender_id`
  `proxy-token:<token id>` and the agent's id.
- `permission_approved`, or `permission_denied` with its `denial_reason`:
  the operator's, or `approval timeout`.
- `tool_result`, with what the tool returned or the refusal.
- `proxy_tool_call`: `call_id`, `token_id`, `agent_id`, `mcp_session`,
  `tool`, `success`, `latency_ms`, the SHA-256 and size of the request and
  of the answer as exchanged with the client, and whether they were archived.

The arguments and the output are on the chain itself, on the
`assistant_tool_calls` and `tool_result` rows. That is unlike a model call,
whose rows hold only hashes.

The call id is the id of the model's tool use when the client sends it in the
call's `_meta` (a key ending in `toolUseId`), which ties the row to the
model's answer on the same lane. Otherwise it is `mcp-` and a random value.

A request refused before the gate is a `proxy_tool_refused` row with a
`reason`. A refusal of a `tools/call` is on the session's lane; one made
before a session exists is on the token's lane, `proxy-<token id>`.

| `reason` | Refused because |
|---|---|
| `no_mcp_grant` | The token was granted no MCP server. |
| `not_granted` | The tool is not one the session was shown. |
| `definition_changed` | The tool's definition is not the one shown. |
| `malformed` | The body is not one JSON-RPC message, the call names no tool, its arguments are not an object, or the body is over `max_body_bytes`. |
| `unavailable` | The agent's tools could not be reached, the tool is not served now, or the call could not be run. |
| `record_failed` | The session's `proxy_tools_listed` row could not be written. |
| `archive_failed` | The tool list, or a call's request, could not be written to the archive. |

A request with no token, or a revoked one, is a `proxy_refused` row as for
inference ([inference-proxy.md](inference-proxy.md#what-is-refused)).

All three rows are forwarded to a SIEM by default, with the token in the
sender column.

## Archive, verify, export and redaction

With an archive configured, the tool list a session was shown and the request
and answer of each call are written to it. `sessions verify` checks them,
`sessions export` includes the calls, and `proxy archive redact --session`
destroys the keys of those bodies: all in
[proxy-archive.md](proxy-archive.md).

A tool call's arguments and output are on its rows, not only in the archive.
`proxy archive redact --session` rewrites those rows with the bodies, each
under a signed redaction record
([proxy-archive.md](proxy-archive.md#redacting-a-session)).

## Limits

- Tools only. Resources, prompts, sampling and server notifications are not
  served.
- A token's call and spend ceilings count its inference calls, not its tool
  calls.
- Sessions are held in memory.
- A long approval wait holds the client's request open.
