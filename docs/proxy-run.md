# Proxy run

A client pointed at the proxy listener from outside keeps its own shell, its
own files and its own network. For a coding agent that is most of what it
does: it acts through its own tools, not through MCP, and Wirken sees none of
it ([proxy.md](proxy.md)). `wirken proxy run` starts the client itself, in a
container whose only way out is the listener, so its shell and its files are
bounded too.

```bash
wirken proxy run --image my-agent-image \
    --workspace ~/src/project --read-only ~/src/docs \
    --egress registry.npmjs.org \
    --upstream anthropic --ceiling-usd 5 \
    -- claude
```

The run attaches the container to the terminal it was started at, and ends
when the client exits. Its exit status is the client's.

## What the client gets

| | |
|---|---|
| Files | The workspace read-write at `/workspace`; each `--read-only` folder at `/mnt/ro/<its name>`, up to eight; a home at `/home/wirken`; a 64 MB `/tmp`. Nothing else: the root is read-only. |
| Network | The listener at `http://127.0.0.1:18791` on the container's own loopback, and HTTPS on 443 or HTTP on 80 to the `--egress` hosts through its sidecar. No other host, no address, no resolver. |
| Credentials | One token, minted for the run from the grant flags, the same flags `proxy token issue` takes. No provider key and no MCP server's credential. |
| Limits | 4 GiB of memory, 1024 processes, two CPUs. Every capability dropped and none added back, `no-new-privileges`, the seccomp profile, and `runsc` where `sandbox.json` sets `gvisor`, as for an `exec` ([sandbox-properties.md](sandbox-properties.md#container-hardening-applies-to-execonly-and-gvisor)). It runs as the operator's uid. |

The client finds the listener and its token in its environment:

| Variable | Value |
|---|---|
| `WIRKEN_PROXY_URL` | `http://127.0.0.1:18791` |
| `WIRKEN_PROXY_TOKEN` | the run's token |
| `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN` | the listener, the token |
| `OPENAI_BASE_URL`, `OPENAI_API_KEY` | the listener's `/v1`, the token |
| `HTTP_PROXY`, `HTTPS_PROXY` | the sidecar |
| `HOME` | `/home/wirken` |

The MCP endpoint is at `$WIRKEN_PROXY_URL/mcp`, with the token as its bearer,
for a client given `--mcp-server` ([proxy-mcp.md](proxy-mcp.md)).

A client that signs in to a subscription in place of an API key is not
served: the run holds no provider credential to give it, and a sign-in would
need a host the run does not reach.

## How it reaches the listener

The container's first process is a relay on its loopback. It runs the
client's command and copies every connection to its address to the run's
sidecar, which hands it over a Unix socket to the `wirken proxy run` process,
which copies it to the listener. None of the three reads what it copies. The
listener checks the token and records each call as for any client
([inference-proxy.md](inference-proxy.md#what-is-recorded)). A listener with
`tls` is refused: the route carries plain HTTP.

The gateway must be running, and its `proxy.json` must allow the grants.
Docker's default runtime is needed, as for a contained MCP server with
egress: rootless Docker, Podman and Windows are refused. The image must be
on the host; a run does not pull. The relay and the sidecar run the static
`wirken` binary, `sandbox.json`'s `sidecar_binary` where it is set.

## The client's home

A workspace has one home, kept between runs, under
`<data dir>/proxy-run/<workspace id>/home`, so a client's sign-in to its own
tools, its settings and its saved conversations last from one run to the
next. A run without a workspace has a home of its own. A home is the
operator's to remove.

## What is recorded

On the run token's lane, `proxy-<token id>`:

| Row | When |
|---|---|
| `proxy_run_started` | The container is created, before it starts: the image and its id and registry digest, the runtime, the command, the mounts, the egress hosts and the limits. |
| `sandbox_egress_verdict` | Each request to the sidecar, allowed or refused, with the token as its sender and `proxy-run` as its agent. |
| `proxy_run_ended` | The container exited, with its exit code, or was stopped because the run was. |

The token's minting and its revocation are `operator_command` rows on the
`gateway-operator` lane, as for `proxy token issue` and `revoke`: the first
before anything starts, the last after the container is removed.

The client's model and tool calls are on the token's conversation lanes,
`proxy-<token id>-<label>`, as for any client. `wirken proxy sessions --token
<id>` lists them.

## When a run is cut short

`SIGTERM`, `SIGINT` or `SIGHUP` to the run, the last of them when its
terminal goes away, stops the container and then ends the run as above.
Ctrl-C at the terminal goes to the client, not to the run. A run killed outright (`SIGKILL`) leaves its
container running with its token live. The next `wirken proxy run` of the
data directory removes every container and network a run left whose process
is gone, and revokes their tokens, before it starts its own.

## What it does not do

- It does not gate or record what the client does inside the container. A
  shell command there is not an `exec`: what is bounded is what the client
  can reach, not what it runs.
- It does not intercept TLS. The client holds no provider key, so there is
  none to swap, and it reaches the provider only through the listener.
- An allowed host is allowed for the whole run. Hosts are named at the
  start; none can be added while the run lasts, and nothing asks.
- A package registry named with `--egress` serves whatever it serves. No age
  gate or allowlist applies to the packages fetched from it.
- No Docker inside the container.
- An allowed host is checked on the name a tunnel is opened to. What the
  client sends inside the tunnel is not seen
  ([egress.md](egress.md#sandbox-egress)).
- Files the client writes to the workspace or its home are owned by the
  operator's uid on the host.
