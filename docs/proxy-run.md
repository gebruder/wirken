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
    -- my-agent
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

The client holds the token itself, not a placeholder for it. A client that
sends it to an `--egress` host gives away something the listener accepts
only on this host's loopback, and only until the run ends. A placeholder,
swapped for the token on the host side, would not narrow that further: the
container runs as the operator's uid, so the operator's own processes can
read the client's environment, as they could read the token from the process
that would hold it instead.

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

## Running a coding agent

What a coding client needs to run here, in the order it is set up. `<client>`,
`<image>` and the file names stand for the client's own.

### 1. An image with the client in it

A run does not pull or install. Build an image on the host with the client
and what it calls: its runtime, `git`, the search tools its file tools use.
Pin the client's version.

```dockerfile
FROM <runtime image>
RUN <install git and the tools the client calls>
RUN <install the client at a pinned version>
```

Whatever the client would fetch at start, such as a newer version, a model
catalog or a helper binary, it cannot fetch in a run unless the host is named
with `--egress`. Put it in the image, or turn the fetch off (step 4).

### 2. Its configuration, through a read-only folder

A run takes no environment variables and no config files on its command line.
Put the client's config files and a start script in a folder and give it
with `--read-only`; the folder is at `/mnt/ro/<folder name>`. The script
copies the files into the client's home, which is writable and kept for the
workspace, sets what the client reads from its environment, and starts it:

```sh
#!/bin/sh
mkdir -p "$HOME/<config dir>"
cp /mnt/ro/<folder name>/<config files> "$HOME/<config dir>/"
cd /workspace
exec <client> <flags>
```

Give the script as the command, `-- sh /mnt/ro/<folder name>/start.sh`. The
command is not run through a shell, so a variable in it is not expanded: one
more reason for the script.

### 3. A model provider at the listener

Configure the client with a provider for an OpenAI chat-completions endpoint
at `http://127.0.0.1:18791/v1`, or an Anthropic messages endpoint at
`http://127.0.0.1:18791`, with its key read from `$OPENAI_API_KEY` or
`$ANTHROPIC_AUTH_TOKEN`. Both hold the run's token. The model is one the
token allows (`--model`), named as the upstream names it. A client that reads
`OPENAI_BASE_URL` or `ANTHROPIC_BASE_URL` needs no provider entry. A client
that only signs in to a subscription cannot be run.

Turn off the client's use of tools the provider runs, such as a web search,
a fetch or code execution: the listener refuses a request that names one
(`provider_tool`, [inference-proxy.md](inference-proxy.md#what-is-forwarded)).

### 4. Its own network calls, off

Clients reach out at start: an update check, a model or price catalog,
telemetry, the download of a helper tool. In a run each is refused at the
sidecar and recorded as a `sandbox_egress_verdict` row on the run's lane, and
the client carries on, or fails, as it would offline. Turn them off with the
client's offline or no-telemetry settings, or name a host with `--egress`
when the client needs it. The verdict rows show what it tried.

### 5. Tools at the MCP endpoint

For tools the operator holds, grant the run an agent's signed MCP servers
with `--mcp-server` and `--agent`, and configure the client with one
streamable-HTTP MCP server at `http://127.0.0.1:18791/mcp` that sends
`Authorization: Bearer <the value of WIRKEN_PROXY_TOKEN>`, in whatever form
the client reads a variable into a header. Where the client offers a choice,
declare the tools to the model directly: a small model calls a declared tool
more reliably than one it has to search for. The tools are named
`<server>_<tool>` ([proxy-mcp.md](proxy-mcp.md)).

Each call waits at the agent's gate until the operator answers, from another
terminal:

```bash
wirken permissions pending list
wirken permissions pending approve <id>
```

A call nobody answers is denied after 300 seconds
([proxy-mcp.md](proxy-mcp.md#the-gate)), and the client gets the refusal as
the tool's result.

### 6. A git identity

The home starts empty, so `git` in the run has no name or email, and a client
that commits uses a placeholder or fails. Write one into the workspace's home
once, from the host. The home is `<data dir>/proxy-run/<workspace id>/home`,
made by the workspace's first run, where the id is the first sixteen hex
characters of the SHA-256 of the workspace's resolved path:

```bash
id=$(printf '%s' "$(realpath <workspace>)" | sha256sum | cut -c1-16)
git config --file <data dir>/proxy-run/$id/home/.gitconfig user.name "<name>"
git config --file <data dir>/proxy-run/$id/home/.gitconfig user.email "<email>"
```

### 7. Start it at a terminal

The run attaches the client to the terminal it is started at, and refuses to
start without one. Start it from a shell of your own, not from a tool that
runs commands without a terminal. Ctrl-C goes to the client; quit the client
the way it quits, and the run ends with it.

### A first run

Try a one-shot task before an interactive session: most clients take a
prompt and exit. Then read what the run recorded:

```bash
wirken proxy sessions --token <token id>
wirken sessions verify proxy-<token id>
```

The run's lane carries what the client tried to reach; the conversation
lanes, its model calls; an MCP session's lane, its tool calls and their
approvals.

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
data directory removes every container, network and broker socket directory
a run left whose process is gone, and revokes their tokens, before it starts
its own. A socket directory is named for its run's process, and only a
directory of the operator's under the system's temporary directory is
removed.

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
