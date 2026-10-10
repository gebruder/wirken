# MCP Setup

Wirken includes an MCP (Model Context Protocol) client. MCP servers expose tools, resources, and prompts that the agent can use alongside its built-in tools.

A stdio MCP server runs in a container of its own, under the same hardening as the `exec` sandbox. It is installed beforehand, nothing is fetched when it starts, and it has no network unless its entry lists the hosts it may reach. Stdio servers therefore need Docker, or a per-server opt-out that runs them on the host.

## Configuration

Install the server into a directory of its own, and pull the image it runs in:

```bash
mkdir -p ~/.wirken/mcp/filesystem
npm install --prefix ~/.wirken/mcp/filesystem @modelcontextprotocol/server-filesystem
docker pull node:22-slim
```

Then add it to `~/.wirken/mcp.json`:

```json
{
    "servers": {
        "filesystem": {
            "command": "/opt/mcp/node_modules/.bin/mcp-server-filesystem",
            "args": ["/projects"],
            "sandbox": {
                "image": "node:22-slim",
                "install_dir": "/home/user/.wirken/mcp/filesystem",
                "mounts": [
                    { "source": "/home/user/projects", "target": "/projects" }
                ]
            }
        }
    }
}
```

`install_dir` is mounted read-only at `/opt/mcp`, which is also the working directory. `command` and `args` run as the container's entrypoint, so the image's own entrypoint is not used. Wirken talks to the server over its stdin and stdout using JSON-RPC 2.0.

If the entry is signed, re-sign it after any change to it, the `sandbox` block included: `wirken mcp sign filesystem`.

### The `sandbox` block

| Field | Default | Meaning |
|---|---|---|
| `image` | required | Image the server runs in. Pull it first; the proxy does not. A digest-pinned reference (`node:22-slim@sha256:...`) fixes what runs. |
| `install_dir` | none | Absolute host path, mounted read-only at `/opt/mcp`. |
| `mounts` | none | `{ "source", "target", "writable" }`. Read-only unless `writable` is `true`. `source` must be an absolute path that exists. `target` must be absolute, and may not be, or sit under, `/opt/mcp`, `/scratch`, `/run/wirken-secrets`, `/tmp`, `/proc`, `/sys` or `/dev`. |
| `scratch` | `false` | A writable directory at `/scratch`, kept on the host at `~/.wirken/mcp-scratch/<agent>/<server>`. |
| `egress.hosts` | none | Domain names the server may reach over HTTP(S). Empty or absent means no network. See [Network](#network). |
| `limits` | 512 MB, 256 processes, 1 CPU | `memory_mb`, `pids`, `cpus`. Each one given replaces its default; there is no ceiling. |
| `secrets_in_env` | none | `vault:` variables to deliver in the environment instead of as files. See [Using vault secrets](#using-vault-secrets-in-mcp-config). |

Every container also gets: all Linux capabilities dropped, `no-new-privileges`, Docker's default seccomp profile, a read-only root with a 64 MB tmpfs at `/tmp`, and the operator's own uid and gid (container uid 0 under a rootless runtime, which is the operator). `sandbox.json`'s `mode` chooses the runtime: `gvisor` runs servers under `runsc`, anything else under Docker's default. `"mode": "off"` turns off the `exec` sandbox only. It does not run MCP servers on the host.

### Running one server on the host

`"sandbox": "off"` runs that one server as a child process of the proxy, outside any container, with the trust model described under [`"sandbox": "off"`](#sandbox-off) below. It needs no container runtime. Every start logs a warning and writes `mcp_server_unsandboxed` to the audit chain.

```json
"legacy-tool": { "command": "/usr/local/bin/legacy-mcp", "sandbox": "off" }
```

### When a server is not started

The proxy refuses a stdio server, logs why and what to change, and writes `mcp_entry_refused` with one of these reasons:

| Reason | When |
|---|---|
| `sandbox_config_invalid` | No `sandbox` block. A block with no `image`. A path that is not absolute or does not exist. A reserved or repeated mount target. A limit of zero. An `egress.hosts` entry that is not a domain name. A `secrets_in_env` name that is not a `vault:` variable. |
| `sandbox_unavailable` | No container runtime answers. A secret has to be delivered as a file and the host has no memory-backed directory for it. The egress sidecar's binary is missing. |
| `image_unavailable` | The image is not on the host. |
| `egress_unsupported_runtime` | `egress.hosts` is set and the runtime is rootless Docker, Podman, or Windows. |

A refused server is not retried; fix the entry or the host and restart the gateway. `wirken mcp verify` and `wirken doctor` both name stdio entries that will be refused for want of a `sandbox` block, before the gateway starts.

**Entries from before this release** have no `sandbox` block and are refused with `sandbox_config_invalid`. There is no silent fallback to the host. Either add a block naming the server's image (and an `install_dir` in place of `npx -y`), or set `"sandbox": "off"`; then re-sign the entry if it is signed.

## Using vault secrets in MCP config

Prefix an `env` value with `vault:` to resolve it from the encrypted credential vault. The vault entry must already exist. Vault entries are populated by `wirken setup` (provider API key), `wirken channel add` (per-channel tokens), and `wirken credentials add NAME`, which stores an arbitrary secret under `NAME` for reference as `vault:NAME` in `mcp.json`.

By default a `vault:` value is delivered as a file, not as an environment variable. `TOKEN` becomes `TOKEN_FILE=/run/wirken-secrets/TOKEN`, pointing at a file readable only by the server's uid, in a memory-backed host directory (`$XDG_RUNTIME_DIR`, else `/dev/shm`) mounted read-only. The value is in no process environment and in no container configuration. The file is removed when the server stops.

A server that reads its credential only from its environment needs the variable listed in `secrets_in_env`. The value is then in the container's environment, where the server's own processes and anyone with access to the Docker socket (`docker inspect`) can read it. The `mcp_server_sandboxed` row names every variable delivered this way.

The official GitHub server is one such server. It reads its token only from `GITHUB_PERSONAL_ACCESS_TOKEN` and has no shell to read a file into it. Delivered as a file, the token goes unread: the server starts without one, and at its first call tries to log in through `github.com`, which its sidecar refuses because only `api.github.com` is listed. So its entry lists the variable in `secrets_in_env`:

```bash
docker pull ghcr.io/github/github-mcp-server
```

```json
{
    "servers": {
        "github": {
            "command": "/server/github-mcp-server",
            "args": ["stdio"],
            "env": {
                "GITHUB_PERSONAL_ACCESS_TOKEN": "vault:github-token"
            },
            "sandbox": {
                "image": "ghcr.io/github/github-mcp-server",
                "egress": { "hosts": ["api.github.com"] },
                "secrets_in_env": ["GITHUB_PERSONAL_ACCESS_TOKEN"]
            }
        }
    }
}
```

## Network

A server with no `egress.hosts` runs with `--network none`.

A server that lists hosts gets the route `exec` gets under an allowlist ([egress.md](egress.md#sandbox-egress)): an internal network it shares only with its own egress sidecar, which is its `HTTP_PROXY` and `HTTPS_PROXY`, and a decision broker in `wirken-mcp-proxy`. For every connection the server opens through the sidecar, a CONNECT tunnel or a plain-HTTP request, the broker checks the target against the listed hosts, resolves the name itself, and drops any address outside global unicast. Each verdict, allowed or not, is a `sandbox_egress_verdict` row naming the agent and the server (`mcp_server`). Requests a server sends inside a tunnel it already holds are not decided again: a row stands for a connection, not for each HTTP request on it.

- An entry is a domain name, `*.` and a domain name (one label under it), or `*` for any domain name.
- CONNECT to port 443 and plain HTTP to port 80 are the only requests forwarded. IP-address targets are refused whatever the list says.
- A server that ignores the proxy variables and opens its own socket has no route anywhere.
- The CONNECT tunnel is not inspected after the target is decided. A client that presents a different TLS server name inside an allowed tunnel reaches whatever the allowed host's address serves for that name.

Proxied egress is verified on rootful Docker on Linux, and refused elsewhere with `egress_unsupported_runtime`. `--network none` works on every runtime.

## How it works

On startup, `wirken-mcp-proxy`:

1. Verifies each entry's signature (see [Signing MCP entries](#signing-mcp-entries)).
2. Removes any container, network and secret file an earlier proxy for the same data directory left behind.
3. Starts each stdio server in its container, one container per agent and server, labelled with the data directory's instance, the agent and the server, and writes `mcp_server_sandboxed`.
4. Performs the MCP `initialize` handshake and calls `tools/list` to discover tools.
5. Adds discovered tools to the agent's tool definitions, prefixed with `mcp_{server}_`.

When the LLM calls an MCP tool, the proxy routes the call to the correct server via `tools/call` and returns the result. When the gateway stops, the proxy stops and removes every container, sidecar, network and secret file it started.

### Restarts

When a contained server's container exits, the proxy writes `mcp_server_exited`, removes it, and starts the server again, running `initialize` and `tools/list` before the new run takes calls. Each restart is an `mcp_server_restart` row with its cause (`exited`, `start_failed` or `initialize_failed`) and delay. The delay starts at one second, doubles to a minute, and goes back to one second after a run that stayed up for a minute. After eight runs in a row that never complete `initialize`, the proxy writes `mcp_server_restart_abandoned`, logs an error, and stops trying until the gateway restarts. A server that initializes and later exits is restarted without limit.

When a run fails `initialize` or its container exits, the proxy logs the last 20 lines the server wrote to stderr, read before the container is removed. They go to the log only, not the audit chain: they are the server's own text and can hold anything, a credential included.

Servers run with `"sandbox": "off"` are not restarted.

## Per-agent MCP config

For multi-agent setups, place the config at `~/.wirken/agents/{agent-id}/mcp.json`. If a per-agent config doesn't exist, the shared `~/.wirken/mcp.json` is used.

## Trust boundary

MCP servers are an explicit trust extension by the operator. Read this section before adding a server.

### Process topology

```
wirken run                        gateway + agent (holds the vault key, provider API keys, audit handle)
  └─ wirken mcp-proxy             separate subprocess; resolves vault: values for MCP servers
       ├─ <server container>      one per agent and server, started through the container runtime
       └─ <egress sidecar>        one per server that lists egress hosts; that server's only route out
```

The proxy reaches each server through the container runtime's attach stream, not as a child process. Provider API keys, the agent's session log writer, and adapter Ed25519 secrets live in the gateway process and adapter subprocesses, and are not reachable from inside a server's container.

### What a contained server can reach

- **Files:** its install directory (read-only), the mounts its entry declares, its scratch directory, its own secret files, and its `/tmp`. Not the operator's home or the data directory (`audit.db`, `vault.db`, agent identity keys) unless a mount puts them there.
- **Network:** nothing, or HTTP(S) to its listed hosts through its sidecar.
- **Credentials:** the `vault:` values in its own `env` block, and nothing else from the vault.
- **Resources:** its memory, process and CPU limits.
- **Its declared tool surface,** which is operator-trusted like any tool.

### What containment does not cover

- **The kernel.** Under Docker's default runtime the container shares the host kernel, bounded by namespaces, the default seccomp profile and an empty capability set. `sandbox.json` `"mode": "gvisor"` puts it under `runsc` instead.
- **Writable mounts.** Files a server writes there are owned by the operator's uid on the host.
- **Env-delivered secrets.** A variable in `secrets_in_env` is readable through `docker inspect` by anyone who can reach the Docker socket.
- **The image.** The signature covers the entry, not the image's contents; a digest-pinned `image` fixes them.

### `"sandbox": "off"`

A server with `"sandbox": "off"` runs as a child of `wirken-mcp-proxy` at the operator's UID, with no `cap_drop`, seccomp filter, namespace or resource limit. `StdioTransport::spawn` clears its environment and adds back only allowlisted shell variables and its own `env` block. What is at risk is the operator's blast radius:

- **Operator UID filesystem.** It can read or write anything the operator can, `audit.db` and the home directory included. Byte-tampering of `audit.db` is detected by `wirken sessions verify`, after the fact.
- **Operator UID network reach.** Outbound to any host the operator can reach.
- **Per-MCP credentials in `env`.** Anything in its `env` block, `vault:`-resolved secrets included, is plaintext in its environment.

Treat such a server like a third-party CLI: audit the source and the package provenance before adding it, and give it only the credentials it needs.

### Signing MCP entries

`mcp.json` entries can carry an Ed25519 signature over the entry's canonical hash. The pattern mirrors signed skills: signatures are computed by an operator (or registry) key, an optional compile-time bundled root anchors trust, and the proxy refuses unsigned entries under an anchored build unless an explicit bypass is set.

**Default build.** `crates/mcp-proxy/src/wirken-mcp-pubkey.pub` ships empty. With no anchor, unsigned entries load (pre-anchor parity); signed entries verify against their inline `signer_key`; an invalid signature is always a hard fail.

**Anchored build.** Populate `wirken-mcp-pubkey.pub` with a hex-encoded 32-byte Ed25519 public key and rebuild. Under an anchor, each entry's `signer_key` must additionally carry a `signer_key_delegation` Ed25519 signature by the anchor over the raw 32-byte signer key. Unsigned entries refuse to load unless `WIRKEN_ALLOW_UNSIGNED_MCP=1` is set, in which case the bypass is logged on every spawn and recorded on the audit chain as `mcp_entry_verified` with signer `<unsigned-bypass>`.

**Anchor rotation requires rebuilding the binary.** An anchor file at the same UID as the gateway adds no real defense; the anchor is meaningful only when the binary itself is what an attacker cannot replace without operator action.

**Canonical hash layout.** `crates/mcp-proxy/src/mcp_signing.rs::hash_mcp_entry` is the source of truth.

- **Stdio:** `sha256("stdio\0" || name_len_le || name || command_len_le || command || arg_count_le || (per-arg arg_len_le || arg) || env_count_le || (per-env key_len_le || key) || sandbox)`. Env keys, sorted ascending. Env values are not in the payload because they are `vault:NAME` references the proxy resolves at load time; the signature stays stable across vault rotations of the same logical credential.
- **Stdio `sandbox`:** absent, it adds nothing, so an entry signed before the block existed keeps its signature (and is then refused at start for having no block). Present, it is `"sandbox\0"` followed by `"off\0"`, or by `"container\0"` and every field of the block: `image` and `install_dir` (each a presence byte, then length-prefixed), `egress.hosts` sorted and deduplicated, `mounts` sorted by target, source and `writable` (each as source, target and a `writable` byte), a `scratch` byte, `memory_mb`, `pids` and the bits of `cpus` (each a presence byte, then a little-endian `u64`), and `secrets_in_env` sorted and deduplicated. Lists are a little-endian `u32` count, then each item length-prefixed. Widening a server's hosts or mounts, raising its limits, or moving a secret into its environment changes the hash, so a signed entry no longer verifies until it is re-signed.
- **Http:** `sha256("http\0" || name_len_le || name || url_len_le || url || auth_kind_le)` where `auth_kind_le` is `u8`: 0 = none, 1 = bearer, 2 = oauth2. The credential ref is not in the payload for the same reason.

**What the signature attests.** "This is the entry config the publisher intended," the sandbox block included: the image reference, what the server may reach, and how its secrets are delivered. It does not attest to the binary at `command` resolving to a specific artifact on disk, nor to an image tag resolving to specific contents; a digest-pinned `image` does that: a signed entry whose `command` is `/usr/local/bin/foo` verifies the same on two operator machines where `foo` is built differently. Per-binary attestation is a separate concern (operator's package manager, sandbox posture).

**CLI.** `wirken mcp sign <server>` signs one entry against `~/.wirken/signing-key.hex` (shared with `wirken skills sign`; generated on first use). `wirken mcp verify [<server>]` reports `valid` / `invalid` / `unsigned` per entry, applying the delegation gate when an anchor is configured.

**Audit.** Every load attempt lands on the `gateway-mcp` sentinel session as `SessionEvent::McpEntryVerified { server_name, signer }` or `SessionEvent::McpEntryRefused { server_name, reason }`. A stdio entry that verified and was then refused by the sandbox has both rows; its `reason` is one of the four in [When a server is not started](#when-a-server-is-not-started). The same session carries how each server ran:

| Kind | Written |
|---|---|
| `mcp_server_sandboxed` | At every contained start, restarts included: agent, image, image id and registry digest, runtime, container id, egress hosts, mounts, limits, and the names of secrets delivered as files and through the environment. Never a value. |
| `mcp_server_unsandboxed` | At every start of a server with `"sandbox": "off"`. |
| `mcp_server_exited` | A contained server's container exited, with its exit code: on its own, or stopped by the proxy at shutdown (`stopped_by_proxy: true`). |
| `mcp_server_restart` / `mcp_server_restart_abandoned` | See [Restarts](#restarts). |
| `sandbox_egress_verdict` | One per request through a server's sidecar, with `mcp_server` set. |

All of them are on the default typed-SIEM forwarded set; consumers can pivot on `kind == "mcp_entry_refused"` without an opt-in.

## Supported transports

- **stdio**: start the server in its container (or, with `"sandbox": "off"`, as a host process) and communicate via stdin/stdout. Default for local MCP servers.
- **HTTP**: connect to a remote MCP server over HTTP/HTTPS. Supports three auth modes:
  - `NoAuth`: no authentication header.
  - `BearerAuth`: static bearer token from the vault.
  - `OAuth2Auth`: authorization code flow with PKCE via the `oauth2` crate. Token refresh is automatic. Bootstrap an OAuth credential with `wirken mcp authorize <server>`; see [`credentials.md`](credentials.md) for the interactive scope picker and the inspection / rescoping commands.

The MCP proxy runs as a separate process (`wirken-mcp-proxy`), communicating with the agent over a Unix domain socket. MCP credentials (bearer tokens, OAuth2 client secrets) are held in the proxy process and never exposed to the agent.

## Declaring what a tool costs

An MCP tool can carry a per-call cost, in USD micros, on its server entry:

```json
{
  "servers": {
    "vendor": {
      "transport": "stdio",
      "command": "/opt/mcp/vendor-mcp",
      "sandbox": { "image": "debian:bookworm-slim", "install_dir": "/opt/vendor-mcp" },
      "tool_costs": { "provision": 600000 }
    }
  }
}
```

A tool named here is gated by the agent's budget rather than by the permission tier model. Before the call, the window's spend is checked against the agent's ceiling; after a call that succeeded, the declared cost is debited. Both go through the same ledger and the same `BudgetExceeded` row that inference spend uses, so one budget covers both. A refused or failed call debits nothing.

A tool absent from `tool_costs` is not budget gated and debits nothing, which is every tool on every server until an operator declares otherwise. Spend is not a permission tier, so nothing about a declared cost changes what tier a tool sits at: MCP tools stay Tier 3 and still prompt.

The figure is what the operator declares, not what the vendor charges. Nothing reconciles the two. This is a budget set against calls known to be expensive, not metering.

`tool_costs` is inside the signed entry envelope. Declaring, editing or removing a cost changes the entry hash and requires re-signing, so a cost cannot be zeroed while the entry still verifies. Entries signed before the field existed hash unchanged and keep working.

When the gate turns a call away, the `BudgetExceeded` row names the tool:

```json
{ "kind": "budget_exceeded", "agent_id": "default",
  "window_spend_usd_micros": 600000, "ceiling_usd_micros": 500000,
  "window": "day", "action": "blocked", "tool": "mcp_vendor_provision" }
```

An inference block carries no `tool`, which is how the two are told apart.
