# MCP Setup

Wirken includes an MCP (Model Context Protocol) client. MCP servers expose tools, resources, and prompts that the agent can use alongside its built-in tools.

## Configuration

Create `~/.wirken/mcp.json`:

```json
{
    "servers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"],
            "env": {}
        }
    }
}
```

Each server entry specifies a command to spawn. Wirken communicates with the server over stdin/stdout using JSON-RPC 2.0.

## Using vault secrets in MCP config

Prefix environment variable values with `vault:` to resolve them from the encrypted credential vault:

```json
{
    "servers": {
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {
                "GITHUB_TOKEN": "vault:github-token"
            }
        }
    }
}
```

The vault entry referenced by `vault:github-token` must already exist. Vault entries are populated by `wirken setup` (provider API key), `wirken channel add` (per-channel tokens), and `wirken credentials add NAME`, which stores an arbitrary secret under `NAME` for reference as `vault:NAME` in `mcp.json`. An MCP server can also read a credential from a regular environment variable in the `env` block instead.

## How it works

On startup, wirken:

1. Spawns each configured MCP server as a child process
2. Performs the MCP `initialize` handshake
3. Calls `tools/list` to discover available tools
4. Adds discovered tools to the agent's tool definitions (prefixed with `mcp_{server}_`)

When the LLM calls an MCP tool, wirken routes the call to the correct server via `tools/call` and returns the result.

## Per-agent MCP config

For multi-agent setups, place the config at `~/.wirken/agents/{agent-id}/mcp.json`. If a per-agent config doesn't exist, the shared `~/.wirken/mcp.json` is used.

## Example: Datadog MCP

Connect the agent to Datadog for querying logs, metrics, and incidents:

```json
{
    "servers": {
        "datadog": {
            "command": "npx",
            "args": ["-y", "@datadog/mcp-server"],
            "env": {
                "DD_API_KEY": "vault:datadog-api-key",
                "DD_APP_KEY": "vault:datadog-app-key"
            }
        }
    }
}
```

## Trust boundary

MCP servers are an explicit trust extension by the operator. Read this section before pasting an MCP-server command from the internet into `mcp.json`.

### Process topology

```
wirken run                              gateway + agent (one process; holds vault key + provider API keys + audit handle)
  └─ wirken mcp-proxy                   separate subprocess; holds the resolved keychain for vault: lookups + per-MCP credentials
       └─ <your MCP server>             grandchild of the gateway; spawned by mcp-proxy with a sanitised environment
```

The MCP server runs as a grandchild of the gateway, parented by `wirken-mcp-proxy`. It does **not** share the gateway's address space. Provider API keys, the agent's session log writer, and adapter Ed25519 secrets all live in the gateway process and are not reachable from inside an MCP server process.

### What a compromised MCP server can reach

Protected (a compromised MCP server cannot reach these):

- **Provider API keys** (OpenAI, Anthropic, Bedrock, Tinfoil, Privatemode, …). They live in the gateway process memory and are used by the in-process agent.
- **Vault unwrap key.** `WIRKEN_VAULT_PASSPHRASE` is removed from `mcp-proxy`'s environ after `probe_keychain` reads it on startup, and `StdioTransport::spawn` calls `env_clear()` before adding back only the allowlisted shell variables (`PATH`, `HOME`, locale + `XDG_*`, etc.). The MCP child's environ does not contain the passphrase.
- **Vault contents at rest.** `~/.wirken/vault.db` is XChaCha20-Poly1305-encrypted. Without the unwrap key (above), the bytes are inert.
- **Adapter Ed25519 secrets.** Each adapter's secret stays in its own subprocess; the gateway resolves them once at handshake.

At risk (the operator's blast radius if an MCP server is malicious or compromised):

- **Operator UID filesystem.** Same UID as the gateway. The MCP child can read/write anything the operator can: `~/.wirken/audit.db`, the operator's home directory, any path outside `~/.wirken/` they have access to. Direct byte-tampering of `audit.db` is detected by `wirken sessions verify` (the hash chain catches it), but the tamper happens; the detection is after the fact.
- **Operator UID network reach.** Outbound to any host the operator can reach. Use a per-server `network` strategy if your MCP doesn't need that reach.
- **Per-MCP credentials in `env`.** Anything passed in via `mcp.json`'s `env` block is plaintext in the MCP child's environment — including `vault:`-resolved secrets. This is by operator design (you listed it), not an inadvertent leak. A compromised MCP server reads its own `env` and gets these tokens.
- **The MCP server's declared tool surface.** Whatever tools the MCP server exposes to the LLM are operator-trusted. A compromised filesystem-MCP server gives the LLM file ops within its bind-mount; a compromised git-MCP server gives the LLM `git` operations on its checkout.

### What the operator should do

- Treat each MCP server like a third-party CLI. Audit the source (or the `npx @org/package` provenance) before adding it to `mcp.json`.
- Use a per-server `env` block to pass only the credentials that server actually needs. Don't dump shared secrets across multiple MCP servers.
- For MCP servers that don't need the operator's network reach, run `wirken-mcp-proxy` (or the operator's whole gateway) inside a network-namespaced container or a `firejail` profile. Wirken does not yet ship per-MCP-server sandboxing — see the next section.

### Signing MCP entries

`mcp.json` entries can carry an Ed25519 signature over the entry's canonical hash. The pattern mirrors signed skills: signatures are computed by an operator (or registry) key, an optional compile-time bundled root anchors trust, and the proxy refuses unsigned entries under an anchored build unless an explicit bypass is set.

**Default build.** `crates/mcp-proxy/src/wirken-mcp-pubkey.pub` ships empty. With no anchor, unsigned entries load (pre-anchor parity); signed entries verify against their inline `signer_key`; an invalid signature is always a hard fail.

**Anchored build.** Populate `wirken-mcp-pubkey.pub` with a hex-encoded 32-byte Ed25519 public key and rebuild. Under an anchor, each entry's `signer_key` must additionally carry a `signer_key_delegation` Ed25519 signature by the anchor over the raw 32-byte signer key. Unsigned entries refuse to load unless `WIRKEN_ALLOW_UNSIGNED_MCP=1` is set, in which case the bypass is logged on every spawn and recorded on the audit chain as `mcp_entry_verified` with signer `<unsigned-bypass>`.

**Anchor rotation requires rebuilding the binary.** An anchor file at the same UID as the gateway adds no real defense; the anchor is meaningful only when the binary itself is what an attacker cannot replace without operator action.

**Canonical hash layout.** `crates/mcp-proxy/src/mcp_signing.rs::hash_mcp_entry` is the source of truth.

- **Stdio:** `sha256("stdio\0" || name_len_le || name || command_len_le || command || arg_count_le || (per-arg arg_len_le || arg) || env_count_le || (per-env key_len_le || key))`. Env keys, sorted ascending. Env values are not in the payload because they are `vault:NAME` references the proxy resolves at load time; the signature stays stable across vault rotations of the same logical credential.
- **Http:** `sha256("http\0" || name_len_le || name || url_len_le || url || auth_kind_le)` where `auth_kind_le` is `u8`: 0 = none, 1 = bearer, 2 = oauth2. The credential ref is not in the payload for the same reason.

**What the signature attests.** "This is the entry config the publisher intended." It does not attest to the binary at `command` resolving to a specific artifact on disk: a signed entry whose `command` is `/usr/local/bin/foo` verifies the same on two operator machines where `foo` is built differently. Per-binary attestation is a separate concern (operator's package manager, sandbox posture).

**CLI.** `wirken mcp sign <server>` signs one entry against `~/.wirken/signing-key.hex` (shared with `wirken skills sign`; generated on first use). `wirken mcp verify [<server>]` reports `valid` / `invalid` / `unsigned` per entry, applying the delegation gate when an anchor is configured.

**Audit.** Every load attempt lands on the `gateway-mcp` sentinel session as `SessionEvent::McpEntryVerified { server_name, signer }` or `SessionEvent::McpEntryRefused { server_name, reason }`. Both variants are on the default typed-SIEM forwarded set; consumers can pivot on `kind == "mcp_entry_refused"` without an opt-in.

### What this is not

This is not a sandbox. There is no `cap_drop`, seccomp filter, namespace, gVisor, or Wasm runtime around the MCP child. The `exec` tool runs in a Docker / gVisor sandbox per `docs/sandbox-properties.md`; MCP servers do not. Closing that asymmetry is design work that lands together with — or after — the broader decision about whether agents themselves should run as subprocesses (see `docs/architecture.md` §6 "Direct LLM calls"). Doing it before that decision would lock in container-isolation shapes around a process boundary the project hasn't yet committed to.

## Supported transports

- **stdio**: spawn process, communicate via stdin/stdout. Default for local MCP servers.
- **HTTP**: connect to a remote MCP server over HTTP/HTTPS. Supports three auth modes:
  - `NoAuth`: no authentication header.
  - `BearerAuth`: static bearer token from the vault.
  - `OAuth2Auth`: authorization code flow with PKCE via the `oauth2` crate. Token refresh is automatic. Bootstrap an OAuth credential with `wirken mcp authorize <server>`; see [`credentials.md`](credentials.md) for the interactive scope picker and the inspection / rescoping commands.

The MCP proxy runs as a separate process (`wirken-mcp-proxy`), communicating with the agent over a Unix domain socket. MCP credentials (bearer tokens, OAuth2 client secrets) are held in the proxy process and never exposed to the agent.
