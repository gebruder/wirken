# Egress

The skill-set `egress.domains` allowlist is a defense-in-depth control on a specific set of agent built-in tools, not a network boundary. This page documents what `egress.domains` covers, what it does not, and where operators bound the gaps.

## What `egress.domains` covers

`EgressClient` mediates outbound HTTP for three built-in agent paths:

- `web_search`: the agent's web-search tool.
- `generate_image`: the agent's image-generation tool.
- The Zirkel daily-fetch transport: `wirken zirkel run` uses an `EgressClient` constructed with an explicit `RateLimitConfig` so per-source daily budgets apply.

Each call resolves the request host against the agent's effective `egress.domains` allowset (the union of every loaded skill's `egress.domains` declaration). Hosts not in the allowset are denied pre-flight, before any TCP connection and without consuming the rate-limit budget. Wildcard `"*"` is supported on the allowset; `"*.example.com"` style suffix patterns are also supported.

Source: `crates/agent/src/egress.rs:246-282` (host-based check), `crates/agent/src/skill_perms.rs:831-889` (allowset resolution).

## What `egress.domains` does not cover

Three outbound paths bypass `EgressClient` entirely and are not constrained by skill-side allowlists.

### `exec` shell sink

When the agent invokes the `exec` tool, the host shell runs the command directly. Anything that command does (`curl https://attacker.example.com`, `wget`, `nc`, `msiexec /i http://...`, `powershell -c "Invoke-WebRequest ..."`, etc.) happens through the OS network stack at the wirken UID. The `egress.domains` allowlist is not consulted.

This applies under every `sandbox.json` mode that the gateway supports. Docker and gVisor sandboxes default to `no-network`, which is what bounds shell egress in those modes; the constraint lives in the container runtime, not in wirken. The `mode: off` path runs the shell on the host directly and has no network bound at all.

**Mitigation.** Run wirken inside a network namespace (Linux), a restricted-egress container, or with OS-level firewall rules (`iptables`, `nftables`, `pf`). Docker/gVisor sandbox modes provide the cleanest bound by default; `mode: off` requires explicit operator firewalling.

### MCP server children

MCP servers spawned by `wirken-mcp-proxy` are separate processes at the wirken UID with no process-level sandbox. They open their own outbound connections (HTTP, WebSocket, stdio, whatever the server speaks) directly through the OS. The agent's permission gate checks the MCP tool *name* before invocation but does not constrain what the child does once spawned.

**Mitigation.** Same as the `exec` sink: OS-level network controls. The gateway lists configured MCP server names at startup so the operator can see the inventory; install MCP servers only from trusted sources, and pin versions in `mcp.json`.

### LLM HTTP client

The agent's LLM client uses its own `reqwest::Client` so traffic to the configured provider always works regardless of the operator's egress posture for skill tools. The provider host is gated by `provider.json::base_url` (and by the bound channel-override `base_url` for channel-specific overrides) but not by `egress.domains`.

This is deliberate: an `egress.domains` rule that accidentally excludes the provider would break the agent entirely with a vague tool-side error, when the right place to enforce provider-host policy is the operator's network config.

**Mitigation.** Provider choice plus network controls. For TEE-backed providers (Tinfoil, Privatemode), end-to-end encryption to the enclave gives an additional confidentiality layer that does not depend on the network path.

## Cross-reference

The same gap appears in [security-properties.md](security-properties.md) under AG02 (Code execution), where it is described as a code-execution surface rather than a configuration-side scope. The two pages describe the same constraint from different angles; if you are reading this page to evaluate a deployment, the AG02 row carries the threat-model context.

## Source references

- `EgressClient` scope and host check: `crates/agent/src/egress.rs:154-282`.
- Allowset and wildcard resolution: `crates/agent/src/skill_perms.rs:831-889`.
- Threat-model row: [security-properties.md](security-properties.md), row `AG02` (Code execution).
