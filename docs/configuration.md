# Configuration reference

All configuration lives in the data directory: `WIRKEN_DATA_DIR` when set,
`~/.wirken` otherwise. The gateway, the CLI and the child processes the
gateway spawns all resolve it through one function, so setting the variable
moves every process at once.

## Files

| File | Purpose | Created by |
|------|---------|-----------|
| `provider.json` | LLM provider, model, base URL | `wirken setup` |
| `vault.db` | Encrypted credentials | `wirken setup` |
| `audit.db` | Session log (`session_events`, per-session hash chain) plus a legacy `audit_events` view for SIEM | `wirken run` |
| `audit/audit-signing.{key,pub}` | Chain-head signing keypair | `wirken run` |
| `audit-alarms.log` | Out-of-chain integrity alarms | `wirken run` |
| `sessions.db` | Session metadata | `wirken run` |
| `agent_config.db` | Agent configs, channel bindings, subagent ceilings | `wirken agents add` |
| `permissions.db` | Tool approval records | `wirken run` |
| `permissions.json` | Default grant window (`default_expiry_days`, 30 when absent) | Manual |
| `adapters.db` | Registered channel adapters and Ed25519 keys | `wirken channel add` |
| `hooks.db` | Registered observe, veto and egress hooks | `wirken hooks register` |
| `cron.db` | Scheduled cron jobs | `wirken cron create` |
| `memory.db` | Labelled cross-channel memory entries | `wirken run` |
| `imported.db` | Imported assistant archives | `wirken import` |
| `sandbox.json` | Sandbox settings. Keys read: `mode`, `image`, `network`, `shell`, `sidecar_binary`; any other key is named in a startup warning and ignored | `wirken setup` or manual |
| `siem.json` | SIEM forwarding config | Manual or org config |
| `budget.json` | Per-agent spend budgets | Manual |
| `budget.db` | Durable per-agent spend ledger | `wirken run` |
| `mcp.json` | MCP server config | Manual or org config |
| `tool_policy.json` | Org allow and deny tool lists | `wirken setup --org` |
| `org.url` | Organization config endpoint | `wirken setup --org` |
| `registry-root.pub` | Operator skill-registry root (mode 0o644) | `wirken skills trust-root` |
| `signing-key.hex` | Per-author skill and MCP signing seed | `wirken skills sign` |
| `keychain/` | age-encrypted device key when the OS keychain is unavailable | `wirken setup` |
| `skills/` | Installed skills | `wirken skills install` or setup |
| `agents/<id>/` | Per-agent `identity.{key,pub}`, `workspace/`, `skills/`, `mcp.json` | `wirken agents add` |
| `sockets/` | Unix domain sockets for IPC. On Windows the gateway uses named pipes derived from these path stems and the directory holds no live files | `wirken run` |
| `workspace/` | Default agent workspace | `wirken run` |

The data directory is created at mode 0o700, and re-chmod'd on every start so
a loose 0o755 left by an earlier run or a permissive umask converges back.

## provider.json

```json
{
    "provider": "openai",
    "model": "gpt-4o",
    "base_url": "https://api.openai.com/v1"
}
```

Values `wirken setup` writes: `openai`, `anthropic`, `gemini`, `bedrock`,
`ollama`, `tinfoil`, `infomaniak`, `hetzner`, `custom`. `custom` covers any
OpenAI-compatible endpoint, including NIM and the Privatemode proxy.

Bedrock adds a `region` field:

```json
{
    "provider": "bedrock",
    "model": "anthropic.claude-sonnet-4-20250514-v2:0",
    "base_url": "https://bedrock-runtime.us-east-1.amazonaws.com",
    "region": "us-east-1"
}
```

The API key is resolved from the vault entry `<provider>-api-key`. The model
an agent runs is operator configuration, not a chat setting: there is no
user-facing model selector and no chat command switches it. A per-agent
override in `agent_config.db` takes precedence over this file, so pinning a
model version means editing one of the two and restarting.

## Confidential inference

Two providers run the model inside a hardware TEE. Both are configured through
`wirken setup`; neither changes the rest of the pipeline.

### Tinfoil

`wirken setup` picks **Tinfoil**, stores the key under `tinfoil-api-key`, and
writes `provider: "tinfoil"`. Dispatch goes through the `tinfoil-rs` SDK,
pinned in `crates/agent/Cargo.toml`, which constructs its client on the first
chat call and performs three checks:

1. **Hardware attestation.** AMD SEV-SNP report fetched from the enclave,
   ECDSA P-384 signature verified, VCEK to ASK to ARK chain validated, enclave
   measurement extracted from the verified report.
2. **Code provenance.** Latest release attestation pulled from the published
   enclave repo, DSSE signature verified against the certificate's P-256 key,
   certificate validated as issued by GitHub Actions for that repo, source
   measurement extracted from the signed in-toto statement.
3. **Measurement comparison.** Enclave measurement against source measurement.
   A mismatch is a hard verification failure.

The SDK then extracts the enclave's TLS public key from the attestation
document, computes the SPKI fingerprint, and pins a client to that exact
certificate. All chat traffic flows through it, so a MITM with a compromised
CA cannot intercept; if the certificate rotates, the next request surfaces a
connect-level error and wirken re-attests. The verified client is cached for
the process lifetime and dropped on the attestation-or-TLS failure path, which
re-attests on the next call.

Chat traffic uses the same OpenAI-compatible build and parse path as other
providers, with the pinned client substituted. Tool calling works. Streaming
and the SDK's `chat_relaxed` escape hatch for vendor extensions are not wired.
The SDK is AGPL-3.0; wirken stays MIT.

### Privatemode

Privatemode runs as a local proxy. Start it on loopback, because the upstream
image binds `0.0.0.0` by default and constraining that is the deployer's job:

```bash
docker run -d --name privatemode-proxy \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/edgelesssys/privatemode/privatemode-proxy:latest \
  --apiKey <YOUR_ACCESS_KEY>

curl -s http://127.0.0.1:8080/v1/models | head    # JSON, not an error
```

`wirken setup` picks **Privatemode**, accepts the default proxy URL, and
writes a `provider.json` pointing at it. The access key lives encrypted in the
vault. Wirken opens an OpenAI-shape client at
`POST http://localhost:8080/v1/chat/completions`; it speaks the documented
HTTP API directly, since Privatemode ships JS and Wasm SDKs but no Rust one.
Proxy attestation happens before wirken sends any request, and the proxy
writes manifest transitions to `log.txt` in its workspace.

Pin the proxy image to a release at or above v1.33; backends dropped support
for older clients. Anthropic-shape responses do not return
`cache_creation_input_tokens` separately, folding them into `input_tokens`, so
audit consumers must not assume the field is present.

**Gaps.** Wirken does not verify Privatemode attestation independently; it
trusts the proxy handshake. No CI integration test exercises the Privatemode
path end to end; the adapter and LLM client paths have unit coverage and the
round trip against a real proxy is verified by hand. The access-key credential
is per-agent, not per-caller, so a multi-user deployment cannot bill inference
to distinct humans.

### Verifying either round-trip

```bash
wirken sessions list              # find the session id
wirken sessions verify <id>       # exits 0 on an intact hash chain
```

Each turn writes one `LlmRequest` carrying the provider and model, which is
wirken's record that the turn went where you configured it.

To route one channel to a confidential provider and leave others elsewhere,
create a named agent and bind that channel to it; see
[multi-agent.md](multi-agent.md).

## siem.json

```json
{
    "target": "datadog",
    "endpoint": "https://http-intake.logs.datadoghq.com/api/v2/logs",
    "api_key": "your-dd-api-key",
    "service": "wirken",
    "environment": "production"
}
```

`target` is `datadog`, `splunk`, `sentinel` or `webhook`. HTTPS is required
for non-localhost endpoints. Per-target envelope shapes, the typed pipe's
opt-in keys, HMAC, and the Sentinel two-stream split:
[siem-forwarder.md](siem-forwarder.md).

## budget.json

```json
{
    "default": { "mode": "alert", "ceiling_usd_micros": 5000000, "window": "day" },
    "agents": {
        "work": { "mode": "block", "ceiling_usd_micros": 10000000, "window": "day" }
    }
}
```

`mode` is `off` (the default), `alert` or `block`; `window` is `hour`, `day`
or `week`; `ceiling_usd_micros` is USD micros (1 USD = 1,000,000). Resolution
for an agent is its per-agent entry, else the global `default`, else off. A
per-agent entry fully replaces the default rather than merging, and an
explicit per-agent `"mode": "off"` opts that agent out even under a global
default. Enforcement behaviour, fail-closed handling and the uncosted-provider
gap: [cost-monitoring.md](cost-monitoring.md#enforcement).

## mcp.json

```json
{
    "servers": {
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": { "GITHUB_TOKEN": "vault:github-token" }
        }
    }
}
```

The `vault:` prefix resolves values from the encrypted vault at runtime. See
[mcp.md](mcp.md).

## Environment variables

| Variable | Purpose |
|----------|---------|
| `WIRKEN_DATA_DIR` | Override the data directory (default: `~/.wirken`) |
| `WIRKEN_VAULT_PASSPHRASE` | Passphrase for the age-file keychain; every credentials verb reads it when set and prompts only when it is not |
| `WIRKEN_SKILLS_INDEX` | Override the skill registry URL |
| `WIRKEN_CACHE_MODE` | `drop` bypasses the agent LRU cache so every inbound message wakes a fresh agent from the session log. Default: `cached` |
| `WIRKEN_AGENT_CACHE_SIZE` | LRU cache capacity in hot sessions. Default: `64` |
| `WIRKEN_ASK_APPROVAL_TIMEOUT_S` | Deadline on the `wirken ask` approval prompt. Default: `60` |
| `WIRKEN_VETO_BUDGET_MS` / `WIRKEN_EGRESS_BUDGET_MS` | Cumulative hook-dispatch budget. Default `1000` each, per-hook ceiling 500ms |
| `WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES` | Flush cycles between continuous verification passes. Default: `100` |
| `RUST_LOG` | Log verbosity, e.g. `RUST_LOG=wirken=debug` |

Per-adapter port and token overrides (`WIRKEN_TEAMS_PORT`,
`WIRKEN_WHATSAPP_PORT`, `WIRKEN_GOOGLE_CHAT_PORT`, `WIRKEN_IMESSAGE_PORT`,
`WIRKEN_SLACK_TOKEN` and siblings) are described with each channel in
[channels.md](channels.md). The escape-hatch variables are inventoried in
[security-properties.md](security-properties.md#documented-escape-hatches).
