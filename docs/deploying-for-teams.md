# Deploying Wirken for a Team

This guide covers running one Wirken instance that a small team shares across chat channels, with a self-hosted inference endpoint. For single-operator deployment, start with [getting-started.md](getting-started.md). For the org-config-pull model, see [enterprise.md](enterprise.md).

Every claim here maps to current behavior. Items that read like team-scale features but are not yet implemented are listed under **What Wirken does not do today** at the end. Read that section before committing to an architecture.

## Reference topology

```
  Team members ──▶ Slack workspace / Matrix homeserver
                         │
                         │  (platform API, bearer tokens)
                         ▼
                   ┌───────────┐
                   │  Wirken   │     separate adapter process per channel
                   │           │     Unix domain socket + ed25519 IPC
                   │  host     │     XChaCha20-Poly1305 credential vault
                   └─────┬─────┘
                         │  HTTPS (rustls) or WireGuard-tunneled HTTP
                         ▼
                   ┌───────────┐
                   │ Inference │     Hetzner GPU box, self-hosted vLLM,
                   │   host    │     or Ollama with an OpenAI-compatible
                   └───────────┘     endpoint at /v1
                         │
                         ▼
                 Datadog / Splunk / Sentinel / webhook (SIEM forwarding, optional)
```

Wirken runs on its own VPS or bare-metal host. The inference host runs Ollama, vLLM, or any OpenAI-compatible server. The two hosts talk over HTTPS or, for plain-HTTP inference endpoints, a WireGuard or Tailscale tunnel so the bearer is not on the public internet. Adapters connect from the Wirken host outward to Slack, Teams, Matrix, or whichever platforms the team uses. Each adapter is a separate OS process. The gateway routes inbound platform messages to the configured agent, which calls the inference endpoint and writes structured events to the per-session audit log.

One channel in Wirken maps to one platform workspace. A Slack deployment covering two workspaces needs two registered channels, each with its own adapter process and its own vault entries.

## Credential setup

Credentials live in `~/.wirken/vault.db`, encrypted with XChaCha20-Poly1305. The device key is retrieved from the OS keychain (macOS Keychain, Linux Secret Service) or from an age-encrypted key file with a passphrase-derived wrapping key (Argon2id).

Each channel stores its platform credentials under a well-known set of vault names:

| Channel | Vault entries |
|---------|---------------|
| `slack` | `slack-token` (bot `xoxb-`), `slack-app-token` (`xapp-`), `slack-adapter-key` (ed25519 IPC identity) |
| `teams` | `teams-token` (app password), `teams-app-id`, `teams-adapter-key` |
| `matrix` | `matrix-token` (password), `matrix-homeserver`, `matrix-username`, `matrix-adapter-key` |

`wirken channel add <channel>` prompts for each entry, encrypts it, and writes it. The adapter process loads these entries at startup via the vault, which decrypts them in memory as `VaultSecret` values. `VaultSecret` does not implement `Display`, `Debug`, `Clone`, or `Serialize`, and memory is zeroed on drop.

The vault records per-credential `expires_at` and `rotation_due_at` metadata. `CredentialStore::rotate` replaces the encrypted value, resets `last_used_at`, and clears the due-for-rotation flag. Rotation is manual today: nothing in the gateway triggers rotation on a schedule. See **What Wirken does not do today** for detail.

To rotate a Slack bot token, obtain a new `xoxb-` from the Slack app console, then either re-run `wirken channel add slack` (which performs `INSERT OR REPLACE`) or call `CredentialStore::rotate` via the library API. Restart the adapter process so the new token is loaded.

## Audit log for incident reconstruction

Every inbound message, tool call, tool result, LLM request, LLM response, permission denial, and rewind is written to `~/.wirken/audit.db` as a structured `SessionEvent`. Each session has its own SHA-256 hash chain. The chain is per-session, not global.

`wirken audit log` prints a text table of recent events:

```
  ID     TIMESTAMP             ACTOR             ACTION                TARGET
  ─────  ──────────────────── ──────────────── ──────────────────── ────────────
  1023   2026-04-18 11:42:08  U04ABCD9          message.inbound       deploy the staging env
  1024   2026-04-18 11:42:09  agent:work        llm.request           anthropic/claude-sonnet-4
  1025   2026-04-18 11:42:11  agent:work        tool.exec             kubectl rollout status
```

Filter by action or channel:

```
wirken audit log --action tool.exec --channel slack -n 200
```

`wirken audit verify` walks every per-session chain and reports the first break. A tampered row breaks the session's chain (leaf hash mismatch, prev hash mismatch, or both). Verify reports the session ID and sequence number of the first mismatch.

For per-session replay against LLM request hashes and tool determinism, use `wirken sessions verify <session_id>`.

For structured egress to a SIEM, write `~/.wirken/siem.json`:

```json
{
    "target": "datadog",
    "endpoint": "https://http-intake.logs.datadoghq.com/api/v2/logs",
    "api_key": "your-dd-api-key",
    "service": "wirken",
    "environment": "production"
}
```

Supported targets: `datadog`, `splunk` (HEC), `sentinel` (Microsoft Sentinel via Logs Ingestion API; bearer token required), `webhook`. HTTPS is required for non-localhost endpoints. Every audit event is forwarded as structured JSON: actor, action, target, channel, session, timestamp, detail payload, hostname. See [configuration.md](configuration.md) for each target's exact schema.

A compliance officer reconstructing an incident from the local audit.db proceeds as follows:

1. `wirken audit verify` to confirm no chain break. If broken, the reason and session seq are reported.
2. `wirken audit log --channel slack -n 500` (or filter by action) to find the inbound message that started the incident.
3. Read the `actor` column for the platform sender id (Slack `user_id`, Teams Bot Framework id, Matrix MXID) and the `session` column for the conversation ID.
4. `wirken sessions verify <agent_id>/<channel>/<conversation_id>` to replay the full typed session transcript with chain integrity and LLM input hashes.

For cross-incident investigation across many sessions, the SIEM side carries the same actor/action/target/channel/session fields in structured form, which is the only batched query path today. See **What Wirken does not do today** on CLI audit export.

## Concrete example: team of 12, self-hosted Qwen 2.5 72B

Layout:

- **Inference host**: Hetzner GPU dedicated (for example, a machine with 1 or more RTX 4090/6000). Runs Ollama with Qwen 2.5 72B, exposing `http://inference:11434/v1`.
- **Wirken host**: separate VPS. Runs `wirken run` as a systemd service under a dedicated unix user.
- **Network**: WireGuard between Wirken host and inference host. The `base_url` points at the inference host's WireGuard address, not the public IP.
- **Channels**: one Slack workspace, one Matrix homeserver. Two adapter processes.

### Provider config

`~/.wirken/provider.json` on the Wirken host:

```json
{
    "provider": "ollama",
    "model": "qwen2.5:72b",
    "base_url": "http://10.8.0.2:11434/v1"
}
```

`10.8.0.2` is the WireGuard IP of the inference host. Ollama's OpenAI-compatible endpoint lives at `/v1`. `provider: "ollama"` sets `tools_enabled: false` by default because local tool-calling support varies. If the chosen Qwen build supports tool calls, override per-agent:

```bash
wirken agents set default --tools-enabled true
```

The provider field is honored even when the base URL is a remote host, because Wirken dispatches on the provider string, not the URL.

### Channel setup

On the Wirken host:

```bash
wirken channel add slack
# Bot token (xoxb-...):     paste
# App token (xapp-...):     paste
# ed25519 adapter key: generated and stored

wirken channel add matrix
# Homeserver URL:           https://matrix.example.com
# Username:                 wirken
# Password:                 paste
# ed25519 adapter key: generated and stored
```

Each `wirken channel add` call writes vault entries, generates an ed25519 keypair for the adapter's IPC handshake, and registers the channel in `adapters.db`.

### Routing

With one `default` agent handling both channels, no routing change is needed. Every bound channel routes to `default`.

For separate agents per channel (for example, a stricter tool set on Matrix), create named agents and bind:

```bash
wirken agents add           # create 'work' with its own model/key
wirken agents bind work slack
wirken agents bind work matrix
```

Each channel can be bound to exactly one agent. Agents can reuse one provider config or override their own provider, model, API key, and tool settings in `agent_config.db`.

### Run

```bash
wirken run
```

Startup prints:

```
  Provider: ollama/qwen2.5:72b
  Route: slack -> agent:work
  Route: matrix -> agent:work
  Socket: ~/.wirken/sockets/gateway.sock
```

Two adapter processes spawn, one per channel. Each connects back over the Unix domain socket, performs the ed25519 handshake, and begins polling its platform.

### SIEM

`~/.wirken/siem.json` as in the Audit section. Forwarding is best-effort: failures are logged, not blocking. The local audit chain remains the source of truth.

## What Wirken does not do today

These are hard boundaries. If a team requirement lands on one of them, either defer the requirement or plan to build it on top.

- **Wirken is not an IdP.** It does not issue identities, it does not manage user accounts, it does not have a login flow. Platform sender identity (Slack `user_id`, Teams activity sender, Matrix MXID) is recorded on every inbound audit event but is not an identity Wirken authenticates.
- **Wirken does not replace SSO.** There is no SAML, no OIDC, no SCIM provisioning.
- **Wirken does not do content DLP.** The prompt-injection detector flags inbound text for role-switching attempts, instruction overrides, base64-encoded commands, tool-call injection, and system prompt extraction, and writes the flag to the audit log. That is not data loss prevention. Message content, attachments, and outbound responses are not scanned for secrets, PII, or policy violations.
- **Permissions are scoped per agent, not per user.** A Tier 2 approval granted when any user first triggers an action on a channel applies to every user on that channel for the 30-day approval window. If per-user authorization matters for a team deployment, either run one agent per user (not the intended model) or wait for per-user scoping to land.
- **Permissions are not scoped per channel within an agent.** The approval key is `(action_key, agent_id)`. If one agent is bound to both `slack` and `matrix`, a Tier 2 approval on Slack applies when the same agent processes Matrix messages.
- **The vault `channel` column is metadata, not access control.** Any process that holds the device key and a handle to `vault.db` can retrieve any credential by name. Per-channel isolation comes from running each adapter as a separate OS process, not from vault-level ACLs.
- **One platform workspace per adapter process.** One Slack workspace per `slack` adapter, one Teams tenant per `teams` adapter, one Matrix homeserver per `matrix` adapter. A second workspace requires a second registered channel with a distinct name.
- **No OAuth refresh or scope rotation in the adapters.** Tokens are loaded at startup as opaque bearers. If a token is revoked out-of-band, the adapter will fail on next call. Teams clears its cached access token on HTTP 401 and re-acquires from the app_id and app_password, but if the app_password itself has been rotated the adapter will loop on 401 until restarted with the new value. Slack and Matrix have no explicit revocation-detection branch.
- **No automatic credential rotation.** `rotation_due_at` metadata is tracked. Nothing fires on it. Rotation is operator-initiated.
- **No CLI audit export.** `wirken audit log` prints a text table; no `--format=json` or `--format=jsonl` flag exists. For batched, structured egress, configure SIEM forwarding. If offline regulator-facing export is required, either query `audit.db` directly via SQLite or wait for a dedicated export command.
- **The audit chain is per-session, not global.** Do not describe it as "one chain for the whole deployment." Each session has its own chain; `wirken audit verify` reports aggregate integrity by walking every session chain.
- **No role-based access control.** No admin users, no groups, no named roles.
- **No platform-to-principal identity mapping.** `U04ABCD9` in Slack and `@user:matrix.example.com` are stored as actor strings. Wirken has no notion that they are the same human.
- **No certification under any framework.** Wirken ships mechanisms (per-channel process isolation, encrypted vault, per-session hash-chained audit, SIEM forwarding). Whether any deployment meets an organization's compliance obligations is a determination for that organization and its auditors.
