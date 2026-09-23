# Deploying for a team

Two shapes. **Org config**: each person runs their own instance and IT
controls what it can do from a central URL. **Shared instance**: one instance
serves a team across chat channels, with a self-hosted inference endpoint.
They compose; the second half of this page is the hard boundaries that apply
to both.

## Org config

IT hosts a JSON config at a company URL. People onboard with one command:

```bash
wirken setup --org https://wirken.corp.example.com/config
```

This fetches the config and applies provider settings, SIEM forwarding, MCP
servers and permission policy. The developer picks their channels and enters
their own bot tokens. On every `wirken run` the org config refreshes.

```json
{
    "provider": { "provider": "openai", "model": "gpt-4o", "base_url": "https://api.openai.com/v1" },
    "api_key_name": "openai-api-key",
    "siem": {
        "target": "datadog",
        "endpoint": "https://http-intake.logs.datadoghq.com/api/v2/logs",
        "api_key": "dd-org-api-key",
        "service": "wirken",
        "environment": "production"
    },
    "mcp": { "servers": { "datadog": { "command": "npx", "args": ["-y", "@datadog/mcp-server"], "env": {} } } },
    "permissions": { "sandbox_mode": "exec-only" }
}
```

All fields are optional; only provided fields are applied.

- `permissions.sandbox_mode` drives `sandbox.json`. Valid values `off`,
  `exec-only`, `gvisor`; unknown values fall back to `exec-only` with a
  warning. `wirken run` re-reads the file on every start, so an org policy
  change takes effect at the next gateway start.
- `permissions.allowed_tools` and `permissions.blocked_tools` drive
  `tool_policy.json`, persisted when at least one list is non-empty.
  `wirken run` loads it and injects it into every waked agent. The check sits
  in `execute_tool` ahead of the tier check: a name in `blocked_tools` fails
  before dispatch, a name not in a non-empty `allowed_tools` fails before
  dispatch, and `blocked_tools` wins when a name is in both. Denials land as
  `PermissionDenied` with `denial_source: "org_policy"` and a null `tier`.

Bundles are Ed25519-verified and carry a freshness window; see
[signing.md](signing.md) and the escape hatches in
[security-properties.md](security-properties.md#documented-escape-hatches).

**Credential distribution.** Each person enters their own API key during
setup, encrypted immediately into the local vault. There is no plaintext
config file. For a shared organizational key, `api_key_name` prompts for it
during setup and maps it to a vault entry.

**Rollout.** MDM push (Jamf, Intune, Ansible) running `wirken setup --org
<url>`; or `wirken setup --install-service` for a systemd or launchd unit that
starts on login; or a person running `curl | sh` and the same setup command.

## Shared instance

```
  Team members ──▶ Slack workspace / Matrix homeserver
                         │  (platform API, bearer tokens)
                         ▼
                   ┌───────────┐
                   │  Wirken   │  separate adapter process per channel
                   │   host    │  local IPC + ed25519, XChaCha20-Poly1305 vault
                   └─────┬─────┘
                         │  HTTPS (rustls) or WireGuard-tunneled HTTP
                         ▼
                   ┌───────────┐
                   │ Inference │  self-hosted vLLM, or Ollama with an
                   │   host    │  OpenAI-compatible endpoint at /v1
                   └───────────┘
                         │
                         ▼
                 Datadog / Splunk / Sentinel / webhook (optional)
```

Wirken runs on its own VPS or bare metal. The two hosts talk over HTTPS, or
over a WireGuard or Tailscale tunnel for a plain-HTTP inference endpoint so
the bearer is not on the public internet. Adapters connect outward from the
wirken host to each platform.

### Worked example: twelve people, self-hosted Qwen

`provider.json` points `base_url` at the inference host's tunnel address, not
its public IP. Tools are on by default for every provider, `ollama`
included. Local tool-calling support varies by model; if the model on the
inference host loops on invented tool calls, turn tools off for that agent:

```bash
wirken agents set default --tools-enabled false
```

The provider field is honored even when the base URL is remote, because
dispatch is on the provider string and not the URL.

Add the channels ([channels.md](channels.md) has the per-channel prompts and
vault entries), then run:

```bash
wirken run
```

```
  Provider: ollama/qwen2.5:72b
  Route: slack -> agent:work
  Route: matrix -> agent:work
```

One adapter process spawns per channel. With a single `default` agent handling
both channels no routing change is needed; for a stricter tool set on one
channel, create a named agent and bind it. See
[multi-agent.md](multi-agent.md).

### Reconstructing an incident

1. `wirken audit verify` to confirm no chain break.
2. `wirken audit log --channel slack -n 500`, or filter by action, to find the
   inbound message that started it.
3. Read the `actor` column for the platform sender id and the `session` column
   for the conversation id.
4. `wirken sessions verify <agent>/<channel>/<conversation>` to replay the
   typed transcript with chain integrity and LLM input hashes.

Flags and exit codes: [audit-cli.md](audit-cli.md). For cross-incident work
across many sessions, the SIEM side carries the same actor, action, target,
channel and session fields; see [siem-forwarder.md](siem-forwarder.md).

## Hard boundaries

If a team requirement lands on one of these, either defer the requirement or
build on top.

- **Wirken is not an IdP and does not replace SSO.** No identities issued, no
  user accounts, no login flow, no SAML, no OIDC, no SCIM. Platform sender
  identity is recorded on every inbound audit event and is not an identity
  Wirken authenticates.
- **Permissions are scoped per agent, not per user.** A Tier 2 approval
  granted when any user first triggers an action applies to every user on that
  channel for the approval window. Running one agent per user is not the
  intended model.
- **Permissions are not scoped per channel within an agent.** The key is
  `(action_key, agent_id)`. One agent bound to both `slack` and `matrix`
  carries its Slack approvals into Matrix.
- **No role-based access control.** No admin users, no groups, no named roles.
- **No platform-to-principal identity mapping.** A Slack uid and a Matrix MXID
  are stored as actor strings; wirken has no notion that they are the same
  human.
- **The vault `channel` column is metadata, not access control.** Any process
  holding the device key and a handle to `vault.db` can retrieve any
  credential by name. Per-channel isolation comes from running each adapter as
  a separate OS process.
- **One platform workspace per adapter process.** A second workspace requires
  a second registered channel with a distinct name.
- **No OAuth refresh or scope rotation in the adapters.** Tokens are loaded at
  startup as opaque bearers. Per-channel revocation behaviour is in
  [channels.md](channels.md).
- **No automatic credential rotation.** `rotation_due_at` is tracked; nothing
  fires on it. Rotation is operator-initiated.
- **No JSONL streaming audit export.** `wirken audit log --format json` emits
  a one-shot document. For batched structured egress configure SIEM
  forwarding; for offline regulator-facing export, query `audit.db` directly
  or use the JSON output.
- **The audit chain is per-session, not global.** Do not describe it as one
  chain for the whole deployment.
- **No content DLP scanner is bundled.** The prompt-injection detector flags
  inbound text and writes the flag to the audit log; inbound and outbound
  content are not pattern-scanned for secrets, PII or policy violations.
  Operators who need that wire an external process as a `HookType::Egress`
  hook. See [enforcement-model.md](enforcement-model.md#veto-and-egress-hooks).
- **No certification under any framework.** Wirken ships mechanisms. Whether a
  deployment meets an organization's compliance obligations is a determination
  for that organization and its auditors.
