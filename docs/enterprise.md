# Enterprise Setup

Deploy wirken to a team with centralized policy and monitoring.

## How it works

Each developer runs their own wirken instance on their machine. IT controls what it can do via a central config endpoint. The developer owns their instance. The company owns the policy.

## Setup with org config

IT hosts a JSON config at a company URL. Developers onboard with one command:

```bash
wirken setup --org https://wirken.corp.example.com/config
```

This fetches the config, applies provider settings, SIEM forwarding, MCP servers, and permission policy. The developer picks their channels and enters their own bot tokens.

On every `wirken run`, the org config refreshes automatically.

## Org config format

```json
{
    "provider": {
        "provider": "openai",
        "model": "gpt-4o",
        "base_url": "https://api.openai.com/v1"
    },
    "api_key_name": "openai-api-key",
    "siem": {
        "target": "datadog",
        "endpoint": "https://http-intake.logs.datadoghq.com/api/v2/logs",
        "api_key": "dd-org-api-key",
        "service": "wirken",
        "environment": "production"
    },
    "mcp": {
        "servers": {
            "datadog": {
                "command": "npx",
                "args": ["-y", "@datadog/mcp-server"],
                "env": {}
            }
        }
    },
    "permissions": {
        "sandbox_mode": "exec-only"
    },
    "skills": {
        "auto_install": ["github", "git", "web-fetch"],
        "blocked": []
    }
}
```

All fields are optional. Only provided fields are applied. The `provider`, `api_key_name`, `siem`, `mcp`, `skills`, and `permissions` fields are wired through. `permissions.sandbox_mode` drives `sandbox.json`; `permissions.allowed_tools` and `permissions.blocked_tools` drive `tool_policy.json`, which `wirken run` loads and enforces in the agent's tool dispatcher ahead of the tier permission check. See [Permissions and identity](permissions-and-identity.md) for enforcement details.

## SIEM integration

Every agent action is forwarded to Datadog, Splunk HEC, Microsoft Sentinel (Logs Ingestion API), or any webhook in real time. See [configuration.md](configuration.md) for siem.json format.

Events include: actor, action, target, channel, session, timestamp, and a detail payload. The local audit log is per-session hash-chained for tamper detection. SIEM forwarding runs alongside, not instead of, the local log.

## Credential distribution

Each developer enters their own API key during setup. The key is encrypted immediately into the local vault. There is no plaintext config file.

For organizations using a shared API key, the `api_key_name` field in the org config prompts the developer to enter it during setup. The name maps to a vault credential entry.

## Sandbox enforcement

The Docker sandbox code path supports three modes, selected by `SandboxMode` in the agent runtime:

- `ExecOnly` (the default as of 0.7.5): Docker containers with default `runc` runtime. Ephemeral, no network, 512MB memory, 256 PID limit, non-root user.
- `GVisor`: Docker containers with `runsc` runtime. Same resource constraints as `ExecOnly`, with kernel attack surface reduction: syscalls are intercepted by gVisor's Sentry rather than reaching the host kernel. Requires gVisor installed on the host.
- `Off`: Direct host execution at the wirken UID. The explicit opt-out, not the default; the gateway warns at startup when it engages.

The runtime's `SandboxConfig::default()` is `ExecOnly` as of 0.7.5. `wirken run` loads `sandbox.json` from the data directory at startup via `load_sandbox_config`, and `apply_org_config` writes that file from the org config's `permissions.sandbox_mode`, so an org policy selecting `off`, `exec-only`, or `gvisor` takes effect on the next gateway start.

## Deployment options

- **MDM push.** Use Jamf, Intune, or Ansible to install the binary and run `wirken setup --org <url>`.
- **Service install.** `wirken setup --install-service` installs a systemd (Linux) or launchd (macOS) service that starts on login.
- **Manual.** Developer runs `curl | sh` and `wirken setup --org <url>`.
