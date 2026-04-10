# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.7.x   | Yes       |
| 0.6.x   | Yes       |
| < 0.6   | No        |

## Reporting a Vulnerability

Report security vulnerabilities via GitHub's private vulnerability reporting at [github.com/gebruder/wirken/security/advisories](https://github.com/gebruder/wirken/security/advisories).

Do not open a public issue for security vulnerabilities.

You should receive an initial response within 72 hours. If the vulnerability is accepted, a fix will be released as a patch version (e.g., 0.3.1) and the advisory will be published after the fix is available.

## Scope

The following are in scope for security reports:

- Credential vault (encryption, key derivation, keychain integration)
- Session log integrity (per-session hash chain, tamper detection, attestation)
- Tool execution (path traversal, sandbox escape, command injection)
- IPC authentication (Ed25519 handshake, adapter isolation)
- Permission model bypass (including subagent capability-attenuation escape)
- MCP proxy isolation (credential leakage through the out-of-process proxy)
- SIEM log forwarding (credential leakage, injection)
- Org config endpoint (config injection, MITM)
- Skill signature verification bypass
- LLM API key leakage (logs, error messages, URLs)
- Subagent ceiling bypass (depth cap, permission tier, tool allowlist)

The following are out of scope:

- Prompt injection (application-layer LLM behavior, not a wirken vulnerability)
- Denial of service via LLM token exhaustion (rate-limited by the LLM provider)
- Vulnerabilities in third-party dependencies (report upstream, but let us know)
