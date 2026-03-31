# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.4.x   | Yes       |
| 0.3.x   | Yes       |
| < 0.3   | No        |

## Reporting a Vulnerability

Report security vulnerabilities via GitHub's private vulnerability reporting at [github.com/gebruder/wirken/security/advisories](https://github.com/gebruder/wirken/security/advisories).

Do not open a public issue for security vulnerabilities.

You should receive an initial response within 72 hours. If the vulnerability is accepted, a fix will be released as a patch version (e.g., 0.3.1) and the advisory will be published after the fix is available.

## Scope

The following are in scope for security reports:

- Credential vault (encryption, key derivation, keychain integration)
- Audit log integrity (hash chain, tamper detection)
- Tool execution (path traversal, sandbox escape, command injection)
- IPC authentication (Ed25519 handshake, adapter isolation)
- Permission model bypass
- SIEM log forwarding (credential leakage, injection)
- Org config endpoint (config injection, MITM)
- Skill signature verification bypass
- LLM API key leakage (logs, error messages, URLs)

The following are out of scope:

- Prompt injection (application-layer LLM behavior, not a wirken vulnerability)
- Denial of service via LLM token exhaustion (rate-limited by the LLM provider)
- Vulnerabilities in third-party dependencies (report upstream, but let us know)
