# Security Policy

## Supported Versions

Only the latest release is supported. Security fixes ship forward in the
next release; there are no backports to earlier versions. Upgrade to the
latest release to receive them.

| Version | Supported |
| ------- | --------- |
| 1.9.x   | Yes       |
| < 1.9   | No        |

## Reporting a Vulnerability

Report security vulnerabilities via one of:

- GitHub private vulnerability reporting: [github.com/gebruder/wirken/security/advisories](https://github.com/gebruder/wirken/security/advisories)
- Email: security@gebruder.ottenheimer.app

Do not open a public issue for security vulnerabilities.

You should receive an initial response within 72 hours. If the vulnerability is accepted, a fix will be released in the next version (e.g., 1.9.1) and the advisory will be published after the fix is available.

## Release signing

Release artifacts are signed offline with an Ed25519 SSH key. The public key is pinned in [KEYS](KEYS) at the repository root and embedded in `install.sh` so installer verification needs no network fetch of the key. The full procedure, including key rotation, is in [docs/release-signing.md](docs/release-signing.md).

Current active key:

- Identity: `releases@gebruder.ottenheimer.app`
- Algorithm: `ssh-ed25519`
- Fingerprint: `SHA256:tzlfNHy4G1KIsmAR+cM3MGwVndheh2ak/usA6rw7SuE`
- Issued: 2026-04-18
- Signed file: `checksums.sha256` for every published release (verify with `ssh-keygen -Y verify`)

In addition to the offline signature, releases tagged after build provenance landed publish `wirken.intoto.jsonl`, a SLSA Build L3 provenance attestation signed through the GitHub OIDC-rooted Sigstore chain. It is a second, independent trust root (build origin, recorded in a public transparency log) beside the offline maintainer key, and both are standalone release assets. Verify it with `slsa-verifier`; see [docs/release-signing.md](docs/release-signing.md#build-provenance-slsa).

## Cryptography

Wirken's own signatures are Ed25519, verified with `verify_strict`
(non-canonical scalars and small-order R points rejected): the IPC and
hook handshakes, session attestation, the audit chain head, skill
bundles, the org-config trust anchor, and MCP entries. Symmetric
encryption for the credential vault is XChaCha20-Poly1305 with Argon2id
key derivation.

Inbound webhook authentication for Google Chat and Microsoft Teams
verifies the platform-issued JWT with RSA-PKCS1 (RS256) via `ring`,
because those providers sign with RSA. This is third-party token
verification, not a Wirken-issued signature.

Post-quantum signature and key-encapsulation algorithms are not
supported. There is no ML-KEM / ML-DSA path and no algorithm-agility
layer; the signature algorithm is Ed25519 across every Wirken-issued
signature surface.

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
