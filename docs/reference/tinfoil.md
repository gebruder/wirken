# Tinfoil reference instance

Reference documentation for running Wirken against the
[Tinfoil](https://tinfoil.sh) confidential-inference service.
Everything described here is verified on the current `wirken`
binary. Claims about Tinfoil itself (model capabilities, enclave
shapes, billing, release history) are sourced from upstream:

- Tinfoil docs: <https://docs.tinfoil.sh>
- Rust SDK: <https://github.com/tinfoilsh/tinfoil-rs>
- Inference dashboard and API key issuance: <https://dash.tinfoil.sh>

For other providers wirken supports see [`docs/reference/privatemode.md`](privatemode.md).

## Quickstart

One sequential procedure to get a working Wirken + Tinfoil instance.
Assumes a built `wirken` binary and outbound network access.

1. **Get a Tinfoil API key.** Sign up at <https://dash.tinfoil.sh> and generate an API key.
2. **Configure Wirken.** `wirken setup` and choose:
   - Step 1 (provider): pick **Tinfoil (confidential)**. Paste your API key. The wizard hits
     `https://inference.tinfoil.sh/v1/models` over plain HTTPS to enumerate available models
     (this listing call is pre-attestation; the wizard does not gate model selection on the
     enclave verification). Pick a model from the list, or accept the default.
   - Step 2 (channel): pick at least one. WebChat is the simplest first run.
3. **Start wirken.** `wirken run`. The first inbound message pays the attestation cost
   (a few seconds while the SDK runs router discovery, AMD SEV-SNP hardware attestation,
   Sigstore code-provenance verification, and TLS-key pinning). Subsequent messages reuse
   the pinned transport.
4. **Send a test message.** Through the channel you configured. The response should come
   back through the same channel.
5. **Verify the round trip landed in the audit log.**
   ```
   wirken sessions list              # find the session id
   wirken sessions verify <id>       # exits 0 on an intact hash chain
   ```
   The session log records one `LlmRequest` event per turn carrying `provider: "tinfoil"`
   and your chosen model name.

If any step fails, see [Troubleshooting](#troubleshooting).

## What works

`wirken setup` picks **Tinfoil**, stores the API key in the XChaCha20-Poly1305 vault under
`tinfoil-api-key`, and writes a `provider.json` with `provider: "tinfoil"`. `wirken run`
opens an `LlmClient` whose tinfoil dispatch arm constructs a
[`tinfoil::Client`](https://github.com/tinfoilsh/tinfoil-rs/blob/main/src/client.rs) on
first chat call. The constructor performs three checks:

1. **Hardware attestation.** AMD SEV-SNP report fetched from the enclave, ECDSA P-384
   signature verified, VCEK to ASK to ARK certificate chain validated, enclave
   measurement extracted from the verified report.
2. **Code provenance.** Latest release attestation pulled from the published enclave
   repo (`tinfoilsh/confidential-model-router` by default), DSSE signature verified
   against the certificate's P-256 key, certificate validated as issued by GitHub
   Actions for the named repo, source measurement extracted from the signed in-toto
   statement.
3. **Measurement comparison.** Enclave measurement (from hardware) compared against
   source measurement (from Sigstore). Mismatch is a hard verification failure.

The SDK then extracts the enclave's TLS public key from the attestation document,
computes the SPKI fingerprint, and configures a `reqwest::Client` that pins to that
exact certificate. All chat traffic flows through this pinned client. A MITM with a
compromised CA cannot intercept; if the cert rotates, the next request surfaces a
connect-level error and wirken re-attests against the new attestation document.

The verified client is cached for the gateway's process lifetime
(`LlmClient.tinfoil` mutex in `crates/agent/src/llm.rs`). On the
attestation-or-TLS-failure path wirken drops the cached client and re-attests on the
next call.

Chat traffic is built and parsed with the same OpenAI-compatible code path the other
providers use (`build_openai_request_body` and `parse_completion_response`), with the
pinned `reqwest::Client` from the SDK substituted for wirken's default HTTP client.
Tool calling is supported. Streaming and the SDK's `chat_relaxed` escape hatch for
vendor extensions are not yet wired.

## Models

Available models depend on the enclave version. The setup wizard's model picker calls
`https://inference.tinfoil.sh/v1/models` and presents whatever the enclave returns;
that list is the canonical source. Tinfoil's docs at
<https://docs.tinfoil.sh/inference/models> document the catalog.

For Lyrik phase pinning, the `provider_default_base_url` mapping in
`crates/cli/src/commands/lyrik.rs` returns the inference URL for `tinfoil`, but on the
tinfoil dispatch path the URL is unused (the SDK's discovery picks the host at
construction time). The `base_url` field on `LlmConfig` survives for backward
compatibility with code that reads it.

## Trust model

What the verification proves:

- The enclave responding to wirken's traffic is running AMD SEV-SNP with a measurement
  that matches the published source release.
- The TLS connection wirken's pinned client makes terminates inside that enclave (the
  TLS public key was bound to the enclave's identity in the attestation document).
- The published source release was signed by GitHub Actions for the named enclave
  repo.

What it does not prove:

- That the published source has no bugs or backdoors. Code review of the enclave repo
  is a separate exercise.
- That Tinfoil cannot rotate the enclave to a different image with a fresh
  attestation. The freshness of the verification is bounded by the cached client's
  lifetime; long-running gateways re-attest only on TLS-pinning failure. If you
  require periodic re-verification on a schedule, that work is out of slice 1.
- That the API key is not exfiltrated by a side channel inside the enclave. Tinfoil's
  threat model is a software-attack adversary on the host, not a supply-chain
  adversary inside the enclave.

The license on `tinfoil-rs` is AGPL-3.0; wirken stays MIT and the AGPL-3.0 surface is
carved out for the `tinfoil` crate in `deny.toml`. Wirken's source is public on
GitHub, satisfying AGPL §5; §13 (network-use source disclosure) keys on operator
modification of the program, not on Wirken's authors.

## Troubleshooting

**`tinfoil attestation failed: ...`** at first chat.
The SDK's verification surfaced an `is_attestation()` error: signature mismatch,
certificate chain failure, measurement mismatch, or unsupported attestation format.
This is **security-relevant** — the SDK refuses to retry blindly and wirken propagates
that. Check Tinfoil's status page for an enclave incident; if the failure persists,
check that your wirken binary is recent enough to consume the enclave's current
attestation format (`tinfoil-rs` is pinned in
`crates/agent/Cargo.toml`).

**`tinfoil pinned client unavailable`.**
Internal: the SDK's `Client` was constructed but its pinned HTTP client could not be
extracted. File a wirken issue with the audit log entry; this is not expected.

**Network errors during the first call.**
The SDK reaches three external services during verification: Tinfoil's router
discovery (`atc.tinfoil.sh`), Sigstore (GitHub via the Tinfoil GitHub proxy), and the
AMD KDS proxy (`kds-proxy.tinfoil.sh`) for VCEK certificates. All must be reachable
from the wirken host. A firewalled environment will need outbound HTTPS to all three.

**Wizard model picker returns an empty list.**
The `https://inference.tinfoil.sh/v1/models` endpoint did not return a parseable
catalog. Check the API key (the listing call sends it as a Bearer token). If the
catalog is genuinely empty, the wizard falls back to the typed-default `llama3-3-70b`
which you may need to override to a model the current enclave actually serves.

**429s on a busy gateway.**
The SDK's pinned `reqwest::Client` does not pass through wirken's `send_with_retry`
backoff; tinfoil dispatch surfaces 429s directly. If contention with other inbound
traffic is real, the lyrik per-phase retry layer or harness send-loop will handle it
the same way it does for other providers.
