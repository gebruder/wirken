# Privatemode reference instance

> **Status: in development (tracked in [#57](https://github.com/gebruder/wirken/issues/57)).**
> This document specifies the target Wirken + Privatemode reference instance timed to the Privatemode 2.0 release. Sections marked _Target_ describe work that is not yet built; sections marked _Today_ describe what ships in the current Wirken binary. The "Verified claims" list describes properties of Privatemode itself (not this integration's completeness).

## What works today

Wirken already ships a Privatemode provider option. Running `wirken setup` and selecting Privatemode will:

- Prompt for the proxy URL (default `http://localhost:8080`) and access key.
- Encrypt the access key into the XChaCha20-Poly1305 vault alongside channel credentials.
- Configure the agent to call the Privatemode local proxy with OpenAI-shape requests at `POST /v1/chat/completions`, 128k context, tools enabled.

That path works end-to-end against a user-started `privatemode-proxy` container. What this reference instance adds: Anthropic-shape default, packaged sidecar recipes, an end-to-end integration test, and a round-trip verification procedure documented below.

## Architecture

![Wirken and Privatemode](../architecture/wirken-privatemode.svg)

Three trust zones, three enforcement mechanisms.

1. Channels do not trust each other. Enforcement: per-channel process isolation via Rust phantom types.
2. Tool execution is not trusted. Enforcement: gVisor sandbox.
3. Inference operator is not trusted. Enforcement: confidential computing attestation in the Privatemode local proxy.

Stacked, the only parties who see plaintext are the end user and the TEE.

## Request flow

1. Message arrives at a channel adapter. Adapter authenticates to core with Ed25519.
2. Core loads channel-scoped credentials from the vault.
3. Skills run in the gVisor sandbox if tools are invoked.
4. Core emits an inference request to `privatemode-proxy` at `localhost:8080`.
5. Proxy has already attested the Privatemode backend. It encrypts the request, ships it, receives the encrypted response.
6. Proxy returns plaintext to Wirken.
7. Wirken routes the agent output back through the originating channel adapter.
8. Every transition is appended to the hash-chained audit log.

## API shape

Privatemode supports both Anthropic `/v1/messages` and OpenAI `/v1/chat/completions`.

- _Today:_ Wirken uses OpenAI shape (`POST http://localhost:8080/v1/chat/completions`). See `crates/agent/src/llm.rs::privatemode()`.
- _Target:_ default to Anthropic shape with OpenAI shape as alternate, selectable via `api_shape = "anthropic" | "openai"` in the provider config.

## Models

- `gpt-oss-120b`: primary default. Stable, 128k context, tool calling.
- Kimi K2.5: preview. 262k context, multimodal. Use when stability is acceptable.

## Credentials

_Today._ The Privatemode access key is stored in Wirken's XChaCha20-Poly1305 vault as a single inference credential. It is not channel-scoped — all channels share one inference backend.

## Deployment

_Today._ Users start `privatemode-proxy` themselves, for example:

```
docker run -p 8080:8080 ghcr.io/edgelesssys/privatemode/privatemode-proxy:latest --apiKey <key>
```

The `wirken setup` wizard prints this command when Privatemode is selected.

_Target._ Packaged sidecar recipes in `deploy/privatemode/`:

- `systemd/privatemode-proxy.service` for systemd hosts
- `compose/docker-compose.yml` for container hosts

Both will bind the proxy to `127.0.0.1:8080`. Wirken talks to loopback only.

## Verifying a round-trip

_Target procedure:_

1. Start the proxy via the chosen recipe.
2. `wirken run` with `provider = "privatemode"`.
3. Send a message through a configured channel.
4. Confirm receipt of the agent response in the channel.
5. `wirken audit log` shows the inference request and response appended.
6. `wirken sessions verify` succeeds against the hash-chained log.

Step 5 and step 6 depend on audit/session tooling covered by the acceptance criteria in #57.

## Verified claims

- Privatemode supports Anthropic `/v1/messages` as of release v1.37.
- Privatemode 2.0 promotes web app access, separate input/output/cached token pricing, and Kimi K2.5.
- Proxy attestation happens before Wirken sends any request.
- `gpt-oss-120b` is stable with 128k context and tool calling.
- Kimi K2.5 is in preview with 262k context and multimodal input.

## Gaps

- Per-channel inference provider selection is not yet implemented.
- Wirken does not verify Privatemode attestation independently; it trusts the proxy handshake.
- Kimi K2.5 preview status may change; pin `gpt-oss-120b` as default until K2.5 exits preview.
