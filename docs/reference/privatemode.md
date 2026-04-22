# Privatemode reference instance

Wirken advertises Privatemode as a supported confidential inference backend. This document describes the reference instance: what runs, how it is deployed, how it is tested, and how to verify a round-trip.

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

Privatemode supports both Anthropic `/v1/messages` and OpenAI `/v1/chat/completions`. Wirken defaults to Anthropic shape:

- `POST http://localhost:8080/v1/messages` (default)
- `POST http://localhost:8080/v1/chat/completions` (alternate)

Select with `api_shape = "anthropic"` or `"openai"` in the provider config.

## Models

- `gpt-oss-120b`: primary default. Stable, 128k context, tool calling.
- Kimi K2.5: preview. 262k context, multimodal. Use when stability is acceptable.

## Credentials

The Privatemode access key is stored in Wirken's XChaCha20-Poly1305 vault as a single inference credential. It is not channel-scoped. All channels share one inference backend.

## Deployment

`privatemode-proxy` runs as a sidecar next to Wirken. Recipes live in `deploy/privatemode/`:

- `systemd/privatemode-proxy.service` for systemd hosts
- `compose/docker-compose.yml` for container hosts

Both bind the proxy to `127.0.0.1:8080`. Wirken talks to loopback only.

## Verifying a round-trip

1. Start the proxy via the chosen recipe.
2. `wirken run` with `provider = "privatemode"`.
3. Send a message through a configured channel.
4. Confirm receipt of the agent response in the channel.
5. `wirken audit log` shows the inference request and response appended.
6. `wirken sessions verify` succeeds against the hash-chained log.

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
