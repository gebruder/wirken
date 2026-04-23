# Privatemode reference instance

Reference documentation for running Wirken against the Privatemode 2.0
confidential-inference proxy. Everything described here is verified on
the current `wirken` binary; aspirational sections that did not survive
contact with a live run were removed. Claims about Privatemode itself
(model capabilities, endpoint shapes, release history) are sourced from
Privatemode's docs at <https://docs.privatemode.ai/> and the public
source at <https://github.com/edgelesssys/privatemode-public>.

## Quickstart

One sequential procedure to get a working Wirken + Privatemode instance. Assumes you already have Docker and a built `wirken` binary. Every step runs locally.

1. **Get a Privatemode access key.** Sign up at <https://www.privatemode.ai> and generate an API key from the dashboard.
2. **Start the proxy on loopback.** The upstream image binds `0.0.0.0` by default; the `-p 127.0.0.1:…` form below constrains that to local traffic only:
   ```
   docker run -d --name privatemode-proxy \
     -p 127.0.0.1:8080:8080 \
     ghcr.io/edgelesssys/privatemode/privatemode-proxy:latest \
     --apiKey <YOUR_ACCESS_KEY>
   ```
   Confirm it's up: `curl -s http://127.0.0.1:8080/v1/models | head`. You should see JSON, not an error.
3. **Configure Wirken.** `wirken setup` and choose:
   - Step 1 (provider): pick **Privatemode**. Accept the default proxy URL (`http://localhost:8080`). Paste your access key. Accept the default model (`kimi-k2.5`).
   - Step 2 (channel): pick at least one — Telegram or Signal is easiest for a first run.
4. **Start the gateway.** `wirken run`. You should see `Provider: openai/kimi-k2.5` and your channel listed as a route.
5. **Send a test message** through the channel you configured. The response should come back in the same channel.
6. **Verify the round-trip landed in the audit log.**
   ```
   wirken sessions list              # find the session id
   wirken sessions verify <id>       # exits 0 on an intact hash chain
   ```
   The session log records one `LlmRequest` event per turn, carrying `provider: "openai"` and `model: "kimi-k2.5"` — that is Wirken's record that the turn went through Privatemode.

If any step fails, see [Troubleshooting](#troubleshooting). For a mixed-provider agent (e.g., Privatemode on Signal, Anthropic on Slack), see [Route a single channel to Privatemode](#route-a-single-channel-to-privatemode) instead of step 3.

## What works

`wirken setup` picks **Privatemode** and writes a `provider.json` pointing at the local proxy. `wirken run` opens an OpenAI-shape client at `POST http://localhost:8080/v1/chat/completions`. The access key lives encrypted in the XChaCha20-Poly1305 vault. Default model is `kimi-k2.5`; context window and tool support depend on the chosen model — see the [Models](#models) table.

End-to-end verified: message arrives on a channel adapter → agent runs → outbound request hits the local Privatemode proxy → response routes back through the channel. Every turn writes one `LlmRequest` event to the hash-chained session log, and `wirken sessions verify` walks the chain.

## Architecture

![Wirken and Privatemode](../architecture/wirken-privatemode.svg)

Three trust zones, three enforcement mechanisms.

1. Channels do not trust each other. Enforcement: per-channel process isolation via Rust phantom types.
2. Tool execution is not trusted. Enforcement: configurable sandbox — `exec-only` (default since 0.7.5), `gvisor`, or `off`. Mode is read from `~/.wirken/sandbox.json`. See `docs/security-properties.md` for the full matrix.
3. Inference operator is not trusted. Enforcement: confidential-computing attestation inside the Privatemode local proxy. The proxy fetches a signed manifest from `cdn.confidential.cloud:443`, validates the remote TEE attestation (AMD SEV-SNP, Intel TDX, NVIDIA H100 CC per the Privatemode docs), and establishes an end-to-end encrypted channel before forwarding any client request. Wirken trusts the proxy handshake — it does not independently verify the attestation.

Stacked, the only parties who see plaintext are the end user and the TEE.

## Request flow

1. Message arrives at a channel adapter. Adapter authenticates to core with Ed25519.
2. Core loads channel-scoped credentials from the vault.
3. Skills run in the configured sandbox (`exec-only` by default) if tools are invoked.
4. Core emits an inference request to `privatemode-proxy` at `localhost:8080`.
5. Proxy has already attested the Privatemode backend. It encrypts the request, ships it to `api.privatemode.ai:443`, receives the encrypted response.
6. Proxy returns plaintext to Wirken.
7. Wirken routes the agent output back through the originating channel adapter.
8. Every transition is appended to the hash-chained audit log.

## API shape

Privatemode exposes both Anthropic-compatible and OpenAI-compatible surfaces on the same proxy. Privatemode does not designate either as primary — the choice is Wirken's.

| Shape | Proxy path | Supports |
|-------|------------|----------|
| OpenAI | `POST /v1/chat/completions` | Chat, tools, streaming |
| Anthropic | `POST /v1/messages` | Chat, streaming (SSE), `system` prompt, `max_tokens` required |
| OpenAI | `POST /v1/embeddings` | `qwen3-embedding-4b` only |
| OpenAI | `POST /v1/audio/transcriptions` | `whisper-large-v3`, `voxtral-mini-3b` |

All requests use `Content-Type: application/json`. The `--apiKey` flag on the proxy authenticates the proxy-to-backend leg.

Wirken uses the OpenAI shape (`POST /v1/chat/completions`). Implementation in `crates/agent/src/llm.rs::privatemode()`. Anthropic-shape and embeddings / transcription endpoints are exposed by the same proxy and documented upstream; Wirken does not send to them today.

## Models

Verified against <https://docs.privatemode.ai/models/overview/> as of Privatemode v1.38.0.

| Model ID | Context | Tools | Vision | Status |
|----------|---------|-------|--------|--------|
| `kimi-k2.5` | 262k | Yes | Yes | Stable |
| `gemma-3-27b` | 128k | Yes¹ | Yes | Stable |
| `gpt-oss-120b` | 128k | Yes | No | Stable |
| `qwen3-coder-30b-a3b` | 128k | Yes | No | **Deprecated** — migrate to `kimi-k2.5` |
| `qwen3-embedding-4b` | 32k | — | — | Stable (embeddings, 1024 or 2560 dim) |

¹ Gemma 3 cannot generate mixed text and tool outputs in the same response.

**Wirken's default: `kimi-k2.5`.** Matches Privatemode's recommended flagship: 262k context, tools, multimodal. Alternates are selectable via `model = "..."` in the provider config.

## Route a single channel to Privatemode

The more interesting configuration — and the Privatemode partnership's headline demo — routes privacy-sensitive channels (Signal, iMessage) to Privatemode while other channels keep using a cheap-or-capable provider (Anthropic, OpenAI) under the same agent identity. One agent, one skill set, one permission surface; provider chosen per line. This is the #60 feature.

**Pre-reqs:** run the generic [Quickstart](#quickstart) once to get a default provider wired. Then:

1. **Store the Privatemode key in the vault under its own slot.** The wizard would have stored it as `privatemode-access-key` when Privatemode was your default; if Privatemode is an *override*, add the slot explicitly:
   ```
   echo "<YOUR_ACCESS_KEY>" | wirken credentials add privatemode-access-key --stdin
   ```
2. **Re-run `wirken setup`** and answer yes to _"Configure a per-channel LLM provider override?"_ When prompted:
   - Channel: `signal` (or whichever channel you want routed to Privatemode)
   - Provider: `privatemode`
   - Model: `kimi-k2.5`
   - Base URL: `http://localhost:8080/v1`
   - Vault slot for API key: `privatemode-access-key`
3. **Inspect `~/.wirken/provider.json`**. It should now contain a `channel_overrides` block:
   ```json
   {
     "provider": "anthropic",
     "model": "claude-sonnet-4-6",
     "channel_overrides": {
       "signal": {
         "provider": "privatemode",
         "model": "kimi-k2.5",
         "base_url": "http://localhost:8080/v1",
         "api_key_name": "privatemode-access-key"
       }
     }
   }
   ```
4. **`wirken run`.** A Signal message now routes to Privatemode; a Slack message stays on the agent's default. The audit log's `LlmRequest` events carry the per-turn provider and model.

**Fail-closed behavior:** if `api_key_name` points at a vault slot that doesn't exist, `wirken run` refuses to start with a message naming the missing slot. Nothing silently degrades to the default.

## Credentials

The Privatemode access key is stored in Wirken's XChaCha20-Poly1305 vault as a single inference credential (`privatemode-access-key` when used as a channel override; otherwise the default `<provider>-api-key` slot). The operator delivers the key to the proxy via `--apiKey` on the `docker run` command line — that leg is proxy ↔ backend, not Wirken's surface.

## Deployment

Wirken does not manage the proxy lifecycle. Operators start `privatemode-proxy` themselves. The `wirken setup` wizard prints the reference command:

```
docker run -d --name privatemode-proxy \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/edgelesssys/privatemode/privatemode-proxy:latest \
  --apiKey <key>
```

**Security note:** the proxy binary binds `0.0.0.0` by default. The `-p 127.0.0.1:8080:8080` form above restricts the published port to loopback so it is not reachable from other hosts. Do not drop the `127.0.0.1:` prefix on a multi-tenant or internet-exposed host.

Under systemd, run the same `docker` invocation from a user unit, or point `ExecStart=` at the binary directly. Under Kubernetes, use Privatemode's upstream Helm chart at `privatemode-proxy/charts/privatemode-proxy/` in <https://github.com/edgelesssys/privatemode-public>. Wirken does not ship unit files or charts of its own.

Run with manifest auto-fetch enabled (the default). Pinning via `--manifestPath` is not recommended for production per the upstream guide.

## Verifying a round-trip

1. Start the proxy (see [Quickstart](#quickstart) step 2).
2. `wirken run` with Privatemode configured — either as the default provider or as a channel override.
3. Send a message through a configured channel.
4. Confirm the agent response arrives in that channel.
5. `wirken sessions list` shows the session. `wirken sessions verify <id>` walks the hash-chained session log and exits 0 on an intact chain.
6. Each LLM turn writes one `LlmRequest` event into the session log carrying `provider` and `model`. For Privatemode turns the provider is `openai` (because Privatemode ships OpenAI-shape today) and the model is `kimi-k2.5`. A surfaced per-turn view in the CLI is out of scope here — operators who want to confirm directly can query the session log via `sqlite3 ~/.wirken/audit.db "SELECT payload FROM session_events WHERE session_id = '<id>' AND event_type = 'LlmRequest'"`.

## Troubleshooting

- **`curl http://127.0.0.1:8080/v1/models` times out or is refused.** The proxy container isn't up. `docker ps | grep privatemode-proxy` — if absent, re-run step 2 of the Quickstart. If present but unhealthy, `docker logs privatemode-proxy`; the common first-run cause is attestation against `cdn.confidential.cloud:443` being blocked by an outbound firewall.
- **Proxy logs say "401" or "invalid api key".** The key you passed to `--apiKey` is wrong. Generate a fresh one at <https://www.privatemode.ai> and restart the container. This is a proxy-to-backend error, not a Wirken error — `wirken run` will print success, then every message will fail at inference.
- **`wirken run` aborts with "vault slot X is not present".** You configured a channel override but never ran `wirken credentials add X --stdin` to populate the slot. The message names the exact slot and the fix.
- **`wirken run` starts but messages get no reply.** Check two things in order: (a) `docker logs privatemode-proxy` for proxy-side errors, (b) `tail -f ~/.wirken/audit.db`-backed session events or `wirken sessions list` to see if an `LlmRequest` event was even emitted. If no event, the adapter never reached the agent — usually an adapter config problem. If the event is there but no response, the call to the proxy failed; proxy logs will say why.
- **First message after a cold start takes 10+ seconds.** The proxy fetches a signed manifest from `cdn.confidential.cloud:443` and runs the remote attestation handshake on first request. Second and subsequent requests are fast. Not a bug.
- **I see two `privatemode-proxy` containers listening on the same port.** `docker ps`, kill the extra one. Wirken does not manage the proxy lifecycle — it assumes the operator owns `:8080`.

## Verified claims

Grounded in the Privatemode 2.0 launch email (2026-04-22) and the public release notes.

- Privatemode supports Anthropic `/v1/messages` as of release **v1.37.0**.
- Privatemode 2.0 bundles Kimi K2.5, the browser web app, and separate input/output/cached token pricing. The desktop app is deprecated in favor of the web app.
- Proxy attestation happens before Wirken sends any request. The proxy writes manifest transitions to `log.txt` in its workspace.
- `gpt-oss-120b` is stable with 128k context and tool calling (text-only, no vision).
- `kimi-k2.5` shipped in **v1.38.0** (2026-04-22) with 262k context and multimodal input.

## Known gotchas

- **`reasoning_content` deprecation**: removed from Anthropic-shape responses on 2026-05-01. If Wirken's audit writer records `reasoning_content` directly, it must switch to the supported field before that date.
- **Client-version cutoff**: Privatemode backends dropped support for clients older than v1.33 on 2026-04-17. Pin the proxy image to `:latest` or a release ≥ v1.33.
- **Cache token reporting**: Anthropic-shape responses from Privatemode do **not** return `cache_creation_input_tokens` separately; those tokens are folded into `input_tokens`. Audit records must not assume the field is present.
- **No Rust SDK**: Privatemode ships official SDKs at `sdk/js` and `sdk/wasm` in the public repo. Wirken speaks the documented HTTP API directly (`reqwest` against the local proxy).
- **Default bind**: the proxy binary binds `0.0.0.0` — loopback-only exposure is the deployer's responsibility via port publication (docker `-p 127.0.0.1:...`) or systemd socket activation.

## Gaps

- Wirken does not verify Privatemode attestation independently; it trusts the proxy handshake.
- No integration test in CI exercises the Privatemode code path. The adapter + LLM client paths have unit coverage, but the end-to-end request/response with the real proxy (or a stub) is verified by hand.
- The `privatemode-access-key` vault slot is per-agent, not per-caller. Multi-user deployments that want to bill inference to distinct humans need per-caller key scoping that does not exist today.

## References

- Privatemode docs: <https://docs.privatemode.ai/>
- API overview: <https://docs.privatemode.ai/api/overview/>
- Anthropic endpoint: <https://docs.privatemode.ai/api/messages/>
- Proxy configuration guide: <https://docs.privatemode.ai/guides/proxy-configuration/>
- Models overview: <https://docs.privatemode.ai/models/overview/>
- Release notes: <https://docs.privatemode.ai/release/>
- Public source (MIT): <https://github.com/edgelesssys/privatemode-public>
