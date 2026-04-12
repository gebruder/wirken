# Security Properties

Designed against the [OWASP Top 10 for Agentic AI](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/).

| OWASP | Threat | Mitigation |
|-------|--------|------------|
| AG01 | Excessive agency | Three-tier permission model. Tier 1 (always allowed): workspace file access, web search. Tier 2 (first-use approval, remembered 30 days): shell exec, external file access. Tier 3 (always prompt): destructive ops, credential access, network requests, skill install. |
| AG02 | Code execution | Docker sandbox: ephemeral containers, no-network, 512MB memory, 256 PID limit, non-root user. gVisor sandbox: same constraints with kernel attack surface reduction via `runsc` runtime. Wasm sandbox: compiled skill modules run in Wasmtime with fuel-based CPU limits, no filesystem, no network. Shell exec timeout at 300s. |
| AG04 | Tool misuse | Tool inputs validated against JSON schema. Workspace path confinement: file operations are canonicalized and rejected if outside workspace boundary. |
| AG05 | Identity spoofing | Per-adapter Ed25519 challenge-response handshake over Unix domain sockets. Compile-time channel isolation: `SessionHandle<Telegram>` and `SessionHandle<Discord>` are different types; the compiler rejects cross-channel access. |
| AG07 | Multi-agent manipulation | Each channel adapter runs as a separate OS process. If an adapter is compromised, the blast radius is one channel. IPC boundary prevents lateral movement. Child agents spawned via `spawn_subagent` run under capability-attenuated ceilings: tool allowlist intersection, clamped permission tier, max rounds, max runtime, headless (no interactive approvals). Hard depth cap of 4 prevents nesting cycles. |
| AG08 | Runaway loops | Agent tool call loop capped at 20 rounds per turn. Child agents have a separate per-ceiling `max_rounds` budget. Shell exec timeout at 300s. Rate limiting on all sources including loopback, with no localhost exemption. |
| AG09 | Insufficient logging | Every agent action logged as a typed session event to an append-only, per-session hash-chained SQLite table before execution. Per-agent Ed25519 attestation signs the chain head after every turn. `wirken session verify` replays the session log offline and re-checks hashes. 90-day retention with configurable pruning. Real-time SIEM forwarding to Datadog, Splunk, or webhook. Prompt injection detection flags inbound messages with threat indicators. Permission denials logged with full context: tool, tier, agent, trigger message. |
| | Credential security | XChaCha20-Poly1305 encryption at rest, keyed from OS keychain (macOS Keychain / libsecret / age fallback). Per-credential expiry and rotation. `secrecy` + `zeroize` ensure that logging or serializing a secret is a compile error. Key material zeroed after use. |
| | Transport security | HTTPS enforced at transport level for all LLM and Matrix connections (non-localhost). Cap'n Proto IPC with 16MB frame limit, 512M word traversal limit, 64-level nesting limit. |
| | Supply chain | Skill signatures verified against registry-provided Ed25519 key, not a bundled key. Release binaries include SHA-256 checksums; installer verifies before installing. CI runs clippy with `-D warnings`, fmt check, and full test suite on every push. |
| | Confidential inference | Tinfoil and Privatemode providers run open-source LLMs inside hardware TEEs (AMD SEV-SNP, Intel TDX, NVIDIA H100 CC). Prompts encrypted end-to-end, protected against software attacks on infrastructure. |

## NIST AI Risk Management Framework mapping

The [NIST AI RMF (AI 100-1)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) takes the complementary view: how an organization governs, maps, measures, and manages AI risk across its lifecycle. The mapping below lists only RMF subcategories where Wirken ships a code-verifiable capability today. Subcategory text is defined in the companion [NIST AI RMF Playbook](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook).

| Subcategory | Wirken Capability | Implementation |
|-------------|-------------------|----------------|
| GOVERN 1.1, policies and procedures | Three-tier permission model with first-use approval, expiry, and revocation | `wirken-gateway::permissions` |
| GOVERN 1.6, AI system inventory and lifecycle | Per-credential lifecycle metadata: `created_at`, `expires_at`, `last_used_at`, `rotation_due_at`; `rotate()` API | `wirken-vault::store` |
| GOVERN 2.1, roles and responsibilities | Centralized org policy endpoint: provider, SIEM, MCP servers, sandbox mode pulled from a company URL and applied locally | `wirken-gateway::org` |
| MAP 1.1, context and use cases | Model-agnostic provider routing across OpenAI, Anthropic, Gemini, Bedrock, Ollama, Tinfoil, Privatemode, and OpenAI-compatible endpoints | `wirken-agent::llm` |
| MAP 5.1, impact and blast radius | Compile-time channel isolation: `SessionHandle<C: Channel>` is parameterized by a sealed marker type, so cross-channel access is a type error | `wirken-ipc::channel` |
| MEASURE 2.5, output monitoring | Real-time SIEM forwarding to Datadog Log Intake, Splunk HEC, or generic webhook, in addition to the local session log | `wirken-audit::siem` |
| MEASURE 2.6, security and resilience | Prompt injection detector flags inbound messages with threat metadata (role-switching, instruction overrides, base64 commands, tool-call injection); events are tagged in audit, not blocked | `wirken-gateway::injection_detect` |
| MEASURE 2.7, system logging | Append-only per-session hash-chained session log. Each event carries a SHA-256 leaf hash and chain hash. Per-agent Ed25519 attestation signs the chain head. `wirken session verify` replays events offline and re-checks hashes and tool results | `wirken-audit::session_log`, `wirken-agent::attestation` |
| MANAGE 1.3, risk mitigation | Three sandbox runtimes: Docker and gVisor confine the `exec` tool (no-network, 512 MB, 256 PID, non-root, 300 s); Wasmtime runs Wasm skills with fuel-based CPU limits, no filesystem, no network | `wirken-agent::sandbox`, `wirken-agent::wasm_sandbox` |
| MANAGE 2.2, input validation | Tool inputs declared as JSON Schema; filesystem tools canonicalize paths and reject anything outside the workspace boundary | `wirken-agent::tool` |
| MANAGE 2.4, abuse and overuse limits | Auth rate limiter with no loopback exemption (5 failures / 60 s / 10-minute lockout) and a control-plane GCRA limiter via `governor` | `wirken-gateway::rate_limit` |
