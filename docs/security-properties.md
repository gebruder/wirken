# Security properties

Three mapping tables plus the escape-hatch inventory. Every mechanism named
here is owned by another page; the cells say what the control is and link to
where it is described, rather than restating it.

- Permission tiers, approvals, identity: [permissions-and-identity.md](permissions-and-identity.md)
- Audit chain, events, verification: [audit-cli.md](audit-cli.md)
- Sandbox: [sandbox-properties.md](sandbox-properties.md)
- Egress, both axes: [egress.md](egress.md)
- Signing surfaces: [signing.md](signing.md)
- Compile-time vs runtime enforcement: [enforcement-model.md](enforcement-model.md)

Every rating sits on the same floor: a process running at the wirken UID is
outside the model.

## OWASP Agentic AI Threats and Mitigations

The [OWASP agentic-threats taxonomy](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
numbers its threats T1-T15. Listed below are the ones Wirken ships a control
for.

| OWASP | Threat | Control | Gap |
|-------|--------|---------|-----|
| T2 | Tool misuse | Tool inputs validated against JSON schema; filesystem tools confined by `cap_std::Dir` rooted at the workspace, so path traversal is rejected at the capability boundary. [Tiers](permissions-and-identity.md) | Workspace TOCTOU: files inside the workspace may be modified by any process at the same UID between the agent's read and its use of the contents. The `Dir` confinement defends against the agent escaping the workspace, not against same-UID writers racing it inside. |
| T3 | Privilege compromise | [Three-tier permission model](permissions-and-identity.md): first-use approval with expiry, Tier 3 always prompting, `http_request` at Tier 1 with the skill's own block as authorization. | Tier 2 approvals are per permissions-store, not per operator: every operator driving the same data dir inherits the others' Tier 2 approvals. Multi-operator deployments that do not share a trust boundary should run separate instances against separate data dirs. |
| T4 | Resource overload | Tool-call loop capped at 20 rounds per turn; child agents carry a separate `max_rounds`; `exec` timeout 300s; [rate limiting](enforcement-model.md#rate-limits) on all sources with no localhost exemption. | None beyond the local-attacker floor. |
| T8 | Repudiation and untraceability | [Hash-chained audit log](audit-cli.md) written before execution, per-agent attestation, offline replay, 90-day retention with chain-preserving pruning, [SIEM forwarding](siem-forwarder.md), [injection detection](enforcement-model.md#prompt-injection-detection), [egress hooks](enforcement-model.md#veto-and-egress-hooks). | The audit signing key is held by the process that writes the chain, so the signature is meaningful for offline replay and third-party detection, not as a guarantee of fidelity at write time. Tamper-evidence against a same-UID attacker needs an out-of-band anchor. |
| T9 | Identity spoofing and impersonation | Per-adapter Ed25519 challenge-response over local IPC; the signature covers `(domain \|\| adapter_id \|\| nonce)`, so the payload binds the identity cryptographically and not only through the pubkey lookup. After handshake the gateway resolves the adapter's channel into `AuthenticatedChannel`; every inbound frame's self-declared channel is matched against it and a mismatch is rejected with an `adapter.channel_mismatch` row. | The compile-time `SessionHandle<C: Channel>` API is not on the production message path; the live cross-channel control is the runtime match. See [enforcement model](enforcement-model.md#channel-isolation). |
| T11 | Unexpected RCE and code attacks | [Docker or gVisor sandbox](sandbox-properties.md) for `exec`, Wasmtime for Wasm skills, refusal rather than host fallback when the runtime is missing. | `sandbox.json` `mode: off` runs `exec` on the host at the wirken UID, and the host shell can then read or rewrite every trust file under the data dir. MCP children spawn at the wirken UID with no process sandbox. The `exec` sink, MCP children and the LLM client are all outside the skill-set egress allowlist; see [egress](egress.md). |
| T13 | Rogue agents in multi-agent systems | One OS process per channel adapter, so a compromised adapter's blast radius is one channel. [Capability-attenuated sub-agents](multi-agent.md#sub-agent-orchestration): tool-allowlist intersection, clamped tier, max rounds, max runtime, headless, depth cap of 4. | Sub-agents run in the parent's process. |
| | Credential security | XChaCha20-Poly1305 at rest, keyed from the OS keychain on Linux and macOS with an age-encrypted file fallback; per-credential expiry and rotation; `secrecy` + `zeroize` make logging a secret a compile error; ciphertexts bind the credential name into the AEAD additional-authenticated data so a row cannot be spliced into another. See [credentials](credentials.md). | Windows uses the age-file backend. The vault enforces no per-process ACL: any process holding the device key and the database can retrieve any credential by name. |
| | Keychain access serialization | On macOS the process serializes keychain read-modify-write with a process-local mutex around every `SecItemAdd` / `SecItemUpdate` / `SecItemCopyMatching`, closing the intra-process race where two threads observe the same pre-update value. | Cross-process keychain races are out of scope: a same-UID attacker is excluded by the floor, and an attacker without same-UID access cannot drive the macOS permission gate at all. |
| | Signature verification | Every Ed25519 verification in the workspace uses `verify_strict`, rejecting non-canonical scalar encodings and small-order or mixed-order R points, so a malleable variant cannot be substituted. Covers attestation, gateway and MCP-proxy handshakes, skill bundles, the org-config anchor and the chain-head verifier. Where bundles carry `signed_at` + `max_age_seconds` the gateway also enforces a freshness window. See [signing](signing.md). | `WIRKEN_ALLOW_STALE_ORG_CONFIG` bypasses the freshness window; the signature itself is still verified. |
| | Transport security | HTTPS enforced for all LLM and Matrix connections outside localhost. Cap'n Proto IPC with a 16MB frame limit, a 64M word traversal limit (512 MB) and a 64-level nesting limit. | The IPC sockets are a same-user trust boundary; cross-user isolation is the operator's OS-level responsibility. |
| | Supply chain | [Skill and MCP signatures](signing.md) verified at install and again at load; release binaries carry signed checksums and SLSA provenance; CI runs clippy with `-D warnings`, fmt check and the full suite on every push. Skill installation is not tier-gated: `Action::SkillInstall` was removed because the CLI install path never reached it, and the `action_variant_set_is_pinned` tripwire keeps it from being reintroduced unwired. | Default builds ship an empty `wirken-registry-pubkey.pub`, so the registry-provided key is the sole anchor unless an operator sets a root. Rotating a compile-time anchor requires rebuilding the binary. |
| | Confidential inference | Tinfoil and Privatemode run open-source models inside hardware TEEs (AMD SEV-SNP, Intel TDX, NVIDIA H100 CC). Tinfoil dispatch gates each session on hardware attestation plus Sigstore provenance, over TLS pinned to the attested certificate. See [configuration](configuration.md#confidential-inference). | The LLM client is outside the egress allowlist on every provider, this one included. |

## OWASP Top 10 for Agentic Applications (2026)

[ASI01-ASI10](https://genai.owasp.org/) is the 2026 agentic-application
taxonomy, distinct from T1-T15 above. Citations name a `fn`, `const` or type;
the line number is a hint that drifts, so grep the symbol. Ratings:
`Mitigated` (addressed on the live dispatch path), `Partial` (addressed with a
documented gap or operator opt-out), `Partial (detection only)` (observed and
logged, not blocked).

| ASI | Control | Rating | Gap or opt-out |
|-----|---------|--------|----------------|
| ASI01 Agent Goal Hijack | `InjectionDetector::scan` (`crates/gateway/src/injection_detect.rs:105`) from `message_loop` (`crates/cli/src/commands/run.rs:3164`); the `exec` tier gate (`tool_to_action`, `crates/agent/src/tool.rs:1721`; `Action::tier`, `crates/gateway/src/permissions.rs:224`); per-skill phase overlays | Partial (detection only) | Detection tags the row and emits `message.threat_flagged` (`run.rs:3191`) but does not block or downgrade the message. A hijacked goal is bounded by the downstream tool gate, not prevented at the prompt. |
| ASI02 Tool Misuse and Exploitation | `tool_to_action` (`tool.rs:1721`) with `TIER2_ALLOWLIST` (`permissions.rs:195`) and the `SHELL_METACHARS` pipeline sentinel (`tool.rs:1624`, applied at `:1730`); MCP tools at Tier 3; unregistered names default-deny via `Action::UnknownTool` (`runtime.rs:3036`); org allow/deny lists (`runtime.rs:2980`); veto hooks | Partial | The skill-set allowlist covers `web_search`, `generate_image`, `http_request` and the Zirkel transport (`EgressClient`, `egress.rs:167`); MCP children and the LLM client are unmediated. `exec` is bounded on a separate per-channel axis that defaults to no networking at all. `sandbox.json mode: off` runs `exec` on the host. |
| ASI03 Identity and Privilege Abuse | Checks key on `(approval_key, agent_id)` (`PermissionStore::check`, `permissions.rs:729`; `get_approval`, `:1137`); tier clamp `set_subagent_runtime` (`runtime.rs:1525`), depth cap `MAX_SUBAGENT_DEPTH` = 4 (`runtime.rs:60`), tool-allowlist intersection (`bind_as_subagent`, `runtime.rs:1560`) | Partial | A Tier 2 approval is per permissions-store, not per user: one sender's approval applies to every sender on a shared agent until it expires. |
| ASI04 Agentic Supply Chain | `verify_skill_signature` (`crates/agent/src/skill.rs:510`) against a registry-anchored key with optional root delegation (`verify_skill_with_expected_key_and_delegation`, `crates/gateway/src/skill_registry.rs:398`); the same check gates install (`crates/cli/src/commands/skills.rs:64`); MCP entry signatures; signed release binaries | Partial | Opt-outs `WIRKEN_ALLOW_UNSIGNED_SKILLS` (`ALLOW_UNSIGNED_ENV`, `skill.rs:18`), `_MCP`, `_ORG_CONFIG`. MCP children spawn at the wirken UID with no process sandbox and outside the egress allowlist. |
| ASI05 Unexpected Code Execution | `exec` in a Docker or gVisor sandbox (`ToolExecutor::sandbox`, `tool.rs:565`) with `cap_drop=ALL`, `no-new-privileges`, read-only rootfs and no network by default (`build_host_config`, `sandbox.rs:994`, flags at `:1035`); a channel granted egress reaches the network only through a policed CONNECT proxy; refusal rather than host fallback when the sandbox is unavailable (`tool.rs:708-733`); Wasm fuel limit (`wasm_sandbox.rs:64`, `:125`); 300s timeout (`sandbox.rs:265`, enforced at `:457`); exec tiering classifies on the resolved symlink target, not the lexical basename | Mitigated (with opt-out) | `sandbox.json mode: off` is a documented operator opt-out that runs `exec` on the host at the wirken UID; the gateway warns at startup when it engages. |
| ASI06 Memory and Context Poisoning | Append-only per-session chain (`SessionLog::append` / `verify`, `session_log.rs:1996`, `:2050`; schema at `:2861`) with per-agent attestation (`attestation.rs:86`); the context engine trims under the per-model budget (`context.rs:86`); `CrossChannelMemoryRead`, `ImportedChatRead` and `ImportedChatSearch` are all Tier 3 (`permissions.rs:224`), so every cross-conversation read prompts and none can be pre-approved by key alone | Partial | Tier 3 prompts on each use, but an operator who approves a cross-channel read admits whatever that channel's entries contain, including text an attacker put there earlier: the gate controls disclosure, not the integrity of what is disclosed. The workspace is readable and writable by any process at the wirken UID between an agent's read and its use of the bytes. |
| ASI07 Insecure Inter-Agent Communication | Per-adapter Ed25519 handshake (`perform_gateway_handshake`, `crates/ipc/src/auth.rs:178`; adapter side at `:88`), rejected handshakes audited (`run.rs:2116`, `:2086`); Cap'n Proto frame bounds, 16 MB and 64-level nesting (`MAX_FRAME_SIZE`, `transport.rs:7`); per-frame channel-mismatch rejection (`run.rs:3119`); sub-agents run in-process with no network | Mitigated | The IPC sockets are a same-user trust boundary; cross-user isolation is the operator's OS-level responsibility. |
| ASI08 Cascading Failures | `MAX_TOOL_ROUNDS` = 20 (`runtime.rs:25`); `MAX_SUBAGENT_DEPTH` = 4 (`runtime.rs:60`) plus per-child max-rounds and max-runtime budgets; 300s exec timeout; auth and control-plane limiters with no loopback exemption (`rate_limit.rs:11`, `:132`) | Mitigated | None beyond the local-attacker floor. |
| ASI09 Human-Agent Trust Exploitation | Tier 3 actions always prompt and are never served from the persisted approvals table (`permissions.rs:801`); out-of-band approval gates per channel; permission denials logged with full context | Partial | The Tier 3 arm is reached only after the session-cache short-circuit at the top of `check` (`permissions.rs:744`), which is deliberately tier-agnostic. No current caller session-grants a Tier 3 action, so the always-prompt property holds today by emitter discipline rather than by structure. A Tier 2 approval is also shared across all senders on an agent, and prompt-injection that fabricates operator trust is logged, not blocked (`run.rs:3164`). |
| ASI10 Rogue Agents | Per-agent Ed25519 identity and session attestation (`attestation.rs:86`; `verify_session_attestations` at `:134`); tamper-evident hash-chained audit (`session_log.rs:2050`); org `blocked_tools` as a configuration-time kill switch (`runtime.rs:2980`); unregistered tools default-deny (`runtime.rs:3036`); sub-agent ceilings | Partial | No central agent registry or live revocation surface beyond org config and per-agent identity; revocation requires a config push and a gateway restart. |

## Documented escape hatches

The defaults above are deliberately strict. Each knob below is opt-in, emits a
`tracing::warn!` every time it engages, and leaves the operator on the hook for
what the relaxed posture loses. A one-shot env var on the command line is not
durable across reboots, so the practical forms are a systemd
`EnvironmentFile`, a shell `rc` export, or a wrapper script that invokes
`wirken run`.

| Knob | What it disables |
|------|------------------|
| `WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG=1` | Ed25519 verification of the org-config bundle pulled from the policy URL. The bundle is then trusted on HTTPS and URL pinning alone. The gateway logs a warn on every fetch. |
| `WIRKEN_ALLOW_UNSIGNED_SKILLS=1` | Both skill gates. At install, lands a registry skill that has no `signer_key` in the index entry. At load, accepts a bundle with no `SKILL.sig` / `SKILL.pub`. Neither gate accepts a present-but-invalid signature, and neither bypass applies once a registry root is configured. See [signing](signing.md#skill-signing). |
| `WIRKEN_ALLOW_UNSIGNED_MCP=1` | Lets the MCP proxy spawn an `mcp.json` entry carrying no `signature` even under a build compiled with a populated anchor. Invalid signatures are never bypassed. Each spawn lands an `mcp_entry_verified` row with signer `<unsigned-bypass>` on the `gateway-mcp` sentinel session. |
| `WIRKEN_ALLOW_STALE_ORG_CONFIG=1` | The org-config freshness window, including a `signed_at` in the future, which usually means clock skew or replay. The signature itself is still verified. Each bypass warns with the bundle's age and the configured `max_age_seconds`. |
| `WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN=1` | The `Origin` header check on the webchat `/api/chat` endpoint. Same-host non-browser callers can drive the agent; same-UID becomes the sole trust boundary. Warn at startup. |
| `WIRKEN_ALLOW_UNREGISTERED_HOOKS=1` | Flips the veto- and egress-hook timeout path from fail-closed to fail-open, and admits a hook process whose id is not in the registry. A hook that times out then passes the tool call through instead of refusing it. The audit row records the timeout either way. See [enforcement model](enforcement-model.md#veto-and-egress-hooks). |
| `WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES=N` | Sets the flush cycles between continuous chain-verification passes (default 100). Above 10,000 the in-process verifier is effectively disabled, so a chain break is caught only at the next operator-run `wirken audit verify`. Only the above-10,000 case warns; smaller departures do not. |
| `sandbox.json` `mode: off` | Runs `exec` directly on the host at the wirken UID instead of inside a container. The only remaining gate is the permission tier, and the host shell can read or rewrite every trust file under the data dir (`tool_policy.json`, `sandbox.json`, `org.url`, `org-config-pubkey.pub`, `audit.db`, `vault.db`, `agents/<id>/identity.key`, `audit-alarms.log`); changes take effect at the next gateway start. Edit the file once; persists across restarts; gateway warns at startup. |
| `WIRKEN_ALLOW_UNVERIFIED=1` *(install-time only)* | The release-binary checksum and signature verification step in `install.sh`. The binary is installed on the strength of the network and the URL alone. Not honored at runtime; re-running `install.sh` is the only way to engage it. |

## NIST AI Risk Management Framework

The [NIST AI RMF (AI 100-1)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf)
takes the complementary view: how an organization governs, maps, measures and
manages AI risk across its lifecycle. Only subcategories where Wirken ships a
code-verifiable capability are listed. Subcategory text is defined in the
companion [Playbook](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook).

| Subcategory | Capability | Owner |
|-------------|------------|-------|
| GOVERN 1.1, policies and procedures | Three-tier model with first-use approval, expiry and revocation, plus a sweep of stored grants the gate cannot act on | [permissions-and-identity.md](permissions-and-identity.md) |
| GOVERN 1.6, inventory and lifecycle | Per-credential `created_at`, `expires_at`, `last_used_at`, `rotation_due_at`, and a `rotate` API | [credentials.md](credentials.md) |
| GOVERN 2.1, roles and responsibilities | Centralized org policy: provider, SIEM, MCP servers and sandbox mode pulled from a company URL and applied locally | [enterprise.md](enterprise.md) |
| MAP 1.1, context and use cases | Provider-agnostic routing across OpenAI, Anthropic, Gemini, Bedrock, Ollama, Tinfoil, Privatemode, Infomaniak, Hetzner and any OpenAI-compatible endpoint | [configuration.md](configuration.md#providerjson) |
| MAP 5.1, impact and blast radius | One OS process per channel adapter; a sealed `Channel` marker makes cross-channel access a type error in the API that carries it | [enforcement-model.md](enforcement-model.md#channel-isolation) |
| MEASURE 2.5, output monitoring | Real-time forwarding to Datadog, Splunk HEC, Microsoft Sentinel or a generic webhook, alongside the local session log | [siem-forwarder.md](siem-forwarder.md) |
| MEASURE 2.6, security and resilience | Prompt-injection detector flags role-switching, instruction overrides, base64 commands and tool-call injection; events are tagged in audit, not blocked | [enforcement-model.md](enforcement-model.md#prompt-injection-detection) |
| MEASURE 2.7, system logging | Append-only per-session hash chain with per-agent Ed25519 attestation and offline replay | [audit-cli.md](audit-cli.md) |
| MANAGE 1.3, risk mitigation | Docker and gVisor confine `exec` (no network, 512 MB, 256 PIDs, non-root, 300s); Wasmtime runs Wasm skills under a fuel limit with no filesystem and no network | [sandbox-properties.md](sandbox-properties.md) |
| MANAGE 2.2, input validation | Tool inputs declared as JSON Schema; filesystem tools constrained by `cap_std::Dir` rooted at the workspace | [sandbox-properties.md](sandbox-properties.md) |
| MANAGE 2.4, abuse and overuse limits | Auth rate limiter with no loopback exemption (5 failures / 60s / 10-minute lockout) and a control-plane GCRA limiter via `governor` | [enforcement-model.md](enforcement-model.md#rate-limits) |
