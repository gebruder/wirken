# Threat model

This is Wirken's threat model. It is also the input to automated security
scans, which work offline in the image `docker/audit.Dockerfile` builds.

## What wirken is

Wirken is a local agent gateway written in Rust. One `wirken` binary runs the
gateway, which hosts the agents in its own process, and is started again as
each chat channel's adapter process and as the MCP proxy. Agents call LLM
providers over HTTPS and act through tools. A permission gate decides every
tool call before it runs, `exec` runs in a container, and every action is
written to a per-session hash chain in SQLite before it executes.

The design is in [architecture.md](architecture.md), the compile-time and
runtime controls in [enforcement-model.md](enforcement-model.md), and the
control-by-control mapping in [security-properties.md](security-properties.md).
Those pages name the symbol behind each control
and state each control's known gap. Read them before reporting: a finding that
restates a documented gap is not a finding.

The floor under everything below: a process running as the wirken OS user is
outside the model. That includes code running inside an adapter, the MCP
proxy or a hook process, which all run as that user.

## Trust boundaries and adversarial inputs

1. **Chat platforms to adapters.** Message text, sender ids, attachments and
   platform events from Telegram, Discord, Slack, Teams, Matrix, WhatsApp,
   Signal, iMessage and Google Chat are attacker-controlled. Webhook adapters
   listen on 127.0.0.1 behind the operator's ingress. Teams and Google Chat
   webhooks are authenticated by RS256 JWT verification
   (`crates/adapter-teams/src/auth.rs`, `crates/adapter-google-chat/src/auth.rs`),
   WhatsApp by an HMAC-SHA256 signature (`verify_signature`,
   `crates/adapter-whatsapp/src/adapter.rs`). iMessage (BlueBubbles) webhooks
   carry no authentication, so that boundary is the loopback bind, and
   `wirken run` refuses to start the adapter on any other address
   ([channels.md](channels.md)). Parsing before authentication, verification bypass,
   and one sender acting as another are in scope.

2. **Adapter to gateway.** A Unix socket carrying Cap'n Proto frames after a
   peer-credential check and an Ed25519 challenge-response over
   `(domain || adapter_id || nonce)` (`perform_gateway_handshake`,
   `crates/ipc/src/auth.rs`). `FrameReader` bounds a frame at 16 MB, traversal
   at 64M words and nesting at 64 levels (`crates/ipc/src/transport.rs`). After
   the handshake the gateway pins the adapter's channel and rejects a frame
   declaring another (`adapter.channel_mismatch`, `message_loop`,
   `crates/cli/src/commands/run.rs`). Approval decisions arriving as frames are
   checked against the gateway-side approver allowlist keyed by
   `(adapter_id, user_id)` (`crates/gateway/src/approver_registry.rs`). In
   scope: platform-controlled bytes, forwarded by an adapter working as
   written, that make the gateway misroute a message, cross a channel, resolve
   an approval for someone not on the allowlist, crash or allocate without
   bound.

3. **Model output to tools.** Tool names and arguments the model emits are
   attacker-influenced through anything that reaches its context: messages,
   tool results, fetched pages, MCP results, imported archives, memory
   entries. A compromised LLM provider is the same adversary. Every call is
   classified by `tool_to_action` (`crates/agent/src/tool.rs`), answered by
   `PermissionStore::check` (`crates/gateway/src/permissions.rs`), and written
   to the chain before it runs. An agent cannot be built without the
   operator's permission store (`ToolGate`, `crates/agent/src/runtime.rs`);
   the one built without it, the `wirken sessions verify` replay
   (`AgentFactory::for_verify`), is `ToolGate::ReplayOnly` and refuses every
   dispatch. Tier 1 runs without a prompt, Tier 2 prompts once and can be
   remembered, Tier 3 prompts on every use and is never stored. A shell
   metacharacter in `exec` forces the pipeline sentinel, which
   matches no allowlist. A name nothing classifies resolves to `UnknownTool`,
   Tier 3. A turn is capped at 20 tool rounds (`MAX_TOOL_ROUNDS`) and
   sub-agents at depth 4 (`MAX_SUBAGENT_DEPTH`, both
   `crates/agent/src/runtime.rs`). A sub-agent gets per-child round and
   runtime budgets, a clamped tier and an intersected tool allowlist, and is
   checked against its own agent id with none of the parent's grants. In
   scope: a call classified below its effect, a command form or path form that
   changes the classification, a Tier 3 action answered from storage, a stored
   grant for a key that is not Tier 2, a sub-agent exceeding a ceiling or
   inheriting a grant, an approval prompt that shows the operator a different
   call from the one that runs, a dispatch from the replay agent, and a tool
   that runs with no row on the chain first.

4. **`exec` to the host.** A command the model runs is hostile. `exec` runs in
   a Docker or gVisor container (`build_host_config`,
   `crates/agent/src/sandbox.rs`) with all capabilities dropped,
   `no-new-privileges`, a read-only root, a non-root user, 512 MB, 256 PIDs,
   300 s, the workspace as its only mount, and no network unless the channel's
   egress grant routes it through the egress proxy (`crates/sandbox/src/`). The
   exec perimeter in [security-properties.md](security-properties.md) states what the process must
   not reach: any gateway socket, the data dir around its workspace, a `wirken`
   binary, anything key-like in its environment. With no container runtime,
   `exec` is refused, never run on the host. In scope: anything that breaks
   one of those statements through wirken's own setup of the container,
   egress beyond the channel's grant, and a host fallback.

5. **Outbound HTTP tools.** `http_request`, `web_search` and
   `generate_image` go through `EgressClient` (`crates/agent/src/egress.rs`)
   against the skill allow-set. With no allow-set, `http_request` reaches no
   host. In scope: reaching a host outside the allow-set (redirects, address
   and hostname forms, rebinding). Response bodies are untrusted input.

6. **MCP servers.** Reached through the proxy process (`crates/mcp-proxy`).
   `mcp.json` entries carry an Ed25519 signature over a canonical hash
   (`mcp_signing.rs`). Each stdio server runs in its own container with no
   network unless its signed entry lists hosts (`container.rs`, `egress.rs`).
   Every MCP tool call is Tier 3. The proxy receives only the credentials its
   configs reference, on stdin, OAuth ones without their refresh token. It
   asks the gateway over `mcp-refresh.sock`, mode 0600, for two things: an
   OAuth refresh, and, after an HTTP server refuses a credential (a 401, or an
   `invalid_token` challenge), that credential's current vault value. The
   gateway answers only the proxy's pid holding the token handed to it at
   spawn, only for credentials it handed the proxy, never with a refresh
   token, and writes an `mcp_credential_refetched` row naming each credential
   whose value it sends (`crates/mcp-proxy/src/refresh_service.rs`). In
   scope: a server reaching hosts its entry does not list, one server's
   credentials reaching another server or the model, a signature that does not
   cover what is spawned, and that service answering any other caller,
   sending a credential the proxy was not handed or a refresh token, or
   sending a value with no row.

7. **Signed artifacts.** Skill bundles (`verify_skill_signature`,
   `crates/agent/src/skill.rs`; `crates/gateway/src/skill_registry.rs`), the
   org-config bundle fetched from the policy URL (`crates/gateway/src/org.rs`,
   signature plus freshness), and MCP entries. Every Ed25519 check uses
   `verify_strict`. In scope: an artifact the anchor did not sign accepted,
   a signature checked over bytes other than the ones used, and a bypass
   engaging without its variable set.

8. **Imported chat archives.** A data-export zip, DEFLATE only
   (`crates/gateway/src/imported_archive.rs`, `imported_format.rs`). The
   archive is attacker-influenced. In scope: decompression and parsing
   robustness, path handling, and imported content reaching a session without
   the Tier 3 `ImportedChatRead` or `ImportedChatSearch` gate.

9. **Cross-channel memory.** Entries carry five origin labels the runtime
   stamps from the turn's inbound context; no tool argument can set them
   (`crates/gateway/src/memory.rs`, `crates/agent/src/memory_tool.rs`).
   Reading another channel's entries is Tier 3 and cannot be pre-approved. In
   scope: a model setting its own provenance, a partial label set written, and
   a cross-channel read without the Tier 3 prompt or its audit row.

10. **Webchat.** Served on 127.0.0.1 with an `Origin` check on `/api/chat`
    (`crates/cli/src/commands/webchat.rs`). In scope: a page in the operator's
    browser driving the agent cross-origin.

11. **Vault.** XChaCha20-Poly1305 with an Argon2id-derived or keychain device
    key (`crates/vault`). No process the gateway starts opens it or holds
    the passphrase; adapters get their own channel's credentials on stdin
    (`crates/cli/src/commands/adapter_handoff.rs`). `VaultSecret`
    (`crates/vault/src/secret.rs`) implements none of `Display`, `Debug`,
    `Clone`, `Serialize`. In scope: recovering a secret from a copy of
    `vault.db` without the passphrase or device key, AEAD or KDF misuse, and a
    secret reaching a log, an error message, a URL, an audit row, a SIEM
    payload, the model's context, another channel's adapter or a child's
    environment.

12. **Audit chain.** `SessionLog::append` and `verify`
    (`crates/audit/src/session_log.rs`), head signing
    (`crates/audit/src/signing.rs`), `wirken audit verify` and
    `wirken sessions verify` (`crates/cli/src/commands/audit.rs`,
    `session.rs`). Treat `audit.db` as edited by an attacker before a verifier
    reads it offline. In scope: an edit, deletion, reorder or truncation that
    verification passes, a head signature accepted from a key it should not
    accept, and a row that misattributes its actor, channel, agent or key id.
    What the hash covers is in [audit-cli.md](audit-cli.md), "Hash chain
    construction": the leaf hash is over the row's canonical-JSON payload,
    chained per session.

13. **Output to the operator.** Text printed to the operator's terminal is
    stripped of ANSI and C1 controls (`crates/agent/src/ansi.rs`). SIEM
    forwarding (`crates/audit/src/siem*.rs`, `otel_*.rs`) carries
    attacker-chosen strings into the operator's SIEM. In scope: escape
    sequences that survive to the terminal, and a string that forges a field
    or record in a SIEM payload.

14. **Local sockets.** `gateway.sock`, `gateway-hooks.sock`,
    `gateway-permissions.sock`, `mcp-proxy.sock` and `orchestrator.sock` under
    `<data_dir>/sockets`, mode 0600, each taking a signed handshake. Veto and
    egress hooks fail closed on timeout
    (`crates/gateway/src/hook_dispatcher.rs`, `egress_dispatcher.rs`). In
    scope: another OS user reaching a socket, a hook timeout passing a call
    without `WIRKEN_ALLOW_UNREGISTERED_HOOKS=1`, and a veto `Deny` that does
    not stop dispatch.

## Components that matter most / least

- **Most:** `crates/gateway/src/permissions.rs`, `crates/agent/src/tool.rs`,
  the dispatch path in `crates/agent/src/runtime.rs`,
  `crates/agent/src/sandbox.rs`, `crates/sandbox`, `crates/ipc`,
  `crates/vault`, `crates/audit/src/session_log.rs` and `signing.rs`,
  `message_loop` and adapter spawning in `crates/cli/src/commands/run.rs`,
  `adapter_handoff.rs`, `crates/mcp-proxy`, skill and org-config verification,
  and the webhook authentication in the Teams, Google Chat and WhatsApp
  adapters.
- **Also in scope:** the other adapters, the rest of `crates/gateway` (memory,
  imported archives, hook dispatch, approvers, rate limits, injection
  detection), `crates/agent/src/egress.rs` and `http_tool.rs`, webchat,
  `crates/skill-store`, SIEM and OTel forwarding.
- **Lower:** `crates/zirkel`, the `lyrik` commands
  (`crates/cli/src/commands/lyrik*.rs`), pricing and cost reporting, setup and
  `doctor`, `install.sh`.
- **Out of scope:** the harness code in `fuzz/`, `scripts/`, `docs/`,
  `.github/`, the content of `skills/` and `preset/`, and test fixtures.

## How to exercise it

- The image `docker/audit.Dockerfile` builds has every test target compiled,
  and `cargo test --workspace` runs in it offline. Tests that need a live
  Docker or gVisor runtime print `skipping:` and pass;
  `sandbox_refuses_host_fallback_when_unavailable` runs there because there
  is no runtime. Tests run as root in that image, and root ignores file
  modes: a test that needs a mode to refuse a write skips itself at euid 0,
  and a proof that depends on a file-permission denial does not show there.
- `cargo test -p wirken-agent --test hostile_corpus -- --nocapture` replays
  `tests/hostile/corpus.jsonl`, the hostile tool-call corpus, through
  `tool_to_action` and `PermissionStore::check`. A new hostile shape is one
  JSON line with its expected outcome.
- `crates/cli/tests/` drives the built binary end to end: adapter credential
  hand-off, the MCP proxy holding no vault, audit verification of malformed
  signatures, session replay.
- `target/debug/wirken` is built. `WIRKEN_DATA_DIR` points it at a scratch
  data dir. No LLM provider and no chat platform is reachable.
- `fuzz/fuzz_targets/` names the parsers worth fuzzing: `exec_classifier`,
  `skill_frontmatter`, `injection_scan`, `ipc_frame_decode`. They need nightly
  and `cargo-fuzz`, which that image does not have; replay an input as a unit
  test instead.

## Out of scope

- Anything that needs code execution as the wirken user, including inside an
  adapter, the MCP proxy or a hook process.
- The documented escape hatches while set: the `WIRKEN_ALLOW_*` variables,
  `WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN`, `WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES`,
  `sandbox.json` `mode: off`, and an `mcp.json` entry with `"sandbox": "off"`
  (table in [security-properties.md](security-properties.md)). A hatch whose effect is wider than
  that table states, or that engages without being set, is in scope.
- Gaps the docs already state: the Gap columns in
  [security-properties.md](security-properties.md) and the "What this does not
  cover" notes in [enforcement-model.md](enforcement-model.md). Showing that a gap is wider than stated is in
  scope.
- Prompt injection that changes what the model asks for. Injection detection
  flags and does not block, by design. What the gate lets the request do is in
  scope.
- LLM token and cost exhaustion.
- Vulnerabilities inside third-party crates; report those upstream. Known
  advisories with their exposure analysis are in `osv-scanner.toml` and
  `deny.toml`. A wirken call site that uses a crate unsafely is in scope.
- Kernel and container-runtime escapes that do not depend on how wirken
  configures the container.
- Configuration files in the data dir, which the operator writes and wirken
  trusts. Where a signature check exists (skills, `mcp.json` entries, the
  org-config bundle) the check is in scope.
- An operator approving a prompt that described the call accurately. The
  operator is the approver.

## How you rate severity

Rate by the property broken, on the default configuration, from the untrusted
inputs above.

- **Critical**
  - Code execution on the host, or a process holding the gateway's principal,
    from a chat message, model output, an `exec` command, a tool result, an
    MCP server or an imported archive. This includes `exec` reaching a gateway
    socket, the data dir or a key, and `exec` running on the host.
  - A vault secret disclosed anywhere listed in boundary 11.
  - A tool call that runs without the gate deciding it, or before its row is
    on the chain.
  - A skill, MCP entry or org-config bundle the anchor did not sign, accepted
    with no bypass set.
- **High**
  - Tier escalation: a call classified below its effect, the metacharacter
    sentinel bypassed, a Tier 3 action answered from storage, a grant stored
    for a non-Tier-2 key, a grant applied to an agent or key other than the
    one approved, a prompt that misdescribes the call.
  - A sub-agent exceeding depth, tier, tool allowlist, round or runtime
    ceilings, or gaining a parent's grant.
  - A channel crossing without the Tier 3 prompt: a frame, session, memory
    entry or credential reaching another channel; an approval resolved by a
    user not on the allowlist.
  - A modified, deleted, reordered or truncated chain that verification
    passes; an action with no row; a forged chain head accepted.
  - `exec`, `http_request` or an MCP server reaching a host its grant or
    signed entry does not list.
  - A webhook accepted without a valid platform signature or JWT.
  - An escape hatch that engages without being set, or without its
    documented warning and audit row.
  - Undefined behaviour in an `unsafe` block reachable from untrusted input.
    Critical if it reaches code execution.
- **Medium**
  - A gateway crash, hang or unbounded allocation from a chat message, a
    frame an adapter forwards as written, a tool result, an MCP response or an
    imported archive. The gateway hosts every agent and routes every
    channel.
  - An adapter that a hostile input keeps down past its restart loop.
  - An audit row that misattributes its actor, channel, agent or key id, or a
    refusal that is not recorded.
  - Escape sequences reaching the terminal past the strip; a forged field or
    record in a SIEM payload; webchat driven cross-origin.
  - Another OS user reaching a gateway socket.
- **Low**
  - An adapter or MCP proxy crash that its restart loop recovers from.
  - Disclosure of non-secret metadata (paths, ids) in errors.
  - Hardening with no demonstrated path.
  - A fail-closed defect: a control that refuses, errors or denies something
    it should allow. That is a correctness bug, not a vulnerability; label it
    so.

A finding whose chain has a Tier B step is rated as if that step holds and
labelled Tier B.

## Dedup by mechanism

- One report per defective mechanism: the function, check or missing check
  that is wrong. Every entry point and call site that reaches it goes in that
  one report.
- Two different defects with the same impact are two reports.
- A composition, where each step does what it is written to do and the steps
  together break a property, is one report that names every step.
- A report that shows a documented claim is false cites the doc line it
  falsifies. Two reports that falsify the same claim through the same
  mechanism are one.
- Check `tests/hostile/corpus.jsonl` and the crate's tests first. An expected
  outcome there records intended behaviour; a report that it is wrong is filed
  against that line.

## Report format

- **Title:** the impact in one line, the severity, and the Tier.
- **Commit:** the hash scanned. Line numbers are against it.
- **Mechanism:** the defective symbol at `path/to/file.rs:line`, relative to
  the repository root.
- **Path:** numbered steps from the untrusted input to the effect, each as
  `path/to/file.rs:line` with its symbol, each tagged `[A]` or `[B]`:
  - **Tier A:** read at the cited line and traced onto the default or
    production path.
  - **Tier B:** inferred; test-only; config or docs only; behind a non-default
    profile, feature flag or escape hatch; inside a third-party crate; or not
    traced end to end.
  The finding's tier is its weakest step.
- **Preconditions:** what the attacker controls, and every setting that is
  not the default.
- **Proof:** the failing test, the command that runs it, and its output on the
  scanned commit.
- **Patch:** as below.

## Proof: a failing test

- A Rust test that fails on the scanned commit and passes with the patch. It
  goes where the crate keeps its tests: the module's `#[cfg(test)]` block or
  `src/tests.rs` for unit tests, `crates/<crate>/tests/` for end-to-end
  tests. For a classification defect, a line in `tests/hostile/corpus.jsonl`
  with the correct `expect` is the test.
- It runs offline, in the image `docker/audit.Dockerfile` builds, with
  `cargo test -p <crate> <name>`. Servers bind `127.0.0.1:0`. A test that
  needs Docker or gVisor uses the existing `skipping:` guard, the report says
  it did not run there, and that step is Tier B.
- It asserts the property: the call is refused, the row is on the chain, the
  bytes do not appear. Not an implementation detail. A check on the text of a
  `.rs` file is a lint (`scripts/source_lints.py`), not a test.

## Patches: one concern each

- A patch fixes one mechanism and carries its test. No refactors, renames,
  reformatting of untouched code, or dependency bumps unless the dependency is
  the concern.
- The fix fails closed: an error path denies; no fallback that allows.
- It passes `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`
  and `cargo test --workspace`. Every `unsafe` block keeps its `SAFETY:`
  comment.
- It never relaxes an existing assertion, hostile-corpus line or fuzz
  expectation to pass.
- If it changes documented behaviour, it updates the sentence in `docs/` that
  described it, in the same patch.
- A unified diff against the scanned commit.
