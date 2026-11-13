# Threat model

This is Wirken's threat model. It is also the input to automated security
scans, which work offline in the image `docker/audit.Dockerfile` builds, and
to `wirken lyrik run`, which loads it from this path when it is committed and
unmodified and holds every candidate against it
([lyrik-brocards.md](lyrik-brocards.md#the-targets-threat-model)).

## What wirken is

Wirken is a local agent gateway written in Rust. One `wirken` binary runs the
gateway, which hosts the agents in its own process, and is started again as
each chat channel's adapter process and as the MCP proxy. Agents call LLM
providers over HTTPS and act through tools. A permission gate decides every
tool call before it runs, `exec` runs in a container, and every tool call is
written to a per-session hash chain in SQLite before it executes, its outcome
after.

The design is in [architecture.md](architecture.md), the compile-time and
runtime controls in [enforcement-model.md](enforcement-model.md), and the
control-by-control mapping in [security-properties.md](security-properties.md).
Those pages name the symbol behind each control
and state each control's known gap. Read them before reporting: a finding that
restates a documented gap is not a finding.

The floor under everything below: a process running as the wirken OS user is
outside the model. That includes code running inside an adapter, the MCP
proxy or a hook process, which all run as that user.

## Assets

What the controls protect, in the order a loss matters:

- **The operator's host and the wirken OS user's principal.** Every process
  wirken starts runs as that user; code running as it is the end of the model.
- **Vault contents and the passphrase or device key that opens them:** channel
  tokens, model-provider credentials, MCP credentials, signing seeds. Only the
  gateway opens the vault; each adapter receives its own channel's credentials
  on stdin and the MCP proxy only the credentials its configs reference,
  without refresh tokens.
- **The permission decision.** The tier a call is classified at, the stored
  Tier 2 grants in `permissions.db`, the approver allowlist, and the prompt
  the operator answers. A call that runs without the gate deciding it, or with
  a decision for a different call, is the loss.
- **The audit chain and its signing key.** `audit.db` rows, per-session hash
  chains and signed heads. A request row before each action, an outcome row
  after it, and verification that fails on an edit.
- **Signing anchors:** the skill registry root, the org-config anchor, and the
  keys MCP entries are signed with. An artifact the anchor did not sign,
  accepted, is the loss.
- **Channel isolation.** A session's messages, memory entries, approvals and
  credentials stay in their channel unless a Tier 3 prompt crosses them.
- **The workspace.** The one mount `exec` gets; the operator's files in it are
  what a command can change.
- **The local sockets** under `<data_dir>/sockets`, each mode 0600 behind a
  signed handshake.

## Trust boundaries and adversarial inputs

1. **Chat platforms to adapters.** Message text, sender ids, attachments and
   platform events from Telegram, Discord, Slack, Teams, Matrix, WhatsApp,
   Signal, iMessage and Google Chat are attacker-controlled. Webhook adapters
   listen on 127.0.0.1 behind the operator's ingress. Teams and Google Chat
   webhooks are authenticated by RS256 JWT verification
   (`crates/adapter-teams/src/auth.rs`, `crates/adapter-google-chat/src/auth.rs`),
   WhatsApp by an HMAC-SHA256 signature (`verify_signature`,
   `crates/adapter-whatsapp/src/adapter.rs`). iMessage (BlueBubbles) webhooks
   carry no authentication of their own, so the adapter registers its webhook
   URL with a per-install secret, derived from the BlueBubbles password, and
   refuses a POST without it (`webhook_access`,
   `crates/adapter-imessage/src/adapter.rs`); the listener also binds to
   loopback only ([channels.md](channels.md)). Parsing before authentication, verification bypass,
   and one sender acting as another are in scope.

2. **Adapter to gateway.** A Unix socket carrying Cap'n Proto frames after a
   peer-credential check and an Ed25519 challenge-response over
   `(domain || adapter_id || nonce)` (`perform_gateway_handshake`,
   `crates/ipc/src/auth.rs`). `FrameReader` bounds a frame at 16 MB, traversal
   at 64M words and nesting at 64 levels (`crates/ipc/src/transport.rs`). After
   the handshake the gateway pins the adapter's channel and rejects a frame
   declaring another (`adapter.channel_mismatch`, `message_loop`,
   `crates/cli/src/commands/run.rs`). A message frame then passes the inbound
   sender allowlist (`InboundGate::check`,
   `crates/gateway/src/sender_registry.rs`): unless its sender or its
   conversation is an entry for the channel, it is dropped before the scan,
   the inbound row, the session and the route, and an `inbound_sender_refused`
   row is written, rate-limited per sender and per lane. Approval decisions arriving as frames are
   checked against the gateway-side approver allowlist keyed by
   `(adapter_id, user_id)` (`crates/gateway/src/approver_registry.rs`), then
   against the request: it must have been raised on the adapter's channel,
   and the decision must come from the conversation its prompt was posted in
   (`adapter_decision_misplaced`, `crates/cli/src/commands/run.rs`); otherwise
   a `permission_approval_refused` row with `wrong_channel` or
   `wrong_conversation` is written and the request stays open. In
   scope: platform-controlled bytes, forwarded by an adapter working as
   written, that make the gateway misroute a message, cross a channel, admit a
   sender the sender allowlist does not list, resolve an approval for someone
   not on the approver allowlist, crash or allocate without bound.

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
   egress grant routes it through the egress proxy (`crates/sandbox/src/`) or
   `sandbox.json` sets `"network": true` ([Boundaries](#shell)). The
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
   An `mcp.json` entry may carry an Ed25519 signature over a canonical hash
   (`mcp_signing.rs`); the released build has no anchor, so an unsigned entry
   loads ([Boundaries](#mcp-servers)). Each stdio server runs in its own
   container with no network unless its entry lists hosts (`container.rs`,
   `egress.rs`).
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
   signature plus freshness), and MCP entries in a build with an MCP anchor.
   Every Ed25519 check uses
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

10. **Webchat.** Served on 127.0.0.1. Every `/api` route takes a login cookie
    or the per-start session token as a bearer, compared in constant time
    (`crates/cli/src/commands/webchat_auth.rs`), on top of the `Host` check and
    an `Origin` check on state-changing routes
    (`crates/cli/src/commands/webchat.rs`). The session token is in
    `webchat.json` at mode 0600; a login token is single-use and expires
    after 60 seconds. In scope: a page in the operator's browser driving the
    agent cross-origin, and a local process of another user reaching any
    `/api` route without the cookie or token.

11. **Vault.** XChaCha20-Poly1305 with an Argon2id-derived or keychain device
    key (`crates/vault`). No process the gateway starts opens it or holds
    the passphrase; adapters get their own channel's credentials on stdin
    (`crates/cli/src/commands/adapter_handoff.rs`). `VaultSecret`
    (`crates/vault/src/secret.rs`) implements none of `Display`, `Debug`,
    `Clone`, `Serialize`. In scope: recovering a secret from a copy of
    `vault.db` without the passphrase or device key, AEAD or KDF misuse, and a
    secret reaching a log, an error message, a URL, an audit row, a SIEM
    payload, the model's context, another channel's adapter or a child's
    environment. Each entry's destinations are sealed into its encryption
    and checked before every handoff (`crates/vault/src/binding.rs`); in
    scope: a value handed to a destination its binding does not allow, and a
    binding changed without the vault key.

12. **Audit chain.** `SessionLog::append` and `verify`
    (`crates/audit/src/session_log.rs`), head signing
    (`crates/audit/src/signing.rs`), `wirken audit verify` and
    `wirken sessions verify` (`crates/cli/src/commands/audit.rs`,
    `session.rs`). Treat `audit.db` as edited by an attacker before a verifier
    reads it offline. In scope: an edit, deletion or reorder that
    verification passes, a head signature accepted from a key it should not
    accept, and a row that misattributes its actor, channel, agent or key id.
    Truncation from the end of a session is not detected: the rows that
    remain still verify, signed heads included. A forwarded row the chain no
    longer holds shows the cut in the SIEM forwarder's copy.
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
    egress hooks fail closed on timeout and while a registered hook is not
    connected (`crates/gateway/src/hook_dispatcher.rs`,
    `egress_dispatcher.rs`). In scope: another OS user reaching a socket, a
    hook timeout passing a call without `WIRKEN_ALLOW_UNREGISTERED_HOOKS=1`, a
    call passing while a registered hook is not connected, and a veto `Deny`
    that does not stop dispatch.

## Access controls

Who holds what, so a precondition can be compared with an impact:

- **The operator** is the OS user. They hold the vault passphrase, write the
  configuration files in the data dir, answer approval prompts on the CLI, and
  may name approvers for Telegram, Signal and Discord, keyed by
  `(adapter_id, user_id)` in the approver registry. A decision from anyone not on that allowlist is
  dropped. The operator is the approver: an operator approving a prompt that
  described the call accurately is not a finding.
- **Another OS user** holds nothing. The sockets are mode 0600 and every
  connection takes a signed handshake.
- **A chat user** reaches the agent only when the sender allowlist admits
  them, by their own platform id or by a group entry for the conversation they
  write in; anyone else's messages are dropped at the gateway before they
  reach a session. An admitted chat user can send messages and attachments on
  their channel. They hold no permission authority. A stored grant is keyed
  on `(action_key, agent_id, channel)`, not on the sender
  ([Boundaries](#senders-and-approvals)). Approvals on
  Slack, Teams, WhatsApp, Google Chat, Matrix and iMessage sessions
  prompt on the operator's CLI, not in the channel.
- **The model** holds nothing. Every tool call is classified and gated: Tier 1
  runs, Tier 2 prompts once and may be stored for thirty days under a Tier 2
  key only, Tier 3 prompts every time and is never stored. A sub-agent runs
  under its own agent id with a clamped tier, an intersected tool allowlist,
  and none of the parent's grants.
- **An adapter** holds its own channel's credentials and is pinned to its
  channel after the handshake.
- **The MCP proxy** holds the credentials its configs reference, no refresh
  tokens, and a per-spawn token the refresh service checks before answering.
- **A command under `exec`** holds a container with every capability dropped,
  `no-new-privileges`, a read-only root, a non-root user, the workspace as its
  only mount, and no network unless the channel's egress grant routes it
  through the egress proxy or `sandbox.json` sets `"network": true`.
- **A skill** holds what its signed permission block grants: tools, egress
  allow-set, read and write paths. A bundle the anchor did not sign does not
  load.

## Boundaries

What each control leaves outside it, stated once. Other pages link here.

### The operating-system user

- A process running as the Wirken OS user is outside every control below. It
  can read the vault key file, the audit signing key and the operator key,
  and rewrite any file in the data directory. Adapters, the MCP proxy and
  hook processes run as that user.
- Wirken ships no AppArmor or SELinux policy. Container isolation is that of
  the container runtime.

### Processes

- Agents, sub-agents, WebChat and the terminal channel run in the gateway
  process and share its address space, the vault, the audit writer, the
  permission store and the MCP proxy.
- Channel adapters and the MCP proxy are separate processes. They are not
  sandboxed. The gateway hands an adapter its own channel's credentials on
  stdin and no others.
- Channel separation is the process boundary, an Ed25519 handshake and a
  per-frame check of declared against authenticated channel. The typed
  `SessionHandle<Channel>` API is not on the production message path, and the
  `Channel` trait is not sealed.
- On Windows the named-pipe peer check is not called when a connection is
  accepted; the handshake is the only IPC check. Key files are written
  without ACL tightening.
- No authentication path is rate limited: `AuthRateLimiter` is not
  constructed outside tests.
- A heartbeat is echoed, not timed. An adapter that keeps its connection
  open and stops forwarding is not detected.

### Senders and approvals

- Wirken does not authenticate people. It admits the sender id the platform
  reports, from an allowlist per channel. A channel with no entries admits
  nobody. A group entry admits every member of that conversation.
- An approval answered at a prompt covers that one call.
- A grant recorded with `wirken permissions approve --session` ends with the
  session.
- A grant recorded with `wirken permissions approve --channel` is keyed by
  action, agent and channel. It covers every admitted sender on that agent
  and channel until it expires, 30 days by default, or is revoked.
- A shell grant is keyed by the command's first word and covers any
  arguments.
- Tier 2 is 23 inspection commands (`TIER2_ALLOWLIST`,
  `crates/gateway/src/permissions.rs`). A command containing `|`, `;`, `&`,
  `$(`, a backtick, `>`, `<` or a newline is Tier 3. Tier 3 prompts on every
  call and is never stored.
- Workspace file reads and writes, and the agent's own memory entries, are
  Tier 1 and do not prompt. The workspace is per agent and shared by all of
  the agent's channels and conversations.
- Telegram, Signal, Discord, WebChat and the terminal answer approvals in
  the channel. Approvals on Slack, Teams, WhatsApp, Google Chat, Matrix and
  iMessage are answered on the operator CLI. Discord approval cards are
  unit-tested and have not been run against Discord. The iMessage adapter
  has not been run against a BlueBubbles server.
- A call whose arguments exceed 2000 characters on the approval card is
  refused without asking.

### Model input

- Injection detection marks an inbound channel message and forwards the
  mark. It does not block the message, and it does not scan tool results.
- A tool result enters the conversation after a leak match. Nothing else
  validates it unless an egress hook is registered.
- Leak detection matches the exact bytes of a secret the vault holds, 8
  bytes or longer. An encoded form, a split value, a shorter secret and a
  secret the vault does not hold pass. The matcher has no operation that
  forgets a secret: each one it learns stays in memory, in a zeroizing
  buffer and in the search automaton built from it, until the matcher is
  dropped (`LeakMatcher`, `crates/gateway/src/leak.rs`).

### Shell

- Under `exec-only` the container shares the host kernel, with no
  capabilities, `no-new-privileges`, a read-only root, 512 MB, 256 PIDs and
  the shipped seccomp profile.
- Under `gvisor` the container runs under `runsc`. The seccomp profile is
  sent with the container and `runsc` does not apply it to the workload:
  `unshare -Ur` succeeds, and so does a tmpfs mount inside a new user and
  mount namespace. A mount outside a new user namespace is refused
  (`a_gvisor_exec_makes_a_user_namespace_and_mounts_in_it`,
  `crates/agent/src/tests.rs`, run in CI under the runsc release
  `.github/workflows/ci.yml` pins). Egress sidecars run under the daemon's
  default runtime in every mode.
- Under `off`, `exec` runs on the host as the Wirken user with no container.
  The command can read and rewrite every file in the data directory,
  including keys and policy files. A child that calls `setsid` outlives the
  call.
- `"network": true` in `sandbox.json`, with no channel egress policy, puts
  the `exec` container on Docker's default bridge with no allowlist.
- The workspace is mounted read-write. A command can change a workspace
  file between a host check and its use.
- The Podman path is not tested against Podman. Under an `allowlist` or
  `open` egress policy, `exec` is refused on Windows.

### Network

- Bounded by egress policy: sandboxed `exec` and contained stdio MCP
  servers.
- Not bounded by egress policy: the model-provider client, HTTP MCP servers,
  a stdio MCP server with `"sandbox": "off"`, and `exec` under `mode: off`.
  These connect from the gateway process, the proxy process or the host.
- A skill's `egress.domains` governs `http_request`, `web_search` and the
  Zirkel fetch. `http_request` reaches no host without it and refuses a host
  that resolves to no global address. `web_search` is not restricted without
  it. `generate_image` is Tier 3.
- The egress proxy decides on the CONNECT target and does not inspect the
  tunnel. It forwards HTTPS to port 443 and plain HTTP to port 80 only.
- MCP server egress does not depend on what the session has read.
- Plain `http://` is accepted only for a URL whose host is exactly
  `localhost`, `127.0.0.1` or `[::1]`, for an MCP endpoint, a Matrix
  homeserver, a SIEM endpoint and a model provider.

### MCP servers

- The released build has no MCP trust anchor
  (`crates/mcp-proxy/src/wirken-mcp-pubkey.pub` is empty). An unsigned
  `mcp.json` entry loads. A signed entry is checked against the key it
  carries.
- A signature covers the entry's configuration, not the binary at `command`
  or the contents of an image tag.
- A stdio server with `"sandbox": "off"` runs as a child of the proxy as the
  operator, with no container, seccomp profile or limit. Secrets in its
  `env` are plaintext in its environment. Secrets delivered to a contained
  server through `secrets_in_env` are readable by anyone with the Docker
  socket.

### Skills

- A skill is Markdown. It is not sandboxed; it is confined by its permission
  block and by the tools it drives. There is no runtime for compiled skills.

### Audit

- A request row is appended before the action. An outcome row is appended
  after it. If the outcome row of an `http_request` or a memory write fails
  to land, the call returns `ToolEffectUnrecorded`.
- The signing key is held by the process that writes the chain and is
  readable by any process of the same user. A holder can write and sign any
  sequence of rows.
- `wirken audit verify` without `--anchor` checks against a public key
  stored beside the chain. A same-user process can replace both.
- Removing the last rows of a session after its last signed head is not
  detected. Removing a whole session, `audit.db` or the data directory
  removes the evidence; an empty log verifies.
- `wirken sessions verify` does not check head signatures; `wirken audit
  verify` does. Verification re-executes `read_file` and `list_files` only,
  against the current workspace.
- The audit library can redact a row: it rewrites the payload and signs a
  head recording the superseded one. No `wirken` command performs it.
- A SIEM batch the endpoint answers with a non-success status is not
  delivered. The legacy forwarder drops it; the typed forwarder sends it
  again on its next pass. The typed forwarder's position is not persisted,
  so each gateway start sends every forwardable row again.
- With typed forwarding on, the default feed carries tool arguments, tool
  output and assistant text. `siem.json` holds its API key and HMAC secret
  in plaintext.
- The OpenTelemetry projector is library code and is not started by the
  `wirken` binary.

### Credentials and cost

- In the released build the vault key is a passphrase-wrapped file in the
  data directory. The OS keychain backends are build features no release
  enables.
- `rotation_due_at` is recorded and triggers nothing. The Teams adapter
  refreshes its token; the Google Chat adapter sends a static one.
- A budget is off until configured. It is checked before a call and charged
  after it, so the call in flight at a ceiling completes. A model missing
  from the pricing table is not charged against the USD ceiling; the
  model-time ceiling, where set, charges every call.
- Wirken has no attestation code of its own. For Tinfoil the gateway calls
  the Tinfoil SDK, which performs the attestation, and fails the model call
  when the SDK reports an attestation error (`tinfoil_client`,
  `crates/agent/src/llm.rs`). For Privatemode the gateway talks to the
  Privatemode proxy on localhost as an OpenAI-compatible endpoint and checks
  nothing about it (`LlmConfig::privatemode`).

### Organisation policy

- Organisation policy is fetched by `wirken setup --org` and once at each
  `wirken run` start, not while the gateway runs, and is written to files in
  the user's data directory. `provider.json`, `mcp.json`, `sandbox.json` and
  `tool_policy.json` written at a start are read later in that start;
  `siem.json` is read before the fetch, so it applies from the next start.
  When the fetch fails the gateway logs a warning, records
  `org-config.apply-failed` and starts on the files already there. When a
  write fails part-way, the sections written before it are the new ones and
  the rest are the old (`crates/cli/src/commands/run.rs`, the org-config
  block; `apply_org_config`, `crates/gateway/src/org.rs`).
- `allowed_tools` and `blocked_tools` do not apply to `spawn_subagent` or the
  phase tools.

### Updates and release signing

- `wirken update` refuses a manifest issued earlier than the newest one this
  install has verified. It accepts one with the same issue time and compares
  nothing against the clock, so a source that keeps serving the last manifest
  is not detected (`check_and_record_freshness`,
  `crates/cli/src/commands/update/manifest.rs`).
- Release binaries carry an offline Ed25519 signature over their checksums
  and SLSA provenance. They carry no Authenticode or Apple notarization
  signature.
- Signatures are Ed25519. No post-quantum algorithm is used.
- Only the latest release receives fixes.

### Lyrik and Zirkel

- Lyrik findings are model output. The citation gate checks that the cited
  file and line exist, not that the finding is correct.
- Only `--bench` on the command line skips the Lyrik sign-off. Nothing in
  the assessed repository does.
- A Lyrik run continues on an unsigned chain when the audit signing key
  cannot be loaded, with a warning.
- An approved `exec` in a Lyrik run mounts the target read-write. A change
  to the three team files is detected at the end of the run, not prevented.
- Zirkel's keyword file and kept set stay under `<data_dir>/zirkel/`, and
  `wirken zirkel run` scores with a model on this host. The digest, which
  carries each item's title, source, theme and the model's reason for
  surfacing it, is sent to the bound channel's platform. `/librarian`
  questions and answers travel over that channel and through the model
  provider of the agent that answers.

### Assurance

- No third party has assessed Wirken. No SBOM is produced. It holds no
  certification.

## Supported configurations

Severity is rated on the default configuration. What that is:

- **Platforms:** Linux (x86_64, aarch64), macOS (Intel, Apple Silicon) and
  Windows 11 (x86_64). On Windows the IPC is named pipes, the vault is an
  age-encrypted file, and `sandbox.json` `mode: off` is a documented default
  for the single-user profile ([windows.md](windows.md)); a finding that needs
  that mode is rated as off-default, Tier B. Service and scheduled modes are
  Linux and macOS only.
- **Sandbox:** `mode: exec-only` with the default image under Docker is the
  default; `gvisor` is supported; `off` is opt-in and out of scope while set.
  With no container runtime `exec` is refused.
- **Escape hatches unset.** Every `WIRKEN_ALLOW_*` variable,
  `WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN`, `WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES` and
  `WIRKEN_LIVE_RELOAD_INTERVAL_S` absent, and no `mcp.json` entry with `"sandbox": "off"`.
- **One gateway per data dir, one operator.** Many chat users reach it through
  channels; there are no roles and no per-user permissions
  ([enterprise.md](enterprise.md)). Webhook adapters listen on 127.0.0.1
  behind the operator's ingress; webchat is served on 127.0.0.1.
- **Signed artifacts verified:** skills against the registry root, the
  org-config bundle against its anchor, and a signed MCP entry against the
  key it carries.
- **Offline test image:** `docker/audit.Dockerfile`, where the proof runs.

A path that exists only under a non-default profile, feature flag or escape
hatch is a Tier B step and is reported as such.

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
  `tool_to_action` and `PermissionStore::check`. An `http_request` line that
  carries `permissions`, a skill block, and `gate`, `allowed` or
  `refused:<axis>`, is also replayed through the skill-profile gates behind
  the tier gate: `tools.allow`, the method and POST-endpoint rules, the
  credential allow-set and the egress allow-set. A line can also name a
  control behind the gate and the answer it has to give: `resolves_to` (the
  address check on `http_request`), `card` (an approval card shows the
  arguments as sent), `ask` (a call too long for the card is not asked),
  `container` (what an exec container is given), `egress_ask` (what an
  egress approval shows) and `seccomp_refuses` (syscalls the exec profile
  refuses). A new hostile shape is one JSON line with its expected outcome.
- `crates/cli/tests/` drives the built binary end to end: adapter credential
  hand-off, the MCP proxy holding no vault, audit verification of malformed
  signatures, session replay.
- `target/debug/wirken` is built. `WIRKEN_DATA_DIR` points it at a scratch
  data dir. No LLM provider and no chat platform is reachable.
- `fuzz/fuzz_targets/` names the parsers worth fuzzing: `exec_classifier`,
  `skill_frontmatter`, `injection_scan`, `ipc_frame_decode`. They need nightly
  and `cargo-fuzz`, which that image does not have; replay an input as a unit
  test instead.

## What is and is not a vulnerability

A vulnerability here is a property in "How you rate severity" broken, on the
default configuration, by an input from one of the trust boundaries above,
along a path traced to the cited lines, and shown by a failing test. The
property is the thing: the call was not refused, the row was not on the chain,
the bytes reached where they must not.

Not a vulnerability, whatever its shape:

- Anything in "Out of scope" below.
- A fail-closed defect: a control that refuses, errors or denies what it
  should allow. That is a correctness bug; label it so and rate it Low.
- A documented gap restated. The Gap columns in
  [security-properties.md](security-properties.md) and the "What this does
  not cover" notes in [enforcement-model.md](enforcement-model.md) are known.
  Showing a gap is wider than stated is a finding.
- Hardening with no demonstrated path.
- A finding whose attacker already holds the access the harm needs, or whose
  precondition is the wirken OS user.
- The content of a prompt injection. What the gate lets the injected request
  do is the finding, if anything is.

## Out of scope

- Anything that needs code execution as the wirken user, including inside an
  adapter, the MCP proxy or a hook process.
- The documented escape hatches while set: the `WIRKEN_ALLOW_*` variables,
  `WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN`, `WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES`,
  `WIRKEN_LIVE_RELOAD_INTERVAL_S`, `sandbox.json` `mode: off`, and an `mcp.json` entry with `"sandbox": "off"`
  (table in [security-properties.md](security-properties.md)). A hatch whose effect is wider than
  that table states, or that engages without being set, is in scope.
- Gaps the docs already state: the Gap columns in
  [security-properties.md](security-properties.md) and the "What this does not
  cover" notes in [enforcement-model.md](enforcement-model.md). Showing that a gap is wider than stated is in
  scope.
- Prompt injection that changes what the model asks for. Injection detection
  flags and does not block ([Boundaries](#model-input)). What the gate lets
  the request do is in scope.
- LLM token and cost exhaustion.
- Reading stored secrets out of the leak matcher's memory. Its search
  automaton keeps unzeroized copies of them for the life of the process, which
  already holds the decrypted values and the vault's device key.
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
  - A skill or org-config bundle the anchor did not sign, accepted with no
    bypass set; an MCP entry the anchor did not sign, accepted in a build
    that has an MCP anchor.
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
  - A message from a sender the sender allowlist does not admit reaching the
    injection scan, an inbound row, a session, the router or an agent.
  - A modified, deleted or reordered chain that verification passes; an
    action with no row; a forged chain head accepted.
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
  scanned commit. This is the evidence; the section below says what counts.
- **Patch:** as below.

## Evidence required for a valid report: a failing test

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
