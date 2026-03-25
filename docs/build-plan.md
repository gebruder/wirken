# Build Plan

## Hard Engineering Problems

### 1. Cross-Platform Keychain FFI

The entire security model rests on the encrypted vault, and the vault's master key lives in the OS keychain.

**Hard part:** Three completely different APIs:
- macOS: `security-framework` 3.7 wraps Security.framework. Well-maintained, stable bindings.
- Linux desktop: `secret-service` 5.1 talks to GNOME Keyring or KDE Wallet over D-Bus. Known issue: deadlocks if called on the tokio main thread (D-Bus + async runtime contention). Must be called from `tokio::task::spawn_blocking`.
- Linux headless (servers, containers, Raspberry Pi): No keychain at all. Fallback to an `age`-encrypted file with passphrase derived via `argon2` 0.5 (Argon2id).

**Approach:** A `Keychain` trait with three implementations behind a compile-time feature flag (`--features keychain-macos`, `--features keychain-linux`, `--features keychain-age`). The age fallback is always compiled in. At runtime, the gateway probes for a working keychain and falls back to age if it fails. The passphrase prompt happens exactly once per gateway start; the derived key is held in a `SecretString` in memory.

**Test matrix:** macOS Sonoma+ (Keychain), Ubuntu 24.04 (GNOME Keyring), Fedora (KDE Wallet), Ubuntu Server headless (age fallback), Raspberry Pi OS (age fallback). CI runs the age fallback path; keychain tests require platform-specific runners.

**Risk:** `secret-service` on KDE Wallet limits stored values to UTF-8. Binary keys must be base64-encoded before storage. Document and handle this in the KDE path.

### 2. Telegram Crate Maturity

Telegram is the MVP channel. `teloxide` 0.17 is the most complete Rust Telegram framework, but it is not as battle-tested as grammY or python-telegram-bot.

**Hard part:** `teloxide` covers Bot API v9.1, which includes long polling, webhooks, media groups, inline keyboards, reactions, and dialogue state machines. What's less proven: behavior under sustained load, reconnection edge cases, and coverage of newer Bot API features (message effects, business connections, paid media).

**Approach:** Build the Telegram adapter against `teloxide` 0.17. Use long polling for simplicity (no webhook URL management). Write integration tests against the Telegram Bot API test environment. If `teloxide` has a gap in a specific API method, call the raw Telegram HTTP API via `reqwest` for that method — `teloxide` exposes the underlying `Bot` client for raw requests.

**Risk:** `teloxide` is maintained by a small team. If it falls behind the Telegram Bot API, the escape hatch is direct HTTP calls. The adapter abstraction isolates this — the gateway never sees Telegram-specific types.

### 3. No Rust Slack SDK (Almost)

`slack-morphism` 2.19 exists and covers the Slack Web API, Events API, Socket Mode, and Block Kit. It is actively maintained but has a fraction of the downloads of `@slack/bolt`.

**Hard part:** Socket Mode (persistent WebSocket for receiving events without a public webhook URL) is the preferred connection method for single-workspace bots. `slack-morphism` supports it, but the implementation is less battle-tested than Bolt's. Event signature verification, reconnection handling, and multi-connection support need validation.

**Approach:** Build the Slack adapter against `slack-morphism` 2.19 for Socket Mode. Write integration tests against a Slack test workspace. If Socket Mode has reliability issues, fall back to HTTP Events API (requires a public URL, handled via the existing webhook infrastructure).

**Risk:** If `slack-morphism` has a critical bug, the fallback is raw REST via `reqwest` + manual OAuth token management + manual WebSocket handling for Socket Mode. This is more work but the Slack Web API is well-documented JSON-over-HTTP — no binary protocol to reverse-engineer.

### 4. Async Runtime Choice and Coloring

The entire gateway is async on `tokio` 1.50. This is the right call — IPC, HTTP, SQLite (via `spawn_blocking`), and process management are all IO-bound. But "function coloring" (async vs. sync) creates friction.

**Hard part:** `rusqlite` is synchronous. Every database call (audit writes, vault reads, session loads, permission checks) must go through `tokio::task::spawn_blocking`. This is correct but verbose. The `secret-service` crate has the same issue (sync D-Bus calls). Wasmtime's fuel metering is synchronous (the Wasm execution blocks a thread).

**Approach:** Three separate thread pools, not one shared `spawn_blocking`:

1. **DB pool (4 threads):** All `rusqlite` operations — audit writes, vault reads, session loads, permission checks. 4 threads because: audit flush is the hot path (batched writes every 50ms), vault reads are infrequent (startup + credential rotation), session/permission reads are per-message but fast (<1ms each). Under burst tool execution (30 shell commands), the audit queue absorbs the spike and drains across 4 writer threads without blocking the message path. Tested scenario: 100 audit events queued in 50ms, flushed in one batch transaction, <5ms wall time.

2. **Keychain pool (1 thread):** All `secret-service` D-Bus calls and `security-framework` Keychain calls. Exactly 1 thread because: keychain access is rare (gateway startup, credential rotation, new channel setup) and `secret-service`'s zbus D-Bus client creates its own internal event loop that conflicts with multiple concurrent callers. This thread is never contended with audit writes — that's the point of separating it. The `secret-service` + tokio deadlock happens when D-Bus calls run on tokio's cooperative thread pool; a dedicated thread with its own blocking runtime eliminates this entirely.

3. **Skill pool (2 threads, expandable to CPU count):** Wasmtime execution. CPU-bound, not IO-bound. 2 threads default because most users run 1 skill at a time; auto-scales to `num_cpus` if concurrent skill invocations are detected. gVisor skill execution does not use this pool — container lifecycle is managed via async `bollard` calls on the tokio runtime.

These are `std::thread` pools managed by a `BlockingDispatcher` that wraps `tokio::sync::oneshot` for result delivery. Not configurable at runtime — the sizes are chosen for the workload profile described above. If profiling shows a bottleneck, the fix is to change the hardcoded constant and release, not to expose a tuning knob that users will misconfigure.

**Risk:** The DB pool and keychain pool are separate but share the same process memory. Under extreme audit load + simultaneous credential rotation, total thread count peaks at 4+1+2=7 blocking threads. On a Raspberry Pi with 1GB RAM, this is noticeable (~7MB stack per thread = ~50MB). Acceptable — this is the minimum viable isolation.

### 5. Skill Compatibility and Migration

The skill story is simpler than it first appears, but the details matter.

**Hard part:** Understanding what OpenClaw skills actually are. They are not code. All 52 bundled skills are `SKILL.md` files — structured markdown with YAML frontmatter that the LLM reads as system prompt context. The agent interprets the instructions at runtime using built-in tools (exec, web search, file read/write). Zero compilation. Zero sandboxing. The `weather` skill is a markdown file that says "use `curl wttr.in/{city}`." The `github` skill says "use the `gh` CLI."

This means the majority migration path is: **copy the skill directory into Wirken's skill folder.** If Wirken's agent runtime reads `SKILL.md` files and injects them into the system prompt — matching OpenClaw's frontmatter contract (`name`, `description`, `requires.bins`) — then most OpenClaw skills work on day one.

The engineering work is:
1. **SKILL.md loader.** Parse YAML frontmatter (`serde_yaml` 0.9), extract skill metadata, validate `requires.bins` (check PATH for required binaries), inject markdown body into agent system prompt. This is straightforward — the format is documented and simple.
2. **Binary dependency checking.** Skills declare required binaries (e.g., `curl`, `gh`, `tmux`). Wirken checks PATH at skill load time and warns if missing. On macOS, suggest Homebrew install commands. On Linux, suggest apt/dnf.
3. **ClawHub compatibility.** ClawHub skills follow the same format. `wirken skills install <name>` downloads the skill directory from ClawHub's registry API. No compilation step.

**The minority case: code skills.** A small number of ClawHub skills are actual JavaScript that runs as a custom tool. These need the gVisor container path (Node.js in a sandbox) or the Wasmtime path (if rewritten). This is a real migration cost for users of those specific skills, but it affects the long tail, not the common case.

**Approach:**
1. Ship the SKILL.md loader in the MVP. Test against all 52 bundled OpenClaw skills.
2. Test the top 50 ClawHub skills and publish a compatibility table before launch: "works (markdown)", "works in container mode (code)", or "needs changes (uses unsupported features)."
3. Container runtime (gVisor/Docker) for code skills ships in the MVP but is not the primary migration path — it's the escape hatch for the minority of skills that are actual code.
4. Wasm skill SDK (`wirken-skill-sdk` crate + `wirken skill new` scaffolding) ships post-MVP for new skill development.

**Risk:** Frontmatter format divergence. If OpenClaw changes their SKILL.md format, the loader breaks for new skills. Pin to the current format and document the contract. OpenClaw's format has been stable — it's YAML + markdown, not a moving target.

### 6. Cross-Compilation and Distribution

Wirken ships as a single static binary. Users download it and run it. No runtime, no package manager, no dependencies.

**Hard part:** Cross-compiling Rust for four targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`. The `bundled` feature of `rusqlite` compiles SQLite from C source via the `cc` crate, which requires a C cross-compiler for each target. `security-framework` links against macOS system frameworks — it only compiles on macOS.

**Approach:** CI builds on GitHub Actions. Linux targets built in Docker with `musl-cross-make` toolchains. macOS targets built on macOS runners. The binary is fully static on Linux (musl) and dynamically links only system frameworks on macOS (Security.framework, CoreFoundation — always present). Feature flags select the keychain backend at compile time: Linux builds include `keychain-linux` + `keychain-age`, macOS builds include `keychain-macos` + `keychain-age`.

**Binary size target:** <30MB stripped (Rust + SQLite + TLS + Wasmtime). Wasmtime is the largest contributor (~15MB). Acceptable for a self-contained runtime. `cargo build --release` with LTO and `opt-level = "z"` if size is an issue.

**Risk:** Compile times. A full release build with LTO takes 10-15 minutes. Incremental debug builds are fast (~30s for a single crate change). CI parallelism across 4 targets mitigates this.

### 7. Audit Log Performance

Write-ahead logging on every action cannot block the message path.

**Hard part:** SQLite WAL mode handles concurrent reads well but writes are serialized. Burst tool execution (agent runs 30 commands in sequence) must not create a write bottleneck. All SQLite access goes through `spawn_blocking`.

**Approach:** Audit writes go through a `tokio::sync::mpsc` channel (bounded, 4096 capacity). A dedicated blocking task reads batches from the channel and flushes to SQLite in a transaction (every 50ms or 100 events, whichever comes first). Events held in memory with monotonic sequence numbers. Crash recovery: un-flushed events are lost. Hash chain computed at flush time over the batch.

**Risk:** Losing ~50ms of audit events on crash. For a personal assistant, this is acceptable.

---

## Dependency Chain

```
Vault crate (keychain FFI, encryption, SecretString types)
    |
    ├── compiles and tests independently, no gateway dependency
    |
IPC protocol (Cap'n Proto schema, message types)
    |
    ├── compiles independently, shared by gateway and adapters
    |
Gateway core (routing, sessions, LLM proxy, audit, permissions)
    |
    ├── depends on: vault, IPC protocol
    ├── audit log and rate limiter are internal modules, not separate crates
    |
Adapter trait + Telegram adapter
    |
    ├── depends on: IPC protocol, vault (for credential decryption)
    ├── does NOT depend on gateway core (adapters are separate binaries)
    |
Agent runtime (tool execution, LLM streaming, session management)
    |
    ├── depends on: gateway core, IPC protocol
    |
Skill sandbox (Wasmtime integration, gVisor/bollard integration)
    |
    ├── depends on: gateway core (for permission checks, audit)
    ├── can be stubbed for MVP (skills disabled) without blocking other work
    |
CLI + onboarding (dialoguer wizard, service installation)
    |
    ├── depends on: vault, gateway core (for config validation)
    ├── last in chain — requires everything else to work
    |
WebChat UI (embedded HTTP server for browser-based testing)
    |
    ├── depends on: gateway core
    ├── parallel track — not on critical path
```

**Critical path:** Vault → IPC schema → Gateway core → Telegram adapter → Agent runtime → CLI/onboarding.

**Parallel tracks:** Audit log (internal to gateway core), skill sandbox (can ship MVP with skills disabled), WebChat UI.

**What compiles first:** The vault crate and IPC schema crate have zero internal dependencies. They compile and test before anything else. This is by design — they are the foundation of the security model and should be reviewed and tested in isolation before the gateway consumes them.

**What blocks what:** The Telegram adapter cannot be tested end-to-end until the gateway core routes messages. The agent runtime cannot be tested until the LLM proxy streams responses. The CLI cannot be tested until the vault encrypts credentials. But each crate compiles and unit-tests independently — integration testing is what requires the chain.

---

## MVP Definition

**Ships with:**
- 1 channel: Telegram (official Bot API via `teloxide` 0.17)
- 1 agent with workspace
- Encrypted credential vault (OS keychain + age fallback)
- Adapter process isolation (even with 1 channel — the architecture is in place)
- LLM proxy with OpenAI + Ollama support (SSE streaming via `reqwest-eventsource`)
- Built-in tools: shell exec (with approval), file read/write/edit, web search
- Audit log (all actions, hash-chained)
- Skill loading via SKILL.md (markdown skills — the majority of the OpenClaw ecosystem, zero compilation)
- Session management with 24h expiry
- Rate limiting (no loopback exemption)
- `wirken setup` onboarding (curl + one command)
- systemd/launchd service installation
- WebChat UI for testing without a channel
- Single static binary per platform (4 targets)

**Does not ship with:**
- Discord, Slack, Matrix (next after MVP)
- Multi-agent routing (next after MVP)
- Voice/TTS (later)
- Canvas (later)
- Mobile companion apps (later)
- Skill marketplace/registry (later)
- WhatsApp (never, unless Meta ships a personal bot API)

**What's harder in Rust vs. TypeScript:**
- Telegram adapter: `teloxide` is less battle-tested than grammY. More manual error handling. Webhook setup requires more boilerplate.
- Slack adapter: `slack-morphism` is less mature than `@slack/bolt`. Socket Mode implementation is thinner.
- Skill migration: Markdown skills (the majority) work by copying the directory — zero friction. Code skills (the minority, from ClawHub) need the gVisor container path, which requires Docker on the host. The compatibility table must be published before launch.
- Onboarding UX: `dialoguer` is capable but less polished than Node TUI libraries like `@clack/prompts`. No color theming, no animated spinners (use `indicatif` 0.17 for progress bars).
- Dev iteration speed: Compile times are slower than TypeScript hot-reload. Use `cargo watch` + incremental builds. Full release builds are CI-only.

**What's easier in Rust:**
- Credential safety: `SecretString` + `Zeroize` make accidental secret exposure a compile error. In TypeScript this is a runtime convention that every developer must remember.
- Process isolation: Separate binaries from a single Cargo workspace. No subprocess API quirks (Bun vs. Node). Crash recovery is straightforward — process exits, gateway detects EOF.
- Binary distribution: One static binary, no npm, no node_modules, no runtime version management. `curl | sh` and done.
- Memory footprint: 3-8MB per adapter process vs. 20-50MB for a Node.js process. Meaningful on Raspberry Pi and low-memory VPS.
- Audit log integrity: Hash chain computation with `sha2` is trivial and constant-time. No surprise GC pauses during batch flush.
- Concurrency correctness: Rust's ownership model prevents data races at compile time. No "forgot to await" bugs, no shared mutable state surprises.

---

## Sequencing After MVP

**v1.1 — Channel expansion:**
- Discord adapter (`serenity` 0.12)
- Slack adapter (`slack-morphism` 2.19)
- Multi-agent routing (bind channels to agents)
- Follows MVP because: adapters are the same architecture (new binary, same IPC contract, same Cap'n Proto schema). Each adapter is an independent crate in the workspace.

**v1.2 — Ecosystem:**
- Matrix adapter (E2EE via `matrix-sdk` + `vodozemac` for Olm/Megolm)
- Skill registry with Ed25519 signing + ClawHub integration
- `wirken skills search` / `wirken skills install` (downloads skill directories from ClawHub)
- gVisor container runtime for code skills (the minority that are actual JS/TS)
- Wasm skill SDK (`wirken-skill-sdk` crate + `wirken skill new` scaffolding)
- Follows v1.1 because: skill ecosystem requires a working multi-channel product to attract skill authors. The MVP ships with markdown skill loading only; code skill sandboxing and the Wasm SDK come here.

**v1.3 — Platform expansion:**
- BlueBubbles/iMessage adapter (REST client, no special crate needed)
- MS Teams adapter (Bot Framework REST API via `reqwest`)
- Voice input/output (Whisper API + ElevenLabs API, both HTTP)
- macOS menu bar companion (Swift app, communicates with gateway over UDS)
- Follows v1.2 because: these are niche channels and features that matter for retention, not acquisition.

**v2.0 — Full platform:**
- iOS/Android companion apps
- Canvas (agent visual workspace)
- MCP server support
- Cron/scheduling system
- Follows v1.3 because: mobile and visual features require a stable, multi-channel foundation.

---

## First User

**Profile:** A developer or sysadmin who currently runs OpenClaw on a personal server or Mac, uses it primarily through Telegram or Discord, and has read at least one of the GHSAs with discomfort.

**Why they switch:**
1. They already know what a multi-channel AI gateway does. No education needed.
2. OpenClaw's security track record makes them nervous. 29 GHSAs in three months is a pattern, not an anomaly. The architecture doesn't prevent new classes of vulnerability — it patches them one at a time.
3. `curl | sh && wirken setup` is simpler than OpenClaw's install. No npm, no Node version management. One binary.
4. The audit log gives them something OpenClaw never did: the ability to see what their AI actually did on their machine.
5. The binary is 30MB, not 300MB of node_modules. It starts in milliseconds, not seconds.

**Why they stay:**
- Their Telegram bot works identically.
- They copy their OpenClaw skill directories into `~/.wirken/skills/` and they work. All 52 bundled skills are markdown — the agent reads the same SKILL.md instructions and uses the same built-in tools. Zero compilation, zero rewriting.
- They sleep better knowing a compromised Telegram bot can't read their Slack messages or exec on their host.

**Acquisition channel:** GitHub README with a "Migrating from OpenClaw" section. Post in OpenClaw's Discord. HN launch post emphasizing the security architecture and the single-binary distribution model — both are catnip for the HN audience.

---

## What Could Kill This

1. **OpenClaw fixes its security architecture.** Possible but unlikely given the pace of feature development vs. security debt. Their 29 GHSAs are symptoms of architectural decisions (single-process, trusted-operator model) that can't be patched incrementally.

2. **WhatsApp launches a personal bot API.** Would change the connector calculus entirely. Monitor Meta's developer announcements. If it happens, be the first secure gateway to support it. Adding a new adapter is a single crate in the Cargo workspace — the architecture is designed for this.

3. **Nobody cares about security in personal AI assistants.** The 328K stars say people want the product. The GHSAs say the informed minority cares about the risk. The bet is that the informed minority is the early adopter, and their word-of-mouth drives the rest.

4. **SKILL.md format compatibility breaks.** The majority migration path depends on Wirken's SKILL.md loader matching OpenClaw's frontmatter contract exactly. If there are undocumented frontmatter fields, conditional skill activation rules, or ClawHub-specific extensions that Wirken doesn't handle, skills silently fail to load or behave differently. Mitigate by testing all 52 bundled skills + the top 50 ClawHub skills and publishing a compatibility table before launch. Every frontmatter field that exists in the wild must be documented as "supported", "ignored", or "incompatible."

5. **Compile times slow iteration to a crawl.** A full `cargo build` of the workspace with Wasmtime takes minutes. Incremental builds are fast (~30s) but full rebuilds (CI, new contributor, clean checkout) are painful. Mitigate with: aggressive crate splitting (vault, IPC, gateway, adapters as separate crates), `cargo-chef` for Docker layer caching in CI, and `mold` linker on Linux for 2-3x faster linking.

6. **Rust scares away contributors.** OpenClaw has hundreds of contributors because TypeScript is widely known. Rust has a smaller pool. The first user is a developer who already knows Rust (or wants to learn it). The bet is that the security audience and the Rust audience overlap significantly. If they don't, the project stays small. That's acceptable for a security-focused tool — better a small correct product than a large vulnerable one.

7. **Channel SDK ecosystem gaps.** `teloxide`, `serenity`, and `slack-morphism` are maintained by small teams. If any of them falls behind its platform's API, the adapter needs to fill the gap with raw HTTP calls. The adapter abstraction isolates this — the gateway never touches channel-specific types. But it means the Wirken team carries more maintenance burden per channel than OpenClaw, which leans on the massive npm ecosystem.
