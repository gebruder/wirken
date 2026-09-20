# Sandbox Properties

What Wirken's `exec` and Wasm sandboxes actually enforce. Every claim cites
the source line that implements it; every command in [Verification](#verification)
can be run on a Wirken host to confirm.

This document covers the runtime sandbox only. Process-level isolation between
adapters (one OS process per channel) and IPC boundary properties live in
[architecture.md](architecture.md). Permission tiers live in
[permissions-and-identity.md](permissions-and-identity.md).

## Modes

`SandboxMode` is the operator-facing knob. Three values, one default
([`crates/agent/src/sandbox.rs:29-49`](../crates/agent/src/sandbox.rs)):

| Mode | Default | Runtime | Meaning |
|---|---|---|---|
| `ExecOnly` | yes (since 0.7.5) | Docker `runc` | The `exec` tool runs in an ephemeral container with the hardening below. Other tools run on the host. |
| `GVisor` | no | Docker `runsc` | Same container hardening; the OCI runtime is gVisor. Every guest syscall is intercepted by gVisor's userspace kernel (`Sentry`) instead of reaching the host kernel directly. |
| `Off` | no | none | No sandboxing. Opt-in via `"mode":"off"` in `~/.wirken/sandbox.json`. The shell process runs as the agent's UID with the agent's privileges. |

Unknown mode strings fall back to `ExecOnly`, not `Off`: a config typo gets
the secure default with a warning, never the bypass
([`sandbox.rs:56-71`](../crates/agent/src/sandbox.rs)).

## No silent fallback

[`crates/agent/src/tool.rs:708-733`](../crates/agent/src/tool.rs):

```rust
if let Some(sandbox) = self.sandbox().await {
    let egress = self.sandbox_egress.read().ok().and_then(|g| g.clone());
    return sandbox
        .exec(&command, &self.workspace, egress.as_ref())
        .await;
}
if self.sandbox_config.mode != SandboxMode::Off {
    return Err(AgentError::Sandbox(format!(
        "sandbox mode is {:?} but the sandbox is unavailable; \
         refusing to fall back to host execution. ..."
    )));
}
```

If the configured sandbox runtime is missing (Docker not running; `runsc` not
registered), the `exec` tool refuses to run rather than running the command
on the host. Operators who want host execution must opt in by writing
`"mode":"off"` explicitly.

## Where a call ran is on the row

An `exec` result records where the command ran, written by the branch that
dispatched it rather than read back from configuration when the row is
emitted:

```json
"sandbox":{"mode":"exec_only","runtime":"docker","container_id":"4911033061e420d87fab47be210b0f8ad9f52e1c05540090c5bf42d2e5dd261f"}
```

`mode` is the configured mode of the sandbox that dispatched the call,
`runtime` is what actually ran it (`docker`, `gvisor` or `host`), and
`container_id` is the id Docker returned, absent on the host. Both output
paths format their output identically, so before this field an auditor
reading `audit.db` could not tell a containerised `exec` from a host one.

The two can disagree and the row says so when they do: `mode: exec_only`
with `runtime: host` is a sandbox that failed open, which is the case
worth being able to see afterwards. A call refused at the gate records no
`sandbox` at all, which is a different answer from `host`: nothing ran
anywhere. A call cut at the timeout still records where it ran.

## Container hardening (applies to ExecOnly and GVisor)

[`crates/agent/src/sandbox.rs:994-1045`](../crates/agent/src/sandbox.rs)
(`build_host_config`) constructs the `HostConfig` for every sandboxed exec.
The separate `HostConfig` at `sandbox.rs:671-685` belongs to the egress
sidecar container, not to the exec sandbox:

| Property | Value | Source line |
|---|---|---|
| `cap_drop` | `ALL` | `:1035` - every Linux capability stripped. No `CAP_NET_BIND_SERVICE`, `CAP_CHOWN`, `CAP_SYS_ADMIN`, etc. |
| `cap_add` | `[]` | `:1036` - no capabilities re-added. |
| `security_opt` | `no-new-privileges:true` | `:1037-1040` - `setuid`/`setgid` binaries cannot elevate. |
| `readonly_rootfs` | `true` | `:1041` - container `/` is read-only. |
| `tmpfs` | `/tmp` mounted at 64MB, mode `1777` | `:1018-1021, 1042` - the only writable filesystem outside `/workspace`. |
| `network_mode` | `none` (configurable) | `:1006-1013, 1025` - default is no network namespace; outbound DNS/HTTP fail. A channel configured for sandbox egress joins a policed internal network instead; see below. |
| `dns` | unset, or `127.0.0.1` on the egress path | `:1014-1017, 1026` - pinned to an address with no resolver behind it when an egress network is in use, so names are resolved by the proxy rather than in the container. |
| `binds` | `<workspace>:/workspace:rw` | `:1024` - only the agent workspace is mounted, RW. |
| `memory` | 512 MB | `:25, 1027` - `MEMORY_LIMIT` constant. |
| `pids_limit` | 256 | `:27, 1028` - `PIDS_LIMIT` constant; fork-bomb cap. |
| `user` | `1000:1000` | `:409` - non-root UID/GID inside the container. |
| `auto_remove` | `false` | `:1033` - explicit `kill_and_remove` after log collection so output is never lost to a teardown race. |
| timeout | 300 s | `:265, 457` - wall-clock cap; container is killed and removed on timeout. |

### Sandbox egress

`network_mode: none` is the default and applies whenever the channel serving
the turn has no egress policy. A channel configured for `allowlist` or `open`
joins a per-exec two-member internal network and reaches the outside only
through a sidecar proxy container. The topology, the isolation invariant, the
port and address rules, and the known CONNECT/SNI limit are in
[egress.md](egress.md#sandbox-egress). Everything else in the hardening table
above is unchanged on that path.

Two `sandbox.json` keys matter here:

```json
{
  "mode": "exec-only",
  "image": "curlimages/curl:latest",
  "sidecar_binary": "/usr/local/bin/wirken"
}
```

`sidecar_binary` absent defaults to the gateway's own executable, which is the
shipping shape: the sidecar runs the wirken binary itself, bind-mounted
read-only, and releases are statically linked. A dynamically linked
development build cannot run inside the sandbox image, so this key points at a
static one. A configured path that does not exist refuses the `exec` rather
than running it unproxied.

`image` absent or empty means the compiled-in default, and **the default
carries no HTTP client by decision**, so an `exec` on a channel granted
proxied egress reaches nothing from it. An operator who needs that path
exercised sets `image` to an image carrying a proxy-aware client, and that
opt-in key is the supported way to get one. The default stays without a client
because adding one widens the sandbox surface for every install, including
installs that never configure egress and rely on no interface and no client as
two independent walls. Putting the choice in `sandbox.json` puts it where the
consequence lands.

A key in `sandbox.json` that the loader does not read is named in a warning at
start and ignored. The loader never refuses a file over one, so a file written
for a newer build does not stop an older one from starting; the warning is
what says the setting did nothing.

`security_opt` does NOT explicitly set seccomp. Per Docker semantics
([upstream](https://docs.docker.com/engine/security/seccomp/)), when no
seccomp profile is named, the daemon applies its **default profile**. That
profile blocks ~44 syscalls including:

- Kernel-module loaders: `init_module`, `finit_module`, `delete_module`.
- Mount manipulation: `mount`, `umount`, `umount2`, `pivot_root`.
- Kernel keyring: `add_key`, `request_key`, `keyctl`.
- Kexec: `kexec_load`, `kexec_file_load`.
- Cross-process state: `ptrace` (when not in `cap_sys_ptrace`), `process_vm_readv`/`_writev`.
- Personality: `personality` non-zero.
- Clock and time setting: `clock_settime`, `clock_adjtime`, `settimeofday`,
  `stime`.
- BPF programs: `bpf` (when not in `cap_sys_admin`).
- Reboot: `reboot`.

The full list is the Docker daemon's responsibility, not Wirken's. Setting
`security_opt: ["seccomp=default"]` is rejected by the Docker API as an
invalid token; the absence of a seccomp `SecurityOpt` is what activates the
default profile ([`sandbox.rs:1037-1040`](../crates/agent/src/sandbox.rs)).

## gVisor delta (`SandboxMode::GVisor`)

When mode is `GVisor`, `runtime_name()` returns `Some("runsc")`
([`sandbox.rs:73-78`](../crates/agent/src/sandbox.rs)) and Docker
launches the container under gVisor instead of `runc`.

gVisor changes the threat model. Under `runc`, the guest's syscalls reach
the host kernel directly, filtered by Docker's seccomp profile. Under
gVisor, **every** guest syscall is trapped by `runsc` and serviced by the
Sentry, gVisor's userspace re-implementation of the Linux syscall surface
in Go. The host kernel sees only a small, fixed set of syscalls from
`runsc` itself.

Practical consequences:

- A guest exploit of a host-kernel CVE is not reachable; the host kernel
  receives a different (much smaller) syscall vocabulary.
- Some real workloads break. gVisor's compatibility table flags
  `prlimit`/`io_uring`/some `seccomp(2)` operations; binaries that depend
  on these fail at the boundary instead of escaping it.
- Performance penalty: gVisor's syscall trap is slower than a direct
  syscall. Acceptable for `exec` calls; you would not run a database
  inside it.

Wirken does not require gVisor; `ExecOnly` is the default. `GVisor` is the
opt-in for operators who want kernel attack surface reduction. Detection
([`sandbox.rs:1071-1083`](../crates/agent/src/sandbox.rs)) is automatic;
the wizard refuses to enable `GVisor` mode if `runsc` is not registered as
a Docker runtime.

## Wasm skills

Wasm skills are orthogonal to the `exec` sandbox. They are loaded and
executed by `wasmtime`
([`crates/agent/src/wasm_sandbox.rs:19-21`](../crates/agent/src/wasm_sandbox.rs))
inside the agent process, not in a container. The isolation surface is
the WebAssembly + WASI boundary:

- **No filesystem.** `WasiCtxBuilder::new()` is built without
  `preopened_dir`/`inherit_stdio`-style filesystem handles; only `stdin`,
  `stdout`, `stderr` are wired, and they are
  `MemoryInputPipe`/`MemoryOutputPipe` (in-memory, capped). See
  [`wasm_sandbox.rs:115-119`](../crates/agent/src/wasm_sandbox.rs).
- **No network.** No network handles are exposed via WASI.
- **CPU bound.** `Config::consume_fuel(true)` and `store.set_fuel(DEFAULT_FUEL)`
  give a hard fuel cap. An infinite loop trips fuel exhaustion (caught at
  [`wasm_sandbox.rs:163-167`](../crates/agent/src/wasm_sandbox.rs)) and
  returns a tool error rather than hanging the agent.
- **Memory bound.** Output pipe sizes are constants (`MAX_MEMORY_BYTES`
  for stdout, 4096 for stderr); a runaway producer caps at the pipe
  limit instead of growing without bound.

Wasm skills are not a replacement for `exec` confinement; they are a
sandbox for trusted-source compiled skills that need a clean boundary
without the latency cost of a container.

## What is not enforced

Honest about the gaps:

- **Container-escape CVEs in Docker, runc, or gVisor.** Wirken assumes
  the chosen OCI runtime is sound. Operators on outdated Docker versions
  inherit those CVEs. There is no second layer of host hardening (no
  AppArmor profile shipped, no SELinux module).
- **Side-channel attacks** (Spectre-class, page-cache timing, etc.).
  Wirken's sandbox is a logical isolation boundary, not a microarchitectural
  one. Multi-tenant deployments that need that should use a TEE provider
  ([configuration.md](configuration.md#confidential-inference)).
- **Workspace TOCTOU.** The bind-mount at `/workspace` is the host
  workspace. Shell code inside the sandbox can write files the host
  process later reads; if the host process trusts file metadata between
  read and use, an attacker who controls workspace contents can race
  it. The agent's tool layer reads/canonicalizes paths but does not
  re-stat after read.
- **DNS rebinding from a network-enabled sandbox.** If the operator sets
  `network: true` on the sandbox config, the container gets the host's
  network namespace and inherits whatever DNS it can resolve. Default is
  `network_mode: none`. This applies to the `network: true` flag only: on
  the sandbox-egress path the proxy resolves names itself and drops answers
  outside global unicast, so an allowlisted name cannot be rebound onto
  loopback, private space, or the link-local metadata address.

## Verification

Commands an operator can run to confirm the sandbox is what this document
claims:

```bash
# 1. Mode in effect
cat ~/.wirken/sandbox.json
# Expect: {"mode":"exec-only"} or {"mode":"gvisor"} or {"mode":"off"}

# 2. ExecOnly: the seccomp default blocks `mount`
wirken run &
# In another terminal, send the agent: "run `mount -t tmpfs none /tmp`"
# Expected response: the container reports `mount: ... Operation not permitted`,
# NOT a successful mount.

# 3. ExecOnly: the container has no network
# (Holds when the serving channel has no egress policy, which is the default.)
# Send: "run `curl -m 5 https://example.com`"
# Expected: curl fails with "Could not resolve host", because DNS is not reachable
# from `network_mode: none`.

# 4. ExecOnly: the rootfs is read-only
# Send: "run `touch /etc/wirken-test`"
# Expected: `touch: cannot touch '/etc/wirken-test': Read-only file system`.

# 5. GVisor: runsc is the runtime in use
docker info --format '{{ json .Runtimes }}' | jq .
# Expect a `runsc` key listed.

# 6. Sandbox refuses to fall back when its runtime is missing
sudo systemctl stop docker      # disable the runtime
wirken run                      # next exec request
# Expected: AgentError::Sandbox("sandbox mode is ExecOnly but the
# sandbox is unavailable; refusing to fall back to host execution. ...")
```

If any of these checks return a different result, file an issue against
[wirken](https://github.com/gebruder/wirken/issues): the divergence is
either a documentation bug here or a code bug in `sandbox.rs`.
