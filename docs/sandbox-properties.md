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
([`crates/agent/src/sandbox.rs:25-43`](../crates/agent/src/sandbox.rs)):

| Mode | Default | Runtime | Meaning |
|---|---|---|---|
| `ExecOnly` | yes (since 0.7.5) | Docker `runc` | The `exec` tool runs in an ephemeral container with the hardening below. Other tools run on the host. |
| `GVisor` | no | Docker `runsc` | Same container hardening; the OCI runtime is gVisor. Every guest syscall is intercepted by gVisor's userspace kernel (`Sentry`) instead of reaching the host kernel directly. |
| `Off` | no | none | No sandboxing. Opt-in via `"mode":"off"` in `~/.wirken/sandbox.json`. The shell process runs as the agent's UID with the agent's privileges. |

Unknown mode strings fall back to `ExecOnly`, not `Off` — a config typo gets
the secure default with a warning, never the bypass
([`sandbox.rs:50-64`](../crates/agent/src/sandbox.rs)).

## No silent fallback

[`crates/agent/src/tool.rs:533-553`](../crates/agent/src/tool.rs):

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

## Container hardening (applies to ExecOnly and GVisor)

[`crates/agent/src/sandbox.rs:644-687`](../crates/agent/src/sandbox.rs)
constructs the `HostConfig` for every sandboxed exec:

| Property | Value | Source line |
|---|---|---|
| `cap_drop` | `ALL` | `:678` - every Linux capability stripped. No `CAP_NET_BIND_SERVICE`, `CAP_CHOWN`, `CAP_SYS_ADMIN`, etc. |
| `cap_add` | `[]` | `:679` - no capabilities re-added. |
| `security_opt` | `no-new-privileges:true` | `:680-683` - `setuid`/`setgid` binaries cannot elevate. |
| `readonly_rootfs` | `true` | `:684` - container `/` is read-only. |
| `tmpfs` | `/tmp` mounted at 64MB, mode `1777` | `:661-665, 685` - the only writable filesystem outside `/workspace`. |
| `network_mode` | `none` (configurable) | `:653-659, 668` - default is no network namespace; outbound DNS/HTTP fail. A channel configured for sandbox egress joins a policed internal network instead; see below. |
| `dns` | unset, or `127.0.0.1` on the egress path | `:660, 669` - pinned to an address with no resolver behind it when an egress network is in use, so names are resolved by the proxy rather than in the container. |
| `binds` | `<workspace>:/workspace:rw` | `:667` - only the agent workspace is mounted, RW. |
| `memory` | 512 MB | `:20, 670` - `MEMORY_LIMIT` constant. |
| `pids_limit` | 256 | `:21, 671` - `PIDS_LIMIT` constant; fork-bomb cap. |
| `user` | `1000:1000` | `:327` - non-root UID/GID inside the container. |
| `auto_remove` | `false` | `:676` - explicit `kill_and_remove` after log collection so output is never lost to a teardown race. |
| timeout | 300 s | `:251, 377` - wall-clock cap; container is killed and removed on timeout. |

### Sandbox egress

`network_mode: none` is the default and applies whenever the channel serving
the turn has no egress policy.

When a channel is configured for `allowlist` or `open` egress, two networks are
created for that exec:

| Network | Kind | Members | Purpose |
|---|---|---|---|
| `wirken-egress-<id>` | `Internal`, no route off the host | the sandbox and its sidecar, exactly two | carries the sandbox's requests to the sidecar |
| `wirken-egress-out-<id>` | ordinary bridge | the sidecar only | the sole path outward |

The sandbox joins the internal network only, so its one reachable peer is its
own sidecar. The isolation invariant is that network being `Internal`, per
exec, and two-member; both networks are removed when the exec ends.
Inter-container communication is left enabled on the internal network because
the sandbox reaching its sidecar is the only flow it carries.

The sidecar proxy holds no policy: it asks the gateway over a per-exec Unix
socket, so no host port is bound. The other rows in the table above are
unchanged on this path.

The sidecar runs the wirken binary itself, bind-mounted read-only, which
requires the statically linked build. `sandbox.json` sets `sidecar_binary` to
point at a static binary when the running gateway is not one, and `image` to
name the container image `exec` runs in:

```json
{
  "mode": "exec-only",
  "image": "curlimages/curl:latest",
  "sidecar_binary": "/usr/local/bin/wirken"
}
```

`sidecar_binary` absent defaults to the gateway's own executable. A configured
path that does not exist refuses the `exec` rather than running it unproxied.

`image` absent or empty means the compiled-in default. That default carries no
HTTP client, so an `exec` on a channel granted proxied egress reaches nothing
from it; naming an image that carries one is how an operator exercises the
egress path. The choice is per install and opt-in, which is where it belongs:
a default image with a network client widens every sandbox's capability
surface for everyone.

See [egress.md](egress.md) for the modes, properties, runtime requirement, and
the known CONNECT/SNI limit.

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
default profile ([`sandbox.rs:680-683`](../crates/agent/src/sandbox.rs)).

## gVisor delta (`SandboxMode::GVisor`)

When mode is `GVisor`, `runtime_name()` returns `Some("runsc")`
([`sandbox.rs:67-72`](../crates/agent/src/sandbox.rs)) and Docker
launches the container under gVisor instead of `runc`.

gVisor changes the threat model. Under `runc`, the guest's syscalls reach
the host kernel directly, filtered by Docker's seccomp profile. Under
gVisor, **every** guest syscall is trapped by `runsc` and serviced by the
Sentry — gVisor's userspace re-implementation of the Linux syscall surface
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
([`sandbox.rs:714-726`](../crates/agent/src/sandbox.rs)) is automatic;
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
  [`wasm_sandbox.rs:158-160`](../crates/agent/src/wasm_sandbox.rs)) and
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
  ([reference/privatemode.md](reference/privatemode.md)).
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
# Expected: curl fails with "Could not resolve host" — DNS is not reachable
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
[wirken](https://github.com/gebruder/wirken/issues) — the divergence is
either a documentation bug here or a code bug in `sandbox.rs`.
