# Sandbox Properties

What Wirken's `exec` sandbox actually enforces. Every claim cites
the source line that implements it; every command in [Verification](#verification)
can be run on a Wirken host to confirm.

This document covers the runtime sandbox only. Process-level isolation between
adapters (one OS process per channel) and IPC boundary properties live in
[architecture.md](architecture.md). Permission tiers live in
[permissions-and-identity.md](permissions-and-identity.md).

## Modes

`SandboxMode` is the operator-facing knob. Three values, one default
([`crates/sandbox/src/lib.rs:42-60`](../crates/sandbox/src/lib.rs), re-exported
at [`crates/agent/src/sandbox.rs:40`](../crates/agent/src/sandbox.rs)):

| Mode | Default | Runtime | Meaning |
|---|---|---|---|
| `ExecOnly` | yes (since 0.7.5) | Docker `runc` | The `exec` tool runs in an ephemeral container with the hardening below. Other tools run on the host. |
| `GVisor` | no | Docker `runsc` | Same container settings; the OCI runtime is gVisor. Every guest syscall is intercepted by gVisor's userspace kernel (`Sentry`) instead of reaching the host kernel directly. The seccomp profile is not applied to the workload; see [gVisor delta](#gvisor-delta-sandboxmodegvisor). |
| `Off` | no | none | No sandboxing. Opt-in via `"mode":"off"` in `~/.wirken/sandbox.json`. The shell process runs as the agent's UID with the agent's privileges. |

A `mode` that is none of the three is refused when `sandbox.json` is
loaded, with an error naming the file and the value, and `wirken run` does
not start. A missing file, or one with no `mode` key, is `ExecOnly`
(`SandboxMode::from_sandbox_json`, `crates/sandbox/src/lib.rs`).

## No silent fallback

The runtime an `exec` runs under is the one the mode names, and no other:
`runsc` under `gvisor`, the container runtime's default under `exec-only`,
the host under `off` (`RuntimeStatus::resolve`,
`crates/sandbox/src/lib.rs`).

- **At start.** `wirken run` asks the container runtime, prints what it
  found, and records it as one `exec_runtime_at_start` row on the
  `gateway-sandbox` session: the mode, the runtime's name as the daemon
  gives it, whether it can run a container, the reason when it cannot, and
  the runtime egress sidecars run under.

  ```
  Sandbox: exec runs under Docker default runtime (runc) (sandbox mode exec-only)
  ```

  ```
  Sandbox: exec is refused: sandbox mode gvisor needs gVisor (runsc), and runsc is not registered with the container runtime
  ```

- **At each `exec`.** If the runtime the mode names cannot run a container
  (the daemon is not reachable; `gvisor` and no `runsc` registered), the
  call is refused. It does not run on the host and it does not run under
  the daemon's default in place of `runsc`. The refusal is an
  `exec_runtime_unavailable` row naming the mode, the runtime and the
  reason, and a failed tool result the model reads; the turn goes on. The
  decision is made on the agent's first `exec` and holds until the gateway
  restarts (`ToolRegistry::sandbox`, `crates/agent/src/tool.rs`;
  `a_gvisor_exec_without_runsc_is_refused_with_a_row`,
  `crates/agent/src/tests.rs`).

- **MCP servers.** Under `gvisor` with no `runsc` registered, a contained
  server is refused with an `mcp_entry_refused` row, reason
  `sandbox_unavailable` (`ContainerPlan::new`,
  `crates/mcp-proxy/src/container.rs`).

- **Egress sidecars.** A sidecar container names no runtime, so it runs
  under the daemon's default in every mode, `gvisor` included. Under
  `gvisor` the startup output says so:

  ```
  Sandbox: egress sidecars run under the container runtime's default (runc), not gVisor
  ```

Operators who want host execution opt in by writing `"mode":"off"`.

## Processes end with the call

A gated `exec` call does not leave work running after it returns.

- **`ExecOnly` and `GVisor`.** The command runs in its own container, and the
  container, its egress sidecar and its networks are killed and removed on
  every return path, and when the call is dropped before it returns, as when
  a turn is aborted or the gateway stops (`ExecResources` in
  [`sandbox.rs`](../crates/agent/src/sandbox.rs)). That ends every process
  in its PID namespace, including children detached with `&`, `nohup`,
  `setsid`, or a double fork. Each object is labelled with the data
  directory's instance and the creating process, and `wirken run` and
  `wirken lyrik run` remove at start any whose process has ended, as after a
  kill.
- **`Off` on Linux and macOS.** The shell leads its own process group, and
  the group is killed when the call returns or times out (`HostGroup` in
  [`tool.rs`](../crates/agent/src/tool.rs)). That ends children started with
  `&`, `nohup`, or a double fork. A child that calls `setsid` starts a new
  session, leaves the group, and keeps running.
- **`Off` on Windows.** The shell is killed on timeout. Processes it started
  are not tracked.

Under `Off` the command does not inherit the gateway's environment: it starts
from an empty one plus the minimal host-child set (`PATH`, `HOME`, `USER`,
`LOGNAME`, `LANG`, `LC_ALL`, `TERM`, `TMPDIR`; on Windows the system
locations a shell needs; `child_env::BASE` in
[`crates/sandbox/src/child_env.rs`](../crates/sandbox/src/child_env.rs), the
set every host-side child Wirken spawns begins with) and the `WIRKEN_EXEC`
marker that `wirken update` and the authority-changing commands refuse on
([update.md](update.md#inside-an-exec), [cli.md](cli.md))
(`host_exec_env`, [`crates/agent/src/tool.rs`](../crates/agent/src/tool.rs)),
so a passphrase or key the gateway was started with is not passed on.
Its stdin is `/dev/null`, not the operator's terminal. The command still runs
as the gateway's user and can read whatever that user can.

The tests are `exec_children_die_with_the_call` (process lifetime) and
`host_exec_inherits_nothing` (environment and stdin) in
[`crates/agent/src/tests.rs`](../crates/agent/src/tests.rs).

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
paths write the same `output` and `success` shape, so before this field an
auditor reading `audit.db` could not tell a containerised `exec` from a host
one.

The two can disagree and the row says so when they do: `mode: exec_only`
with `runtime: host` is a sandbox that failed open, which is the case
worth being able to see afterwards. A call refused at the gate records no
`sandbox` at all, which is a different answer from `host`: nothing ran
anywhere. A call cut at the timeout still records where it ran.

## Container hardening (applies to ExecOnly and GVisor)

[`crates/agent/src/sandbox.rs:876-910`](../crates/agent/src/sandbox.rs)
(`build_host_config`) chooses the network, DNS, bind and runtime values for
every sandboxed exec and hands them to `hardened_host_config`
([`crates/sandbox/src/lib.rs:148-174`](../crates/sandbox/src/lib.rs)), which
sets the fixed hardening and is shared with MCP server containers. The
separate sidecar `HostConfig` (`sidecar_body`,
[`crates/sandbox/src/egress_net.rs:291-325`](../crates/sandbox/src/egress_net.rs))
belongs to the egress sidecar container, not to the exec sandbox:

| Property | Value | Source line |
|---|---|---|
| `cap_drop` | `ALL` | `lib.rs:164` - every Linux capability stripped. No `CAP_NET_BIND_SERVICE`, `CAP_CHOWN`, `CAP_SYS_ADMIN`, etc. |
| `cap_add` | `[]` | `lib.rs:165` - no capabilities re-added. |
| `security_opt` | `no-new-privileges:true` | `lib.rs:166-169` - `setuid`/`setgid` binaries cannot elevate. |
| `readonly_rootfs` | `true` | `lib.rs:170` - container `/` is read-only. |
| `tmpfs` | `/tmp` mounted at 64MB, mode `1777` | `lib.rs:149-150, 171` - the only writable filesystem outside `/workspace`. |
| `network_mode` | `none` (configurable) | `sandbox.rs:888-893, 903` - default is `--network none`, loopback only; outbound DNS/HTTP fail. A channel configured for sandbox egress joins a policed internal network instead; see below. |
| `dns` | unset, or `127.0.0.1` on the egress path | `sandbox.rs:896-899, 904` - pinned to an address with no resolver behind it when an egress network is in use, so names are resolved by the proxy rather than in the container. |
| `binds` | `<workspace>:/workspace:rw` | `sandbox.rs:901` - only the agent workspace is mounted, RW. |
| `memory` | 512 MB | `lib.rs:27`, applied at `sandbox.rs:905` - `MEMORY_LIMIT` constant. |
| `pids_limit` | 256 | `lib.rs:29`, applied at `sandbox.rs:906` - `PIDS_LIMIT` constant; fork-bomb cap. |
| `user` | `1000:1000` | `sandbox.rs:548` - non-root UID/GID inside the container. |
| `auto_remove` | `false` | `lib.rs:162` - removed explicitly after log collection (`ExecResources`, `sandbox.rs:560`) so output is never lost to a teardown race. |
| timeout | 300 s | `sandbox.rs:235`, applied at `:610-611` - wall-clock cap; container is killed and removed on timeout. |

### Sandbox egress

`network_mode: none` is the default and applies whenever the channel serving
the turn has no egress policy and `sandbox.json` does not set `network: true`
(`build_host_config`, `sandbox.rs:888-893`; a `none` policy sets it whatever
the flag says). A channel configured for `allowlist` or `open`
joins a per-exec two-member internal network and reaches the outside only
through a sidecar proxy container. The topology, the isolation invariant, the
port and address rules, and the known CONNECT/SNI limit are in
[egress.md](egress.md#sandbox-egress). Everything else in the hardening table
above is unchanged on that path.

This axis is separate from the skill-set allow-set that governs
`http_request`. Both default to no reach: a channel with no egress policy
gives `exec` no network, and an agent whose skills declare no allow-set gives
`http_request` no host ([egress.md](egress.md#what-egressdomains-covers)).

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

`security_opt` names a seccomp profile for every `exec` and MCP server
container, and for the egress sidecar of each:
`crates/sandbox/src/seccomp.json`, passed to the runtime with the container
(`crates/sandbox/src/seccomp.rs`). It is Docker's default allowlist
([upstream](https://docs.docker.com/engine/security/seccomp/)), as released
in the Moby profiles project's `seccomp/v0.3.0`, with every allowance that
depends on a capability removed. Like that release it allows `socket` per
address family. The default refuses
`unshare`, `mount`, `setns` and a namespace-making `clone` only because the
container holds no `CAP_SYS_ADMIN`; this profile refuses them
unconditionally, so a user namespace or a mount is refused by what Wirken
sends and not by what the daemon applies when nothing is named. `clone3`,
whose flags a filter cannot read, answers `ENOSYS`, and a libc falls back to
`clone`. No syscall is allowed that the default does not allow a container
with no capabilities. `seccomp.NOTICE` records the profile's origin.

The profile blocks, among others:

- Namespaces: `unshare`, `setns`, and `clone` with any `CLONE_NEW*` flag.

- Kernel-module loaders: `init_module`, `finit_module`, `delete_module`.
- Mount manipulation: `mount`, `umount`, `umount2`, `pivot_root`.
- Kernel keyring: `add_key`, `request_key`, `keyctl`.
- Kexec: `kexec_load`, `kexec_file_load`.
- Personality: `personality` outside five listed values.
- Clock setting: `clock_settime`, `settimeofday`, `stime`.
- BPF programs: `bpf`.
- Reboot: `reboot`.

`sandbox_refuses_user_namespaces_and_mounts` in
`crates/agent/src/tests.rs` runs `unshare -Urm` and `mount` through `exec`
against a live daemon and expects both refused.

All of this is the profile under `runc`. Under `gvisor` the profile is sent
and not applied to the workload; see
[gVisor delta](#gvisor-delta-sandboxmodegvisor).

Docker's API takes the profile as JSON. Podman's takes a path and reads the
file itself, so on Podman the profile is written to
`<tmp>/wirken-seccomp-<uid>/seccomp.json`, in a directory only the operator
can enter, and the container names that path. A directory already at that
place that the operator does not own, or that others can enter, is not used,
and the `exec` or the server is refused. Both runtimes run the container
under the same profile. The Podman path is not exercised by a test against
a live Podman.

## gVisor delta (`SandboxMode::GVisor`)

When mode is `GVisor`, `runtime_name()` returns `Some("runsc")`
([`crates/sandbox/src/lib.rs:119-124`](../crates/sandbox/src/lib.rs)) and Docker
launches the `exec` container, and each contained MCP server's container,
under gVisor instead of `runc`. Egress sidecars stay on the daemon's
default runtime.

gVisor changes the threat model. Under `runc`, the guest's syscalls reach
the host kernel directly, filtered by the seccomp profile above. Under
gVisor, **every** guest syscall is trapped by `runsc` and serviced by the
Sentry, gVisor's userspace re-implementation of the Linux syscall surface
in Go. The host kernel sees only a small, fixed set of syscalls from
`runsc` itself.

The seccomp profile above is still sent with the container, and `runsc`
does not apply it to the workload: what a guest syscall does is the
Sentry's decision. `a_gvisor_exec_makes_a_user_namespace_and_mounts_in_it`
in `crates/agent/src/tests.rs` pins the outcome through `exec`, in CI, under
the runsc release `.github/workflows/ci.yml` installs:

- `unshare -Ur id -u` succeeds and prints 0.
- Inside a new user and mount namespace, `mount -t tmpfs -o exec` succeeds.
- `mount` outside a new user namespace is refused.

`sandbox_refuses_user_namespaces_and_mounts` runs the same calls under
`exec-only`, where each is refused. The boundary is stated in
[threat-model.md](threat-model.md#shell).

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
opt-in for operators who want kernel attack surface reduction. `wirken
setup` offers `gvisor` only where `runsc` is registered with Docker
(`detect_gvisor`, `crates/agent/src/sandbox.rs`); a `sandbox.json` written
by hand is checked at start and at each `exec`, as
[above](#no-silent-fallback).

`a_gvisor_exec_records_gvisor` and `a_gvisor_exec_runs_on_the_runsc_kernel`
in `crates/agent/src/tests.rs` run an `exec` under `runsc`. The CI job
`Sandbox under runsc` installs runsc and sets `WIRKEN_TEST_REQUIRE_RUNSC=1`,
under which they fail where `runsc` is missing. Without that variable they
print `skipping:` and pass on a host with no `runsc`.

## What is not enforced

Each boundary is stated in [threat-model.md](threat-model.md#shell). The
detail for the sandbox:

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
  `network: true` in `sandbox.json` and no channel egress policy reaches the
  exec, the container joins Docker's default bridge network
  (`build_host_config`, `sandbox.rs:891`) and resolves whatever that network's
  DNS can. Default is `network_mode: none`. This applies to the `network: true`
  flag only: on
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

# 2. ExecOnly: `cap_drop ALL` and the seccomp profile both block `mount`
wirken run &
# In another terminal, send the agent: "run `mount -t tmpfs none /tmp`"
# Expected response: the container reports `mount: ... Operation not permitted`,
# NOT a successful mount. (With every capability dropped the result does not
# single out seccomp.)

# 3. ExecOnly: the container has no network
# (Holds when the serving channel has no egress policy, which is the default.
# The default image carries no HTTP client, so set `image` in sandbox.json to
# one with curl first; on the default image the shell reports `curl: not found`.)
# Send: "run `curl -m 5 https://example.com`"
# Expected: curl fails with "Could not resolve host", because DNS is not reachable
# from `network_mode: none`.

# 4. ExecOnly: the rootfs is read-only
# Send: "run `touch /etc/wirken-test`"
# Expected: `touch: cannot touch '/etc/wirken-test': Read-only file system`.

# 5. GVisor: runsc is the runtime in use
docker info --format '{{ json .Runtimes }}' | jq .
# Expect a `runsc` key listed.
wirken run
# Expect: Sandbox: exec runs under gVisor (runsc) (sandbox mode gvisor)

# 6. Sandbox refuses to fall back when its runtime is missing
sudo systemctl stop docker      # disable the runtime
wirken run
# Expected at start: Sandbox: exec is refused: sandbox mode exec-only needs
# Docker default runtime, and the container runtime is not reachable
# Expected at the next exec request: an `exec_runtime_unavailable` row and
# a failed tool result carrying the same sentence.
```

If any of these checks return a different result, file an issue against
[wirken](https://github.com/gebruder/wirken/issues): the divergence is
either a documentation bug here or a code bug in `sandbox.rs`.
