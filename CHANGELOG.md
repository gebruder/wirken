# Changelog

All notable changes to Wirken are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [semver](https://semver.org).

The `release-process.md` runbook covers how versions get cut and
signed. Unreleased changes accumulate at the top until a release is
tagged.

## Unreleased

### Sandbox defaults, configuration plumbing, hardening, and exec tier granularity

Four changes that together close the gaps documented in the 0.7.4
verification report:

- **Wire `sandbox_mode` config through to the runtime.** `OrgPermissions.sandbox_mode` now writes `sandbox.json` in the data dir via `apply_org_config`, and the CLI reads it at gateway start. `AgentStaticConfig` carries a `sandbox` field that the factory clones into every waked agent. `Agent::new_with_sandbox` is the new explicit constructor; `Agent::new` becomes a shim that uses the default. `Agent::from_session_log` takes a `SandboxConfig` parameter. Precedence: org config (force-overwrite on `wirken run`) > local `sandbox.json` > default.
- **Flip the default sandbox mode from `Off` to `ExecOnly`.** Fresh installs sandbox shell exec in an ephemeral Docker container by default. `SandboxMode::from_str_config` unknown/empty values now fall back to the current default rather than silently stripping the sandbox. `ToolRegistry::sandbox` probes Docker first and emits a distinct warning if Docker is unreachable; if `gvisor` is configured but `runsc` is not registered, the warning names `runsc` specifically. Both fall through to host execution with the existing sticky-failure semantics. `wirken setup` adds a fourth step that detects `runsc` and offers to upgrade to `gvisor`, writing `sandbox.json` either way.
- **Harden the sandbox container.** `cap_drop=ALL`, empty `cap_add`, `security_opt=["no-new-privileges:true","seccomp=default"]`, `readonly_rootfs=true`, and a 64 MB `tmpfs` at `/tmp` with `mode=1777`. Workspace stays bind-mounted RW at `/workspace`. Memory, PID, no-network, and non-root user settings are unchanged. Structural unit tests assert each field, and Docker-backed integration tests (skipped when Docker is absent) verify the kernel-level effect: write to `/` fails, writes to `/workspace` and `/tmp` succeed, `chown` fails under `cap_drop`, and setuid binaries fail to elevate under `no-new-privileges`.
- **Promote high-risk shell exec prefixes to Tier 3.** `curl`, `wget`, `ssh`, `scp`, `sftp`, `sudo`, `su`, `doas`, `kubectl`, `helm`, `docker`, `podman`, `nc`, `ncat`, `socat`, and `git` now always prompt instead of remembering a single approval for 30 days. Other `exec` prefixes keep the Tier 2 first-use-approval behaviour. No `permissions.db` schema change; existing Tier-2-style approvals for newly-Tier-3 prefixes are ignored by the tier lookup rather than migrated.

### Docs

- `docs/permissions-and-identity.md` no longer says `sandbox_mode` is parsed-but-not-enforced. `allowed_tools` and `blocked_tools` remain in the "parsed, not enforced" set.
- `docs/enforcement-model.md` describes the new default, the fallback warning paths, and the `sandbox.json` override.
- `README.md` Status section describes the new default and container hardening.

### Version

No version bump in these commits. The next release will be tagged
`0.7.5` per the maintainer runbook, with the bump in its own commit
at release time.
