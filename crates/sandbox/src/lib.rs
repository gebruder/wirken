//! Container hardening shared by the `exec` sandbox and the containers
//! stdio MCP servers run in.
//!
//! What every container gets is fixed here: no Linux capabilities, no
//! privilege elevation, Docker's default seccomp profile, a read-only
//! root with a tmpfs at `/tmp`, and memory and PID caps. What differs
//! between an `exec` and an MCP server, its mounts, network and
//! limits, is passed in as [`HostSettings`].
//!
//! The egress proxy both use, a policy-free sidecar and a host-side
//! decision broker, is in [`egress`], and the networks that make the
//! sidecar the sandbox's only route are built by `egress_net`.

// Slicing a str off a character boundary panics. Each slice that
// stays carries an allow naming why its offsets are boundaries.
#![cfg_attr(not(test), deny(clippy::string_slice))]

pub mod egress;
#[cfg(unix)]
pub mod egress_net;

use std::collections::HashMap;

use bollard::models::{HostConfig, Mount, SystemInfo, SystemVersion};

/// Default container memory cap.
pub const MEMORY_LIMIT: i64 = 512 * 1024 * 1024; // 512 MB
/// Default container PID cap; see [`MEMORY_LIMIT`].
pub const PIDS_LIMIT: i64 = 256;

/// Sandbox mode, from `sandbox.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxMode {
    /// No sandboxing. Direct host execution. Opt-in only; set
    /// `"mode": "off"` in `sandbox.json` to use this.
    Off,
    /// Only the `exec` tool runs in a Docker container (default runc runtime).
    /// This is the default as of 0.7.5. If Docker is not reachable, the
    /// `exec` tool refuses to run rather than silently falling back to
    /// host execution; operators who want host execution must set
    /// `"mode":"off"` explicitly. Sandbox provisioning is still lazy
    /// (attempted on first `exec` call), so a missing runtime only
    /// surfaces when a tool call is issued.
    #[default]
    ExecOnly,
    /// Only the `exec` tool runs in a gVisor container (runsc runtime).
    /// Provides kernel attack surface reduction: syscalls are intercepted by
    /// gVisor's Sentry rather than reaching the host kernel. Requires
    /// `runsc` registered as a Docker runtime.
    GVisor,
}

impl SandboxMode {
    /// Parse a sandbox mode from a config string. Unknown modes fall
    /// back to [`SandboxMode::default`] rather than forcing `Off`, so
    /// a config typo does not silently strip the sandbox; the
    /// operator gets the secure default instead, with a warning.
    pub fn from_str_config(s: &str) -> Self {
        match s {
            "exec-only" => Self::ExecOnly,
            "gvisor" => Self::GVisor,
            "off" => Self::Off,
            "" => Self::default(),
            _ => {
                tracing::warn!(
                    "Unknown sandbox_mode '{s}', falling back to default ({:?})",
                    Self::default()
                );
                Self::default()
            }
        }
    }

    /// How this mode is named on an audit row.
    pub fn label(self) -> wirken_audit::SandboxModeLabel {
        match self {
            Self::Off => wirken_audit::SandboxModeLabel::Off,
            Self::ExecOnly => wirken_audit::SandboxModeLabel::ExecOnly,
            Self::GVisor => wirken_audit::SandboxModeLabel::Gvisor,
        }
    }

    /// The OCI runtime name to pass to Docker, or None for the default (runc).
    pub fn runtime_name(self) -> Option<String> {
        match self {
            Self::GVisor => Some("runsc".to_string()),
            _ => None,
        }
    }
}

/// The runtime an audit row names, from the OCI runtime on the
/// container body about to be sent.
///
/// Read off the body rather than off the sandbox's mode: this is what
/// Docker is being told to use for this one container. A mode whose
/// `runtime_name` says `runsc` and a body that carries none shows up
/// as a `docker` row under a `gvisor` mode, which is the disagreement
/// worth being able to see on the chain. `None` is Docker's default
/// runtime, runc.
pub fn runtime_label(runtime: Option<&str>) -> wirken_audit::SandboxRuntimeLabel {
    match runtime {
        Some("runsc") => wirken_audit::SandboxRuntimeLabel::Gvisor,
        _ => wirken_audit::SandboxRuntimeLabel::Docker,
    }
}

/// What varies from one container to the next. Everything else in the
/// host config is fixed by [`hardened_host_config`].
#[derive(Debug, Clone, PartialEq)]
pub struct HostSettings {
    /// `source:target:mode` bind mounts.
    pub binds: Vec<String>,
    /// Structured mounts, for paths that should not go through the
    /// `source:target:mode` string form.
    pub mounts: Vec<Mount>,
    /// `none`, a network name, or `None` for Docker's default.
    pub network_mode: Option<String>,
    /// DNS servers, pinned only where a resolver must not work.
    pub dns: Option<Vec<String>>,
    /// Memory cap in bytes.
    pub memory: i64,
    /// PID cap.
    pub pids: i64,
    /// CPU cap in billionths of a CPU; `None` for no cap.
    pub nano_cpus: Option<i64>,
    /// OCI runtime, `None` for Docker's default (runc).
    pub runtime: Option<String>,
}

/// The host config every sandbox container runs under.
///
/// Kernel-level hardening, in addition to the memory, PID, network,
/// and user caps the caller sets:
///
/// * `cap_drop=ALL`: strip every Linux capability. Nothing sandboxed
///   needs `CAP_NET_BIND_SERVICE`, `CAP_CHOWN`, etc. If a real use
///   case breaks this, re-evaluate rather than loosening by default.
/// * `no-new-privileges`: block setuid/setgid elevation inside the
///   container. Pairs with `cap_drop`.
/// * seccomp: rely on Docker's default seccomp profile. Docker
///   applies it automatically when no seccomp SecurityOpt is set;
///   the string `seccomp=default` is not a valid option and causes
///   the daemon to reject container start.
/// * `readonly_rootfs`: make the container's `/` read-only. Bind
///   mounts keep the mode the caller gave them, and a tmpfs at `/tmp`
///   gives the process somewhere to scratch.
pub fn hardened_host_config(settings: HostSettings) -> HostConfig {
    let mut tmpfs_mounts = HashMap::new();
    tmpfs_mounts.insert("/tmp".to_string(), "size=64m,mode=1777".to_string());
    HostConfig {
        binds: Some(settings.binds),
        mounts: (!settings.mounts.is_empty()).then_some(settings.mounts),
        network_mode: settings.network_mode,
        dns: settings.dns,
        memory: Some(settings.memory),
        pids_limit: Some(settings.pids),
        nano_cpus: settings.nano_cpus,
        // With auto_remove=true a container is torn down the moment it
        // exits, which races any later read of its logs or exit code.
        // Callers remove containers explicitly instead.
        auto_remove: Some(false),
        runtime: settings.runtime,
        cap_drop: Some(vec!["ALL".into()]),
        cap_add: Some(Vec::new()),
        security_opt: Some(vec![
            "no-new-privileges:true".into(),
            // Docker applies its default seccomp profile when no seccomp SecurityOpt is set.
        ]),
        readonly_rootfs: Some(true),
        tmpfs: Some(tmpfs_mounts),
        ..Default::default()
    }
}

/// The `uid:gid` a container runs as to act as the operator: the
/// operator's own, or `0:0` under a rootless runtime, where container
/// uid 0 is the operator and every other uid a subordinate one that
/// could not open the operator's files or sockets.
pub fn operator_user(rootless: bool) -> String {
    if rootless {
        return "0:0".to_string();
    }
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` and `getegid` are always-safe FFI;
        // documented as never failing.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        format!("{uid}:{gid}")
    }
    #[cfg(not(unix))]
    {
        "1000:1000".to_string()
    }
}

/// What the container runtime behind a Docker API socket is, as far
/// as proxied egress is concerned.
///
/// Proxied egress needs an `Internal` network, a sidecar that can
/// connect a bind-mounted Unix socket, and the broker on the same
/// host. It is verified on rootful Docker on Linux and nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuntimeFacts {
    /// The API is served by Podman.
    pub podman: bool,
    /// The daemon runs without root, so container uid 0 is the
    /// invoking user and other uids are subordinate ones.
    pub rootless: bool,
    /// The daemon runs Windows containers, or this host has no Unix
    /// sockets for the broker.
    pub windows: bool,
}

impl RuntimeFacts {
    /// Ask the daemon.
    pub async fn probe(docker: &bollard::Docker) -> Result<Self, String> {
        let info = docker
            .info()
            .await
            .map_err(|e| format!("runtime info: {e}"))?;
        let version = docker
            .version()
            .await
            .map_err(|e| format!("runtime version: {e}"))?;
        Ok(Self::from_reports(&info, &version))
    }

    /// Read the facts out of the daemon's `/info` and `/version`.
    pub fn from_reports(info: &SystemInfo, version: &SystemVersion) -> Self {
        let is_podman = |name: &str| name.to_ascii_lowercase().contains("podman");
        let podman = version
            .components
            .iter()
            .flatten()
            .any(|c| is_podman(&c.name))
            || version
                .platform
                .as_ref()
                .is_some_and(|p| is_podman(&p.name));
        let rootless = info
            .security_options
            .iter()
            .flatten()
            .any(|o| o.split(',').any(|kv| kv == "name=rootless"));
        let windows = cfg!(not(unix)) || info.os_type.as_deref() == Some("windows");
        Self {
            podman,
            rootless,
            windows,
        }
    }

    /// Why proxied egress cannot run on this runtime, if it cannot.
    pub fn egress_unsupported(&self) -> Option<&'static str> {
        if self.windows {
            Some("the egress broker needs a Unix socket, which this host does not have")
        } else if self.podman {
            Some("proxied egress is not verified on Podman")
        } else if self.rootless {
            Some("proxied egress is not verified on rootless Docker")
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> HostSettings {
        HostSettings {
            binds: vec!["/src:/dst:ro".into()],
            mounts: Vec::new(),
            network_mode: Some("none".into()),
            dns: None,
            memory: MEMORY_LIMIT,
            pids: PIDS_LIMIT,
            nano_cpus: Some(1_000_000_000),
            runtime: Some("runsc".into()),
        }
    }

    #[test]
    fn every_container_gets_the_fixed_hardening() {
        let host = hardened_host_config(settings());
        assert_eq!(host.cap_drop, Some(vec!["ALL".to_string()]));
        assert_eq!(host.cap_add, Some(Vec::new()));
        assert_eq!(
            host.security_opt,
            Some(vec!["no-new-privileges:true".to_string()])
        );
        assert_eq!(host.readonly_rootfs, Some(true));
        assert_eq!(
            host.tmpfs.unwrap().get("/tmp").map(String::as_str),
            Some("size=64m,mode=1777")
        );
        assert_eq!(host.auto_remove, Some(false));
    }

    #[test]
    fn the_caller_settings_land_as_given() {
        let host = hardened_host_config(settings());
        assert_eq!(host.binds, Some(vec!["/src:/dst:ro".to_string()]));
        assert_eq!(host.network_mode.as_deref(), Some("none"));
        assert_eq!(host.memory, Some(MEMORY_LIMIT));
        assert_eq!(host.pids_limit, Some(PIDS_LIMIT));
        assert_eq!(host.nano_cpus, Some(1_000_000_000));
        assert_eq!(host.runtime.as_deref(), Some("runsc"));
    }

    #[test]
    fn modes_map_to_their_runtime() {
        assert_eq!(SandboxMode::GVisor.runtime_name().as_deref(), Some("runsc"));
        assert_eq!(SandboxMode::ExecOnly.runtime_name(), None);
        assert_eq!(SandboxMode::from_str_config("gvisor"), SandboxMode::GVisor);
        assert_eq!(SandboxMode::from_str_config("typo"), SandboxMode::ExecOnly);
    }

    fn reports(security: &[&str], components: &[&str], os: &str) -> (SystemInfo, SystemVersion) {
        let info = SystemInfo {
            security_options: Some(security.iter().map(|s| s.to_string()).collect()),
            os_type: Some(os.to_string()),
            ..Default::default()
        };
        let version = SystemVersion {
            components: Some(
                components
                    .iter()
                    .map(|n| bollard::models::SystemVersionComponents {
                        name: n.to_string(),
                        version: "1".into(),
                        details: None,
                    })
                    .collect(),
            ),
            ..Default::default()
        };
        (info, version)
    }

    #[cfg(unix)]
    #[test]
    fn the_operator_user_is_this_process_or_root_under_rootless() {
        // SAFETY: as in `operator_user`.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        assert_eq!(operator_user(false), format!("{uid}:{gid}"));
        assert_eq!(operator_user(true), "0:0");
    }

    #[test]
    fn rootful_docker_on_linux_supports_proxied_egress() {
        let (info, version) = reports(
            &["name=seccomp,profile=builtin", "name=cgroupns"],
            &["Engine", "containerd"],
            "linux",
        );
        let facts = RuntimeFacts::from_reports(&info, &version);
        assert_eq!(facts, RuntimeFacts::default());
        assert_eq!(facts.egress_unsupported(), None);
    }

    #[test]
    fn rootless_podman_and_windows_do_not() {
        let (info, version) = reports(&["name=rootless"], &["Engine"], "linux");
        let rootless = RuntimeFacts::from_reports(&info, &version);
        assert!(rootless.rootless && !rootless.podman);
        assert!(rootless.egress_unsupported().is_some());

        let (info, version) = reports(&[], &["Podman Engine"], "linux");
        let podman = RuntimeFacts::from_reports(&info, &version);
        assert!(podman.podman);
        assert!(podman.egress_unsupported().is_some());

        let (info, version) = reports(&[], &["Engine"], "windows");
        assert!(
            RuntimeFacts::from_reports(&info, &version)
                .egress_unsupported()
                .is_some()
        );
    }
}
