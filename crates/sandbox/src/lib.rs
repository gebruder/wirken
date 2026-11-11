//! Container hardening shared by the `exec` sandbox and the containers
//! stdio MCP servers run in.
//!
//! What every container gets is fixed here: no Linux capabilities, no
//! privilege elevation, a seccomp profile, a read-only root with a
//! tmpfs at `/tmp`, and memory and PID caps. What differs between an
//! `exec` and an MCP server, its mounts, network, limits and which
//! seccomp profile, is passed in as [`HostSettings`]. An `exec` runs
//! under the profile in [`seccomp`]; an MCP server under the runtime's
//! default.
//!
//! The egress proxy both use, a policy-free sidecar and a host-side
//! decision broker, is in [`egress`], and the networks that make the
//! sidecar the sandbox's only route are built by `egress_net`.
//!
//! What a process started outside any container begins with is in
//! [`child_env`]: every host-side child Wirken spawns starts from that
//! module's minimal environment and is given, by name, only what it
//! needs.

// Slicing a str off a character boundary panics. Each slice that
// stays carries an allow naming why its offsets are boundaries.
#![cfg_attr(not(test), deny(clippy::string_slice))]

pub mod child_env;
pub mod egress;
#[cfg(unix)]
pub mod egress_net;
pub mod seccomp;

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
    /// The mode a config string names, or an error naming the string.
    /// A value that is none of the three is not read as any of them:
    /// an operator who wrote `gvisr` asked for something, and running
    /// under the default instead would be a runtime they did not choose.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "exec-only" => Ok(Self::ExecOnly),
            "gvisor" => Ok(Self::GVisor),
            "off" => Ok(Self::Off),
            other => Err(format!(
                "unknown sandbox mode {other:?}: the modes are \"exec-only\", \"gvisor\" and \"off\""
            )),
        }
    }

    /// The mode a parsed `sandbox.json` sets. A file with no `mode` key
    /// sets none and keeps the default. A `mode` that is not a string
    /// naming one of the three modes is an error naming the value.
    pub fn from_sandbox_json(value: &serde_json::Value) -> Result<Self, String> {
        match value.get("mode") {
            None => Ok(Self::default()),
            Some(serde_json::Value::String(mode)) => Self::parse(mode),
            Some(other) => Err(format!(
                "unknown sandbox mode {other}: the modes are \"exec-only\", \"gvisor\" and \"off\""
            )),
        }
    }

    /// The mode the `sandbox.json` in `data_dir` sets. A missing file
    /// keeps the default. A file that cannot be read or parsed, or
    /// whose `mode` names no mode, is an error naming the file and the
    /// value: what the operator asked for cannot be told, and it is not
    /// taken to be the default.
    pub fn from_data_dir(data_dir: &std::path::Path) -> Result<Self, String> {
        Self::from_sandbox_json(&read_sandbox_json(data_dir)?.unwrap_or(serde_json::Value::Null))
    }

    /// How this mode is written in `sandbox.json`.
    pub fn config_name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::ExecOnly => "exec-only",
            Self::GVisor => "gvisor",
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

/// What the container runtime says it can run containers under.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DaemonRuntimes {
    /// The runtime a container gets when none is named, as the daemon
    /// names it. Usually `runc`.
    pub default: Option<String>,
    /// Every runtime registered with the daemon, by name.
    pub registered: Vec<String>,
}

impl DaemonRuntimes {
    /// Read the runtimes out of the daemon's `/info`.
    pub fn from_info(info: &SystemInfo) -> Self {
        let mut registered: Vec<String> = info
            .runtimes
            .iter()
            .flat_map(|r| r.keys().cloned())
            .collect();
        registered.sort();
        Self {
            default: info.default_runtime.clone().filter(|d| !d.is_empty()),
            registered,
        }
    }

    /// Ask the daemon. `None` where it does not answer.
    pub async fn probe(docker: &bollard::Docker) -> Option<Self> {
        docker.info().await.ok().map(|info| Self::from_info(&info))
    }
}

/// What containers under a sandbox mode run under, and whether that
/// runtime can run one now.
///
/// The runtime is the one the mode names and no other: `gvisor` is
/// `runsc`, `exec-only` is the daemon's default. Where the named
/// runtime cannot run a container, `available` is false and the caller
/// refuses. Nothing here picks a different runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub mode: SandboxMode,
    /// The OCI runtime's name. `None` under `off`, where there is no
    /// container, and where the daemon did not say what its default is.
    pub runtime: Option<String>,
    pub available: bool,
    /// Why the runtime is not available, when it is not.
    pub reason: Option<String>,
    /// The daemon's default runtime, which egress sidecars run under in
    /// every mode.
    pub sidecar_runtime: Option<String>,
}

impl RuntimeStatus {
    /// The status of `mode` against what the daemon reported; `None`
    /// is a daemon that did not answer.
    pub fn resolve(mode: SandboxMode, daemon: Option<&DaemonRuntimes>) -> Self {
        let sidecar_runtime = daemon.and_then(|d| d.default.clone());
        let unavailable = |runtime: Option<String>, reason: &str| Self {
            mode,
            runtime,
            available: false,
            reason: Some(reason.to_string()),
            sidecar_runtime: sidecar_runtime.clone(),
        };
        match (mode, daemon) {
            (SandboxMode::Off, _) => Self {
                mode,
                runtime: None,
                available: true,
                reason: None,
                sidecar_runtime,
            },
            (SandboxMode::ExecOnly, None) => {
                unavailable(None, "the container runtime is not reachable")
            }
            (SandboxMode::GVisor, None) => unavailable(
                mode.runtime_name(),
                "the container runtime is not reachable",
            ),
            (SandboxMode::ExecOnly, Some(d)) => Self {
                mode,
                runtime: d.default.clone(),
                available: true,
                reason: None,
                sidecar_runtime,
            },
            (SandboxMode::GVisor, Some(d)) => {
                let runtime = mode.runtime_name();
                if d.registered.iter().any(|r| Some(r) == runtime.as_ref()) {
                    Self {
                        mode,
                        runtime,
                        available: true,
                        reason: None,
                        sidecar_runtime,
                    }
                } else {
                    unavailable(
                        runtime,
                        "runsc is not registered with the container runtime",
                    )
                }
            }
        }
    }

    /// The runtime in words, as an approval card names it.
    pub fn runtime_words(&self) -> String {
        match (self.mode, self.runtime.as_deref()) {
            (SandboxMode::Off, _) => "this host, no container".to_string(),
            (SandboxMode::GVisor, _) => "gVisor (runsc)".to_string(),
            (SandboxMode::ExecOnly, Some(name)) => format!("Docker default runtime ({name})"),
            (SandboxMode::ExecOnly, None) => "Docker default runtime".to_string(),
        }
    }

    /// One line saying what `exec` will run under, or that it will be
    /// refused and why.
    pub fn statement(&self) -> String {
        match &self.reason {
            Some(reason) if !self.available => format!(
                "exec is refused: sandbox mode {} needs {}, and {reason}",
                self.mode.config_name(),
                self.runtime_words()
            ),
            _ => format!(
                "exec runs under {} (sandbox mode {})",
                self.runtime_words(),
                self.mode.config_name()
            ),
        }
    }
}

impl std::fmt::Display for RuntimeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.statement())
    }
}

/// The parsed `sandbox.json` in `data_dir`, `None` where there is no
/// such file. A file that is there and cannot be read or parsed is an
/// error naming it.
pub fn read_sandbox_json(data_dir: &std::path::Path) -> Result<Option<serde_json::Value>, String> {
    let path = data_dir.join("sandbox.json");
    let body = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not read {}: {e}", path.display())),
    };
    let value: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("could not parse {}: {e}", path.display()))?;
    SandboxMode::from_sandbox_json(&value).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(value))
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
    /// DNS search domains. `None` copies the host's into the
    /// container's `/etc/resolv.conf`; `["."]` writes none.
    pub dns_search: Option<Vec<String>>,
    /// Memory cap in bytes.
    pub memory: i64,
    /// PID cap.
    pub pids: i64,
    /// CPU cap in billionths of a CPU; `None` for no cap.
    pub nano_cpus: Option<i64>,
    /// OCI runtime, `None` for Docker's default (runc).
    pub runtime: Option<String>,
    /// The seccomp profile the container runs under.
    pub seccomp: seccomp::Seccomp,
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
/// * seccomp: the profile the caller chose. [`seccomp::Seccomp::Profile`]
///   passes [`seccomp::PROFILE`]; `RuntimeDefault` names none, and the
///   runtime then applies its own (the string `seccomp=default` is not
///   a valid option and causes the daemon to reject container start).
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
        dns_search: settings.dns_search,
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
        security_opt: Some(
            std::iter::once("no-new-privileges:true".to_string())
                .chain(settings.seccomp.security_opt())
                .collect(),
        ),
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
    /// `runsc` is registered with the daemon, so a container can be
    /// started under gVisor.
    pub runsc: bool,
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
        let runsc = info
            .runtimes
            .as_ref()
            .is_some_and(|r| r.contains_key("runsc"));
        Self {
            podman,
            rootless,
            windows,
            runsc,
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
            dns_search: None,
            memory: MEMORY_LIMIT,
            pids: PIDS_LIMIT,
            nano_cpus: Some(1_000_000_000),
            runtime: Some("runsc".into()),
            seccomp: seccomp::Seccomp::RuntimeDefault,
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
        assert_eq!(SandboxMode::parse("gvisor"), Ok(SandboxMode::GVisor));
        assert_eq!(SandboxMode::parse("exec-only"), Ok(SandboxMode::ExecOnly));
        assert_eq!(SandboxMode::parse("off"), Ok(SandboxMode::Off));
    }

    fn daemon(default: &str, registered: &[&str]) -> DaemonRuntimes {
        DaemonRuntimes {
            default: Some(default.to_string()),
            registered: registered.iter().map(|r| r.to_string()).collect(),
        }
    }

    /// Each mode runs under the runtime it names, and says so.
    #[test]
    fn a_mode_resolves_to_the_runtime_it_names() {
        let both = daemon("runc", &["runc", "runsc"]);
        let exec_only = RuntimeStatus::resolve(SandboxMode::ExecOnly, Some(&both));
        assert_eq!(exec_only.runtime.as_deref(), Some("runc"));
        assert!(exec_only.available);
        assert_eq!(
            exec_only.statement(),
            "exec runs under Docker default runtime (runc) (sandbox mode exec-only)"
        );
        let gvisor = RuntimeStatus::resolve(SandboxMode::GVisor, Some(&both));
        assert_eq!(gvisor.runtime.as_deref(), Some("runsc"));
        assert!(gvisor.available);
        assert_eq!(gvisor.sidecar_runtime.as_deref(), Some("runc"));
        assert_eq!(
            gvisor.statement(),
            "exec runs under gVisor (runsc) (sandbox mode gvisor)"
        );
        let off = RuntimeStatus::resolve(SandboxMode::Off, None);
        assert_eq!(off.runtime, None);
        assert!(off.available);
        assert_eq!(
            off.statement(),
            "exec runs under this host, no container (sandbox mode off)"
        );
    }

    /// `exec-only` on a daemon whose default is not runc names what the
    /// daemon will use.
    #[test]
    fn exec_only_names_the_daemons_own_default() {
        let status = RuntimeStatus::resolve(
            SandboxMode::ExecOnly,
            Some(&daemon("runsc", &["runc", "runsc"])),
        );
        assert_eq!(status.runtime.as_deref(), Some("runsc"));
        assert_eq!(
            status.statement(),
            "exec runs under Docker default runtime (runsc) (sandbox mode exec-only)"
        );
    }

    /// `gvisor` without runsc, and any container mode without a daemon,
    /// is unavailable with the reason. It is never the default runtime
    /// in place of the one named.
    #[test]
    fn a_missing_runtime_is_unavailable_not_replaced() {
        let no_runsc =
            RuntimeStatus::resolve(SandboxMode::GVisor, Some(&daemon("runc", &["runc"])));
        assert!(!no_runsc.available);
        assert_eq!(no_runsc.runtime.as_deref(), Some("runsc"));
        assert_eq!(
            no_runsc.statement(),
            "exec is refused: sandbox mode gvisor needs gVisor (runsc), and runsc is not \
             registered with the container runtime"
        );
        for mode in [SandboxMode::ExecOnly, SandboxMode::GVisor] {
            let status = RuntimeStatus::resolve(mode, None);
            assert!(!status.available, "{mode:?}");
            assert!(
                status.statement().contains("is not reachable"),
                "{}",
                status.statement()
            );
        }
    }

    /// A mode that is none of the three is refused with the value in
    /// the message, and is never read as the default.
    #[test]
    fn an_unknown_mode_is_an_error_naming_it() {
        for raw in ["gvisr", "exec_only", "Off", "GVISOR", "", " ", "docker"] {
            let err = SandboxMode::parse(raw).expect_err(raw);
            assert!(err.contains(&format!("{raw:?}")), "{err}");
        }
        for value in [
            serde_json::json!({"mode": "chrooty"}),
            serde_json::json!({"mode": ""}),
            serde_json::json!({"mode": 3}),
            serde_json::json!({"mode": null}),
            serde_json::json!({"mode": ["gvisor"]}),
        ] {
            let err = SandboxMode::from_sandbox_json(&value).expect_err(&value.to_string());
            assert!(err.contains("unknown sandbox mode"), "{err}");
        }
    }

    /// Only a file that sets no mode, or no file, keeps the default.
    #[test]
    fn a_file_with_no_mode_key_keeps_the_default() {
        assert_eq!(
            SandboxMode::from_sandbox_json(&serde_json::json!({"image": "x"})),
            Ok(SandboxMode::ExecOnly)
        );
        assert_eq!(
            SandboxMode::from_sandbox_json(&serde_json::json!({"mode": "gvisor"})),
            Ok(SandboxMode::GVisor)
        );
    }

    #[cfg_attr(miri, ignore = "touches the filesystem; miri has none")]
    #[test]
    fn a_missing_file_keeps_the_default_and_an_unusable_one_is_refused() {
        let dir = std::env::temp_dir().join(format!("wirken-sandbox-json-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(SandboxMode::from_data_dir(&dir), Ok(SandboxMode::ExecOnly));
        let file = dir.join("sandbox.json");
        std::fs::write(&file, r#"{"mode":"gvisor"}"#).unwrap();
        assert_eq!(SandboxMode::from_data_dir(&dir), Ok(SandboxMode::GVisor));
        for (body, names) in [
            (r#"{"mode":"gvisr"}"#, "\"gvisr\""),
            (r#"{"mode": "gvisor",}"#, "could not parse"),
            ("not json", "could not parse"),
        ] {
            std::fs::write(&file, body).unwrap();
            let err = SandboxMode::from_data_dir(&dir).expect_err(body);
            assert!(
                err.contains("sandbox.json") && err.contains(names),
                "{body}: {err}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
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
