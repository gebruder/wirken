//! Docker/Podman sandbox for tool execution.

use std::path::Path;

use bollard::Docker;
use bollard::container::LogOutput;
use bollard::models::ContainerCreateBody;
use bollard::models::HostConfig;
use bollard::models::NetworkCreateRequest;
use bollard::query_parameters::{
    CreateContainerOptions, LogsOptions, RemoveContainerOptions, WaitContainerOptions,
};
use futures_util::StreamExt;

use crate::error::AgentError;
use crate::sandbox_egress::{SandboxEgressContext, SandboxEgressProxy};
use crate::tool::ToolResult;

const DEFAULT_IMAGE: &str = "debian:bookworm-slim";
const MEMORY_LIMIT: i64 = 512 * 1024 * 1024; // 512 MB
const PIDS_LIMIT: i64 = 256;

/// Sandbox mode for tool execution.
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

    /// The OCI runtime name to pass to Docker, or None for the default (runc).
    pub(crate) fn runtime_name(self) -> Option<String> {
        match self {
            Self::GVisor => Some("runsc".to_string()),
            _ => None,
        }
    }
}

/// Which interpreter the `exec` tool uses when running commands on
/// the host (i.e. when `SandboxMode::Off` is configured).
///
/// `Auto` is the default and the only sensible choice for
/// cross-platform skill portability: on unix it always resolves to
/// `Sh`; on windows it probes PATH in order `sh > powershell > cmd`
/// so that a skill written against POSIX shell semantics keeps
/// working when the operator has Git for Windows installed.
///
/// Operators can pin a specific shell via `sandbox.json`'s `shell`
/// field if their skill set assumes a particular interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShellMode {
    /// Probe PATH at exec time. `sh > powershell > cmd` on windows;
    /// always `sh` on unix.
    #[default]
    Auto,
    /// POSIX `sh -c`. Available everywhere on unix, and on windows
    /// when Git for Windows (or another sh implementation) is on
    /// PATH.
    Sh,
    /// PowerShell: prefers `pwsh.exe` (PowerShell Core) and falls
    /// back to `powershell.exe` (Windows PowerShell 5.1) via
    /// `-Command`.
    Powershell,
    /// `cmd.exe /C`. Windows-native, semantically distinct from sh.
    Cmd,
}

impl ShellMode {
    pub fn from_str_config(s: &str) -> Self {
        match s {
            "auto" => Self::Auto,
            "sh" => Self::Sh,
            "powershell" | "pwsh" => Self::Powershell,
            "cmd" => Self::Cmd,
            "" => Self::default(),
            _ => {
                tracing::warn!("Unknown exec shell '{s}', falling back to auto");
                Self::Auto
            }
        }
    }

    /// Resolve to a concrete shell invocation by probing PATH.
    /// Returns `None` if no candidate executable is found, in which
    /// case the `exec` tool refuses rather than guessing.
    pub fn resolve(self) -> Option<ResolvedShell> {
        match self {
            Self::Auto => auto_resolve(),
            Self::Sh => find_executable("sh").map(|p| ResolvedShell {
                program: p,
                arg_flag: "-c",
                kind: ShellKind::Sh,
            }),
            Self::Powershell => find_executable("pwsh")
                .or_else(|| find_executable("powershell"))
                .map(|p| ResolvedShell {
                    program: p,
                    arg_flag: "-Command",
                    kind: ShellKind::Powershell,
                }),
            Self::Cmd => find_executable("cmd").map(|p| ResolvedShell {
                program: p,
                arg_flag: "/C",
                kind: ShellKind::Cmd,
            }),
        }
    }
}

/// A resolved shell invocation: which program to run and which flag
/// it expects before the command string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedShell {
    pub program: std::path::PathBuf,
    pub arg_flag: &'static str,
    pub kind: ShellKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Sh,
    Powershell,
    Cmd,
}

impl std::fmt::Display for ShellKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sh => write!(f, "sh"),
            Self::Powershell => write!(f, "powershell"),
            Self::Cmd => write!(f, "cmd"),
        }
    }
}

#[cfg(unix)]
fn auto_resolve() -> Option<ResolvedShell> {
    // sh is part of the POSIX baseline; assume it's at /bin/sh and
    // let Command resolve via PATH if it isn't.
    Some(ResolvedShell {
        program: std::path::PathBuf::from("sh"),
        arg_flag: "-c",
        kind: ShellKind::Sh,
    })
}

#[cfg(windows)]
fn auto_resolve() -> Option<ResolvedShell> {
    if let Some(p) = find_executable("sh") {
        return Some(ResolvedShell {
            program: p,
            arg_flag: "-c",
            kind: ShellKind::Sh,
        });
    }
    if let Some(p) = find_executable("pwsh").or_else(|| find_executable("powershell")) {
        return Some(ResolvedShell {
            program: p,
            arg_flag: "-Command",
            kind: ShellKind::Powershell,
        });
    }
    if let Some(p) = find_executable("cmd") {
        return Some(ResolvedShell {
            program: p,
            arg_flag: "/C",
            kind: ShellKind::Cmd,
        });
    }
    None
}

/// Walk PATH for an executable named `name`. On windows, tries
/// `name`, `name.exe`, `name.cmd`, `name.bat` in each directory.
fn find_executable(name: &str) -> Option<std::path::PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    let extensions: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_env) {
        for ext in extensions {
            let candidate = if ext.is_empty() {
                dir.join(name)
            } else {
                dir.join(format!("{name}{ext}"))
            };
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Configuration for the sandbox.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub mode: SandboxMode,
    pub image: String,
    pub timeout_secs: u64,
    /// Allow network access from sandbox (default: false).
    pub network: bool,
    /// Which interpreter the host-exec fallback uses when
    /// `SandboxMode::Off` is configured. Default `Auto`.
    pub shell: ShellMode,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: SandboxMode::ExecOnly,
            image: DEFAULT_IMAGE.into(),
            timeout_secs: 300,
            network: false,
            shell: ShellMode::Auto,
        }
    }
}

/// Docker sandbox executor.
pub struct DockerSandbox {
    client: Docker,
    config: SandboxConfig,
}

/// The per-exec egress plumbing: the internal network the container
/// joins and the proxy that is its only reachable endpoint. Held for
/// the duration of one `exec` and torn down with it.
struct EgressSetup {
    network_name: String,
    proxy: SandboxEgressProxy,
}

impl DockerSandbox {
    /// Connect to the Docker daemon.
    pub fn new(config: SandboxConfig) -> Result<Self, AgentError> {
        let client = Docker::connect_with_local_defaults()
            .map_err(|e| AgentError::Sandbox(format!("Docker connect: {e}")))?;
        Ok(Self { client, config })
    }

    /// Execute a command inside an ephemeral container.
    /// The workspace is bind-mounted at /workspace.
    ///
    /// `egress` carries the channel's egress policy plus the
    /// attribution this exec's denials are recorded under. `None`,
    /// or a policy whose mode is `none`, runs the container with no
    /// networking at all: the proxy path is entered only when the
    /// operator configured reach for this channel.
    pub async fn exec(
        &self,
        command: &str,
        workspace: &Path,
        egress: Option<&SandboxEgressContext>,
    ) -> Result<ToolResult, AgentError> {
        let workspace_str = workspace
            .canonicalize()
            .unwrap_or_else(|_| workspace.to_path_buf())
            .to_string_lossy()
            .to_string();

        // Provision the internal network and this exec's proxy
        // before the container exists, so the container is never
        // startable without the enforcement point already up. Both
        // are torn down on every exit path below.
        let egress_setup = match egress.filter(|c| c.policy.mode.needs_proxy()) {
            Some(ctx) => Some(self.provision_egress(ctx).await?),
            None => None,
        };
        let network_name = egress_setup.as_ref().map(|s| s.network_name.as_str());
        let env = egress_setup.as_ref().map(|s| {
            let url = s.proxy.proxy_url();
            vec![
                format!("HTTP_PROXY={url}"),
                format!("HTTPS_PROXY={url}"),
                format!("http_proxy={url}"),
                format!("https_proxy={url}"),
                // An inherited NO_PROXY would carve holes in the
                // allowlist for whatever it names; pin it empty.
                "NO_PROXY=".to_string(),
                "no_proxy=".to_string(),
            ]
        });

        let container_config = ContainerCreateBody {
            image: Some(self.config.image.clone()),
            cmd: Some(vec!["sh".into(), "-c".into(), command.into()]),
            working_dir: Some("/workspace".into()),
            user: Some("1000:1000".into()),
            env,
            host_config: Some(build_host_config(
                &self.config,
                &workspace_str,
                network_name,
            )),
            ..Default::default()
        };

        let result = self.run_container(container_config).await;

        // Tear down unconditionally. The proxy dies with its handle;
        // the network needs an explicit removal, and leaking one per
        // exec would exhaust Docker's address pool.
        if let Some(setup) = egress_setup {
            self.teardown_egress(setup).await;
        }
        result
    }

    /// Create, run, and reap one container. Split from [`Self::exec`]
    /// so every early return there still passes through the egress
    /// teardown.
    async fn run_container(
        &self,
        container_config: ContainerCreateBody,
    ) -> Result<ToolResult, AgentError> {
        let container_name = format!("wirken-sandbox-{}", short_id());

        let create_opts = CreateContainerOptions {
            name: Some(container_name.clone()),
            platform: String::new(),
        };

        let container = self
            .client
            .create_container(Some(create_opts), container_config)
            .await
            .map_err(|e| AgentError::Sandbox(format!("create container: {e}")))?;

        self.client
            .start_container(&container.id, None)
            .await
            .map_err(|e| AgentError::Sandbox(format!("start container: {e}")))?;

        // Wait for container to finish, with timeout.
        // Bollard surfaces any container exit with status_code > 0
        // as `DockerContainerWaitError`; treat it as a successful
        // wait with a non-zero exit code rather than a sandbox error.
        let timeout = std::time::Duration::from_secs(self.config.timeout_secs);
        let wait_result = tokio::time::timeout(timeout, async {
            let mut stream = self.client.wait_container(
                &container.id,
                Some(WaitContainerOptions {
                    condition: "not-running".into(),
                }),
            );
            if let Some(result) = stream.next().await {
                match result {
                    Ok(exit) => return Ok(exit.status_code),
                    Err(bollard::errors::Error::DockerContainerWaitError { code, .. }) => {
                        return Ok(code);
                    }
                    Err(e) => return Err(AgentError::Sandbox(format!("wait: {e}"))),
                }
            }
            Ok(0i64)
        })
        .await;

        let exit_code = match wait_result {
            Ok(Ok(code)) => code,
            Ok(Err(e)) => {
                let _ = self.kill_and_remove(&container.id).await;
                return Err(e);
            }
            Err(_) => {
                let _ = self.kill_and_remove(&container.id).await;
                return Ok(ToolResult {
                    output: format!(
                        "Command timed out after {}s (sandbox)",
                        self.config.timeout_secs
                    ),
                    success: false,
                });
            }
        };

        // Collect logs
        let mut stdout = String::new();
        let mut stderr = String::new();

        let mut log_stream = self.client.logs(
            &container.id,
            Some(LogsOptions {
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );

        while let Some(log) = log_stream.next().await {
            match log {
                Ok(LogOutput::StdOut { message }) => {
                    stdout.push_str(&String::from_utf8_lossy(&message));
                }
                Ok(LogOutput::StdErr { message }) => {
                    stderr.push_str(&String::from_utf8_lossy(&message));
                }
                _ => {}
            }
        }

        // Cleanup — auto_remove is off so logs can be collected; we
        // must remove the container explicitly here.
        let _ = self.kill_and_remove(&container.id).await;

        let mut result = String::new();
        if !stdout.is_empty() {
            result.push_str(&stdout);
        }
        if !stderr.is_empty() {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str("[stderr] ");
            result.push_str(&stderr);
        }
        if result.is_empty() {
            result.push_str("(no output)");
        }

        if result.len() > 32_000 {
            result.truncate(32_000);
            result.push_str("\n... (truncated)");
        }

        Ok(ToolResult {
            output: result,
            success: exit_code == 0,
        })
    }

    /// Create this exec's internal network and start its proxy.
    ///
    /// Every failure here is an error, never a downgrade to an
    /// unproxied container: an operator who configured egress for a
    /// channel must not silently get either wide-open networking or
    /// a silently network-less sandbox because network creation
    /// failed.
    async fn provision_egress(
        &self,
        ctx: &SandboxEgressContext,
    ) -> Result<EgressSetup, AgentError> {
        let network_name = format!("wirken-egress-{}", short_id());

        let mut options = std::collections::HashMap::new();
        // Close inter-container reach. Each exec gets its own
        // network so there is normally no sibling to reach, but a
        // network is a namespace an operator or a future code path
        // could attach something else to; ICC off makes the
        // isolation a property of the network rather than of the
        // current call pattern.
        options.insert(
            "com.docker.network.bridge.enable_icc".to_string(),
            "false".to_string(),
        );
        // No NAT for this bridge. `Internal` already withholds the
        // route; dropping masquerade means a rule added elsewhere
        // cannot turn the bridge into a working exit on its own.
        options.insert(
            "com.docker.network.bridge.enable_ip_masquerade".to_string(),
            "false".to_string(),
        );

        self.client
            .create_network(NetworkCreateRequest {
                name: network_name.clone(),
                driver: Some("bridge".to_string()),
                internal: Some(true),
                attachable: Some(false),
                enable_ipv6: Some(false),
                options: Some(options),
                ..Default::default()
            })
            .await
            .map_err(|e| AgentError::Sandbox(format!("create egress network: {e}")))?;

        let gateway = match self.network_gateway(&network_name).await {
            Ok(gw) => gw,
            Err(e) => {
                let _ = self.client.remove_network(&network_name).await;
                return Err(e);
            }
        };

        let proxy = match SandboxEgressProxy::bind(gateway, ctx.clone()).await {
            Ok(p) => p,
            Err(e) => {
                let _ = self.client.remove_network(&network_name).await;
                // The usual cause is a rootless container runtime
                // (rootless Podman), where the bridge lives in a
                // separate network namespace and its gateway address
                // is not a host interface, so a host-side listener
                // cannot claim it. Named explicitly because the bare
                // OS error ("cannot assign requested address") does
                // not point anywhere useful.
                return Err(AgentError::Sandbox(format!(
                    "bind egress proxy on {gateway}: {e}. Sandbox egress modes \
                     'allowlist' and 'open' need a container runtime whose bridge \
                     gateway is a host interface (rootful Docker). Under a rootless \
                     runtime, set the channel's egress mode to 'none'."
                )));
            }
        };

        tracing::info!(
            "sandbox egress proxy listening on {} for network {network_name} (mode={})",
            proxy.addr(),
            ctx.policy.mode.as_str(),
        );
        Ok(EgressSetup {
            network_name,
            proxy,
        })
    }

    /// Read the gateway address Docker assigned to the network's
    /// bridge. This is the only address the container can reach, and
    /// therefore where the proxy must listen.
    async fn network_gateway(&self, network_name: &str) -> Result<std::net::IpAddr, AgentError> {
        let inspect = self
            .client
            .inspect_network(network_name, None)
            .await
            .map_err(|e| AgentError::Sandbox(format!("inspect egress network: {e}")))?;
        inspect
            .ipam
            .and_then(|ipam| ipam.config)
            .and_then(|configs| {
                configs
                    .into_iter()
                    .find_map(|c| c.gateway.and_then(|g| g.parse::<std::net::IpAddr>().ok()))
            })
            .ok_or_else(|| {
                AgentError::Sandbox(format!(
                    "egress network {network_name} reported no usable gateway address"
                ))
            })
    }

    /// Drop the proxy and remove the network. Best-effort: the
    /// container is already gone by this point, so a failure here
    /// leaks a Docker object rather than leaving reach open.
    async fn teardown_egress(&self, setup: EgressSetup) {
        drop(setup.proxy);
        if let Err(e) = self.client.remove_network(&setup.network_name).await {
            tracing::warn!(
                "could not remove egress network {}: {e}",
                setup.network_name
            );
        }
    }

    async fn kill_and_remove(&self, id: &str) {
        let _ = self.client.kill_container(id, None).await;
        let _ = self
            .client
            .remove_container(
                id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
    }

    /// Check if Docker is available.
    pub async fn check(&self) -> Result<String, AgentError> {
        let version = self
            .client
            .version()
            .await
            .map_err(|e| AgentError::Sandbox(format!("Docker version: {e}")))?;

        let ver_str = version.version.unwrap_or_else(|| "unknown".into());
        Ok(format!("Docker {ver_str}"))
    }
}

/// Build the `HostConfig` for a sandboxed exec. Extracted so the
/// hardening settings can be asserted without spinning up Docker.
///
/// Kernel-level hardening, in addition to the memory, PID, network,
/// and user caps already set below:
///
/// * `cap_drop=ALL`: strip every Linux capability. The agent never
///   needs `CAP_NET_BIND_SERVICE`, `CAP_CHOWN`, etc. If a real use
///   case breaks this, re-evaluate rather than loosening by default.
/// * `no-new-privileges`: block setuid/setgid elevation inside the
///   container. Pairs with `cap_drop`.
/// * seccomp: rely on Docker's default seccomp profile. Docker
///   applies it automatically when no seccomp SecurityOpt is set;
///   the string `seccomp=default` is not a valid option and causes
///   the daemon to reject container start.
/// * `readonly_rootfs`: make the container's `/` read-only. The
///   workspace bind-mount stays RW, and a tmpfs at `/tmp` gives the
///   shell somewhere to scratch.
/// * `egress_network`: when `Some`, the container joins that Docker
///   network instead of running with no networking. The network is
///   created `Internal` with inter-container communication off, so
///   the only address it can reach is the gateway where this exec's
///   egress proxy listens. DNS is pinned to an address with nothing
///   behind it: the container must not resolve names itself, because
///   the proxy resolves them after the allowlist decision.
pub(crate) fn build_host_config(
    config: &SandboxConfig,
    workspace_str: &str,
    egress_network: Option<&str>,
) -> HostConfig {
    // Egress-network mode wins over the legacy `network` bool: the
    // proxy path is the bounded one, and letting `network: true`
    // widen it back to unrestricted host networking would defeat the
    // allowlist the operator configured.
    let network_mode = match (egress_network, config.network) {
        (Some(name), _) => Some(name.to_string()),
        (None, true) => None,
        (None, false) => Some("none".to_string()),
    };
    // Only meaningful on the egress-network path; harmless otherwise
    // since `--network none` has no resolver to point anywhere.
    let dns = egress_network.map(|_| vec!["127.0.0.1".to_string()]);
    let tmpfs_mounts: std::collections::HashMap<String, String> = {
        let mut m = std::collections::HashMap::new();
        m.insert("/tmp".into(), "size=64m,mode=1777".into());
        m
    };
    HostConfig {
        binds: Some(vec![format!("{workspace_str}:/workspace:rw")]),
        network_mode,
        dns,
        memory: Some(MEMORY_LIMIT),
        pids_limit: Some(PIDS_LIMIT),
        // With auto_remove=true the container is torn down the
        // moment it exits, which races the post-wait `logs` call and
        // leaves no output to return to the agent. Rely on the
        // explicit `kill_and_remove` cleanup instead.
        auto_remove: Some(false),
        runtime: config.mode.runtime_name(),
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

/// Detect if Docker is available.
pub async fn detect_runtime() -> Option<String> {
    if let Ok(docker) = Docker::connect_with_local_defaults()
        && docker.version().await.is_ok()
    {
        return Some("docker".into());
    }
    None
}

/// Detect whether the given image is present locally. Returns false
/// if Docker is unreachable or the image is not pulled. Used by the
/// Docker-backed integration tests to skip cleanly when the sandbox
/// base image has not been pulled on the host (CI runners, for
/// example, do not pre-pull `debian:bookworm-slim`).
pub async fn detect_image(image: &str) -> bool {
    let Ok(docker) = Docker::connect_with_local_defaults() else {
        return false;
    };
    docker.inspect_image(image).await.is_ok()
}

/// Detect if gVisor (runsc) is available as a Docker runtime.
/// Checks both that Docker is running and that `runsc` is listed in its runtimes.
pub async fn detect_gvisor() -> bool {
    let Ok(docker) = Docker::connect_with_local_defaults() else {
        return false;
    };
    let Ok(info) = docker.info().await else {
        return false;
    };
    // Docker info returns runtimes as a map. Check if "runsc" is a key.
    if let Some(runtimes) = info.runtimes {
        return runtimes.contains_key("runsc");
    }
    false
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}
