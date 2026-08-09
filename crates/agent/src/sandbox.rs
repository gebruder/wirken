//! Docker/Podman sandbox for tool execution.

use std::path::Path;

use bollard::Docker;
use bollard::container::LogOutput;
use bollard::models::ContainerCreateBody;
use bollard::models::HostConfig;
#[cfg(unix)]
use bollard::models::NetworkCreateRequest;
use bollard::query_parameters::{
    CreateContainerOptions, LogsOptions, RemoveContainerOptions, WaitContainerOptions,
};
use futures_util::StreamExt;

use crate::error::AgentError;
#[cfg(unix)]
use crate::sandbox_egress::SandboxEgressBroker;
use crate::sandbox_egress::SandboxEgressContext;
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
    /// Binary the egress sidecar container runs, bind-mounted into
    /// it read-only. `None` means this process's own executable,
    /// which is the shipping shape: wirken releases are statically
    /// linked, so the gateway can mount itself into any image. A
    /// dynamically linked development build cannot run in the
    /// sandbox image, so this override exists for those builds and
    /// for the live tests.
    pub sidecar_binary: Option<std::path::PathBuf>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: SandboxMode::ExecOnly,
            image: DEFAULT_IMAGE.into(),
            timeout_secs: 300,
            network: false,
            shell: ShellMode::Auto,
            sidecar_binary: None,
        }
    }
}

/// Docker sandbox executor.
pub struct DockerSandbox {
    client: Docker,
    config: SandboxConfig,
}

#[cfg(unix)]
/// The per-exec egress plumbing. Held for one `exec` and torn down
/// with it.
///
/// Two networks, because the sandbox and its proxy need different
/// reach. `internal_network` is `Internal`, so nothing on it has a
/// route off the host; the sandbox joins only this one. The sidecar
/// joins it too, plus `egress_network`, which is an ordinary bridge
/// and is the only path to the internet. The sandbox therefore cannot
/// reach anything except the sidecar, and the sidecar is the only
/// thing that can reach out.
struct EgressSetup {
    internal_network: String,
    egress_network: String,
    sidecar_id: String,
    socket_dir: std::path::PathBuf,
    /// Unix-only: the decision broker listens on a Unix socket, and
    /// `provision_egress` refuses before constructing this on other
    /// platforms.
    #[cfg(unix)]
    broker: SandboxEgressBroker,
    sidecar_ip: std::net::IpAddr,
}

#[cfg(unix)]
impl EgressSetup {
    /// Address the sandbox is handed as `HTTP_PROXY`: the sidecar's
    /// address on the internal network. No host port is involved.
    fn proxy_url(&self) -> String {
        format!("http://{}:{}", self.sidecar_ip, SIDECAR_PORT)
    }
}

#[cfg(unix)]
/// Port the sidecar listens on inside the internal network. Fixed
/// rather than ephemeral: it is a container-private port on a
/// per-exec network, so there is nothing to collide with, and the
/// sandbox needs to be told the address before the sidecar starts.
const SIDECAR_PORT: u16 = 3128;

#[cfg(unix)]
/// How long to wait for the sidecar to report its listener is up.
const SIDECAR_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
        #[cfg(unix)]
        let egress_setup = match egress.filter(|c| c.policy.mode.needs_proxy()) {
            Some(ctx) => Some(self.provision_egress(ctx).await?),
            None => None,
        };
        // Platforms without the broker transport refuse here. The
        // refusal is recorded before it is returned; see
        // `provision_egress`.
        #[cfg(not(unix))]
        if let Some(ctx) = egress.filter(|c| c.policy.mode.needs_proxy()) {
            return Err(self.refuse_egress(ctx));
        }
        // Fail closed one last time before the sandbox exists: if
        // the sidecar died between reporting ready and now, refuse
        // rather than start a sandbox whose only route is gone.
        #[cfg(unix)]
        if let Some(setup) = egress_setup.as_ref()
            && let Err(e) = self.assert_sidecar_running(&setup.sidecar_id).await
        {
            let setup = egress_setup.expect("checked above");
            self.teardown_egress(setup).await;
            return Err(e);
        }
        #[cfg(unix)]
        let network_name = egress_setup.as_ref().map(|s| s.internal_network.as_str());
        #[cfg(not(unix))]
        let network_name: Option<&str> = None;
        #[cfg(unix)]
        let env = egress_setup.as_ref().map(|s| {
            let url = s.proxy_url();
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
        #[cfg(not(unix))]
        let env: Option<Vec<String>> = None;

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
        #[cfg(unix)]
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

    /// Create this exec's two networks, start its sidecar proxy, and
    /// bring up the host-side decision broker.
    ///
    /// Every failure is an error, never a downgrade to an unproxied
    /// container: an operator who configured egress must not silently
    /// get either wide-open networking or a network-less sandbox.
    #[cfg(not(unix))]
    fn refuse_egress(&self, ctx: &SandboxEgressContext) -> AgentError {
        // The broker carries decisions over a bind-mounted Unix
        // socket, which has no equivalent here. Refuse rather than
        // run the sandbox unproxied: a channel configured for egress
        // must not silently get either wide-open networking or a
        // silently network-less sandbox.
        //
        // The refusal goes on the hash chain, not just to stderr. An
        // operator on this platform has a channel configured for
        // egress that will never carry any, and that belongs in the
        // audit log with the rest of the enforcement record. Recorded
        // once per refused exec, since nothing reaches a proxy here.
        ctx.record_unsupported();
        AgentError::Sandbox(
            "sandbox egress modes 'allowlist' and 'open' are unavailable on this platform: \
             the decision broker needs a Unix socket. Refusing the exec rather than running \
             it unproxied; set the channel's egress mode to 'none'"
                .into(),
        )
    }

    #[cfg(unix)]
    async fn provision_egress(
        &self,
        ctx: &SandboxEgressContext,
    ) -> Result<EgressSetup, AgentError> {
        // Resolve the sidecar binary before allocating anything.
        // This is the one check that can fail on pure configuration,
        // and doing it first means the fail-closed path leaves no
        // network, socket, or container behind.
        let sidecar_binary = self.sidecar_binary()?;

        let id = short_id();
        let internal_network = format!("wirken-egress-{id}");
        let egress_network = format!("wirken-egress-out-{id}");

        // Inter-container communication stays enabled on the internal
        // network: the sandbox reaching its sidecar is the whole
        // point, and that traffic is container-to-container. The
        // isolation comes from the network being `Internal` and
        // per-exec, so the only peer on it is this sandbox's own
        // sidecar.
        self.client
            .create_network(NetworkCreateRequest {
                name: internal_network.clone(),
                driver: Some("bridge".to_string()),
                internal: Some(true),
                attachable: Some(false),
                enable_ipv6: Some(false),
                ..Default::default()
            })
            .await
            .map_err(|e| AgentError::Sandbox(format!("create internal network: {e}")))?;

        if let Err(e) = self
            .client
            .create_network(NetworkCreateRequest {
                name: egress_network.clone(),
                driver: Some("bridge".to_string()),
                enable_ipv6: Some(false),
                ..Default::default()
            })
            .await
        {
            let _ = self.client.remove_network(&internal_network).await;
            return Err(AgentError::Sandbox(format!("create egress network: {e}")));
        }

        let cleanup_networks = || async {
            let _ = self.client.remove_network(&internal_network).await;
            let _ = self.client.remove_network(&egress_network).await;
        };

        // Per-exec directory holding the broker socket. Bind-mounted
        // into the sidecar, so the sidecar reaches the host over the
        // filesystem rather than the network and no host port exists.
        let socket_dir = std::env::temp_dir().join(format!("wirken-egress-{id}"));
        if let Err(e) = std::fs::create_dir_all(&socket_dir) {
            cleanup_networks().await;
            return Err(AgentError::Sandbox(format!(
                "create egress socket dir {}: {e}",
                socket_dir.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o777));
        }
        let socket_path = socket_dir.join("egress.sock");

        let mut broker = match SandboxEgressBroker::bind(socket_path.clone(), ctx.clone()).await {
            Ok(b) => b,
            Err(e) => {
                cleanup_networks().await;
                let _ = std::fs::remove_dir_all(&socket_dir);
                return Err(AgentError::Sandbox(format!(
                    "bind egress decision broker at {}: {e}",
                    socket_path.display()
                )));
            }
        };

        let sidecar_name = format!("wirken-egress-sidecar-{id}");
        let sidecar_config = ContainerCreateBody {
            image: Some(self.config.image.clone()),
            cmd: Some(vec![
                "/wirken-sidecar".into(),
                "egress-sidecar".into(),
                "--socket".into(),
                "/run/wirken-egress/egress.sock".into(),
                "--listen".into(),
                format!("0.0.0.0:{SIDECAR_PORT}"),
            ]),
            host_config: Some(HostConfig {
                binds: Some(vec![
                    format!("{}:/wirken-sidecar:ro", sidecar_binary.display()),
                    format!("{}:/run/wirken-egress:rw", socket_dir.display()),
                ]),
                network_mode: Some(internal_network.clone()),
                memory: Some(MEMORY_LIMIT),
                pids_limit: Some(PIDS_LIMIT),
                auto_remove: Some(false),
                cap_drop: Some(vec!["ALL".into()]),
                cap_add: Some(Vec::new()),
                security_opt: Some(vec!["no-new-privileges:true".into()]),
                readonly_rootfs: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        let created = match self
            .client
            .create_container(
                Some(CreateContainerOptions {
                    name: Some(sidecar_name.clone()),
                    platform: String::new(),
                }),
                sidecar_config,
            )
            .await
        {
            Ok(c) => c,
            Err(e) => {
                cleanup_networks().await;
                let _ = std::fs::remove_dir_all(&socket_dir);
                return Err(AgentError::Sandbox(format!("create egress sidecar: {e}")));
            }
        };

        // Second network for the sidecar's own outbound reach. The
        // sandbox never joins it.
        if let Err(e) = self
            .client
            .connect_network(
                &egress_network,
                bollard::models::NetworkConnectRequest {
                    container: created.id.clone(),
                    ..Default::default()
                },
            )
            .await
        {
            let _ = self.kill_and_remove(&created.id).await;
            cleanup_networks().await;
            let _ = std::fs::remove_dir_all(&socket_dir);
            return Err(AgentError::Sandbox(format!(
                "attach sidecar to egress network: {e}"
            )));
        }

        if let Err(e) = self.client.start_container(&created.id, None).await {
            let _ = self.kill_and_remove(&created.id).await;
            cleanup_networks().await;
            let _ = std::fs::remove_dir_all(&socket_dir);
            return Err(AgentError::Sandbox(format!("start egress sidecar: {e}")));
        }

        if let Err(e) = broker.await_sidecar(SIDECAR_READY_TIMEOUT).await {
            let logs = self.container_logs(&created.id).await;
            let _ = self.kill_and_remove(&created.id).await;
            cleanup_networks().await;
            let _ = std::fs::remove_dir_all(&socket_dir);
            return Err(AgentError::Sandbox(format!(
                "egress sidecar never became ready: {e}. Sidecar output: {logs}"
            )));
        }

        let sidecar_ip = match self.container_ip(&created.id, &internal_network).await {
            Ok(ip) => ip,
            Err(e) => {
                let _ = self.kill_and_remove(&created.id).await;
                cleanup_networks().await;
                let _ = std::fs::remove_dir_all(&socket_dir);
                return Err(e);
            }
        };

        tracing::info!(
            "sandbox egress sidecar {sidecar_name} ready at {sidecar_ip}:{SIDECAR_PORT} \
             on {internal_network} (mode={})",
            ctx.policy.mode.as_str(),
        );

        Ok(EgressSetup {
            internal_network,
            egress_network,
            sidecar_id: created.id,
            socket_dir,
            broker,
            sidecar_ip,
        })
    }

    #[cfg(unix)]
    /// Path to the binary the sidecar container runs.
    ///
    /// Defaults to this process's own executable, which is the
    /// shipping shape: wirken releases are statically linked, so the
    /// gateway can mount itself into any image. A dynamically linked
    /// development build cannot run in the sandbox image, so
    /// `sandbox.json`'s `sidecar_binary` overrides the path, which is
    /// also what lets the live tests exercise this path without a
    /// release build.
    fn sidecar_binary(&self) -> Result<std::path::PathBuf, AgentError> {
        if let Some(p) = &self.config.sidecar_binary {
            if !p.exists() {
                return Err(AgentError::Sandbox(format!(
                    "configured sidecar_binary {} does not exist; refusing to run \
                     exec without an egress proxy",
                    p.display()
                )));
            }
            return Ok(p.clone());
        }
        std::env::current_exe().map_err(|e| {
            AgentError::Sandbox(format!(
                "cannot resolve own executable for the sidecar: {e}"
            ))
        })
    }

    #[cfg(unix)]
    /// Refuse if the sidecar is not running. Called immediately
    /// before the sandbox is created.
    async fn assert_sidecar_running(&self, id: &str) -> Result<(), AgentError> {
        let running = self
            .client
            .inspect_container(
                id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
            .ok()
            .and_then(|c| c.state)
            .and_then(|s| s.running)
            .unwrap_or(false);
        if running {
            Ok(())
        } else {
            Err(AgentError::Sandbox(
                "egress sidecar is not running; refusing to exec rather than run \
                 without an egress proxy"
                    .into(),
            ))
        }
    }

    #[cfg(unix)]
    /// The container's address on `network`, which is what the
    /// sandbox is pointed at.
    async fn container_ip(&self, id: &str, network: &str) -> Result<std::net::IpAddr, AgentError> {
        self.client
            .inspect_container(
                id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
            .ok()
            .and_then(|c| c.network_settings)
            .and_then(|n| n.networks)
            .and_then(|nets| nets.get(network).and_then(|e| e.ip_address.clone()))
            .and_then(|ip| ip.parse().ok())
            .ok_or_else(|| {
                AgentError::Sandbox(format!("egress sidecar reported no address on {network}"))
            })
    }

    #[cfg(unix)]
    /// Best-effort log capture, used to explain a sidecar that never
    /// reported ready.
    async fn container_logs(&self, id: &str) -> String {
        let mut out = String::new();
        let mut stream = self.client.logs(
            id,
            Some(LogsOptions {
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );
        while let Some(Ok(chunk)) = stream.next().await {
            out.push_str(&chunk.to_string());
            if out.len() > 2_000 {
                break;
            }
        }
        out.trim().to_string()
    }

    #[cfg(unix)]
    /// Drop the broker, stop the sidecar, and remove both networks
    /// and the socket directory. Best-effort: the sandbox is already
    /// gone, so a failure here leaks a Docker object rather than
    /// leaving reach open.
    async fn teardown_egress(&self, setup: EgressSetup) {
        self.kill_and_remove(&setup.sidecar_id).await;
        #[cfg(unix)]
        drop(setup.broker);
        for net in [&setup.internal_network, &setup.egress_network] {
            if let Err(e) = self.client.remove_network(net).await {
                tracing::warn!("could not remove egress network {net}: {e}");
            }
        }
        if let Err(e) = std::fs::remove_dir_all(&setup.socket_dir) {
            tracing::warn!(
                "could not remove egress socket dir {}: {e}",
                setup.socket_dir.display()
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
