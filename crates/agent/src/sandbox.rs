//! Docker/Podman sandbox for tool execution.
//!
//! Every container an `exec` creates, and its egress sidecar and
//! networks, carry labels naming this data directory's instance and the
//! process that started them. They are removed when the call returns,
//! and from `Drop` when the call's future is dropped first, as when a
//! turn is aborted. [`sweep_leftovers`] removes what a process that
//! ended without either left behind.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{LazyLock, Mutex, PoisonError};

use bollard::Docker;
use bollard::container::LogOutput;
use bollard::models::ContainerCreateBody;
use bollard::models::HostConfig;
use bollard::query_parameters::{
    CreateContainerOptions, ListContainersOptions, ListNetworksOptions, LogsOptions,
    RemoveContainerOptions, WaitContainerOptions,
};
use futures_util::StreamExt;

#[cfg(unix)]
use wirken_sandbox::egress_net::{EgressRoute, SidecarSpec};

use crate::error::AgentError;
use crate::sandbox_egress::SandboxEgressContext;
use crate::tool::ToolResult;

const DEFAULT_IMAGE: &str = "debian:bookworm-slim";

/// Marks an `exec` container, its egress sidecar and its networks.
pub const LABEL_ROLE: &str = "wirken.exec";
/// The data directory's instance; see [`SandboxConfig::instance`].
pub const LABEL_INSTANCE: &str = "wirken.exec.instance";
/// The process that created the object. The sweep leaves a live one's alone.
pub const LABEL_PID: &str = "wirken.exec.pid";
/// Sandbox mode, shared with MCP server containers.
pub use wirken_sandbox::SandboxMode;
pub(crate) use wirken_sandbox::runtime_label;
/// Container memory and PID caps, shared with MCP server containers.
/// Public so the webchat status route reports the value the sandbox
/// actually applies rather than a copy of it.
pub use wirken_sandbox::{MEMORY_LIMIT, PIDS_LIMIT};

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
    /// Names the data directory on container labels, as MCP server
    /// containers carry it. Empty labels nothing with an instance, and
    /// [`sweep_leftovers`] then removes nothing.
    pub instance: String,
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
            instance: String::new(),
        }
    }
}

/// The labels every object one `exec` creates carries.
fn exec_labels(instance: &str) -> HashMap<String, String> {
    HashMap::from([
        (LABEL_ROLE.to_string(), "1".to_string()),
        (LABEL_INSTANCE.to_string(), instance.to_string()),
        (LABEL_PID.to_string(), std::process::id().to_string()),
    ])
}

/// What one `exec` has created on the daemon. [`Self::release`] removes
/// it on every return path; `Drop` removes it when the future holding it
/// is dropped first.
struct ExecResources {
    client: Docker,
    /// The container's name, set before it is created, so a drop during
    /// the create call still reaches it.
    container: Option<String>,
    #[cfg(unix)]
    route: Option<EgressRoute>,
}

impl ExecResources {
    fn new(client: Docker) -> Self {
        Self {
            client,
            container: None,
            #[cfg(unix)]
            route: None,
        }
    }

    async fn release(mut self) {
        let client = self.client.clone();
        let container = self.container.take();
        #[cfg(unix)]
        let route = self.route.take();
        remove_container_by_id(&client, container).await;
        #[cfg(unix)]
        if let Some(route) = route {
            route.teardown(&client).await;
        }
    }
}

impl Drop for ExecResources {
    /// Must not panic: this can run while a panic unwinds.
    fn drop(&mut self) {
        let container = self.container.take();
        #[cfg(unix)]
        let route = self.route.take();
        #[cfg(unix)]
        let nothing = container.is_none() && route.is_none();
        #[cfg(not(unix))]
        let nothing = container.is_none();
        if nothing {
            return;
        }
        let client = self.client.clone();
        spawn_cleanup(async move {
            remove_container_by_id(&client, container).await;
            #[cfg(unix)]
            if let Some(route) = route {
                route.teardown(&client).await;
            }
        });
    }
}

async fn remove_container_by_id(client: &Docker, container: Option<String>) {
    let Some(id) = container else {
        return;
    };
    let _ = client.kill_container(&id, None).await;
    let _ = client
        .remove_container(
            &id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

/// Removals started from `Drop`, held so [`drain_cleanups`] can wait
/// for them before the runtime goes.
static CLEANUPS: LazyLock<Mutex<tokio::task::JoinSet<()>>> =
    LazyLock::new(|| Mutex::new(tokio::task::JoinSet::new()));

/// Run `cleanup` on the current runtime, or on a thread of its own
/// where there is none. Never panics.
fn spawn_cleanup(cleanup: impl std::future::Future<Output = ()> + Send + 'static) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let mut set = CLEANUPS.lock().unwrap_or_else(PoisonError::into_inner);
        while set.try_join_next().is_some() {}
        set.spawn_on(cleanup, &handle);
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("wirken-exec-cleanup".into())
        .spawn(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(cleanup),
                Err(e) => tracing::warn!("could not remove an exec container: {e}"),
            }
        });
    if let Err(e) = spawned {
        tracing::warn!("could not remove an exec container: {e}");
    }
}

/// Wait for every removal `Drop` started. Shutdown calls this after it
/// has stopped the turns, so the runtime does not end with one pending.
pub async fn drain_cleanups() {
    loop {
        let mut set = std::mem::take(&mut *CLEANUPS.lock().unwrap_or_else(PoisonError::into_inner));
        if set.is_empty() {
            return;
        }
        while set.join_next().await.is_some() {}
    }
}

/// Whether `pid` names a running process. Assumed so where it cannot be
/// asked, which leaves an object in place rather than removing a live
/// one.
fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return true;
        };
        // SAFETY: signal 0 performs only the existence and permission
        // check; no signal is delivered.
        let rc = unsafe { libc::kill(pid, 0) };
        rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Whether an object with these labels was left by a process that has
/// ended.
fn left_behind(labels: Option<&HashMap<String, String>>) -> bool {
    labels
        .and_then(|l| l.get(LABEL_PID))
        .and_then(|p| p.parse::<u32>().ok())
        .is_some_and(|pid| !pid_alive(pid))
}

/// [`sweep_leftovers`] against the local daemon; 0 where none answers.
pub async fn sweep_local_leftovers(instance: &str) -> usize {
    match Docker::connect_with_local_defaults() {
        Ok(docker) => sweep_leftovers(&docker, instance).await,
        Err(_) => 0,
    }
}

/// Remove the `exec` containers, sidecars and networks `instance` left
/// behind: those whose creating process has ended, as after a kill or a
/// crash. Returns how many containers. An empty `instance` removes
/// nothing.
pub async fn sweep_leftovers(docker: &Docker, instance: &str) -> usize {
    if instance.is_empty() {
        return 0;
    }
    let filters = || {
        HashMap::from([(
            "label".to_string(),
            vec![format!("{LABEL_INSTANCE}={instance}")],
        )])
    };
    let Ok(containers) = docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            filters: Some(filters()),
            ..Default::default()
        }))
        .await
    else {
        return 0;
    };
    let mut removed = 0;
    for c in containers {
        if left_behind(c.labels.as_ref()) {
            remove_container_by_id(docker, c.id).await;
            removed += 1;
        }
    }
    // Networks after containers: one with a container still attached
    // cannot be removed.
    if let Ok(networks) = docker
        .list_networks(Some(ListNetworksOptions {
            filters: Some(filters()),
        }))
        .await
    {
        for n in networks {
            if !left_behind(n.labels.as_ref()) {
                continue;
            }
            if let Some(name) = n.name
                && let Err(e) = docker.remove_network(&name).await
            {
                tracing::warn!("could not remove exec egress network {name}: {e}");
            }
        }
    }
    removed
}

/// Docker sandbox executor.
pub struct DockerSandbox {
    client: Docker,
    config: SandboxConfig,
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

        let mut resources = ExecResources::new(self.client.clone());

        // Provision the internal network and this exec's proxy
        // before the container exists, so the container is never
        // startable without the enforcement point already up. Both
        // are torn down on every exit path below.
        #[cfg(unix)]
        if let Some(ctx) = egress.filter(|c| c.policy.mode.needs_proxy()) {
            resources.route = Some(self.provision_egress(ctx).await?);
        }
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
        if let Some(route) = resources.route.as_ref()
            && !route.sidecar_running(&self.client).await
        {
            resources.release().await;
            return Err(AgentError::Sandbox(
                "egress sidecar is not running; refusing to exec rather than run \
                 without an egress proxy"
                    .into(),
            ));
        }
        #[cfg(unix)]
        let decision = egress_decision(
            egress.is_some(),
            resources
                .route
                .as_ref()
                .map(|s| s.internal_network.as_str()),
        );
        // No broker transport here, so a proxy-needing policy has
        // already refused above. A policy that needs no proxy still
        // decided, and decided deny.
        #[cfg(not(unix))]
        let decision = egress_decision(egress.is_some(), None);
        #[cfg(unix)]
        let env = resources.route.as_ref().map(EgressRoute::proxy_env);
        #[cfg(not(unix))]
        let env: Option<Vec<String>> = None;

        let container_config = ContainerCreateBody {
            image: Some(self.config.image.clone()),
            cmd: Some(vec!["sh".into(), "-c".into(), command.into()]),
            working_dir: Some("/workspace".into()),
            user: Some("1000:1000".into()),
            env,
            host_config: Some(build_host_config(&self.config, &workspace_str, decision)),
            labels: Some(exec_labels(&self.config.instance)),
            ..Default::default()
        };

        let result = self.run_container(container_config, &mut resources).await;

        // Tear down unconditionally. The proxy dies with its handle;
        // the network needs an explicit removal, and leaking one per
        // exec would exhaust Docker's address pool.
        resources.release().await;
        result
    }

    /// Create, run, and read one container. The caller removes it
    /// through `resources`, which holds its name from before the create.
    async fn run_container(
        &self,
        container_config: ContainerCreateBody,
        resources: &mut ExecResources,
    ) -> Result<ToolResult, AgentError> {
        let container_name = format!("wirken-sandbox-{}", short_id());
        resources.container = Some(container_name.clone());

        let create_opts = CreateContainerOptions {
            name: Some(container_name.clone()),
            platform: String::new(),
        };

        let runtime = runtime_label(
            container_config
                .host_config
                .as_ref()
                .and_then(|host| host.runtime.as_deref()),
        );

        let container = self
            .client
            .create_container(Some(create_opts), container_config)
            .await
            .map_err(|e| AgentError::Sandbox(format!("create container: {e}")))?;
        resources.container = Some(container.id.clone());

        // The id Docker returned for the container this command ran
        // in, not a name this process chose.
        let provenance = wirken_audit::SandboxProvenance {
            mode: self.config.mode.label(),
            runtime,
            container_id: Some(container.id.clone()),
        };

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
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Ok(ToolResult {
                    output: format!(
                        "Command timed out after {}s (sandbox)",
                        self.config.timeout_secs
                    ),
                    success: false,
                    sandbox: Some(provenance),
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
            sandbox: Some(provenance),
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
    ) -> Result<EgressRoute, AgentError> {
        // Resolve the sidecar binary before allocating anything.
        // This is the one check that can fail on pure configuration,
        // and doing it first means the fail-closed path leaves no
        // network, socket, or container behind.
        let sidecar_binary = self.sidecar_binary()?;

        // A runtime that cannot be asked is taken as rootful. Were it
        // rootless, the sidecar's uid would not be the operator's, it
        // could not open the socket, and the exec is refused when the
        // sidecar never reports ready.
        let rootless = wirken_sandbox::RuntimeFacts::probe(&self.client)
            .await
            .is_ok_and(|f| f.rootless);
        let mut spec = exec_sidecar_spec(
            short_id(),
            self.config.image.clone(),
            sidecar_binary,
            rootless,
        );
        spec.labels = exec_labels(&self.config.instance);
        let route = wirken_sandbox::egress_net::provision(
            &self.client,
            spec,
            std::sync::Arc::new(ctx.clone()),
        )
        .await
        .map_err(AgentError::Sandbox)?;
        tracing::info!(
            "sandbox egress for exec on {} (mode={})",
            route.internal_network,
            ctx.policy.mode.as_str(),
        );
        Ok(route)
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

/// Which of the three states this exec is in.
///
/// `policy_present` is whether a `SandboxEgressContext` reached
/// `exec`; `proxy_network` is the internal network of the provisioned
/// proxy, which exists only for a policy whose mode needs one. A
/// policy present with no proxy network is therefore a policy that
/// granted no egress: a decision, not an absence, and the distinction
/// the two-state form could not carry.
///
/// Takes the network name rather than the `EgressSetup` that carries
/// it, because that struct is unix-only and this mapping is not.
///
/// Its own function so the mapping is reachable without Docker. The
/// three-state type alone does not prevent the collapse; something has
/// to assert that a deny policy is read as `Denied` rather than folded
/// back into `Unset`, and that assertion needs a callable seam.
pub(crate) fn egress_decision(
    policy_present: bool,
    proxy_network: Option<&str>,
) -> EgressDecision<'_> {
    match (policy_present, proxy_network) {
        (_, Some(network)) => EgressDecision::Proxied(network),
        (true, None) => EgressDecision::Denied,
        (false, None) => EgressDecision::Unset,
    }
}

/// What the egress layer decided about this exec's network, as three
/// states rather than two.
///
/// The distinction that matters is between *no decision* and a
/// decision of *deny*. Both used to arrive as `None` alongside a
/// network name, so a channel whose policy said "no egress" was
/// indistinguishable from an exec that had no policy at all, and both
/// fell through to the legacy `network` flag. With that flag set, the
/// deny case joined Docker's default bridge: the strictest policy
/// produced the widest network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EgressDecision<'a> {
    /// No egress policy reached this exec. The legacy `network` flag
    /// decides, as it did before per-channel egress existed.
    Unset,
    /// A policy decided: no egress. Nothing to proxy because nothing
    /// is granted, so the container gets no network whatever the
    /// legacy flag says.
    Denied,
    /// A policy decided: egress through the proxy on this internal
    /// network.
    Proxied(&'a str),
}

/// Build the `HostConfig` for a sandboxed exec. Extracted so the
/// hardening settings can be asserted without spinning up Docker.
///
/// The fixed hardening (no capabilities, no privilege elevation,
/// default seccomp, read-only root, tmpfs `/tmp`) comes from
/// [`wirken_sandbox::hardened_host_config`], the same function MCP server
/// containers use. What is particular to `exec` is set here:
///
/// * the agent workspace, bind-mounted read-write at `/workspace`;
/// * the memory and PID caps, and no CPU cap;
/// * `egress`: what the egress layer decided. `Proxied` joins the
///   named Docker network, created `Internal` with inter-container
///   communication off, so the only address it can reach is the
///   gateway where this exec's egress proxy listens. DNS is pinned to
///   an address with nothing behind it: the container must not resolve
///   names itself, because the proxy resolves them after the allowlist
///   decision. `Denied` gets no network. `Unset` means no policy
///   reached this exec and the legacy flag decides.
pub(crate) fn build_host_config(
    config: &SandboxConfig,
    workspace_str: &str,
    egress: EgressDecision<'_>,
) -> HostConfig {
    // An egress decision wins over the legacy `network` bool, in both
    // directions. The proxy path is the bounded one, and letting
    // `network: true` widen it back to unrestricted host networking
    // would defeat the allowlist the operator configured. A decision
    // of `Denied` is equally a decision: it is not the absence of one,
    // and it does not hand the question back to a flag that predates
    // per-channel egress. Only `Unset` does that.
    let network_mode = match (egress, config.network) {
        (EgressDecision::Proxied(name), _) => Some(name.to_string()),
        (EgressDecision::Denied, _) => Some("none".to_string()),
        (EgressDecision::Unset, true) => None,
        (EgressDecision::Unset, false) => Some("none".to_string()),
    };
    // Only meaningful on the egress-network path; harmless otherwise
    // since `--network none` has no resolver to point anywhere.
    let dns = match egress {
        EgressDecision::Proxied(_) => Some(vec!["127.0.0.1".to_string()]),
        _ => None,
    };
    wirken_sandbox::hardened_host_config(wirken_sandbox::HostSettings {
        binds: vec![format!("{workspace_str}:/workspace:rw")],
        mounts: Vec::new(),
        network_mode,
        dns,
        memory: MEMORY_LIMIT,
        pids: PIDS_LIMIT,
        nano_cpus: None,
        runtime: config.mode.runtime_name(),
    })
}

/// The sidecar for one exec. It runs as the operator, so the broker's
/// socket directory and socket admit the operator alone: no other local
/// user can ask the broker for decisions or write rows through it.
#[cfg(unix)]
pub(crate) fn exec_sidecar_spec(
    id: String,
    image: String,
    binary: std::path::PathBuf,
    rootless: bool,
) -> SidecarSpec {
    SidecarSpec {
        name_prefix: "wirken-egress".into(),
        socket_dir: std::env::temp_dir().join(format!("wirken-egress-{id}")),
        id,
        image,
        binary,
        labels: Default::default(),
        user: Some(wirken_sandbox::operator_user(rootless)),
        socket_dir_mode: 0o700,
        socket_mode: 0o600,
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

#[allow(
    clippy::string_slice,
    reason = "a simple UUID string is 32 ASCII hex digits"
)]
fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}
