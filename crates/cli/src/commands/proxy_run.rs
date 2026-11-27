//! `wirken proxy run`: a proxy client started in a container.
//!
//! A client pointed at the listener from outside keeps its own shell,
//! files and network, where Wirken sees and gates nothing. Started
//! here, it runs in a container with the exec sandbox's hardening: a
//! read-only root, no capability, `no-new-privileges`, the seccomp
//! profile, process and memory limits. Its files are the workspace,
//! the folders named read-only, and a home of its own. Its network is
//! the proxy listener, on its own loopback, and the hosts named with
//! `--egress`, through its sidecar.
//!
//! The listener is reached the way a contained MCP server's injected
//! route is: a relay on the container's loopback copies each
//! connection to the sidecar, which hands it over the broker socket to
//! this process, which copies it to the listener. None of them reads
//! what it copies; the listener checks the token and records the call
//! as it does for any client.
//!
//! The client holds one token, minted for the run with the grants on
//! the command line and revoked when the run ends. It holds no provider
//! key and no MCP server's credential.
//!
//! Nothing inside the container is gated or recorded one command at a
//! time. What is bounded is what it can reach.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use bollard::Docker;
use bollard::models::{ContainerCreateBody, Mount, MountType};
use sha2::{Digest, Sha256};
use wirken_audit::{
    SandboxEgressModeLabel, SessionEvent, SessionId, SessionLog, TrustLevel, proxy_session,
};
use wirken_gateway::proxy::{ProxyConfig, TokenGrant};
use wirken_sandbox::egress::{
    EgressDecider, InjectRoute, InjectStream, RequestKind, RequestSeen, Verdict, check_shape,
    host_matches,
};

/// Where the listener is inside the container: its own loopback, on
/// the listener's default port, whatever the host's listener is bound
/// to.
pub const CLIENT_PORT: u16 = 18791;

/// Where the relay binary is mounted inside the container.
const RELAY_TARGET: &str = "/wirken-relay";

/// Where the workspace is mounted.
pub const WORKSPACE_TARGET: &str = "/workspace";

/// Where a read-only folder is mounted: under this, by its name.
pub const READ_ONLY_ROOT: &str = "/mnt/ro";

/// The client's home inside the container.
pub const HOME_TARGET: &str = "/home/wirken";

/// The most read-only folders a run takes.
const MAX_READ_ONLY: usize = 8;

/// A coding agent's runtime is larger than one `exec`.
const MEMORY_BYTES: i64 = 4 * 1024 * 1024 * 1024;
const PIDS: i64 = 1024;
const NANO_CPUS: i64 = 2_000_000_000;

/// Container labels: what the container is, the data directory it is
/// of, the token it holds and the process that started it.
const LABEL_ROLE: &str = "wirken.proxy-run";
const LABEL_INSTANCE: &str = "wirken.proxy-run.instance";
const LABEL_TOKEN: &str = "wirken.proxy-run.token";
const LABEL_PID: &str = "wirken.proxy-run.pid";

/// What a run's egress rows carry as their agent: no agent of
/// Wirken's runs the client.
pub const RUN_AGENT: &str = "proxy-run";

/// The bare wildcard of `--egress`.
const ANY_HOST: &str = "*";

/// What a run was asked for, as the command line gave it.
pub struct RunRequest {
    pub image: String,
    pub workspace: Option<PathBuf>,
    pub read_only: Vec<PathBuf>,
    pub egress: Vec<String>,
    pub grant: TokenGrant,
    pub command: Vec<String>,
}

/// One host folder in the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub source: PathBuf,
    pub target: String,
    pub writable: bool,
}

impl Bind {
    fn summary(&self) -> String {
        format!(
            "{}:{}:{}",
            self.source.display(),
            self.target,
            if self.writable { "rw" } else { "ro" }
        )
    }

    fn mount(&self) -> Mount {
        Mount {
            target: Some(self.target.clone()),
            source: Some(self.source.to_string_lossy().into_owned()),
            typ: Some(MountType::BIND),
            read_only: Some(!self.writable),
            ..Default::default()
        }
    }
}

/// A run, checked: every path resolved and allowed, every host a
/// pattern the broker can match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPlan {
    pub image: String,
    pub binds: Vec<Bind>,
    pub egress: Vec<String>,
    pub command: Vec<String>,
    /// Where the host's listener answers.
    pub listener: SocketAddr,
}

/// A host folder a run may bind: absolute, existing, a directory, and
/// neither inside the data directory nor holding it. Returned resolved,
/// so what is bound is what was checked.
fn bindable(path: &Path, what: &str, data_dir: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("{what} {} is not an absolute path", path.display());
    }
    let real = path
        .canonicalize()
        .with_context(|| format!("{what} {}", path.display()))?;
    if !real.is_dir() {
        bail!("{what} {} is not a directory", path.display());
    }
    let data = data_dir
        .canonicalize()
        .unwrap_or_else(|_| data_dir.to_path_buf());
    if real.starts_with(&data) {
        bail!("{what} {} is inside the data directory", path.display());
    }
    if data.starts_with(&real) {
        bail!("{what} {} holds the data directory", path.display());
    }
    Ok(real)
}

/// Check one `--egress` host: a domain name, `*.` and a domain name,
/// or `*`.
fn check_egress(pattern: &str) -> Result<()> {
    wirken_mcp_proxy::egress::check_host_pattern(pattern)
        .map_err(|e| anyhow::anyhow!("{}", e.replace("egress.hosts entry", "--egress")))
}

/// Where the listener `config` describes answers, for a process on
/// this host. A listener with TLS is refused: the route copies the
/// client's plain HTTP and does not speak TLS to it.
pub fn listener_address(config: &ProxyConfig) -> Result<SocketAddr> {
    if config.tls.is_some() {
        bail!(
            "proxy.json sets tls, and a run reaches the listener over plain HTTP. Run a \
             loopback listener without tls for wirken proxy run"
        );
    }
    let bound: SocketAddr = config
        .bind
        .parse()
        .with_context(|| format!("proxy.json bind {:?}", config.bind))?;
    let ip = if bound.ip().is_unspecified() {
        match bound {
            SocketAddr::V4(_) => std::net::IpAddr::from([127, 0, 0, 1]),
            SocketAddr::V6(_) => std::net::IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
        }
    } else {
        bound.ip()
    };
    Ok(SocketAddr::new(ip, bound.port()))
}

/// The client's home for `workspace`: one per workspace, kept between
/// runs, under the data directory. A run without a workspace has one
/// of its own kind.
pub fn home_for(data_dir: &Path, workspace: Option<&Path>) -> PathBuf {
    let key = match workspace {
        Some(path) => {
            let digest = Sha256::digest(path.to_string_lossy().as_bytes());
            digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
        }
        None => "no-workspace".to_string(),
    };
    data_dir.join("proxy-run").join(key).join("home")
}

/// Check `request` against `data_dir` and the listener `config`
/// describes. `home` is the client's home, made by the caller.
pub fn plan(
    request: &RunRequest,
    data_dir: &Path,
    config: &ProxyConfig,
    home: &Path,
) -> Result<RunPlan> {
    if request.image.trim().is_empty() {
        bail!("--image names no image");
    }
    if request.command.is_empty() {
        bail!("no command to run: give it after --");
    }
    let mut binds = Vec::new();
    if let Some(workspace) = &request.workspace {
        binds.push(Bind {
            source: bindable(workspace, "--workspace", data_dir)?,
            target: WORKSPACE_TARGET.to_string(),
            writable: true,
        });
    }
    if request.read_only.len() > MAX_READ_ONLY {
        bail!("at most {MAX_READ_ONLY} --read-only folders");
    }
    for folder in &request.read_only {
        let source = bindable(folder, "--read-only", data_dir)?;
        let name = source
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| {
                n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            })
            .with_context(|| {
                format!(
                    "--read-only {}: its name is not letters, digits, -, _ or .",
                    folder.display()
                )
            })?;
        let target = format!("{READ_ONLY_ROOT}/{name}");
        if binds.iter().any(|b| b.target == target) {
            bail!("two --read-only folders are named {name}");
        }
        binds.push(Bind {
            source,
            target,
            writable: false,
        });
    }
    binds.push(Bind {
        source: home.to_path_buf(),
        target: HOME_TARGET.to_string(),
        writable: true,
    });
    for pattern in &request.egress {
        check_egress(pattern)?;
    }
    let mut egress = request.egress.clone();
    egress.sort();
    egress.dedup();
    Ok(RunPlan {
        image: request.image.clone(),
        binds,
        egress,
        command: request.command.clone(),
        listener: listener_address(config)?,
    })
}

/// What the container body takes from the run's route and runtime.
pub struct BodyFacts<'a> {
    /// The run token, which the client holds.
    pub token: &'a str,
    pub token_id: &'a str,
    pub instance: &'a str,
    /// The relay binary, mounted read-only.
    pub relay: &'a Path,
    /// Where the relay copies to: the sidecar's injected-route port.
    pub relay_to: SocketAddr,
    pub network: &'a str,
    /// The sidecar as the client's HTTP(S) proxy.
    pub proxy_env: Vec<String>,
    pub user: &'a str,
    pub runtime: Option<String>,
    pub seccomp: wirken_sandbox::seccomp::Seccomp,
    /// `TERM` of the operator's terminal.
    pub term: Option<String>,
}

/// The body sent to the runtime. The relay is the first process and
/// runs the client's command; the container has a terminal, which the
/// run attaches the operator's to.
pub fn create_body(plan: &RunPlan, facts: BodyFacts<'_>) -> ContainerCreateBody {
    let url = format!("http://127.0.0.1:{CLIENT_PORT}");
    let mut env = facts.proxy_env;
    // The relay is on the container's loopback; a client honouring the
    // proxy variables for every address would otherwise ask the
    // sidecar for it.
    env.retain(|e| !e.starts_with("NO_PROXY=") && !e.starts_with("no_proxy="));
    env.extend([
        "NO_PROXY=127.0.0.1,localhost".to_string(),
        "no_proxy=127.0.0.1,localhost".to_string(),
        format!("HOME={HOME_TARGET}"),
        format!("WIRKEN_PROXY_URL={url}"),
        format!("WIRKEN_PROXY_TOKEN={}", facts.token),
        format!("ANTHROPIC_BASE_URL={url}"),
        format!("ANTHROPIC_AUTH_TOKEN={}", facts.token),
        format!("OPENAI_BASE_URL={url}/v1"),
        format!("OPENAI_API_KEY={}", facts.token),
    ]);
    if let Some(term) = facts.term {
        env.push(format!("TERM={term}"));
    }
    let mut mounts: Vec<Mount> = plan.binds.iter().map(Bind::mount).collect();
    mounts.push(
        Bind {
            source: facts.relay.to_path_buf(),
            target: RELAY_TARGET.to_string(),
            writable: false,
        }
        .mount(),
    );
    let args: Vec<String> = [
        "inject-relay".to_string(),
        "--listen".to_string(),
        format!("127.0.0.1:{CLIENT_PORT}"),
        "--to".to_string(),
        facts.relay_to.to_string(),
        "--".to_string(),
    ]
    .into_iter()
    .chain(plan.command.iter().cloned())
    .collect();
    let working_dir = if plan.binds.iter().any(|b| b.target == WORKSPACE_TARGET) {
        WORKSPACE_TARGET
    } else {
        HOME_TARGET
    };
    let labels = HashMap::from([
        (LABEL_ROLE.to_string(), "true".to_string()),
        (LABEL_INSTANCE.to_string(), facts.instance.to_string()),
        (LABEL_TOKEN.to_string(), facts.token_id.to_string()),
        (LABEL_PID.to_string(), std::process::id().to_string()),
    ]);
    ContainerCreateBody {
        image: Some(plan.image.clone()),
        entrypoint: Some(vec![RELAY_TARGET.to_string()]),
        cmd: Some(args),
        env: Some(env),
        user: Some(facts.user.to_string()),
        working_dir: Some(working_dir.to_string()),
        labels: Some(labels),
        attach_stdin: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        open_stdin: Some(true),
        // The container's input ends when the run's attach does, so a
        // client left behind by a run that is gone reads end of input.
        stdin_once: Some(true),
        tty: Some(true),
        host_config: Some(wirken_sandbox::hardened_host_config(
            wirken_sandbox::HostSettings {
                binds: Vec::new(),
                mounts,
                network_mode: Some(facts.network.to_string()),
                // Names are resolved by the broker, after the hosts
                // check; the container's resolver answers nothing.
                dns: Some(vec!["127.0.0.1".to_string()]),
                dns_search: Some(vec![".".to_string()]),
                memory: MEMORY_BYTES,
                pids: PIDS,
                nano_cpus: Some(NANO_CPUS),
                runtime: facts.runtime,
                seccomp: facts.seccomp,
            },
        )),
        ..Default::default()
    }
}

/// The host side of the run's loopback relay: each connection is
/// copied to the listener as it is.
pub struct ListenerRoute {
    pub listener: SocketAddr,
}

#[async_trait::async_trait]
impl InjectRoute for ListenerRoute {
    async fn serve(&self, mut stream: Box<dyn InjectStream>) {
        match tokio::net::TcpStream::connect(self.listener).await {
            Ok(mut listener) => {
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut listener).await;
            }
            Err(e) => {
                tracing::warn!("proxy run: the listener at {} refused: {e}", self.listener);
            }
        }
    }
}

/// The run's egress policy: the `--egress` hosts, every verdict a row
/// on the run's lane.
pub struct RunEgress {
    pub lane: String,
    /// `proxy-token:<id>` of the run token.
    pub sender: String,
    pub hosts: Vec<String>,
    pub audit: Option<Arc<dyn SessionLog>>,
}

impl RunEgress {
    fn mode(&self) -> SandboxEgressModeLabel {
        if self.hosts.iter().any(|h| h == ANY_HOST) {
            SandboxEgressModeLabel::Open
        } else {
            SandboxEgressModeLabel::Allowlist
        }
    }

    pub fn check(&self, host: &str, port: u16, kind: RequestKind) -> Verdict {
        if let Err(reason) = check_shape(host, port, kind) {
            return Verdict::deny(reason);
        }
        if self
            .hosts
            .iter()
            .any(|p| p == ANY_HOST || host_matches(host, p))
        {
            Verdict::allow()
        } else {
            Verdict::deny(wirken_audit::SandboxEgressDenyReason::NotAllowed)
        }
    }
}

#[async_trait::async_trait]
impl EgressDecider for RunEgress {
    async fn decide(
        &self,
        host: &str,
        port: u16,
        kind: RequestKind,
        _seen: RequestSeen<'_>,
    ) -> Verdict {
        self.check(host, port, kind)
    }

    fn record(&self, host: &str, port: u16, method: &str, verdict: &Verdict) -> Result<(), String> {
        let Some(log) = &self.audit else {
            return Ok(());
        };
        let handle = log.handle_for(SessionId::new(self.lane.clone()));
        log.append(
            &handle,
            TrustLevel::System,
            SessionEvent::SandboxEgressVerdict {
                host: host.to_string(),
                port,
                method: (!method.is_empty()).then(|| method.to_string()),
                allowed: verdict.allowed,
                reason: verdict.reason,
                mode: self.mode(),
                sensitivity_basis: verdict.basis.clone(),
                escalated: verdict.escalated,
                // No agent of Wirken's runs the client: the run is
                // named, and its token is the sender.
                agent_id: RUN_AGENT.to_string(),
                channel: None,
                adapter_id: None,
                sender_id: Some(self.sender.clone()),
                mcp_server: None,
            },
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }
}

/// Whether process `pid` is alive on this host.
fn alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        // SAFETY: `kill` with signal 0 sends nothing; it only reports
        // whether the process exists and may be signalled.
        let rc = unsafe { libc::kill(pid, 0) };
        rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// The labels of everything a run starts: its client container, its
/// sidecar and its networks.
fn run_labels(instance: &str, token_id: &str) -> HashMap<String, String> {
    HashMap::from([
        (LABEL_INSTANCE.to_string(), instance.to_string()),
        (LABEL_TOKEN.to_string(), token_id.to_string()),
        (LABEL_PID.to_string(), std::process::id().to_string()),
    ])
}

/// Remove what runs of this data directory left behind when their
/// process went away without ending them: containers, networks, and
/// the tokens they held. Returns how many runs were cleared.
async fn reap(docker: &Docker, data_dir: &Path, instance: &str) -> usize {
    use bollard::query_parameters::{
        ListContainersOptionsBuilder, ListNetworksOptionsBuilder, RemoveContainerOptionsBuilder,
    };
    let filter = HashMap::from([(
        "label".to_string(),
        vec![format!("{LABEL_INSTANCE}={instance}")],
    )]);
    let left = |labels: Option<&HashMap<String, String>>| -> Option<String> {
        let labels = labels?;
        let pid: u32 = labels.get(LABEL_PID)?.parse().ok()?;
        (!alive(pid)).then(|| labels.get(LABEL_TOKEN).cloned().unwrap_or_default())
    };
    let mut tokens = std::collections::BTreeSet::new();
    let containers = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::new()
                .all(true)
                .filters(&filter)
                .build(),
        ))
        .await
        .unwrap_or_default();
    for container in containers {
        let Some(token) = left(container.labels.as_ref()) else {
            continue;
        };
        if let Some(id) = &container.id {
            let _ = docker
                .remove_container(
                    id,
                    Some(RemoveContainerOptionsBuilder::new().force(true).build()),
                )
                .await;
        }
        tokens.insert(token);
    }
    let networks = docker
        .list_networks(Some(
            ListNetworksOptionsBuilder::new().filters(&filter).build(),
        ))
        .await
        .unwrap_or_default();
    for network in networks {
        if left(network.labels.as_ref()).is_some()
            && let Some(id) = &network.id
        {
            let _ = docker.remove_network(id).await;
        }
    }
    for token in tokens.iter().filter(|t| !t.is_empty()) {
        if let Err(e) = super::proxy::revoke_recorded(data_dir, token) {
            tracing::warn!("proxy run: a token a run left could not be revoked: {e:#}");
        }
    }
    tokens.len()
}

/// The operator's terminal in raw mode for as long as this is held.
struct RawTerminal;

impl RawTerminal {
    fn enter() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("put the terminal in raw mode")?;
        Ok(Self)
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

async fn resize(docker: &Docker, id: &str) {
    if let Ok((width, height)) = crossterm::terminal::size() {
        let _ = docker
            .resize_container_tty(
                id,
                bollard::query_parameters::ResizeContainerTTYOptionsBuilder::new()
                    .w(i32::from(width))
                    .h(i32::from(height))
                    .build(),
            )
            .await;
    }
}

fn random_id() -> String {
    use rand::Rng as _;
    let mut bytes = [0u8; 6];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// How the client's container ended.
struct Ended {
    exit_code: Option<i64>,
    stopped: bool,
}

/// Run `request`: start the client in its container, attach the
/// operator's terminal, and when it exits remove the container and its
/// route and revoke its token. Returns the client's exit status.
pub async fn run(request: RunRequest) -> Result<i32> {
    super::proxy::require_terminal("run")?;
    if !std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        bail!("wirken proxy run attaches the client to this terminal, and stdout is not one");
    }
    let cfg = super::config();
    let data_dir = cfg.data_dir.clone();
    let config = ProxyConfig::load(&data_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("there is no proxy.json, so there is no listener for the client to reach")?;
    let listener = listener_address(&config)?;
    if tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(listener),
    )
    .await
    .map_or(true, |c| c.is_err())
    {
        bail!(
            "the proxy listener at {listener} does not answer. Start the gateway with wirken run"
        );
    }

    let mut host = wirken_mcp_proxy::container::SandboxHost::new(&data_dir)
        .map_err(|e| anyhow::anyhow!("sandbox.json: {e}"))?;
    host.probe().await;
    let (Some(docker), Some(facts)) = (host.docker.clone(), host.facts) else {
        bail!("no container runtime answers. Start Docker and run again");
    };
    if let Some(why) = facts.egress_unsupported() {
        bail!("a run's only route out is its sidecar, and {why}");
    }
    let relay = host
        .ready_sidecar_binary()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let cleared = reap(&docker, &data_dir, &host.instance).await;
    if cleared > 0 {
        println!("  Removed what {cleared} earlier run(s) left, and revoked their tokens.");
    }

    let home = home_for(
        &data_dir,
        request
            .workspace
            .as_ref()
            .and_then(|w| w.canonicalize().ok())
            .as_deref(),
    );
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&home)
            .with_context(|| format!("the client's home {}", home.display()))?;
    }
    let plan = plan(&request, &data_dir, &config, &home)?;
    let image = docker.inspect_image(&plan.image).await.map_err(|_| {
        anyhow::anyhow!(
            "image {} is not on this host, and a run does not pull; run docker pull {}",
            plan.image,
            plan.image
        )
    })?;

    let mut grant = request.grant.clone();
    grant.name = format!("run-{}", random_id());
    let (token, value) = super::proxy::issue_recorded(&data_dir, &grant)?;
    let lane = proxy_session(&token.id, None);
    let log: Arc<dyn SessionLog> = super::open_signed_session_log(&cfg)?;
    let started = Instant::now();

    let outcome = contained(
        &docker,
        &host,
        &plan,
        &image,
        &relay,
        facts.podman,
        facts.rootless,
        (&token.id, &value),
        &lane,
        log.clone(),
    )
    .await;

    let (container_id, ended) = match &outcome {
        Ok((id, ended)) => (id.clone(), Some(ended)),
        Err((id, _)) => (id.clone(), None),
    };
    if let Some(container_id) = container_id {
        let ended_row = SessionEvent::ProxyRunEnded {
            token_id: token.id.clone(),
            container_id,
            exit_code: ended.and_then(|e| e.exit_code),
            stopped: ended.is_none_or(|e| e.stopped),
            duration_ms: started.elapsed().as_millis() as u64,
        };
        if let Err(e) = log.append(
            &log.handle_for(SessionId::new(lane.clone())),
            TrustLevel::System,
            ended_row,
        ) {
            tracing::error!("proxy run: the end of the run was not recorded: {e}");
        }
    }
    let revoked = super::proxy::revoke_recorded(&data_dir, &token.id);
    match outcome {
        Ok((_, ended)) => {
            revoked?;
            println!();
            println!(
                "  The run ended ({}). Its token {} is revoked. Its calls: wirken proxy \
                 sessions --token {}",
                ended
                    .exit_code
                    .map_or("no exit code".to_string(), |c| format!("exit {c}")),
                token.id,
                token.id
            );
            Ok(ended
                .exit_code
                .and_then(|c| i32::try_from(c).ok())
                .unwrap_or(1))
        }
        Err((_, e)) => {
            if let Err(r) = revoked {
                tracing::error!("proxy run: the run's token was not revoked: {r:#}");
            }
            Err(e)
        }
    }
}

/// A run's container, from its route to its removal. Returns the
/// container's id once one exists, with how it ended or why the run
/// failed. The route and the container are gone when this returns.
#[allow(clippy::too_many_arguments)]
async fn contained(
    docker: &Docker,
    host: &wirken_mcp_proxy::container::SandboxHost,
    plan: &RunPlan,
    image: &bollard::models::ImageInspect,
    relay: &Path,
    podman: bool,
    rootless: bool,
    (token_id, token): (&str, &str),
    lane: &str,
    log: Arc<dyn SessionLog>,
) -> std::result::Result<(Option<String>, Ended), (Option<String>, anyhow::Error)> {
    let fail = |id: Option<String>| move |e: anyhow::Error| (id, e);
    let user = wirken_sandbox::operator_user(rootless);
    let seccomp = wirken_sandbox::seccomp::for_runtime(podman)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .map_err(fail(None))?;
    let id = random_id();
    let spec = wirken_sandbox::egress_net::SidecarSpec {
        name_prefix: "wirken-run-egress".into(),
        socket_dir: std::env::temp_dir().join(format!("wirken-run-egress-{}-{id}", host.instance)),
        id: id.clone(),
        image: plan.image.clone(),
        binary: relay.to_path_buf(),
        labels: run_labels(&host.instance, token_id),
        user: Some(user.clone()),
        socket_dir_mode: 0o700,
        socket_mode: 0o600,
        seccomp: seccomp.clone(),
        inject: Some(Arc::new(ListenerRoute {
            listener: plan.listener,
        })),
    };
    let decider = RunEgress {
        lane: lane.to_string(),
        sender: format!("proxy-token:{token_id}"),
        hosts: plan.egress.clone(),
        audit: Some(log.clone()),
    };
    let route = wirken_sandbox::egress_net::provision(docker, spec, Arc::new(decider))
        .await
        .map_err(|e| anyhow::anyhow!("the run's route out: {e}"))
        .map_err(fail(None))?;
    let Some(relay_to) = route.inject_addr() else {
        route.teardown(docker).await;
        return Err((None, anyhow::anyhow!("the run's sidecar serves no relay")));
    };
    let body = create_body(
        plan,
        BodyFacts {
            token,
            token_id,
            instance: &host.instance,
            relay,
            relay_to,
            network: &route.internal_network,
            proxy_env: route.proxy_env(),
            user: &user,
            runtime: host.runtime.clone(),
            seccomp,
            term: std::env::var("TERM").ok(),
        },
    );
    let created = docker
        .create_container(
            Some(
                bollard::query_parameters::CreateContainerOptionsBuilder::new()
                    .name(&format!("wirken-run-{id}"))
                    .build(),
            ),
            body,
        )
        .await;
    let container = match created {
        Ok(created) => created.id,
        Err(e) => {
            route.teardown(docker).await;
            return Err((None, anyhow::anyhow!("create the client's container: {e}")));
        }
    };
    let runtime = wirken_sandbox::runtime_label(host.runtime.as_deref());
    let result = attached(
        docker, &container, plan, image, runtime, token_id, lane, &log,
    )
    .await;
    let _ = docker
        .remove_container(
            &container,
            Some(
                bollard::query_parameters::RemoveContainerOptionsBuilder::new()
                    .force(true)
                    .build(),
            ),
        )
        .await;
    route.teardown(docker).await;
    match result {
        Ok(ended) => Ok((Some(container), ended)),
        Err(e) => Err((Some(container), e)),
    }
}

/// Record the run, start the container with the operator's terminal
/// attached, and wait for it to exit.
#[allow(clippy::too_many_arguments)]
async fn attached(
    docker: &Docker,
    container: &str,
    plan: &RunPlan,
    image: &bollard::models::ImageInspect,
    runtime: wirken_audit::SandboxRuntimeLabel,
    token_id: &str,
    lane: &str,
    log: &Arc<dyn SessionLog>,
) -> Result<Ended> {
    use futures_util::StreamExt as _;
    use tokio::io::AsyncWriteExt as _;

    // The row first: no client runs without one saying what it was
    // given.
    log.append(
        &log.handle_for(SessionId::new(lane.to_string())),
        TrustLevel::System,
        SessionEvent::ProxyRunStarted {
            token_id: token_id.to_string(),
            image: plan.image.clone(),
            image_id: image.id.clone(),
            image_digest: image.repo_digests.as_ref().and_then(|d| d.first().cloned()),
            runtime,
            container_id: container.to_string(),
            command: plan.command.clone(),
            mounts: plan.binds.iter().map(Bind::summary).collect(),
            egress_hosts: plan.egress.clone(),
            memory_bytes: MEMORY_BYTES,
            pids: PIDS,
            nano_cpus: NANO_CPUS,
        },
    )
    .map_err(|e| anyhow::anyhow!("the run could not be recorded, so it was not started: {e}"))?;

    let attach = docker
        .attach_container(
            container,
            Some(
                bollard::query_parameters::AttachContainerOptionsBuilder::new()
                    .stdin(true)
                    .stdout(true)
                    .stderr(true)
                    .stream(true)
                    .build(),
            ),
        )
        .await
        .context("attach to the client's container")?;
    let mut input = attach.input;
    let mut output = attach.output;

    let raw = RawTerminal::enter()?;
    docker
        .start_container(
            container,
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await
        .context("start the client's container")?;
    resize(docker, container).await;

    // The operator's keystrokes, read on a thread of their own: a read
    // of stdin blocks, and the process exits with it still waiting.
    let (keys_tx, mut keys) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if keys_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    use tokio::signal::unix::{SignalKind, signal};
    let mut winch = signal(SignalKind::window_change()).context("watch the terminal's size")?;
    let mut term = signal(SignalKind::terminate()).context("watch for SIGTERM")?;
    let mut hup = signal(SignalKind::hangup()).context("watch for SIGHUP")?;
    // The terminal is raw, so Ctrl-C goes to the client; a SIGINT here
    // came from elsewhere, and stops the run as SIGTERM does.
    let mut int = signal(SignalKind::interrupt()).context("watch for SIGINT")?;
    let mut waited = docker.wait_container(
        container,
        None::<bollard::query_parameters::WaitContainerOptions>,
    );
    let mut stdout = tokio::io::stdout();
    let mut stopped = false;
    let exit_code = loop {
        tokio::select! {
            chunk = output.next() => match chunk {
                Some(Ok(chunk)) => {
                    let _ = stdout.write_all(&chunk.into_bytes()).await;
                    let _ = stdout.flush().await;
                }
                // The attach is done; the exit code is the wait's.
                _ => {
                    break match waited.next().await {
                        Some(Ok(done)) => Some(done.status_code),
                        Some(Err(bollard::errors::Error::DockerContainerWaitError { code, .. })) => {
                            Some(code)
                        }
                        _ => None,
                    };
                }
            },
            Some(bytes) = keys.recv() => {
                if input.write_all(&bytes).await.is_err() {
                    continue;
                }
                let _ = input.flush().await;
            }
            _ = winch.recv() => resize(docker, container).await,
            _ = term.recv() => { stopped = true; break None; }
            _ = hup.recv() => { stopped = true; break None; }
            _ = int.recv() => { stopped = true; break None; }
        }
    };
    drop(raw);
    if stopped {
        let _ = docker
            .stop_container(
                container,
                Some(
                    bollard::query_parameters::StopContainerOptionsBuilder::new()
                        .t(10)
                        .build(),
                ),
            )
            .await;
    }
    Ok(Ended { exit_code, stopped })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(bind: &str, tls: bool) -> ProxyConfig {
        let mut json = serde_json::json!({
            "bind": bind,
            "upstreams": {"local": {"provider": "ollama", "base_url": "http://localhost:1/v1"}},
        });
        if tls {
            json["tls"] = serde_json::json!({"certificate": "c.pem", "private_key": "k.pem"});
            json["bind_beyond_loopback"] = true.into();
        }
        serde_json::from_value(json).unwrap()
    }

    fn request(dirs: &Path) -> RunRequest {
        RunRequest {
            image: "node:22-slim".into(),
            workspace: Some(dirs.join("work")),
            read_only: vec![dirs.join("docs")],
            egress: vec!["registry.npmjs.org".into(), "*.github.com".into()],
            grant: TokenGrant::default(),
            command: vec!["claude".into()],
        }
    }

    /// A temporary tree: a data directory and two folders beside it.
    fn dirs() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        for d in ["data", "work", "docs"] {
            std::fs::create_dir(tmp.path().join(d)).unwrap();
        }
        let data = tmp.path().join("data");
        (tmp, data)
    }

    /// The listener is reached on loopback, wherever it is bound; one
    /// with TLS is refused, since the route copies plain HTTP.
    #[test]
    fn the_listener_is_reached_on_loopback_and_not_over_tls() {
        assert_eq!(
            listener_address(&config("127.0.0.1:18791", false)).unwrap(),
            "127.0.0.1:18791".parse().unwrap()
        );
        assert_eq!(
            listener_address(&config("0.0.0.0:9000", false)).unwrap(),
            "127.0.0.1:9000".parse().unwrap()
        );
        assert_eq!(
            listener_address(&config("[::]:9000", false)).unwrap(),
            "[::1]:9000".parse().unwrap()
        );
        let err = listener_address(&config("0.0.0.0:9000", true)).unwrap_err();
        assert!(err.to_string().contains("tls"), "{err}");
    }

    /// The workspace is read-write at /workspace, each read-only folder
    /// at /mnt/ro/<name>, the home at its own place. Nothing in or
    /// around the data directory is bound, and every host is a pattern.
    #[test]
    fn a_plan_binds_only_folders_outside_the_data_directory() {
        let (tmp, data) = dirs();
        let home = home_for(&data, Some(&tmp.path().join("work")));
        std::fs::create_dir_all(&home).unwrap();
        let config = config("127.0.0.1:18791", false);
        let plan = plan(&request(tmp.path()), &data, &config, &home).unwrap();
        let binds: Vec<(&str, bool)> = plan
            .binds
            .iter()
            .map(|b| (b.target.as_str(), b.writable))
            .collect();
        assert_eq!(
            binds,
            [
                (WORKSPACE_TARGET, true),
                ("/mnt/ro/docs", false),
                (HOME_TARGET, true)
            ]
        );
        assert!(home.starts_with(&data));
        assert_eq!(plan.egress, ["*.github.com", "registry.npmjs.org"]);

        let refused = |change: &dyn Fn(&mut RunRequest)| {
            let mut r = request(tmp.path());
            change(&mut r);
            plan_err(&r, &data, &config, &home)
        };
        for (why, change) in [
            (
                "inside the data directory",
                Box::new(|r: &mut RunRequest| r.workspace = Some(data.join(".")))
                    as Box<dyn Fn(&mut RunRequest)>,
            ),
            (
                "holds the data directory",
                Box::new(|r: &mut RunRequest| r.read_only = vec![tmp.path().to_path_buf()]),
            ),
            (
                "not an absolute path",
                Box::new(|r: &mut RunRequest| r.workspace = Some("work".into())),
            ),
            (
                "not a directory",
                Box::new(|r: &mut RunRequest| {
                    std::fs::write(tmp.path().join("file"), "x").unwrap();
                    r.read_only = vec![tmp.path().join("file")];
                }),
            ),
            (
                "two --read-only folders are named docs",
                Box::new(|r: &mut RunRequest| {
                    std::fs::create_dir_all(tmp.path().join("other/docs")).unwrap();
                    r.read_only.push(tmp.path().join("other/docs"));
                }),
            ),
            (
                "--egress",
                Box::new(|r: &mut RunRequest| r.egress = vec!["10.0.0.1".into()]),
            ),
            (
                "no command",
                Box::new(|r: &mut RunRequest| r.command.clear()),
            ),
        ] {
            let err = refused(&*change);
            assert!(err.contains(why), "{why}: {err}");
        }
    }

    fn plan_err(r: &RunRequest, data: &Path, config: &ProxyConfig, home: &Path) -> String {
        format!("{:#}", plan(r, data, config, home).unwrap_err())
    }

    /// The container is hardened as an exec's, runs the relay as its
    /// first process with the client's command after it, has a
    /// terminal, and is pointed at the listener on its own loopback
    /// with the run token and no other credential.
    #[test]
    fn the_container_is_hardened_and_reaches_the_listener_on_loopback() {
        let (tmp, data) = dirs();
        let home = home_for(&data, None);
        std::fs::create_dir_all(&home).unwrap();
        let plan = plan(
            &request(tmp.path()),
            &data,
            &config("127.0.0.1:18791", false),
            &home,
        )
        .unwrap();
        let body = create_body(
            &plan,
            BodyFacts {
                token: "wkp_t",
                token_id: "t1",
                instance: "i1",
                relay: Path::new("/usr/local/bin/wirken"),
                relay_to: "172.18.0.2:3129".parse().unwrap(),
                network: "wirken-run-egress-x",
                proxy_env: vec![
                    "HTTPS_PROXY=http://172.18.0.2:3128".into(),
                    "NO_PROXY=".into(),
                ],
                user: "1000:1000",
                runtime: None,
                seccomp: wirken_sandbox::seccomp::Seccomp::Profile,
                term: Some("xterm-256color".into()),
            },
        );
        assert_eq!(body.entrypoint, Some(vec![RELAY_TARGET.to_string()]));
        let args = body.cmd.unwrap();
        assert_eq!(
            args,
            [
                "inject-relay",
                "--listen",
                "127.0.0.1:18791",
                "--to",
                "172.18.0.2:3129",
                "--",
                "claude"
            ]
        );
        assert_eq!(body.tty, Some(true));
        assert_eq!(body.working_dir.as_deref(), Some(WORKSPACE_TARGET));
        let env = body.env.unwrap();
        for wanted in [
            "WIRKEN_PROXY_URL=http://127.0.0.1:18791",
            "WIRKEN_PROXY_TOKEN=wkp_t",
            "ANTHROPIC_BASE_URL=http://127.0.0.1:18791",
            "ANTHROPIC_AUTH_TOKEN=wkp_t",
            "OPENAI_BASE_URL=http://127.0.0.1:18791/v1",
            "HTTPS_PROXY=http://172.18.0.2:3128",
            "NO_PROXY=127.0.0.1,localhost",
            "HOME=/home/wirken",
            "TERM=xterm-256color",
        ] {
            assert!(env.iter().any(|e| e == wanted), "{wanted} in {env:?}");
        }
        assert!(!env.iter().any(|e| e == "NO_PROXY="), "{env:?}");

        let host = body.host_config.unwrap();
        assert_eq!(host.cap_drop, Some(vec!["ALL".to_string()]));
        assert_eq!(host.cap_add, Some(Vec::new()));
        assert_eq!(host.readonly_rootfs, Some(true));
        assert_eq!(host.network_mode.as_deref(), Some("wirken-run-egress-x"));
        assert_eq!(host.dns, Some(vec!["127.0.0.1".to_string()]));
        assert_eq!(
            (host.memory, host.pids_limit),
            (Some(MEMORY_BYTES), Some(PIDS))
        );
        let relay = host
            .mounts
            .unwrap()
            .into_iter()
            .find(|m| m.target.as_deref() == Some(RELAY_TARGET))
            .unwrap();
        assert_eq!(relay.read_only, Some(true));
        assert_eq!(
            body.labels.unwrap().get(LABEL_TOKEN).map(String::as_str),
            Some("t1")
        );
    }

    /// The hosts named, and nothing else; an address never, whatever
    /// is named; `*` any domain name.
    #[test]
    fn egress_is_the_hosts_named_and_no_address() {
        let egress = |hosts: &[&str]| RunEgress {
            lane: "proxy-t".into(),
            sender: "proxy-token:t".into(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            audit: None,
        };
        let named = egress(&["registry.npmjs.org", "*.github.com"]);
        assert!(
            named
                .check("registry.npmjs.org", 443, RequestKind::Connect)
                .allowed
        );
        assert!(
            named
                .check("api.github.com", 443, RequestKind::Connect)
                .allowed
        );
        assert!(
            !named
                .check("example.com", 443, RequestKind::Connect)
                .allowed
        );
        assert!(
            !named
                .check("registry.npmjs.org", 8443, RequestKind::Connect)
                .allowed
        );
        assert!(
            !named
                .check("140.82.112.3", 443, RequestKind::Connect)
                .allowed
        );
        let any = egress(&["*"]);
        assert!(any.check("example.com", 443, RequestKind::Connect).allowed);
        assert!(!any.check("127.0.0.1", 443, RequestKind::Connect).allowed);
        assert!(
            !egress(&[])
                .check("example.com", 443, RequestKind::Connect)
                .allowed
        );
    }

    /// One home per workspace, and the same one each time.
    #[test]
    fn a_workspace_keeps_its_home_between_runs() {
        let data = Path::new("/d");
        let a = home_for(data, Some(Path::new("/w/a")));
        assert_eq!(a, home_for(data, Some(Path::new("/w/a"))));
        assert_ne!(a, home_for(data, Some(Path::new("/w/b"))));
        assert_ne!(a, home_for(data, None));
        assert!(a.starts_with("/d/proxy-run"));
    }
}
