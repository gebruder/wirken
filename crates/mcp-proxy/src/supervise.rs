//! Restarts for contained stdio MCP servers.
//!
//! Each server that started in a container, or failed to start for a
//! reason its entry does not name, gets a supervisor. When the
//! container exits, the supervisor records `McpServerExited`, removes
//! the dead client, and starts the server again after a delay, running
//! `initialize` and `tools/list` before the new client takes the old
//! one's place. The delay doubles from one second to a minute, and goes
//! back to one second after a run that stayed up for a minute. After
//! eight runs in a row that never complete `initialize` the supervisor
//! records `McpServerRestartAbandoned` and stops; only a restart of the
//! gateway starts the server again. This is the adapters' policy.
//!
//! A server refused at load, for an entry or host the operator has to
//! change, gets no supervisor: restarting it could not succeed.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use wirken_audit::{McpServerRestartCause, SessionEvent, SessionLog};

use crate::container::SandboxHost;
use crate::mcp_client::McpClient;
use crate::mcp_config::StdioSandbox;
use crate::mcp_registry::{
    ProxyRegistry, SharedVault, StartError, StdioEntry, init_and_list, record, resolve_env,
    start_stdio,
};
use crate::mcp_transport::Transport;

/// Delays between restarts of one server.
#[derive(Clone, Copy, Debug)]
pub struct RestartBackoff {
    /// The delay before the first restart.
    pub first: Duration,
    /// The longest delay; each restart doubles the last one up to here.
    pub cap: Duration,
    /// A run that stayed up this long after `initialize` sets the delay
    /// back to `first`.
    pub reset_after: Duration,
    /// This many runs in a row that never complete `initialize` stop
    /// the supervisor. A run that completes it sets the count back to
    /// zero, so a server that initializes and then exits is restarted
    /// without bound.
    pub abandon_after: u32,
}

/// The adapters' policy: about two minutes of attempts for a server
/// that never comes up.
pub const MCP_RESTART_BACKOFF: RestartBackoff = RestartBackoff {
    first: Duration::from_secs(1),
    cap: Duration::from_secs(60),
    reset_after: Duration::from_secs(60),
    abandon_after: 8,
};

/// How long supervisors get to finish a start already under way when
/// the proxy stops.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// Why a run did not get as far as `initialize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    pub cause: McpServerRestartCause,
    pub detail: String,
}

/// One supervised server, as the loop drives it.
#[async_trait::async_trait]
pub(crate) trait ServerLife: Send {
    /// Start the server, complete `initialize` and `tools/list`, and
    /// put its client in the registry. Returns the container id.
    async fn start(&mut self) -> Result<String, Failure>;
    /// Resolve when the container exits, with its exit code.
    async fn exited(&mut self, container_id: &str) -> Option<i64>;
    /// Take the server's client out of the registry and stop it.
    async fn retire(&mut self);
}

/// A server the registry started, or failed to start, at load, waiting
/// for a supervisor.
pub(crate) struct Pending {
    pub agent_id: String,
    pub server: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: std::collections::HashMap<String, String>,
    pub sandbox: StdioSandbox,
    pub host: SandboxHost,
    /// The container id of the run under way, or why there is none.
    pub first: Result<String, Failure>,
}

/// The supervisors of every contained server, and the switch that
/// stops them.
pub struct Supervisors {
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Supervisors {
    /// Supervise every server the registry loaded or tried to.
    pub async fn start(
        registry: Arc<Mutex<ProxyRegistry>>,
        vault: SharedVault,
        audit: Option<Arc<dyn SessionLog>>,
    ) -> Self {
        Self::start_with(registry, vault, audit, MCP_RESTART_BACKOFF).await
    }

    pub(crate) async fn start_with(
        registry: Arc<Mutex<ProxyRegistry>>,
        vault: SharedVault,
        audit: Option<Arc<dyn SessionLog>>,
        backoff: RestartBackoff,
    ) -> Self {
        let (stop, stopped) = watch::channel(false);
        let pending = registry.lock().await.take_pending();
        let tasks = pending
            .into_iter()
            .map(|p| {
                let first = p.first.clone();
                let mut life = ContainerLife {
                    registry: registry.clone(),
                    vault: vault.clone(),
                    audit: audit.clone(),
                    pending: p,
                };
                let audit = audit.clone();
                let stopped = stopped.clone();
                tokio::spawn(async move {
                    let (agent_id, server) =
                        (life.pending.agent_id.clone(), life.pending.server.clone());
                    supervise(
                        &mut life,
                        &agent_id,
                        &server,
                        first,
                        audit.as_ref(),
                        backoff,
                        stopped,
                    )
                    .await;
                })
            })
            .collect();
        Self { stop, tasks }
    }

    /// Stop supervising. A start under way gets five seconds to finish
    /// and leave its client in the registry, where the registry's own
    /// shutdown stops it.
    pub async fn stop(mut self) {
        let _ = self.stop.send(true);
        let finishing = futures_util::future::join_all(self.tasks.iter_mut());
        let _ = tokio::time::timeout(STOP_GRACE, finishing).await;
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Keep one server running until `stopped` turns true or the server is
/// given up on. `current` is the run under way: its container id, or
/// why it did not start.
pub(crate) async fn supervise(
    life: &mut dyn ServerLife,
    agent_id: &str,
    server: &str,
    mut current: Result<String, Failure>,
    audit: Option<&Arc<dyn SessionLog>>,
    backoff: RestartBackoff,
    mut stopped: watch::Receiver<bool>,
) {
    let mut delay = backoff.first;
    let mut attempt: u64 = 0;
    let mut uninitialized_runs: u32 = 0;
    loop {
        let (failure, ran_for) = match current {
            Ok(container_id) => {
                let started = tokio::time::Instant::now();
                let exit_code = tokio::select! {
                    code = life.exited(&container_id) => code,
                    _ = stopped.changed() => return,
                };
                if *stopped.borrow() {
                    // The proxy stopped the container; that is not an
                    // exit to restart from.
                    return;
                }
                let ran_for = started.elapsed();
                record(
                    audit,
                    SessionEvent::McpServerExited {
                        server_name: server.to_string(),
                        agent_id: agent_id.to_string(),
                        container_id,
                        exit_code,
                        stopped_by_proxy: false,
                    },
                );
                life.retire().await;
                uninitialized_runs = 0;
                let detail = match exit_code {
                    Some(code) => format!("exit code {code}"),
                    None => "exited".to_string(),
                };
                (
                    Failure {
                        cause: McpServerRestartCause::Exited,
                        detail,
                    },
                    Some(ran_for),
                )
            }
            Err(failure) => {
                uninitialized_runs += 1;
                (failure, None)
            }
        };

        if ran_for.is_some_and(|d| d >= backoff.reset_after) {
            delay = backoff.first;
            attempt = 0;
        }
        if uninitialized_runs >= backoff.abandon_after {
            tracing::error!(
                agent_id,
                server,
                "MCP server '{server}' ended {uninitialized_runs} runs in a row without \
                 completing initialize (last: {}, {}); it is no longer restarted. Fix it and \
                 restart the gateway.",
                failure.cause.as_str(),
                failure.detail
            );
            record(
                audit,
                SessionEvent::McpServerRestartAbandoned {
                    server_name: server.to_string(),
                    agent_id: agent_id.to_string(),
                    attempts: uninitialized_runs,
                    last_cause: failure.cause,
                    last_detail: failure.detail,
                },
            );
            return;
        }

        attempt += 1;
        let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
        tracing::warn!(
            agent_id,
            server,
            "MCP server '{server}' {} ({}); restart {attempt} in {delay_ms} ms",
            failure.cause.as_str(),
            failure.detail
        );
        record(
            audit,
            SessionEvent::McpServerRestart {
                server_name: server.to_string(),
                agent_id: agent_id.to_string(),
                attempt,
                cause: failure.cause,
                detail: failure.detail,
                delay_ms,
                ran_for_ms: ran_for.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            },
        );
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            _ = stopped.changed() => return,
        }
        delay = (delay * 2).min(backoff.cap);
        current = life.start().await;
        if *stopped.borrow() {
            return;
        }
    }
}

/// The real thing: a server started through the registry's start path.
struct ContainerLife {
    registry: Arc<Mutex<ProxyRegistry>>,
    vault: SharedVault,
    audit: Option<Arc<dyn SessionLog>>,
    pending: Pending,
}

#[async_trait::async_trait]
impl ServerLife for ContainerLife {
    async fn start(&mut self) -> Result<String, Failure> {
        let p = &self.pending;
        // Resolved afresh, so a credential rotated in the vault reaches
        // the next run.
        let resolved = {
            let guard = self.vault.lock().expect("vault mutex");
            resolve_env(&p.env, guard.as_ref())
        };
        let entry = StdioEntry {
            agent_id: &p.agent_id,
            server: &p.server,
            command: &p.command,
            args: &p.args,
            env: &p.env,
            sandbox: Some(&p.sandbox),
        };
        let transport = start_stdio(&p.host, entry, &resolved, self.audit.as_ref())
            .await
            .map_err(|e| Failure {
                cause: McpServerRestartCause::StartFailed,
                detail: match e {
                    StartError::Refused { reason, why } => format!("{reason}: {why}"),
                    StartError::Failed(e) => e.to_string(),
                },
            })?;
        let container_id = transport.container_id().unwrap_or_default().to_string();
        let mut client = McpClient::new(p.server.clone(), Transport::Stdio(Box::new(transport)));
        if let Err(e) = init_and_list(&mut client, &p.agent_id).await {
            client.shutdown().await;
            return Err(Failure {
                cause: McpServerRestartCause::InitializeFailed,
                detail: e.to_string(),
            });
        }
        self.registry
            .lock()
            .await
            .install(&p.agent_id, &p.server, client);
        Ok(container_id)
    }

    async fn exited(&mut self, container_id: &str) -> Option<i64> {
        let docker = self.pending.host.docker.as_ref()?;
        let mut wait = docker.wait_container(
            container_id,
            Some(bollard::query_parameters::WaitContainerOptions {
                condition: "not-running".into(),
            }),
        );
        match wait.next().await {
            Some(Ok(exit)) => Some(exit.status_code),
            Some(Err(bollard::errors::Error::DockerContainerWaitError { code, .. })) => Some(code),
            _ => None,
        }
    }

    async fn retire(&mut self) {
        let client = self
            .registry
            .lock()
            .await
            .take(&self.pending.agent_id, &self.pending.server);
        if let Some(mut client) = client {
            client.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const FAST: RestartBackoff = RestartBackoff {
        first: Duration::from_millis(10),
        cap: Duration::from_millis(40),
        reset_after: Duration::from_secs(60),
        abandon_after: 8,
    };

    /// What one scripted run does once started.
    #[derive(Clone)]
    enum Run {
        /// Exits with this code at once.
        Exits(i64),
        /// Stays up until the test stops supervision.
        StaysUp,
    }

    /// Plays back a script: each start takes the next result, each
    /// started run behaves as its `Run` says.
    struct Scripted {
        starts: VecDeque<Result<Run, Failure>>,
        current: Option<Run>,
        started: u32,
        retired: u32,
    }

    impl Scripted {
        fn new(starts: Vec<Result<Run, Failure>>) -> Self {
            Self {
                starts: starts.into(),
                current: None,
                started: 0,
                retired: 0,
            }
        }
    }

    #[async_trait::async_trait]
    impl ServerLife for Scripted {
        async fn start(&mut self) -> Result<String, Failure> {
            self.started += 1;
            match self.starts.pop_front().unwrap_or(Ok(Run::StaysUp)) {
                Ok(run) => {
                    self.current = Some(run);
                    Ok(format!("c{}", self.started))
                }
                Err(f) => Err(f),
            }
        }

        async fn exited(&mut self, _container_id: &str) -> Option<i64> {
            match self.current.take() {
                Some(Run::Exits(code)) => Some(code),
                _ => std::future::pending().await,
            }
        }

        async fn retire(&mut self) {
            self.retired += 1;
        }
    }

    fn start_failed() -> Failure {
        Failure {
            cause: McpServerRestartCause::StartFailed,
            detail: "image_unavailable: gone".into(),
        }
    }

    fn log() -> Arc<dyn SessionLog> {
        Arc::new(wirken_audit::SqliteSessionLog::open_in_memory().unwrap())
    }

    fn rows(log: &Arc<dyn SessionLog>) -> Vec<SessionEvent> {
        let handle = log.handle_for(wirken_audit::SessionId::new(
            crate::mcp_registry::MCP_SENTINEL_SESSION,
        ));
        log.get_since(&handle, 0)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect()
    }

    #[tokio::test]
    async fn a_server_that_never_starts_is_given_up_after_eight_runs() {
        let log = log();
        let mut life = Scripted::new(vec![Err(start_failed()); 7]);
        let (_stop, stopped) = watch::channel(false);
        supervise(
            &mut life,
            "agent-1",
            "srv",
            Err(start_failed()),
            Some(&log),
            FAST,
            stopped,
        )
        .await;

        let rows = rows(&log);
        let delays: Vec<u64> = rows
            .iter()
            .filter_map(|e| match e {
                SessionEvent::McpServerRestart { delay_ms, .. } => Some(*delay_ms),
                _ => None,
            })
            .collect();
        assert_eq!(delays, [10, 20, 40, 40, 40, 40, 40]);
        assert_eq!(
            rows.last(),
            Some(&SessionEvent::McpServerRestartAbandoned {
                server_name: "srv".into(),
                agent_id: "agent-1".into(),
                attempts: 8,
                last_cause: McpServerRestartCause::StartFailed,
                last_detail: "image_unavailable: gone".into(),
            })
        );
        assert_eq!(life.started, 7);
    }

    #[tokio::test]
    async fn an_exit_after_initialize_is_recorded_restarted_and_resets_the_count() {
        let log = log();
        // Exits, then seven failed starts, then one that initializes and
        // exits, then seven more failures: never eight in a row.
        let mut script = vec![Err(start_failed()); 7];
        script.push(Ok(Run::Exits(3)));
        script.extend(vec![Err(start_failed()); 7]);
        script.push(Ok(Run::StaysUp));
        let mut life = Scripted::new(script);
        life.current = Some(Run::Exits(1));
        let (stop, stopped) = watch::channel(false);
        let log2 = log.clone();
        let task = tokio::spawn(async move {
            supervise(
                &mut life,
                "agent-1",
                "srv",
                Ok("c0".into()),
                Some(&log2),
                FAST,
                stopped,
            )
            .await;
            life
        });
        // Wait for the last run to be up: sixteen starts.
        for _ in 0..500 {
            let restarts = rows(&log)
                .iter()
                .filter(|e| matches!(e, SessionEvent::McpServerRestart { .. }))
                .count();
            if restarts >= 16 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The sixteenth row comes before the last start; let it happen.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = stop.send(true);
        let life = task.await.unwrap();

        let rows = rows(&log);
        assert!(
            !rows
                .iter()
                .any(|e| matches!(e, SessionEvent::McpServerRestartAbandoned { .. })),
            "{rows:?}"
        );
        let exits: Vec<Option<i64>> = rows
            .iter()
            .filter_map(|e| match e {
                SessionEvent::McpServerExited { exit_code, .. } => Some(*exit_code),
                _ => None,
            })
            .collect();
        assert_eq!(exits, [Some(1), Some(3)]);
        assert_eq!(life.retired, 2);
        assert_eq!(life.started, 16);
        let first = rows
            .iter()
            .find(|e| matches!(e, SessionEvent::McpServerRestart { .. }))
            .unwrap();
        assert!(
            matches!(
                first,
                SessionEvent::McpServerRestart {
                    attempt: 1,
                    cause: McpServerRestartCause::Exited,
                    ran_for_ms: Some(_),
                    ..
                }
            ),
            "{first:?}"
        );
    }

    #[tokio::test]
    async fn stopping_supervision_restarts_nothing() {
        let log = log();
        let mut life = Scripted::new(vec![]);
        life.current = Some(Run::StaysUp);
        let (stop, stopped) = watch::channel(false);
        let log2 = log.clone();
        let task = tokio::spawn(async move {
            supervise(
                &mut life,
                "agent-1",
                "srv",
                Ok("c0".into()),
                Some(&log2),
                FAST,
                stopped,
            )
            .await;
            life
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = stop.send(true);
        let life = task.await.unwrap();
        assert!(rows(&log).is_empty());
        assert_eq!((life.started, life.retired), (0, 0));
    }

    /// Live: a contained server whose container exits after it answered
    /// `initialize` is started again, re-initialized, and put back in
    /// the registry; the old container is gone and the rows say so.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_contained_server_that_exits_is_restarted_live() {
        let Ok(docker) = bollard::Docker::connect_with_local_defaults() else {
            return;
        };
        if docker.ping().await.is_err()
            || docker.inspect_image("debian:bookworm-slim").await.is_err()
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut host = SandboxHost::new(dir.path());
        host.probe().await;
        let answer = r#"read a; printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"t","version":"1"}}}\n'; read b; read c; printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}\n'"#;
        // The first run marks its scratch dir and exits; the next stays.
        let script = format!(
            "{answer}; if [ -f /scratch/ran ]; then cat >/dev/null; else touch /scratch/ran; exit 3; fi"
        );
        let config: crate::mcp_config::McpConfig = serde_json::from_value(serde_json::json!({
            "servers": { "flaky": {
                "command": "sh",
                "args": ["-c", script],
                "sandbox": { "image": "debian:bookworm-slim", "scratch": true }
            }}
        }))
        .unwrap();
        let log = log();
        let vault: SharedVault = Arc::new(std::sync::Mutex::new(None));
        let mut registry = ProxyRegistry::new().with_sandbox(host);
        registry
            .load_agent("agent-1", &config, vault.clone(), Some(&log))
            .await
            .unwrap();
        let registry = Arc::new(Mutex::new(registry));
        let supervisors = Supervisors::start_with(
            registry.clone(),
            vault,
            Some(log.clone()),
            RestartBackoff {
                first: Duration::from_millis(100),
                ..MCP_RESTART_BACKOFF
            },
        )
        .await;

        let mut started = 0;
        for _ in 0..200 {
            started = rows(&log)
                .iter()
                .filter(|e| matches!(e, SessionEvent::McpServerSandboxed { .. }))
                .count();
            if started >= 2 && registry.lock().await.has_agent("agent-1") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        supervisors.stop().await;
        let rows = rows(&log);
        let containers: Vec<String> = rows
            .iter()
            .filter_map(|e| match e {
                SessionEvent::McpServerSandboxed { container_id, .. } => Some(container_id.clone()),
                _ => None,
            })
            .collect();
        let restarted = registry.lock().await.has_agent("agent-1");
        registry.lock().await.shutdown().await;

        assert_eq!(started, 2, "{rows:?}");
        assert!(restarted, "{rows:?}");
        assert!(
            rows.iter().any(|e| matches!(
                e,
                SessionEvent::McpServerExited {
                    exit_code: Some(3),
                    ..
                }
            )),
            "{rows:?}"
        );
        assert!(
            rows.iter().any(|e| matches!(
                e,
                SessionEvent::McpServerRestart {
                    attempt: 1,
                    cause: McpServerRestartCause::Exited,
                    ..
                }
            )),
            "{rows:?}"
        );
        for id in containers {
            assert!(
                docker
                    .inspect_container(
                        &id,
                        None::<bollard::query_parameters::InspectContainerOptions>
                    )
                    .await
                    .is_err(),
                "container {id} outlived its run"
            );
        }
    }
}
