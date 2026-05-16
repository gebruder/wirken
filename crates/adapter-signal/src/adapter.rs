use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use lru::LruCache;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, mpsc, oneshot};

use wirken_adapter_core::{OutboundFormatter, SignalFormatter};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{
    AdapterIdentity, IpcFrameReader, IpcFrameWriter, connect, perform_adapter_handshake,
    split_stream,
};

use crate::convert::{self, InboundKind, SignalAllowlist, SignalInbound};
use crate::error::SignalError;

/// Size of the self-echo cache. Stores the message timestamp (Signal's
/// message id) of every successful send RPC. When a `syncMessage.sentMessage`
/// notification arrives with a matching timestamp, the adapter drops it
/// rather than forwarding the operator's own outgoing reply back into the
/// agent as a fresh inbound.
const ECHO_CACHE_CAP: usize = 1024;

/// Bounded capacity for the inbound channel. Large enough to absorb a
/// burst (e.g., backlog delivery after reconnect) without dropping
/// notifications, small enough that a stalled gateway writer produces
/// backpressure rather than unbounded memory growth.
const INBOUND_CHAN_CAP: usize = 256;

/// Wall-clock timeout on any single signal-cli JSON-RPC request.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Reconnect backoff. Starts at `BACKOFF_MIN`, doubles on each failure,
/// caps at `BACKOFF_MAX`. Successful connect (subscribe + read-loop
/// entry) resets to `BACKOFF_MIN`.
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Wall-clock cap on how long `send_message` will wait for
/// signal-cli reconnect when the connection is down. After this
/// elapses the call returns `SignalError::ReconnectTimeout` so
/// the gateway-side path can emit `ApprovalRequestFailed` with a
/// `reconnect_timeout` reason rather than waiting indefinitely on
/// a daemon that may be permanently gone. Overridable via
/// `WIRKEN_SIGNAL_RECONNECT_WAIT_S`.
pub const DEFAULT_RECONNECT_WAIT_SECS: u64 = 30;

pub fn resolve_reconnect_wait() -> Duration {
    match std::env::var("WIRKEN_SIGNAL_RECONNECT_WAIT_S") {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => Duration::from_secs(DEFAULT_RECONNECT_WAIT_SECS),
        },
        Err(_) => Duration::from_secs(DEFAULT_RECONNECT_WAIT_SECS),
    }
}

/// Sentinel for "no subscribe in flight" / "no subscription yet".
/// signal-cli assigns monotonically increasing positive ids, so
/// `u64::MAX` never collides with a real subscription or request id.
const ID_SENTINEL: u64 = u64::MAX;

/// Signal adapter: connects to signal-cli's Unix-socket JSON-RPC daemon,
/// subscribes to receive notifications, and bridges them <-> the Wirken
/// gateway IPC frame channel.
///
/// Transport rewrite (0.7.9): replaces the HTTP polling loop. signal-cli
/// 0.14.x auto-consumes inbound messages in the daemon and blocks
/// concurrent `receive` RPCs, which broke the previous implementation.
/// The socket path pushes envelopes as JSON-RPC notifications after a
/// single `subscribeReceive` call, no polling required.
pub struct SignalAdapter {
    identity: AdapterIdentity,
    socket_path: PathBuf,
    phone_number: String,
    allowlist: SignalAllowlist,
    /// When false (default), `syncMessage.sentMessage` notifications are
    /// dropped entirely. When true, they are still filtered by the
    /// self-echo cache but otherwise forwarded so tests-to-self work.
    /// Controlled by `WIRKEN_SIGNAL_FORWARD_LINKED_DEVICE_SENDS=1`.
    forward_linked_device_sends: bool,
    /// Timestamps of messages this adapter sent successfully via the
    /// socket. Signal echoes our own sends back as syncMessage.sentMessage
    /// notifications; matching on the returned timestamp suppresses the
    /// reply loop.
    echoed_timestamps: Mutex<LruCache<i64, ()>>,
    /// Global (per-adapter-lifetime) request-id counter. Survives
    /// reconnects so an in-flight RPC timing out on the old connection
    /// cannot be confused with a fresh request on the new one.
    next_req_id: AtomicU64,
    /// Current signal-cli connection. `None` during reconnect windows;
    /// send RPCs during those return `ConnectionClosed`.
    inner: Mutex<Option<Arc<Connection>>>,
    inbound_tx: mpsc::Sender<(SignalInbound, InboundKind)>,
    /// Receiver is taken once by `run()` and handed to the inbound-pump
    /// task. Kept behind a Mutex<Option<_>> so the struct itself can be
    /// Sync without carrying a !Send handle.
    inbound_rx: Mutex<Option<mpsc::Receiver<(SignalInbound, InboundKind)>>>,
    /// Channel-specific outbound rendering. Agents emit markdown;
    /// Signal only renders a narrow dialect (`*bold*`, `_italic_`,
    /// no tables, no fenced blocks). Running every reply through
    /// `SignalFormatter` strips the markdown vocabulary Signal shows
    /// as literal characters (`###`, `**`, pipes).
    formatter: SignalFormatter,
    /// Adapter-local prefix → request_id map for the text-command
    /// approval surface. Populated when an `ApprovalRequest` frame
    /// arrives from the gateway (we render the prompt and remember
    /// which prefix corresponds to which request_id). Looked up
    /// when an inbound `!approve <prefix>` / `!deny <prefix>`
    /// command arrives. Collisions on the 8-char prefix produce
    /// a Vec of request_ids; the handler responds with a
    /// clarification message and does not route. Entries live
    /// until the operator decides, the gate times out, or the
    /// adapter restarts (in-memory only; cross-restart in-flight
    /// approvals would have to be re-issued by the gateway).
    approval_prefix_map: Mutex<HashMap<String, Vec<String>>>,
    /// Gateway-bound IPC writer, populated once at the top of
    /// `run()` after the adapter handshake completes. The
    /// inbound-command path (`handle_notification` ->
    /// `route_approval_command`) takes a clone to send
    /// `ApprovalDecision` frames back to the gateway without
    /// re-routing through the inbound-pump task. `None` only
    /// before `run()` populates it; production callers must call
    /// `run()` before driving inbound notifications.
    gateway_writer: Mutex<Option<Arc<Mutex<IpcFrameWriter>>>>,
    /// Notification fired by `run()` after every successful
    /// signal-cli connect (initial + reconnect). `send_message`
    /// uses this to block during a reconnect window rather than
    /// failing the caller's frame immediately with
    /// `ConnectionClosed`. Edge-triggered, with the
    /// register-then-recheck pattern in `wait_for_connection` so
    /// a notify that fires between check and registration is not
    /// lost.
    connect_notify: Arc<tokio::sync::Notify>,
}

/// Per-connection state. Recreated on every reconnect cycle. Shared
/// between the reader task (which consumes the read half and resolves
/// pending oneshots) and the adapter body (which writes requests and
/// awaits responses).
struct Connection {
    writer: Mutex<OwnedWriteHalf>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Value>>>,
    /// Request id of the in-flight `subscribeReceive` call.
    /// `ID_SENTINEL` when no subscribe is pending.
    subscribe_request_id: AtomicU64,
    /// Subscription id returned by `subscribeReceive`. `ID_SENTINEL`
    /// until the reader intercepts the response and stores it.
    subscription_id: AtomicU64,
}

impl SignalAdapter {
    /// Construct an adapter. `endpoint` accepts a bare filesystem path
    /// (e.g. `/tmp/signal-cli.sock`) or the `unix://` scheme. HTTP URLs
    /// are rejected with a migration error message.
    pub fn new(
        identity: AdapterIdentity,
        endpoint: String,
        phone_number: String,
        allowlist: SignalAllowlist,
    ) -> Result<Self, SignalError> {
        let socket_path = parse_endpoint(&endpoint)?;
        let forward_linked_device_sends =
            std::env::var("WIRKEN_SIGNAL_FORWARD_LINKED_DEVICE_SENDS")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

        let (tx, rx) = mpsc::channel(INBOUND_CHAN_CAP);
        let echo_cap = NonZeroUsize::new(ECHO_CACHE_CAP).expect("ECHO_CACHE_CAP is nonzero");
        Ok(Self {
            identity,
            socket_path,
            phone_number,
            allowlist,
            forward_linked_device_sends,
            echoed_timestamps: Mutex::new(LruCache::new(echo_cap)),
            next_req_id: AtomicU64::new(1),
            inner: Mutex::new(None),
            inbound_tx: tx,
            inbound_rx: Mutex::new(Some(rx)),
            formatter: SignalFormatter,
            approval_prefix_map: Mutex::new(HashMap::new()),
            gateway_writer: Mutex::new(None),
            connect_notify: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// Length in hex characters of the prefix the operator types
    /// to disambiguate a pending approval. The full request_id is
    /// also included in the approval message body for operators
    /// who hit a collision; 8 is the typing-ergonomic default.
    pub(crate) const PREFIX_LEN: usize = 8;

    /// Run the adapter to completion (or indefinitely). Handles the
    /// gateway handshake once, makes the first signal-cli connect,
    /// then spawns the long-lived gateway-side tasks (heartbeat,
    /// outbound handler, inbound pump), and enters the signal-cli
    /// reconnect loop. First-attempt signal-cli failure is fatal
    /// (run() returns Err so the adapter process exits with a
    /// clear error); mid-session disconnects retry with backoff.
    ///
    /// Connect ordering: outbound_handler is spawned only after the
    /// first signal-cli connect+subscribe completes. The
    /// alternative ordering (handler first, connect second) admits
    /// a race where a gateway frame arriving in the connect window
    /// would fail with ConnectionClosed and surface to operators
    /// as ApprovalRequestFailed for what should have been a
    /// well-formed pending approval.
    pub async fn run(self: Arc<Self>, gateway_socket: &Path) -> Result<(), SignalError> {
        if self.allowlist.is_empty() {
            tracing::warn!(
                "Signal adapter starting with an empty sender allowlist. All incoming \
                 messages will be dropped. Add entries via `wirken setup` or the vault \
                 under `signal-allowed-senders` to enable delivery."
            );
        } else {
            tracing::info!(
                "Signal adapter allowlist contains {} entries",
                self.allowlist.len()
            );
        }

        tracing::info!("Connecting to gateway at {}", gateway_socket.display());
        let gw_stream = connect(gateway_socket).await?;
        let (mut gw_reader, mut gw_writer) = split_stream(gw_stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut gw_reader, &mut gw_writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let gw_writer = Arc::new(Mutex::new(gw_writer));
        *self.gateway_writer.lock().await = Some(gw_writer.clone());

        let hb_writer = gw_writer.clone();
        tokio::spawn(heartbeat_loop(hb_writer));

        let inbound_rx = self
            .inbound_rx
            .lock()
            .await
            .take()
            .expect("inbound_rx taken twice — run() must only be called once");
        let pump_writer = gw_writer.clone();
        tokio::spawn(inbound_pump(inbound_rx, pump_writer));

        tracing::info!(
            "Connecting to signal-cli socket at {} for account {}",
            self.socket_path.display(),
            self.phone_number
        );

        // First signal-cli connect happens BEFORE spawning the
        // outbound handler. If signal-cli is unreachable at
        // startup (daemon not running, socket path wrong) the
        // adapter exits here with a clear error rather than
        // entering a degraded state where every outbound frame
        // surfaces as ApprovalRequestFailed.
        let mut reader_handle = self.connect_and_subscribe().await?;

        let outbound_self = self.clone();
        let outbound_writer = gw_writer.clone();
        tokio::spawn(async move {
            outbound_handler(gw_reader, outbound_self, outbound_writer).await;
        });

        let mut backoff = BACKOFF_MIN;
        loop {
            let outcome = match reader_handle.await {
                Ok(r) => r,
                Err(join_err) => Err(SignalError::Signal(format!(
                    "reader task joined: {join_err}"
                ))),
            };
            *self.inner.lock().await = None;

            match outcome {
                Ok(()) => {
                    tracing::info!("signal-cli socket closed, reconnecting");
                    backoff = BACKOFF_MIN;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        backoff_ms = backoff.as_millis() as u64,
                        "signal-cli socket error, reconnecting"
                    );
                }
            }

            // Reconnect attempts. Gateway frames arriving while
            // we are between attempts park in
            // `send_message` -> `wait_for_connection` rather than
            // failing immediately; the notify_waiters() inside
            // `connect_and_subscribe` wakes them after the next
            // successful attempt. If the cap elapses with no
            // attempt succeeding, the parked send returns
            // `ReconnectTimeout` and the gateway sees an
            // `ApprovalRequestFailed` with that reason.
            loop {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
                match self.connect_and_subscribe().await {
                    Ok(handle) => {
                        reader_handle = handle;
                        backoff = BACKOFF_MIN;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            backoff_ms = backoff.as_millis() as u64,
                            "signal-cli reconnect failed; will retry"
                        );
                    }
                }
            }
        }
    }

    /// Connect to signal-cli, spawn the read loop, and complete
    /// the `subscribeReceive` handshake. Returns the `JoinHandle`
    /// of the spawned read loop so the caller can await connection
    /// lifetime separately from establishment. On any failure the
    /// reader is aborted and `self.inner` is cleared so a retry
    /// starts from a clean state.
    async fn connect_and_subscribe(
        self: &Arc<Self>,
    ) -> Result<tokio::task::JoinHandle<Result<(), SignalError>>, SignalError> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (read, write) = stream.into_split();
        let conn = Arc::new(Connection {
            writer: Mutex::new(write),
            pending: Mutex::new(HashMap::new()),
            subscribe_request_id: AtomicU64::new(ID_SENTINEL),
            subscription_id: AtomicU64::new(ID_SENTINEL),
        });

        *self.inner.lock().await = Some(conn.clone());

        // Spawn the reader BEFORE sending subscribe so the response does
        // not deadlock on a missing consumer. The reader intercepts the
        // subscribe response and publishes the subscription id before
        // any subsequent notification line can be dispatched.
        let reader_adapter = self.clone();
        let reader_conn = conn.clone();
        let reader_handle =
            tokio::spawn(async move { read_loop(read, reader_adapter, reader_conn).await });

        if let Err(e) = self.subscribe(&conn).await {
            reader_handle.abort();
            *self.inner.lock().await = None;
            return Err(e);
        }
        // Wake any send_message calls that are parked in
        // wait_for_connection because they hit `self.inner = None`
        // during a reconnect window.
        self.connect_notify.notify_waiters();
        Ok(reader_handle)
    }

    /// Block until `self.inner` is `Some`, returning the
    /// `Arc<Connection>` for use by the caller. Returns
    /// `SignalError::ReconnectTimeout` when `cap` elapses without
    /// a successful reconnect. Designed for the
    /// reconnect-window race in `send_message`: a gateway frame
    /// that arrives while the reconnect inner loop is between
    /// attempts can park here rather than failing the caller's
    /// approval delivery with the misleading
    /// `channel_not_accessible` label.
    ///
    /// The register-then-recheck pattern (enable the Notified
    /// future *before* the state check) ensures a notify that
    /// fires between our state check and our await is not lost.
    async fn wait_for_connection(&self, cap: Duration) -> Result<Arc<Connection>, SignalError> {
        let deadline = tokio::time::Instant::now() + cap;
        loop {
            // Register the waiter BEFORE checking state. A
            // notify_waiters fired between our state check and
            // our await would otherwise be lost; enable() makes
            // this future visible to the next notify regardless
            // of polling order.
            let notified = self.connect_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            // Scoped to drop the MutexGuard before any await.
            let inner_clone = {
                let guard = self.inner.lock().await;
                guard.as_ref().cloned()
            };
            if let Some(conn) = inner_clone {
                return Ok(conn);
            }

            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(SignalError::ReconnectTimeout);
            }

            if tokio::time::timeout(remaining, notified).await.is_err() {
                return Err(SignalError::ReconnectTimeout);
            }
        }
    }

    async fn subscribe(&self, conn: &Arc<Connection>) -> Result<(), SignalError> {
        let id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        conn.subscribe_request_id.store(id, Ordering::Release);

        let resp = self
            .rpc_with_id(
                conn,
                "subscribeReceive",
                json!({"account": self.phone_number}),
                id,
            )
            .await?;

        let sub_id = resp
            .pointer("/result")
            .and_then(|v| v.as_u64())
            .ok_or(SignalError::BadSubscribeResponse)?;
        tracing::info!("Subscribed to signal-cli receive stream (subscription id {sub_id})");
        Ok(())
    }

    /// Issue a signal-cli JSON-RPC call on the current connection. Returns
    /// the full response `Value` (caller extracts `result` or `error`).
    async fn rpc(
        &self,
        conn: &Arc<Connection>,
        method: &str,
        params: Value,
    ) -> Result<Value, SignalError> {
        let id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        self.rpc_with_id(conn, method, params, id).await
    }

    async fn rpc_with_id(
        &self,
        conn: &Arc<Connection>,
        method: &str,
        params: Value,
        id: u64,
    ) -> Result<Value, SignalError> {
        let (tx, rx) = oneshot::channel();
        conn.pending.lock().await.insert(id, tx);

        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        {
            let mut w = conn.writer.lock().await;
            w.write_all(line.as_bytes()).await?;
            w.flush().await?;
        }

        match tokio::time::timeout(RPC_TIMEOUT, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(SignalError::ConnectionClosed),
            Err(_) => {
                conn.pending.lock().await.remove(&id);
                Err(SignalError::Timeout {
                    method: method.into(),
                })
            }
        }
    }

    /// Dispatch a single inbound JSON-RPC notification from signal-cli.
    /// Applies, in order: subscription-id match, self-echo drop,
    /// linked-device-send gate, envelope extraction, allowlist.
    async fn handle_notification(&self, msg: Value, conn: &Arc<Connection>) {
        let Some(params) = msg.get("params") else {
            return;
        };
        // Filter 1: drop legacy fan-out notifications that do not carry
        // a subscription id. signal-cli emits every envelope twice per
        // subscriber — once in the subscribed form under /result/envelope
        // and once in the legacy form under /envelope. We read only the
        // subscribed form, keyed on our own subscription id.
        let Some(sub) = params.get("subscription").and_then(|v| v.as_u64()) else {
            return;
        };
        if sub != conn.subscription_id.load(Ordering::Acquire) {
            return;
        }

        let Some(envelope) = params.pointer("/result/envelope") else {
            return;
        };

        let envelope_ts = envelope
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let is_sync_sent = envelope.pointer("/syncMessage/sentMessage").is_some();

        // Filter 2: self-echo. When this adapter sends a reply via
        // signal-cli, Signal's multi-device protocol mirrors that send
        // back to every linked device including the daemon itself. The
        // echo arrives as syncMessage.sentMessage with the same
        // timestamp signal-cli returned on the `send` RPC. Drop it so
        // the agent does not process its own reply as a fresh inbound.
        if is_sync_sent
            && envelope_ts != 0
            && self.echoed_timestamps.lock().await.contains(&envelope_ts)
        {
            tracing::debug!(ts = envelope_ts, "dropping own send echo");
            return;
        }

        // Filter 3: linked-device-send gate. Operator sending from their
        // phone to a contact is visible here as a SyncSent envelope. The
        // default is to drop those (agent only processes inbound from
        // other people); operators opt-in for test-to-self via env var.
        if is_sync_sent && !self.forward_linked_device_sends {
            tracing::debug!(
                ts = envelope_ts,
                "dropping linked-device send (WIRKEN_SIGNAL_FORWARD_LINKED_DEVICE_SENDS not set)"
            );
            return;
        }

        let Some((inbound, _kind)) = convert::extract_inbound(envelope) else {
            return;
        };

        if !convert::should_process(&inbound, &self.allowlist) {
            tracing::debug!(
                "Dropping Signal message from {} (not in allowlist or empty)",
                inbound
                    .group_id
                    .as_deref()
                    .unwrap_or(inbound.sender.as_str())
            );
            return;
        }

        // Filter 4: text-command approval shortcut. If the
        // allowlisted sender typed `!approve <prefix>` /
        // `!deny <prefix> [reason]`, route directly to the
        // approval-command handler and DO NOT forward to the
        // gateway as a fresh inbound message. Otherwise continue
        // the existing pipeline (regular agent-bound message).
        if let Some(cmd) = crate::commands::parse_command(&inbound.text) {
            self.route_approval_command(&inbound, cmd).await;
            return;
        }

        if let Err(e) = self.inbound_tx.send((inbound, _kind)).await {
            tracing::error!("inbound channel closed: {e}");
        }
    }

    /// Resolve a parsed approval command against the adapter's
    /// prefix map and forward the operator's decision to the
    /// gateway. Zero-match or multi-match on the prefix produces
    /// a clarification reply (sent back to the conversation the
    /// command came from) and does NOT send an `ApprovalDecision`
    /// frame; the operator retries with a more specific prefix or
    /// the full request_id. Authorization (allowlist vs the
    /// approver registry) happens gateway-side after the
    /// `ApprovalDecision` arrives; the adapter does not consult
    /// registry state.
    async fn route_approval_command(
        &self,
        inbound: &SignalInbound,
        cmd: crate::commands::CommandKind,
    ) {
        let prefix = match &cmd {
            crate::commands::CommandKind::Approve { prefix } => prefix.clone(),
            crate::commands::CommandKind::Deny { prefix, .. } => prefix.clone(),
        };
        // The conversation to reply into for clarifications. In a
        // group, that's the group; in a 1:1 approval, the sender.
        let reply_conversation = inbound
            .group_id
            .clone()
            .unwrap_or_else(|| inbound.sender.clone());

        let matches: Vec<String> = {
            let map = self.approval_prefix_map.lock().await;
            map.get(&prefix).cloned().unwrap_or_default()
        };

        if matches.is_empty() {
            let _ = self
                .send_message(
                    &reply_conversation,
                    &format!("no pending request matching prefix `{prefix}`."),
                )
                .await;
            return;
        }
        if matches.len() > 1 {
            let count = matches.len();
            let _ = self
                .send_message(
                    &reply_conversation,
                    &format!(
                        "prefix `{prefix}` matches {count} pending requests; use a longer \
                         prefix or paste the full request id from the approval message."
                    ),
                )
                .await;
            return;
        }

        let request_id = matches.into_iter().next().expect("len == 1");
        // Drop the prefix entry now so a duplicate command from
        // another allowlisted operator doesn't double-resolve.
        // The gateway's authorization step still gates the
        // resolve; this just avoids redundant work on the wire.
        {
            let mut map = self.approval_prefix_map.lock().await;
            map.remove(&prefix);
        }

        let (is_allow, deny_reason_wire): (bool, String) = match cmd {
            crate::commands::CommandKind::Approve { .. } => (true, String::new()),
            crate::commands::CommandKind::Deny { reason, .. } => {
                (false, reason.unwrap_or_default())
            }
        };

        // Actor identity: prefer ACI UUID (stable across phone
        // number privacy changes), fall back to E.164 phone.
        // Empty when neither is present (the allowlist already
        // gated this so an empty fallback would be surprising).
        let actor_user_id = inbound
            .sender_uuid
            .clone()
            .unwrap_or_else(|| inbound.sender.clone());
        let actor_display = inbound.sender_name.clone();

        let Some(writer) = self.gateway_writer.lock().await.clone() else {
            tracing::error!(
                request_id = %request_id,
                "signal approval: gateway writer not yet initialized; dropping command"
            );
            return;
        };

        let mut decision_msg = capnp::message::Builder::new_default();
        convert::build_approval_decision(
            &mut decision_msg,
            &request_id,
            is_allow,
            &deny_reason_wire,
            &actor_user_id,
            &actor_display,
        );
        {
            let mut w = writer.lock().await;
            if let Err(e) = w.write_message(&decision_msg).await {
                tracing::error!(
                    request_id = %request_id,
                    error = %e,
                    "signal approval: failed to forward ApprovalDecision to gateway"
                );
            }
        }
        // `reply_conversation` is kept on the stack for a future
        // in-channel acknowledgment (the Signal surface currently
        // does not echo the decision back; the audit chain is the
        // record of record). Suppress the unused-variable warn.
        let _ = reply_conversation;
    }

    /// Send a Signal message and record the returned timestamp in the
    /// self-echo cache so the subsequent SyncSent notification is
    /// filtered out. Returns the Signal message timestamp (used as the
    /// message id in the gateway result frame).
    ///
    /// Routing: phone-shaped `conversation_id` values (starting with
    /// `+`, E.164) go through the `recipient` param; anything else is
    /// treated as a Signal group id and goes through `groupId`.
    /// signal-cli rejects the RPC if both are present, so this
    /// branching is required for group sends to work at all.
    async fn send_message(&self, conversation_id: &str, text: &str) -> Result<i64, SignalError> {
        // Fast path: signal-cli is currently connected. Slow
        // path: park on `wait_for_connection` until reconnect
        // completes or the cap (default 30s) elapses. The slow
        // path catches the mid-session reconnect window so
        // gateway frames arriving during the window deliver
        // after reconnect rather than failing immediately with
        // `channel_not_accessible`.
        // Scope the lock so its MutexGuard drops BEFORE the
        // wait_for_connection await. Without the explicit scope
        // the guard would live across the await (match scrutinee
        // temporary), and wait_for_connection takes the same
        // mutex - deadlock.
        let inner_clone = {
            let guard = self.inner.lock().await;
            guard.as_ref().cloned()
        };
        let conn = match inner_clone {
            Some(c) => c,
            None => self.wait_for_connection(resolve_reconnect_wait()).await?,
        };

        // Agents emit markdown; Signal renders almost none of it.
        // Run the reply through SignalFormatter here so every path
        // into signal-cli's send RPC shares the same rendering.
        let rendered = self.formatter.format(text);

        let params = if is_group_id(conversation_id) {
            json!({
                "account": self.phone_number,
                "groupId": conversation_id,
                "message": rendered,
            })
        } else {
            json!({
                "account": self.phone_number,
                "recipient": [conversation_id],
                "message": rendered,
            })
        };

        let resp = self.rpc(&conn, "send", params).await?;

        if let Some(err) = resp.get("error") {
            return Err(SignalError::Signal(err.to_string()));
        }

        let ts = resp
            .pointer("/result/timestamp")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| SignalError::Signal("send response missing result.timestamp".into()))?;

        self.echoed_timestamps.lock().await.put(ts, ());
        Ok(ts)
    }
}

/// Heuristic: Signal 1:1 recipients are either E.164 phone numbers
/// (start with `+`) or ACI UUIDs (canonical layout, see
/// [`convert::is_canonical_uuid`]). Everything else in a
/// `conversation_id` slot is treated as a Signal group id.
fn is_group_id(s: &str) -> bool {
    !s.starts_with('+') && !convert::is_canonical_uuid(s)
}

/// Normalize and validate a configured endpoint string. Accepts
/// `unix:///path`, bare filesystem paths, and rejects http(s) URLs
/// with a migration-oriented error message.
fn parse_endpoint(raw: &str) -> Result<PathBuf, SignalError> {
    let trimmed = raw.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Err(SignalError::HttpEndpointRejected(trimmed.to_string()));
    }
    let path = trimmed.strip_prefix("unix://").unwrap_or(trimmed);
    Ok(PathBuf::from(path))
}

/// Read loop: newline-delimited JSON-RPC messages from signal-cli. Splits
/// by `id` presence into responses (routed to pending oneshot senders)
/// and notifications (dispatched to `handle_notification`).
///
/// Critical invariant: when the reader sees the response to an
/// in-flight `subscribeReceive` call, it stores the returned
/// subscription id in the connection atomic *before* advancing to the
/// next line. Because signal-cli emits messages in order over the
/// socket, no notification can reach `handle_notification` with the
/// subscription id unset.
async fn read_loop(
    read: OwnedReadHalf,
    adapter: Arc<SignalAdapter>,
    conn: Arc<Connection>,
) -> Result<(), SignalError> {
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "malformed JSON-RPC line from signal-cli");
                continue;
            }
        };

        match msg.get("id").and_then(|v| v.as_u64()) {
            Some(id) => {
                // Intercept the subscribe response so subscription_id is
                // published before the reader moves on to any subsequent
                // notification line.
                let pending_sub = conn.subscribe_request_id.load(Ordering::Acquire);
                if id == pending_sub {
                    if let Some(sub_id) = msg.pointer("/result").and_then(|v| v.as_u64()) {
                        conn.subscription_id.store(sub_id, Ordering::Release);
                    }
                    conn.subscribe_request_id
                        .store(ID_SENTINEL, Ordering::Release);
                }
                if let Some(tx) = conn.pending.lock().await.remove(&id) {
                    let _ = tx.send(msg);
                }
            }
            None => {
                adapter.handle_notification(msg, &conn).await;
            }
        }
    }
    Ok(())
}

/// Drain the adapter's internal inbound queue and write each message
/// to the gateway as a Cap'n Proto inbound frame.
async fn inbound_pump(
    mut rx: mpsc::Receiver<(SignalInbound, InboundKind)>,
    writer: Arc<Mutex<IpcFrameWriter>>,
) {
    while let Some((msg, _kind)) = rx.recv().await {
        let mut capnp_msg = capnp::message::Builder::new_default();
        convert::signal_to_inbound(&msg, &mut capnp_msg);
        let mut w = writer.lock().await;
        if let Err(e) = w.write_message(&capnp_msg).await {
            tracing::error!("Failed to forward to gateway: {e}");
        }
    }
}

/// Handle outbound frames from the gateway: parse, route to
/// `send_message` (for `Outbound` messages) or to the approval
/// renderer (for `ApprovalRequest`), and emit the corresponding
/// upstream result so the gateway can correlate.
async fn outbound_handler(
    mut reader: IpcFrameReader,
    adapter: Arc<SignalAdapter>,
    writer: Arc<Mutex<IpcFrameWriter>>,
) {
    loop {
        let msg = match reader.read_message().await {
            Ok(msg) => msg,
            Err(wirken_ipc::IpcError::ConnectionClosed) => {
                tracing::info!("Gateway connection closed");
                break;
            }
            Err(e) => {
                tracing::error!("IPC read error: {e}");
                break;
            }
        };

        let action = {
            let frame_reader = match msg.get_root::<frame::Reader<'_>>() {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Failed to parse frame: {e}");
                    continue;
                }
            };
            match frame_reader.which() {
                Ok(frame::Outbound(_)) => match convert::parse_outbound(&msg) {
                    Ok(f) => GatewayBoundAction::SendMessage(f),
                    Err(e) => {
                        tracing::error!("Failed to parse outbound: {e}");
                        GatewayBoundAction::Skip
                    }
                },
                Ok(frame::ApprovalRequest(_)) => match convert::parse_approval_request(&msg) {
                    Ok(f) => GatewayBoundAction::SendApprovalRequest(f),
                    Err(e) => {
                        tracing::error!("Failed to parse approval request: {e}");
                        GatewayBoundAction::Skip
                    }
                },
                Ok(_) => GatewayBoundAction::Skip,
                Err(e) => {
                    tracing::error!("Frame variant error: {e}");
                    GatewayBoundAction::Skip
                }
            }
        };

        match action {
            GatewayBoundAction::SendMessage(fields) => {
                let (success, msg_id, error) = match adapter
                    .send_message(&fields.conversation_id, &fields.text)
                    .await
                {
                    Ok(ts) => (true, ts.to_string(), String::new()),
                    Err(e) => (false, String::new(), e.to_string()),
                };

                let mut result_msg = capnp::message::Builder::new_default();
                convert::build_outbound_result(&mut result_msg, success, &msg_id, &error);
                let mut w = writer.lock().await;
                if let Err(e) = w.write_message(&result_msg).await {
                    tracing::error!("Failed to send outbound result: {e}");
                }
            }
            GatewayBoundAction::SendApprovalRequest(fields) => {
                send_approval_request(adapter.clone(), &writer, fields).await;
            }
            GatewayBoundAction::Skip => {}
        }
    }
}

/// Intermediate enum so we can drop Cap'n Proto readers before
/// `.await`-ing on `send_message` or the writer mutex.
enum GatewayBoundAction {
    SendMessage(convert::OutboundFields),
    SendApprovalRequest(convert::ApprovalRequestFields),
    Skip,
}

/// Render the approval prompt in the configured conversation,
/// register the prefix in the adapter's prefix map, and on send
/// failure emit an `ApprovalRequestFailed` frame so the gateway
/// resolves the queue entry with a delivery-failure denial
/// rather than waiting for a timeout.
async fn send_approval_request(
    adapter: Arc<SignalAdapter>,
    writer: &Arc<Mutex<IpcFrameWriter>>,
    fields: convert::ApprovalRequestFields,
) {
    let prefix: String = fields
        .request_id
        .chars()
        .filter(|c| *c != '-')
        .take(SignalAdapter::PREFIX_LEN)
        .collect::<String>()
        .to_ascii_lowercase();

    // Register the prefix BEFORE sending so a fast operator who
    // reads the message and responds within microseconds finds
    // the entry. If the send fails below we remove it again.
    {
        let mut map = adapter.approval_prefix_map.lock().await;
        map.entry(prefix.clone())
            .or_default()
            .push(fields.request_id.clone());
    }

    let trigger_block = if fields.trigger_message.is_empty() {
        "Trigger: (none)".to_string()
    } else {
        format!("Trigger: {}", fields.trigger_message)
    };
    let body = format!(
        "Approval requested\n\
         Agent: {}\n\
         Tool: {}\n\
         Action: {}\n\
         Tier: {}\n\
         {}\n\
         \n\
         Reply: !approve {}  or  !deny {} [reason]\n\
         Request: {}",
        fields.triggering_agent,
        fields.tool_name,
        fields.action_key,
        fields.requested_tier,
        trigger_block,
        prefix,
        prefix,
        fields.request_id,
    );

    if let Err(e) = adapter
        .send_message(&fields.target_conversation_id, &body)
        .await
    {
        tracing::warn!(
            request_id = %fields.request_id,
            error = %e,
            "signal approval: send failed; emitting ApprovalRequestFailed"
        );
        // Roll back the prefix-map entry so a future legitimate
        // request can reuse the same prefix without collision
        // noise.
        {
            let mut map = adapter.approval_prefix_map.lock().await;
            if let Some(entries) = map.get_mut(&prefix) {
                entries.retain(|rid| rid != &fields.request_id);
                if entries.is_empty() {
                    map.remove(&prefix);
                }
            }
        }
        let reason = classify_send_error(&e);
        let mut failure = capnp::message::Builder::new_default();
        convert::build_approval_request_failed(&mut failure, &fields.request_id, reason);
        let mut w = writer.lock().await;
        if let Err(send_err) = w.write_message(&failure).await {
            tracing::error!("signal approval: failed to send ApprovalRequestFailed: {send_err}");
        }
    }
}

/// Map a `SignalError` to a stable snake_case label for
/// `ApprovalRequestFailed.reason`. Mirrors the Telegram adapter's
/// label set so SIEM detections can group across channels without
/// per-platform branching.
fn classify_send_error(e: &SignalError) -> &'static str {
    match e {
        SignalError::ConnectionClosed => "channel_not_accessible",
        SignalError::ReconnectTimeout => "reconnect_timeout",
        SignalError::Timeout { .. } => "signal_rpc_timeout",
        SignalError::Signal(_) => "signal_rpc_error",
        SignalError::Io(_) => "network_error",
        SignalError::Serde(_) => "signal_rpc_error",
        SignalError::Ipc(_) => "network_error",
        SignalError::Handshake(_) => "network_error",
        SignalError::HttpEndpointRejected(_) => "signal_rpc_error",
        SignalError::BadSubscribeResponse => "signal_rpc_error",
    }
}

async fn heartbeat_loop(writer: Arc<Mutex<IpcFrameWriter>>) {
    let mut seq = 0u64;
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        interval.tick().await;
        seq += 1;
        let mut msg = capnp::message::Builder::new_default();
        convert::build_heartbeat(&mut msg, seq);
        let mut w = writer.lock().await;
        if let Err(e) = w.write_message(&msg).await {
            tracing::error!("Heartbeat send failed: {e}");
            break;
        }
    }
}

#[cfg(test)]
pub(crate) fn test_parse_endpoint(raw: &str) -> Result<PathBuf, SignalError> {
    parse_endpoint(raw)
}

#[cfg(test)]
impl SignalAdapter {
    /// Test-only handle on the prefix-map mutex. Lets unit tests
    /// seed entries and inspect post-call state without going
    /// through the full gateway-side ApprovalRequest flow.
    pub(crate) async fn approval_prefix_map_for_test(
        &self,
    ) -> tokio::sync::MutexGuard<'_, HashMap<String, Vec<String>>> {
        self.approval_prefix_map.lock().await
    }

    /// Test-only accessor on `route_approval_command`. Wraps the
    /// private async method so tests can exercise the
    /// prefix-resolve and clarification branches without spinning
    /// up the full fake-signal-cli harness.
    pub(crate) async fn route_approval_command_for_test(
        &self,
        inbound: &SignalInbound,
        cmd: crate::commands::CommandKind,
    ) {
        self.route_approval_command(inbound, cmd).await;
    }
}
