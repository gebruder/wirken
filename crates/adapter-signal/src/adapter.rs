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
use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake};

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
        })
    }

    /// Run the adapter to completion (or indefinitely). Handles the
    /// gateway handshake once, spawns the long-lived gateway-side tasks
    /// (heartbeat, outbound handler, inbound pump), and enters the
    /// signal-cli reconnect loop. The reconnect loop never returns; the
    /// adapter process exits only when the gateway drops it or a fatal
    /// protocol error escapes the reconnect boundary.
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
        let gw_stream = UnixStream::connect(gateway_socket).await?;
        let (mut gw_reader, mut gw_writer) = split_stream(gw_stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut gw_reader, &mut gw_writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let gw_writer = Arc::new(Mutex::new(gw_writer));

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

        let outbound_self = self.clone();
        let outbound_writer = gw_writer.clone();
        tokio::spawn(async move {
            outbound_handler(gw_reader, outbound_self, outbound_writer).await;
        });

        tracing::info!(
            "Connecting to signal-cli socket at {} for account {}",
            self.socket_path.display(),
            self.phone_number
        );

        let mut backoff = BACKOFF_MIN;
        loop {
            let outcome = self.connect_once().await;
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

            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    /// One connect-subscribe-read cycle. Returns `Ok(())` on clean EOF,
    /// `Err(...)` on any other failure. Caller retries with backoff.
    async fn connect_once(self: &Arc<Self>) -> Result<(), SignalError> {
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

        self.subscribe(&conn).await?;

        // Block on the reader. It returns when signal-cli closes the
        // socket (normal EOF) or hits a read error.
        match reader_handle.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(join_err) => Err(SignalError::Signal(format!(
                "reader task joined: {join_err}"
            ))),
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

        if let Err(e) = self.inbound_tx.send((inbound, _kind)).await {
            tracing::error!("inbound channel closed: {e}");
        }
    }

    /// Send a Signal message and record the returned timestamp in the
    /// self-echo cache so the subsequent SyncSent notification is
    /// filtered out. Returns the Signal message timestamp (used as the
    /// message id in the gateway result frame).
    ///
    /// Sends go through the `recipient` param. Group sends are a known
    /// gap — signal-cli's send RPC expects `groupId` rather than
    /// `recipient` when the destination is a group, and this path does
    /// not branch yet. Tracked as a follow-up.
    async fn send_message(&self, conversation_id: &str, text: &str) -> Result<i64, SignalError> {
        let conn = {
            let guard = self.inner.lock().await;
            guard
                .as_ref()
                .cloned()
                .ok_or(SignalError::ConnectionClosed)?
        };

        // Agents emit markdown; Signal renders almost none of it.
        // Run the reply through SignalFormatter here so every path
        // into signal-cli's send RPC shares the same rendering.
        let rendered = self.formatter.format(text);

        let params = json!({
            "account": self.phone_number,
            "recipient": [conversation_id],
            "message": rendered,
        });

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
    writer: Arc<Mutex<FrameWriter>>,
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
/// `send_message`, and return a result frame upstream so the gateway
/// can correlate.
async fn outbound_handler(
    mut reader: FrameReader,
    adapter: Arc<SignalAdapter>,
    writer: Arc<Mutex<FrameWriter>>,
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

        let fields = {
            let frame_reader = match msg.get_root::<frame::Reader<'_>>() {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Failed to parse frame: {e}");
                    continue;
                }
            };
            match frame_reader.which() {
                Ok(frame::Outbound(_)) => match convert::parse_outbound(&msg) {
                    Ok(f) => Some(f),
                    Err(e) => {
                        tracing::error!("Failed to parse outbound: {e}");
                        None
                    }
                },
                Ok(_) => None,
                Err(e) => {
                    tracing::error!("Frame variant error: {e}");
                    None
                }
            }
        };

        let Some(fields) = fields else {
            continue;
        };

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
}

async fn heartbeat_loop(writer: Arc<Mutex<FrameWriter>>) {
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
