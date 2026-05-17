use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{
    AdapterIdentity, IpcFrameReader, IpcFrameWriter, connect, perform_adapter_handshake,
    split_stream,
};

use crate::commands::{self, CommandKind};
use crate::convert;
use crate::error::IMessageError;

/// Per-process map from 8-hex-char `request_id` prefix to the
/// list of full `request_id`s sharing that prefix. The adapter
/// inserts on outbound `ApprovalRequest` send and looks up on
/// inbound `!approve <prefix>` / `!deny <prefix> [reason]`
/// commands. Prefix collisions are rare in practice (Signal's
/// empirical no-collision result carries over because the prefix
/// length and workload pattern are identical) but the map stores
/// `Vec<String>` rather than `String` so a collision can be
/// surfaced by the handler rather than silently misrouting.
///
/// TODO #119-followup: this is in-memory and bot-restart erases
/// it. Gateway-side pending approvals persist across adapter
/// restart (the gateway queue has a 300s timeout that bounds the
/// asymmetry in practice). The proper fix is durable adapter-side
/// correlation: persist `prefix -> request_id` to disk keyed by
/// the adapter's identity so a restart resumes routing. Parallel
/// to Teams' `service_url` cache TODO, Google Chat's
/// service-account auth TODO, and Matrix's `pending_approvals`
/// TODO; same shape of slice-local accommodation for a concern
/// that does not gate the approval flow but eventually wants a
/// proper home.
type ApprovalPrefixMap = Arc<Mutex<HashMap<String, Vec<String>>>>;

/// iMessage adapter: bridges BlueBubbles Server <-> Wirken gateway IPC.
pub struct IMessageAdapter {
    identity: AdapterIdentity,
    bluebubbles_url: String,
    server_password: String,
    listen_port: u16,
}

impl IMessageAdapter {
    /// Construct an iMessage adapter. Fails with `IMessageError::Config`
    /// when `server_password` is empty: previously an empty password
    /// combined with a missing inbound-auth check turned the adapter
    /// into an unauthenticated POST endpoint. The password is now
    /// required and verified on every inbound webhook.
    pub fn new(
        identity: AdapterIdentity,
        bluebubbles_url: String,
        server_password: String,
        listen_port: u16,
    ) -> Result<Self, IMessageError> {
        if server_password.is_empty() {
            return Err(IMessageError::Config(
                "iMessage adapter requires a non-empty server_password; \
                 inbound BlueBubbles webhooks are authenticated with it"
                    .into(),
            ));
        }
        Ok(Self {
            identity,
            bluebubbles_url,
            server_password,
            listen_port,
        })
    }

    /// Connect to gateway, authenticate, register webhook, then run the listener.
    pub async fn run(&self, socket_path: &Path) -> Result<(), IMessageError> {
        tracing::info!("Connecting to gateway at {}", socket_path.display());
        let stream = connect(socket_path).await?;
        let (mut reader, mut writer) = split_stream(stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut reader, &mut writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let writer = Arc::new(Mutex::new(writer));

        // Register webhook with BlueBubbles
        let webhook_url = format!("http://localhost:{}/webhook", self.listen_port);
        self.register_webhook(&webhook_url).await?;

        // Approval-command prefix map. Lives for the duration of
        // this `run` call; shared between the outbound task (writes
        // on `ApprovalRequest` send) and the per-connection webhook
        // handlers (reads on inbound `!approve`/`!deny`). See the
        // `ApprovalPrefixMap` doc comment for the TODO
        // #119-followup naming durable correlation as the proper
        // fix.
        let approval_map: ApprovalPrefixMap = Arc::new(Mutex::new(HashMap::new()));

        // Spawn outbound handler
        let out_bb_url = self.bluebubbles_url.clone();
        let out_password = self.server_password.clone();
        let out_writer = writer.clone();
        let out_map = approval_map.clone();
        let _outbound_handle = tokio::spawn(async move {
            handle_outbound(reader, out_bb_url, out_password, out_writer, out_map).await;
        });

        // Spawn heartbeat
        let hb_writer = writer.clone();
        let _hb_handle = tokio::spawn(async move {
            heartbeat_loop(hb_writer).await;
        });

        // Run HTTP webhook listener. Loopback-only by construction.
        // BlueBubbles posts outbound webhooks with only
        // `Content-Type: application/json` (no HMAC, bearer, or
        // shared-secret — verified against
        // https://github.com/BlueBubblesApp/bluebubbles-server/blob/master/packages/server/src/server/services/webhookService/index.ts).
        // So the adapter has no request-authentication handle on
        // the inbound path. The trust boundary is therefore the
        // host: the listener binds to 127.0.0.1 only and we assert
        // the bound local address is a loopback IP. Exposing the
        // adapter to a non-loopback interface (direct or via a
        // reverse proxy that doesn't add its own auth) makes every
        // iMessage message spoofable by anyone reachable to the
        // port.
        tracing::info!(
            "Starting iMessage webhook listener on 127.0.0.1:{} (loopback-only)",
            self.listen_port
        );
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.listen_port)).await?;
        let local = listener.local_addr()?;
        if !local.ip().is_loopback() {
            return Err(IMessageError::Config(format!(
                "iMessage webhook listener bound to non-loopback address {local}; \
                 BlueBubbles webhooks are unauthenticated so the adapter must \
                 bind to 127.0.0.1 only. Put a trusted reverse proxy in front if \
                 remote delivery is required."
            )));
        }

        loop {
            let (mut stream, _) = listener.accept().await?;
            let w = writer.clone();
            let m = approval_map.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_webhook(&mut stream, w, m).await {
                    tracing::error!("Webhook error: {e}");
                }
            });
        }
    }

    /// Register a webhook URL with BlueBubbles Server.
    async fn register_webhook(&self, webhook_url: &str) -> Result<(), IMessageError> {
        let url = format!("{}/api/v1/server/webhooks", self.bluebubbles_url);

        let body = serde_json::json!({
            "url": webhook_url,
            "events": ["new-message"],
            "password": self.server_password
        });

        let http = reqwest::Client::new();
        let resp =
            http.post(&url).json(&body).send().await.map_err(|e| {
                IMessageError::BlueBubbles(format!("Failed to register webhook: {e}"))
            })?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IMessageError::BlueBubbles(format!(
                "Webhook registration failed: {body}"
            )));
        }

        tracing::info!("Registered webhook with BlueBubbles: {webhook_url}");
        Ok(())
    }
}

/// Handle an incoming webhook request from BlueBubbles.
///
/// BlueBubbles' webhook service posts outbound events with only
/// `Content-Type: application/json` and no authentication of any
/// kind (verified against the upstream server source; see the
/// comment in [`IMessageAdapter::run`]). There is therefore
/// nothing this handler can verify on the request itself. The
/// trust boundary is enforced at the listener level: the socket
/// is bound to 127.0.0.1 only.
///
/// A previous iteration of this handler tried to extract a
/// password from the JSON body and `X-BlueBubbles-Password`
/// headers, but BlueBubbles does not send either — the check
/// always failed, silently rejecting every legitimate event. That
/// code is removed: it claimed a security control the protocol
/// does not provide and broke the adapter in the process.
pub(crate) async fn handle_webhook(
    stream: &mut tokio::net::TcpStream,
    writer: Arc<Mutex<IpcFrameWriter>>,
    approval_map: ApprovalPrefixMap,
) -> Result<(), IMessageError> {
    let mut buf = vec![0u8; 65536];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| IMessageError::BlueBubbles(e.to_string()))?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    if !first_line.starts_with("POST /webhook") {
        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        return Ok(());
    }

    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    let json: serde_json::Value = serde_json::from_str(body).unwrap_or_default();

    if let Some(msg) = convert::extract_message(&json) {
        // Approval-command branch first: structured approval
        // interactions bypass the regular `should_process` filter
        // (umbrella convention; cf. adapter-signal/src/commands.rs
        // for the in-tree precedent on text-command bypass and
        // adapter-matrix's reaction routing for the reaction-shape
        // parallel). An empty-text message can never be a command,
        // so the should_process equivalent for the regular path
        // still applies below.
        if let Some(cmd) = commands::parse_command(&msg.text) {
            forward_approval_decision(&cmd, &msg, &writer, &approval_map).await;
        } else if convert::should_process(&msg) {
            let mut capnp_msg = capnp::message::Builder::new_default();
            convert::imessage_to_inbound(&msg, &mut capnp_msg);
            let mut w = writer.lock().await;
            if let Err(e) = w.write_message(&capnp_msg).await {
                tracing::error!("Failed to forward to gateway: {e}");
            }
        }
    }

    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let _ = stream.write_all(resp.as_bytes()).await;

    Ok(())
}

/// Look up a stored pending approval by prefix and forward an
/// `ApprovalDecision` to the gateway. Drops with debug log on
/// prefix miss (no pending approval) or prefix-collision (multi-
/// match — operator needs a longer prefix to disambiguate).
/// Mirrors Signal's prefix-map handler shape.
async fn forward_approval_decision(
    cmd: &CommandKind,
    msg: &convert::IMessageInbound,
    writer: &Arc<Mutex<IpcFrameWriter>>,
    approval_map: &ApprovalPrefixMap,
) {
    let (prefix, is_allow, denial_reason) = match cmd {
        CommandKind::Approve { prefix } => (prefix.clone(), true, None),
        CommandKind::Deny { prefix, reason } => (prefix.clone(), false, reason.clone()),
    };
    let request_id = {
        let mut map = approval_map.lock().await;
        match map.get(&prefix) {
            Some(matches) if matches.len() == 1 => {
                let r = matches[0].clone();
                map.remove(&prefix);
                r
            }
            Some(matches) if matches.is_empty() => {
                tracing::debug!(
                    sender = %msg.sender_handle,
                    prefix = %prefix,
                    "imessage approval: empty match list for prefix; dropping"
                );
                return;
            }
            Some(matches) => {
                tracing::debug!(
                    sender = %msg.sender_handle,
                    prefix = %prefix,
                    count = matches.len(),
                    "imessage approval: prefix collision; dropping (operator needs a longer prefix)"
                );
                return;
            }
            None => {
                tracing::debug!(
                    sender = %msg.sender_handle,
                    prefix = %prefix,
                    "imessage approval: no pending approval for prefix; dropping"
                );
                return;
            }
        }
    };
    let mut capnp_msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(
        &mut capnp_msg,
        &request_id,
        is_allow,
        &msg.sender_handle,
        &msg.sender_name,
        denial_reason.as_deref(),
    );
    let mut w = writer.lock().await;
    if let Err(e) = w.write_message(&capnp_msg).await {
        tracing::error!("imessage approval: failed to send ApprovalDecision to gateway: {e}");
    }
}

/// Handle outbound messages from gateway to iMessage via BlueBubbles.
async fn handle_outbound(
    mut reader: IpcFrameReader,
    bluebubbles_url: String,
    server_password: String,
    writer: Arc<Mutex<IpcFrameWriter>>,
    approval_map: ApprovalPrefixMap,
) {
    let http = reqwest::Client::new();

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
                    Ok(fields) => FrameAction::SendMessage(fields),
                    Err(e) => {
                        tracing::error!("Failed to parse outbound: {e}");
                        FrameAction::Skip
                    }
                },
                Ok(frame::ApprovalRequest(_)) => match convert::parse_approval_request(&msg) {
                    Ok(fields) => FrameAction::SendApprovalRequest(fields),
                    Err(e) => {
                        tracing::error!("Failed to parse approval request: {e}");
                        FrameAction::Skip
                    }
                },
                Ok(frame::Heartbeat(_)) => FrameAction::Skip,
                Ok(_) => FrameAction::Skip,
                Err(e) => {
                    tracing::error!("Frame variant error: {e}");
                    FrameAction::Skip
                }
            }
        };

        match action {
            FrameAction::SendMessage(fields) => {
                let url = format!("{}/api/v1/message/text", bluebubbles_url);

                let body = serde_json::json!({
                    "chatGuid": fields.conversation_id,
                    "message": fields.text,
                    "password": server_password,
                });

                let resp = http.post(&url).json(&body).send().await;

                let (success, msg_id, error) = match resp {
                    Ok(r) if r.status().is_success() => {
                        let body: serde_json::Value = r.json().await.unwrap_or_default();
                        let mid = body["data"]["guid"].as_str().unwrap_or("").to_string();
                        (true, mid, String::new())
                    }
                    Ok(r) => {
                        let body = r.text().await.unwrap_or_default();
                        (false, String::new(), body)
                    }
                    Err(e) => (false, String::new(), e.to_string()),
                };

                let mut result_msg = capnp::message::Builder::new_default();
                convert::build_outbound_result(&mut result_msg, success, &msg_id, &error);
                let mut w = writer.lock().await;
                if let Err(e) = w.write_message(&result_msg).await {
                    tracing::error!("Failed to send outbound result: {e}");
                }
            }
            FrameAction::SendApprovalRequest(fields) => {
                send_approval_request(
                    &http,
                    &bluebubbles_url,
                    &server_password,
                    fields,
                    &writer,
                    &approval_map,
                )
                .await;
            }
            FrameAction::Skip => {}
        }
    }
}

enum FrameAction {
    SendMessage(convert::OutboundFields),
    SendApprovalRequest(convert::ApprovalRequestFields),
    Skip,
}

/// Render an approval-request message and post it to BlueBubbles.
/// The body matches the umbrella majority sentence-with-parens
/// shape (7 of 8 adapters share it; Signal's labelled-line shape
/// is the historical outlier, flagged in a follow-up to
/// normalize). The trailing instruction line carries the iMessage-
/// specific text-command shape so the operator knows how to reply.
///
/// On success, the 8-hex-char prefix of `request_id` is inserted
/// into `approval_map`, mapping to the full `request_id` for later
/// `!approve <prefix>` / `!deny <prefix>` resolution. The
/// adapter intentionally does NOT capture the BlueBubbles
/// response GUID for correlation: text-command shape doesn't bind
/// to message_id, only to the prefix in the message body the
/// operator types back. The `OutboundResult` IPC frame still
/// gets populated with the response GUID via the same path
/// text-message sends use, so downstream audit consumers see
/// consistent IPC traffic across send types.
///
/// On failure, emits `ApprovalRequestFailed` with a snake_case
/// reason label from `classify_send_error`.
async fn send_approval_request(
    http: &reqwest::Client,
    bluebubbles_url: &str,
    server_password: &str,
    fields: convert::ApprovalRequestFields,
    writer: &Arc<Mutex<IpcFrameWriter>>,
    approval_map: &ApprovalPrefixMap,
) {
    let prefix = if fields.request_id.len() >= 8 {
        fields.request_id[..8].to_ascii_lowercase()
    } else {
        fields.request_id.to_ascii_lowercase()
    };

    let prompt = format!(
        "Agent {} requests {} (tier {}).\n\
         Action: {}\n\
         Trigger: {}\n\
         Reply !approve {} to approve or !deny {} [reason] to deny.",
        fields.triggering_agent,
        fields.tool_name,
        fields.requested_tier,
        fields.action_key,
        if fields.trigger_message.is_empty() {
            "(none)".to_string()
        } else {
            fields.trigger_message.clone()
        },
        prefix,
        prefix,
    );

    let url = format!("{bluebubbles_url}/api/v1/message/text");
    let body = serde_json::json!({
        "chatGuid": fields.target_chat_guid,
        "message": prompt,
        "password": server_password,
    });
    let resp = http.post(&url).json(&body).send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let mut map = approval_map.lock().await;
            map.entry(prefix)
                .or_default()
                .push(fields.request_id.clone());
        }
        Ok(r) => {
            let status = r.status().as_u16();
            let response_body = r.text().await.unwrap_or_default();
            let reason = classify_send_error(status, &response_body);
            tracing::error!(
                request_id = %fields.request_id,
                chat_guid = %fields.target_chat_guid,
                status,
                body = %response_body,
                reason = %reason,
                "imessage approval: send failed; emitting ApprovalRequestFailed"
            );
            emit_approval_failure(writer, &fields.request_id, reason).await;
        }
        Err(e) => {
            tracing::error!(
                request_id = %fields.request_id,
                error = %e,
                "imessage approval: network error; emitting ApprovalRequestFailed"
            );
            emit_approval_failure(writer, &fields.request_id, "network_error").await;
        }
    }
}

async fn emit_approval_failure(
    writer: &Arc<Mutex<IpcFrameWriter>>,
    request_id: &str,
    reason: &str,
) {
    let mut failure = capnp::message::Builder::new_default();
    convert::build_approval_request_failed(&mut failure, request_id, reason);
    let mut w = writer.lock().await;
    if let Err(send_err) = w.write_message(&failure).await {
        tracing::error!("imessage approval: failed to send ApprovalRequestFailed: {send_err}");
    }
}

/// Classify a BlueBubbles REST API error response into a stable
/// snake_case `reason` label for `ApprovalRequestFailed`. The
/// response body shape is `{"status": <int>, "message": "..."}`
/// or sometimes `{"error": ..., "message": "..."}` depending on
/// the BlueBubbles server version and endpoint; we key off the
/// HTTP status code primarily and the body's `status` field when
/// present.
///
/// BlueBubbles error response field names are NOT stable across
/// server versions in the same way Meta's WhatsApp error.code
/// integers are. The mapping below is reverified against the
/// upstream server source at
/// https://github.com/BlueBubblesApp/bluebubbles-server. When
/// the BlueBubbles server version bumps and any misclassified
/// error surfaces here, check the upstream response shape before
/// adjusting the mapping rather than guessing from the body's
/// content.
///
/// HTTP 429 (rate limit) maps to `imessage_api_error` rather than
/// a distinct label so SIEM detection groups it with other API-
/// class failures, matching the Slack / Teams / Google Chat
/// convention for rate-limit responses.
pub(crate) fn classify_send_error(http_status: u16, response_body: &str) -> &'static str {
    let body_status = serde_json::from_str::<serde_json::Value>(response_body)
        .ok()
        .as_ref()
        .and_then(|v| v.get("status"))
        .and_then(|s| s.as_i64());
    // BlueBubbles sometimes returns 200 OK with a status field in
    // the body indicating an application-level error. The caller
    // already filters Ok-success on http_status, so we only reach
    // here on http_status >= 400; the body's status is supplementary.
    match http_status {
        401 | 403 => "auth_error",
        404 => "chat_not_found",
        429 => "imessage_api_error",
        500..=599 => match body_status {
            Some(4006) => "chat_not_found",
            _ => "imessage_api_error",
        },
        _ => "imessage_api_error",
    }
}

async fn heartbeat_loop(writer: Arc<Mutex<IpcFrameWriter>>) {
    let mut seq = 0u64;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
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
