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

use crate::convert;
use crate::error::IMessageError;
use wirken_adapter_core::approval_card::CardStyle;
use wirken_adapter_core::text_command::{self as commands, CommandKind};

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
    /// The secret the registered webhook URL carries and every inbound
    /// webhook must present. See [`webhook_secret`].
    webhook_secret: String,
}

impl IMessageAdapter {
    /// Construct an iMessage adapter. Fails with `IMessageError::Config`
    /// when `server_password` is empty: every BlueBubbles API call takes
    /// it, and the webhook secret every inbound webhook must present is
    /// derived from it ([`webhook_secret`]).
    pub fn new(
        identity: AdapterIdentity,
        bluebubbles_url: String,
        server_password: String,
        listen_port: u16,
    ) -> Result<Self, IMessageError> {
        if server_password.is_empty() {
            return Err(IMessageError::Config(
                "iMessage adapter requires a non-empty server_password; \
                 BlueBubbles API calls take it and the webhook secret is derived from it"
                    .into(),
            ));
        }
        let webhook_secret = webhook_secret(&server_password);
        Ok(Self {
            identity,
            bluebubbles_url,
            server_password,
            listen_port,
            webhook_secret,
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

        // Register the webhook with BlueBubbles. The URL carries the
        // secret every inbound webhook is checked for; it is the same on
        // every start, so BlueBubbles, which keeps one registration per
        // URL, does not collect a new one each time.
        let webhook_url = format!(
            "http://localhost:{}/webhook?secret={}",
            self.listen_port, self.webhook_secret
        );
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

        // Run HTTP webhook listener. Loopback-only by construction, and
        // every POST must present the webhook secret: BlueBubbles posts
        // its webhooks with only `Content-Type: application/json` (no
        // HMAC, header or signature; `webhookService/index.ts` in
        // bluebubbles-server), so the secret rides in the URL it was
        // registered with, which it posts to as given. Without it any
        // local process could post a message as any sender.
        tracing::info!(
            "Starting iMessage webhook listener on 127.0.0.1:{} (loopback-only)",
            self.listen_port
        );
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.listen_port)).await?;
        let local = listener.local_addr()?;
        if !local.ip().is_loopback() {
            return Err(IMessageError::Config(format!(
                "iMessage webhook listener bound to non-loopback address {local}; \
                 the adapter binds to 127.0.0.1 only. Put a trusted reverse proxy \
                 in front if remote delivery is required."
            )));
        }

        loop {
            let (mut stream, _) = listener.accept().await?;
            let w = writer.clone();
            let m = approval_map.clone();
            let secret = self.webhook_secret.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_webhook(&mut stream, w, m, &secret).await {
                    tracing::error!("Webhook error: {e}");
                }
            });
        }
    }

    /// Register a webhook URL with BlueBubbles Server.
    async fn register_webhook(&self, webhook_url: &str) -> Result<(), IMessageError> {
        let body = serde_json::json!({
            "url": webhook_url,
            "events": ["new-message"],
        });

        let http = reqwest::Client::new();
        let resp = bluebubbles_post(
            &http,
            &self.bluebubbles_url,
            WEBHOOK_PATH,
            &self.server_password,
            &body,
        )
        .send()
        .await
        .map_err(|e| IMessageError::BlueBubbles(format!("Failed to register webhook: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IMessageError::BlueBubbles(format!(
                "Webhook registration failed: {body}"
            )));
        }

        // The URL less its query: the secret stays out of the log.
        tracing::info!(
            "Registered webhook with BlueBubbles: {}",
            webhook_url.split('?').next().unwrap_or("")
        );
        Ok(())
    }
}

/// The secret the iMessage webhook URL carries: HMAC-SHA256 of a fixed
/// label keyed by the BlueBubbles server password, hex.
///
/// BlueBubbles authenticates nothing on its webhooks
/// (`packages/server/src/server/services/webhookService/index.ts`
/// posts with only `Content-Type: application/json`), so the URL it is
/// given is the one thing a receiver can check. Deriving the secret
/// from the server password makes it per install and stable across
/// restarts with no state of its own, and the one-way MAC means a copy
/// of the URL (BlueBubbles logs it at debug level) does not give the
/// password away. Rotating the password changes it.
pub fn webhook_secret(server_password: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(server_password.as_bytes())
        .expect("HMAC takes a key of any length");
    mac.update(b"wirken imessage webhook v1");
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What an inbound request line is, given the webhook secret.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WebhookAccess {
    /// `POST /webhook` with the secret.
    Accepted,
    /// `POST /webhook` without it, or with another.
    Refused,
    /// Not `POST /webhook` at all.
    NotFound,
}

/// Decide a request by its request line: the path must be `/webhook`
/// and its `secret` query parameter must equal `secret`, compared in
/// constant time.
pub(crate) fn webhook_access(first_line: &str, secret: &str) -> WebhookAccess {
    use subtle::ConstantTimeEq;
    let mut parts = first_line.split_whitespace();
    let (Some("POST"), Some(target)) = (parts.next(), parts.next()) else {
        return WebhookAccess::NotFound;
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != "/webhook" {
        return WebhookAccess::NotFound;
    }
    let presented = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("secret="))
        .unwrap_or("");
    if bool::from(presented.as_bytes().ct_eq(secret.as_bytes())) {
        WebhookAccess::Accepted
    } else {
        WebhookAccess::Refused
    }
}

/// Handle an incoming webhook request from BlueBubbles. The request must
/// present the webhook secret ([`webhook_access`]); one that does not is
/// answered 403 and its body is not read.
pub(crate) async fn handle_webhook(
    stream: &mut tokio::net::TcpStream,
    writer: Arc<Mutex<IpcFrameWriter>>,
    approval_map: ApprovalPrefixMap,
    secret: &str,
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

    match webhook_access(first_line, secret) {
        WebhookAccess::Accepted => {}
        WebhookAccess::NotFound => {
            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes()).await;
            return Ok(());
        }
        WebhookAccess::Refused => {
            // Not the value: the log names the refusal, never a secret.
            tracing::warn!(
                "iMessage webhook refused: missing or wrong secret. A webhook registered by \
                 an earlier version, without the secret, stays in BlueBubbles until it is \
                 deleted there."
            );
            let resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes()).await;
            return Ok(());
        }
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
        &msg.chat_guid,
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
                let body = serde_json::json!({
                    "chatGuid": fields.conversation_id,
                    "message": fields.text,
                });

                let resp =
                    bluebubbles_post(&http, &bluebubbles_url, TEXT_PATH, &server_password, &body)
                        .send()
                        .await;

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
                convert::build_outbound_result(
                    &mut result_msg,
                    success,
                    &msg_id,
                    &error,
                    &fields.correlation_id,
                );
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
/// The approval message body: the card every surface renders, plain,
/// then the text commands that decide it.
pub(crate) fn approval_text(fields: &convert::ApprovalRequestFields, prefix: &str) -> String {
    format!(
        "{}\nReply !approve {prefix} to approve or !deny {prefix} [reason] to deny.",
        fields.card().render(CardStyle::Plain)
    )
}

/// BlueBubbles' route for registering a webhook (`prefix: "webhook"` in
/// its `httpRoutes.ts`).
pub(crate) const WEBHOOK_PATH: &str = "/api/v1/webhook";

/// BlueBubbles' route for sending a text message.
pub(crate) const TEXT_PATH: &str = "/api/v1/message/text";

/// A POST to the BlueBubbles API at `path` with a JSON `body`. Its
/// authentication middleware reads the server password from the query
/// string only (`guid`, `password` or `token`, in
/// `packages/server/src/server/api/http/api/v1/middleware/authMiddleware.ts`),
/// so the password goes there and not in the body.
pub(crate) fn bluebubbles_post(
    http: &reqwest::Client,
    bluebubbles_url: &str,
    path: &str,
    server_password: &str,
    body: &serde_json::Value,
) -> reqwest::RequestBuilder {
    let raw = format!("{}{path}", bluebubbles_url.trim_end_matches('/'));
    match reqwest::Url::parse(&raw) {
        Ok(mut url) => {
            url.query_pairs_mut()
                .append_pair("password", server_password);
            http.post(url).json(body)
        }
        // Not a URL: the request fails when sent, naming why.
        Err(_) => http.post(raw).json(body),
    }
}

async fn send_approval_request(
    http: &reqwest::Client,
    bluebubbles_url: &str,
    server_password: &str,
    fields: convert::ApprovalRequestFields,
    writer: &Arc<Mutex<IpcFrameWriter>>,
    approval_map: &ApprovalPrefixMap,
) {
    let prefix = approval_prefix(&fields.request_id);

    let prompt = approval_text(&fields, &prefix);

    let body = serde_json::json!({
        "chatGuid": fields.target_chat_guid,
        "message": prompt,
    });
    let resp = bluebubbles_post(http, bluebubbles_url, TEXT_PATH, server_password, &body)
        .send()
        .await;

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

/// The prefix an operator types after `!approve` / `!deny`: the first
/// eight bytes of `request_id`, lower-cased. An id shorter than that,
/// or one whose eighth byte falls inside a character, is used whole.
pub(crate) fn approval_prefix(request_id: &str) -> String {
    request_id
        .get(..8)
        .unwrap_or(request_id)
        .to_ascii_lowercase()
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
