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

use wirken_adapter_core::approval::{self, ApprovalPayload, Decision};

use crate::auth::{JwksCache, extract_bearer_token};
use crate::convert::{self, ApprovalPress};
use crate::error::GoogleChatError;

/// Google Chat adapter: bridges Google Chat webhook API <-> Wirken gateway IPC.
pub struct GoogleChatAdapter {
    identity: AdapterIdentity,
    service_account_token: String,
    app_project_number: String,
    listen_port: u16,
}

impl GoogleChatAdapter {
    /// Construct a Google Chat adapter. Fails if either
    /// `service_account_token` (outbound bearer) or
    /// `app_project_number` (inbound JWT audience) is empty. Both
    /// are security-critical: the token authenticates outbound
    /// messages to Google Chat, and the project number is the
    /// audience claim that every inbound JWT must match.
    pub fn new(
        identity: AdapterIdentity,
        service_account_token: String,
        app_project_number: String,
        listen_port: u16,
    ) -> Result<Self, GoogleChatError> {
        if service_account_token.is_empty() {
            return Err(GoogleChatError::Config(
                "Google Chat adapter requires a non-empty service_account_token".into(),
            ));
        }
        if app_project_number.is_empty() {
            return Err(GoogleChatError::Config(
                "Google Chat adapter requires a non-empty app_project_number; \
                 inbound JWT validation uses it as the audience claim"
                    .into(),
            ));
        }
        Ok(Self {
            identity,
            service_account_token,
            app_project_number,
            listen_port,
        })
    }

    /// Connect to gateway, authenticate, then run the webhook listener.
    pub async fn run(&self, socket_path: &Path) -> Result<(), GoogleChatError> {
        tracing::info!("Connecting to gateway at {}", socket_path.display());
        let stream = connect(socket_path).await?;
        let (mut reader, mut writer) = split_stream(stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut reader, &mut writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let writer = Arc::new(Mutex::new(writer));
        let http = reqwest::Client::new();
        let jwks = Arc::new(JwksCache::new(http.clone()));

        // Spawn outbound handler (gateway -> Google Chat via REST API)
        let out_token = self.service_account_token.clone();
        let out_writer = writer.clone();
        let _outbound_handle = tokio::spawn(async move {
            handle_outbound(reader, out_token, out_writer).await;
        });

        // Spawn heartbeat
        let hb_writer = writer.clone();
        let _hb_handle = tokio::spawn(async move {
            heartbeat_loop(hb_writer).await;
        });

        // Run HTTP webhook listener
        tracing::info!(
            "Starting Google Chat webhook listener on port {}",
            self.listen_port
        );
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.listen_port)).await?;

        loop {
            let (mut stream, _) = listener.accept().await?;
            let w = writer.clone();
            let j = jwks.clone();
            let aud = self.app_project_number.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_webhook(&mut stream, &j, &aud, w).await {
                    tracing::error!("Webhook error: {e}");
                }
            });
        }
    }
}

async fn respond(stream: &mut tokio::net::TcpStream, status_line: &str) -> std::io::Result<()> {
    let body = format!("HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(body.as_bytes()).await
}

/// Sibling to [`respond`]: writes a 200 OK with a JSON body. Used
/// by the approval-press path so the inline `actionResponse` (with
/// `privateMessageViewer` for the ephemeral toast) ships back to
/// Google Chat in the same response that acknowledges the webhook.
///
/// Two helpers instead of one with an optional body so each call
/// site is structurally honest about what kind of response it
/// sends: empty-body for the existing message path, JSON-body for
/// the approval-press path.
async fn respond_with_json_body(
    stream: &mut tokio::net::TcpStream,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await
}

/// Build the inline 200-OK response body for an approval press.
/// Carries an `actionResponse` with a `NEW_MESSAGE` whose
/// `privateMessageViewer.name` is the clicker's path-shaped user
/// id, so the "Approved" / "Denied" toast is visible only to them.
///
/// Google Chat rejoins the ephemeral-feedback group
/// (Telegram callback toast, Discord ephemeral, Slack ephemeral)
/// here because `privateMessageViewer` is a platform-supported
/// affordance. Teams and WhatsApp stayed on silent ack because
/// their platforms have no equivalent.
pub(crate) fn build_approval_response_body(user_name: &str, is_allow: bool) -> String {
    let text = if is_allow { "Approved" } else { "Denied" };
    serde_json::json!({
        "actionResponse": { "type": "NEW_MESSAGE" },
        "text": text,
        "privateMessageViewer": { "name": user_name }
    })
    .to_string()
}

/// Handle an incoming webhook request from Google Chat.
pub(crate) async fn handle_webhook(
    stream: &mut tokio::net::TcpStream,
    jwks: &JwksCache,
    expected_aud: &str,
    writer: Arc<Mutex<IpcFrameWriter>>,
) -> Result<(), GoogleChatError> {
    let mut buf = vec![0u8; 65536];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| GoogleChatError::Webhook(e.to_string()))?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    // Only handle POST requests
    if !first_line.starts_with("POST") {
        let _ = respond(stream, "200 OK").await;
        return Ok(());
    }

    // JWT validation must succeed before touching the body. On
    // failure, always 401 with the specific reason going to tracing.
    let token = match extract_bearer_token(&request) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Google Chat webhook rejected: {e}");
            let _ = respond(stream, "401 Unauthorized").await;
            return Ok(());
        }
    };
    if let Err(e) = jwks.validate_token(token, expected_aud).await {
        tracing::warn!("Google Chat webhook rejected: {e}");
        let _ = respond(stream, "401 Unauthorized").await;
        return Ok(());
    }

    // Extract JSON body
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    let json: serde_json::Value = serde_json::from_str(body).unwrap_or_default();

    // Approval-press branch first: a CARD_CLICKED interaction
    // event carries the press payload in event.common.parameters
    // and never matches the MESSAGE-only extractor below. Response
    // body is a structured actionResponse with privateMessageViewer
    // so the clicker sees an ephemeral "Approved" or "Denied" toast
    // visible only to them.
    if let Some(press) = convert::extract_approval_press(&json) {
        let response_body = handle_approval_press(&press, &writer).await;
        let _ = respond_with_json_body(stream, &response_body).await;
        return Ok(());
    }

    // Only process MESSAGE events
    if let Some(msg) = convert::extract_message(&json)
        && convert::should_process(&msg)
    {
        let mut capnp_msg = capnp::message::Builder::new_default();
        convert::google_chat_to_inbound(&msg, &mut capnp_msg);
        let mut w = writer.lock().await;
        if let Err(e) = w.write_message(&capnp_msg).await {
            tracing::error!("Failed to forward to gateway: {e}");
        }
    }

    let _ = respond(stream, "200 OK").await;

    Ok(())
}

/// Decode an approval press, forward an `ApprovalDecision` frame
/// to the gateway, and return the response body the inline 200 OK
/// will carry. Drops the press on the malformed-payload path with
/// a warn log; the response body in that case is a neutral
/// "not recognised" ephemeral so the clicker's UI does not hang.
async fn handle_approval_press(
    press: &ApprovalPress,
    writer: &Arc<Mutex<IpcFrameWriter>>,
) -> String {
    let payload = match approval::decode(&press.encoded_payload) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                user = %press.user_name,
                button_id = %press.encoded_payload,
                error = %e,
                "googlechat interaction: unrecognized wirken_approval; dropping"
            );
            return serde_json::json!({
                "actionResponse": { "type": "NEW_MESSAGE" },
                "text": "This button is not recognised.",
                "privateMessageViewer": { "name": press.user_name }
            })
            .to_string();
        }
    };
    let is_allow = matches!(payload.decision, Decision::Allow);

    let mut capnp_msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(
        &mut capnp_msg,
        &payload.request_id,
        is_allow,
        &press.user_name,
        &press.user_display,
    );
    {
        let mut w = writer.lock().await;
        if let Err(e) = w.write_message(&capnp_msg).await {
            tracing::error!(
                "googlechat interaction: failed to send ApprovalDecision to gateway: {e}"
            );
        }
    }
    build_approval_response_body(&press.user_name, is_allow)
}

/// Handle outbound messages from gateway — POST to Google Chat REST API.
async fn handle_outbound(
    mut reader: IpcFrameReader,
    service_account_token: String,
    writer: Arc<Mutex<IpcFrameWriter>>,
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
                // POST to Google Chat REST API to send a message in the space.
                let url = format!(
                    "https://chat.googleapis.com/v1/{}/messages",
                    fields.conversation_id
                );

                let body = serde_json::json!({
                    "text": fields.text,
                });

                let resp = http
                    .post(&url)
                    .header("Authorization", format!("Bearer {service_account_token}"))
                    .json(&body)
                    .send()
                    .await;

                let (success, msg_id, error) = match resp {
                    Ok(r) if r.status().is_success() => {
                        let body: serde_json::Value = r.json().await.unwrap_or_default();
                        let mid = body
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
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
                send_approval_request(&http, &service_account_token, fields, &writer).await;
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

/// Render an approval request as a Cards v2 button message and
/// POST it to the Google Chat REST API. Each button's
/// `onClick.action.parameters` carries the cross-adapter encoded
/// payload under the `wirken_approval` key (see
/// `convert::APPROVAL_FIELD`); the inbound press path reads it
/// back via `extract_approval_press`.
///
/// TODO #119-followup: the outbound bearer is a long-lived static
/// `service_account_token` passed at construction. Google Chat
/// REST API access tokens expire in 3600 seconds, so this path
/// assumes the operator pre-mints externally and refreshes
/// out-of-band. The proper fix is service-account JWT
/// minting + OAuth token exchange at
/// https://oauth2.googleapis.com/token + cached short-lived
/// access token with refresh-on-expiry, parallel to how the Teams
/// adapter would land real auth. Pre-existing limitation; not
/// introduced by the approval slice. Its own slice.
async fn send_approval_request(
    http: &reqwest::Client,
    service_account_token: &str,
    fields: convert::ApprovalRequestFields,
    writer: &Arc<Mutex<IpcFrameWriter>>,
) {
    let allow_id = match approval::encode(&ApprovalPayload {
        request_id: fields.request_id.clone(),
        decision: Decision::Allow,
    }) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                request_id = %fields.request_id,
                error = %e,
                "googlechat approval: encode failed; emitting ApprovalRequestFailed"
            );
            emit_approval_failure(writer, &fields.request_id, "encode_failed").await;
            return;
        }
    };
    let deny_id = match approval::encode(&ApprovalPayload {
        request_id: fields.request_id.clone(),
        decision: Decision::Deny,
    }) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                request_id = %fields.request_id,
                error = %e,
                "googlechat approval: encode failed; emitting ApprovalRequestFailed"
            );
            emit_approval_failure(writer, &fields.request_id, "encode_failed").await;
            return;
        }
    };

    let prompt = format!(
        "Agent **{}** requests **{}** (tier `{}`).\n\
         Action: `{}`\n\
         Trigger: _{}_",
        fields.triggering_agent,
        fields.tool_name,
        fields.requested_tier,
        fields.action_key,
        if fields.trigger_message.is_empty() {
            "(none)".to_string()
        } else {
            fields.trigger_message.clone()
        },
    );

    let card = serde_json::json!({
        "cardId": format!("approval-{}", fields.request_id),
        "card": {
            "sections": [{
                "widgets": [
                    { "textParagraph": { "text": prompt } },
                    {
                        "buttonList": {
                            "buttons": [
                                {
                                    "text": "Approve",
                                    "onClick": {
                                        "action": {
                                            "function": "wirken_approve",
                                            "parameters": [
                                                { "key": convert::APPROVAL_FIELD, "value": allow_id }
                                            ]
                                        }
                                    }
                                },
                                {
                                    "text": "Deny",
                                    "onClick": {
                                        "action": {
                                            "function": "wirken_deny",
                                            "parameters": [
                                                { "key": convert::APPROVAL_FIELD, "value": deny_id }
                                            ]
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }]
        }
    });

    let url = format!(
        "https://chat.googleapis.com/v1/{}/messages",
        fields.target_channel_id
    );
    let body = serde_json::json!({ "cardsV2": [card] });

    let resp = http
        .post(&url)
        .header("Authorization", format!("Bearer {service_account_token}"))
        .json(&body)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => {
            let status = r.status();
            let response_body = r.text().await.unwrap_or_default();
            let reason = classify_send_error(status.as_u16(), &response_body);
            tracing::error!(
                request_id = %fields.request_id,
                channel_id = %fields.target_channel_id,
                status = status.as_u16(),
                body = %response_body,
                reason = %reason,
                "googlechat approval: send failed; emitting ApprovalRequestFailed"
            );
            emit_approval_failure(writer, &fields.request_id, reason).await;
        }
        Err(e) => {
            tracing::error!(
                request_id = %fields.request_id,
                error = %e,
                "googlechat approval: network error; emitting ApprovalRequestFailed"
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
        tracing::error!("googlechat approval: failed to send ApprovalRequestFailed: {send_err}");
    }
}

/// Classify a Google Chat REST API error response into a stable
/// snake_case `reason` label for `ApprovalRequestFailed`.
///
/// The body is JSON shaped like:
/// `{"error":{"code":403,"message":"...","status":"PERMISSION_DENIED",...}}`.
/// We key off `error.status` when present (it is the canonical
/// Google-style code), with HTTP status as fallback.
pub(crate) fn classify_send_error(http_status: u16, response_body: &str) -> &'static str {
    let google_status = serde_json::from_str::<serde_json::Value>(response_body)
        .ok()
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(|e| e.get("status"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    match google_status.as_deref() {
        Some("PERMISSION_DENIED") => "permission_denied",
        Some("NOT_FOUND") => "space_not_found",
        Some("UNAUTHENTICATED") => "googlechat_auth_error",
        Some("RESOURCE_EXHAUSTED") => "googlechat_api_error",
        Some("INVALID_ARGUMENT") => "googlechat_api_error",
        Some(_) | None => match http_status {
            401 | 403 => "googlechat_auth_error",
            404 => "space_not_found",
            429 => "googlechat_api_error",
            500..=599 => "googlechat_api_error",
            _ => "googlechat_api_error",
        },
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
