use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::Mutex;

use wirken_adapter_core::approval::Decision;
use wirken_adapter_core::{MatrixFormatter, OutboundFormatter, SignalFormatter};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{
    AdapterIdentity, IpcFrameReader, IpcFrameWriter, connect, perform_adapter_handshake,
    split_stream,
};

use crate::convert::{self, MatrixInbound, ReactionEvent};
use crate::error::MatrixError;

/// Per-process map from (room_id, bot_approval_message_event_id) to
/// gateway `request_id`. The adapter inserts on outbound approval-
/// request send (after capturing the response's `event_id`), looks
/// up on inbound m.reaction, and removes on use (one-shot consume).
///
/// TODO #119-followup: this is in-memory and bot-restart erases it.
/// Gateway-side pending approvals persist across adapter restart
/// (the gateway queue has a 300s timeout that bounds the asymmetry
/// in practice), but the proper fix is durable adapter-side
/// correlation: persist (room_id, event_id) -> request_id to disk
/// keyed by the adapter's identity so a restart resumes routing.
/// Parallel to Teams' `service_url` cache TODO and Google Chat's
/// service-account auth TODO; same shape of slice-local
/// accommodation for a concern that does not gate the approval
/// flow but eventually wants a proper home.
type PendingApprovals = Arc<Mutex<HashMap<(String, String), String>>>;

/// Matrix adapter: bridges Matrix Client-Server API <-> Wirken gateway IPC.
/// Uses the Matrix CS API directly via reqwest (no matrix-sdk dependency).
/// E2EE support requires matrix-sdk — will be added when the sqlite version
/// conflict with rusqlite 0.39 is resolved.
pub struct MatrixAdapter {
    identity: AdapterIdentity,
    homeserver_url: String,
    username: String,
    password: String,
}

impl MatrixAdapter {
    pub fn new(
        identity: AdapterIdentity,
        homeserver_url: String,
        username: String,
        password: String,
        _state_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            identity,
            homeserver_url,
            username,
            password,
        }
    }

    /// Connect to gateway, authenticate, login to Matrix, then sync.
    pub async fn run(&self, socket_path: &Path) -> Result<(), MatrixError> {
        tracing::info!("Connecting to gateway at {}", socket_path.display());
        let stream = connect(socket_path).await?;
        let (mut reader, mut writer) = split_stream(stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut reader, &mut writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let writer = Arc::new(Mutex::new(writer));

        // Validate HTTPS — refuse to send credentials over plaintext HTTP
        let is_localhost = self.homeserver_url.starts_with("http://localhost")
            || self.homeserver_url.starts_with("http://127.0.0.1");

        if !self.homeserver_url.starts_with("https://") && !is_localhost {
            return Err(MatrixError::Matrix(format!(
                "Homeserver URL must use HTTPS: {}",
                self.homeserver_url
            )));
        }

        // Enforce HTTPS at transport level — reqwest will reject any http:// request
        // unless the homeserver is localhost (development/testing).
        let http = reqwest::Client::builder()
            .https_only(!is_localhost)
            .build()
            .map_err(|e| MatrixError::Matrix(format!("HTTP client: {e}")))?;

        // Login to Matrix
        tracing::info!("Logging in to {} as {}", self.homeserver_url, self.username);
        let login_url = format!("{}/_matrix/client/v3/login", self.homeserver_url);
        let login_body = serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": self.username,
            },
            "password": self.password,
            "initial_device_display_name": "Wirken",
        });

        let login_resp = http
            .post(&login_url)
            .json(&login_body)
            .send()
            .await
            .map_err(|e| MatrixError::Matrix(format!("login request: {e}")))?;

        if !login_resp.status().is_success() {
            let body = login_resp.text().await.unwrap_or_default();
            return Err(MatrixError::Matrix(format!("login failed: {body}")));
        }

        let login_json: serde_json::Value = login_resp
            .json()
            .await
            .map_err(|e| MatrixError::Matrix(format!("login parse: {e}")))?;

        let access_token = login_json["access_token"]
            .as_str()
            .ok_or_else(|| MatrixError::Matrix("no access_token in login response".into()))?
            .to_string();

        let user_id = login_json["user_id"]
            .as_str()
            .unwrap_or(&self.username)
            .to_string();

        tracing::info!("Logged in as {user_id}");

        // Pending-approvals correlation table. Lives for the duration
        // of this `run` call; shared between the sync loop (reads on
        // m.reaction inbound) and the outbound handler (writes on
        // ApprovalRequest send). See `PendingApprovals` doc comment
        // for the TODO #119-followup naming durable correlation as
        // the proper fix.
        let pending_approvals: PendingApprovals = Arc::new(Mutex::new(HashMap::new()));

        // Spawn outbound handler
        let out_http = http.clone();
        let out_hs = self.homeserver_url.clone();
        let out_token = access_token.clone();
        let out_writer = writer.clone();
        let out_pending = pending_approvals.clone();
        let _outbound_handle = tokio::spawn(async move {
            handle_outbound(reader, out_http, out_hs, out_token, out_writer, out_pending).await;
        });

        // Spawn heartbeat
        let hb_writer = writer.clone();
        let _hb_handle = tokio::spawn(async move {
            heartbeat_loop(hb_writer).await;
        });

        // Sync loop
        tracing::info!("Starting Matrix sync");
        let mut since: Option<String> = None;

        loop {
            let mut sync_url = format!(
                "{}/_matrix/client/v3/sync?timeout=30000",
                self.homeserver_url
            );
            if let Some(ref token) = since {
                sync_url.push_str(&format!("&since={token}"));
            }

            let resp = http
                .get(&sync_url)
                .header("Authorization", format!("Bearer {access_token}"))
                .send()
                .await;

            let sync_json: serde_json::Value = match resp {
                Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
                Ok(r) => {
                    let status = r.status();
                    tracing::warn!("Sync returned {status}, retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
                Err(e) => {
                    tracing::error!("Sync error: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            since = sync_json["next_batch"].as_str().map(|s| s.to_string());

            // Process room events
            if let Some(rooms) = sync_json["rooms"]["join"].as_object() {
                for (room_id, room_data) in rooms {
                    let is_dm = is_room_dm(&room_data["summary"]);
                    if let Some(events) = room_data["timeline"]["events"].as_array() {
                        // Reaction branch first. Structured approval
                        // interactions bypass the mention-gate (cf.
                        // `adapter-signal/src/commands.rs:19-24` for
                        // the in-tree precedent on the noise-filter
                        // bypass convention). Reactions to non-
                        // approval messages drop on the pending-
                        // approvals lookup miss.
                        for reaction in convert::extract_reactions(events, room_id) {
                            forward_approval_decision(
                                &reaction,
                                &user_id,
                                &writer,
                                &pending_approvals,
                            )
                            .await;
                        }
                        for event in events {
                            if let Some(inbound) = parse_sync_event(event, room_id, &user_id, is_dm)
                            {
                                if !convert::should_process(&inbound, &user_id, "Wirken") {
                                    continue;
                                }
                                let mut capnp_msg = capnp::message::Builder::new_default();
                                convert::matrix_to_inbound(&inbound, &mut capnp_msg);
                                let mut w: tokio::sync::MutexGuard<'_, IpcFrameWriter> =
                                    writer.lock().await;
                                if let Err(e) = w.write_message(&capnp_msg).await {
                                    tracing::error!("Failed to forward to gateway: {e}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Look up a stored pending approval and forward an
/// `ApprovalDecision` to the gateway when the reaction matches.
/// Reactor self-reactions (the bot reacting to its own message)
/// drop silently. Reactions with non-enum emoji keys drop with a
/// debug log. Reactions to events not in the pending table drop
/// with a debug log (stale press, or to a non-approval message).
/// On match, the table entry is removed (one-shot consume).
async fn forward_approval_decision(
    reaction: &ReactionEvent,
    bot_user_id: &str,
    writer: &Arc<Mutex<IpcFrameWriter>>,
    pending: &PendingApprovals,
) {
    if reaction.reactor_mxid == bot_user_id {
        return;
    }
    let Some(decision) = convert::normalize_reaction_key(&reaction.key) else {
        tracing::debug!(
            reactor = %reaction.reactor_mxid,
            key = %reaction.key,
            "matrix reaction: key not in approval enum; dropping"
        );
        return;
    };
    let request_id = {
        let mut table = pending.lock().await;
        match table.remove(&(
            reaction.room_id.clone(),
            reaction.reacted_to_event_id.clone(),
        )) {
            Some(r) => r,
            None => {
                tracing::debug!(
                    reactor = %reaction.reactor_mxid,
                    room = %reaction.room_id,
                    event_id = %reaction.reacted_to_event_id,
                    "matrix reaction: no pending approval for this event_id; dropping"
                );
                return;
            }
        }
    };
    let is_allow = matches!(decision, Decision::Allow);
    let mut capnp_msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(
        &mut capnp_msg,
        &request_id,
        is_allow,
        &reaction.reactor_mxid,
        &reaction.reactor_mxid,
    );
    let mut w = writer.lock().await;
    if let Err(e) = w.write_message(&capnp_msg).await {
        tracing::error!("matrix reaction: failed to send ApprovalDecision to gateway: {e}");
    }
}

/// A Matrix room is treated as a 1:1 DM when its sync `summary`
/// reports exactly two joined members. The Matrix spec also defines
/// `m.direct` account-data for an authoritative DM flag, but that
/// requires a separate fetch and depends on the peer having set it at
/// room creation; member-count is the reliable signal available
/// inline in every /sync response. Missing/malformed summary falls
/// back to `false` (treated as group, mention-gated).
pub(crate) fn is_room_dm(summary: &serde_json::Value) -> bool {
    summary
        .get("m.joined_member_count")
        .and_then(|v| v.as_i64())
        .is_some_and(|n| n == 2)
}

/// Parse a sync timeline event into a MatrixInbound.
pub(crate) fn parse_sync_event(
    event: &serde_json::Value,
    room_id: &str,
    bot_user_id: &str,
    is_dm: bool,
) -> Option<MatrixInbound> {
    let event_type = event.get("type")?.as_str()?;
    if event_type != "m.room.message" {
        return None;
    }

    let sender = event.get("sender")?.as_str()?;
    if sender == bot_user_id {
        return None;
    }

    let content = event.get("content")?;
    let msgtype = content.get("msgtype")?.as_str()?;
    if msgtype != "m.text" {
        return None;
    }

    let body = content.get("body")?.as_str()?;
    if body.is_empty() {
        return None;
    }

    let event_id = event.get("event_id")?.as_str()?.to_string();
    let timestamp_ms = event.get("origin_server_ts")?.as_i64().unwrap_or(0);

    let reply_to_event = content
        .get("m.relates_to")
        .and_then(|r| r.get("m.in_reply_to"))
        .and_then(|r| r.get("event_id"))
        .and_then(|e| e.as_str())
        .map(|s| s.to_string());

    Some(MatrixInbound {
        event_id,
        sender_id: sender.to_string(),
        sender_name: sender.to_string(), // Display name resolved separately
        room_id: room_id.to_string(),
        text: body.to_string(),
        timestamp_ms,
        is_dm,
        reply_to_event,
        room_name: None,
        is_encrypted: false, // No E2EE without matrix-sdk
    })
}

/// Handle outbound messages — send via Matrix CS API.
async fn handle_outbound(
    mut reader: IpcFrameReader,
    http: reqwest::Client,
    homeserver: String,
    access_token: String,
    writer: Arc<Mutex<IpcFrameWriter>>,
    pending_approvals: PendingApprovals,
) {
    let mut txn_id: u64 = 0;

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
                txn_id += 1;
                let url = format!(
                    "{}/_matrix/client/v3/rooms/{}/send/m.room.message/wirken.{}",
                    homeserver,
                    urlencoded(&fields.room_id),
                    txn_id
                );

                // Matrix `m.room.message` carries two rendering
                // surfaces: a plain-text `body` and an HTML
                // `formatted_body` with `format: org.matrix.custom.html`.
                // Both ship on every send. Clients that ignore HTML
                // (or accessibility tooling) see the plain-text
                // version; clients that render HTML see the rich
                // version. Sourcing `body` from SignalFormatter
                // keeps it as real plain-text-from-markdown rather
                // than the raw markdown source.
                let body = SignalFormatter.format(&fields.text);
                let formatted_body = MatrixFormatter.format(&fields.text);
                let mut content = serde_json::json!({
                    "msgtype": "m.text",
                    "body": body,
                    "format": "org.matrix.custom.html",
                    "formatted_body": formatted_body,
                });

                if let Some(ref reply_to) = fields.reply_to_event {
                    content["m.relates_to"] = serde_json::json!({
                        "m.in_reply_to": {
                            "event_id": reply_to,
                        }
                    });
                }

                let resp = http
                    .put(&url)
                    .header("Authorization", format!("Bearer {access_token}"))
                    .json(&content)
                    .send()
                    .await;

                let (success, msg_id, error) = match resp {
                    Ok(r) if r.status().is_success() => {
                        let body: serde_json::Value = r.json().await.unwrap_or_default();
                        let eid = body["event_id"].as_str().unwrap_or("").to_string();
                        (true, eid, String::new())
                    }
                    Ok(r) => {
                        let body = r.text().await.unwrap_or_default();
                        (false, String::new(), body)
                    }
                    Err(e) => (false, String::new(), e.to_string()),
                };

                let mut result_msg = capnp::message::Builder::new_default();
                convert::build_outbound_result(&mut result_msg, success, &msg_id, &error);
                let mut w: tokio::sync::MutexGuard<'_, IpcFrameWriter> = writer.lock().await;
                if let Err(e) = w.write_message(&result_msg).await {
                    tracing::error!("Failed to send outbound result: {e}");
                }
            }
            FrameAction::SendApprovalRequest(fields) => {
                txn_id += 1;
                send_approval_request(
                    &http,
                    &homeserver,
                    &access_token,
                    txn_id,
                    fields,
                    &writer,
                    &pending_approvals,
                )
                .await;
            }
            FrameAction::Skip => {}
        }
    }
}

/// Send an approval-request message as an `m.room.message` with
/// the canonical reaction instruction. On success, capture the
/// returned `event_id` and insert into `pending_approvals` so the
/// matching inbound m.reaction can be routed to the gateway. On
/// failure, emit `ApprovalRequestFailed`.
///
/// Matrix has no inbound-ack mechanism: the reactor's own client
/// renders their reaction immediately as visual feedback, and the
/// bot has no separate ephemeral-toast affordance over the
/// Client-Server API. This is a genuine platform absence (not a
/// posture choice), and Matrix joins Teams and WhatsApp in the
/// silent-ack-because-platform-absent group from the umbrella
/// taxonomy.
async fn send_approval_request(
    http: &reqwest::Client,
    homeserver: &str,
    access_token: &str,
    txn_id: u64,
    fields: convert::ApprovalRequestFields,
    writer: &Arc<Mutex<IpcFrameWriter>>,
    pending: &PendingApprovals,
) {
    let prompt = format!(
        "Agent {} requests {} (tier {}).\n\
         Action: {}\n\
         Trigger: {}\n\n\
         React with ✅ to approve or ❌ to deny.",
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

    let url = format!(
        "{}/_matrix/client/v3/rooms/{}/send/m.room.message/wirken-approval.{}",
        homeserver,
        urlencoded(&fields.target_room_id),
        txn_id
    );
    let content = serde_json::json!({
        "msgtype": "m.text",
        "body": prompt,
        "format": "org.matrix.custom.html",
        "formatted_body": prompt,
    });

    let resp = http
        .put(&url)
        .header("Authorization", format!("Bearer {access_token}"))
        .json(&content)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            let Some(event_id) = body.get("event_id").and_then(|e| e.as_str()) else {
                tracing::error!(
                    request_id = %fields.request_id,
                    "matrix approval: send succeeded but response missing event_id; emitting \
                     ApprovalRequestFailed"
                );
                emit_approval_failure(writer, &fields.request_id, "missing_event_id").await;
                return;
            };
            let mut table = pending.lock().await;
            table.insert(
                (fields.target_room_id.clone(), event_id.to_string()),
                fields.request_id.clone(),
            );
        }
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            let reason = classify_send_error(status.as_u16(), &body);
            tracing::error!(
                request_id = %fields.request_id,
                room_id = %fields.target_room_id,
                status = status.as_u16(),
                body = %body,
                reason = %reason,
                "matrix approval: send failed; emitting ApprovalRequestFailed"
            );
            emit_approval_failure(writer, &fields.request_id, reason).await;
        }
        Err(e) => {
            tracing::error!(
                request_id = %fields.request_id,
                error = %e,
                "matrix approval: network error; emitting ApprovalRequestFailed"
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
        tracing::error!("matrix approval: failed to send ApprovalRequestFailed: {send_err}");
    }
}

/// Map a Matrix Client-Server API HTTP error to a stable
/// snake_case `reason` label for `ApprovalRequestFailed`. The CS
/// API returns standardised error codes in the body (e.g.
/// `M_FORBIDDEN`, `M_NOT_FOUND`); key off those when present and
/// fall back to HTTP status otherwise.
pub(crate) fn classify_send_error(http_status: u16, response_body: &str) -> &'static str {
    let errcode = serde_json::from_str::<serde_json::Value>(response_body)
        .ok()
        .as_ref()
        .and_then(|v| v.get("errcode"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string());
    match errcode.as_deref() {
        Some("M_FORBIDDEN") => "matrix_auth_error",
        Some("M_UNKNOWN_TOKEN") | Some("M_MISSING_TOKEN") => "matrix_auth_error",
        Some("M_NOT_FOUND") => "room_not_found",
        Some("M_LIMIT_EXCEEDED") => "matrix_api_error",
        Some(_) | None => match http_status {
            401 | 403 => "matrix_auth_error",
            404 => "room_not_found",
            429 => "matrix_api_error",
            500..=599 => "matrix_api_error",
            _ => "matrix_api_error",
        },
    }
}

fn urlencoded(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                String::from(b as char)
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

enum FrameAction {
    SendMessage(convert::OutboundFields),
    SendApprovalRequest(convert::ApprovalRequestFields),
    Skip,
}

async fn heartbeat_loop(writer: Arc<Mutex<IpcFrameWriter>>) {
    let mut seq = 0u64;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        interval.tick().await;
        seq += 1;
        let mut msg = capnp::message::Builder::new_default();
        convert::build_heartbeat(&mut msg, seq);
        let mut w: tokio::sync::MutexGuard<'_, IpcFrameWriter> = writer.lock().await;
        if let Err(e) = w.write_message(&msg).await {
            tracing::error!("Heartbeat send failed: {e}");
            break;
        }
    }
}
