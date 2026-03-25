use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixStream;
use tokio::sync::Mutex;

use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake};

use crate::convert::{self, MatrixInbound};
use crate::error::MatrixError;

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
        let stream = UnixStream::connect(socket_path).await?;
        let (mut reader, mut writer) = split_stream(stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut reader, &mut writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let writer = Arc::new(Mutex::new(writer));
        let http = reqwest::Client::new();

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

        // Spawn outbound handler
        let out_http = http.clone();
        let out_hs = self.homeserver_url.clone();
        let out_token = access_token.clone();
        let out_writer = writer.clone();
        let _outbound_handle = tokio::spawn(async move {
            handle_outbound(reader, out_http, out_hs, out_token, out_writer).await;
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
                    if let Some(events) = room_data["timeline"]["events"].as_array() {
                        for event in events {
                            if let Some(inbound) = parse_sync_event(event, room_id, &user_id) {
                                if !convert::should_process(&inbound, &user_id, "Wirken") {
                                    continue;
                                }
                                let mut capnp_msg = capnp::message::Builder::new_default();
                                convert::matrix_to_inbound(&inbound, &mut capnp_msg);
                                let mut w: tokio::sync::MutexGuard<'_, FrameWriter> =
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

/// Parse a sync timeline event into a MatrixInbound.
fn parse_sync_event(
    event: &serde_json::Value,
    room_id: &str,
    bot_user_id: &str,
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
        is_dm: false, // Determined by room membership count
        reply_to_event,
        room_name: None,
        is_encrypted: false, // No E2EE without matrix-sdk
    })
}

/// Handle outbound messages — send via Matrix CS API.
async fn handle_outbound(
    mut reader: FrameReader,
    http: reqwest::Client,
    homeserver: String,
    access_token: String,
    writer: Arc<Mutex<FrameWriter>>,
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

                let mut content = serde_json::json!({
                    "msgtype": "m.text",
                    "body": fields.text,
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
                let mut w: tokio::sync::MutexGuard<'_, FrameWriter> = writer.lock().await;
                if let Err(e) = w.write_message(&result_msg).await {
                    tracing::error!("Failed to send outbound result: {e}");
                }
            }
            FrameAction::Skip => {}
        }
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
    Skip,
}

async fn heartbeat_loop(writer: Arc<Mutex<FrameWriter>>) {
    let mut seq = 0u64;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        interval.tick().await;
        seq += 1;
        let mut msg = capnp::message::Builder::new_default();
        convert::build_heartbeat(&mut msg, seq);
        let mut w: tokio::sync::MutexGuard<'_, FrameWriter> = writer.lock().await;
        if let Err(e) = w.write_message(&msg).await {
            tracing::error!("Heartbeat send failed: {e}");
            break;
        }
    }
}
