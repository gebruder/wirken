use std::path::Path;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::Mutex;

use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake};

use crate::convert::{self, WhatsAppInbound};
use crate::error::WhatsAppError;

type HmacSha256 = Hmac<Sha256>;

/// WhatsApp Cloud API adapter: bridges Meta's webhook API <-> Wirken gateway IPC.
pub struct WhatsAppAdapter {
    identity: AdapterIdentity,
    access_token: String,
    phone_number_id: String,
    verify_token: String,
    app_secret: String,
    listen_port: u16,
}

impl WhatsAppAdapter {
    pub fn new(
        identity: AdapterIdentity,
        access_token: String,
        phone_number_id: String,
        verify_token: String,
        app_secret: String,
        listen_port: u16,
    ) -> Self {
        Self {
            identity,
            access_token,
            phone_number_id,
            verify_token,
            app_secret,
            listen_port,
        }
    }

    /// Connect to gateway, authenticate, then run the webhook listener.
    pub async fn run(&self, socket_path: &Path) -> Result<(), WhatsAppError> {
        tracing::info!("Connecting to gateway at {}", socket_path.display());
        let stream = UnixStream::connect(socket_path).await?;
        let (mut reader, mut writer) = split_stream(stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut reader, &mut writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let writer = Arc::new(Mutex::new(writer));

        // Spawn outbound handler
        let out_token = self.access_token.clone();
        let out_phone_id = self.phone_number_id.clone();
        let out_writer = writer.clone();
        let _outbound_handle = tokio::spawn(async move {
            handle_outbound(reader, out_token, out_phone_id, out_writer).await;
        });

        // Spawn heartbeat
        let hb_writer = writer.clone();
        let _hb_handle = tokio::spawn(async move {
            heartbeat_loop(hb_writer).await;
        });

        // Run HTTP webhook listener
        tracing::info!(
            "Starting WhatsApp webhook listener on port {}",
            self.listen_port
        );
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.listen_port)).await?;

        let verify_token = self.verify_token.clone();
        let app_secret = self.app_secret.clone();

        loop {
            let (mut stream, _) = listener.accept().await?;
            let w = writer.clone();
            let vt = verify_token.clone();
            let secret = app_secret.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_webhook(&mut stream, &vt, &secret, w).await {
                    tracing::error!("Webhook error: {e}");
                }
            });
        }
    }
}

/// Handle an incoming webhook request from Meta.
async fn handle_webhook(
    stream: &mut tokio::net::TcpStream,
    verify_token: &str,
    app_secret: &str,
    writer: Arc<Mutex<FrameWriter>>,
) -> Result<(), WhatsAppError> {
    let mut buf = vec![0u8; 65536];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| WhatsAppError::Webhook(e.to_string()))?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    // Webhook verification (GET request from Meta)
    if first_line.starts_with("GET /webhook") {
        return handle_verification(stream, &request, verify_token).await;
    }

    // Webhook event (POST request)
    if first_line.starts_with("POST /webhook") {
        let body = request.split("\r\n\r\n").nth(1).unwrap_or("");

        // Verify HMAC signature if app_secret is configured
        if !app_secret.is_empty() {
            let signature = extract_header(&request, "X-Hub-Signature-256");
            if !verify_signature(app_secret, body, &signature) {
                let resp =
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes()).await;
                return Ok(());
            }
        }

        let json: serde_json::Value = serde_json::from_str(body).unwrap_or_default();

        // Parse WhatsApp Cloud API webhook format
        if let Some(messages) = extract_messages(&json) {
            for msg in messages {
                if !convert::should_process(&msg) {
                    continue;
                }
                let mut capnp_msg = capnp::message::Builder::new_default();
                convert::whatsapp_to_inbound(&msg, &mut capnp_msg);
                let mut w = writer.lock().await;
                if let Err(e) = w.write_message(&capnp_msg).await {
                    tracing::error!("Failed to forward to gateway: {e}");
                }
            }
        }

        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
    } else {
        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
    }

    Ok(())
}

/// Handle Meta's webhook verification challenge.
async fn handle_verification(
    stream: &mut tokio::net::TcpStream,
    request: &str,
    verify_token: &str,
) -> Result<(), WhatsAppError> {
    let first_line = request.lines().next().unwrap_or("");
    let query = first_line
        .split_whitespace()
        .nth(1)
        .and_then(|path| path.split('?').nth(1))
        .unwrap_or("");

    let params: std::collections::HashMap<&str, &str> =
        query.split('&').filter_map(|p| p.split_once('=')).collect();

    let mode = params.get("hub.mode").copied().unwrap_or("");
    let token = params.get("hub.verify_token").copied().unwrap_or("");
    let challenge = params.get("hub.challenge").copied().unwrap_or("");

    if mode == "subscribe" && token == verify_token {
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            challenge.len(),
            challenge
        );
        let _ = stream.write_all(resp.as_bytes()).await;
    } else {
        let resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
    }

    Ok(())
}

/// Extract messages from the WhatsApp Cloud API webhook payload.
pub(crate) fn extract_messages(json: &serde_json::Value) -> Option<Vec<WhatsAppInbound>> {
    let entry = json.get("entry")?.as_array()?.first()?;
    let changes = entry.get("changes")?.as_array()?;

    let mut messages = Vec::new();

    for change in changes {
        let value = change.get("value")?;
        let phone_number_id = value
            .get("metadata")
            .and_then(|m| m.get("phone_number_id"))
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();

        let contacts = value.get("contacts").and_then(|c| c.as_array());

        if let Some(msgs) = value.get("messages").and_then(|m| m.as_array()) {
            for msg in msgs {
                let msg_type = msg.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if msg_type != "text" {
                    continue;
                }

                let from = msg
                    .get("from")
                    .and_then(|f| f.as_str())
                    .unwrap_or("")
                    .to_string();

                let from_name = contacts
                    .and_then(|c| {
                        c.iter().find_map(|contact| {
                            let wa_id = contact.get("wa_id").and_then(|w| w.as_str()).unwrap_or("");
                            if wa_id == from {
                                contact
                                    .get("profile")
                                    .and_then(|p| p.get("name"))
                                    .and_then(|n| n.as_str())
                                    .map(|s| s.to_string())
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or_else(|| from.clone());

                let text = msg
                    .get("text")
                    .and_then(|t| t.get("body"))
                    .and_then(|b| b.as_str())
                    .unwrap_or("")
                    .to_string();

                let message_id = msg
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();

                let timestamp = msg
                    .get("timestamp")
                    .and_then(|t| t.as_str())
                    .and_then(|t| t.parse::<i64>().ok())
                    .unwrap_or(0);

                messages.push(WhatsAppInbound {
                    message_id,
                    from,
                    from_name,
                    text,
                    timestamp,
                    phone_number_id: phone_number_id.clone(),
                });
            }
        }
    }

    Some(messages)
}

/// Handle outbound messages from gateway to WhatsApp.
async fn handle_outbound(
    mut reader: FrameReader,
    access_token: String,
    phone_number_id: String,
    writer: Arc<Mutex<FrameWriter>>,
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
                let url = format!(
                    "https://graph.facebook.com/v21.0/{}/messages",
                    phone_number_id
                );

                let body = serde_json::json!({
                    "messaging_product": "whatsapp",
                    "to": fields.conversation_id,
                    "type": "text",
                    "text": {
                        "body": fields.text,
                    }
                });

                let resp = http
                    .post(&url)
                    .header("Authorization", format!("Bearer {access_token}"))
                    .json(&body)
                    .send()
                    .await;

                let (success, msg_id, error) = match resp {
                    Ok(r) if r.status().is_success() => {
                        let body: serde_json::Value = r.json().await.unwrap_or_default();
                        let mid = body["messages"]
                            .as_array()
                            .and_then(|a| a.first())
                            .and_then(|m| m["id"].as_str())
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
            FrameAction::Skip => {}
        }
    }
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
        let mut w = writer.lock().await;
        if let Err(e) = w.write_message(&msg).await {
            tracing::error!("Heartbeat send failed: {e}");
            break;
        }
    }
}

fn extract_header(request: &str, name: &str) -> String {
    let lower = name.to_lowercase();
    for line in request.lines() {
        if let Some((key, value)) = line.split_once(':')
            && key.trim().to_lowercase() == lower
        {
            return value.trim().to_string();
        }
    }
    String::new()
}

/// Verify the HMAC-SHA256 signature from Meta's webhook.
pub(crate) fn verify_signature(app_secret: &str, body: &str, signature_header: &str) -> bool {
    let expected_prefix = "sha256=";
    let hex_sig = match signature_header.strip_prefix(expected_prefix) {
        Some(s) => s,
        None => return false,
    };

    let mut mac = match HmacSha256::new_from_slice(app_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body.as_bytes());

    let expected = mac.finalize().into_bytes();
    let expected_hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();

    // Constant-time comparison
    expected_hex == hex_sig
}
