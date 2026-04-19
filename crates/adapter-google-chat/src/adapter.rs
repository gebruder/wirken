use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::Mutex;

use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake};

use crate::auth::{JwksCache, extract_bearer_token};
use crate::convert;
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
        let stream = UnixStream::connect(socket_path).await?;
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

/// Handle an incoming webhook request from Google Chat.
pub(crate) async fn handle_webhook(
    stream: &mut tokio::net::TcpStream,
    jwks: &JwksCache,
    expected_aud: &str,
    writer: Arc<Mutex<FrameWriter>>,
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

/// Handle outbound messages from gateway — POST to Google Chat REST API.
async fn handle_outbound(
    mut reader: FrameReader,
    service_account_token: String,
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
