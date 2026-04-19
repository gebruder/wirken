use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::Mutex;

use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake};

use crate::auth::{JwksCache, extract_bearer_token};
use crate::convert::{self, Activity};
use crate::error::TeamsError;

/// MS Teams adapter: bridges Bot Framework REST API <-> Wirken gateway IPC.
/// Receives activities via HTTP webhook, sends replies via Bot Framework REST API.
pub struct TeamsAdapter {
    identity: AdapterIdentity,
    app_id: String,
    app_password: String,
    listen_port: u16,
}

impl TeamsAdapter {
    /// Construct a Teams adapter. Fails if `app_id` or `app_password`
    /// is empty, since both are required: `app_id` is the JWT
    /// audience claim checked on every inbound webhook, and
    /// `app_password` is the client secret used to mint outbound
    /// Bot Framework tokens. Missing either silently breaks
    /// authentication (previously `app_id`-empty combined with the
    /// missing JWT validation to accept any POST as any user).
    pub fn new(
        identity: AdapterIdentity,
        app_id: String,
        app_password: String,
        listen_port: u16,
    ) -> Result<Self, TeamsError> {
        if app_id.is_empty() {
            return Err(TeamsError::Config(
                "Teams adapter requires a non-empty app_id; \
                 inbound JWT validation uses it as the audience claim"
                    .into(),
            ));
        }
        if app_password.is_empty() {
            return Err(TeamsError::Config(
                "Teams adapter requires a non-empty app_password; \
                 outbound messaging cannot mint Bot Framework tokens without it"
                    .into(),
            ));
        }
        Ok(Self {
            identity,
            app_id,
            app_password,
            listen_port,
        })
    }

    /// Connect to the gateway, authenticate, then run the webhook listener.
    pub async fn run(&self, socket_path: &Path) -> Result<(), TeamsError> {
        tracing::info!("Connecting to gateway at {}", socket_path.display());
        let stream = UnixStream::connect(socket_path).await?;
        let (mut reader, mut writer) = split_stream(stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut reader, &mut writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let writer = Arc::new(Mutex::new(writer));
        let http = reqwest::Client::new();
        let jwks = Arc::new(JwksCache::new(http.clone()));

        // Spawn outbound handler (gateway -> Teams via Bot Framework REST API)
        let outbound_writer = writer.clone();
        let outbound_app_id = self.app_id.clone();
        let outbound_password = self.app_password.clone();
        let _outbound_handle = tokio::spawn(async move {
            handle_outbound(reader, outbound_app_id, outbound_password, outbound_writer).await;
        });

        // Spawn heartbeat
        let hb_writer = writer.clone();
        let _hb_handle = tokio::spawn(async move {
            heartbeat_loop(hb_writer).await;
        });

        // Run HTTP webhook listener for incoming Bot Framework activities
        tracing::info!(
            "Starting Teams webhook listener on port {}",
            self.listen_port
        );
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.listen_port)).await?;

        let bot_id = self.app_id.clone();

        loop {
            let (mut stream, _) = listener.accept().await?;
            let w = writer.clone();
            let bid = bot_id.clone();
            let j = jwks.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_webhook_request(&mut stream, &bid, &j, w).await {
                    tracing::error!("Webhook request error: {e}");
                }
            });
        }
    }
}

/// HTTP response helpers. Bodies are empty; the status code carries
/// the outcome. Callers should return after writing.
async fn respond(stream: &mut tokio::net::TcpStream, status_line: &str) -> std::io::Result<()> {
    let body = format!("HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(body.as_bytes()).await
}

/// Handle a single incoming HTTP request from Bot Framework.
pub(crate) async fn handle_webhook_request(
    stream: &mut tokio::net::TcpStream,
    bot_id: &str,
    jwks: &JwksCache,
    writer: Arc<Mutex<FrameWriter>>,
) -> Result<(), TeamsError> {
    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);

    // Only handle POST requests
    let first_line = request.lines().next().unwrap_or("");
    if !first_line.starts_with("POST") {
        let _ = respond(stream, "200 OK").await;
        return Ok(());
    }

    // Inbound JWT validation. Must succeed before the body is
    // parsed or forwarded to the gateway. A failed validation always
    // surfaces as a generic 401 on the wire; the specific reason
    // goes to tracing so an operator can debug without the reason
    // becoming an oracle for attackers.
    let token = match extract_bearer_token(&request) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Teams webhook rejected: {e}");
            let _ = respond(stream, "401 Unauthorized").await;
            return Ok(());
        }
    };
    if let Err(e) = jwks.validate_token(token, bot_id).await {
        tracing::warn!("Teams webhook rejected: {e}");
        let _ = respond(stream, "401 Unauthorized").await;
        return Ok(());
    }

    // Extract JSON body (after the auth check passes)
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    let activity: Activity = match serde_json::from_str(body) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("Invalid activity JSON: {e}");
            let _ = respond(stream, "400 Bad Request").await;
            return Ok(());
        }
    };

    // Respond 200 immediately (Bot Framework expects fast response)
    let _ = respond(stream, "200 OK").await;

    // Check if we should process this message
    if !convert::should_process(&activity, bot_id) {
        return Ok(());
    }

    // Convert and forward to gateway
    let mut capnp_msg = capnp::message::Builder::new_default();
    convert::activity_to_inbound(&activity, bot_id, &mut capnp_msg);

    let mut w: tokio::sync::MutexGuard<'_, FrameWriter> = writer.lock().await;
    w.write_message(&capnp_msg).await.map_err(TeamsError::Ipc)?;

    tracing::debug!(
        "Forwarded Teams activity {} to gateway",
        activity.id.as_deref().unwrap_or("?")
    );

    Ok(())
}

/// Handle outbound messages from gateway — POST to Bot Framework REST API.
async fn handle_outbound(
    mut reader: FrameReader,
    app_id: String,
    app_password: String,
    writer: Arc<Mutex<FrameWriter>>,
) {
    let http = reqwest::Client::new();
    // Cache for service URL -> access token
    let mut access_token: Option<String> = None;

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
                // Ensure we have an access token
                if access_token.is_none() {
                    match get_bot_framework_token(&http, &app_id, &app_password).await {
                        Ok(token) => access_token = Some(token),
                        Err(e) => {
                            tracing::error!("Failed to get Bot Framework token: {e}");
                            let mut result_msg = capnp::message::Builder::new_default();
                            convert::build_outbound_result(
                                &mut result_msg,
                                false,
                                "",
                                &e.to_string(),
                            );
                            let mut w = writer.lock().await;
                            let _ = w.write_message(&result_msg).await;
                            continue;
                        }
                    }
                }

                let token = access_token.as_ref().unwrap();
                let reply_url = format!(
                    "https://smba.trafficmanager.net/teams/v3/conversations/{}/activities",
                    fields.conversation_id
                );

                let mut reply_body = serde_json::json!({
                    "type": "message",
                    "text": fields.text,
                    "conversation": {
                        "id": fields.conversation_id
                    }
                });

                if let Some(ref reply_to) = fields.reply_to_id {
                    reply_body["replyToId"] = serde_json::Value::String(reply_to.clone());
                }

                let resp = http
                    .post(&reply_url)
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .json(&reply_body)
                    .send()
                    .await;

                let (success, msg_id, error) = match resp {
                    Ok(r) if r.status().is_success() => {
                        let body: serde_json::Value = r.json().await.unwrap_or_default();
                        let id = body
                            .get("id")
                            .and_then(|i| i.as_str())
                            .unwrap_or("")
                            .to_string();
                        (true, id, String::new())
                    }
                    Ok(r) => {
                        let status = r.status();
                        let body = r.text().await.unwrap_or_default();
                        // Token might have expired
                        if status.as_u16() == 401 {
                            access_token = None;
                        }
                        (false, String::new(), format!("HTTP {status}: {body}"))
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

/// Get a Bot Framework access token using client credentials.
async fn get_bot_framework_token(
    http: &reqwest::Client,
    app_id: &str,
    app_password: &str,
) -> Result<String, TeamsError> {
    let token_url = "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token";

    let form_body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
        url_encode(app_id),
        url_encode(app_password),
        url_encode("https://api.botframework.com/.default"),
    );

    let resp = http
        .post(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form_body)
        .send()
        .await
        .map_err(|e| TeamsError::Auth(e.to_string()))?;

    if !resp.status().is_success() {
        let body_text: String = resp.text().await.unwrap_or_default();
        return Err(TeamsError::Auth(format!(
            "token request failed: {body_text}"
        )));
    }

    let body_json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| TeamsError::Auth(format!("parse token response: {e}")))?;

    body_json
        .get("access_token")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| TeamsError::Auth("no access_token in response".into()))
}

fn url_encode(s: &str) -> String {
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
