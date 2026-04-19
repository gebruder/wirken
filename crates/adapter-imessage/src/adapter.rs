use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::Mutex;

use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake};

use crate::convert;
use crate::error::IMessageError;

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
        let stream = UnixStream::connect(socket_path).await?;
        let (mut reader, mut writer) = split_stream(stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut reader, &mut writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let writer = Arc::new(Mutex::new(writer));

        // Register webhook with BlueBubbles
        let webhook_url = format!("http://localhost:{}/webhook", self.listen_port);
        self.register_webhook(&webhook_url).await?;

        // Spawn outbound handler
        let out_bb_url = self.bluebubbles_url.clone();
        let out_password = self.server_password.clone();
        let out_writer = writer.clone();
        let _outbound_handle = tokio::spawn(async move {
            handle_outbound(reader, out_bb_url, out_password, out_writer).await;
        });

        // Spawn heartbeat
        let hb_writer = writer.clone();
        let _hb_handle = tokio::spawn(async move {
            heartbeat_loop(hb_writer).await;
        });

        // Run HTTP webhook listener
        tracing::info!(
            "Starting iMessage webhook listener on port {}",
            self.listen_port
        );
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.listen_port)).await?;

        loop {
            let (mut stream, _) = listener.accept().await?;
            let w = writer.clone();
            let pw = self.server_password.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_webhook(&mut stream, &pw, w).await {
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
pub(crate) async fn handle_webhook(
    stream: &mut tokio::net::TcpStream,
    expected_password: &str,
    writer: Arc<Mutex<FrameWriter>>,
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

    // Authenticate the request using the shared BlueBubbles password
    // registered at webhook setup. Without this check the webhook
    // accepted any POST matching the payload shape. The password is
    // searched for in the JSON body (matches the outbound flow
    // convention) or in an `X-BlueBubbles-Password` header. Missing
    // or mismatched → 401.
    let presented = extract_webhook_password(&request, &json);
    if !verify_password(expected_password, presented) {
        tracing::warn!("iMessage webhook rejected: missing or invalid password");
        let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        return Ok(());
    }

    if let Some(msg) = convert::extract_message(&json)
        && convert::should_process(&msg)
    {
        let mut capnp_msg = capnp::message::Builder::new_default();
        convert::imessage_to_inbound(&msg, &mut capnp_msg);
        let mut w = writer.lock().await;
        if let Err(e) = w.write_message(&capnp_msg).await {
            tracing::error!("Failed to forward to gateway: {e}");
        }
    }

    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let _ = stream.write_all(resp.as_bytes()).await;

    Ok(())
}

/// Pull the password presented by BlueBubbles. Checks the JSON body
/// field `password` (matches the outbound convention on line where
/// wirken sends its own password to BB in the body) and the
/// `X-BlueBubbles-Password` / `X-BB-Password` headers. Returns the
/// first non-empty match.
pub(crate) fn extract_webhook_password<'a>(
    request: &'a str,
    json: &'a serde_json::Value,
) -> Option<&'a str> {
    if let Some(pw) = json.get("password").and_then(|v| v.as_str())
        && !pw.is_empty()
    {
        return Some(pw);
    }
    for line in request.lines() {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("x-bluebubbles-password")
            || name.eq_ignore_ascii_case("x-bb-password")
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Constant-time password comparison. Length mismatch short-circuits
/// (length is typically fixed for a provisioned secret, and
/// revealing "wrong length" is not meaningfully useful to an
/// attacker); content comparison is constant-time.
pub(crate) fn verify_password(expected: &str, presented: Option<&str>) -> bool {
    let Some(presented) = presented else {
        return false;
    };
    if expected.is_empty() || presented.is_empty() {
        return false;
    }
    let a = expected.as_bytes();
    let b = presented.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Handle outbound messages from gateway to iMessage via BlueBubbles.
async fn handle_outbound(
    mut reader: FrameReader,
    bluebubbles_url: String,
    server_password: String,
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
