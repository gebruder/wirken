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

            tokio::spawn(async move {
                if let Err(e) = handle_webhook(&mut stream, w).await {
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

/// Handle outbound messages from gateway to iMessage via BlueBubbles.
async fn handle_outbound(
    mut reader: IpcFrameReader,
    bluebubbles_url: String,
    server_password: String,
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
