use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixStream;
use tokio::sync::Mutex;

use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake};

use crate::convert::{self, SignalInbound};
use crate::error::SignalError;

/// Signal adapter: bridges signal-cli's JSON-RPC daemon <-> Wirken gateway IPC.
pub struct SignalAdapter {
    identity: AdapterIdentity,
    signal_cli_endpoint: String,
    phone_number: String,
}

impl SignalAdapter {
    pub fn new(
        identity: AdapterIdentity,
        signal_cli_endpoint: String,
        phone_number: String,
    ) -> Self {
        Self {
            identity,
            signal_cli_endpoint,
            phone_number,
        }
    }

    /// Connect to gateway, authenticate, then poll signal-cli for messages.
    pub async fn run(&self, socket_path: &Path) -> Result<(), SignalError> {
        tracing::info!("Connecting to gateway at {}", socket_path.display());
        let stream = UnixStream::connect(socket_path).await?;
        let (mut reader, mut writer) = split_stream(stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut reader, &mut writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let writer = Arc::new(Mutex::new(writer));

        // Spawn outbound handler
        let out_endpoint = self.signal_cli_endpoint.clone();
        let out_phone = self.phone_number.clone();
        let out_writer = writer.clone();
        let _outbound_handle = tokio::spawn(async move {
            handle_outbound(reader, out_endpoint, out_phone, out_writer).await;
        });

        // Spawn heartbeat
        let hb_writer = writer.clone();
        let _hb_handle = tokio::spawn(async move {
            heartbeat_loop(hb_writer).await;
        });

        // Main loop: poll signal-cli for incoming messages
        tracing::info!(
            "Polling signal-cli at {} for account {}",
            self.signal_cli_endpoint,
            self.phone_number
        );

        let http = reqwest::Client::new();
        let mut poll_interval = tokio::time::interval(std::time::Duration::from_secs(1));

        loop {
            poll_interval.tick().await;

            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "receive",
                "id": 1
            });

            let resp = match http
                .post(&self.signal_cli_endpoint)
                .json(&body)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Failed to poll signal-cli: {e}");
                    continue;
                }
            };

            let json: serde_json::Value = match resp.json().await {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!("Failed to parse signal-cli response: {e}");
                    continue;
                }
            };

            if let Some(messages) = extract_messages(&json) {
                for msg in messages {
                    if !convert::should_process(&msg) {
                        continue;
                    }
                    let mut capnp_msg = capnp::message::Builder::new_default();
                    convert::signal_to_inbound(&msg, &mut capnp_msg);
                    let mut w = writer.lock().await;
                    if let Err(e) = w.write_message(&capnp_msg).await {
                        tracing::error!("Failed to forward to gateway: {e}");
                    }
                }
            }
        }
    }
}

/// Extract messages from a signal-cli JSON-RPC receive response.
///
/// signal-cli returns a result array of envelope objects. Each envelope may
/// contain a `dataMessage` with optional `message` (text body) and `groupInfo`.
pub(crate) fn extract_messages(json: &serde_json::Value) -> Option<Vec<SignalInbound>> {
    let result = json.get("result")?;
    let envelopes = result.as_array()?;

    let mut messages = Vec::new();

    for envelope_wrapper in envelopes {
        let envelope = envelope_wrapper.get("envelope").unwrap_or(envelope_wrapper);

        let source = envelope
            .get("source")
            .or_else(|| envelope.get("sourceNumber"))
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();

        let source_name = envelope
            .get("sourceName")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();

        let timestamp = envelope
            .get("timestamp")
            .and_then(|t| t.as_i64())
            .unwrap_or(0);

        let data_message = match envelope.get("dataMessage") {
            Some(dm) => dm,
            None => continue,
        };

        let text = data_message
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();

        let group_id = data_message
            .get("groupInfo")
            .and_then(|g| g.get("groupId"))
            .and_then(|id| id.as_str())
            .map(|s| s.to_string());

        let message_id = format!("{source}_{timestamp}");

        messages.push(SignalInbound {
            message_id,
            sender: source,
            sender_name: if source_name.is_empty() {
                source_name.clone()
            } else {
                source_name
            },
            text,
            timestamp,
            group_id,
        });
    }

    Some(messages)
}

/// Handle outbound messages from gateway to Signal via signal-cli.
async fn handle_outbound(
    mut reader: FrameReader,
    signal_cli_endpoint: String,
    phone_number: String,
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
                let body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "send",
                    "params": {
                        "account": phone_number,
                        "recipient": [fields.conversation_id],
                        "message": fields.text,
                    },
                    "id": 1
                });

                let resp = http.post(&signal_cli_endpoint).json(&body).send().await;

                let (success, msg_id, error) = match resp {
                    Ok(r) if r.status().is_success() => {
                        let body: serde_json::Value = r.json().await.unwrap_or_default();
                        let ts = body["result"]["timestamp"]
                            .as_i64()
                            .map(|t| t.to_string())
                            .unwrap_or_default();
                        (true, ts, String::new())
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
