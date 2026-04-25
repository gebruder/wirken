use std::path::Path;
use std::sync::Arc;

use teloxide::prelude::*;
use teloxide::types::{ChatId, MessageId, ParseMode, ReplyParameters};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use wirken_adapter_core::{OutboundFormatter, TelegramFormatter};
use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake};

use crate::convert;
use crate::error::TelegramError;

/// Telegram adapter: bridges Telegram Bot API <-> Wirken gateway IPC.
pub struct TelegramAdapter {
    identity: AdapterIdentity,
    bot_token: String,
}

impl TelegramAdapter {
    /// Create a new Telegram adapter.
    pub fn new(identity: AdapterIdentity, bot_token: String) -> Self {
        Self {
            identity,
            bot_token,
        }
    }

    /// Connect to the gateway, authenticate, then run the message loop.
    pub async fn run(&self, socket_path: &Path) -> Result<(), TelegramError> {
        tracing::info!("Connecting to gateway at {}", socket_path.display());
        let stream = UnixStream::connect(socket_path).await?;
        let (mut reader, mut writer) = split_stream(stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut reader, &mut writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let writer = Arc::new(Mutex::new(writer));
        let bot = Bot::new(&self.bot_token);

        tracing::info!("Starting Telegram long polling");

        // Spawn outbound handler (gateway -> Telegram)
        let outbound_bot = bot.clone();
        let outbound_writer = writer.clone();
        let outbound_handle = tokio::spawn(async move {
            handle_outbound(reader, outbound_bot, outbound_writer).await;
        });

        // Spawn heartbeat
        let hb_writer = writer.clone();
        let hb_handle = tokio::spawn(async move {
            heartbeat_loop(hb_writer).await;
        });

        // Run inbound handler (Telegram -> gateway) — blocks until bot stops
        let inbound_writer = writer.clone();
        run_inbound(bot, inbound_writer).await;

        outbound_handle.abort();
        hb_handle.abort();
        Ok(())
    }
}

/// Handle inbound Telegram messages and forward to gateway via IPC.
async fn run_inbound(bot: Bot, writer: Arc<Mutex<FrameWriter>>) {
    let handler = Update::filter_message().endpoint(move |msg: Message, _bot: Bot| {
        let writer = writer.clone();
        async move {
            let mut capnp_msg = capnp::message::Builder::new_default();
            convert::telegram_to_inbound(&msg, &mut capnp_msg);

            let mut w: tokio::sync::MutexGuard<'_, FrameWriter> = writer.lock().await;
            if let Err(e) = w.write_message(&capnp_msg).await {
                tracing::error!("Failed to send inbound to gateway: {e}");
            } else {
                tracing::debug!("Forwarded msg {} from {}", msg.id.0, msg.chat.id.0);
            }

            Ok::<(), teloxide::RequestError>(())
        }
    });

    Dispatcher::builder(bot, handler)
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;
}

/// Handle outbound messages from gateway and send via Telegram.
async fn handle_outbound(mut reader: FrameReader, bot: Bot, writer: Arc<Mutex<FrameWriter>>) {
    loop {
        // Read frame from gateway
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

        // Extract what we need from the Cap'n Proto message BEFORE any .await
        // Cap'n Proto readers contain raw pointers and are not Send.
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
                Ok(frame::Heartbeat(_)) => {
                    tracing::trace!("Received heartbeat from gateway");
                    FrameAction::Skip
                }
                Ok(_) => {
                    tracing::warn!("Unexpected frame type from gateway");
                    FrameAction::Skip
                }
                Err(e) => {
                    tracing::error!("Frame variant error: {e}");
                    FrameAction::Skip
                }
            }
        };
        // msg (and all Cap'n Proto readers) dropped here — safe to .await below

        match action {
            FrameAction::SendMessage(fields) => {
                let chat_id = ChatId(fields.conversation_id);
                // Render the agent's markdown into Telegram's HTML
                // dialect, then ship it with `parse_mode=HTML` so the
                // bot API actually parses the tags. Without the
                // parse_mode set, Telegram renders the HTML as
                // literal text.
                let rendered = TelegramFormatter.format(&fields.text);
                let mut request = bot.send_message(chat_id, rendered);
                request = request.parse_mode(ParseMode::Html);

                if let Some(reply_id) = fields.reply_to_id {
                    request = request.reply_parameters(ReplyParameters::new(MessageId(reply_id)));
                }

                let (success, msg_id, error) = match request.await {
                    Ok(sent) => (true, sent.id.0.to_string(), String::new()),
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

/// Intermediate enum so we can drop Cap'n Proto readers before .await
enum FrameAction {
    SendMessage(convert::OutboundFields),
    Skip,
}

/// Send periodic heartbeats to the gateway.
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
        tracing::trace!("Sent heartbeat seq={seq}");
    }
}
