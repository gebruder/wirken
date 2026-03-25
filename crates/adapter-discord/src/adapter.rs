use std::path::Path;
use std::sync::Arc;

use serenity::Client;
use serenity::all::{
    ChannelId, Context, CreateMessage, EventHandler, GatewayIntents, Message as DcMessage,
    MessageId, Ready,
};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake};

use crate::convert;
use crate::error::DiscordError;

/// Discord adapter: bridges Discord Bot API <-> Wirken gateway IPC.
pub struct DiscordAdapter {
    identity: AdapterIdentity,
    bot_token: String,
}

impl DiscordAdapter {
    pub fn new(identity: AdapterIdentity, bot_token: String) -> Self {
        Self {
            identity,
            bot_token,
        }
    }

    /// Connect to the gateway, authenticate, then run the bot.
    pub async fn run(&self, socket_path: &Path) -> Result<(), DiscordError> {
        tracing::info!("Connecting to gateway at {}", socket_path.display());
        let stream = UnixStream::connect(socket_path).await?;
        let (mut reader, mut writer) = split_stream(stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut reader, &mut writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let writer = Arc::new(Mutex::new(writer));

        // Spawn outbound handler (gateway -> Discord)
        // We need a serenity Http client to send messages. We'll get it after the
        // bot connects, so we start with a placeholder and swap it in.
        let http: Arc<Mutex<Option<Arc<serenity::http::Http>>>> = Arc::new(Mutex::new(None));
        let outbound_http = http.clone();
        let outbound_writer = writer.clone();
        let outbound_handle = tokio::spawn(async move {
            handle_outbound(reader, outbound_http, outbound_writer).await;
        });

        // Spawn heartbeat
        let hb_writer = writer.clone();
        let hb_handle = tokio::spawn(async move {
            heartbeat_loop(hb_writer).await;
        });

        // Create serenity event handler
        let handler = Handler {
            writer: writer.clone(),
            bot_id: Arc::new(Mutex::new(0)),
            http_slot: http.clone(),
        };

        // Intents: guild messages, DM messages, message content
        let intents = GatewayIntents::GUILD_MESSAGES
            | GatewayIntents::DIRECT_MESSAGES
            | GatewayIntents::MESSAGE_CONTENT;

        let mut client = Client::builder(&self.bot_token, intents)
            .event_handler(handler)
            .await?;

        tracing::info!("Starting Discord gateway connection");
        client.start().await?;

        outbound_handle.abort();
        hb_handle.abort();
        Ok(())
    }
}

/// Serenity event handler that forwards Discord messages to the Wirken gateway.
struct Handler {
    writer: Arc<Mutex<FrameWriter>>,
    bot_id: Arc<Mutex<u64>>,
    http_slot: Arc<Mutex<Option<Arc<serenity::http::Http>>>>,
}

#[serenity::async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        tracing::info!("Discord bot ready: {} ({})", ready.user.name, ready.user.id);
        *self.bot_id.lock().await = ready.user.id.get();

        // Store the HTTP client for outbound messages
        *self.http_slot.lock().await = Some(ctx.http.clone());
    }

    async fn message(&self, _ctx: Context, msg: DcMessage) {
        let bot_id = *self.bot_id.lock().await;

        // Don't respond to ourselves
        if msg.author.id.get() == bot_id {
            return;
        }

        // Mention-gating: in guilds, only respond when @mentioned
        if !convert::should_process(&msg, bot_id) {
            return;
        }

        // Convert and send to gateway
        let mut capnp_msg = capnp::message::Builder::new_default();
        convert::discord_to_inbound(&msg, bot_id, &mut capnp_msg);

        let mut w: tokio::sync::MutexGuard<'_, FrameWriter> = self.writer.lock().await;
        if let Err(e) = w.write_message(&capnp_msg).await {
            tracing::error!("Failed to send inbound to gateway: {e}");
        } else {
            tracing::debug!(
                "Forwarded message {} from {} to gateway",
                msg.id,
                msg.author.name
            );
        }
    }
}

/// Handle outbound messages from gateway and send via Discord.
async fn handle_outbound(
    mut reader: FrameReader,
    http: Arc<Mutex<Option<Arc<serenity::http::Http>>>>,
    writer: Arc<Mutex<FrameWriter>>,
) {
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

        // Extract fields before .await (Cap'n Proto readers not Send)
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

        match action {
            FrameAction::SendMessage(fields) => {
                let http_guard = http.lock().await;
                let Some(ref http_client) = *http_guard else {
                    tracing::warn!("Discord HTTP client not ready yet, dropping outbound");
                    continue;
                };
                let http_client = http_client.clone();
                drop(http_guard);

                let channel_id = ChannelId::new(fields.channel_id);
                let mut message = CreateMessage::new().content(&fields.text);

                if let Some(reply_id) = fields.reply_to_id {
                    message = message.reference_message((channel_id, MessageId::new(reply_id)));
                }

                let (success, msg_id, error) =
                    match channel_id.send_message(&http_client, message).await {
                        Ok(sent) => (true, sent.id.to_string(), String::new()),
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
