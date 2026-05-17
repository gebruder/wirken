use std::path::Path;
use std::sync::Arc;

use serenity::Client;
use serenity::all::{
    ButtonStyle, ChannelId, Context, CreateActionRow, CreateButton, CreateInteractionResponse,
    CreateInteractionResponseMessage, CreateMessage, EventHandler, GatewayIntents, Interaction,
    Message as DcMessage, MessageId, Ready,
};
use tokio::sync::Mutex;

use wirken_adapter_core::approval::{self, ApprovalPayload, Decision};
use wirken_adapter_core::{DiscordFormatter, OutboundFormatter};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{
    AdapterIdentity, IpcFrameReader, IpcFrameWriter, connect, perform_adapter_handshake,
    split_stream,
};

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
        let stream = connect(socket_path).await?;
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
    writer: Arc<Mutex<IpcFrameWriter>>,
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

        let mut w: tokio::sync::MutexGuard<'_, IpcFrameWriter> = self.writer.lock().await;
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

    /// Component-interaction press (approval buttons). Decodes the
    /// `custom_id` under the cross-adapter encoding from
    /// `wirken_adapter_core::approval`, forwards an
    /// `ApprovalDecision` IPC frame to the gateway, and ephemerally
    /// acknowledges to the clicker. Discord requires acknowledgement
    /// within 3s of receipt; the work in this path (decode + IPC
    /// write + ack) is well under budget.
    ///
    /// Authorization is gateway-side. The adapter forwards every
    /// press; an unauthorized presser sees the same ephemeral
    /// acknowledgement as an authorized one, and the gateway
    /// silently drops their decision. This mirrors Telegram's
    /// posture and avoids leaking approver-allowlist membership
    /// information through differential UI feedback.
    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        let component = match interaction {
            Interaction::Component(c) => c,
            _ => return,
        };
        let custom_id = &component.data.custom_id;
        let payload = match approval::decode(custom_id) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    user = component.user.id.get(),
                    custom_id = %custom_id,
                    error = %e,
                    "discord interaction: unrecognized custom_id; dropping"
                );
                // Acknowledge anyway so the operator's client clears
                // the spinner; a stuck spinner is worse than the
                // dropped press.
                let _ = component
                    .create_response(
                        &ctx.http,
                        CreateInteractionResponse::Message(
                            CreateInteractionResponseMessage::new()
                                .content("This button is not recognised.")
                                .ephemeral(true),
                        ),
                    )
                    .await;
                return;
            }
        };

        let user_id = component.user.id.get();
        let user_display = component
            .user
            .global_name
            .clone()
            .unwrap_or_else(|| component.user.name.clone());
        let is_allow = matches!(payload.decision, Decision::Allow);

        let mut capnp_msg = capnp::message::Builder::new_default();
        convert::build_approval_decision(
            &mut capnp_msg,
            &payload.request_id,
            is_allow,
            user_id,
            &user_display,
        );
        {
            let mut w = self.writer.lock().await;
            if let Err(e) = w.write_message(&capnp_msg).await {
                tracing::error!(
                    "discord interaction: failed to send ApprovalDecision to gateway: {e}"
                );
            }
        }

        let ack_text = if is_allow { "Approved" } else { "Denied" };
        let _ = component
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content(ack_text)
                        .ephemeral(true),
                ),
            )
            .await;
    }
}

/// Handle outbound messages from gateway and send via Discord.
async fn handle_outbound(
    mut reader: IpcFrameReader,
    http: Arc<Mutex<Option<Arc<serenity::http::Http>>>>,
    writer: Arc<Mutex<IpcFrameWriter>>,
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
                Ok(frame::ApprovalRequest(_)) => match convert::parse_approval_request(&msg) {
                    Ok(fields) => FrameAction::SendApprovalRequest(fields),
                    Err(e) => {
                        tracing::error!("Failed to parse approval request: {e}");
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
                // Render the agent's markdown into Discord's flavor
                // before handing it to serenity. Most of CommonMark
                // passes through; the meaningful work is flattening
                // GFM tables (Discord has no table primitive) and
                // collapsing horizontal rules.
                let rendered = DiscordFormatter.format(&fields.text);
                let mut message = CreateMessage::new().content(&rendered);

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
                let mut w: tokio::sync::MutexGuard<'_, IpcFrameWriter> = writer.lock().await;
                if let Err(e) = w.write_message(&result_msg).await {
                    tracing::error!("Failed to send outbound result: {e}");
                }
            }
            FrameAction::SendApprovalRequest(fields) => {
                let http_guard = http.lock().await;
                let Some(ref http_client) = *http_guard else {
                    tracing::warn!("Discord HTTP client not ready yet, dropping approval request");
                    continue;
                };
                let http_client = http_client.clone();
                drop(http_guard);
                send_approval_request(&http_client, &writer, fields).await;
            }
            FrameAction::Skip => {}
        }
    }
}

enum FrameAction {
    SendMessage(convert::OutboundFields),
    SendApprovalRequest(convert::ApprovalRequestFields),
    Skip,
}

/// Render an approval message in the configured channel and ship
/// it with a Components-v2 button row carrying Approve / Deny
/// buttons. Each button's `custom_id` is the cross-adapter
/// encoding from `wirken_adapter_core::approval`.
///
/// On send failure (channel inaccessible, Discord API rejection),
/// emits an `ApprovalRequestFailed` frame back to the gateway with
/// a snake_case reason label so the audit row records the failure
/// distinctly from a generic timeout.
async fn send_approval_request(
    http: &Arc<serenity::http::Http>,
    writer: &Arc<Mutex<IpcFrameWriter>>,
    fields: convert::ApprovalRequestFields,
) {
    let text = format!(
        "Agent **{}** requests **{}** (tier: **{}**).\n\
         Action: `{}`\n\
         Trigger: _{}_",
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

    // Encode the approval payloads under the cross-adapter
    // convention. Encoding failure here would indicate a malformed
    // request_id; emit ApprovalRequestFailed rather than building a
    // half-shaped message.
    let allow_id = match approval::encode(&ApprovalPayload {
        request_id: fields.request_id.clone(),
        decision: Decision::Allow,
    }) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                request_id = %fields.request_id,
                error = %e,
                "discord approval: encode failed; emitting ApprovalRequestFailed"
            );
            emit_failure(writer, &fields.request_id, "encode_failed").await;
            return;
        }
    };
    let deny_id = match approval::encode(&ApprovalPayload {
        request_id: fields.request_id.clone(),
        decision: Decision::Deny,
    }) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                request_id = %fields.request_id,
                error = %e,
                "discord approval: encode failed; emitting ApprovalRequestFailed"
            );
            emit_failure(writer, &fields.request_id, "encode_failed").await;
            return;
        }
    };

    let approve = CreateButton::new(allow_id)
        .label("Approve")
        .style(ButtonStyle::Success);
    let deny = CreateButton::new(deny_id)
        .label("Deny")
        .style(ButtonStyle::Danger);
    let row = CreateActionRow::Buttons(vec![approve, deny]);

    let channel = ChannelId::new(fields.target_channel_id);
    let message = CreateMessage::new().content(text).components(vec![row]);

    if let Err(e) = channel.send_message(http, message).await {
        tracing::error!(
            request_id = %fields.request_id,
            channel_id = fields.target_channel_id,
            error = %e,
            "discord approval: send failed; emitting ApprovalRequestFailed"
        );
        emit_failure(writer, &fields.request_id, classify_send_error(&e)).await;
    }
}

async fn emit_failure(writer: &Arc<Mutex<IpcFrameWriter>>, request_id: &str, reason: &str) {
    let mut failure = capnp::message::Builder::new_default();
    convert::build_approval_request_failed(&mut failure, request_id, reason);
    let mut w = writer.lock().await;
    if let Err(send_err) = w.write_message(&failure).await {
        tracing::error!("discord approval: failed to send ApprovalRequestFailed: {send_err}");
    }
}

/// Map a `serenity::Error` to a stable snake_case label for
/// `ApprovalRequestFailed.reason`. Used by SIEM detections to
/// group failures without parsing free text. Longer error detail
/// goes to gateway logs via the error! call above.
fn classify_send_error(e: &serenity::Error) -> &'static str {
    use serenity::Error;
    match e {
        Error::Http(_) => "discord_api_error",
        Error::Model(_) => "discord_api_error",
        Error::Json(_) => "discord_api_error",
        Error::Other(_) => "discord_api_error",
        _ => "network_error",
    }
}

/// Send periodic heartbeats to the gateway.
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
        tracing::trace!("Sent heartbeat seq={seq}");
    }
}
