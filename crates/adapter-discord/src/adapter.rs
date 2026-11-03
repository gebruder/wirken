use std::path::Path;
use std::sync::Arc;

use serenity::Client;
use serenity::all::{
    ButtonStyle, ChannelId, Context, CreateActionRow, CreateButton, CreateInteractionResponse,
    CreateInteractionResponseFollowup, CreateInteractionResponseMessage, CreateMessage,
    EventHandler, GatewayIntents, Interaction, Message as DcMessage, MessageId, Ready,
};
use tokio::sync::Mutex;

use wirken_adapter_core::approval::{self, ApprovalPayload, Decision};
use wirken_adapter_core::approval_card::CardStyle;
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
            decided: Arc::new(Mutex::new(DecidedCards::default())),
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
    /// Cards a press has already decided in this process.
    decided: Arc<Mutex<DecidedCards>>,
}

/// How many decided request ids the adapter keeps. Far more than are
/// ever open at once; past it the oldest is forgotten, and the
/// gateway drops a repeat decision on its own in any case.
const DECIDED_CARDS_CAP: usize = 1024;

/// Request ids this adapter has forwarded a decision for. A second
/// press on the same card is answered and sends nothing.
#[derive(Default)]
pub(crate) struct DecidedCards {
    order: std::collections::VecDeque<String>,
    set: std::collections::HashSet<String>,
}

impl DecidedCards {
    /// Mark `request_id` decided. False when it already was.
    pub(crate) fn insert(&mut self, request_id: &str) -> bool {
        if !self.set.insert(request_id.to_string()) {
            return false;
        }
        self.order.push_back(request_id.to_string());
        if self.order.len() > DECIDED_CARDS_CAP
            && let Some(oldest) = self.order.pop_front()
        {
            self.set.remove(&oldest);
        }
        true
    }
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

        // The first press decides the card. A later one, from a client
        // that still shows the buttons live, sends nothing to the
        // gateway and gets a reply that depends on the card alone.
        if !self.decided.lock().await.insert(&payload.request_id) {
            let _ = component
                .create_response(
                    &ctx.http,
                    CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new()
                            .content("This request has already been decided.")
                            .ephemeral(true),
                    ),
                )
                .await;
            return;
        }

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
            &component.channel_id.get().to_string(),
        );
        {
            let mut w = self.writer.lock().await;
            if let Err(e) = w.write_message(&capnp_msg).await {
                tracing::error!(
                    "discord interaction: failed to send ApprovalDecision to gateway: {e}"
                );
            }
        }

        // Answer the interaction by redrawing the card with both
        // buttons disabled. Only `components` is set, so the card's
        // text stays as posted. The ids encode from the request id
        // alone, so the redrawn row carries the same `custom_id`s.
        let response = match approval_buttons(&payload.request_id, true) {
            Ok(row) => CreateInteractionResponse::UpdateMessage(
                CreateInteractionResponseMessage::new().components(vec![row]),
            ),
            // The id encoded when the card was posted, so this does
            // not happen; if it did, the press still has to be
            // acknowledged or the client shows a stuck spinner.
            Err(e) => {
                tracing::warn!(
                    request_id = %payload.request_id,
                    error = %e,
                    "discord interaction: could not rebuild the button row; card left as is"
                );
                CreateInteractionResponse::Acknowledge
            }
        };
        let _ = component.create_response(&ctx.http, response).await;

        // The presser's own reply, as before, now as a follow-up to
        // the redraw.
        let _ = component
            .create_followup(
                &ctx.http,
                CreateInteractionResponseFollowup::new()
                    .content(acknowledgement(is_allow))
                    .ephemeral(true),
            )
            .await;
    }
}

/// The reply a presser sees. It depends on the button only, so it says
/// nothing about whether the presser is an approver.
pub(crate) fn acknowledgement(is_allow: bool) -> &'static str {
    if is_allow { "Approved" } else { "Denied" }
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
                convert::build_outbound_result(
                    &mut result_msg,
                    success,
                    &msg_id,
                    &error,
                    &fields.correlation_id,
                );
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

/// The approval message body: the card every surface renders, in the
/// Markdown Discord draws. The buttons under it carry the decision.
pub(crate) fn approval_text(fields: &convert::ApprovalRequestFields) -> String {
    fields.card().render(CardStyle::Markdown)
}

/// The Approve / Deny button row for one card. `disabled` is the
/// only difference between the row a card is posted with and the
/// row it is redrawn with after a press: each button's `custom_id`
/// is the cross-adapter encoding from `wirken_adapter_core::approval`
/// of the request id and the decision, so both rows decode to the
/// same request.
pub(crate) fn approval_buttons(
    request_id: &str,
    disabled: bool,
) -> Result<CreateActionRow, approval::EncodeError> {
    let button = |decision, label, style| {
        approval::encode(&ApprovalPayload {
            request_id: request_id.to_string(),
            decision,
        })
        .map(|id| {
            CreateButton::new(id)
                .label(label)
                .style(style)
                .disabled(disabled)
        })
    };
    Ok(CreateActionRow::Buttons(vec![
        button(Decision::Allow, "Approve", ButtonStyle::Success)?,
        button(Decision::Deny, "Deny", ButtonStyle::Danger)?,
    ]))
}

/// Render an approval message in the configured channel and ship
/// it with a Components-v2 button row carrying Approve / Deny
/// buttons, built by [`approval_buttons`].
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
    let text = approval_text(&fields);

    // Encoding failure here would indicate a malformed request_id;
    // emit ApprovalRequestFailed rather than building a half-shaped
    // message.
    let row = match approval_buttons(&fields.request_id, false) {
        Ok(row) => row,
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
