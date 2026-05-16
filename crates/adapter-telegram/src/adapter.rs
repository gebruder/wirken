use std::path::Path;
use std::sync::Arc;

use teloxide::prelude::*;
use teloxide::types::{
    CallbackQuery, ChatId, InlineKeyboardButton, InlineKeyboardMarkup, MessageId, ParseMode,
    ReplyParameters,
};
use tokio::sync::Mutex;

use wirken_adapter_core::{OutboundFormatter, TelegramFormatter};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{
    AdapterIdentity, IpcFrameReader, IpcFrameWriter, connect, perform_adapter_handshake,
    split_stream,
};

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
        let stream = connect(socket_path).await?;
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

/// Handle inbound Telegram messages and callback-query presses,
/// forwarding both to the gateway via IPC. Two dispatcher branches:
///
/// - **Message branch**: existing path. Forwards as `InboundMessage`.
/// - **Callback-query branch**: new for the approval slice. Parses
///   `callback_data` of the form `req:<uuid>:allow|deny`, extracts
///   the pressing user's id/display, and forwards as
///   `ApprovalDecision`. Acknowledges the press via Telegram's
///   `answer_callback_query` so the spinner clears on the operator's
///   client.
async fn run_inbound(bot: Bot, writer: Arc<Mutex<IpcFrameWriter>>) {
    let msg_writer = writer.clone();
    let message_branch = Update::filter_message().endpoint(move |msg: Message, _bot: Bot| {
        let writer = msg_writer.clone();
        async move {
            let mut capnp_msg = capnp::message::Builder::new_default();
            convert::telegram_to_inbound(&msg, &mut capnp_msg);

            let mut w: tokio::sync::MutexGuard<'_, IpcFrameWriter> = writer.lock().await;
            if let Err(e) = w.write_message(&capnp_msg).await {
                tracing::error!("Failed to send inbound to gateway: {e}");
            } else {
                tracing::debug!("Forwarded msg {} from {}", msg.id.0, msg.chat.id.0);
            }

            Ok::<(), teloxide::RequestError>(())
        }
    });

    let cb_writer = writer.clone();
    let callback_branch =
        Update::filter_callback_query().endpoint(move |q: CallbackQuery, bot: Bot| {
            let writer = cb_writer.clone();
            async move { handle_callback_query(q, bot, writer).await }
        });

    let handler = dptree::entry()
        .branch(message_branch)
        .branch(callback_branch);

    Dispatcher::builder(bot, handler)
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;
}

/// One callback-query press. Format of `callback_data`:
/// `req:<uuid>:allow` or `req:<uuid>:deny`. Documented at the
/// encode site in [`build_approval_message`] so the next channel
/// adapter implementer can match the format. Other adapters'
/// callback-data limits (Discord 100, Slack 255) accommodate the
/// same shape trivially.
async fn handle_callback_query(
    q: CallbackQuery,
    bot: Bot,
    writer: Arc<Mutex<IpcFrameWriter>>,
) -> Result<(), teloxide::RequestError> {
    let id = q.id.clone();
    let parsed = q.data.as_deref().and_then(parse_callback_data);
    let Some((request_id, decision_is_allow)) = parsed else {
        tracing::warn!(
            user = q.from.id.0,
            data = ?q.data,
            "telegram callback: unrecognized callback_data; dropping"
        );
        let _ = bot.answer_callback_query(id).await;
        return Ok(());
    };

    let user_id = q.from.id.0 as i64;
    let user_display = q
        .from
        .username
        .clone()
        .unwrap_or_else(|| q.from.first_name.clone());

    let mut capnp_msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(
        &mut capnp_msg,
        &request_id,
        decision_is_allow,
        user_id,
        &user_display,
    );

    {
        let mut w = writer.lock().await;
        if let Err(e) = w.write_message(&capnp_msg).await {
            tracing::error!("telegram callback: failed to send ApprovalDecision to gateway: {e}");
        }
    }

    // Acknowledge so the operator's client clears the loading
    // spinner. Operator-facing text reflects which button they
    // pressed; the gateway-side authorization check may still
    // silently reject the press (the queue stays open until
    // another authorized press or timeout), but the operator's
    // UI doesn't need to wait for that.
    let ack_text = if decision_is_allow {
        "Approved"
    } else {
        "Denied"
    };
    let _ = bot.answer_callback_query(id).text(ack_text).await;
    Ok(())
}

#[cfg(test)]
pub(crate) fn parse_callback_data_for_test(data: &str) -> Option<(String, bool)> {
    parse_callback_data(data)
}

/// Parse `req:<uuid>:allow|deny`. Returns `(uuid, is_allow)`.
/// Malformed payloads return None; the caller drops the press.
fn parse_callback_data(data: &str) -> Option<(String, bool)> {
    let stripped = data.strip_prefix("req:")?;
    let (uuid, suffix) = stripped.rsplit_once(':')?;
    let is_allow = match suffix {
        "allow" => true,
        "deny" => false,
        _ => return None,
    };
    if uuid.is_empty() {
        return None;
    }
    Some((uuid.to_string(), is_allow))
}

/// Handle outbound messages from gateway and send via Telegram.
async fn handle_outbound(mut reader: IpcFrameReader, bot: Bot, writer: Arc<Mutex<IpcFrameWriter>>) {
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
                let mut w: tokio::sync::MutexGuard<'_, IpcFrameWriter> = writer.lock().await;
                if let Err(e) = w.write_message(&result_msg).await {
                    tracing::error!("Failed to send outbound result: {e}");
                }
            }
            FrameAction::SendApprovalRequest(fields) => {
                send_approval_request(&bot, &writer, fields).await;
            }
            FrameAction::Skip => {}
        }
    }
}

/// Render an approval message in the configured chat and ship it
/// with an inline keyboard carrying Approve / Deny buttons.
/// `callback_data` format: `req:<uuid>:allow` and `req:<uuid>:deny`.
/// Documented format so the next channel adapter (Discord's
/// `custom_id` is 100 bytes, Slack's `action_id` is 255) can match.
///
/// On send failure (chat not accessible, Telegram API rejection),
/// emits an `ApprovalRequestFailed` frame back to the gateway with
/// a snake_case reason label so the audit row records the failure
/// distinctly from a generic timeout.
async fn send_approval_request(
    bot: &Bot,
    writer: &Arc<Mutex<IpcFrameWriter>>,
    fields: convert::ApprovalRequestFields,
) {
    let text = format!(
        "Agent <b>{}</b> requests <b>{}</b> (tier: <b>{}</b>).\n\
         Action: <code>{}</code>\n\
         Trigger: <i>{}</i>",
        html_escape(&fields.triggering_agent),
        html_escape(&fields.tool_name),
        html_escape(&fields.requested_tier),
        html_escape(&fields.action_key),
        if fields.trigger_message.is_empty() {
            "(none)".to_string()
        } else {
            html_escape(&fields.trigger_message)
        },
    );

    let approve =
        InlineKeyboardButton::callback("Approve", format!("req:{}:allow", fields.request_id));
    let deny = InlineKeyboardButton::callback("Deny", format!("req:{}:deny", fields.request_id));
    let keyboard = InlineKeyboardMarkup::new(vec![vec![approve, deny]]);

    let chat = ChatId(fields.target_chat_id);
    let send = bot
        .send_message(chat, text)
        .parse_mode(ParseMode::Html)
        .reply_markup(keyboard);

    if let Err(e) = send.await {
        tracing::error!(
            request_id = %fields.request_id,
            chat_id = fields.target_chat_id,
            error = %e,
            "telegram approval: send failed; emitting ApprovalRequestFailed"
        );
        let reason = classify_send_error(&e);
        let mut failure = capnp::message::Builder::new_default();
        convert::build_approval_request_failed(&mut failure, &fields.request_id, reason);
        let mut w = writer.lock().await;
        if let Err(send_err) = w.write_message(&failure).await {
            tracing::error!("telegram approval: failed to send ApprovalRequestFailed: {send_err}");
        }
    }
}

/// Map a `teloxide::RequestError` to a stable snake_case label for
/// `ApprovalRequestFailed.reason`. Used by SIEM detections to
/// group failures without parsing free text. The longer error
/// detail goes to gateway logs via the warn! above.
fn classify_send_error(e: &teloxide::RequestError) -> &'static str {
    use teloxide::RequestError;
    match e {
        RequestError::Api(_) => "telegram_api_error",
        RequestError::MigrateToChatId(_) => "chat_not_accessible",
        RequestError::RetryAfter(_) => "telegram_api_error",
        RequestError::Network(_) => "network_error",
        RequestError::InvalidJson { .. } => "telegram_api_error",
        RequestError::Io(_) => "network_error",
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Intermediate enum so we can drop Cap'n Proto readers before .await
enum FrameAction {
    SendMessage(convert::OutboundFields),
    SendApprovalRequest(convert::ApprovalRequestFields),
    Skip,
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
