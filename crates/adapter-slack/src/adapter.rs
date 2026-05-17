use std::path::Path;
use std::sync::Arc;

use slack_morphism::prelude::*;
use tokio::sync::Mutex;

use wirken_adapter_core::approval::{self, ApprovalPayload, Decision};
use wirken_adapter_core::{OutboundFormatter, SlackFormatter};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{
    AdapterIdentity, IpcFrameReader, IpcFrameWriter, connect, perform_adapter_handshake,
    split_stream,
};

use crate::convert;
use crate::error::SlackError;

/// Shared context threaded through the Slack Socket Mode listener.
/// Carries the inbound event forwarder plus the bot's self-identity
/// (user id + bot id) so [`convert::from_push_event`] can drop the
/// bot's own messages from `message.im` events instead of forwarding
/// them to the agent — Slack delivers a bot's own outbound back
/// through `message.im` and the agent treats every one as fresh user
/// input, generating a reply, which Slack delivers back, ad infinitum.
///
/// Also carries the IPC writer and bot token for the
/// interaction-event callback. Block-action presses produce
/// `ApprovalDecision` frames that go directly to the IPC writer
/// (independent of push-event ordering), and the fire-and-forget
/// ephemeral toast uses the bot token to open a session on demand.
struct SlackBotContext {
    tx: tokio::sync::mpsc::Sender<convert::SlackInbound>,
    identity: convert::SlackBotIdentity,
    writer: Arc<Mutex<IpcFrameWriter>>,
    bot_token: String,
}

/// Slack adapter: bridges Slack API <-> Wirken gateway IPC.
/// Uses Socket Mode (WebSocket) — no public URL required.
pub struct SlackAdapter {
    identity: AdapterIdentity,
    bot_token: String,
    app_token: String,
}

impl SlackAdapter {
    pub fn new(identity: AdapterIdentity, bot_token: String, app_token: String) -> Self {
        Self {
            identity,
            bot_token,
            app_token,
        }
    }

    /// Connect to the gateway, authenticate, then run the Slack client.
    pub async fn run(&self, socket_path: &Path) -> Result<(), SlackError> {
        tracing::info!("Connecting to gateway at {}", socket_path.display());
        let stream = connect(socket_path).await?;
        let (mut reader, mut writer) = split_stream(stream);

        tracing::info!("Performing handshake as '{}'", self.identity.adapter_id());
        perform_adapter_handshake(&mut reader, &mut writer, &self.identity).await?;
        tracing::info!("Handshake complete");

        let writer = Arc::new(Mutex::new(writer));

        // Spawn outbound handler (gateway -> Slack)
        let outbound_writer = writer.clone();
        let outbound_bot_token = self.bot_token.clone();
        let outbound_handle = tokio::spawn(async move {
            handle_outbound(reader, outbound_bot_token, outbound_writer).await;
        });

        // Spawn heartbeat
        let hb_writer = writer.clone();
        let hb_handle = tokio::spawn(async move {
            heartbeat_loop(hb_writer).await;
        });

        // Run Socket Mode listener
        tracing::info!("Starting Slack Socket Mode");

        let client = SlackClient::new(
            SlackClientHyperConnector::new()
                .map_err(|e| SlackError::Slack(format!("connector: {e}")))?,
        );

        // Resolve the bot's own Slack user id once at connect time.
        // `auth.test` returns the bot-user id that Slack uses in
        // `<@Uxxx>` mention syntax. Storing it here lets the event
        // handler match exact mentions of the bot rather than any
        // user mention. If auth.test fails the adapter refuses to
        // start: running without bot_user_id means we would either
        // accept every mention (the bug we are fixing) or drop
        // every mention.
        let bot_token = make_token(&self.bot_token);
        let auth_client = Arc::new(SlackClient::new(
            SlackClientHyperConnector::new()
                .map_err(|e| SlackError::Slack(format!("connector: {e}")))?,
        ));
        let auth_session = auth_client.open_session(&bot_token);
        let auth_resp = auth_session
            .auth_test()
            .await
            .map_err(|e| SlackError::Slack(format!("auth.test: {e}")))?;
        let bot_user_id = auth_resp.user_id.0.clone();
        let bot_id = auth_resp.bot_id.as_ref().map(|b| b.0.clone());
        tracing::info!(
            "Slack bot identity resolved: user_id={bot_user_id} bot_id={}",
            bot_id.as_deref().unwrap_or("(none)")
        );

        // Use a channel to bridge Socket Mode events to our IPC writer
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<convert::SlackInbound>(256);

        // Spawn event processor
        let event_writer = writer.clone();
        let event_handle = tokio::spawn(async move {
            while let Some(inbound) = event_rx.recv().await {
                if !convert::should_process(&inbound) {
                    continue;
                }

                let mut capnp_msg = capnp::message::Builder::new_default();
                convert::slack_to_inbound(&inbound, &mut capnp_msg);

                let mut w: tokio::sync::MutexGuard<'_, IpcFrameWriter> = event_writer.lock().await;
                if let Err(e) = w.write_message(&capnp_msg).await {
                    tracing::error!("Failed to send inbound to gateway: {e}");
                }
            }
        });

        let ctx = SlackBotContext {
            tx: event_tx,
            identity: convert::SlackBotIdentity {
                user_id: bot_user_id,
                bot_id,
            },
            writer: writer.clone(),
            bot_token: self.bot_token.clone(),
        };
        let listener_env = Arc::new(
            SlackClientEventsListenerEnvironment::new(Arc::new(client)).with_user_state(ctx),
        );

        let callbacks = SlackSocketModeListenerCallbacks::new()
            .with_push_events(
                |event: SlackPushEventCallback, _client: Arc<SlackHyperClient>, states| async move {
                    tracing::info!("Slack push event received");
                    let state_lock = states.read().await;
                    if let Some(ctx) = state_lock.get_user_state::<SlackBotContext>() {
                        process_push_event(event, &ctx.tx, &ctx.identity).await;
                    } else {
                        tracing::warn!("No SlackBotContext in user state");
                    }
                    Ok(())
                },
            )
            .with_interaction_events(
                |event: SlackInteractionEvent, client: Arc<SlackHyperClient>, states| async move {
                    let state_lock = states.read().await;
                    if let Some(ctx) = state_lock.get_user_state::<SlackBotContext>() {
                        process_interaction_event(event, client, &ctx.writer, &ctx.bot_token).await;
                    } else {
                        tracing::warn!("No SlackBotContext in user state for interaction event");
                    }
                    Ok(())
                },
            );

        let socket_listener = SlackClientSocketModeListener::new(
            &SlackClientSocketModeConfig::new(),
            Arc::clone(&listener_env),
            callbacks,
        );

        let app_token = make_token(&self.app_token);
        socket_listener
            .listen_for(&app_token)
            .await
            .map_err(|e| SlackError::Slack(format!("socket mode register: {e}")))?;

        // `listen_for` only registers the app token with the clients
        // manager; it does not open a WSS connection. `start()` is
        // what drives the WSS handshake. Done explicitly rather than
        // via `serve()` so the adapter owns its own shutdown
        // ordering: ctrl_c here, then shutdown(), then abort the
        // task handles below — instead of nesting slack-morphism's
        // `await_term_signals` under our task supervision.
        socket_listener.start().await;
        tracing::info!("Slack Socket Mode WSS connection started");

        tokio::signal::ctrl_c().await.ok();

        tracing::info!("Slack Socket Mode shutdown initiated");
        socket_listener.shutdown().await;

        outbound_handle.abort();
        hb_handle.abort();
        event_handle.abort();
        Ok(())
    }
}

/// Process a push event and send to the event channel.
async fn process_push_event(
    event: SlackPushEventCallback,
    tx: &tokio::sync::mpsc::Sender<convert::SlackInbound>,
    identity: &convert::SlackBotIdentity,
) {
    // All filtering — bot self-message drop, subtype allowlist, empty
    // text, missing sender — lives in `convert::from_push_event` so
    // it can be unit-tested without spinning up the listener.
    let Some(inbound) = convert::from_push_event(&event, identity) else {
        return;
    };
    let _ = tx.send(inbound).await;
}

/// Handle a Socket Mode interaction event (button presses, modal
/// submissions, etc.). Only `BlockActions` is wired today; other
/// variants drop silently. For each action in the press payload:
/// decode the `action_id` under the cross-adapter encoding from
/// `wirken_adapter_core::approval`, write an `ApprovalDecision` IPC
/// frame to the gateway, and fire-and-forget an ephemeral toast to
/// the clicker. The 3-second envelope ACK is sent by slack-morphism
/// when this function returns; the ephemeral toast runs
/// independently and does not gate the ack.
///
/// Authorization is gateway-side. The adapter forwards every press;
/// an unauthorized presser sees the same ephemeral toast as an
/// authorized one and the gateway silently drops their decision,
/// matching Telegram and Discord. The uniform UI feedback avoids
/// leaking approver-allowlist membership through differential
/// behaviour.
async fn process_interaction_event(
    event: SlackInteractionEvent,
    client: Arc<SlackHyperClient>,
    writer: &Arc<Mutex<IpcFrameWriter>>,
    bot_token: &str,
) {
    let SlackInteractionEvent::BlockActions(press) = event else {
        return;
    };
    let Some(user) = press.user else {
        tracing::warn!("slack interaction: BlockActions missing user; dropping");
        return;
    };
    let Some(actions) = press.actions else {
        tracing::debug!("slack interaction: BlockActions has no actions array; dropping");
        return;
    };
    let Some(channel) =
        press
            .channel
            .as_ref()
            .map(|c| c.id.clone())
            .or_else(|| match &press.container {
                SlackInteractionActionContainer::Message(m) => m.channel_id.clone(),
                _ => None,
            })
    else {
        tracing::warn!(
            user = %user.id.0,
            "slack interaction: BlockActions missing channel; ephemeral toast suppressed"
        );
        // We can still forward the IPC frame without a channel, but
        // the toast needs one. Process actions, skip the toast.
        for action in &actions {
            forward_decision(writer, &action.action_id.0, &user, None, &client, bot_token).await;
        }
        return;
    };

    for action in &actions {
        forward_decision(
            writer,
            &action.action_id.0,
            &user,
            Some(channel.clone()),
            &client,
            bot_token,
        )
        .await;
    }
}

async fn forward_decision(
    writer: &Arc<Mutex<IpcFrameWriter>>,
    action_id: &str,
    user: &SlackBasicUserInfo,
    channel: Option<SlackChannelId>,
    client: &Arc<SlackHyperClient>,
    bot_token: &str,
) {
    let payload = match approval::decode(action_id) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                user = %user.id.0,
                action_id = %action_id,
                error = %e,
                "slack interaction: unrecognized action_id; dropping"
            );
            return;
        }
    };
    let is_allow = matches!(payload.decision, Decision::Allow);
    let user_display = user
        .username
        .clone()
        .or_else(|| user.name.clone())
        .unwrap_or_else(|| user.id.0.clone());

    let mut capnp_msg = capnp::message::Builder::new_default();
    convert::build_approval_decision(
        &mut capnp_msg,
        &payload.request_id,
        is_allow,
        &user.id.0,
        &user_display,
    );
    {
        let mut w = writer.lock().await;
        if let Err(e) = w.write_message(&capnp_msg).await {
            tracing::error!("slack interaction: failed to send ApprovalDecision to gateway: {e}");
        }
    }

    if let Some(channel) = channel {
        let ack_text = if is_allow { "Approved" } else { "Denied" };
        post_ephemeral(client, bot_token, channel, user.id.clone(), ack_text).await;
    }
}

async fn post_ephemeral(
    client: &Arc<SlackHyperClient>,
    bot_token: &str,
    channel: SlackChannelId,
    user: SlackUserId,
    text: &str,
) {
    let token = make_token(bot_token);
    let session = client.open_session(&token);
    let content = SlackMessageContent::new().with_text(text.to_string());
    let req = SlackApiChatPostEphemeralRequest::new(channel, user, content);
    if let Err(e) = session.chat_post_ephemeral(&req).await {
        // Fire-and-forget. A failed toast does not undo the
        // forwarded ApprovalDecision and does not block the
        // envelope ACK; log and continue.
        tracing::debug!("slack interaction: postEphemeral failed: {e}");
    }
}

/// Handle outbound messages from gateway and send via Slack Web API.
async fn handle_outbound(
    mut reader: IpcFrameReader,
    bot_token: String,
    writer: Arc<Mutex<IpcFrameWriter>>,
) {
    let client = SlackClient::new(SlackClientHyperConnector::new().expect("slack connector"));
    let token = make_token(&bot_token);
    let session = client.open_session(&token);

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
                Ok(frame::ApprovalRequest(_)) => match convert::parse_approval_request(&msg) {
                    Ok(fields) => FrameAction::SendApprovalRequest(fields),
                    Err(e) => {
                        tracing::error!("Failed to parse approval request: {e}");
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
                let channel: SlackChannelId = fields.channel_id.into();
                // Render the agent's markdown into Slack mrkdwn before
                // handing it to the SDK. Without this, `**bold**`,
                // `[text](url)`, GFM tables, and `# headings` reach
                // Slack as literal text rather than rendered markup.
                let rendered = SlackFormatter.format(&fields.text);
                let content = SlackMessageContent::new().with_text(rendered);
                let mut req = SlackApiChatPostMessageRequest::new(channel, content);

                if let Some(ref ts) = fields.thread_ts {
                    req = req.with_thread_ts(SlackTs(ts.clone()));
                }

                let (success, msg_id, error) = match session.chat_post_message(&req).await {
                    Ok(resp) => (true, resp.ts.0.clone(), String::new()),
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
                send_approval_request(&session, &writer, fields).await;
            }
            FrameAction::Skip => {}
        }
    }
}

/// Render an approval message in the configured channel and ship
/// it with a Block Kit message containing a section block (prompt)
/// and an actions block carrying Approve / Deny buttons. Each
/// button's `action_id` is the cross-adapter encoding from
/// `wirken_adapter_core::approval`.
///
/// On send failure (channel inaccessible, Slack API rejection, or
/// an encode failure on a malformed `request_id`), emits an
/// `ApprovalRequestFailed` frame back to the gateway with a
/// snake_case reason label so the audit row records the failure
/// distinctly from a generic timeout.
async fn send_approval_request<C: SlackClientHttpConnector + Send + Sync>(
    session: &SlackClientSession<'_, C>,
    writer: &Arc<Mutex<IpcFrameWriter>>,
    fields: convert::ApprovalRequestFields,
) {
    let allow_id = match approval::encode(&ApprovalPayload {
        request_id: fields.request_id.clone(),
        decision: Decision::Allow,
    }) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                request_id = %fields.request_id,
                error = %e,
                "slack approval: encode failed; emitting ApprovalRequestFailed"
            );
            emit_approval_failure(writer, &fields.request_id, "encode_failed").await;
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
                "slack approval: encode failed; emitting ApprovalRequestFailed"
            );
            emit_approval_failure(writer, &fields.request_id, "encode_failed").await;
            return;
        }
    };

    let prompt = format!(
        "*Agent* `{}` requests *{}* (tier `{}`).\n\
         *Action:* `{}`\n\
         *Trigger:* _{}_",
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

    let section = SlackSectionBlock::new().with_text(SlackBlockText::MarkDown(
        SlackBlockMarkDownText::new(prompt),
    ));
    let approve_btn = SlackBlockButtonElement::new(
        SlackActionId(allow_id),
        SlackBlockPlainTextOnly::from("Approve"),
    )
    .with_style("primary".to_string());
    let deny_btn = SlackBlockButtonElement::new(
        SlackActionId(deny_id),
        SlackBlockPlainTextOnly::from("Deny"),
    )
    .with_style("danger".to_string());
    let actions = SlackActionsBlock::new(vec![
        SlackActionBlockElement::Button(approve_btn),
        SlackActionBlockElement::Button(deny_btn),
    ]);

    let channel = SlackChannelId(fields.target_channel_id.clone());
    let content = SlackMessageContent::new()
        .with_text(format!(
            "Approval requested for {} ({}).",
            fields.tool_name, fields.requested_tier
        ))
        .with_blocks(vec![section.into(), actions.into()]);
    let req = SlackApiChatPostMessageRequest::new(channel, content);

    if let Err(e) = session.chat_post_message(&req).await {
        tracing::error!(
            request_id = %fields.request_id,
            channel_id = %fields.target_channel_id,
            error = %e,
            "slack approval: send failed; emitting ApprovalRequestFailed"
        );
        emit_approval_failure(writer, &fields.request_id, classify_send_error(&e)).await;
    }
}

async fn emit_approval_failure(
    writer: &Arc<Mutex<IpcFrameWriter>>,
    request_id: &str,
    reason: &str,
) {
    let mut failure = capnp::message::Builder::new_default();
    convert::build_approval_request_failed(&mut failure, request_id, reason);
    let mut w = writer.lock().await;
    if let Err(send_err) = w.write_message(&failure).await {
        tracing::error!("slack approval: failed to send ApprovalRequestFailed: {send_err}");
    }
}

/// Map a slack-morphism error to a stable snake_case label for
/// `ApprovalRequestFailed.reason`. Used by SIEM detections to
/// group failures without parsing free text. Longer error detail
/// goes to gateway logs via the error! call above.
fn classify_send_error(e: &slack_morphism::errors::SlackClientError) -> &'static str {
    use slack_morphism::errors::SlackClientError as E;
    match e {
        E::ApiError(_) => "slack_api_error",
        E::HttpError(_) => "network_error",
        E::HttpProtocolError(_) => "network_error",
        E::EndOfStream(_) => "network_error",
        E::SystemError(_) => "network_error",
        E::ProtocolError(_) => "slack_api_error",
        E::SocketModeProtocolError(_) => "slack_api_error",
        E::RateLimitError(_) => "slack_api_error",
    }
}

fn make_token(value: &str) -> SlackApiToken {
    SlackApiToken {
        token_value: SlackApiTokenValue(value.to_string()),
        cookie: None,
        team_id: None,
        scope: None,
        token_type: None,
    }
}

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
    }
}
