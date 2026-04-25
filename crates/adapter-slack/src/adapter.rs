use std::path::Path;
use std::sync::Arc;

use slack_morphism::prelude::*;
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use wirken_adapter_core::{OutboundFormatter, SlackFormatter};
use wirken_ipc::transport::{FrameReader, FrameWriter, split_stream};
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake};

use crate::convert;
use crate::error::SlackError;

/// Shared context threaded through the Slack Socket Mode listener.
/// Carries the inbound event forwarder plus the bot's own Slack
/// user id so [`is_bot_mentioned`] can match exact mentions instead
/// of any `<@...>` occurrence.
struct SlackBotContext {
    tx: tokio::sync::mpsc::Sender<convert::SlackInbound>,
    bot_user_id: String,
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
        let stream = UnixStream::connect(socket_path).await?;
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
        tracing::info!("Slack bot user id resolved: {bot_user_id}");

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

                let mut w: tokio::sync::MutexGuard<'_, FrameWriter> = event_writer.lock().await;
                if let Err(e) = w.write_message(&capnp_msg).await {
                    tracing::error!("Failed to send inbound to gateway: {e}");
                }
            }
        });

        let ctx = SlackBotContext {
            tx: event_tx,
            bot_user_id,
        };
        let listener_env = Arc::new(
            SlackClientEventsListenerEnvironment::new(Arc::new(client)).with_user_state(ctx),
        );

        let callbacks = SlackSocketModeListenerCallbacks::new().with_push_events(
            |event: SlackPushEventCallback, _client: Arc<SlackHyperClient>, states| async move {
                tracing::info!("Slack push event received");
                let state_lock = states.read().await;
                if let Some(ctx) = state_lock.get_user_state::<SlackBotContext>() {
                    process_push_event(event, &ctx.tx, &ctx.bot_user_id).await;
                } else {
                    tracing::warn!("No SlackBotContext in user state");
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

/// Check whether the bot is mentioned by its exact Slack user id.
///
/// Slack mention syntax is `<@Uxxxxx>`. An earlier implementation used
/// `text.contains("<@")` which matched any user mention, not just the
/// bot — a workspace member mentioning a colleague would trigger the
/// bot's mention gate. The exact form `<@{bot_user_id}>` (with the
/// closing `>`) also prevents substring collisions between user ids
/// that share a prefix (e.g. `<@U123>` must not match bot id `U1234`).
pub(crate) fn is_bot_mentioned(text: &str, bot_user_id: &str) -> bool {
    if bot_user_id.is_empty() {
        return false;
    }
    text.contains(&format!("<@{bot_user_id}>"))
}

/// Process a push event and send to the event channel.
async fn process_push_event(
    event: SlackPushEventCallback,
    tx: &tokio::sync::mpsc::Sender<convert::SlackInbound>,
    bot_user_id: &str,
) {
    let SlackPushEventCallback { event: body, .. } = event;

    let SlackEventCallbackBody::Message(msg_event) = body else {
        return;
    };

    let user_id = match &msg_event.sender.user {
        Some(uid) => uid.0.clone(),
        None => return,
    };

    let text = msg_event
        .content
        .as_ref()
        .and_then(|c| c.text.as_ref())
        .map(|t| t.to_string())
        .unwrap_or_default();

    if text.is_empty() {
        return;
    }

    let channel_id = msg_event
        .origin
        .channel
        .as_ref()
        .map(|c| c.0.clone())
        .unwrap_or_default();

    let message_ts = msg_event.origin.ts.0.clone();
    let thread_ts = msg_event.origin.thread_ts.as_ref().map(|t| t.0.clone());

    let is_dm = msg_event
        .origin
        .channel_type
        .as_ref()
        .map(|ct| ct.0 == "im")
        .unwrap_or(false);

    let bot_mentioned = is_bot_mentioned(&text, bot_user_id);

    let files: Vec<String> = msg_event
        .content
        .as_ref()
        .and_then(|c| c.files.as_ref())
        .map(|fl| {
            fl.iter()
                .filter_map(|f| f.url_private.as_ref().map(|u| u.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let inbound = convert::SlackInbound {
        message_ts,
        user_id,
        user_name: String::new(),
        channel_id,
        text,
        thread_ts,
        is_dm,
        bot_mentioned,
        files,
    };

    let _ = tx.send(inbound).await;
}

/// Handle outbound messages from gateway and send via Slack Web API.
async fn handle_outbound(
    mut reader: FrameReader,
    bot_token: String,
    writer: Arc<Mutex<FrameWriter>>,
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
                let mut w: tokio::sync::MutexGuard<'_, FrameWriter> = writer.lock().await;
                if let Err(e) = w.write_message(&result_msg).await {
                    tracing::error!("Failed to send outbound result: {e}");
                }
            }
            FrameAction::Skip => {}
        }
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
    }
}
