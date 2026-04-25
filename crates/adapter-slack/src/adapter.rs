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
/// Carries the inbound event forwarder plus the bot's self-identity
/// (user id + bot id) so [`convert::from_push_event`] can drop the
/// bot's own messages from `message.im` events instead of forwarding
/// them to the agent — Slack delivers a bot's own outbound back
/// through `message.im` and the agent treats every one as fresh user
/// input, generating a reply, which Slack delivers back, ad infinitum.
struct SlackBotContext {
    tx: tokio::sync::mpsc::Sender<convert::SlackInbound>,
    identity: convert::SlackBotIdentity,
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

                let mut w: tokio::sync::MutexGuard<'_, FrameWriter> = event_writer.lock().await;
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
        };
        let listener_env = Arc::new(
            SlackClientEventsListenerEnvironment::new(Arc::new(client)).with_user_state(ctx),
        );

        let callbacks = SlackSocketModeListenerCallbacks::new().with_push_events(
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
