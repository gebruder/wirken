//! The frames `wirken chat` exchanges with the gateway on the terminal
//! channel, in owned form for the screen.

use capnp::message::{Builder, HeapAllocator};
use wirken_ipc::wirken_capnp::{frame, llm_chunk, tool_activity};

/// The channel name the gateway pins this connection to.
pub(crate) const CHANNEL: &str = "terminal";

/// An approval the gateway asks for, as the card shows it. Every field
/// but the id is shown, and every one shown goes through
/// [`super::text::sanitize`] first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalAsk {
    pub request_id: String,
    pub tool_name: String,
    pub action_key: String,
    pub tier: String,
    pub agent: String,
    pub trigger: String,
    pub exec_location: String,
    pub arguments: String,
    pub assistant_text: String,
    /// How long the gateway waits, zero when it did not say.
    pub timeout_secs: u32,
    /// The runtime the exec would run under, as the gateway names it:
    /// `gvisor`, `docker` or `host`. Empty for other tools.
    pub exec_runtime: String,
}

/// What the screen asks the gateway about its own state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Query {
    /// The panels for the conversation.
    Status,
    /// Check the conversation's chain.
    Verify,
    /// The agents and their terminal conversations.
    Conversations,
    /// The conversation's messages, to resume it.
    History,
}

/// What the gateway sent, of what the screen uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServerEvent {
    /// Reply text as the model writes it.
    Chunk(String),
    /// The model's stream failed.
    StreamError(String),
    ToolCall {
        id: String,
        name: String,
        arguments: String,
    },
    ToolResult {
        id: String,
        name: String,
        success: bool,
        /// The output as the chain records it.
        output: String,
    },
    Approval(ApprovalAsk),
    /// The turn's reply as the gateway recorded it. Ends the turn.
    Reply(String),
    /// The answer to a [`Query`], as JSON.
    Answer {
        request_id: String,
        body: serde_json::Value,
    },
    /// Anything else on the wire.
    Other,
}

fn text(r: capnp::Result<capnp::text::Reader<'_>>) -> capnp::Result<String> {
    Ok(r?.to_string().unwrap_or_default())
}

/// Read one frame from the gateway.
pub(crate) fn parse(
    msg: &capnp::message::Reader<capnp::serialize::OwnedSegments>,
) -> capnp::Result<ServerEvent> {
    let root = msg.get_root::<frame::Reader<'_>>()?;
    let Ok(which) = root.which() else {
        return Ok(ServerEvent::Other);
    };
    Ok(match which {
        frame::LlmChunk(c) => match c?.which() {
            Ok(llm_chunk::Data(d)) => ServerEvent::Chunk(text(d)?),
            Ok(llm_chunk::Error(e)) => ServerEvent::StreamError(text(e)?),
            _ => ServerEvent::Other,
        },
        frame::ToolActivity(t) => {
            let t = t?;
            let id = text(t.get_call_id())?;
            let name = text(t.get_tool_name())?;
            match t.which() {
                Ok(tool_activity::Call(a)) => ServerEvent::ToolCall {
                    id,
                    name,
                    arguments: text(a)?,
                },
                Ok(tool_activity::Result(success)) => ServerEvent::ToolResult {
                    id,
                    name,
                    success,
                    output: text(t.get_output())?,
                },
                Err(_) => ServerEvent::Other,
            }
        }
        frame::ApprovalRequest(r) => {
            let r = r?;
            ServerEvent::Approval(ApprovalAsk {
                request_id: text(r.get_request_id())?,
                tool_name: text(r.get_tool_name())?,
                action_key: text(r.get_action_key())?,
                tier: text(r.get_requested_tier())?,
                agent: text(r.get_triggering_agent())?,
                trigger: text(r.get_trigger_message())?,
                exec_location: text(r.get_exec_location())?,
                arguments: text(r.get_arguments())?,
                assistant_text: text(r.get_assistant_text())?,
                timeout_secs: r.get_timeout_secs(),
                exec_runtime: text(r.get_exec_runtime())?,
            })
        }
        frame::Outbound(o) => ServerEvent::Reply(text(o?.get_text())?),
        frame::TerminalReply(r) => {
            let r = r?;
            ServerEvent::Answer {
                request_id: text(r.get_request_id())?,
                body: serde_json::from_str(&text(r.get_body())?).unwrap_or_default(),
            }
        }
        _ => ServerEvent::Other,
    })
}

/// A message typed at the terminal. The sender fields are for display
/// only: the gateway records the message against the operator key the
/// handshake verified.
pub(crate) fn message(conversation: &str, text: &str, sender: &str) -> Builder<HeapAllocator> {
    let mut msg = Builder::new_default();
    {
        let mut m = msg.init_root::<frame::Builder<'_>>().init_inbound();
        m.set_id(format!("terminal-{}", uuid::Uuid::new_v4()));
        m.set_sender_id(sender);
        m.set_sender_name(sender);
        m.set_channel(CHANNEL);
        m.set_conversation_id(conversation);
        m.set_text(text);
        m.set_timestamp(chrono::Utc::now().timestamp_millis());
        m.set_metadata("{}");
    }
    msg
}

/// Ask the gateway `query` about `conversation`.
pub(crate) fn request(
    request_id: &str,
    conversation: &str,
    query: Query,
) -> Builder<HeapAllocator> {
    let mut msg = Builder::new_default();
    {
        let mut r = msg
            .init_root::<frame::Builder<'_>>()
            .init_terminal_request();
        r.set_request_id(request_id);
        r.set_conversation_id(conversation);
        match query {
            Query::Status => r.set_status(()),
            Query::Verify => r.set_verify(()),
            Query::Conversations => r.set_conversations(()),
            Query::History => r.set_history(()),
        }
    }
    msg
}

/// The operator's decision on a card. `reason` is recorded with a
/// denial; it is ignored with an approval.
pub(crate) fn decision(
    request_id: &str,
    approve: bool,
    reason: Option<&str>,
    operator: &str,
) -> Builder<HeapAllocator> {
    let mut msg = Builder::new_default();
    {
        let mut d = msg
            .init_root::<frame::Builder<'_>>()
            .init_approval_decision();
        d.set_request_id(request_id);
        d.set_actor_user_id(operator);
        d.set_actor_display(operator);
        let mut kind = d.init_decision();
        if approve {
            kind.set_allow(());
        } else {
            kind.set_deny(reason.unwrap_or(""));
        }
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(msg: &Builder<HeapAllocator>) -> ServerEvent {
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, msg).unwrap();
        let reader = capnp::serialize::read_message(
            &mut bytes.as_slice(),
            capnp::message::ReaderOptions::new(),
        )
        .unwrap();
        parse(&reader).unwrap()
    }

    #[test]
    fn the_events_the_screen_reads_are_parsed() {
        let mut msg = Builder::new_default();
        msg.init_root::<frame::Builder<'_>>()
            .init_llm_chunk()
            .set_data("Hel");
        assert_eq!(round_trip(&msg), ServerEvent::Chunk("Hel".into()));

        let mut msg = Builder::new_default();
        {
            let mut t = msg.init_root::<frame::Builder<'_>>().init_tool_activity();
            t.set_call_id("c1");
            t.set_tool_name("exec");
            t.set_result(false);
            t.set_output("ls: cannot access 'x': No such file or directory");
        }
        assert_eq!(
            round_trip(&msg),
            ServerEvent::ToolResult {
                id: "c1".into(),
                name: "exec".into(),
                success: false,
                output: "ls: cannot access 'x': No such file or directory".into(),
            }
        );

        let mut msg = Builder::new_default();
        {
            let mut r = msg
                .init_root::<frame::Builder<'_>>()
                .init_approval_request();
            r.set_request_id("r1");
            r.set_tool_name("exec");
            r.set_arguments("{}");
            r.set_timeout_secs(300);
            r.set_exec_runtime("gvisor");
        }
        match round_trip(&msg) {
            ServerEvent::Approval(ask) => {
                assert_eq!(ask.request_id, "r1");
                assert_eq!(ask.arguments, "{}");
                assert_eq!(ask.timeout_secs, 300);
                assert_eq!(ask.exec_runtime, "gvisor");
            }
            other => panic!("{other:?}"),
        }

        let mut msg = Builder::new_default();
        msg.init_root::<frame::Builder<'_>>()
            .init_outbound()
            .set_text("done");
        assert_eq!(round_trip(&msg), ServerEvent::Reply("done".into()));
    }

    #[test]
    fn a_message_claims_the_terminal_channel() {
        let msg = message("c-1", "hi", "davi");
        let root = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
        let frame::Inbound(m) = root.which().unwrap() else {
            panic!("expected an inbound frame");
        };
        let m = m.unwrap();
        assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "terminal");
        assert_eq!(m.get_conversation_id().unwrap().to_str().unwrap(), "c-1");
    }
}
