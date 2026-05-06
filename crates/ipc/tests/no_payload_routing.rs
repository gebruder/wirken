//! Regression test: no payload field can change which channel an
//! inbound IPC frame is routed to.
//!
//! Routing for inbound traffic is determined by:
//!
//! - The handshake-validated `adapter_id` returned by
//!   `perform_gateway_handshake` in `crates/ipc/src/auth.rs:173`,
//!   which the gateway maps to a registered channel via the adapter
//!   registry.
//! - That channel is wrapped in `AuthenticatedChannel`
//!   (`crates/ipc/src/channel.rs:20`), which is constructed only by
//!   the gateway and tests.
//! - Every subsequent inbound frame's self-declared `channel` field
//!   is checked with `AuthenticatedChannel::require_match`
//!   (`crates/ipc/src/channel.rs:38`); a mismatch produces
//!   `ChannelMismatch` and the gateway drops the frame after
//!   auditing both sides (call site:
//!   `crates/cli/src/commands/run.rs:937-965`).
//!
//! The schema deliberately does not expose `host`, `target`,
//! `routing`, `routeTo`, `agentId`, or sandbox-parameter fields on
//! any frame variant. The `channel` field on `InboundMessage` is
//! the only routing-relevant payload field, and it is gated.
//!
//! Mapped CVE/GHSA shapes:
//! - CVE-2026-42434: sandbox escape via `host=node` parameter override
//! - GHSA-7vq9-42cc-33j4: device-paired node skips node scope gate
//! - GHSA-r3v5-2grc-429h: operator.pairing → operator.admin via
//!   `device.pair.approve`

use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AuthenticatedChannel, ChannelMismatch};

const SCHEMA_PATH: &str = "schema/wirken.capnp";

#[test]
fn schema_has_no_routing_override_fields() {
    // Read the schema text and assert no field name in the banned
    // list appears. Picks up any future `host @N :Text;` or
    // `target @N :Text;` addition during code review (test fails
    // and the change author has to argue why it is safe).
    let schema =
        std::fs::read_to_string(SCHEMA_PATH).unwrap_or_else(|e| panic!("read {SCHEMA_PATH}: {e}"));

    // A capnp field declaration is `<name> @<n> :<type>;`. Match
    // against `<name> @` so we don't false-positive on documentation
    // prose elsewhere in the file.
    let banned_field_names = [
        "host",
        "target",
        "routing",
        "routeTo",
        "route",
        "agentId",     // routing should be by handshake, not payload
        "sandboxMode", // sandbox config is gateway-side
        "sandboxParam",
        "execHost",
        "spawnTarget",
    ];

    let mut offenders = Vec::new();
    for (idx, line) in schema.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            // Capnp comments use `#`; skip so we don't flag prose.
            continue;
        }
        for field in banned_field_names {
            // Match `<field> @` in the field-declaration form.
            let pat = format!("{field} @");
            if trimmed.starts_with(&pat) {
                offenders.push(format!(
                    "{SCHEMA_PATH}:{}: routing-relevant field `{field}` was added to the IPC \
                     schema. Routing must remain handshake-derived. If this field really \
                     needs to be on the wire, extend `AuthenticatedChannel` first and \
                     gate the field at the gateway message loop.",
                    idx + 1,
                ));
            }
        }
    }
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

#[test]
fn inbound_message_has_only_channel_as_routing_field() {
    // Pin the InboundMessage field set so a future schema edit that
    // adds a routing-relevant payload field has to update this test
    // alongside the schema. The field set comes from
    // `crates/ipc/schema/wirken.capnp:42-65` (InboundMessage).
    //
    // Of these, only `channel` and `conversationId` are
    // routing-influencing on the gateway side. `channel` is gated
    // by `AuthenticatedChannel::require_match`; `conversationId` is
    // the routing key within an authenticated channel and is
    // matched against operator-bound routes in
    // `crates/gateway/src/router.rs:46`.
    let schema = std::fs::read_to_string(SCHEMA_PATH).expect("read schema");

    let inbound_block = extract_struct_block(&schema, "InboundMessage")
        .expect("InboundMessage struct present in schema");

    let mut field_names = Vec::new();
    for line in inbound_block.lines() {
        let trimmed = line.trim();
        // capnp field declaration: `<name> @<idx> :<type>;`
        if let Some(at_pos) = trimmed.find(" @") {
            let name = &trimmed[..at_pos];
            // Strip leading `[]` or other punctuation if present;
            // for our schema, names are bare identifiers.
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                field_names.push(name.to_string());
            }
        }
    }

    let mut sorted = field_names.clone();
    sorted.sort();

    // The expected canonical field set, sorted. Sourced from
    // `crates/ipc/schema/wirken.capnp:42-65`.
    let expected = vec![
        "channel".to_string(),
        "conversationId".to_string(),
        "id".to_string(),
        "isGroup".to_string(),
        "metadata".to_string(),
        "replyToId".to_string(),
        "senderId".to_string(),
        "senderName".to_string(),
        "text".to_string(),
        "timestamp".to_string(),
    ];

    assert_eq!(
        sorted, expected,
        "InboundMessage field set drifted. If this is intentional \
         (e.g. you added a new metadata-only field), update the \
         expected list. If you added a routing-relevant field, \
         extend `AuthenticatedChannel` and the gateway message \
         loop's require_match check first."
    );
}

#[test]
fn forged_channel_field_is_rejected_against_authenticated_channel() {
    // Build a real Cap'n Proto Frame as an adapter would, but with
    // `channel = "slack"` while the connection was authenticated as
    // `telegram`. Then walk the same parse path the gateway uses
    // and run the require_match check that lives in the gateway's
    // message loop (`crates/cli/src/commands/run.rs:943`). The
    // mismatch must surface; it must not be silently routed.
    let mut msg = capnp::message::Builder::new_default();
    {
        let frame_builder = msg.init_root::<frame::Builder<'_>>();
        let mut inbound = frame_builder.init_inbound();
        inbound.set_id("forged-1");
        inbound.set_sender_id("attacker");
        inbound.set_sender_name("Forged");
        // Adapter authenticated as telegram; payload claims slack.
        inbound.set_channel("slack");
        inbound.set_conversation_id("attacker-conv");
        inbound.set_text("steer me to the slack agent");
        inbound.set_timestamp(0);
        inbound.set_is_group(false);
        inbound.set_reply_to_id("");
        inbound.set_metadata("{}");
    }

    // Round-trip through the wire format.
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &msg).expect("write frame");
    let received = capnp::serialize::read_message(
        std::io::Cursor::new(buf),
        capnp::message::ReaderOptions::default(),
    )
    .expect("read frame");
    let frame_reader = received
        .get_root::<frame::Reader<'_>>()
        .expect("frame root");

    let claimed_channel = match frame_reader.which().expect("frame variant") {
        frame::Inbound(inbound) => {
            let m = inbound.expect("inbound");
            m.get_channel()
                .expect("channel")
                .to_str()
                .expect("channel utf8")
                .to_string()
        }
        _ => panic!("expected Inbound variant"),
    };

    // Build the gateway-side `AuthenticatedChannel` exactly as it
    // would be after the handshake at
    // `crates/ipc/src/auth.rs:173-274` and registry resolution.
    let authenticated = AuthenticatedChannel::new("telegram");

    // The gate: identical to the call site at
    // `crates/cli/src/commands/run.rs:943`.
    let outcome = authenticated.require_match(&claimed_channel);

    match outcome {
        Ok(()) => panic!(
            "forged inbound frame with channel=`slack` was accepted \
             on a connection authenticated as `telegram`; the \
             require_match gate failed open"
        ),
        Err(ChannelMismatch {
            authenticated,
            claimed,
        }) => {
            assert_eq!(authenticated, "telegram");
            assert_eq!(claimed, "slack");
        }
    }
}

#[test]
fn matching_channel_field_passes_authenticated_check() {
    // Companion to the forged-channel test: the same frame shape
    // with a matching `channel` field passes. Pinning this prevents
    // a future tightening that breaks legitimate inbound traffic
    // by mistake.
    let mut msg = capnp::message::Builder::new_default();
    {
        let frame_builder = msg.init_root::<frame::Builder<'_>>();
        let mut inbound = frame_builder.init_inbound();
        inbound.set_id("legit-1");
        inbound.set_sender_id("user");
        inbound.set_sender_name("Alice");
        inbound.set_channel("telegram");
        inbound.set_conversation_id("chat-1");
        inbound.set_text("hello");
        inbound.set_timestamp(0);
        inbound.set_is_group(false);
        inbound.set_reply_to_id("");
        inbound.set_metadata("{}");
    }
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &msg).unwrap();
    let received = capnp::serialize::read_message(
        std::io::Cursor::new(buf),
        capnp::message::ReaderOptions::default(),
    )
    .unwrap();
    let frame_reader = received.get_root::<frame::Reader<'_>>().unwrap();
    let frame::Inbound(inbound) = frame_reader.which().unwrap() else {
        panic!("expected Inbound");
    };
    let claimed = inbound
        .unwrap()
        .get_channel()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let authenticated = AuthenticatedChannel::new("telegram");
    assert!(authenticated.require_match(&claimed).is_ok());
}

fn extract_struct_block<'a>(schema: &'a str, struct_name: &str) -> Option<&'a str> {
    // Locate `struct <Name> {` and return the slice up to the
    // matching closing `}` at column 0. Cheap match for our hand-
    // formatted schema; not a general capnp parser.
    let needle = format!("struct {struct_name} {{");
    let start = schema.find(&needle)?;
    let after = &schema[start..];
    // Find the next line starting with `}` that closes the struct.
    let mut depth = 0;
    let mut end_offset = 0;
    for (idx, ch) in after.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end_offset = idx + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    if end_offset == 0 {
        return None;
    }
    Some(&after[..end_offset])
}
