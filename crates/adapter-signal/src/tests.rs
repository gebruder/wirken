use wirken_ipc::transport::split_stream;
use wirken_ipc::wirken_capnp::frame;
use wirken_ipc::{AdapterIdentity, perform_adapter_handshake, perform_gateway_handshake};

use crate::convert::{self, SignalAllowlist, SignalInbound};

// ---------------------------------------------------------------------------
// Inbound parsing from signal-cli JSON-RPC
// ---------------------------------------------------------------------------

#[test]
fn parse_signal_text_message() {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "result": [{
            "envelope": {
                "source": "+15559876543",
                "sourceName": "Alice",
                "timestamp": 1711900000000_i64,
                "dataMessage": {
                    "message": "Hello wirken!",
                    "timestamp": 1711900000000_i64
                }
            }
        }],
        "id": 1
    });

    let messages = super::adapter::extract_messages(&payload).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sender, "+15559876543");
    assert_eq!(messages[0].sender_name, "Alice");
    assert_eq!(messages[0].text, "Hello wirken!");
    assert_eq!(messages[0].timestamp, 1711900000000);
    assert!(messages[0].group_id.is_none());
}

#[test]
fn ignore_non_text_messages() {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "result": [{
            "envelope": {
                "source": "+15559876543",
                "sourceName": "Alice",
                "timestamp": 1711900000000_i64,
                "typingMessage": {
                    "action": "STARTED"
                }
            }
        }],
        "id": 1
    });

    // Envelope without dataMessage should be skipped
    let messages = super::adapter::extract_messages(&payload).unwrap();
    assert!(messages.is_empty());
}

// ---------------------------------------------------------------------------
// should_process filter
// ---------------------------------------------------------------------------

fn allowlist_with(entries: &[&str]) -> SignalAllowlist {
    SignalAllowlist::from_csv(&entries.join(",")).expect("valid allowlist in test")
}

#[test]
fn empty_text_not_processed() {
    let msg = SignalInbound {
        message_id: "sig_1".into(),
        sender: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "".into(),
        timestamp: 0,
        group_id: None,
    };
    let list = allowlist_with(&["+15551234567"]);
    assert!(!convert::should_process(&msg, &list));
}

#[test]
fn valid_text_processed_when_sender_allowed() {
    let msg = SignalInbound {
        message_id: "sig_2".into(),
        sender: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "hello".into(),
        timestamp: 0,
        group_id: None,
    };
    let list = allowlist_with(&["+15551234567"]);
    assert!(convert::should_process(&msg, &list));
}

#[test]
fn unknown_sender_dropped() {
    let msg = SignalInbound {
        message_id: "sig_3".into(),
        sender: "+15550001111".into(),
        sender_name: "Mallory".into(),
        text: "please run rm -rf /".into(),
        timestamp: 0,
        group_id: None,
    };
    let list = allowlist_with(&["+15551234567"]);
    assert!(!convert::should_process(&msg, &list));
}

#[test]
fn empty_allowlist_drops_everything() {
    let msg = SignalInbound {
        message_id: "sig_4".into(),
        sender: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "hi".into(),
        timestamp: 0,
        group_id: None,
    };
    let empty = SignalAllowlist::default();
    assert!(!convert::should_process(&msg, &empty));
    assert!(empty.is_empty());
}

#[test]
fn group_message_uses_group_id_for_allowlist() {
    // Sender is *not* in the allowlist, but the group is — message passes.
    let msg = SignalInbound {
        message_id: "sig_5".into(),
        sender: "+15550001111".into(),
        sender_name: "Stranger".into(),
        text: "group chat".into(),
        timestamp: 0,
        group_id: Some("group-abc-123".into()),
    };
    let list = allowlist_with(&["group-abc-123"]);
    assert!(convert::should_process(&msg, &list));

    // Same message, group not allowed — dropped even if sender is allowed.
    let list = allowlist_with(&["+15550001111"]);
    assert!(!convert::should_process(&msg, &list));
}

#[test]
fn allowlist_parses_whitespace_and_empty_segments() {
    let list = SignalAllowlist::from_csv(" +15551234567 , , group-xyz ,").unwrap();
    assert_eq!(list.len(), 2);
    let msg = SignalInbound {
        message_id: "sig_6".into(),
        sender: "+15551234567".into(),
        sender_name: "Bob".into(),
        text: "hi".into(),
        timestamp: 0,
        group_id: None,
    };
    assert!(list.allows(&msg));
}

// ---------------------------------------------------------------------------
// Conversation ID logic
// ---------------------------------------------------------------------------

#[test]
fn group_message_uses_group_id_as_conversation() {
    let msg = SignalInbound {
        message_id: "sig_3".into(),
        sender: "+15551234567".into(),
        sender_name: "Alice".into(),
        text: "group chat".into(),
        timestamp: 1711900000000,
        group_id: Some("group-abc-123".into()),
    };

    let mut builder = capnp::message::Builder::new_default();
    convert::signal_to_inbound(&msg, &mut builder);

    let reader = builder.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "group-abc-123"
            );
            assert!(m.get_is_group());
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "signal");
        }
        _ => panic!("expected Inbound"),
    }
}

#[test]
fn direct_message_uses_sender_as_conversation() {
    let msg = SignalInbound {
        message_id: "sig_4".into(),
        sender: "+15559876543".into(),
        sender_name: "Bob".into(),
        text: "direct message".into(),
        timestamp: 1711900000000,
        group_id: None,
    };

    let mut builder = capnp::message::Builder::new_default();
    convert::signal_to_inbound(&msg, &mut builder);

    let reader = builder.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(
                m.get_conversation_id().unwrap().to_str().unwrap(),
                "+15559876543"
            );
            assert!(!m.get_is_group());
        }
        _ => panic!("expected Inbound"),
    }
}

// ---------------------------------------------------------------------------
// Frame building smoke tests
// ---------------------------------------------------------------------------

#[test]
fn build_heartbeat() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_heartbeat(&mut msg, 42);

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::Heartbeat(hb) => assert_eq!(hb.unwrap().get_seq(), 42),
        _ => panic!("expected Heartbeat"),
    }
}

#[test]
fn build_outbound_result() {
    let mut msg = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut msg, true, "sig-msg-123", "");

    let reader = msg.get_root_as_reader::<frame::Reader<'_>>().unwrap();
    match reader.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(r.get_message_id().unwrap().to_str().unwrap(), "sig-msg-123");
            assert_eq!(r.get_error().unwrap().to_str().unwrap(), "");
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// Outbound parsing
// ---------------------------------------------------------------------------

fn serialize_and_read(
    builder: &capnp::message::Builder<capnp::message::HeapAllocator>,
) -> capnp::message::Reader<capnp::serialize::OwnedSegments> {
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, builder).unwrap();
    capnp::serialize::read_message(
        std::io::Cursor::new(buf),
        capnp::message::ReaderOptions::default(),
    )
    .unwrap()
}

#[test]
fn parse_outbound_message() {
    let mut msg = capnp::message::Builder::new_default();
    {
        let fb = msg.init_root::<frame::Builder<'_>>();
        let mut outbound = fb.init_outbound();
        outbound.set_conversation_id("+15559876543");
        outbound.set_text("Agent reply");
        outbound.set_reply_to_id("sig_1");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert_eq!(fields.conversation_id, "+15559876543");
    assert_eq!(fields.text, "Agent reply");
    assert_eq!(fields.reply_to_id.unwrap(), "sig_1");
}

#[test]
fn parse_outbound_no_reply() {
    let mut msg = capnp::message::Builder::new_default();
    {
        let fb = msg.init_root::<frame::Builder<'_>>();
        let mut outbound = fb.init_outbound();
        outbound.set_conversation_id("+15551234567");
        outbound.set_text("New message");
        outbound.set_reply_to_id("");
        outbound.set_metadata("{}");
    }

    let reader = serialize_and_read(&msg);
    let fields = convert::parse_outbound(&reader).unwrap();
    assert!(fields.reply_to_id.is_none());
}

// ---------------------------------------------------------------------------
// Handshake over UDS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adapter_handshake_with_gateway() {
    let identity = AdapterIdentity::generate("signal");
    let expected_pk = identity.public_key_bytes();

    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    let (mut cr, mut cw) = split_stream(client);
    let (mut sr, mut sw) = split_stream(server);

    let adapter_side =
        tokio::spawn(async move { perform_adapter_handshake(&mut cr, &mut cw, &identity).await });

    let gateway_side = tokio::spawn(async move {
        perform_gateway_handshake(&mut sr, &mut sw, |id, pk| {
            assert_eq!(id, "signal");
            assert_eq!(pk, &expected_pk);
            Ok(())
        })
        .await
    });

    let (ar, gr) = tokio::join!(adapter_side, gateway_side);
    ar.unwrap().unwrap();
    let (id, pk) = gr.unwrap().unwrap();
    assert_eq!(id, "signal");
    assert_eq!(pk, expected_pk);
}

// ---------------------------------------------------------------------------
// Full flow: handshake -> inbound -> outbound -> result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_message_flow_simulation() {
    let (adapter_stream, gateway_stream) = tokio::net::UnixStream::pair().unwrap();

    let identity = AdapterIdentity::generate("signal");
    let expected_pk = identity.public_key_bytes();

    let (mut ar, mut aw) = split_stream(adapter_stream);
    let (mut gr, mut gw) = split_stream(gateway_stream);

    // Phase 1: Handshake
    let adapter_hs = tokio::spawn(async move {
        perform_adapter_handshake(&mut ar, &mut aw, &identity)
            .await
            .unwrap();
        (ar, aw)
    });
    let gateway_hs = tokio::spawn(async move {
        perform_gateway_handshake(&mut gr, &mut gw, |id, pk| {
            assert_eq!(id, "signal");
            assert_eq!(pk, &expected_pk);
            Ok(())
        })
        .await
        .unwrap();
        (gr, gw)
    });

    let (adapter_res, gateway_res) = tokio::join!(adapter_hs, gateway_hs);
    let (mut ar, mut aw) = adapter_res.unwrap();
    let (mut gr, mut gw) = gateway_res.unwrap();

    // Phase 2: Adapter sends inbound message
    let mut inbound = capnp::message::Builder::new_default();
    {
        let fb = inbound.init_root::<frame::Builder<'_>>();
        let mut m = fb.init_inbound();
        m.set_id("sig_msg_1");
        m.set_sender_id("+15559876543");
        m.set_sender_name("Alice");
        m.set_channel("signal");
        m.set_conversation_id("+15559876543");
        m.set_text("What's the weather?");
        m.set_timestamp(1711900000000);
        m.set_is_group(false);
        m.set_reply_to_id("");
        m.set_metadata("{}");
    }
    aw.write_message(&inbound).await.unwrap();

    // Gateway reads inbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::Inbound(ib) => {
            let m = ib.unwrap();
            assert_eq!(
                m.get_text().unwrap().to_str().unwrap(),
                "What's the weather?"
            );
            assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "signal");
        }
        _ => panic!("expected Inbound"),
    }

    // Phase 3: Gateway sends outbound reply
    let mut outbound = capnp::message::Builder::new_default();
    {
        let fb = outbound.init_root::<frame::Builder<'_>>();
        let mut m = fb.init_outbound();
        m.set_conversation_id("+15559876543");
        m.set_text("Sunny, 22C.");
        m.set_reply_to_id("sig_msg_1");
        m.set_metadata("{}");
    }
    gw.write_message(&outbound).await.unwrap();

    // Adapter reads outbound
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        ar.read_message().await.unwrap();
    let fields = convert::parse_outbound(&received).unwrap();
    assert_eq!(fields.text, "Sunny, 22C.");
    assert_eq!(fields.conversation_id, "+15559876543");

    // Phase 4: Adapter sends delivery result
    let mut result = capnp::message::Builder::new_default();
    convert::build_outbound_result(&mut result, true, "sig-sent-999", "");
    aw.write_message(&result).await.unwrap();

    // Gateway reads result
    let received: capnp::message::Reader<capnp::serialize::OwnedSegments> =
        gr.read_message().await.unwrap();
    let fr: frame::Reader<'_> = received.get_root::<frame::Reader<'_>>().unwrap();
    match fr.which().unwrap() {
        frame::OutboundResult(r) => {
            let r = r.unwrap();
            assert!(r.get_success());
            assert_eq!(
                r.get_message_id().unwrap().to_str().unwrap(),
                "sig-sent-999"
            );
        }
        _ => panic!("expected OutboundResult"),
    }
}

// ---------------------------------------------------------------------------
// End-to-end: real SignalAdapter::run() against a fake signal-cli HTTP server
// and a fake gateway over a Unix socket. Validates the parts the unit tests
// can't reach: reqwest serialization, HTTP request shape, and response parsing
// over a real network round-trip.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_against_fake_signal_cli_daemon() {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UnixListener};
    use tokio::sync::Mutex;

    use crate::SignalAdapter;

    // ----- Fake signal-cli HTTP/JSON-RPC server -----
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let endpoint = format!("http://{http_addr}/api/v1/rpc");

    let captured_send: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let captured_send_for_server = captured_send.clone();

    let http_task = tokio::spawn(async move {
        loop {
            let (mut sock, _) = match http_listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let captured = captured_send_for_server.clone();
            tokio::spawn(async move {
                // Read until headers complete, then read Content-Length bytes.
                let mut buf = Vec::with_capacity(4096);
                let mut tmp = [0u8; 1024];
                let header_end = loop {
                    let n = match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };

                let header_str = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
                let content_length: usize = header_str
                    .lines()
                    .find_map(|l| {
                        let l = l.to_ascii_lowercase();
                        l.strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap_or(0))
                    })
                    .unwrap_or(0);

                while buf.len() < header_end + content_length {
                    let n = match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                }

                let body = &buf[header_end..header_end + content_length];
                let parsed: serde_json::Value =
                    serde_json::from_slice(body).unwrap_or_else(|_| serde_json::json!({}));
                let method = parsed.get("method").and_then(|m| m.as_str()).unwrap_or("");

                let response_body = if method == "receive" {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "result": [{
                            "envelope": {
                                "source": "+15559876543",
                                "sourceName": "Alice Test",
                                "timestamp": 1711900000000_i64,
                                "dataMessage": {
                                    "message": "hello from integration test",
                                    "timestamp": 1711900000000_i64
                                }
                            }
                        }],
                        "id": 1
                    })
                    .to_string()
                } else if method == "send" {
                    *captured.lock().await = Some(parsed.clone());
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "result": { "timestamp": 1711900000001_i64 },
                        "id": 1
                    })
                    .to_string()
                } else {
                    serde_json::json!({"jsonrpc": "2.0", "result": [], "id": 1}).to_string()
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    // ----- Fake gateway over a real Unix socket -----
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("gw.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();

    let gateway_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut gr, mut gw) = split_stream(stream);

        perform_gateway_handshake(&mut gr, &mut gw, |id, _pk| {
            assert_eq!(id, "signal");
            Ok(())
        })
        .await
        .unwrap();

        // Wait for the first inbound to come through (skip heartbeats just in case).
        let mut inbound_text = None;
        for _ in 0..20 {
            let msg = gr.read_message().await.unwrap();
            let fr = msg.get_root::<frame::Reader<'_>>().unwrap();
            match fr.which().unwrap() {
                frame::Inbound(ib) => {
                    let m = ib.unwrap();
                    inbound_text = Some(m.get_text().unwrap().to_str().unwrap().to_string());
                    assert_eq!(m.get_channel().unwrap().to_str().unwrap(), "signal");
                    assert_eq!(m.get_sender_id().unwrap().to_str().unwrap(), "+15559876543");
                    break;
                }
                _ => continue,
            }
        }

        // Tell the adapter to send a reply back through (fake) Signal.
        let mut outbound = capnp::message::Builder::new_default();
        {
            let fb = outbound.init_root::<frame::Builder<'_>>();
            let mut o = fb.init_outbound();
            o.set_conversation_id("+15559876543");
            o.set_text("integration test reply");
            o.set_reply_to_id("");
            o.set_metadata("{}");
        }
        gw.write_message(&outbound).await.unwrap();

        // Drain frames until we see the OutboundResult.
        let mut outbound_success = None;
        for _ in 0..40 {
            let msg = gr.read_message().await.unwrap();
            let fr = msg.get_root::<frame::Reader<'_>>().unwrap();
            if let frame::OutboundResult(r) = fr.which().unwrap() {
                outbound_success = Some(r.unwrap().get_success());
                break;
            }
        }

        (inbound_text, outbound_success)
    });

    // ----- Run the real adapter against both fakes -----
    let identity = AdapterIdentity::generate("signal");
    let allowlist = SignalAllowlist::from_csv("+15559876543").unwrap();
    let adapter = SignalAdapter::new(identity, endpoint, "+15551112222".to_string(), allowlist);
    let socket_path_for_adapter = socket_path.clone();
    let adapter_task = tokio::spawn(async move { adapter.run(&socket_path_for_adapter).await });

    let gateway_result = tokio::time::timeout(std::time::Duration::from_secs(15), gateway_task)
        .await
        .expect("gateway side timed out — adapter never delivered expected frames")
        .expect("gateway task panicked");

    adapter_task.abort();
    http_task.abort();

    let (inbound_text, outbound_success) = gateway_result;
    assert_eq!(
        inbound_text.as_deref(),
        Some("hello from integration test"),
        "inbound text mismatch"
    );
    assert_eq!(outbound_success, Some(true), "outbound result not success");

    let send_call = captured_send
        .lock()
        .await
        .clone()
        .expect("fake signal-cli never received a send call");
    assert_eq!(send_call["method"], "send");
    assert_eq!(send_call["params"]["account"], "+15551112222");
    assert_eq!(send_call["params"]["recipient"][0], "+15559876543");
    assert_eq!(send_call["params"]["message"], "integration test reply");
}

// ---------------------------------------------------------------------------
// Allowlist enforcement over the real adapter loop: fake signal-cli returns a
// message from a sender NOT in the allowlist. The adapter must drop it, so the
// gateway should see only heartbeats (or nothing at all) within the window.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_drops_messages_from_unknown_senders() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UnixListener};

    use crate::SignalAdapter;

    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let endpoint = format!("http://{http_addr}/api/v1/rpc");

    let http_task = tokio::spawn(async move {
        loop {
            let (mut sock, _) = match http_listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(4096);
                let mut tmp = [0u8; 1024];
                loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": [{
                        "envelope": {
                            "source": "+15550001111",
                            "sourceName": "Unknown",
                            "timestamp": 1711900000000_i64,
                            "dataMessage": {
                                "message": "this should never reach the agent",
                                "timestamp": 1711900000000_i64
                            }
                        }
                    }],
                    "id": 1
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("gw.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();

    let gateway_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut gr, mut gw) = split_stream(stream);

        perform_gateway_handshake(&mut gr, &mut gw, |id, _pk| {
            assert_eq!(id, "signal");
            Ok(())
        })
        .await
        .unwrap();

        // Read any frames that show up; fail the test if any Inbound appears.
        // Heartbeats fire every 15s so they won't interfere in a short window.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return;
            }
            match tokio::time::timeout(remaining, gr.read_message()).await {
                Ok(Ok(msg)) => {
                    let fr = msg.get_root::<frame::Reader<'_>>().unwrap();
                    if let frame::Inbound(_) = fr.which().unwrap() {
                        panic!(
                            "gateway received an inbound frame from an unallowed sender — \
                             allowlist did NOT enforce"
                        );
                    }
                }
                Ok(Err(_)) | Err(_) => return,
            }
        }
    });

    // Allowlist contains only a number that is *not* the fake message's sender.
    let identity = AdapterIdentity::generate("signal");
    let allowlist = SignalAllowlist::from_csv("+15559999999").unwrap();
    let adapter = SignalAdapter::new(identity, endpoint, "+15551112222".to_string(), allowlist);
    let socket_path_for_adapter = socket_path.clone();
    let adapter_task = tokio::spawn(async move { adapter.run(&socket_path_for_adapter).await });

    // The gateway task returns after its deadline passes with no Inbound seen.
    gateway_task.await.expect("gateway task panicked");

    adapter_task.abort();
    http_task.abort();
}

// ---------------------------------------------------------------------------
// Vuln 11: allowlist normalization + parse-time rejection
// ---------------------------------------------------------------------------

use crate::convert::SignalAllowlistError;

#[test]
fn allowlist_normalizes_phone_formats_consistently() {
    // Entry written by the operator with human-friendly separators.
    let list = SignalAllowlist::from_csv("+1 (555) 123-4567").unwrap();
    // Runtime senders arriving in various signal-cli format variants
    // must all match the same canonical entry.
    for sender in [
        "+15551234567",
        "+1-555-123-4567",
        "+1 555 123 4567",
        "+1.555.123.4567",
        "+1 (555) 123-4567",
    ] {
        let msg = SignalInbound {
            message_id: "m".into(),
            sender: sender.into(),
            sender_name: "Op".into(),
            text: "hi".into(),
            timestamp: 0,
            group_id: None,
        };
        assert!(
            list.allows(&msg),
            "sender '{sender}' should match normalized allowlist entry"
        );
    }
}

#[test]
fn allowlist_rejects_phone_without_plus_at_parse_time() {
    // A phone-shaped entry missing the leading `+` is ambiguous
    // (country code unknown). Reject it at parse time so the
    // operator sees the error at startup.
    match SignalAllowlist::from_csv("15551234567") {
        Err(SignalAllowlistError::PhoneMissingPlus(_)) => {}
        other => panic!("expected PhoneMissingPlus, got {other:?}"),
    }
    match SignalAllowlist::from_csv("+15551234567, 14155550000") {
        Err(SignalAllowlistError::PhoneMissingPlus(_)) => {}
        other => panic!("expected PhoneMissingPlus on second entry, got {other:?}"),
    }
}

#[test]
fn allowlist_group_ids_are_a_separate_namespace() {
    // Group ids contain non-phone characters and bypass phone
    // normalization entirely. They are stored verbatim.
    let list = SignalAllowlist::from_csv("group.abcDEF123=,+15551234567").unwrap();
    assert_eq!(list.len(), 2);

    let group_msg = SignalInbound {
        message_id: "g".into(),
        sender: "+15550000000".into(),
        sender_name: "Alice".into(),
        text: "hi".into(),
        timestamp: 0,
        group_id: Some("group.abcDEF123=".into()),
    };
    assert!(list.allows(&group_msg));

    // A group id that looks nothing like the allowlist entry is rejected.
    let other_group = SignalInbound {
        message_id: "g2".into(),
        sender: "+15550000000".into(),
        sender_name: "Alice".into(),
        text: "hi".into(),
        timestamp: 0,
        group_id: Some("group.other=".into()),
    };
    assert!(!list.allows(&other_group));
}

#[test]
fn allowlist_runtime_sender_without_plus_is_rejected() {
    // If signal-cli ever hands us a sender without a leading `+`, we
    // cannot safely normalize it to match. Drop rather than match
    // loosely.
    let list = SignalAllowlist::from_csv("+15551234567").unwrap();
    let msg = SignalInbound {
        message_id: "m".into(),
        sender: "15551234567".into(),
        sender_name: "Op".into(),
        text: "hi".into(),
        timestamp: 0,
        group_id: None,
    };
    assert!(!list.allows(&msg));
}

#[test]
fn allowlist_empty_still_parses() {
    let list = SignalAllowlist::from_csv("").unwrap();
    assert!(list.is_empty());
    let list = SignalAllowlist::from_csv("  ,  , ").unwrap();
    assert!(list.is_empty());
}
