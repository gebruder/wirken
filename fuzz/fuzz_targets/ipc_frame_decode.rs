//! The Cap'n Proto frame decoder, fed what an adapter sends.
//!
//! An adapter is a separate process on the other end of a unix socket.
//! Everything it writes reaches the gateway through `FrameReader`:
//! a four-byte big-endian length, then a Cap'n Proto message. The
//! length is attacker-controlled, the message body is
//! attacker-controlled, and the decoder runs before any authentication
//! frame has been checked. That makes this the first parser a hostile
//! adapter reaches.
//!
//! The target asserts no panic, in the decoder and in the typed
//! accessors that follow it: reading a frame is not finished until the
//! fields have been walked, and a truncated or hostile pointer table
//! surfaces there rather than in `read_message`.
//!
//! A crash is a finding. Do not widen a limit to make a case pass.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wirken_ipc::transport::FrameReader;
use wirken_ipc::wirken_capnp::frame;

/// One current-thread runtime for the whole run. The decode future
/// resolves immediately against an in-memory reader, so there is
/// nothing to schedule; building a runtime per iteration would be most
/// of the cost of an iteration.
fn runtime() -> &'static tokio::runtime::Runtime {
    use std::sync::OnceLock;
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime")
    })
}

fuzz_target!(|data: &[u8]| {
    runtime().block_on(async move {
        let mut reader = FrameReader::new(data);

        // A short read is the ordinary end of a stream, so the loop
        // stops on the first error rather than treating it as a
        // finding. Several frames back to back is the realistic shape:
        // an adapter writes a handshake and then traffic.
        while let Ok(message) = reader.read_message().await {
            let Ok(root) = message.get_root::<frame::Reader<'_>>() else {
                continue;
            };

            // Walk the fields. `read_message` only validates the
            // segment table; a hostile far pointer or a list whose
            // declared length runs past its segment is caught here,
            // by the accessor, which is the code the gateway actually
            // runs on an inbound frame. The two variants below are the
            // ones an adapter reaches before the gateway trusts it:
            // the handshake response, and the first inbound message
            // after it.
            match root.which() {
                Ok(frame::AuthResponse(Ok(r))) => {
                    let _ = r.get_adapter_id().map(|t| t.len());
                    let _ = r.get_signature().map(|b| b.len());
                }
                Ok(frame::Inbound(Ok(m))) => {
                    let _ = m.get_id().map(|t| t.len());
                    let _ = m.get_sender_id().map(|t| t.len());
                    let _ = m.get_channel().map(|t| t.len());
                    let _ = m.get_conversation_id().map(|t| t.len());
                    let _ = m.get_text().map(|t| t.len());
                    let _ = m.get_timestamp();
                    let _ = m.get_is_group();
                }
                _ => {}
            }
        }
    });
});
