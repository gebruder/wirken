//! Live-writer registry for orchestrator push.
//!
//! The adapter ↔ gateway capnp connection is created in the gateway's
//! per-adapter handler; the [`FrameWriter`] half lives only inside
//! that task. Orchestrator-side push (e.g. zirkel daily digest) needs
//! to find the writer for a given channel and forward an `Outbound`
//! frame to it. This dispatcher is the rendezvous: the per-adapter
//! handler `register`s on auth, the orchestrator listener reads the
//! writer via [`writer_for`], and the per-adapter handler
//! `unregister`s on disconnect.
//!
//! Keyed by channel name. Today's gateway routes 1:1 between adapter
//! and channel (one Slack adapter, one Telegram adapter, one Signal
//! adapter), so the channel name is a sufficient discriminator. If
//! that ever changes — multiple adapters per channel — this becomes
//! a `(channel, adapter_id)` key and the orchestrator picks one.
//!
//! [`writer_for`]: OutboundDispatcher::writer_for

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Mutex as AsyncMutex;
use wirken_ipc::transport::FrameWriter;

/// Map of channel → live capnp writer for the currently connected
/// adapter on that channel.
#[derive(Default)]
pub struct OutboundDispatcher {
    writers: Mutex<HashMap<String, Arc<AsyncMutex<FrameWriter>>>>,
}

impl OutboundDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the live writer for a channel. If a writer is already
    /// registered for that channel, replace it — last-connect wins,
    /// mirroring the in-memory adapter-registry connected-flag
    /// semantics.
    pub fn register(&self, channel: &str, writer: Arc<AsyncMutex<FrameWriter>>) {
        self.writers
            .lock()
            .unwrap()
            .insert(channel.to_string(), writer);
    }

    /// Unregister the writer for a channel. Idempotent.
    pub fn unregister(&self, channel: &str) {
        self.writers.lock().unwrap().remove(channel);
    }

    /// Look up the live writer for a channel. `None` if no adapter is
    /// currently connected on that channel.
    pub fn writer_for(&self, channel: &str) -> Option<Arc<AsyncMutex<FrameWriter>>> {
        self.writers.lock().unwrap().get(channel).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixStream;

    async fn make_writer() -> Arc<AsyncMutex<FrameWriter>> {
        let (a, _b) = UnixStream::pair().unwrap();
        let (_r, w) = a.into_split();
        Arc::new(AsyncMutex::new(FrameWriter::new(w)))
    }

    #[tokio::test]
    async fn register_and_lookup() {
        let d = OutboundDispatcher::new();
        let w = make_writer().await;
        d.register("signal", w.clone());
        let got = d.writer_for("signal").expect("writer present");
        assert!(Arc::ptr_eq(&got, &w));
    }

    #[tokio::test]
    async fn unregister_removes_writer() {
        let d = OutboundDispatcher::new();
        d.register("signal", make_writer().await);
        d.unregister("signal");
        assert!(d.writer_for("signal").is_none());
    }

    #[tokio::test]
    async fn lookup_for_unconnected_channel_is_none() {
        let d = OutboundDispatcher::new();
        assert!(d.writer_for("nope").is_none());
    }

    #[tokio::test]
    async fn second_register_replaces_first() {
        let d = OutboundDispatcher::new();
        let w1 = make_writer().await;
        let w2 = make_writer().await;
        d.register("signal", w1.clone());
        d.register("signal", w2.clone());
        let got = d.writer_for("signal").unwrap();
        assert!(Arc::ptr_eq(&got, &w2));
        assert!(!Arc::ptr_eq(&got, &w1));
    }
}
