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
//! It is also where a push waits for its delivery result. The pusher
//! registers the frame's outbound target with [`expect_delivery`]
//! before writing the frame; the per-adapter handler, on a verified
//! `OutboundResult` for that target, calls [`resolve_delivery`]; the
//! pusher's [`wait_for_delivery`] returns what came back, or
//! [`DeliveryStatus::Unknown`] when nothing did in time.
//!
//! [`writer_for`]: OutboundDispatcher::writer_for
//! [`expect_delivery`]: OutboundDispatcher::expect_delivery
//! [`resolve_delivery`]: OutboundDispatcher::resolve_delivery
//! [`wait_for_delivery`]: OutboundDispatcher::wait_for_delivery

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::oneshot;
use wirken_ipc::IpcFrameWriter;
use wirken_ipc::orchestrator::DeliveryStatus;

/// Map of channel → live capnp writer for the currently connected
/// adapter on that channel.
#[derive(Default)]
pub struct OutboundDispatcher {
    writers: Mutex<HashMap<String, Arc<AsyncMutex<IpcFrameWriter>>>>,
    /// Outbound target → the push waiting on that frame's result.
    pending: Mutex<HashMap<String, oneshot::Sender<DeliveryStatus>>>,
}

impl OutboundDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the live writer for a channel. If a writer is already
    /// registered for that channel, replace it — last-connect wins,
    /// mirroring the in-memory adapter-registry connected-flag
    /// semantics.
    pub fn register(&self, channel: &str, writer: Arc<AsyncMutex<IpcFrameWriter>>) {
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
    pub fn writer_for(&self, channel: &str) -> Option<Arc<AsyncMutex<IpcFrameWriter>>> {
        self.writers.lock().unwrap().get(channel).cloned()
    }

    /// Wait on the delivery result for the frame sent as `target`.
    /// Called before the frame is written, so a result that comes
    /// back at once still finds its waiter.
    pub fn expect_delivery(&self, target: &str) -> oneshot::Receiver<DeliveryStatus> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(target.to_string(), tx);
        rx
    }

    /// Hand a delivery result to the push waiting on `target`. `false`
    /// when none is: the frame was an agent reply, or its push already
    /// stopped waiting.
    pub fn resolve_delivery(&self, target: &str, status: DeliveryStatus) -> bool {
        match self.pending.lock().unwrap().remove(target) {
            Some(tx) => tx.send(status).is_ok(),
            None => false,
        }
    }

    /// Stop waiting on `target`, as when its frame was never written.
    pub fn forget_delivery(&self, target: &str) {
        self.pending.lock().unwrap().remove(target);
    }

    /// The result for `target` within `timeout`, or
    /// [`DeliveryStatus::Unknown`] when none came.
    pub async fn wait_for_delivery(
        &self,
        target: &str,
        rx: oneshot::Receiver<DeliveryStatus>,
        timeout: Duration,
    ) -> DeliveryStatus {
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(status)) => status,
            Ok(Err(_)) | Err(_) => {
                self.forget_delivery(target);
                DeliveryStatus::Unknown
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirken_ipc::{IpcFrameWriter, split_stream, test_pair};

    async fn make_writer() -> Arc<AsyncMutex<IpcFrameWriter>> {
        let (a, _b) = test_pair().unwrap();
        let (_r, w) = split_stream(a);
        Arc::new(AsyncMutex::new(w))
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
    async fn a_resolved_delivery_reaches_its_waiter() {
        let d = OutboundDispatcher::new();
        let rx = d.expect_delivery("slack:out:a");
        assert!(d.resolve_delivery(
            "slack:out:a",
            DeliveryStatus::Failed {
                error: "channel_not_found".into()
            }
        ));
        let got = d
            .wait_for_delivery("slack:out:a", rx, Duration::from_secs(5))
            .await;
        assert_eq!(
            got,
            DeliveryStatus::Failed {
                error: "channel_not_found".into()
            }
        );
    }

    #[tokio::test]
    async fn a_result_for_another_frame_does_not_resolve_the_wait() {
        let d = OutboundDispatcher::new();
        let rx = d.expect_delivery("slack:out:a");
        assert!(!d.resolve_delivery(
            "slack:out:b",
            DeliveryStatus::Delivered {
                message_id: "m".into()
            }
        ));
        let got = d
            .wait_for_delivery("slack:out:a", rx, Duration::from_millis(50))
            .await;
        assert_eq!(got, DeliveryStatus::Unknown);
    }

    #[tokio::test]
    async fn a_wait_that_times_out_is_unknown_and_forgotten() {
        let d = OutboundDispatcher::new();
        let rx = d.expect_delivery("slack:out:a");
        let got = d
            .wait_for_delivery("slack:out:a", rx, Duration::from_millis(20))
            .await;
        assert_eq!(got, DeliveryStatus::Unknown);
        assert!(
            !d.resolve_delivery(
                "slack:out:a",
                DeliveryStatus::Delivered {
                    message_id: "late".into()
                }
            ),
            "a late result finds no waiter"
        );
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
