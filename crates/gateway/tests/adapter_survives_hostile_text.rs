//! What the evidence-window panic used to take down, and that it does
//! not any more.
//!
//! `InjectionDetector::scan` runs on every inbound channel message, in
//! `message_loop` (`crates/cli/src/commands/run.rs`), inside the task
//! `handle_adapter_connection` spawns per adapter connection. The
//! panic unwound that task, and the workspace builds with the default
//! `panic = "unwind"`, so tokio caught it at the task boundary: the
//! gateway process lived and one adapter's connection died. Four
//! things went with it, and the third and fourth are the reason this
//! is more than a dropped socket:
//!
//! 1. The connection, mid-loop. The adapter had to notice and
//!    reconnect.
//! 2. The message itself, unrecorded. `scan` runs before the
//!    `message.inbound` audit row is written, so the message that
//!    killed the connection left no trace in the chain.
//! 3. The cleanup after `message_loop` returns:
//!    `dispatcher.unregister`, `registry.set_connected(false)` and the
//!    `adapter.disconnect` audit row. An unwind runs none of them, so
//!    the registry went on reporting that adapter connected and the
//!    orchestrator's push dispatcher went on holding a writer for a
//!    dead socket. A daily digest routed to that channel wrote into
//!    nothing.
//! 4. Nothing else. Other adapters are separate tasks and were not
//!    affected, which is what made this quiet.
//!
//! The two tests below are the same harness. One runs the real
//! detector and shows the connection serving the message that used to
//! kill it and the one after; the other replaces the scan with a
//! panicking one and pins the four consequences above as fact rather
//! than as a claim in a commit message.
//!
//! The harness is the shape of `message_loop`, not the function
//! itself: that one is private to the CLI binary and needs an IPC
//! channel, an agent factory, an audit writer and a session store. The
//! shape is what the panic interacted with, and it is reproduced here
//! exactly: one spawned task per connection, a scan on each message
//! before it is recorded, and the cleanup after the loop.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Mutex;
use wirken_gateway::injection_detect::InjectionDetector;

/// What a connection reported, so a test can ask what survived.
#[derive(Default)]
struct ConnectionLog {
    /// Messages that reached the audit step, in order.
    recorded: Mutex<Vec<String>>,
    /// Set by the cleanup that runs after the message loop returns.
    cleaned_up: AtomicBool,
    /// Set while the loop is inside the scan, and cleared after, so a
    /// panicking scan leaves it set.
    still_registered: AtomicBool,
}

/// One adapter connection, spawned the way `handle_adapter_connection`
/// spawns one. `scan` stands in for `detector.scan(&text)` at
/// `run.rs:3166`; recording stands for the `message.inbound` audit row
/// written just after it; the tail stands for the unregister, the
/// disconnect row and `set_connected(false)`.
async fn connection<S>(log: Arc<ConnectionLog>, inbound: Vec<String>, scan: S)
where
    S: Fn(&str) + Send + 'static,
{
    log.still_registered.store(true, Ordering::SeqCst);
    tokio::spawn(async move {
        for text in inbound {
            scan(&text);
            log.recorded.lock().await.push(text);
        }
        // Everything an unwind skipped.
        log.still_registered.store(false, Ordering::SeqCst);
        log.cleaned_up.store(true, Ordering::SeqCst);
    })
    .await
    .ok();
}

/// The message that used to panic, byte for byte, as the fuzzer found
/// it and as `fuzz/artifacts/injection_scan/` keeps it.
fn hostile_message() -> String {
    let bytes = include_bytes!(
        "../../../fuzz/artifacts/injection_scan/crash-e962d9cd672bdc2be29d5d0ac53ddbdf5fd41148"
    );
    String::from_utf8_lossy(bytes).into_owned()
}

/// Today. The message arrives on one adapter, is scanned, and is
/// recorded; the next message on that same adapter is served; a
/// message on a second adapter is served. Both connections reach
/// their cleanup.
#[tokio::test]
async fn a_message_that_used_to_panic_leaves_both_adapters_serving() {
    let detector = Arc::new(InjectionDetector::new());

    let signal = Arc::new(ConnectionLog::default());
    let telegram = Arc::new(ConnectionLog::default());

    let d = detector.clone();
    let signal_run = connection(
        signal.clone(),
        vec![
            "what is the weather in london".to_string(),
            hostile_message(),
            "the next message on this adapter".to_string(),
        ],
        move |text| {
            // The return is deliberately unused: the gateway folds it
            // into the audit row and carries on either way. What is
            // being asserted is that the call returns at all.
            let _ = d.scan(text);
        },
    );

    let d = detector.clone();
    let telegram_run = connection(
        telegram.clone(),
        vec!["a message on another adapter".to_string()],
        move |text| {
            let _ = d.scan(text);
        },
    );

    tokio::join!(signal_run, telegram_run);

    let served = signal.recorded.lock().await.clone();
    assert_eq!(
        served.len(),
        3,
        "the hostile message and the one after it must both be served, got {served:?}"
    );
    assert_eq!(served[1], hostile_message());
    assert_eq!(served[2], "the next message on this adapter");
    assert!(
        signal.cleaned_up.load(Ordering::SeqCst),
        "the connection must reach its unregister and disconnect row"
    );
    assert!(
        !signal.still_registered.load(Ordering::SeqCst),
        "the adapter must not be left registered as connected"
    );

    let other = telegram.recorded.lock().await.clone();
    assert_eq!(other, vec!["a message on another adapter".to_string()]);
    assert!(telegram.cleaned_up.load(Ordering::SeqCst));
}

/// Yesterday, for comparison: the same harness with a scan that
/// panics on the same message. This is what the four consequences in
/// the module docs look like when they happen, and it is here so that
/// claim is checked rather than asserted.
#[tokio::test]
async fn a_panicking_scan_took_the_connection_and_its_cleanup_with_it() {
    let hostile = hostile_message();
    let signal = Arc::new(ConnectionLog::default());
    let telegram = Arc::new(ConnectionLog::default());

    let trigger = hostile.clone();
    let signal_run = connection(
        signal.clone(),
        vec![
            "what is the weather in london".to_string(),
            hostile.clone(),
            "the next message on this adapter".to_string(),
        ],
        move |text| {
            if text == trigger {
                panic!("end byte index is not a char boundary");
            }
        },
    );

    let telegram_run = connection(
        telegram.clone(),
        vec!["a message on another adapter".to_string()],
        |_text| {},
    );

    tokio::join!(signal_run, telegram_run);

    let served = signal.recorded.lock().await.clone();
    assert_eq!(
        served,
        vec!["what is the weather in london".to_string()],
        "only the messages before the hostile one were served"
    );
    assert!(
        !signal.cleaned_up.load(Ordering::SeqCst),
        "the unwind skipped the unregister and the disconnect row"
    );
    assert!(
        signal.still_registered.load(Ordering::SeqCst),
        "the adapter was left registered as connected on a dead socket"
    );

    let other = telegram.recorded.lock().await.clone();
    assert_eq!(
        other,
        vec!["a message on another adapter".to_string()],
        "the other adapter was never affected, which is what made this quiet"
    );
    assert!(telegram.cleaned_up.load(Ordering::SeqCst));
}
