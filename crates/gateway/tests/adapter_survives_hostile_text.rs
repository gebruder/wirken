//! What a detector panic used to take down, and that none of it
//! happens any more.
//!
//! `InjectionDetector::scan` runs on every inbound channel message, in
//! `message_loop` (`crates/cli/src/commands/run.rs`), inside the task
//! `handle_adapter_connection` spawns per adapter connection. The
//! workspace builds with the default `panic = "unwind"`, so tokio
//! caught a panic there at the task boundary: the gateway process
//! lived and one adapter's connection died. Four things went with it:
//!
//! 1. The connection, mid-loop. The adapter had to notice and
//!    reconnect.
//! 2. The message itself, unrecorded. `scan` ran before the
//!    `message.inbound` audit row was written, so the message that
//!    killed the connection left no trace in the chain.
//! 3. The cleanup after `message_loop` returns:
//!    `dispatcher.unregister`, `registry.set_connected(false)` and the
//!    `adapter.disconnect` row. An unwind ran none of them, so the
//!    registry went on reporting that adapter connected and the
//!    orchestrator's push dispatcher went on holding a writer for a
//!    dead socket. A digest routed to that channel wrote into nothing.
//! 4. Nothing else. Other adapters are separate tasks and were not
//!    affected, which is what made this quiet.
//!
//! Two changes close the first three. The scan is wrapped, so it
//! returns whatever the detector does: the loop carries on (1), the
//! `message.inbound` row written after it is written either way and
//! carries the verdict (2), and a panic becomes a
//! `message.threat_flagged` row naming it while the message proceeds
//! as detection-only always did. The teardown moved into a drop guard,
//! so it runs on both paths (3). The fourth stays true and is asserted
//! so that the containment is a fact rather than a leftover.
//!
//! Note which change closes (2). Writing the row first would also have
//! done it, and would have cost the row its shape: `detail.threat` is
//! what every consumer of `message.inbound` reads. The catch keeps
//! both.
//!
//! The harness is the shape of `message_loop`, not the function
//! itself: that one is private to the CLI binary and needs an IPC
//! channel, an agent factory, an audit writer and a session store. The
//! shape is what the panic interacted with, and it is reproduced here
//! exactly: one spawned task per connection, the scan caught, the
//! inbound row written after it carrying the verdict, a threat row on
//! a finding or a failure, and the teardown owned by a guard rather
//! than by the code after the loop.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use wirken_gateway::injection_detect::InjectionDetector;

/// One audit row, reduced to what these tests ask about.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    action: String,
    /// The message body the row carries, or the panic reason for a
    /// row raised by a failed scan.
    detail: String,
}

/// What a connection reported, so a test can ask what survived.
#[derive(Default)]
struct ConnectionLog {
    /// Audit rows in the order they were written. A `std` mutex, not
    /// a tokio one, so the scan closure can read the chain as it
    /// stands at the moment it is called.
    rows: std::sync::Mutex<Vec<Row>>,
    /// Set by the teardown guard when it runs.
    cleaned_up: AtomicBool,
    /// Set while the connection is live and cleared by the teardown,
    /// so a skipped teardown leaves it set.
    still_registered: AtomicBool,
}

impl ConnectionLog {
    fn push(&self, action: &str, detail: &str) {
        self.rows.lock().unwrap().push(Row {
            action: action.to_string(),
            detail: detail.to_string(),
        });
    }

    fn rows(&self) -> Vec<Row> {
        self.rows.lock().unwrap().clone()
    }

    fn actions(&self) -> Vec<String> {
        self.rows().into_iter().map(|r| r.action).collect()
    }

    /// The message bodies of the inbound rows, with the verdict each
    /// row carries beside its body stripped off.
    fn inbound_bodies(&self) -> Vec<String> {
        self.rows()
            .into_iter()
            .filter(|r| r.action == "message.inbound")
            .map(|r| match r.detail.split_once("|threat=") {
                Some((body, _)) => body.to_string(),
                None => r.detail,
            })
            .collect()
    }

    /// Whether the chain holds an inbound row for `text`. The row
    /// carries the scan's verdict beside the body, so a flagged
    /// message's row is the body followed by the finding.
    fn has_inbound(&self, text: &str) -> bool {
        self.rows()
            .iter()
            .any(|r| r.action == "message.inbound" && r.detail.starts_with(text))
    }
}

/// Stands for `ConnectionTeardown` in `run.rs`: the work that has to
/// happen on both exit paths, owned by a value rather than by the
/// statements after the loop.
struct Teardown(Arc<ConnectionLog>);

impl Drop for Teardown {
    fn drop(&mut self) {
        self.0.still_registered.store(false, Ordering::SeqCst);
        self.0.cleaned_up.store(true, Ordering::SeqCst);
    }
}

/// One adapter connection, spawned the way
/// `handle_adapter_connection` spawns one, in the order `message_loop`
/// now does the work: record, then scan, then a threat row if the scan
/// found something or failed.
async fn connection<S, A>(log: Arc<ConnectionLog>, inbound: Vec<String>, scan: S, after_scan: A)
where
    S: Fn(&str) -> Option<String> + Send + 'static,
    A: Fn(&str) + Send + 'static,
{
    log.still_registered.store(true, Ordering::SeqCst);
    tokio::spawn(async move {
        let _teardown = Teardown(log.clone());
        for text in inbound {
            // Detection is advisory, so a scanner that fails is the
            // same non-event as one that finds nothing, except that
            // the failure is named on the chain. Catching it is also
            // what lets the inbound row below be written after the
            // scan rather than before it.
            let finding = match std::panic::catch_unwind(AssertUnwindSafe(|| scan(&text))) {
                Ok(finding) => finding,
                Err(panic) => Some(
                    panic
                        .downcast_ref::<&'static str>()
                        .map(|s| (*s).to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "panic payload was not a string".to_string()),
                ),
            };
            if let Some(detail) = &finding {
                log.push("message.threat_flagged", detail);
            }

            // The inbound row, carrying the verdict the scan produced.
            log.push(
                "message.inbound",
                &match &finding {
                    Some(detail) => format!("{text}|threat={detail}"),
                    None => text.clone(),
                },
            );

            // The rest of the loop body: routing, session lookup, the
            // agent wake. Nothing here is caught, which is what the
            // teardown guard is for.
            after_scan(&text);
        }
    })
    .await
    .ok();
}

fn no_op(_text: &str) {}

/// The message that used to panic, byte for byte, as the fuzzer found
/// it and as `fuzz/artifacts/injection_scan/` keeps it.
fn hostile_message() -> String {
    let bytes = include_bytes!(
        "../../../fuzz/artifacts/injection_scan/crash-e962d9cd672bdc2be29d5d0ac53ddbdf5fd41148"
    );
    String::from_utf8_lossy(bytes).into_owned()
}

fn weather() -> String {
    "what is the weather in london".to_string()
}

fn next_message() -> String {
    "the next message on this adapter".to_string()
}

fn other_adapter_message() -> String {
    "a message on another adapter".to_string()
}

/// The real detector, on the message that used to kill the
/// connection. It returns, the message is recorded, the next message
/// on that adapter is served, a message on a second adapter is served,
/// and both connections reach their teardown.
#[tokio::test]
async fn a_message_that_used_to_panic_leaves_both_adapters_serving() {
    let detector = Arc::new(InjectionDetector::new());

    let signal = Arc::new(ConnectionLog::default());
    let telegram = Arc::new(ConnectionLog::default());

    let d = detector.clone();
    let signal_run = connection(
        signal.clone(),
        vec![weather(), hostile_message(), next_message()],
        move |text| d.scan(text).map(|t| t.to_detail_json().to_string()),
        no_op,
    );

    let d = detector.clone();
    let telegram_run = connection(
        telegram.clone(),
        vec![other_adapter_message()],
        move |text| d.scan(text).map(|t| t.to_detail_json().to_string()),
        no_op,
    );

    tokio::join!(signal_run, telegram_run);

    assert_eq!(
        signal.inbound_bodies(),
        vec![weather(), hostile_message(), next_message()],
        "the hostile message and the one after it must both be recorded"
    );
    assert!(signal.cleaned_up.load(Ordering::SeqCst));
    assert!(!signal.still_registered.load(Ordering::SeqCst));

    assert_eq!(telegram.inbound_bodies(), vec![other_adapter_message()]);
    assert!(telegram.cleaned_up.load(Ordering::SeqCst));
}

/// The same harness with a scan that still panics, which is the
/// question the fix has to answer: a detector can break again, on a
/// pattern nobody has fuzzed yet. Each of the four consequences is
/// asserted gone.
#[tokio::test]
async fn a_panicking_scan_costs_nothing_but_the_detection() {
    let hostile = hostile_message();
    let signal = Arc::new(ConnectionLog::default());
    let telegram = Arc::new(ConnectionLog::default());

    let trigger = hostile.clone();
    let scan_log = signal.clone();
    let signal_run = connection(
        signal.clone(),
        vec![weather(), hostile.clone(), next_message()],
        move |text| {
            // Asked from inside the scan, where the answer pins the
            // ordering: the row is written after this returns, so it
            // cannot be down yet. What makes that safe is that this
            // call always returns, which the panic below exercises.
            assert!(
                !scan_log.has_inbound(text),
                "the inbound row is written after the scan, so it cannot exist yet"
            );
            if text == trigger {
                panic!("end byte index is not a char boundary");
            }
            None
        },
        no_op,
    );

    let telegram_run = connection(
        telegram.clone(),
        vec![other_adapter_message()],
        |_text| None,
        no_op,
    );

    tokio::join!(signal_run, telegram_run);

    // 1. The connection was not taken down: the message after the
    //    panic was served.
    assert_eq!(
        signal.inbound_bodies(),
        vec![weather(), hostile.clone(), next_message()],
        "the loop must carry on past a panicking scan"
    );

    // 2. The message that broke the detector is on the chain. Its row
    //    is written after the scan, and the scan returns, so the write
    //    is reached. The row carries the failure beside the body, just
    //    as it would carry a finding.
    let rows = signal.rows();
    let hostile_row = rows
        .iter()
        .position(|r| r.action == "message.inbound" && r.detail.starts_with(&hostile))
        .expect("the message that broke the detector must be recorded");
    assert!(
        rows[hostile_row].detail.contains("char boundary"),
        "the inbound row must carry the verdict, got {:?}",
        rows[hostile_row].detail
    );

    // 3. The teardown ran, so nothing is left registered. Its
    //    independence from the catch is covered by
    //    `a_panic_outside_the_scan_still_runs_the_teardown`.
    assert!(
        signal.cleaned_up.load(Ordering::SeqCst),
        "the teardown must run on every exit path"
    );
    assert!(
        !signal.still_registered.load(Ordering::SeqCst),
        "the adapter must not be left registered as connected"
    );

    // The failure also raises its own row for SIEM visibility, beside
    // the inbound row rather than instead of it.
    let flagged = rows
        .get(hostile_row - 1)
        .expect("a row must precede the message that broke the detector");
    assert_eq!(flagged.action, "message.threat_flagged");
    assert!(
        flagged.detail.contains("char boundary"),
        "the row must name the panic, got {:?}",
        flagged.detail
    );

    // A clean scan raises no threat row, so the one above is
    // attributable to the failure and not to the harness flagging
    // everything.
    assert_eq!(
        signal
            .actions()
            .iter()
            .filter(|a| *a == "message.threat_flagged")
            .count(),
        1,
        "only the message that broke the detector is flagged"
    );

    // 4. Still true: the other adapter never noticed.
    assert_eq!(telegram.inbound_bodies(), vec![other_adapter_message()]);
    assert!(telegram.cleaned_up.load(Ordering::SeqCst));
}

/// The guard, on its own terms. The catch around the scan covers the
/// scan; it covers nothing else in the loop body, and a panic in the
/// routing or session work below it still unwinds the task. What
/// changed for that case is the teardown: it is owned by a value now,
/// so it runs on the way out.
///
/// Without this the teardown assertion in the test above is vacuous,
/// because nothing there unwinds far enough to skip it.
#[tokio::test]
async fn a_panic_outside_the_scan_still_runs_the_teardown() {
    let hostile = hostile_message();
    let signal = Arc::new(ConnectionLog::default());

    let trigger = hostile.clone();
    connection(
        signal.clone(),
        vec![weather(), hostile.clone(), next_message()],
        |_text| None,
        move |text| {
            if text == trigger {
                panic!("routing blew up after the scan");
            }
        },
    )
    .await;

    // The connection is gone: the guard is not a catch, and the
    // message after the panic was never served.
    assert_eq!(
        signal.inbound_bodies(),
        vec![weather(), hostile],
        "an uncaught panic still ends the loop"
    );

    // The teardown ran anyway, which is the whole of what the guard
    // buys: no adapter left registered on a dead socket, and a
    // disconnect row to pair with the connect row.
    assert!(
        signal.cleaned_up.load(Ordering::SeqCst),
        "the teardown must run even when the loop unwinds"
    );
    assert!(
        !signal.still_registered.load(Ordering::SeqCst),
        "the adapter must not be left registered as connected"
    );
}
