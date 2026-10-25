//! `wirken senders`, driven through the binary with stdin closed.

mod common;

use common::wirken;

fn run(data: &std::path::Path, args: &[&str], exec_marker: bool) -> (bool, String, String) {
    let mut cmd = wirken(data);
    cmd.arg("senders").args(args);
    if exec_marker {
        cmd.env("WIRKEN_EXEC", "1");
    } else {
        cmd.env_remove("WIRKEN_EXEC");
    }
    let out = cmd.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `(kind, channel, id, group)` of every allowlist row on the chain, in
/// order.
fn rows(data: &std::path::Path) -> Vec<(String, String, String, bool)> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.prepare(
        "SELECT json_extract(payload, '$.kind'), json_extract(payload, '$.channel'),
                json_extract(payload, '$.id'), json_extract(payload, '$.group')
           FROM session_events
          WHERE session_id = 'gateway-senders'
            AND json_extract(payload, '$.kind') IN ('inbound_sender_added', 'inbound_sender_removed')
          ORDER BY seq",
    )
    .unwrap()
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

fn sealed(data: &std::path::Path) -> bool {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    let last: String = db
        .query_row(
            "SELECT json_extract(payload, '$.kind') FROM session_events
              WHERE session_id = 'gateway-senders' ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    last == "chain_head"
}

#[cfg(not(windows))]
#[test]
fn add_and_remove_change_the_allowlist_and_leave_sealed_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();

    let (ok, out, err) = run(data, &["add", "telegram", "12345", "--label", "me"], false);
    assert!(ok, "{err}");
    assert!(out.contains("Admitted sender '12345' on telegram"), "{out}");
    let (ok, _, err) = run(data, &["add", "signal", "group-abc=", "--group"], false);
    assert!(ok, "{err}");
    assert!(sealed(data));

    let (ok, out, _) = run(data, &["list"], false);
    assert!(ok);
    assert!(
        out.contains("telegram") && out.contains("12345") && out.contains("me"),
        "{out}"
    );
    assert!(
        out.contains("signal") && out.contains("group") && out.contains("group-abc="),
        "{out}"
    );

    let (ok, out, _) = run(data, &["remove", "signal", "group-abc="], false);
    assert!(ok);
    assert!(out.contains("Pass --group"), "{out}");
    let (ok, out, err) = run(data, &["remove", "signal", "group-abc=", "--group"], false);
    assert!(ok, "{err}");
    assert!(
        out.contains("Removed group 'group-abc=' from signal"),
        "{out}"
    );
    assert!(sealed(data));

    assert_eq!(
        rows(data),
        vec![
            (
                "inbound_sender_added".into(),
                "telegram".into(),
                "12345".into(),
                false
            ),
            (
                "inbound_sender_added".into(),
                "signal".into(),
                "group-abc=".into(),
                true
            ),
            (
                "inbound_sender_removed".into(),
                "signal".into(),
                "group-abc=".into(),
                true
            ),
        ]
    );

    let (ok, out, _) = run(data, &["list", "signal"], false);
    assert!(ok);
    assert!(out.contains("every message on it is dropped"), "{out}");
}

#[cfg(not(windows))]
#[test]
fn a_negative_group_id_is_taken_as_it_is() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();
    let (ok, out, err) = run(
        data,
        &["add", "telegram", "-100123456789", "--group"],
        false,
    );
    assert!(ok, "{err}");
    assert!(out.contains("group '-100123456789'"), "{out}");
    let (ok, out, err) = run(
        data,
        &["remove", "telegram", "-100123456789", "--group"],
        false,
    );
    assert!(ok, "{err}");
    assert!(out.contains("Removed group '-100123456789'"), "{out}");
    assert_eq!(
        rows(data),
        vec![
            (
                "inbound_sender_added".into(),
                "telegram".into(),
                "-100123456789".into(),
                true
            ),
            (
                "inbound_sender_removed".into(),
                "telegram".into(),
                "-100123456789".into(),
                true
            ),
        ]
    );
}

#[cfg(not(windows))]
#[test]
fn an_unknown_channel_or_a_padded_id_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [
        &["add", "telegrm", "1"][..],
        &["add", "webchat", "1"][..],
        &["add", "terminal", "1"][..],
        &["add", "telegram", " 1"][..],
        &["add", "telegram", ""][..],
    ] {
        let (ok, _, err) = run(tmp.path(), args, false);
        assert!(!ok, "{args:?} was accepted");
        assert!(!err.is_empty(), "{args:?}");
    }
    // Refused before the chain was opened, and nobody admitted.
    assert!(!tmp.path().join("audit.db").exists());
    let (ok, out, _) = run(tmp.path(), &["list"], false);
    assert!(ok);
    assert!(out.contains("No senders admitted on any channel"), "{out}");
}

#[cfg(not(windows))]
#[test]
fn every_subcommand_refuses_inside_a_wirken_exec() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [
        &["add", "telegram", "1"][..],
        &["remove", "telegram", "1"][..],
        &["list"][..],
        &["refused"][..],
    ] {
        let (ok, _, err) = run(tmp.path(), args, true);
        assert!(!ok, "{args:?} ran inside an exec");
        assert!(err.contains("inside a Wirken exec"), "{args:?}: {err}");
    }
    assert!(!tmp.path().join("senders.db").exists());
    assert_eq!(refusals(tmp.path()), ["add", "remove", "list", "refused"]);
    assert!(sealed(tmp.path()));
    assert!(rows(tmp.path()).is_empty(), "nothing was added or removed");
}

/// The `invocation` of every `operator_command_refused` row for
/// `senders` with reason `inside_exec` on the lane, in order.
fn refusals(data: &std::path::Path) -> Vec<String> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.prepare(
        "SELECT json_extract(payload, '$.invocation')
           FROM session_events
          WHERE session_id = 'gateway-senders'
            AND json_extract(payload, '$.kind') = 'operator_command_refused'
            AND json_extract(payload, '$.command') = 'senders'
            AND json_extract(payload, '$.reason') = 'inside_exec'
          ORDER BY seq",
    )
    .unwrap()
    .query_map([], |r| r.get(0))
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

#[cfg(not(windows))]
#[test]
fn refused_lists_the_ids_the_gateway_dropped() {
    use wirken_audit::{SessionEvent, SessionId, SessionLog as _, SqliteSessionLog, TrustLevel};
    let tmp = tempfile::tempdir().unwrap();
    {
        let log = SqliteSessionLog::open(&tmp.path().join("audit.db")).unwrap();
        let lane = log.handle_for(SessionId::new(wirken_audit::INBOUND_SENDERS_SESSION));
        for (channel, sender) in [("telegram", "777"), ("slack", "U9"), ("telegram", "888")] {
            log.append(
                &lane,
                TrustLevel::System,
                SessionEvent::InboundSenderRefused {
                    channel: channel.into(),
                    adapter_id: channel.into(),
                    sender_id: sender.into(),
                    conversation_id: format!("c-{sender}"),
                    reason: wirken_audit::InboundRefusalReason::NotAllowed,
                    suppressed: 3,
                    suppressed_on_lane: 0,
                },
            )
            .unwrap();
        }
    }
    let (ok, out, err) = run(tmp.path(), &["refused", "telegram"], false);
    assert!(ok, "{err}");
    let newest = out.find("888").expect("888 listed");
    let older = out.find("777").expect("777 listed");
    assert!(newest < older, "newest first: {out}");
    assert!(
        out.contains("c-888") && out.contains("not_allowed"),
        "{out}"
    );
    assert!(!out.contains("U9"), "filtered to telegram: {out}");

    let (ok, out, _) = run(tmp.path(), &["refused", "-n", "1"], false);
    assert!(ok);
    assert!(out.contains("888") && !out.contains("777"), "{out}");
}
