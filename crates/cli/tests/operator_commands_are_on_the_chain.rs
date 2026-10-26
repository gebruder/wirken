//! An authority-changing command run from the CLI leaves an
//! `operator_command` row on the `gateway-operator` lane, sealed by a
//! chain head, naming the OS account it ran as rather than `$USER`.
#![cfg(unix)]

mod common;

use common::wirken;
use wirken_audit::{OPERATOR_COMMANDS_SESSION, SessionEvent, SessionId, SessionLog};

const VAULT_PASSPHRASE: &str = "test-passphrase";

fn run(data: &std::path::Path, args: &[&str], stdin: Option<&str>) {
    use std::io::Write;
    let mut cmd = wirken(data);
    cmd.args(args)
        .env("USER", "someone-else")
        .env("USERNAME", "someone-else")
        .env("WIRKEN_VAULT_PASSPHRASE", VAULT_PASSPHRASE)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    let mut child = cmd.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "wirken {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("could not be written"),
        "wirken {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn credential_and_hook_commands_are_recorded_with_the_uid() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();
    let key = "11".repeat(32);

    run(
        data,
        &[
            "credentials",
            "add",
            "records-api",
            "--stdin",
            "--host",
            "records.example.org",
        ],
        Some("not-a-real-value\n"),
    );
    run(
        data,
        &["credentials", "rotate", "records-api", "--stdin"],
        Some("still-not-a-real-value\n"),
    );
    run(data, &["credentials", "remove", "records-api"], None);
    run(
        data,
        &["hooks", "register", "watcher", &key, "--type", "observe"],
        None,
    );
    run(data, &["hooks", "unregister", "watcher"], None);

    let log = wirken_audit::SqliteSessionLog::open(&data.join("audit.db")).unwrap();
    let handle = log.handle_for(SessionId::new(OPERATOR_COMMANDS_SESSION.to_string()));
    let rows = log.get_since(&handle, 0).unwrap();
    let commands: Vec<(String, String, String, String)> = rows
        .iter()
        .filter_map(|r| match &r.event {
            SessionEvent::OperatorCommand {
                command,
                target,
                detail,
                run_by,
            } => Some((
                command.clone(),
                target.clone(),
                detail.clone(),
                run_by.clone(),
            )),
            _ => None,
        })
        .collect();
    let names: Vec<(&str, &str)> = commands
        .iter()
        .map(|(c, t, _, _)| (c.as_str(), t.as_str()))
        .collect();
    assert_eq!(
        names,
        vec![
            ("credentials add", "records-api"),
            ("credentials rotate", "records-api"),
            ("credentials remove", "records-api"),
            ("hooks register", "watcher"),
            ("hooks unregister", "watcher"),
        ]
    );
    // SAFETY: getuid(2) cannot fail.
    let uid = unsafe { libc::getuid() };
    for (command, _, detail, run_by) in &commands {
        assert!(
            run_by.starts_with(&format!("uid:{uid}")),
            "{command}: {run_by}"
        );
        assert!(!run_by.contains("someone-else"), "{command}: {run_by}");
        assert!(!detail.contains("not-a-real-value"), "{command}: {detail}");
    }
    assert!(
        commands[0].2.contains("host records.example.org"),
        "{:?}",
        commands[0]
    );
    assert!(
        commands[3].2.starts_with("observe; key 1111"),
        "{:?}",
        commands[3]
    );
    // Each command sealed the lane behind its row.
    let heads = rows
        .iter()
        .filter(|r| {
            matches!(
                r.event,
                SessionEvent::ChainHead {
                    reason: wirken_audit::ChainHeadReason::SessionEnd,
                    ..
                }
            )
        })
        .count();
    assert_eq!(heads, commands.len());
}
