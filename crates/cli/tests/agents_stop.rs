//! `wirken agents stop` and `resume` with no gateway running: the state
//! lands in the permission store, the grants `--revoke-all` names go,
//! and each command is one sealed row on the operator lane.

mod common;

use std::path::Path;

use common::wirken;

fn run(data: &Path, args: &[&str]) -> (bool, String) {
    let out = wirken(data)
        .env_remove("WIRKEN_EXEC")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn stopped(data: &Path) -> Vec<String> {
    let db = rusqlite::Connection::open(data.join("permissions.db")).unwrap();
    db.prepare("SELECT agent_id FROM stopped_agents ORDER BY agent_id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn grants(data: &Path) -> i64 {
    let db = rusqlite::Connection::open(data.join("permissions.db")).unwrap();
    db.query_row("SELECT count(*) FROM approvals", [], |r| r.get(0))
        .unwrap()
}

/// `(kind, payload)` of each row on the operator lane, in order.
fn operator_rows(data: &Path) -> Vec<(String, serde_json::Value)> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.prepare(
        "SELECT json_extract(payload, '$.kind'), payload FROM session_events
          WHERE session_id = 'gateway-operator' ORDER BY seq",
    )
    .unwrap()
    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
    .unwrap()
    .map(|r| {
        let (kind, payload) = r.unwrap();
        (kind, serde_json::from_str(&payload).unwrap())
    })
    .collect()
}

#[cfg(not(windows))]
#[test]
fn stop_and_resume_hold_without_a_gateway_and_leave_sealed_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();

    let (ok, out) = run(
        data,
        &[
            "permissions",
            "approve",
            "shell:ls",
            "--channel",
            "telegram",
        ],
    );
    assert!(ok, "{out}");
    assert_eq!(grants(data), 1);

    let (ok, out) = run(data, &["agents", "stop", "default"]);
    assert!(ok, "{out}");
    assert!(out.contains("Agent 'default' stopped"), "{out}");
    assert_eq!(stopped(data), ["default"]);
    assert_eq!(
        grants(data),
        1,
        "a stop without --revoke-all keeps the grants"
    );

    let (ok, out) = run(data, &["agents", "stop", "default"]);
    assert!(ok, "{out}");
    assert!(out.contains("already stopped"), "{out}");

    let (ok, out) = run(data, &["agents", "stop", "default", "--revoke-all"]);
    assert!(ok, "{out}");
    assert!(out.contains("Removed 1 persisted grant"), "{out}");
    assert_eq!(grants(data), 0);

    let (ok, out) = run(data, &["agents", "resume", "default"]);
    assert!(ok, "{out}");
    assert!(stopped(data).is_empty());
    let (ok, out) = run(data, &["agents", "resume", "default"]);
    assert!(ok, "{out}");
    assert!(out.contains("is not stopped"), "{out}");

    // A socket a stopped gateway left behind is no gateway running.
    #[cfg(unix)]
    {
        let sockets = data.join("sockets");
        std::fs::create_dir_all(&sockets).unwrap();
        drop(
            std::os::unix::net::UnixListener::bind(sockets.join("gateway-permissions.sock"))
                .unwrap(),
        );
        let (ok, out) = run(data, &["agents", "stop", "default"]);
        assert!(ok, "{out}");
        assert!(out.contains("No gateway is running"), "{out}");
        let (ok, out) = run(data, &["agents", "resume", "default"]);
        assert!(ok, "{out}");
        assert!(out.contains("No gateway is running"), "{out}");
    }

    let (ok, out) = run(data, &["agents", "stop", "nobody"]);
    assert!(!ok, "{out}");
    assert!(stopped(data).is_empty());

    let rows = operator_rows(data);
    let kinds: Vec<&str> = rows
        .iter()
        .map(|(k, _)| k.as_str())
        .filter(|k| *k != "chain_head" && *k != "operator_command")
        .collect();
    let expected: &[&str] = if cfg!(unix) {
        &[
            "agent_stopped",
            "agent_stopped",
            "agent_resumed",
            "agent_stopped",
            "agent_resumed",
        ]
    } else {
        &["agent_stopped", "agent_stopped", "agent_resumed"]
    };
    assert_eq!(kinds, expected);
    let revoked: Vec<_> = rows
        .iter()
        .filter(|(k, _)| k == "agent_stopped")
        .map(|(_, p)| p["grants_revoked"].as_u64().unwrap())
        .collect();
    assert_eq!(revoked[..2], [0, 1]);
    assert_eq!(rows.last().unwrap().0, "chain_head", "the lane is sealed");
}

/// A gateway listening on the permissions socket: takes the operator
/// handshake, records one request and answers it. Returns what it saw.
#[cfg(unix)]
async fn fake_gateway(data: std::path::PathBuf) -> wirken_ipc::permissions::PermissionsRequest {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use wirken_ipc::operator::{OperatorKey, PERMISSIONS_SOCKET, handshake_as_gateway};
    use wirken_ipc::permissions::{PermissionsRequest, PermissionsResponse};

    let key = OperatorKey::load_or_create(&data).unwrap().verifying_key();
    let sockets = data.join("sockets");
    std::fs::create_dir_all(&sockets).unwrap();
    let listener =
        tokio::net::UnixListener::bind(sockets.join("gateway-permissions.sock")).unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    handshake_as_gateway(&mut reader, &mut writer, &key, PERMISSIONS_SOCKET)
        .await
        .unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let request: PermissionsRequest = serde_json::from_str(line.trim_end()).unwrap();
    let reply = serde_json::to_string(&PermissionsResponse::AgentStopped {
        approvals_denied: 0,
        turns_ended: 0,
        session_grants_cleared: 0,
        mcp_told: false,
    })
    .unwrap();
    writer.write_all(reply.as_bytes()).await.unwrap();
    writer.write_all(b"\n").await.unwrap();
    writer.shutdown().await.unwrap();
    request
}

/// The stop is persisted and the gateway is told before anything is
/// printed, so a stdout closed from the start changes neither.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_reaches_the_gateway_with_stdout_closed() {
    use std::process::Stdio;
    use wirken_ipc::permissions::PermissionsRequest;

    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().to_path_buf();
    let gateway = tokio::spawn(fake_gateway(data.clone()));
    // The listener is bound once the key file exists.
    while !data
        .join("sockets")
        .join("gateway-permissions.sock")
        .exists()
    {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let status = tokio::task::spawn_blocking(move || {
        let mut child = wirken(&data)
            .env_remove("WIRKEN_EXEC")
            .args(["agents", "stop", "default"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        child.wait().unwrap()
    })
    .await
    .unwrap();

    let seen = tokio::time::timeout(std::time::Duration::from_secs(10), gateway)
        .await
        .expect("the gateway was asked")
        .unwrap();
    assert!(
        matches!(seen, PermissionsRequest::AgentStop { ref agent_id, .. } if agent_id == "default"),
        "{seen:?}"
    );
    assert_eq!(stopped(tmp.path()), ["default"]);
    // The first line it prints finds stdout closed.
    assert_eq!(status.code(), Some(141), "{status:?}");
}
