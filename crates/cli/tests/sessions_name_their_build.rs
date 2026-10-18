//! Every session the binary opens names the build that opened it, on
//! its `SessionStart` chain head, so a chain segment can be attributed
//! to a build however that build was installed.
//!
//! Driven through the binary with a scripted model: a Lyrik bench run
//! opens a session, and its opening head is read back from the chain.

mod common;

use common::{ScriptedModel, wirken};

fn call(name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args}}],
    })
}

#[test]
fn a_sessions_opening_head_names_the_build() {
    const RUN: &str = "build-identity";
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(target.join("src/a.c"), "int a(void) { return 0; }\n").unwrap();
    let model = ScriptedModel::start(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        call(
            "write_file",
            serde_json::json!({
                "path": format!(".lyrik/state/runs/{RUN}/staging/findings/finding-001.json"),
                "content": "{}",
            }),
        ),
        serde_json::json!({"role": "assistant", "content": "Done."}),
    ]);
    let pin = serde_json::json!({
        "provider": "ollama", "model": "scripted", "base_url": model.base_url, "temperature": 0.0,
    });
    std::fs::write(
        target.join(".lyrik/config.json"),
        serde_json::json!({"bench_mode": true, "phases": {"framing": pin}}).to_string(),
    )
    .unwrap();
    let out = wirken(&data)
        .env("HOME", &home)
        .args(["lyrik", "run", "--target"])
        .arg(&target)
        .args(["--run", RUN])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");

    // `--version` prints `wirken <version> (<commit>[, dirty])`.
    let version_out = wirken(&data).arg("--version").output().unwrap();
    let first = String::from_utf8_lossy(&version_out.stdout)
        .lines()
        .next()
        .unwrap()
        .to_string();
    let commit = first
        .split('(')
        .nth(1)
        .unwrap()
        .trim_end_matches(')')
        .split(',')
        .next()
        .unwrap()
        .to_string();

    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    let builds: Vec<serde_json::Value> = db
        .prepare(
            "SELECT json_extract(payload, '$.build') FROM session_events
              WHERE session_id = ?1
                AND json_extract(payload, '$.kind') = 'chain_head'
                AND json_extract(payload, '$.reason') = 'session_start'",
        )
        .unwrap()
        .query_map([format!("lyrik-{RUN}")], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|b| serde_json::from_str(&b.unwrap()).unwrap())
        .collect();
    assert_eq!(builds.len(), 1, "one opening head: {builds:?}");
    assert_eq!(builds[0]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(builds[0]["commit"], commit.as_str());
    assert!(
        matches!(
            builds[0]["dirty"].as_str(),
            Some("clean" | "dirty" | "unknown")
        ),
        "{builds:?}"
    );
    // Later heads on the same session do not repeat it.
    let later: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM session_events
              WHERE session_id = ?1
                AND json_extract(payload, '$.kind') = 'chain_head'
                AND json_extract(payload, '$.reason') != 'session_start'
                AND json_extract(payload, '$.build') IS NOT NULL",
            [format!("lyrik-{RUN}")],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(later, 0);
}
