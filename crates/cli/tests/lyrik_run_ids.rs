//! `wirken lyrik run --run` keeps the run ids an operator would use, an
//! ISO timestamp and a spaced name among them, and refuses only what
//! could take the run's directory or write scope elsewhere.
//!
//! Driven through the binary with a scripted model. An accepted id
//! completes a run whose staged finding lands under its own directory,
//! while a write to a sibling whose name only extends the id is
//! refused. A refused id stops the run before anything is created.

mod common;

use std::path::Path;

use common::{ScriptedModel, wirken};

fn call(name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args}}],
    })
}

fn target(root: &Path) -> std::path::PathBuf {
    let target = root.join("target");
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
    target
}

fn accepted(run: &str) {
    let tmp = tempfile::tempdir().unwrap();
    let (home, data) = (tmp.path().join("home"), tmp.path().join("data"));
    std::fs::create_dir_all(&home).unwrap();
    let target = target(tmp.path());
    let sibling = format!(".lyrik/state/runs/{run}0/finding.json");
    let model = ScriptedModel::start(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        call(
            "write_file",
            serde_json::json!({"path": sibling, "content": "{}"}),
        ),
        call(
            "write_file",
            serde_json::json!({
                "path": format!(".lyrik/state/runs/{run}/staging/findings/finding-001.json"),
                "content": serde_json::json!({
                    "id": "F001",
                    "stable_id": "auth::src/auth.c:1",
                    "framing": ["auth"],
                    "location": {"file": "src/auth.c", "line_start": 1},
                    "title": "stub",
                    "summary": "stub",
                    "tier": "LOW",
                }).to_string(),
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
        .args(["--run", run])
        .output()
        .unwrap();
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{run:?}: {report}");

    let run_dir = target.join(".lyrik/state/runs").join(run);
    let body: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run_dir.join("findings.json")).unwrap())
            .unwrap();
    assert_eq!(body["run_id"], run);
    assert_eq!(body["funnel"]["merged"]["kept"], 1, "{body}");
    assert!(run_dir.join("audit.log").is_file());
    assert!(!target.join(&sibling).exists(), "{run:?}: sibling written");

    // On the chain under the run's session: the sibling write refused,
    // the staged finding written.
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    let writes: Vec<(String, bool)> = db
        .prepare(
            "SELECT json_extract(payload, '$.output'), json_extract(payload, '$.success')
               FROM session_events
              WHERE session_id = ?1
                AND json_extract(payload, '$.kind') = 'tool_result'
                AND json_extract(payload, '$.tool_name') = 'write_file'
              ORDER BY seq",
        )
        .unwrap()
        .query_map([format!("lyrik-{}", run.replace('/', "-"))], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(writes.len(), 2, "{run:?}: {writes:?}");
    assert!(!writes[0].1, "{run:?}: {writes:?}");
    assert!(writes[1].1, "{run:?}: {writes:?}");
}

#[cfg(not(windows))]
#[test]
fn an_iso_timestamp_run_id_completes_a_run() {
    accepted("2026-10-18T10:00:00Z");
}

#[test]
fn a_run_id_with_spaces_completes_a_run() {
    accepted("nightly run 1");
}

#[test]
fn unsafe_run_ids_are_refused_before_anything_is_created() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, data) = (tmp.path().join("home"), tmp.path().join("data"));
    std::fs::create_dir_all(&home).unwrap();
    let target = target(tmp.path());
    std::fs::write(
        target.join(".lyrik/config.json"),
        serde_json::json!({"bench_mode": true, "phases": {"framing": {
            "provider": "ollama", "model": "scripted", "base_url": "http://127.0.0.1:9",
        }}})
        .to_string(),
    )
    .unwrap();
    let outside = tmp.path().join("escape");
    for run in [
        "..",
        "../../../escape",
        outside.to_str().unwrap(),
        "a\"b",
        "a\\b",
        "a\tb",
        "a\u{7f}b",
    ] {
        let out = wirken(&data)
            .env("HOME", &home)
            .args(["lyrik", "run", "--target"])
            .arg(&target)
            .args(["--run", run])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{run:?} was accepted");
        assert!(err.contains("run id"), "{run:?}: {err}");
    }
    assert!(!target.join(".lyrik/state").exists());
    assert!(!outside.exists());
    assert!(!data.join("audit.db").exists());
}
