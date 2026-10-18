//! `inference` on a `wirken lyrik run`'s findings.json says where the
//! code went, and it is read back from the run's signed chain: every
//! model call, the tool-call probe included, is an `LlmRequest` row
//! naming provider, model and request size.
//!
//! Driven through the binary twice under the same run id, with a
//! scripted model. Each run's `inference` matches its own rows and no
//! earlier run's.

mod common;

use std::path::Path;

use common::{ScriptedModel, wirken};

const RUN: &str = "inference";

fn call(name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args}}],
    })
}

/// The `llm_request` rows on the run's session after `after`, as
/// (provider, model, purpose, request_bytes).
fn requests(data: &Path, after: i64) -> Vec<(String, String, Option<String>, i64)> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.prepare(
        "SELECT json_extract(payload, '$.provider'), json_extract(payload, '$.model'),
                json_extract(payload, '$.purpose'), json_extract(payload, '$.request_bytes')
           FROM session_events
          WHERE session_id = ?1 AND seq > ?2
            AND json_extract(payload, '$.kind') = 'llm_request'
          ORDER BY seq",
    )
    .unwrap()
    .query_map(rusqlite::params![format!("lyrik-{RUN}"), after], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

fn last_seq(data: &Path) -> i64 {
    if !data.join("audit.db").exists() {
        return -1;
    }
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.query_row(
        "SELECT COALESCE(MAX(seq), -1) FROM session_events WHERE session_id = ?1",
        [format!("lyrik-{RUN}")],
        |r| r.get(0),
    )
    .unwrap()
}

/// One run: probe, a read, a staged finding, a reply.
fn run_once(home: &Path, data: &Path, target: &Path) -> (serde_json::Value, String) {
    let model = ScriptedModel::start(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        call("read_file", serde_json::json!({"path": "src/auth.c"})),
        call(
            "write_file",
            serde_json::json!({
                "path": format!(".lyrik/state/runs/{RUN}/staging/findings/finding-001.json"),
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
    let out = wirken(data)
        .env("HOME", home)
        .args(["lyrik", "run", "--target"])
        .arg(target)
        .args(["--run", RUN])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(target.join(format!(".lyrik/state/runs/{RUN}/findings.json")))
            .unwrap(),
    )
    .unwrap();
    // Four model calls: the probe and three assessment turns.
    assert_eq!(model.received().len(), 4);
    (body["inference"].clone(), stdout)
}

#[test]
fn inference_is_read_back_from_the_runs_own_chain_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();

    for _ in 0..2 {
        let before = last_seq(&data);
        let (inference, stdout) = run_once(&home, &data, &target);
        let rows = requests(&data, before);

        // Every call the model received is on the chain, the probe
        // marked as such, each with provider, model and a size.
        assert_eq!(rows.len(), 4, "{rows:?}");
        assert_eq!(rows[0].2.as_deref(), Some("tool_call_probe"));
        assert!(rows[1..].iter().all(|r| r.2.is_none()), "{rows:?}");
        assert!(
            rows.iter()
                .all(|r| r.0 == "ollama" && r.1 == "scripted" && r.3 > 0),
            "{rows:?}"
        );

        let bytes: i64 = rows.iter().map(|r| r.3).sum();
        assert_eq!(
            inference,
            serde_json::json!({
                "provider": "ollama",
                "model": "scripted",
                "calls": 4,
                "request_bytes": bytes,
            })
        );
        let printed = stdout
            .split_once("inference: ")
            .map(|(_, rest)| rest)
            .unwrap_or_else(|| panic!("no inference printed: {stdout}"));
        let printed: serde_json::Value = serde_json::Deserializer::from_str(printed)
            .into_iter::<serde_json::Value>()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(printed, inference);
    }
}
