//! A `wirken lyrik run` runs `exec` only in the sandbox. With sandbox
//! mode off, an approved command (`cargo test` running the target's
//! `build.rs`, say) would run on the host with the host's network, so
//! the run's agents are not given `exec`: a call to it is refused by
//! the tool gate, the refusal is on the signed chain, and the turn
//! carries on. With the sandbox on, `exec` is offered and goes to the
//! operator as before, refused here because stdin is not a terminal.
//!
//! Driven through the binary in single-call and walk mode, with a
//! scripted model.

mod common;

use std::path::Path;

use common::{ScriptedModel, offered_tools, wirken};

fn call(name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args}}],
    })
}

fn chain_rows(data: &Path, kind: &str) -> Vec<serde_json::Value> {
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    db.prepare(
        "SELECT payload FROM session_events
          WHERE json_extract(payload, '$.kind') = ?1
          ORDER BY seq",
    )
    .unwrap()
    .query_map([kind], |r| r.get::<_, String>(0))
    .unwrap()
    .map(|p| serde_json::from_str(&p.unwrap()).unwrap())
    .collect()
}

fn scenario(walk: bool, sandbox_off: bool) {
    let run = format!(
        "exec-{}-{}",
        if walk { "walk" } else { "single" },
        if sandbox_off { "off" } else { "on" }
    );
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&data).unwrap();
    if sandbox_off {
        std::fs::write(data.join("sandbox.json"), r#"{"mode":"off"}"#).unwrap();
    }
    if walk {
        let dir = data.join("lyrik/walks/sink-walk");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            "---\nname: sink-walk\ndescription: test walk\n---\n\n# sink-walk\n\nWalk sinks.\n",
        )
        .unwrap();
    }
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
    let staging = if walk { "staging/sink-walk" } else { "staging" };
    let model = ScriptedModel::start(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        call("exec", serde_json::json!({"command": "cargo test"})),
        call(
            "write_file",
            serde_json::json!({
                "path": format!(".lyrik/state/runs/{run}/{staging}/findings/finding-001.json"),
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
    let mut config = serde_json::json!({"bench_mode": true, "phases": {"framing": pin}});
    if walk {
        config["walks"] = serde_json::json!(["sink-walk"]);
    }
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(target.join(".lyrik/config.json"), config.to_string()).unwrap();

    let out = wirken(&data)
        .env("HOME", &home)
        .args(["lyrik", "run", "--target"])
        .arg(&target)
        .args(["--run", &run])
        .output()
        .unwrap();
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{report}");

    // Offered on every assessment turn exactly when the sandbox is on.
    let assessment: Vec<_> = model
        .received()
        .into_iter()
        .filter(|r| !offered_tools(&r.body).contains(&"probe_ping".to_string()))
        .collect();
    assert!(!assessment.is_empty());
    for r in &assessment {
        assert_eq!(
            offered_tools(&r.body).contains(&"exec".to_string()),
            !sandbox_off,
            "{}",
            r.body
        );
    }

    let gate: Vec<_> = chain_rows(&data, "skill_permission_denied")
        .into_iter()
        .filter(|r| r["requested"] == "exec")
        .collect();
    let operator: Vec<_> = chain_rows(&data, "permission_denied")
        .into_iter()
        .filter(|r| r["tool"] == "exec")
        .collect();
    if sandbox_off {
        // Refused by the tool gate, never put to the operator.
        assert_eq!(gate.len(), 1, "{report}");
        assert_eq!(gate[0]["axis"], "tools");
        assert!(operator.is_empty(), "{operator:?}");
    } else {
        // Unchanged: offered, then refused because no one can be asked.
        assert!(gate.is_empty(), "{gate:?}");
        assert_eq!(operator.len(), 1, "{report}");
    }
    let failed: Vec<_> = chain_rows(&data, "tool_result")
        .into_iter()
        .filter(|r| r["tool_name"] == "exec")
        .collect();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["success"], false);
    assert!(
        failed[0].get("sandbox").is_none_or(|s| s.is_null()),
        "{failed:?}"
    );

    // The step was skipped; the turn went on to stage its finding.
    let body: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(target.join(format!(".lyrik/state/runs/{run}/findings.json")))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["funnel"]["merged"]["kept"], 1, "{body}");
}

#[test]
fn single_call_exec_is_refused_with_the_sandbox_off() {
    scenario(false, true);
}

#[test]
fn walk_exec_is_refused_with_the_sandbox_off() {
    scenario(true, true);
}

#[test]
fn single_call_exec_is_unchanged_with_the_sandbox_on() {
    scenario(false, false);
}

#[test]
fn walk_exec_is_unchanged_with_the_sandbox_on() {
    scenario(true, false);
}
