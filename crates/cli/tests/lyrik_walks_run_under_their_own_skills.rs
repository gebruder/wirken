//! A `wirken lyrik run` walk runs under the run's own skills, and a
//! refused call skips a step rather than ending the run.
//!
//! Driven through the binary: a target with one walk selected, a
//! scripted model making the calls a walk would, and a shared skills
//! directory holding a skill that grants writes across the whole
//! workspace. The run's agents never attach it.

mod common;

use std::path::Path;

use common::{ScriptedModel, wirken, write_skill};

const RUN: &str = "refusals";

fn call(name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args}}],
    })
}

fn write_target(target: &Path, model: &ScriptedModel) {
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
    let pin = serde_json::json!({
        "provider": "ollama", "model": "scripted", "base_url": model.base_url, "temperature": 0.0,
    });
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(
        target.join(".lyrik/config.json"),
        serde_json::json!({
            "bench_mode": true,
            "scope": {"include": ["src/**/*"], "exclude": []},
            "phases": {
                "articulate": pin, "rubric": pin, "recon": pin,
                "framing": pin, "score": pin, "exploit": pin,
            },
            "walks": ["sink-walk"],
        })
        .to_string(),
    )
    .unwrap();
}

#[test]
fn a_refused_exec_is_skipped_and_writes_stay_under_lyrik() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    // The walk body, where `lyrik` reads walks from.
    let walk = home.join(".claude/skills/sink-walk");
    std::fs::create_dir_all(&walk).unwrap();
    std::fs::write(
        walk.join("SKILL.md"),
        "---\nname: sink-walk\ndescription: test walk\n---\n\n# sink-walk\n\nWalk sinks.\n",
    )
    .unwrap();
    // A shared skill granting workspace-wide writes, as `notes` does.
    write_skill(
        &data.join("skills/notes"),
        "notes",
        &["write_file"],
        "Writes anywhere in the workspace.",
    );
    std::fs::write(
        data.join("skills/notes/SKILL.md"),
        std::fs::read_to_string(data.join("skills/notes/SKILL.md"))
            .unwrap()
            .replace(
                "  inference:",
                "    write_paths: [\"<workspace>\"]\n  inference:",
            ),
    )
    .unwrap();
    for stale in ["SKILL.sig", "SKILL.pub"] {
        std::fs::remove_file(data.join("skills/notes").join(stale)).unwrap();
    }
    wirken_agent::bundled_skills::self_sign_skill_dir(&data.join("skills/notes")).unwrap();

    let finding = format!(".lyrik/state/runs/{RUN}/staging/sink-walk/findings/finding-001.json");
    let model = ScriptedModel::start(vec![
        // The preflight probe.
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        // The walk: an exec the gate refuses, a write outside `.lyrik`,
        // a staged finding, a reply.
        call(
            "exec",
            serde_json::json!({"command": "git log -p -- src/auth.c"}),
        ),
        call(
            "write_file",
            serde_json::json!({"path": "PROMOTED.md", "content": "outside"}),
        ),
        call(
            "write_file",
            serde_json::json!({"path": finding, "content": "{}"}),
        ),
        serde_json::json!({"role": "assistant", "content": "Done."}),
    ]);
    write_target(&target, &model);

    let out = wirken(&data)
        .env("HOME", &home)
        .args(["lyrik", "run", "--target"])
        .arg(&target)
        .args(["--run", RUN])
        .output()
        .unwrap();
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "a refused exec must not fail the run: {report}"
    );

    // The walk reports the step it skipped, and completed.
    let audit =
        std::fs::read_to_string(target.join(format!(".lyrik/state/runs/{RUN}/audit.log"))).unwrap();
    // The dispatch row keeps its keys: where the run's skills come
    // from, how many it attached, and which.
    let dispatch: serde_json::Value = audit
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|e| e["event"] == "lyrik.dispatch.started")
        .unwrap_or_else(|| panic!("no dispatch.started row:\n{audit}"));
    assert!(
        dispatch["detail"]["skills_dir"]
            .as_str()
            .is_some_and(|d| d.ends_with("lyrik-skill")),
        "{dispatch}"
    );
    assert_eq!(dispatch["detail"]["skills_loaded"], 2, "{dispatch}");
    assert_eq!(
        dispatch["detail"]["skills_attached"],
        serde_json::json!(["lyrik", "sink-walk"]),
        "{dispatch}"
    );
    let completed: serde_json::Value = audit
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|e| e["event"] == "lyrik.walk.completed")
        .unwrap_or_else(|| panic!("no walk.completed row:\n{audit}"));
    assert_eq!(completed["detail"]["status"], "success", "{completed}");
    assert_eq!(
        completed["detail"]["skipped"],
        serde_json::json!(["exec (shell:git)"]),
        "{completed}"
    );

    // Own skills only: the shared skill's workspace-wide grant is not
    // the run's, so the write outside `.lyrik` was refused, and the
    // staged finding went through.
    assert!(!target.join("PROMOTED.md").exists());
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    let writes: Vec<(String, bool)> = db
        .prepare(
            "SELECT json_extract(payload, '$.output'), json_extract(payload, '$.success')
               FROM session_events
              WHERE json_extract(payload, '$.kind') = 'tool_result'
                AND json_extract(payload, '$.tool_name') = 'write_file'
              ORDER BY seq",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(writes.len(), 2, "{writes:?}");
    assert!(
        !writes[0].1 && writes[0].0.contains("PROMOTED.md"),
        "{writes:?}"
    );
    assert!(
        writes[1].1 && writes[1].0.contains("finding-001.json"),
        "{writes:?}"
    );

    // The refusal is on the chain.
    let denied: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM session_events
              WHERE json_extract(payload, '$.kind') = 'permission_denied'
                AND json_extract(payload, '$.tool') = 'exec'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(denied, 1);
}
