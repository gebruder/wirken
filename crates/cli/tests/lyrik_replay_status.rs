//! `lyrik.replay.completed` says what the replay's run showed, read
//! off the chain, and not what the replay wrote about it: a replay
//! whose command is not on the chain is `blocked`, whatever its record
//! says, and the record is carried as its claim.
//!
//! Driven through the binary with a scripted model: one walk writes
//! one reproduction record, and the replay of it writes its own.

mod common;

use std::path::Path;

use common::{ScriptedModel, wirken};

const RUN: &str = "replay-status";

fn call(name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args}}],
    })
}

fn write(path: String, content: serde_json::Value) -> serde_json::Value {
    call(
        "write_file",
        serde_json::json!({"path": path, "content": content.to_string()}),
    )
}

/// Run one walk that records a reproduction, then its replay, which
/// writes `replay` when there is one. Returns the replay's completion
/// row.
fn replay_completed(replay: Option<serde_json::Value>) -> serde_json::Value {
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    let walk = data.join("lyrik/walks/sink-walk");
    std::fs::create_dir_all(&walk).unwrap();
    std::fs::write(
        walk.join("SKILL.md"),
        "---\nname: sink-walk\ndescription: test walk\n---\n\n# sink-walk\n",
    )
    .unwrap();
    let staging = format!(".lyrik/state/runs/{RUN}/staging/sink-walk");
    let command = format!("sh {staging}/harness/h.sh");
    let mut replies = vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        // The walk: a reproduction record.
        write(
            format!("{staging}/reproductions/repro-001.json"),
            serde_json::json!({
                "stable_id": "auth::src/auth.c:1",
                "command": command,
                "expected": "LYRIK_REACHED on stdout",
                "observed": "LYRIK_REACHED",
                "outcome": "reproduced",
                "code_revision": "unknown",
            }),
        ),
        serde_json::json!({"role": "assistant", "content": "Done."}),
    ];
    // The replay.
    if let Some(record) = replay {
        replies.push(write(format!("{staging}/replays/replay-001.json"), record));
    }
    replies.push(serde_json::json!({"role": "assistant", "content": "Done."}));
    let model = ScriptedModel::start(replies);

    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
    let pin = serde_json::json!({
        "provider": "ollama", "model": "scripted", "base_url": model.base_url,
    });
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
    std::fs::write(
        common::lyrik_config(&data, &target),
        serde_json::json!({"phases": {"framing": pin}, "walks": ["sink-walk"]}).to_string(),
    )
    .unwrap();
    let out = wirken(&data)
        .env("HOME", &home)
        .args(["lyrik", "run", "--bench", "--target"])
        .arg(&target)
        .args(["--run", RUN])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    completed(&target)
}

fn completed(target: &Path) -> serde_json::Value {
    let audit =
        std::fs::read_to_string(target.join(format!(".lyrik/state/runs/{RUN}/audit.log"))).unwrap();
    audit
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|e| e["event"] == "lyrik.replay.completed")
        .unwrap_or_else(|| panic!("no lyrik.replay.completed row:\n{audit}"))["detail"]
        .clone()
}

/// A replay's status is what the chain recorded its run of the
/// command showing. Here no replay ran anything: whatever each wrote
/// in its record, the command is not on the chain, so the status is
/// `blocked` and the record is carried as the replay's claim.
#[test]
fn a_replays_word_is_not_its_status() {
    for claimed in ["reproduced", "not_reproduced", "blocked"] {
        let row = replay_completed(Some(serde_json::json!({
            "command_run": "sh harness/h.sh",
            "observed": "LYRIK_REACHED; exit status 1",
            "outcome": claimed,
        })));
        assert_eq!(row["status"], "blocked", "{claimed}: {row}");
        assert_eq!(row["claimed"]["outcome"], claimed, "{row}");
        assert_eq!(
            row["claimed"]["observed"], "LYRIK_REACHED; exit status 1",
            "{row}"
        );
        // Nothing ran, so there is no recorded output to show.
        assert!(row["observed"].is_null(), "{row}");
        assert!(
            row["reason"]
                .as_str()
                .is_some_and(|r| r.contains("no `exec` call of the command")),
            "{row}"
        );
        assert_eq!(row["file"], "repro-001.json", "{row}");
        assert_eq!(row["walk"], "sink-walk", "{row}");
    }
}

/// A replay that wrote nothing is the same: nothing ran.
#[test]
fn a_replay_that_recorded_nothing_ran_nothing() {
    let row = replay_completed(None);
    assert_eq!(row["status"], "blocked", "{row}");
    assert!(row["claimed"].is_null(), "{row}");
}
