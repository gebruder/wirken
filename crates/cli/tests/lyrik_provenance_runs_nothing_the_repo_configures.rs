//! A `wirken lyrik run` against a git target records the target's
//! HEAD and tracked-file state without running any program the target
//! repository configures.
//!
//! Driven through the binary: the target's `.git/config` sets
//! `core.fsmonitor` and a clean filter on every path to commands that
//! write marker files, and a tracked file is edited so `git status`
//! would re-read it through the filter. The run completes, the markers
//! stay absent, and findings.json and the SARIF report carry the
//! provenance. Afterwards a plain `git status` trips both markers, so
//! the trap was live.

mod common;

use std::path::Path;
use std::process::Command;

use common::{ScriptedModel, wirken};

const RUN: &str = "provenance";

fn call(name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args}}],
    })
}

/// Test-setup git, with the operator's global and system config kept
/// out of it.
fn setup_git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn provenance_is_recorded_and_no_repo_configured_program_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
    setup_git(&target, &["init", "-q"]);
    setup_git(&target, &["add", "-A"]);
    setup_git(&target, &["commit", "-q", "-m", "init"]);
    let head = setup_git(&target, &["rev-parse", "HEAD"]);

    // Arm the repo, then edit a tracked file so git would run the
    // clean filter on it.
    let fsmonitor_marker = tmp.path().join("fsmonitor-ran");
    let filter_marker = tmp.path().join("clean-filter-ran");
    setup_git(
        &target,
        &[
            "config",
            "core.fsmonitor",
            &format!("touch {}", fsmonitor_marker.display()),
        ],
    );
    setup_git(
        &target,
        &[
            "config",
            "filter.trap.clean",
            &format!("touch {}; cat", filter_marker.display()),
        ],
    );
    std::fs::write(target.join(".git/info/attributes"), "* filter=trap\n").unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 1; }\n").unwrap();

    let model = ScriptedModel::start(vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
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
        serde_json::json!({"role": "assistant", "content": "Findings emitted to staging."}),
    ]);
    let pin = serde_json::json!({
        "provider": "ollama", "model": "scripted", "base_url": model.base_url, "temperature": 0.0,
    });
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
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
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{report}");
    assert!(!fsmonitor_marker.exists(), "fsmonitor ran: {report}");
    assert!(!filter_marker.exists(), "clean filter ran: {report}");

    let findings = target.join(format!(".lyrik/state/runs/{RUN}/findings.json"));
    let body: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&findings).unwrap()).unwrap();
    assert_eq!(body["target_sha"], head.as_str(), "{body}");
    assert_eq!(body["target_dirty"], true, "{body}");
    assert_eq!(
        body["audit_log_ref"],
        format!(".lyrik/state/runs/{RUN}/audit.log")
    );

    let sarif_path = tmp.path().join("findings.sarif");
    let out = wirken(&data)
        .args(["lyrik", "report", "--findings"])
        .arg(&findings)
        .arg("--output")
        .arg(&sarif_path)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
    let props = &sarif["runs"][0]["invocations"][0]["properties"]["lyrik"];
    assert_eq!(props["target_sha"], head.as_str(), "{props}");
    assert_eq!(props["target_dirty"], true, "{props}");
    assert_eq!(
        props["audit_log_ref"],
        format!(".lyrik/state/runs/{RUN}/audit.log")
    );
    assert!(!fsmonitor_marker.exists() && !filter_marker.exists());

    // Control: the trap was live all along.
    let _ = Command::new("git")
        .current_dir(&target)
        .args(["status", "--porcelain"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        fsmonitor_marker.exists(),
        "control: git status runs fsmonitor"
    );
    assert!(
        filter_marker.exists(),
        "control: git status runs the clean filter"
    );
}

#[test]
fn a_non_git_target_records_why_provenance_is_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();
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
    std::fs::create_dir_all(target.join(".lyrik")).unwrap();
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
    let run_dir = target.join(format!(".lyrik/state/runs/{RUN}"));
    let body: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run_dir.join("findings.json")).unwrap())
            .unwrap();
    assert!(
        body["target_sha"].is_null() && body["target_dirty"].is_null(),
        "{body}"
    );
    let audit = std::fs::read_to_string(run_dir.join("audit.log")).unwrap();
    let row: serde_json::Value = audit
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|e| e["event"] == "lyrik.provenance.unavailable")
        .unwrap_or_else(|| panic!("no provenance.unavailable row:\n{audit}"));
    assert!(
        row["detail"]["reason"]
            .as_str()
            .unwrap()
            .starts_with("not a git work tree"),
        "{row}"
    );
}
