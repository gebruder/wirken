//! A registry root that is present but does not parse is a broken
//! strict anchor. Every path that builds an agent from skills stops on
//! it, rather than building one with no skills while strict mode is
//! broken.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::{ScriptedModel, register_agent, wirken, write_skill};

fn corrupt_root(data_dir: &Path) {
    std::fs::write(data_dir.join("registry-root.pub"), "not a key\n").unwrap();
}

fn assert_refused(out: &std::process::Output, model: &ScriptedModel) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "expected a refusal, got success");
    assert!(
        stderr.contains("registry root unusable"),
        "the error names the root: {stderr}"
    );
    assert!(
        model.received().is_empty(),
        "no request reached the model: {:?}",
        model.received()
    );
}

#[test]
fn ask_with_a_configured_agent_stops_on_an_unusable_root() {
    let data = tempfile::tempdir().unwrap();
    let model = ScriptedModel::start(vec![
        serde_json::json!({"role": "assistant", "content": "unused"}),
    ]);
    register_agent(data.path(), "narrow", &model);
    write_skill(
        &data.path().join("skills/shared"),
        "shared",
        &["read_file"],
        "M",
    );
    corrupt_root(data.path());

    let out = wirken(data.path())
        .args(["ask", "--agent", "narrow", "-m", "hi"])
        .output()
        .unwrap();
    assert_refused(&out, &model);
}

#[test]
fn ask_with_the_default_agent_stops_on_an_unusable_root() {
    let data = tempfile::tempdir().unwrap();
    let model = ScriptedModel::start(vec![
        serde_json::json!({"role": "assistant", "content": "unused"}),
    ]);
    std::fs::write(
        data.path().join("provider.json"),
        serde_json::json!({
            "provider": "ollama",
            "model": "scripted",
            "base_url": model.base_url,
        })
        .to_string(),
    )
    .unwrap();
    write_skill(
        &data.path().join("skills/shared"),
        "shared",
        &["read_file"],
        "M",
    );
    corrupt_root(data.path());

    let out = wirken(data.path())
        .args(["ask", "-m", "hi"])
        .output()
        .unwrap();
    assert_refused(&out, &model);
}

#[test]
fn run_does_not_start_on_an_unusable_root() {
    let data = tempfile::tempdir().unwrap();
    let model = ScriptedModel::start(vec![]);
    std::fs::write(
        data.path().join("provider.json"),
        serde_json::json!({
            "provider": "ollama",
            "model": "scripted",
            "base_url": model.base_url,
        })
        .to_string(),
    )
    .unwrap();
    write_skill(
        &data.path().join("skills/shared"),
        "shared",
        &["read_file"],
        "M",
    );
    corrupt_root(data.path());

    let mut child = wirken(data.path())
        .args(["run", "--port", "0"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("wirken run kept running with an unusable registry root");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output().unwrap();
    assert_refused(&out, &model);
}
