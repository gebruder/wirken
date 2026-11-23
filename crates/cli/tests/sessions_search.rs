//! `wirken sessions search`, driven through the binary over a session
//! log holding an agent's sessions and a proxied one.

mod common;

use common::wirken;
use wirken_audit::{SessionEvent, SessionId, SessionLog, SqliteSessionLog, StoredSessionEvent};
use wirken_gateway::proxy::{PROXY_TOKENS_FILE, ProxyTokenStore, TokenGrant};

fn event(value: serde_json::Value) -> SessionEvent {
    serde_json::from_value(value).unwrap()
}

struct Fixture {
    tmp: tempfile::TempDir,
    token_id: String,
    lane: String,
}

/// Two agent sessions and one proxied session. `heron` is in a user
/// message, in a tool call's arguments and its output, and in a tool
/// call a proxy client made.
fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let (token, _) = ProxyTokenStore::open(&tmp.path().join(PROXY_TOKENS_FILE))
        .unwrap()
        .issue(&TokenGrant {
            name: "laptop".into(),
            upstreams: vec!["local".into()],
            ..Default::default()
        })
        .unwrap();
    let lane = format!("proxy-{}-work", token.id);
    let log = SqliteSessionLog::open(&tmp.path().join("audit.db")).unwrap();
    let put = |session: &str, events: Vec<serde_json::Value>| {
        let handle = log.handle_for(SessionId::new(session.to_string()));
        for value in events {
            log.append(&handle, wirken_audit::TrustLevel::System, event(value))
                .unwrap();
        }
    };
    put(
        "ops/slack/c1",
        vec![
            serde_json::json!({"kind":"user_message","content":"Deploy the Heron service",
                "inbound_id":"i1","adapter_id":"slack","sender_id":"U1"}),
            serde_json::json!({"kind":"assistant_tool_calls","agent_id":"ops",
                "calls":[{"id":"c1","name":"exec",
                          "arguments":"{\"command\":\"grep -n \\\"heron\\\" deploy.yaml\"}"}]}),
            serde_json::json!({"kind":"tool_result","call_id":"c1","tool_name":"exec",
                "output":"3: service: heron","success":true,"agent_id":"ops"}),
        ],
    );
    put(
        "default/telegram/c2",
        vec![
            serde_json::json!({"kind":"user_message","content":"nothing about birds",
            "inbound_id":"i2"}),
        ],
    );
    put(
        &lane,
        vec![
            serde_json::json!({"kind":"assistant_tool_calls","agent_id":"default",
                "sender_id": format!("proxy-token:{}", token.id),
                "calls":[{"id":"m1","name":"mcp_notes_read",
                          "arguments":"{\"name\":\"heron\"}"}]}),
            serde_json::json!({"kind":"tool_result","call_id":"m1","tool_name":"mcp_notes_read",
                "output":"no such note","success":false,"agent_id":"default"}),
        ],
    );
    Fixture {
        tmp,
        token_id: token.id,
        lane,
    }
}

impl Fixture {
    fn search(&self, args: &[&str]) -> serde_json::Value {
        let out = wirken(self.tmp.path())
            .args(["sessions", "search"])
            .args(args)
            .args(["--format", "json"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// `(session, seq)` of each hit.
    fn hits(&self, args: &[&str]) -> Vec<(String, u64)> {
        self.search(args)["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                (
                    h["session"].as_str().unwrap().to_string(),
                    h["seq"].as_u64().unwrap(),
                )
            })
            .collect()
    }

    fn rows(&self, session: &str) -> Vec<StoredSessionEvent> {
        let log = SqliteSessionLog::open(&self.tmp.path().join("audit.db")).unwrap();
        log.get_since(&log.handle_for(SessionId::new(session.to_string())), 0)
            .unwrap()
    }
}

#[test]
fn a_search_finds_rows_across_agent_and_proxied_sessions_and_cites_them() {
    let f = fixture();
    let found = f.search(&["HERON"]);
    let hits = found["hits"].as_array().unwrap();
    let cited: Vec<(&str, u64, &str)> = hits
        .iter()
        .map(|h| {
            (
                h["session"].as_str().unwrap(),
                h["seq"].as_u64().unwrap(),
                h["kind"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        cited,
        vec![
            ("ops/slack/c1", 0, "user_message"),
            ("ops/slack/c1", 1, "assistant_tool_calls"),
            ("ops/slack/c1", 2, "tool_result"),
            (f.lane.as_str(), 0, "assistant_tool_calls"),
        ]
    );
    assert_eq!(found["truncated"], false);
    assert_eq!(found["archive"], "not_configured");
    assert_eq!(found["sessions_searched"], 3);

    // Each hit is the row at that place on its session's chain, and
    // its snippet is what the row says, unescaped.
    for hit in hits {
        let rows = f.rows(hit["session"].as_str().unwrap());
        let row = rows
            .iter()
            .find(|r| r.seq == hit["seq"].as_u64().unwrap())
            .unwrap();
        assert_eq!(hit["chain_hash"], row.hash.0);
        assert_eq!(hit["found_in"], "row");
        assert_eq!(hit["ts"], wirken_time::TimestampExt::to_rfc3339_z(&row.ts));
    }
    assert!(
        hits[1]["snippet"]
            .as_str()
            .unwrap()
            .contains("grep -n \"heron\" deploy.yaml"),
        "{}",
        hits[1]["snippet"]
    );

    // The session a hit names verifies.
    let verify = wirken(f.tmp.path())
        .args(["sessions", "verify", &f.lane])
        .output()
        .unwrap();
    assert!(verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stdout).contains("chain: OK"));
}

#[test]
fn a_search_is_narrowed_by_agent_token_channel_tool_session_and_time() {
    let f = fixture();
    let ops = "ops/slack/c1".to_string();
    assert_eq!(f.hits(&["heron", "--agent", "ops"]).len(), 3);
    assert_eq!(
        f.hits(&["heron", "--agent", "default"]),
        vec![(f.lane.clone(), 0)]
    );
    for token in [f.token_id.as_str(), "laptop"] {
        assert_eq!(
            f.hits(&["heron", "--token", token]),
            vec![(f.lane.clone(), 0)]
        );
    }
    assert_eq!(f.hits(&["heron", "--channel", "slack"]).len(), 3);
    assert!(f.hits(&["heron", "--channel", "telegram"]).is_empty());
    assert_eq!(
        f.hits(&["heron", "--tool", "exec"]),
        vec![(ops.clone(), 1), (ops.clone(), 2)]
    );
    assert_eq!(
        f.hits(&["heron", "--tool", "mcp_notes_read"]),
        vec![(f.lane.clone(), 0)]
    );
    assert_eq!(f.hits(&["heron", "--session", &f.lane]).len(), 1);
    assert!(
        f.hits(&["heron", "--since", "2999-01-01T00:00:00Z"])
            .is_empty()
    );
    assert_eq!(
        f.hits(&["heron", "--until", "2999-01-01T00:00:00Z"]).len(),
        4
    );
    assert!(f.hits(&["wren"]).is_empty());

    let limited = f.search(&["heron", "-n", "2"]);
    assert_eq!(limited["hits"].as_array().unwrap().len(), 2);
    assert_eq!(limited["truncated"], true);

    // An unknown token, a time that is not one, and an empty query are
    // errors, not empty results.
    for args in [
        &["heron", "--token", "nobody"][..],
        &["heron", "--since", "yesterday"],
        &["  "],
    ] {
        let out = wirken(f.tmp.path())
            .args(["sessions", "search"])
            .args(args)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{args:?}");
    }
}

/// With an archive configured, `--skip-archive` searches the rows and
/// opens neither the vault nor the bucket.
#[test]
fn skip_archive_searches_the_rows_only() {
    let f = fixture();
    std::fs::write(
        f.tmp.path().join("proxy.json"),
        serde_json::json!({
            "upstreams": {"local": {"provider": "ollama", "base_url": "http://localhost:11434/v1"}},
            "archive": {
                "endpoint": "http://127.0.0.1:9",
                "bucket": "nowhere",
                "retention_days": 1,
                "credential": "not-stored"
            }
        })
        .to_string(),
    )
    .unwrap();
    let found = f.search(&["heron", "--skip-archive"]);
    assert_eq!(found["archive"], "skipped");
    assert_eq!(found["hits"].as_array().unwrap().len(), 4);
    assert_eq!(found["bodies_searched"], 0);
}

#[test]
fn the_text_output_names_the_session_the_row_and_the_chain_hash() {
    let f = fixture();
    let out = wirken(f.tmp.path())
        .args(["sessions", "search", "heron", "--tool", "mcp_notes_read"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let row = &f.rows(&f.lane)[0];
    assert!(text.contains(&format!("{}  seq 0  ", f.lane)), "{text}");
    assert!(text.contains("assistant_tool_calls"), "{text}");
    assert!(text.contains(&format!("chain {}", row.hash.0)), "{text}");
    assert!(text.contains("in the row"), "{text}");
    assert!(text.contains("1 hit in"), "{text}");
    assert!(text.contains("archive: not configured"), "{text}");
    assert!(text.contains("wirken sessions verify"), "{text}");
}
