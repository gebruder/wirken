//! Live round trip of a real MCP client through the proxy listener,
//! for inference and for tools, with the tool on a stdio MCP server
//! in a container.
//!
//! Ignored by default: it needs a container runtime, the server's
//! image, `script` (for a pseudo-terminal, since a token is issued at
//! one) and a coding-agent CLI that speaks the Anthropic shape and MCP
//! over Streamable HTTP.
//!
//! ```text
//! WIRKEN_LIVE_AGENT_CLI=<path>     the CLI: takes `-p <prompt> --model <model>
//!                                  --mcp-config <file> --strict-mcp-config
//!                                  --allowedTools <tool>`
//! WIRKEN_LIVE_MCP_IMAGE=<image>    an image with python3 (default python:3.12-slim)
//! cargo test -p wirken-cli --test proxy_mcp_live_round_trip -- --ignored --nocapture
//! ```
//!
//! `wirken run` serves the listener and starts the server in its
//! container. The CLI is pointed at the listener by its base-URL
//! variable for inference and by its MCP configuration for tools, with
//! the same token and session label. The provider behind the proxy is
//! a scripted one in this file, so the model's turn is the same every
//! run: it asks for the tool once, then answers. The client, the
//! listener, the gate, the approval route and the server are real.
//!
//! Three sessions: the operator approves the call, denies it, and
//! leaves it unanswered.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use wirken_audit::{SessionEvent, SessionId, SessionLog};

const PASSPHRASE_ENV: &str = "WIRKEN_VAULT_PASSPHRASE";
const PASSPHRASE: &str = "proxy-mcp-live-round-trip";
const TOOL: &str = "mcp_notes_read_note";

/// A stdio MCP server with one tool, `read_note`.
const SERVER: &str = r#"
import json, sys
NOTES = {"alpha": "the alpha note says heron"}
def send(m):
    sys.stdout.write(json.dumps(m) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    mid, method = m.get("id"), m.get("method")
    if mid is None:
        continue
    if method == "initialize":
        version = m.get("params", {}).get("protocolVersion", "2025-06-18")
        send({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": version,
              "capabilities": {"tools": {}}, "serverInfo": {"name": "notes", "version": "1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [{"name": "read_note",
              "description": "Read the note with the given name.",
              "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}},
                              "required": ["name"]}}]}})
    elif method == "tools/call":
        name = m.get("params", {}).get("arguments", {}).get("name", "")
        send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text",
              "text": NOTES.get(name, "no such note")}], "isError": name not in NOTES}})
    else:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no such method"}})
"#;

fn wirken(data: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wirken"));
    command
        .env("WIRKEN_DATA_DIR", data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("NO_COLOR", "1");
    command
}

fn at_terminal(data: &Path, args: &[&str]) -> String {
    let line = std::iter::once(env!("CARGO_BIN_EXE_wirken").to_string())
        .chain(args.iter().map(|a| format!("'{a}'")))
        .collect::<Vec<_>>()
        .join(" ");
    let out = Command::new("script")
        .args(["-qec", &line, "/dev/null"])
        .env("WIRKEN_DATA_DIR", data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .expect("script(1)");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn stop(mut gateway: Child) {
    // SAFETY: `kill` takes a pid and a signal and touches no memory;
    // the pid is this test's own child, still unreaped.
    unsafe {
        libc::kill(gateway.id() as libc::pid_t, libc::SIGINT);
    }
    let _ = gateway.wait();
}

fn rows(data: &Path, session: &str) -> Vec<SessionEvent> {
    let log = wirken_audit::SqliteSessionLog::open(&data.join("audit.db")).unwrap();
    let handle = log.handle_for(SessionId::new(session.to_string()));
    log.get_since(&handle, 0)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect()
}

/// An Anthropic-shaped provider that plays one turn: asked with the
/// MCP tool on offer and no result yet, it calls the tool for the note
/// `alpha`; given the result, or with no such tool, it answers in text.
fn scripted_provider() -> u16 {
    static USES: AtomicUsize = AtomicUsize::new(0);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || answer(stream, &USES));
        }
    });
    port
}

fn answer(mut stream: TcpStream, uses: &AtomicUsize) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let line = line.trim_end().to_ascii_lowercase();
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let tool = request["tools"].as_array().and_then(|tools| {
        tools
            .iter()
            .filter_map(|t| t["name"].as_str())
            .find(|name| name.ends_with("notes_read_note"))
            .map(str::to_string)
    });
    let has_result = request["messages"]
        .as_array()
        .and_then(|m| m.last())
        .and_then(|last| last["content"].as_array())
        .is_some_and(|blocks| blocks.iter().any(|b| b["type"] == "tool_result"));
    let model = request["model"].as_str().unwrap_or("m");
    let start = serde_json::json!({"type": "message_start", "message": {
        "id": "msg_1", "type": "message", "role": "assistant", "model": model, "content": [],
        "stop_reason": null, "usage": {"input_tokens": 10, "output_tokens": 1}}});
    let (events, blocks, stop_reason) = match tool {
        Some(tool) if !has_result => {
            let id = format!("toolu_live{:02}", uses.fetch_add(1, Ordering::SeqCst));
            (
                vec![
                    start,
                    serde_json::json!({"type": "content_block_start", "index": 0,
                        "content_block": {"type": "tool_use", "id": id, "name": tool, "input": {}}}),
                    serde_json::json!({"type": "content_block_delta", "index": 0,
                        "delta": {"type": "input_json_delta", "partial_json": "{\"name\": \"alpha\"}"}}),
                    serde_json::json!({"type": "content_block_stop", "index": 0}),
                    serde_json::json!({"type": "message_delta",
                        "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 5}}),
                    serde_json::json!({"type": "message_stop"}),
                ],
                serde_json::json!([{"type": "tool_use", "id": id, "name": tool,
                    "input": {"name": "alpha"}}]),
                "tool_use",
            )
        }
        _ => (
            vec![
                start,
                serde_json::json!({"type": "content_block_start", "index": 0,
                    "content_block": {"type": "text", "text": ""}}),
                serde_json::json!({"type": "content_block_delta", "index": 0,
                    "delta": {"type": "text_delta", "text": "Done."}}),
                serde_json::json!({"type": "content_block_stop", "index": 0}),
                serde_json::json!({"type": "message_delta",
                    "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 2}}),
                serde_json::json!({"type": "message_stop"}),
            ],
            serde_json::json!([{"type": "text", "text": "Done."}]),
            "end_turn",
        ),
    };
    let (content_type, payload) = if request["stream"] == true {
        let sse: String = events
            .iter()
            .map(|e| format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap()))
            .collect();
        ("text/event-stream", sse)
    } else {
        (
            "application/json",
            serde_json::json!({"id": "msg_1", "type": "message", "role": "assistant",
                "model": model, "content": blocks, "stop_reason": stop_reason,
                "usage": {"input_tokens": 10, "output_tokens": 2}})
            .to_string(),
        )
    };
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{payload}",
        payload.len()
    );
}

/// The id of the one request waiting for the operator, once there is
/// one.
fn pending(data: &Path, within: Duration) -> Option<String> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        let out = wirken(data)
            .args(["permissions", "pending", "list"])
            .output()
            .unwrap();
        let listed = String::from_utf8_lossy(&out.stdout);
        if let Some(id) = listed
            .lines()
            .filter(|line| line.contains(TOOL))
            .filter_map(|line| line.split_whitespace().next())
            .next()
        {
            return Some(id.to_string());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    None
}

/// One run of the client on the session `label`.
fn client(cli: &str, home: &Path, base: &str, token: &str, label: &str) -> Child {
    let config = home.join(format!("mcp-{label}.json"));
    std::fs::write(
        &config,
        serde_json::json!({"mcpServers": {"wirken": {
            "type": "http",
            "url": format!("{base}/mcp"),
            "headers": {"Authorization": format!("Bearer {token}"), "x-wirken-session": label},
        }}})
        .to_string(),
    )
    .unwrap();
    Command::new("timeout")
        .args([
            "180",
            cli,
            "-p",
            "Read the note named alpha.",
            "--model",
            "scripted-1",
            "--mcp-config",
        ])
        .arg(&config)
        .args([
            "--strict-mcp-config",
            "--allowedTools",
            "mcp__wirken__notes_read_note",
        ])
        .env("ANTHROPIC_BASE_URL", base)
        .env("ANTHROPIC_API_KEY", token)
        .env(
            "ANTHROPIC_CUSTOM_HEADERS",
            format!("x-wirken-session: {label}"),
        )
        // The model is offered the MCP tool itself, not a search for it.
        .env("ENABLE_TOOL_SEARCH", "false")
        .env("HOME", home)
        .env("DISABLE_TELEMETRY", "1")
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("agent cli")
}

#[test]
#[ignore = "needs a container runtime, script(1) and WIRKEN_LIVE_AGENT_CLI"]
fn a_real_mcp_client_calls_a_contained_servers_tool_through_the_gate() {
    let cli = std::env::var("WIRKEN_LIVE_AGENT_CLI").expect("WIRKEN_LIVE_AGENT_CLI");
    let image =
        std::env::var("WIRKEN_LIVE_MCP_IMAGE").unwrap_or_else(|_| "python:3.12-slim".to_string());

    // A short path: the gateway's sockets live under the data directory.
    let root = tempfile::Builder::new()
        .prefix("wkm")
        .tempdir_in("/tmp")
        .unwrap();
    let data: PathBuf = root.path().join("d");
    let served = root.path().join("srv");
    let home = root.path().join("home");
    for dir in [&data, &served, &home] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(served.join("server.py"), SERVER).unwrap();

    let provider_port = scripted_provider();
    let proxy_port = free_port();
    std::fs::write(
        data.join("provider.json"),
        r#"{"provider": "ollama", "model": "m", "base_url": "http://127.0.0.1:9"}"#,
    )
    .unwrap();
    std::fs::write(
        data.join("proxy.json"),
        serde_json::json!({
            "bind": format!("127.0.0.1:{proxy_port}"),
            "upstreams": {"scripted": {
                "provider": "anthropic",
                "base_url": format!("http://127.0.0.1:{provider_port}"),
            }},
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        data.join("mcp.json"),
        serde_json::json!({"servers": {"notes": {
            "command": "python3",
            "args": ["/srv/server.py"],
            "sandbox": {
                "image": image,
                "mounts": [{"source": served, "target": "/srv"}],
            },
        }}})
        .to_string(),
    )
    .unwrap();
    assert!(
        wirken(&data)
            .args(["mcp", "sign", "notes"])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );

    let issued = at_terminal(
        &data,
        &[
            "proxy",
            "token",
            "issue",
            "desk",
            "--upstream",
            "scripted",
            "--mcp-server",
            "notes",
        ],
    );
    let token = issued
        .split_whitespace()
        .find(|word| word.starts_with("wkp_"))
        .unwrap_or_else(|| panic!("no token in: {issued}"))
        .to_string();
    let token_id = token.split('_').nth(1).unwrap().to_string();

    let gateway = wirken(&data)
        .args(["run", "-p", &free_port().to_string()])
        // An unanswered approval is given up on after this long.
        .env("WIRKEN_CLI_APPROVAL_TIMEOUT_S", "12")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let base = format!("http://127.0.0.1:{proxy_port}");
    let up = Instant::now();
    while TcpStream::connect(("127.0.0.1", proxy_port)).is_err() {
        assert!(up.elapsed() < Duration::from_secs(60), "the listener is up");
        std::thread::sleep(Duration::from_millis(200));
    }

    // 1. The operator approves.
    let mut run = client(&cli, &home, &base, &token, "approved");
    let id = pending(&data, Duration::from_secs(90)).expect("the approved call is asked");
    assert!(
        wirken(&data)
            .args(["permissions", "pending", "approve", &id])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    run.wait().unwrap();

    // 2. The operator denies.
    let mut run = client(&cli, &home, &base, &token, "denied");
    let id = pending(&data, Duration::from_secs(90)).expect("the denied call is asked");
    assert!(
        wirken(&data)
            .args(["permissions", "pending", "deny", &id, "not this one"])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    run.wait().unwrap();

    // 3. Nobody answers.
    let mut run = client(&cli, &home, &base, &token, "unanswered");
    assert!(
        pending(&data, Duration::from_secs(90)).is_some(),
        "the unanswered call is asked"
    );
    run.wait().unwrap();

    // The lanes verify and export while the gateway is still up.
    let lane = |label: &str| format!("proxy-{token_id}-{label}");
    for label in ["approved", "denied", "unanswered"] {
        let out = wirken(&data)
            .args(["sessions", "verify", &lane(label)])
            .output()
            .unwrap();
        let report = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "{label}: {report}");
        assert!(report.contains("chain: OK"), "{label}: {report}");
        assert!(
            report.contains("tool calls: 1 answered"),
            "{label}: {report}"
        );
    }
    let exported = wirken(&data)
        .args(["sessions", "export", &lane("approved"), "--format", "atif"])
        .output()
        .unwrap();
    assert!(exported.status.success());
    let trajectory: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
    stop(gateway);

    // Each session: the tools the client was shown, the model's calls
    // through the proxy, and the tool call on the same lane.
    let call_of = |events: &[SessionEvent]| {
        events.iter().find_map(|e| match e {
            SessionEvent::AssistantToolCalls {
                calls, sender_id, ..
            } if calls[0].name == TOOL => {
                assert_eq!(
                    sender_id.as_deref(),
                    Some(format!("proxy-token:{token_id}").as_str())
                );
                assert_eq!(calls[0].arguments, r#"{"name":"alpha"}"#);
                Some(calls[0].id.clone())
            }
            _ => None,
        })
    };
    let outcome = |events: &[SessionEvent], id: &str| {
        events.iter().find_map(|e| match e {
            SessionEvent::ProxyToolCall {
                call_id,
                success,
                tool,
                agent_id,
                ..
            } if call_id == id => {
                assert_eq!(tool, TOOL);
                assert_eq!(agent_id, "default");
                Some(*success)
            }
            _ => None,
        })
    };
    for label in ["approved", "denied", "unanswered"] {
        let events = rows(&data, &lane(label));
        assert!(
            events.iter().any(|e| matches!(
                e,
                SessionEvent::ProxyToolsListed { servers, tools, .. }
                    if servers == &["notes".to_string()] && tools == &[TOOL.to_string()]
            )),
            "{label}: {events:?}"
        );
        assert!(
            events
                .iter()
                .filter(|e| matches!(e, SessionEvent::ProxyRequest { .. }))
                .count()
                >= 2,
            "{label}: the model's calls are on the lane"
        );
        let id = call_of(&events).unwrap_or_else(|| panic!("{label}: no tool call"));
        // The row carries the id of the model's tool use.
        assert!(id.starts_with("toolu_live"), "{label}: {id}");
        assert_eq!(outcome(&events, &id), Some(label == "approved"), "{label}");
        let result = events.iter().find_map(|e| match e {
            SessionEvent::ToolResult {
                call_id, output, ..
            } if *call_id == id => Some(output.clone()),
            _ => None,
        });
        let denial = events.iter().find_map(|e| match e {
            SessionEvent::PermissionDenied { denial_reason, .. } => Some(denial_reason.clone()),
            _ => None,
        });
        match label {
            "approved" => {
                assert!(events.iter().any(|e| matches!(
                    e,
                    SessionEvent::PermissionApproved { action_key, .. }
                        if action_key == "mcp:mcp_notes_read_note"
                )));
                assert_eq!(result.as_deref(), Some("the alpha note says heron"));
                assert!(denial.is_none());
            }
            "denied" => {
                assert_eq!(denial, Some(Some("not this one".to_string())));
                assert!(result.unwrap().starts_with("Permission denied"));
            }
            _ => {
                assert_eq!(denial, Some(Some("approval timeout".to_string())));
                assert!(result.unwrap().starts_with("Permission denied"));
            }
        }
    }

    // The server ran in a container.
    assert!(
        rows(&data, "gateway-mcp").iter().any(|e| matches!(
            e,
            SessionEvent::McpServerSandboxed { server_name, .. } if server_name == "notes"
        )),
        "the server's contained start is recorded"
    );

    // The trajectory holds the call and the result the gateway recorded.
    let recorded = trajectory["steps"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| {
            s["observation"]["results"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .find(|r| r["extra"]["recorded_by"] == "wirken")
        .expect("the recorded result is in the trajectory");
    assert_eq!(recorded["content"], "the alpha note says heron");
    assert_eq!(recorded["extra"]["tool_name"], TOOL);
}
