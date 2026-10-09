//! Shared fixtures for tests that drive the `wirken` binary against a
//! scratch data directory and a scripted model.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One request the scripted model received: path and JSON body.
#[derive(Debug, Clone)]
pub struct Received {
    pub path: String,
    pub body: serde_json::Value,
}

/// A model on a loopback port speaking ollama's `/api/chat`. Each
/// request is answered with the next scripted assistant message and
/// recorded, so a test can read back exactly what the agent sent.
pub struct ScriptedModel {
    pub base_url: String,
    pub received: Arc<Mutex<Vec<Received>>>,
}

impl ScriptedModel {
    /// `replies` are assistant `message` objects, served in order.
    pub fn start(replies: Vec<serde_json::Value>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let received = Arc::new(Mutex::new(Vec::new()));
        let log = received.clone();
        std::thread::spawn(move || {
            for message in replies {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0u8; length];
                reader.read_exact(&mut body).unwrap();
                log.lock().unwrap().push(Received {
                    path,
                    body: serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
                });
                let reply = serde_json::json!({
                    "model": "scripted",
                    "message": message,
                    "done": true,
                })
                .to_string();
                let mut stream = stream;
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                )
                .unwrap();
                stream.flush().unwrap();
            }
        });
        Self { base_url, received }
    }

    pub fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

/// The `wirken` binary under test, pointed at `data_dir`, with stdin
/// closed so no approval gate attaches.
pub fn wirken(data_dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wirken"));
    cmd.env("WIRKEN_DATA_DIR", data_dir)
        .env("NO_COLOR", "1")
        .env_remove("WIRKEN_ALLOW_UNSIGNED_SKILLS")
        .stdin(std::process::Stdio::null());
    cmd
}

/// A signed skill at `dir` whose permissions allow exactly `tools`,
/// reading anywhere in the workspace. `marker` goes in the body so a
/// test can find it in the prompt.
pub fn write_skill(dir: &Path, name: &str, tools: &[&str], marker: &str) {
    write_skill_reading(dir, name, tools, &["<workspace>"], marker);
}

/// [`write_skill`] with the given `filesystem.read_paths`.
pub fn write_skill_reading(
    dir: &Path,
    name: &str,
    tools: &[&str],
    read_paths: &[&str],
    marker: &str,
) {
    std::fs::create_dir_all(dir).unwrap();
    let allow = tools.join(", ");
    let reads = read_paths
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        dir.join("SKILL.md"),
        format!(
            "---\nname: {name}\ndescription: test skill {name}\n\
             disable-model-invocation: false\npermissions:\n  tools:\n    \
             allow: [{allow}]\n  egress:\n    mode: deny\n  filesystem:\n    \
             read_paths: [{reads}]\n  inference:\n    \
             allow: [\"*\"]\n---\n\n# {name}\n\n{marker}\n"
        ),
    )
    .unwrap();
    for stale in ["SKILL.sig", "SKILL.pub"] {
        let _ = std::fs::remove_file(dir.join(stale));
    }
    wirken_agent::bundled_skills::self_sign_skill_dir(dir).unwrap();
}

/// Register an ollama-provider agent served by `model`.
pub fn register_agent(data_dir: &Path, id: &str, model: &ScriptedModel) {
    let store =
        wirken_gateway::agent_config::AgentConfigStore::open(&data_dir.join("agent_config.db"))
            .unwrap();
    store
        .register(&wirken_gateway::agent_config::AgentConfig {
            id: id.into(),
            name: id.into(),
            provider: "ollama".into(),
            model: "scripted".into(),
            base_url: model.base_url.clone(),
            api_key_credential: String::new(),
            channels: Vec::new(),
            allowed_subagents: Default::default(),
            tools_enabled: None,
            preset: None,
            channel_egress: Default::default(),
        })
        .unwrap();
}

/// Tool names in a recorded `/api/chat` request, sorted.
pub fn offered_tools(body: &serde_json::Value) -> Vec<String> {
    let mut names: Vec<String> = body["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|t| t["function"]["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// The system prompt in a recorded `/api/chat` request.
pub fn system_prompt(body: &serde_json::Value) -> String {
    body["messages"]
        .as_array()
        .and_then(|m| m.iter().find(|m| m["role"] == "system"))
        .and_then(|m| m["content"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// The gateway's credential hand-off to an adapter: the header line,
/// then each name and value as a little-endian `u32` length and bytes.
pub const HANDOFF_HEADER: &[u8] = b"wirken-adapter-handoff-v1\n";

pub fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
    out.extend_from_slice(bytes);
}

pub fn handoff(entries: &[(String, String)]) -> Vec<u8> {
    let mut out = HANDOFF_HEADER.to_vec();
    for (name, value) in entries {
        push_field(&mut out, name.as_bytes());
        push_field(&mut out, value.as_bytes());
    }
    out
}

/// Run `wirken adapter <adapter>` with `payload` on stdin, no vault
/// passphrase in its environment, listener ports set to 0 and no gateway
/// socket. Returns once the process exits.
pub fn run_adapter(adapter: &str, data_dir: &Path, payload: &[u8]) -> (ExitStatus, String) {
    let mut child = wirken(data_dir)
        .args(["adapter", adapter])
        .env("WIRKEN_SOCKET", data_dir.join("no-gateway.sock"))
        .env_remove("WIRKEN_VAULT_PASSPHRASE")
        .env("WIRKEN_TEAMS_PORT", "0")
        .env("WIRKEN_WHATSAPP_PORT", "0")
        .env("WIRKEN_GOOGLE_CHAT_PORT", "0")
        .env("WIRKEN_IMESSAGE_PORT", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Write the hand-off and close the pipe, as the gateway does.
    child.stdin.take().unwrap().write_all(payload).unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut stderr = String::new();
        stderr_pipe.read_to_string(&mut stderr).unwrap();
        stderr
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("{adapter} adapter did not exit");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (status, reader.join().unwrap())
}
