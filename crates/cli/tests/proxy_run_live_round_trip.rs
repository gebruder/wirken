//! Live round trip of a client started by `wirken proxy run`.
//!
//! Ignored by default: it needs a container runtime, the client's
//! image, `script` (for a pseudo-terminal, since a run is started at
//! one) and a statically linked `wirken` for the relay and the sidecar.
//!
//! ```text
//! WIRKEN_SIDECAR_BINARY=/path/to/wirken   a static build of this tree
//! WIRKEN_LIVE_RUN_IMAGE=<image>           an image with python3
//!                                         (default python:3.12-slim)
//! cargo test -p wirken-cli --test proxy_run_live_round_trip -- --ignored --test-threads 1
//! ```
//!
//! `wirken run` serves the listener with a scripted provider behind
//! it. The client is a short Python program in a read-only folder. It
//! calls a model through the listener at the address the run gives it,
//! writes the answer to its workspace, and then tries what it should
//! not reach: the read-only folder, a host it was not given, and an
//! address directly. It exits with a status of its own, which the run
//! returns. The rows, the token's revocation, and what is left on the
//! runtime afterwards are checked against what the client saw.
//!
//! A second test kills a run outright and checks that the next run
//! clears what it left. It finds the run by its labels on the runtime,
//! so the tests run one at a time.
#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use wirken_audit::{SessionEvent, SessionId, SessionLog};

const PASSPHRASE_ENV: &str = "WIRKEN_VAULT_PASSPHRASE";
const PASSPHRASE: &str = "proxy-run-live-round-trip";

/// The client: what it saw, one line each, into the workspace.
const CLIENT: &str = r#"
import json, os, socket, urllib.request
seen = []
base = os.environ["OPENAI_BASE_URL"]
request = urllib.request.Request(
    base + "/chat/completions",
    data=json.dumps({"model": "m", "messages": [{"role": "user", "content": "hi"}]}).encode(),
    headers={"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"],
             "Content-Type": "application/json"},
)
answer = json.load(urllib.request.urlopen(request, timeout=20))
seen.append("model:" + answer["choices"][0]["message"]["content"])
try:
    open("/mnt/ro/client/written", "w").write("x")
    seen.append("read-only:written")
except OSError:
    seen.append("read-only:refused")
try:
    urllib.request.urlopen("https://example.com/", timeout=10)
    seen.append("example.com:reached")
except Exception:
    seen.append("example.com:refused")
try:
    socket.create_connection(("1.1.1.1", 443), timeout=5)
    seen.append("address:reached")
except OSError:
    seen.append("address:refused")
seen.append("home:" + os.environ["HOME"])
# What the run put in the environment as a credential. The image's own
# variables are the image's.
mine = ("WIRKEN_", "ANTHROPIC_", "OPENAI_")
seen.append("keys:" + ",".join(sorted(k for k in os.environ
    if k.startswith(mine) and (k.endswith("_KEY") or k.endswith("_TOKEN")))))
open("/workspace/seen.txt", "w").write("\n".join(seen) + "\n")
raise SystemExit(7)
"#;

fn wirken(data: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wirken"));
    command
        .env("WIRKEN_DATA_DIR", data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("NO_COLOR", "1");
    command
}

/// Run `wirken <args>` at a pseudo-terminal. Returns its exit status
/// and what it printed.
fn at_terminal(data: &Path, args: &[&str]) -> (i32, String) {
    let line = std::iter::once(env!("CARGO_BIN_EXE_wirken").to_string())
        .chain(args.iter().map(|a| format!("'{a}'")))
        .collect::<Vec<_>>()
        .join(" ");
    let out = Command::new("script")
        .args(["-qec", &line, "/dev/null"])
        .env("WIRKEN_DATA_DIR", data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("NO_COLOR", "1")
        .env("TERM", "xterm")
        .stdin(Stdio::null())
        .output()
        .expect("script(1)");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An OpenAI-shaped provider that answers every call the same and
/// counts them.
fn scripted_provider() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
                let text = String::from_utf8_lossy(&request);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
            }
            counted.fetch_add(1, Ordering::SeqCst);
            let body = r#"{"id":"c1","choices":[{"message":{"role":"assistant","content":"heron"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}"#;
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    (port, calls)
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

fn lanes(data: &Path) -> Vec<String> {
    wirken_audit::SqliteSessionLog::open(&data.join("audit.db"))
        .unwrap()
        .list_session_ids()
        .unwrap()
}

fn stop(mut gateway: common::KillOnDrop) {
    // SAFETY: `kill` takes a pid and a signal and touches no memory;
    // the pid is this test's own child, still unreaped.
    unsafe {
        libc::kill(gateway.id() as libc::pid_t, libc::SIGINT);
    }
    let _ = gateway.wait();
}

/// Names of the runtime's containers and networks that carry `label`.
fn labelled(label: &str) -> Vec<String> {
    let mut found = Vec::new();
    for kind in ["ps", "network"] {
        let mut args = vec![kind];
        if kind == "ps" {
            args.push("-a");
        } else {
            args.push("ls");
        }
        let filter = format!("label={label}");
        args.extend(["--filter", &filter, "--format", "{{.Names}}"]);
        let out = Command::new("docker").args(&args).output().unwrap();
        found.extend(
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::to_string),
        );
    }
    found
}

/// What a test runs against: a data directory with a scripted provider
/// behind its listener, a workspace, the client's folder, and the
/// gateway serving them.
struct Rig {
    root: tempfile::TempDir,
    data: std::path::PathBuf,
    work: std::path::PathBuf,
    client: std::path::PathBuf,
    image: String,
    provider_calls: Arc<AtomicUsize>,
    gateway: Option<common::KillOnDrop>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(gateway) = self.gateway.take() {
            stop(gateway);
        }
    }
}

fn rig() -> Rig {
    let binary = std::env::var("WIRKEN_SIDECAR_BINARY").expect("WIRKEN_SIDECAR_BINARY");
    let image =
        std::env::var("WIRKEN_LIVE_RUN_IMAGE").unwrap_or_else(|_| "python:3.12-slim".to_string());

    // A short path: the gateway's sockets live under the data directory.
    let root = tempfile::Builder::new()
        .prefix("wkr")
        .tempdir_in("/tmp")
        .unwrap();
    let data = root.path().join("d");
    let work = root.path().join("work");
    let client = root.path().join("client");
    for dir in [&data, &work, &client] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(client.join("client.py"), CLIENT).unwrap();
    // The container runs as the operator; its folders are theirs.
    use std::os::unix::fs::PermissionsExt as _;
    for dir in [root.path(), &work, &client] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let (provider_port, provider_calls) = scripted_provider();
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
                "provider": "ollama",
                "base_url": format!("http://127.0.0.1:{provider_port}/v1"),
            }},
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        data.join("sandbox.json"),
        serde_json::json!({"mode": "exec-only", "sidecar_binary": binary}).to_string(),
    )
    .unwrap();

    let gateway = common::KillOnDrop(
        wirken(&data)
            .args(["run", "-p", &free_port().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let up = Instant::now();
    while TcpStream::connect(("127.0.0.1", proxy_port)).is_err() {
        assert!(up.elapsed() < Duration::from_secs(60), "the listener is up");
        std::thread::sleep(Duration::from_millis(200));
    }

    Rig {
        root,
        data,
        work,
        client,
        image,
        provider_calls,
        gateway: Some(gateway),
    }
}

#[test]
#[ignore = "live: needs docker, the image, script and a static wirken"]
fn a_run_reaches_the_listener_and_nothing_it_was_not_given() {
    let rig = rig();
    let (data, work, client, image) = (&rig.data, &rig.work, &rig.client, &rig.image);
    let provider_calls = rig.provider_calls.clone();
    let _ = rig.root.path();
    let (status, printed) = at_terminal(
        data,
        &[
            "proxy",
            "run",
            "--image",
            image,
            "--workspace",
            work.to_str().unwrap(),
            "--read-only",
            client.to_str().unwrap(),
            "--upstream",
            "scripted",
            "--",
            "python3",
            "/mnt/ro/client/client.py",
        ],
    );
    assert_eq!(status, 7, "{printed}");

    // What the client saw.
    let seen = std::fs::read_to_string(work.join("seen.txt")).unwrap_or_else(|_| printed.clone());
    let seen: Vec<&str> = seen.lines().collect();
    assert_eq!(
        seen,
        [
            "model:heron",
            "read-only:refused",
            "example.com:refused",
            "address:refused",
            "home:/home/wirken",
            "keys:ANTHROPIC_AUTH_TOKEN,OPENAI_API_KEY,WIRKEN_PROXY_TOKEN",
        ],
        "{printed}"
    );
    assert!(!client.join("written").exists());
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);

    // The run's rows, on its token's lane.
    let lane = lanes(data)
        .into_iter()
        .find(|lane| {
            rows(data, lane)
                .iter()
                .any(|e| matches!(e, SessionEvent::ProxyRunStarted { .. }))
        })
        .expect("the run's lane");
    let recorded = rows(data, &lane);
    let Some(SessionEvent::ProxyRunStarted {
        token_id,
        image: started_image,
        command,
        mounts,
        egress_hosts,
        container_id,
        ..
    }) = recorded
        .iter()
        .find(|e| matches!(e, SessionEvent::ProxyRunStarted { .. }))
    else {
        unreachable!()
    };
    assert_eq!(lane, format!("proxy-{token_id}"));
    assert_eq!(started_image, image);
    assert_eq!(command, &["python3", "/mnt/ro/client/client.py"]);
    assert!(egress_hosts.is_empty());
    assert_eq!(mounts.len(), 3, "{mounts:?}");
    assert!(mounts[0].ends_with(":/workspace:rw"), "{mounts:?}");
    assert!(mounts[1].ends_with(":/mnt/ro/client:ro"), "{mounts:?}");
    let denied: Vec<&str> = recorded
        .iter()
        .filter_map(|e| match e {
            SessionEvent::SandboxEgressVerdict {
                host,
                allowed: false,
                ..
            } => Some(host.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(denied, ["example.com"]);
    assert!(
        recorded.iter().any(|e| matches!(
            e,
            SessionEvent::ProxyRunEnded { container_id: ended, exit_code: Some(7), stopped: false, .. }
                if ended == container_id
        )),
        "{recorded:?}"
    );
    // The model call, on the token's own conversation lane.
    let called = lanes(data).into_iter().any(|l| {
        l.starts_with(&format!("{lane}-"))
            && rows(data, &l)
                .iter()
                .any(|e| matches!(e, SessionEvent::ProxyRequest { .. }))
    });
    assert!(called, "{:?}", lanes(data));

    // The token was revoked, and nothing of the run is left.
    let listed = wirken(data)
        .args(["proxy", "token", "list"])
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
    let token_line = listed
        .lines()
        .find(|l| l.contains(token_id.as_str()))
        .unwrap_or_default()
        .to_string();
    assert!(token_line.contains("revoked"), "{listed}");
    assert!(
        labelled(&format!("wirken.proxy-run.token={token_id}")).is_empty(),
        "left on the runtime"
    );
}

/// The value of `label` on the running containers that carry it.
fn label_values(label: &str) -> Vec<String> {
    let out = Command::new("docker")
        .args([
            "ps",
            "--filter",
            &format!("label={label}"),
            "--format",
            &format!("{{{{.Label \"{label}\"}}}}"),
        ])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

/// A run killed outright leaves its container running with a live
/// token. The next run of the data directory removes both before it
/// starts its own, and says so.
#[test]
#[ignore = "live: needs docker, the image, script and a static wirken"]
fn a_run_killed_outright_is_cleared_by_the_next() {
    let rig = rig();
    let line = [
        env!("CARGO_BIN_EXE_wirken"),
        "proxy",
        "run",
        "--image",
        &rig.image,
        "--upstream",
        "scripted",
        "--",
        "sleep",
        "300",
    ]
    .join(" ");
    let mut left = Command::new("script")
        .args(["-qec", &line, "/dev/null"])
        .env("WIRKEN_DATA_DIR", &rig.data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("TERM", "xterm")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let up = Instant::now();
    let (pid, token) = loop {
        let pids = label_values("wirken.proxy-run.pid");
        let tokens = label_values("wirken.proxy-run.token");
        if let (Some(pid), Some(token)) = (pids.first(), tokens.first()) {
            break (pid.parse::<i32>().unwrap(), token.clone());
        }
        assert!(up.elapsed() < Duration::from_secs(60), "the run started");
        std::thread::sleep(Duration::from_millis(300));
    };
    // SAFETY: `kill` takes a pid and a signal and touches no memory;
    // the pid is the run this test started.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = left.kill();
    let _ = left.wait();
    std::thread::sleep(Duration::from_secs(1));
    let label = format!("wirken.proxy-run.token={token}");
    assert!(
        !labelled(&label).is_empty(),
        "the killed run's container is left"
    );

    let (status, printed) = at_terminal(
        &rig.data,
        &[
            "proxy",
            "run",
            "--image",
            &rig.image,
            "--upstream",
            "scripted",
            "--",
            "true",
        ],
    );
    assert_eq!(status, 0, "{printed}");
    assert!(
        printed.contains("Removed what 1 earlier run(s) left"),
        "{printed}"
    );
    assert!(
        labelled(&label).is_empty(),
        "the killed run's container is gone"
    );
    let listed = wirken(&rig.data)
        .args(["proxy", "token", "list"])
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
    assert!(
        listed
            .lines()
            .find(|l| l.contains(&token))
            .is_some_and(|l| l.contains("revoked")),
        "{listed}"
    );
}
