//! The MCP proxy never opens the vault and never holds its passphrase.
//!
//! `wirken run` hands the proxy the credentials its `mcp.json` entries
//! reference on stdin and keeps the passphrase out of its environment;
//! the proxy, run on its own with a hand-off, opens no vault file.
#![cfg(target_os = "linux")]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PASSPHRASE_ENV: &str = "WIRKEN_VAULT_PASSPHRASE";
const PASSPHRASE: &str = "proxy-vault-test-passphrase";

/// A data directory whose vault holds `github-token`, and whose
/// `mcp.json` runs one host server that writes the value it was given
/// to `out` and then answers as an MCP server.
fn data_dir(out: &Path) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("provider.json"),
        r#"{"provider": "ollama", "model": "m", "base_url": "http://127.0.0.1:9"}"#,
    )
    .unwrap();
    let mut add = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(["credentials", "add", "github-token", "--stdin"])
        .env("WIRKEN_DATA_DIR", dir.path())
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    add.stdin
        .take()
        .unwrap()
        .write_all(b"ghp-handed-over")
        .unwrap();
    assert!(add.wait().unwrap().success());

    let script = format!(
        r#"printf %s "$TOKEN" > {out}; read a; printf '{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":"2024-11-05","capabilities":{{}},"serverInfo":{{"name":"t","version":"1"}}}}}}\n'; read b; read c; printf '{{"jsonrpc":"2.0","id":2,"result":{{"tools":[]}}}}\n'; cat >/dev/null"#,
        out = out.display()
    );
    let mcp = serde_json::json!({ "servers": { "probe": {
        "command": "sh",
        "args": ["-c", script],
        "env": { "TOKEN": "vault:github-token" },
        "sandbox": "off"
    }}});
    std::fs::write(dir.path().join("mcp.json"), mcp.to_string()).unwrap();
    dir
}

fn children(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return out;
    };
    for task in tasks.flatten() {
        if let Ok(list) = std::fs::read_to_string(task.path().join("children")) {
            out.extend(
                list.split_whitespace()
                    .filter_map(|p| p.parse::<u32>().ok()),
            );
        }
    }
    out
}

fn cmdline(pid: u32) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
        .unwrap_or_default()
}

/// The files `pid` has open.
fn open_files(pid: u32) -> Vec<PathBuf> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|fds| {
            fds.flatten()
                .filter_map(|fd| std::fs::read_link(fd.path()).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn the_proxy_run_starts_has_no_passphrase_no_vault_open_and_its_credential() {
    let scratch = tempfile::tempdir().unwrap();
    let out = scratch.path().join("token-the-server-got");
    let data = data_dir(&out);
    let mut gateway = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .args(["run", "--port", &free_port().to_string()])
        .env("WIRKEN_DATA_DIR", data.path())
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = gateway.id();
    let stdout = gateway.stdout.take().unwrap();
    let (tx, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut output = Vec::new();
    while !output.iter().any(|l: &String| l.contains("Wirken running")) {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => output.push(line),
            Err(_) => {
                let _ = gateway.kill();
                panic!("gateway never came up:\n{}", output.join("\n"));
            }
        }
    }

    let proxies: Vec<u32> = children(pid)
        .into_iter()
        .filter(|c| cmdline(*c).contains("mcp-proxy"))
        .collect();
    let environs: Vec<String> = proxies
        .iter()
        .map(|p| {
            String::from_utf8_lossy(
                &std::fs::read(format!("/proc/{p}/environ")).unwrap_or_default(),
            )
            .into_owned()
        })
        .collect();
    let vault_fds: Vec<PathBuf> = proxies
        .iter()
        .flat_map(|p| open_files(*p))
        .filter(|f| {
            f.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("vault.db"))
        })
        .collect();
    let handed = std::fs::read_to_string(&out).unwrap_or_default();

    // SAFETY: kill(2) on the child this test spawned and still holds.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while gateway.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = gateway.kill();
    let _ = gateway.wait();

    assert_eq!(proxies.len(), 1, "one MCP proxy under the gateway");
    assert!(
        environs
            .iter()
            .all(|e| !e.contains(PASSPHRASE_ENV) && !e.contains(PASSPHRASE)),
        "the proxy's environment carries the vault passphrase"
    );
    assert!(
        vault_fds.is_empty(),
        "the proxy has the vault open: {vault_fds:?}"
    );
    assert_eq!(
        handed, "ghp-handed-over",
        "the server got the handed-over value"
    );
}

/// inotify on one file: how many times it was opened since the last
/// call.
struct Watch {
    fd: libc::c_int,
}

impl Watch {
    fn new(path: &Path) -> Self {
        // SAFETY: plain syscalls on a path this test owns; the fd is
        // closed on drop.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(fd >= 0);
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `fd` is the inotify instance opened above and `c_path`
        // a NUL-terminated path that outlives the call.
        let wd = unsafe { libc::inotify_add_watch(fd, c_path.as_ptr(), libc::IN_OPEN) };
        assert!(wd >= 0);
        Self { fd }
    }

    fn opens(&self) -> usize {
        let mut count = 0;
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: reads into a buffer this function owns.
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                return count;
            }
            let mut at = 0usize;
            while at + 16 <= n as usize {
                let len = u32::from_ne_bytes(buf[at + 12..at + 16].try_into().unwrap()) as usize;
                count += 1;
                at += 16 + len;
            }
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // SAFETY: closes the fd `new` opened.
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[test]
fn the_proxy_binary_opens_no_vault_file() {
    let scratch = tempfile::tempdir().unwrap();
    let data = data_dir(&scratch.path().join("token-the-server-got"));
    let vault = data.path().join("vault.db");
    let watch = Watch::new(&vault);
    // The watch sees an open.
    drop(std::fs::File::open(&vault).unwrap());
    assert_eq!(watch.opens(), 1, "the watch does not see opens");

    // Given the passphrase in its environment and nothing handed over,
    // the proxy still has no reason, and no code, to open the vault.
    let socket = scratch.path().join("proxy.sock");
    let mut proxy = Command::new(env!("CARGO_BIN_EXE_wirken"))
        .arg("mcp-proxy")
        .env("WIRKEN_DATA_DIR", data.path())
        .env("WIRKEN_MCP_SOCKET", &socket)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    proxy
        .stdin
        .take()
        .unwrap()
        .write_all(&common::handoff(&[]))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let served = socket.exists();
    std::thread::sleep(Duration::from_millis(500));
    let opens = watch.opens();
    let _ = proxy.kill();
    let _ = proxy.wait();

    assert!(served, "the proxy never served its socket");
    assert_eq!(opens, 0, "the proxy opened the vault file");
}
