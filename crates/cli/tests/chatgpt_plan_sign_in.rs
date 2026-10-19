//! A ChatGPT plan, end to end against a stub provider: the sign-in
//! registers the app and stores the grant, `wirken ask` runs a turn on
//! the Responses route with it, the next turn refreshes the rotated
//! token before its call, and `credentials remove` revokes the grant.
//!
//! The stub stands in for `auth.openai.com`, reached through the
//! loopback-only `WIRKEN_CHATGPT_OAUTH_BASE`, and for `api.openai.com/v1`,
//! reached through `provider.json`. The browser is the test itself: it
//! reads the URL the command prints, checks what the request carries,
//! and follows the redirect to the callback the command is listening on.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wirken_audit::{SessionEvent, SessionId, SessionLog};

const PASSPHRASE_ENV: &str = "WIRKEN_VAULT_PASSPHRASE";
const PASSPHRASE: &str = "chatgpt-plan-test-passphrase";
const OAUTH_BASE_ENV: &str = "WIRKEN_CHATGPT_OAUTH_BASE";
const PLAN_SCOPES: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const ISSUED_CLIENT_ID: &str = "oaiapp_test_client";
const FIRST_ACCESS: &str = "at-first-00000001";
const FIRST_REFRESH: &str = "rt-first-00000001";
const SECOND_ACCESS: &str = "at-second-0000002";
const SECOND_REFRESH: &str = "rt-second-0000002";

/// One request the stub answered.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// A form field of a URL-encoded body, decoded.
    fn form(&self, key: &str) -> Option<String> {
        self.body
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| percent_decode(v))
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// The provider: its token endpoint, discovery document, revocation
/// endpoint and Responses route, on one loopback port.
struct Stub {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Stub {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let base_for_discovery = base.clone();
        std::thread::spawn(move || {
            loop {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let request = read_request(&stream);
                let response = route(&base_for_discovery, &request);
                log.lock().unwrap().push(request);
                let mut stream = stream;
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Self { base, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn requests_to(&self, path: &str) -> Vec<Seen> {
        self.seen().into_iter().filter(|r| r.path == path).collect()
    }
}

fn read_request(stream: &TcpStream) -> Seen {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.trim_end().split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().to_string();
            if k == "content-length" {
                length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).unwrap();
    Seen {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}

fn http(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn route(base: &str, request: &Seen) -> String {
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/api/accounts/oauth/token") => token(request),
        ("GET", "/.well-known/openid-configuration") => http(
            "200 OK",
            "application/json",
            &format!(r#"{{"revocation_endpoint":"{base}/revoke"}}"#),
        ),
        ("POST", "/revoke") => http("200 OK", "text/plain", ""),
        ("POST", "/v1/responses") => responses(request),
        _ => http("404 Not Found", "text/plain", "no such route"),
    }
}

/// The token endpoint: the code exchange of the registration, and one
/// refresh of the first grant, each demanding what the provider does.
fn token(request: &Seen) -> String {
    let grant = request.form("grant_type").unwrap_or_default();
    let client_id = request.form("client_id").unwrap_or_default();
    if client_id != ISSUED_CLIENT_ID {
        return http(
            "400 Bad Request",
            "application/json",
            &format!(r#"{{"error":"invalid_client","error_description":"client {client_id}"}}"#),
        );
    }
    if request.form("resource").as_deref() != Some("https://api.openai.com/v1") {
        return http(
            "400 Bad Request",
            "application/json",
            r#"{"error":"invalid_target","error_description":"resource"}"#,
        );
    }
    match grant.as_str() {
        "authorization_code"
            if request.form("code").as_deref() == Some("code-1")
                && request.form("code_verifier").is_some() =>
        {
            // One second of life, so the next turn has to refresh.
            http(
                "200 OK",
                "application/json",
                &format!(
                    r#"{{"access_token":"{FIRST_ACCESS}","refresh_token":"{FIRST_REFRESH}","token_type":"bearer","expires_in":1,"scope":"{PLAN_SCOPES}"}}"#
                ),
            )
        }
        "refresh_token"
            if request.form("refresh_token").as_deref() == Some(FIRST_REFRESH)
                && request.form("scope").is_none() =>
        {
            http(
                "200 OK",
                "application/json",
                &format!(
                    r#"{{"access_token":"{SECOND_ACCESS}","refresh_token":"{SECOND_REFRESH}","token_type":"bearer","expires_in":3600}}"#
                ),
            )
        }
        _ => http(
            "400 Bad Request",
            "application/json",
            r#"{"error":"invalid_grant","error_description":"grant"}"#,
        ),
    }
}

/// The plan route: a streamed reply that names which bearer it saw, so
/// a turn proves which token it carried.
fn responses(request: &Seen) -> String {
    let bearer = request
        .header("authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();
    if bearer != FIRST_ACCESS && bearer != SECOND_ACCESS {
        return http(
            "401 Unauthorized",
            "application/json",
            r#"{"error":{"code":"subscription_sharing_invalid_user","message":"bearer"}}"#,
        );
    }
    let which = if bearer == FIRST_ACCESS {
        "first"
    } else {
        "second"
    };
    let body = format!(
        "event: response.created\ndata: {{\"type\":\"response.created\",\"response\":{{\"id\":\"resp_1\"}}}}\n\n\
         event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\"Plan says hi on the {which} token\"}}\n\n\
         event: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{{\"input_tokens\":7,\"output_tokens\":9,\"total_tokens\":16}}}}}}\n\n"
    );
    http("200 OK", "text/event-stream", &body)
}

/// A loopback port nothing is listening on right now.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Reads the command's stderr until the authorization URL is printed.
fn wait_for_auth_url(stderr: &mut BufReader<std::process::ChildStderr>) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        if stderr.read_line(&mut line).unwrap() == 0 {
            panic!("the command ended before printing the sign-in URL");
        }
        let trimmed = line.trim();
        if trimmed.starts_with("http://127.0.0.1:") && trimmed.contains("/api/accounts/authorize?")
        {
            return trimmed.to_string();
        }
    }
    panic!("no sign-in URL within 60 s");
}

fn query_param(url: &str, key: &str) -> Option<String> {
    url.split_once('?')?
        .1
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| percent_decode(v))
}

/// Plays the browser: GETs the callback the command listens on.
fn follow_redirect(port: u16, state: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "GET /auth/callback?code=code-1&state={state}&client_id={ISSUED_CLIENT_ID} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn ask(data: &Path, stub: &Stub, message: &str) -> String {
    let output = common::wirken(data)
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env(OAUTH_BASE_ENV, &stub.base)
        .args(["ask", "-m", message])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ask failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn a_plan_sign_in_runs_turns_refreshes_the_grant_and_revokes_it() {
    let data = tempfile::tempdir().unwrap();
    let stub = Stub::start();
    let port = free_port();

    // --- Sign in. The command prints the URL and waits on the port. ---
    let mut child = common::wirken(data.path())
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env(OAUTH_BASE_ENV, &stub.base)
        .args([
            "credentials",
            "authorize",
            "chatgpt",
            "--port",
            &port.to_string(),
            "--no-browser",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let url = wait_for_auth_url(&mut stderr);

    // What the authorization request carries: the bootstrap client id,
    // PKCE, the resource, the host id, the app name, the plan scopes
    // and the pinned callback path on the chosen port.
    assert!(
        url.starts_with(&format!("{}/api/accounts/authorize?", stub.base)),
        "{url}"
    );
    assert_eq!(
        query_param(&url, "client_id").as_deref(),
        Some("dynamic_agent_client")
    );
    assert_eq!(
        query_param(&url, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert!(query_param(&url, "code_challenge").is_some_and(|c| !c.is_empty()));
    assert_eq!(
        query_param(&url, "resource").as_deref(),
        Some("https://api.openai.com/v1")
    );
    assert!(
        query_param(&url, "ext_agent_host_id").is_some_and(|h| h.starts_with("urn:uuid:")),
        "{url}"
    );
    assert_eq!(
        query_param(&url, "agent_name_hint").as_deref(),
        Some("Wirken")
    );
    assert!(query_param(&url, "nonce").is_some_and(|n| !n.is_empty()));
    let scope = query_param(&url, "scope").unwrap_or_default();
    for s in PLAN_SCOPES.split(' ') {
        assert!(
            scope.split(' ').any(|g| g == s),
            "scope {s} missing from {scope}"
        );
    }
    assert_eq!(
        query_param(&url, "redirect_uri").as_deref(),
        Some(format!("http://127.0.0.1:{port}/auth/callback").as_str())
    );
    let state = query_param(&url, "state").expect("state");

    let page = follow_redirect(port, &state);
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    let status = child.wait().unwrap();
    let mut rest = String::new();
    stderr.read_to_string(&mut rest).unwrap();
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(status.success(), "authorize failed:\n{stdout}\n{rest}");
    assert!(stdout.contains("Plan usage: granted"), "{stdout}");
    assert!(stdout.contains("chatgpt.com/settings/usage"), "{stdout}");

    // The exchange went to the issued client id, with the resource.
    let exchanges = stub.requests_to("/api/accounts/oauth/token");
    assert_eq!(exchanges.len(), 1, "{exchanges:?}");
    assert_eq!(
        exchanges[0].form("grant_type").as_deref(),
        Some("authorization_code")
    );
    assert_eq!(
        exchanges[0].form("client_id").as_deref(),
        Some(ISSUED_CLIENT_ID)
    );
    assert!(
        exchanges[0]
            .form("code_verifier")
            .is_some_and(|v| v.len() >= 43),
        "PKCE verifier: {:?}",
        exchanges[0].body
    );

    // The host id persists under the data directory, outside the vault.
    let host_id = std::fs::read_to_string(data.path().join("chatgpt-host-id")).unwrap();
    assert_eq!(
        query_param(&url, "ext_agent_host_id").as_deref(),
        Some(host_id.trim())
    );

    // The public view names the provider and the plan scope, no token.
    let show = common::wirken(data.path())
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .args(["credentials", "show", "chatgpt-plan"])
        .output()
        .unwrap();
    let shown = String::from_utf8_lossy(&show.stdout).to_string();
    assert!(show.status.success(), "{shown}");
    assert!(
        shown.contains("chatgpt") && shown.contains("chatgpt.tokens.use.direct"),
        "{shown}"
    );
    assert!(
        !shown.contains(FIRST_ACCESS) && !shown.contains(FIRST_REFRESH),
        "{shown}"
    );

    // --- A turn on the plan. The one-second token has expired, so the
    // turn refreshes first and calls with the rotated token. ---
    std::fs::write(
        data.path().join("provider.json"),
        format!(
            r#"{{"provider":"chatgpt","model":"gpt-test","base_url":"{}/v1"}}"#,
            stub.base
        ),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let reply = ask(data.path(), &stub, "hello plan");
    assert!(
        reply.contains("Plan says hi on the second token"),
        "{reply}"
    );

    let refreshes: Vec<Seen> = stub
        .requests_to("/api/accounts/oauth/token")
        .into_iter()
        .filter(|r| r.form("grant_type").as_deref() == Some("refresh_token"))
        .collect();
    assert_eq!(
        refreshes.len(),
        1,
        "one refresh before the first turn: {refreshes:?}"
    );
    assert_eq!(
        refreshes[0].form("client_id").as_deref(),
        Some(ISSUED_CLIENT_ID)
    );
    assert_eq!(
        refreshes[0].form("resource").as_deref(),
        Some("https://api.openai.com/v1")
    );

    let turns = stub.requests_to("/v1/responses");
    assert_eq!(turns.len(), 1, "{turns:?}");
    assert_eq!(
        turns[0].header("authorization"),
        Some(format!("Bearer {SECOND_ACCESS}").as_str())
    );
    let body: serde_json::Value = serde_json::from_str(&turns[0].body).unwrap();
    assert_eq!(body["model"], "gpt-test");
    assert_eq!(body["stream"], true);
    assert_eq!(body["store"], false);
    assert!(
        body.get("temperature").is_none() && body.get("max_output_tokens").is_none(),
        "{body}"
    );
    assert!(
        body["instructions"].as_str().is_some_and(|i| !i.is_empty()),
        "the system prompt is the instructions"
    );
    assert_eq!(body["input"][0]["role"], "user");
    assert_eq!(body["input"][0]["content"], "hello plan");

    // --- A second turn: the rotated grant was stored, so no refresh. ---
    let reply = ask(data.path(), &stub, "again");
    assert!(
        reply.contains("Plan says hi on the second token"),
        "{reply}"
    );
    let refreshes = stub
        .requests_to("/api/accounts/oauth/token")
        .into_iter()
        .filter(|r| r.form("grant_type").as_deref() == Some("refresh_token"))
        .count();
    assert_eq!(refreshes, 1, "the stored grant served the second turn");
    assert_eq!(stub.requests_to("/v1/responses").len(), 2);

    // --- The chain names the provider and the credential, never a token. ---
    let log = wirken_audit::SqliteSessionLog::open(&data.path().join("audit.db")).unwrap();
    let handle = log.handle_for(SessionId::new("default"));
    let rows = log.get_since(&handle, 0).unwrap();
    let requests: Vec<_> = rows
        .iter()
        .filter_map(|r| match &r.event {
            SessionEvent::LlmRequest {
                provider,
                credential_id,
                ..
            } => Some((provider.clone(), credential_id.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(requests.len(), 2, "{requests:?}");
    for (provider, credential) in &requests {
        assert_eq!(provider, "chatgpt");
        assert_eq!(credential.as_deref(), Some("chatgpt-plan"));
    }
    let chain = serde_json::to_string(&rows.iter().map(|r| &r.event).collect::<Vec<_>>()).unwrap();
    for secret in [FIRST_ACCESS, FIRST_REFRESH, SECOND_ACCESS, SECOND_REFRESH] {
        assert!(!chain.contains(secret), "a token reached the chain");
    }

    // --- Removal revokes the current refresh token at the provider. ---
    let removed = common::wirken(data.path())
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env(OAUTH_BASE_ENV, &stub.base)
        .args(["credentials", "remove", "chatgpt-plan"])
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&removed.stdout).to_string();
    assert!(removed.status.success(), "{out}");
    assert!(
        out.contains("revoked at the provider") && out.contains("removed"),
        "{out}"
    );
    let revocations = stub.requests_to("/revoke");
    assert_eq!(revocations.len(), 1, "{revocations:?}");
    assert_eq!(
        revocations[0].form("token").as_deref(),
        Some(SECOND_REFRESH)
    );
    assert_eq!(
        revocations[0].form("token_type_hint").as_deref(),
        Some("refresh_token")
    );
    assert_eq!(
        revocations[0].form("client_id").as_deref(),
        Some(ISSUED_CLIENT_ID)
    );
}

/// A grant that signs in without plan usage is not kept.
#[test]
fn a_sign_in_without_plan_usage_stores_nothing() {
    let data = tempfile::tempdir().unwrap();
    // A token endpoint that grants everything but the plan scope.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            let _ = read_request(&stream);
            let body = format!(
                r#"{{"access_token":"{FIRST_ACCESS}","refresh_token":"{FIRST_REFRESH}","token_type":"bearer","expires_in":3600,"scope":"openid profile email offline_access resource.invoke"}}"#
            );
            let mut stream = stream;
            let _ = stream.write_all(http("200 OK", "application/json", &body).as_bytes());
        }
    });
    let port = free_port();
    let mut child = common::wirken(data.path())
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env(OAUTH_BASE_ENV, &base)
        .args([
            "credentials",
            "authorize",
            "chatgpt",
            "--port",
            &port.to_string(),
            "--no-browser",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let url = wait_for_auth_url(&mut stderr);
    let state = query_param(&url, "state").unwrap();
    follow_redirect(port, &state);
    let status = child.wait().unwrap();
    let mut rest = String::new();
    stderr.read_to_string(&mut rest).unwrap();
    assert!(
        !status.success(),
        "a grant without plan usage must be refused:\n{rest}"
    );
    assert!(rest.contains("chatgpt.tokens.use.direct"), "{rest}");

    let names =
        wirken_vault::CredentialStore::names(&data.path().join("vault.db")).unwrap_or_default();
    assert!(!names.iter().any(|n| n == "chatgpt-plan"), "{names:?}");
}

/// The endpoint override is for a loopback stub and nothing else.
#[test]
fn the_oauth_base_override_refuses_a_remote_host() {
    let data = tempfile::tempdir().unwrap();
    let output = common::wirken(data.path())
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env(OAUTH_BASE_ENV, "https://auth.example.com")
        .args(["credentials", "authorize", "chatgpt", "--no-browser"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("loopback"), "{err}");
}
