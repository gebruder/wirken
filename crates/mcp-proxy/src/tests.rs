use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use ed25519_dalek::{Signer, SigningKey};
use rand::Rng;

use crate::mcp_registry::ProxyRegistry;
use crate::server;
use crate::wire::{
    AuthChallenge, AuthChallengeKind, AuthResponse, AuthResponseKind, HelloAck, HelloAckKind,
    PROTOCOL_VERSION, Request, Response,
};

/// Hex-encode bytes. Matches the server's implementation.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

fn random_signing_key() -> SigningKey {
    let mut secret = [0u8; 32];
    rand::rng().fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

/// Hex-decode a 32-byte value.
fn hex_decode_32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Complete a handshake on `stream` against a proxy that has
/// registered `signing_key.verifying_key()` for `agent_id`. Returns
/// the parsed HelloAck on success.
async fn do_handshake(
    stream: &mut UnixStream,
    agent_id: &str,
    signing_key: &SigningKey,
) -> Result<HelloAck, String> {
    // Read AuthChallenge.
    let challenge: AuthChallenge = read_one_line_result(stream)
        .await
        .map_err(|e| format!("read challenge: {e}"))?;
    if challenge.kind != AuthChallengeKind::AuthChallenge {
        return Err(format!("expected auth_challenge, got {:?}", challenge.kind));
    }

    // Sign (domain || agent_id || nonce) — v3 handshake payload.
    let nonce = hex_decode_32(&challenge.nonce);
    let signed = crate::wire::handshake_signed_payload(agent_id, &nonce);
    let signature = signing_key.sign(&signed);

    // Send AuthResponse.
    let response = AuthResponse {
        kind: AuthResponseKind::AuthResponse,
        agent_id: agent_id.to_string(),
        public_key: hex_encode(&signing_key.verifying_key().to_bytes()),
        signature: hex_encode(&signature.to_bytes()),
    };
    let mut bytes = serde_json::to_vec(&response).unwrap();
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| format!("write response: {e}"))?;

    // Read HelloAck.
    read_one_line_result(stream)
        .await
        .map_err(|e| format!("read ack: {e}"))
}

/// Read one newline-delimited JSON frame, returning an error instead
/// of panicking. Used by the handshake helper above.
async fn read_one_line_result<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
) -> Result<T, String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("eof".into());
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    let s = String::from_utf8(buf).map_err(|e| e.to_string())?;
    serde_json::from_str(&s).map_err(|e| format!("parse {s}: {e}"))
}

#[test]
fn auth_challenge_round_trip() {
    let c = AuthChallenge {
        kind: AuthChallengeKind::AuthChallenge,
        protocol_version: PROTOCOL_VERSION,
        nonce: "a".repeat(64),
    };
    let s = serde_json::to_string(&c).unwrap();
    let parsed: AuthChallenge = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed.kind, AuthChallengeKind::AuthChallenge);
    assert_eq!(parsed.protocol_version, PROTOCOL_VERSION);
    assert_eq!(parsed.nonce.len(), 64);
}

#[test]
fn auth_response_round_trip() {
    let r = AuthResponse {
        kind: AuthResponseKind::AuthResponse,
        agent_id: "work".into(),
        public_key: "b".repeat(64),
        signature: "c".repeat(128),
    };
    let s = serde_json::to_string(&r).unwrap();
    let parsed: AuthResponse = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed.kind, AuthResponseKind::AuthResponse);
    assert_eq!(parsed.agent_id, "work");
}

#[test]
fn hello_ack_round_trip() {
    let a = HelloAck {
        kind: HelloAckKind::HelloAck,
        protocol_version: PROTOCOL_VERSION,
        has_servers: true,
    };
    let s = serde_json::to_string(&a).unwrap();
    let parsed: HelloAck = serde_json::from_str(&s).unwrap();
    assert!(parsed.has_servers);
}

#[test]
fn request_list_tools_round_trip() {
    let r = Request::ListTools { id: 7 };
    let s = serde_json::to_string(&r).unwrap();
    assert!(s.contains("\"kind\":\"list_tools\""));
    let parsed: Request = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed.id(), 7);
}

#[test]
fn request_call_tool_round_trip() {
    let r = Request::CallTool {
        id: 11,
        name: "mcp_filesystem_read_file".into(),
        arguments: "{\"path\":\"x\"}".into(),
    };
    let s = serde_json::to_string(&r).unwrap();
    let parsed: Request = serde_json::from_str(&s).unwrap();
    match parsed {
        Request::CallTool {
            id,
            name,
            arguments,
        } => {
            assert_eq!(id, 11);
            assert_eq!(name, "mcp_filesystem_read_file");
            assert!(arguments.contains("\"path\""));
        }
        _ => panic!("expected CallTool"),
    }
}

#[test]
fn response_call_tool_result_round_trip() {
    let r = Response::CallToolResult {
        id: 12,
        output: "hello".into(),
        success: true,
    };
    let s = serde_json::to_string(&r).unwrap();
    let parsed: Response = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed.id(), 12);
    match parsed {
        Response::CallToolResult {
            output, success, ..
        } => {
            assert_eq!(output, "hello");
            assert!(success);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn response_error_round_trip() {
    let r = Response::Error {
        id: 13,
        message: "boom".into(),
    };
    let s = serde_json::to_string(&r).unwrap();
    let parsed: Response = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed.id(), 13);
}

// ---------------------------------------------------------------------------
// End-to-end server smoke test.
//
// Boots an in-process server bound to a tempdir UDS, opens a client
// connection, walks the hello → list_tools → shutdown handshake, and
// asserts the proxy correctly returns an empty tool set for an agent
// that has no MCP servers loaded. This is the slice 1 happy path
// without depending on a real MCP subprocess.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_round_trip_empty_registry_with_auth() {
    let tmp = TempDir::new().unwrap();
    let socket_path = tmp.path().join("mcp-proxy.sock");

    // Generate a signing key and register its public half under
    // "test-agent" so the handshake succeeds.
    let signing_key = random_signing_key();
    let mut reg = ProxyRegistry::new();
    reg.register_identity("test-agent", signing_key.verifying_key());
    let registry = Arc::new(Mutex::new(reg));

    let server_socket = socket_path.clone();
    let server_registry = registry.clone();
    let server_handle = tokio::spawn(async move {
        let _ = server::serve(server_socket, server_registry).await;
    });

    // Wait for the socket to appear.
    for _ in 0..100 {
        if socket_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(socket_path.exists(), "proxy socket did not appear");

    let mut stream = UnixStream::connect(&socket_path).await.unwrap();

    let ack = do_handshake(&mut stream, "test-agent", &signing_key)
        .await
        .expect("handshake");
    assert_eq!(ack.kind, HelloAckKind::HelloAck);
    assert_eq!(ack.protocol_version, PROTOCOL_VERSION);
    assert!(
        !ack.has_servers,
        "empty registry should report has_servers=false"
    );

    // ListTools
    let req = Request::ListTools { id: 1 };
    let mut bytes = serde_json::to_vec(&req).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).await.unwrap();

    let resp: Response = read_one_line(&mut stream).await;
    match resp {
        Response::ListToolsResult { id, tools } => {
            assert_eq!(id, 1);
            assert!(tools.is_empty(), "empty registry should return zero tools");
        }
        other => panic!("expected ListToolsResult, got {other:?}"),
    }

    // Shutdown
    let req = Request::Shutdown { id: 2 };
    let mut bytes = serde_json::to_vec(&req).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).await.unwrap();

    let resp: Response = read_one_line(&mut stream).await;
    assert!(matches!(resp, Response::ShutdownAck { id: 2 }));

    server_handle.abort();
}

#[tokio::test]
async fn server_rejects_unknown_agent_id() {
    let tmp = TempDir::new().unwrap();
    let socket_path = tmp.path().join("mcp-proxy.sock");

    // Registry has an identity for "work" but not for "evil".
    let known_key = random_signing_key();
    let mut reg = ProxyRegistry::new();
    reg.register_identity("work", known_key.verifying_key());
    let registry = Arc::new(Mutex::new(reg));

    let server_socket = socket_path.clone();
    let server_registry = registry.clone();
    let server_handle = tokio::spawn(async move {
        let _ = server::serve(server_socket, server_registry).await;
    });
    for _ in 0..100 {
        if socket_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let mut stream = UnixStream::connect(&socket_path).await.unwrap();
    // Claim "evil" with a valid-but-unregistered key.
    let evil_key = random_signing_key();
    let result = do_handshake(&mut stream, "evil", &evil_key).await;
    assert!(
        result.is_err(),
        "handshake with unregistered agent_id must fail, got {result:?}"
    );

    server_handle.abort();
}

#[tokio::test]
async fn server_rejects_wrong_signing_key_for_registered_agent() {
    let tmp = TempDir::new().unwrap();
    let socket_path = tmp.path().join("mcp-proxy.sock");

    // Registry registers "work"'s real pubkey; the attacker will try
    // to impersonate "work" with a different key.
    let real_key = random_signing_key();
    let attacker_key = random_signing_key();
    let mut reg = ProxyRegistry::new();
    reg.register_identity("work", real_key.verifying_key());
    let registry = Arc::new(Mutex::new(reg));

    let server_socket = socket_path.clone();
    let server_registry = registry.clone();
    let server_handle = tokio::spawn(async move {
        let _ = server::serve(server_socket, server_registry).await;
    });
    for _ in 0..100 {
        if socket_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let mut stream = UnixStream::connect(&socket_path).await.unwrap();
    let result = do_handshake(&mut stream, "work", &attacker_key).await;
    assert!(
        result.is_err(),
        "handshake with wrong signing key must fail, got {result:?}"
    );

    server_handle.abort();
}

#[tokio::test]
async fn server_rejects_tampered_signature() {
    let tmp = TempDir::new().unwrap();
    let socket_path = tmp.path().join("mcp-proxy.sock");

    let signing_key = random_signing_key();
    let mut reg = ProxyRegistry::new();
    reg.register_identity("work", signing_key.verifying_key());
    let registry = Arc::new(Mutex::new(reg));

    let server_socket = socket_path.clone();
    let server_registry = registry.clone();
    let server_handle = tokio::spawn(async move {
        let _ = server::serve(server_socket, server_registry).await;
    });
    for _ in 0..100 {
        if socket_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let mut stream = UnixStream::connect(&socket_path).await.unwrap();

    // Read the real challenge but send a signature over a different
    // nonce — the proxy must reject.
    let challenge: AuthChallenge = read_one_line(&mut stream).await;
    let mut wrong_nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut wrong_nonce);
    assert_ne!(hex_decode_32(&challenge.nonce), wrong_nonce);

    let bad_sig = signing_key.sign(&wrong_nonce);
    let response = AuthResponse {
        kind: AuthResponseKind::AuthResponse,
        agent_id: "work".into(),
        public_key: hex_encode(&signing_key.verifying_key().to_bytes()),
        signature: hex_encode(&bad_sig.to_bytes()),
    };
    let mut bytes = serde_json::to_vec(&response).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).await.unwrap();

    // Expect EOF, not a HelloAck.
    let mut buf = [0u8; 1];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    assert_eq!(
        n, 0,
        "expected EOF after signature verify failure, got {n} bytes"
    );

    server_handle.abort();
}

// ---------------------------------------------------------------------------
// Item 7 slice 2: HTTP transport + auth providers
// ---------------------------------------------------------------------------

mod http_transport_test {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::auth::{BearerAuth, NoAuth};
    use crate::mcp_transport::HttpTransport;

    /// Tiny JSON-RPC test server. Spawns a TCP listener on 127.0.0.1:0,
    /// accepts one POST, optionally checks the Authorization header,
    /// and replies with a canned JSON-RPC response.
    async fn spawn_test_server(
        expect_auth: Option<String>,
        response_body: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<Result<(), String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/rpc");

        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.map_err(|e| e.to_string())?;
            let request = String::from_utf8_lossy(&buf[..n]).to_string();

            // Confirm auth header if expected.
            if let Some(expected) = expect_auth
                && !request
                    .lines()
                    .any(|l| l.eq_ignore_ascii_case(&format!("authorization: {expected}")))
            {
                return Err(format!(
                    "expected auth header `{expected}` not found in:\n{request}"
                ));
            }

            // Build the HTTP response.
            let body = serde_json::to_string(&response_body).unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            sock.flush().await.map_err(|e| e.to_string())?;
            Ok(())
        });

        (url, handle)
    }

    #[tokio::test]
    async fn http_transport_no_auth_round_trip() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "tools": [] }
        });
        let (url, server) = spawn_test_server(None, response).await;

        let mut transport = HttpTransport::new(url, Box::new(NoAuth)).unwrap();
        let resp = transport
            .request("tools/list", None)
            .await
            .expect("request");
        assert!(resp.error.is_none());
        let result = resp.result.expect("result");
        assert!(result.get("tools").is_some());

        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn http_transport_bearer_sends_authorization_header() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "ok": true }
        });
        let (url, server) =
            spawn_test_server(Some("Bearer test-token".to_string()), response).await;

        // Build a vault with one entry containing the bearer token.
        // Use open_with_key with a deterministic test key — bypasses
        // the keychain so the test doesn't depend on OS state.
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        // 64 hex chars = 32 raw bytes, which is what the vault's
        // crypto module expects.
        let device_key = wirken_vault::VaultSecret::new("a".repeat(64));
        let store = wirken_vault::CredentialStore::open_with_key(&vault_path, device_key).unwrap();
        let secret = wirken_vault::VaultSecret::new("test-token".into());
        store
            .store("linear-token", "test", &secret, None, None)
            .unwrap();

        let vault: Arc<Mutex<Option<wirken_vault::CredentialStore>>> =
            Arc::new(Mutex::new(Some(store)));
        let auth = BearerAuth::new("linear-token".into(), vault);
        let mut transport = HttpTransport::new(url, Box::new(auth)).unwrap();

        let resp = transport
            .request("tools/list", None)
            .await
            .expect("request");
        assert!(resp.error.is_none());

        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn http_transport_rejects_non_localhost_http() {
        // Plain http:// to a non-localhost host must be rejected at
        // construction time. Slice 2 enforces HTTPS for remote URLs.
        let result = HttpTransport::new("http://example.com/rpc".to_string(), Box::new(NoAuth));
        assert!(result.is_err());
    }
}

mod oauth_test {
    use crate::oauth::{OAuthCredential, load_oauth, lookup_provider, provider_names, store_oauth};

    #[test]
    fn provider_registry_has_known_entries() {
        for name in provider_names() {
            assert!(lookup_provider(name).is_some(), "missing provider '{name}'");
        }
        assert!(lookup_provider("nonexistent").is_none());
    }

    #[test]
    fn oauth_credential_round_trips_through_vault() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        let device_key = wirken_vault::VaultSecret::new("a".repeat(64));
        let store = wirken_vault::CredentialStore::open_with_key(&vault_path, device_key).unwrap();

        let cred = OAuthCredential {
            access_token: "AT-deadbeef".into(),
            refresh_token: "RT-cafebabe".into(),
            expires_at: 1_700_000_000,
            scope: "read write".into(),
            provider: "linear".into(),
        };
        store_oauth(&store, "linear-oauth", &cred).unwrap();
        let loaded = load_oauth(&store, "linear-oauth").unwrap();
        assert_eq!(loaded.access_token, "AT-deadbeef");
        assert_eq!(loaded.refresh_token, "RT-cafebabe");
        assert_eq!(loaded.expires_at, 1_700_000_000);
        assert_eq!(loaded.scope, "read write");
        assert_eq!(loaded.provider, "linear");
    }

    #[test]
    fn store_oauth_replaces_existing_entry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        let device_key = wirken_vault::VaultSecret::new("a".repeat(64));
        let store = wirken_vault::CredentialStore::open_with_key(&vault_path, device_key).unwrap();

        let v1 = OAuthCredential {
            access_token: "first".into(),
            refresh_token: "rt1".into(),
            expires_at: 1,
            scope: "".into(),
            provider: "linear".into(),
        };
        store_oauth(&store, "linear-oauth", &v1).unwrap();

        let v2 = OAuthCredential {
            access_token: "second".into(),
            refresh_token: "rt2".into(),
            expires_at: 2,
            scope: "".into(),
            provider: "linear".into(),
        };
        store_oauth(&store, "linear-oauth", &v2).unwrap();

        let loaded = load_oauth(&store, "linear-oauth").unwrap();
        assert_eq!(loaded.access_token, "second");
        assert_eq!(loaded.expires_at, 2);
    }
}

#[tokio::test]
async fn server_rejects_garbage_first_frame() {
    // In version 2 the server speaks first (AuthChallenge), then
    // reads the client's AuthResponse. If the client sends garbage
    // instead of a well-formed AuthResponse, the server must drop
    // the connection without writing a HelloAck.
    let tmp = TempDir::new().unwrap();
    let socket_path = tmp.path().join("mcp-proxy.sock");
    let registry = Arc::new(Mutex::new(ProxyRegistry::new()));

    let server_socket = socket_path.clone();
    let server_registry = registry.clone();
    let server_handle = tokio::spawn(async move {
        let _ = server::serve(server_socket, server_registry).await;
    });

    for _ in 0..100 {
        if socket_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let mut stream = UnixStream::connect(&socket_path).await.unwrap();

    // Read and discard the challenge.
    let _challenge: AuthChallenge = read_one_line(&mut stream).await;

    // Send garbage.
    stream.write_all(b"not json at all\n").await.unwrap();

    // Server should drop the connection without writing a HelloAck.
    let mut buf = [0u8; 1];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    assert_eq!(
        n, 0,
        "expected EOF after malformed auth response, got {n} bytes"
    );

    server_handle.abort();
}

async fn read_one_line<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> T {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.unwrap();
        if n == 0 {
            panic!("EOF before newline");
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    let s = String::from_utf8(buf).unwrap();
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {s}: {e}"))
}

// ---------------------------------------------------------------------------
// Handshake payload: domain + agent_id binding
// ---------------------------------------------------------------------------

#[test]
fn handshake_payload_binds_agent_id() {
    use crate::wire::handshake_signed_payload;
    let nonce = [7u8; 32];
    let a = handshake_signed_payload("agent-a", &nonce);
    let b = handshake_signed_payload("agent-b", &nonce);
    assert_ne!(a, b, "payload must differ when agent_id differs");
}

#[test]
fn handshake_payload_binds_nonce() {
    use crate::wire::handshake_signed_payload;
    let n1 = [1u8; 32];
    let n2 = [2u8; 32];
    assert_ne!(
        handshake_signed_payload("agent", &n1),
        handshake_signed_payload("agent", &n2),
        "payload must differ when nonce differs"
    );
}

#[test]
fn handshake_payload_includes_domain_prefix() {
    use crate::wire::{HANDSHAKE_DOMAIN, handshake_signed_payload};
    let p = handshake_signed_payload("agent", &[0u8; 32]);
    assert!(
        p.starts_with(HANDSHAKE_DOMAIN),
        "payload must be domain-prefixed so it cannot be replayed on another protocol"
    );
}
