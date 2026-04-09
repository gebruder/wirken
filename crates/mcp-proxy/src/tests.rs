use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use crate::mcp_registry::ProxyRegistry;
use crate::server;
use crate::wire::{Hello, HelloAck, HelloAckKind, HelloKind, PROTOCOL_VERSION, Request, Response};

#[test]
fn hello_round_trip() {
    let h = Hello {
        kind: HelloKind::Hello,
        protocol_version: PROTOCOL_VERSION,
        agent_id: "work".into(),
    };
    let s = serde_json::to_string(&h).unwrap();
    let parsed: Hello = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed.kind, HelloKind::Hello);
    assert_eq!(parsed.agent_id, "work");
    assert_eq!(parsed.protocol_version, PROTOCOL_VERSION);
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
async fn server_round_trip_empty_registry() {
    let tmp = TempDir::new().unwrap();
    let socket_path = tmp.path().join("mcp-proxy.sock");

    let registry = Arc::new(Mutex::new(ProxyRegistry::new()));
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

    // Hello
    let hello = Hello {
        kind: HelloKind::Hello,
        protocol_version: PROTOCOL_VERSION,
        agent_id: "test-agent".into(),
    };
    let mut bytes = serde_json::to_vec(&hello).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).await.unwrap();

    let ack: HelloAck = read_one_line(&mut stream).await;
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
async fn server_rejects_protocol_version_mismatch() {
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

    let hello = Hello {
        kind: HelloKind::Hello,
        protocol_version: 9999, // bogus
        agent_id: "test-agent".into(),
    };
    let mut bytes = serde_json::to_vec(&hello).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).await.unwrap();

    // Server should drop the connection without responding.
    let mut buf = [0u8; 1];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    assert_eq!(
        n, 0,
        "expected EOF after protocol version mismatch, got {n} bytes"
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
