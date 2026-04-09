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
        Request::CallTool { id, name, arguments } => {
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
        Response::CallToolResult { output, success, .. } => {
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
