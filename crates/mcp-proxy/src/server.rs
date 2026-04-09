//! Unix domain socket server. Listens for agent connections, runs the
//! NDJSON wire protocol from `wire.rs`, dispatches to `ProxyRegistry`.
//!
//! NOTE: this slice does NOT authenticate connecting agents — the
//! filesystem ACL on the socket file (mode 0600 in the user's data
//! directory) is the trust boundary. Identity-based auth using the
//! existing Ed25519 handshake from `wirken-ipc` is planned for a
//! follow-up commit. The threat we are defending against right now
//! ("memory bug in the agent process leaks credentials") is solved
//! by the OS process boundary alone; a sibling-process threat is out
//! of scope for slice 1.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::error::ProxyError;
use crate::mcp_registry::ProxyRegistry;
use crate::wire::{
    Hello, HelloAck, HelloAckKind, HelloKind, MAX_FRAME_BYTES, PROTOCOL_VERSION, Request, Response,
    ToolDefWire,
};

/// Bind a UnixListener at `socket_path` with mode 0600 and run the
/// accept loop. The loop runs until the listener errors.
pub async fn serve(
    socket_path: PathBuf,
    registry: Arc<Mutex<ProxyRegistry>>,
) -> Result<(), ProxyError> {
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&socket_path)?;

    // Tighten permissions on the socket file. Per-user trust boundary.
    set_socket_perms(&socket_path)?;

    tracing::info!("MCP proxy listening on {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let reg = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, reg).await {
                        tracing::warn!("MCP proxy connection error: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::error!("MCP proxy accept error: {e}");
                return Err(ProxyError::Io(e));
            }
        }
    }
}

#[cfg(unix)]
fn set_socket_perms(path: &Path) -> Result<(), ProxyError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_socket_perms(_path: &Path) -> Result<(), ProxyError> {
    Ok(())
}

async fn handle_connection(
    stream: UnixStream,
    registry: Arc<Mutex<ProxyRegistry>>,
) -> Result<(), ProxyError> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // First frame must be Hello.
    let agent_id = match read_line(&mut reader).await? {
        Some(line) => {
            let hello: Hello = serde_json::from_str(&line)
                .map_err(|e| ProxyError::Protocol(format!("hello parse: {e}")))?;
            if hello.kind != HelloKind::Hello {
                return Err(ProxyError::Protocol(format!(
                    "expected hello, got {:?}",
                    hello.kind
                )));
            }
            if hello.protocol_version != PROTOCOL_VERSION {
                return Err(ProxyError::Protocol(format!(
                    "protocol version mismatch: client {} proxy {}",
                    hello.protocol_version, PROTOCOL_VERSION
                )));
            }
            hello.agent_id
        }
        None => return Err(ProxyError::Protocol("connection closed before hello".into())),
    };

    let has_servers = registry.lock().await.has_agent(&agent_id);

    let ack = HelloAck {
        kind: HelloAckKind::HelloAck,
        protocol_version: PROTOCOL_VERSION,
        has_servers,
    };
    write_line(&mut writer, &ack).await?;

    tracing::info!("MCP proxy: agent '{agent_id}' connected (has_servers={has_servers})");

    // Request loop.
    loop {
        let line = match read_line(&mut reader).await? {
            Some(l) => l,
            None => {
                tracing::debug!("MCP proxy: agent '{agent_id}' disconnected");
                return Ok(());
            }
        };

        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err = Response::Error {
                    id: 0,
                    message: format!("malformed request: {e}"),
                };
                write_line(&mut writer, &err).await?;
                continue;
            }
        };

        let response = dispatch(&agent_id, request, &registry).await;

        let is_shutdown = matches!(response, Response::ShutdownAck { .. });
        write_line(&mut writer, &response).await?;
        if is_shutdown {
            return Ok(());
        }
    }
}

async fn dispatch(
    agent_id: &str,
    request: Request,
    registry: &Arc<Mutex<ProxyRegistry>>,
) -> Response {
    match request {
        Request::ListTools { id } => {
            let defs = registry.lock().await.definitions(agent_id);
            let tools: Vec<ToolDefWire> = defs.into_iter().collect();
            Response::ListToolsResult { id, tools }
        }
        Request::CallTool {
            id,
            name,
            arguments,
        } => {
            let mut reg = registry.lock().await;
            match reg.execute(agent_id, &name, &arguments).await {
                Ok(result) => Response::CallToolResult {
                    id,
                    output: result.output,
                    success: result.success,
                },
                Err(e) => Response::Error {
                    id,
                    message: e.to_string(),
                },
            }
        }
        Request::Shutdown { id } => Response::ShutdownAck { id },
    }
}

/// Read one NDJSON line from the stream, enforcing the size cap.
/// Returns Ok(None) on clean EOF.
async fn read_line(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
) -> Result<Option<String>, ProxyError> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let mut byte = [0u8; 1];
        match tokio::io::AsyncReadExt::read(reader, &mut byte).await {
            Ok(0) => {
                if buf.is_empty() {
                    return Ok(None);
                }
                return Err(ProxyError::Protocol("eof in mid-line".into()));
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    let line = String::from_utf8(buf)
                        .map_err(|e| ProxyError::Protocol(format!("non-utf8 line: {e}")))?;
                    return Ok(Some(line));
                }
                if buf.len() >= MAX_FRAME_BYTES {
                    return Err(ProxyError::Protocol(format!(
                        "frame exceeds {MAX_FRAME_BYTES} bytes"
                    )));
                }
                buf.push(byte[0]);
            }
            Err(e) => return Err(ProxyError::Io(e)),
        }
    }
}

async fn write_line<T: serde::Serialize>(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    value: &T,
) -> Result<(), ProxyError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|e| ProxyError::Protocol(format!("serialize: {e}")))?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
