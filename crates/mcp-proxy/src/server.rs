//! Unix domain socket server. Listens for agent connections, runs the
//! NDJSON wire protocol from `wire.rs`, dispatches to `ProxyRegistry`.
//!
//! Protocol version 2 authenticates every connecting agent via an
//! Ed25519 challenge-response handshake. The filesystem ACL on the
//! socket file (mode 0600 in the user's data directory) is a second
//! line of defense — the authoritative trust boundary is the
//! registered public key for each agent_id in the [`ProxyRegistry`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use wirken_ipc::BoxStream;

use crate::error::ProxyError;
use crate::mcp_registry::ProxyRegistry;
use crate::wire::{
    AuthChallenge, AuthChallengeKind, AuthResponse, AuthResponseKind, CHALLENGE_NONCE_BYTES,
    HelloAck, HelloAckKind, MAX_FRAME_BYTES, PROTOCOL_VERSION, Request, Response, ToolDefWire,
    handshake_signed_payload,
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

    let mut listener =
        wirken_ipc::bind(&socket_path).map_err(|e| ProxyError::Io(std::io::Error::other(e)))?;

    // Tighten permissions on the socket file. Per-user trust boundary.
    set_socket_perms(&socket_path)?;

    tracing::info!("MCP proxy listening on {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok(stream) => {
                let reg = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, reg).await {
                        tracing::warn!("MCP proxy connection error: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::error!("MCP proxy accept error: {e}");
                return Err(ProxyError::Io(std::io::Error::other(e)));
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
    stream: BoxStream,
    registry: Arc<Mutex<ProxyRegistry>>,
) -> Result<(), ProxyError> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    // Ed25519 challenge-response. The server speaks first so every
    // connection gets a fresh nonce the client must sign — this
    // prevents an offline attacker from replaying a captured
    // AuthResponse.
    let agent_id = match authenticate(&mut reader, &mut writer, &registry).await {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!("MCP proxy auth failed: {e}");
            // Drop the connection without writing anything further.
            // Returning here means the client sees a clean EOF with
            // no HelloAck, which is its signal to disconnect.
            return Err(e);
        }
    };

    let has_servers = registry.lock().await.has_agent(&agent_id);

    let ack = HelloAck {
        kind: HelloAckKind::HelloAck,
        protocol_version: PROTOCOL_VERSION,
        has_servers,
    };
    write_line(&mut writer, &ack).await?;

    tracing::info!("MCP proxy: agent '{agent_id}' authenticated (has_servers={has_servers})");

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

/// Run the Ed25519 challenge-response handshake. Returns the
/// authenticated agent_id on success, or a [`ProxyError::Protocol`]
/// on any failure. Callers drop the connection without writing
/// anything further on error.
async fn authenticate<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    registry: &Arc<Mutex<ProxyRegistry>>,
) -> Result<String, ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // 1. Generate and send a fresh challenge.
    let mut nonce = [0u8; CHALLENGE_NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce);
    let nonce_hex = hex_encode(&nonce);

    let challenge = AuthChallenge {
        kind: AuthChallengeKind::AuthChallenge,
        protocol_version: PROTOCOL_VERSION,
        nonce: nonce_hex,
    };
    write_line(writer, &challenge).await?;

    // 2. Read the client's AuthResponse.
    let line = read_line(reader)
        .await?
        .ok_or_else(|| ProxyError::Protocol("connection closed before auth response".into()))?;
    let response: AuthResponse = serde_json::from_str(&line)
        .map_err(|e| ProxyError::Protocol(format!("auth response parse: {e}")))?;
    if response.kind != AuthResponseKind::AuthResponse {
        return Err(ProxyError::Protocol(format!(
            "expected auth_response, got {:?}",
            response.kind
        )));
    }

    // 3. Decode the public key and signature.
    let pubkey_bytes = hex_decode_fixed::<32>(&response.public_key)
        .map_err(|e| ProxyError::Protocol(format!("public key decode: {e}")))?;
    let sig_bytes = hex_decode_fixed::<64>(&response.signature)
        .map_err(|e| ProxyError::Protocol(format!("signature decode: {e}")))?;

    // 4. Confirm the agent_id is registered AND the pubkey matches.
    //    Reject before touching the signature so a bogus agent_id
    //    does not leak a timing channel against the verifier.
    {
        let reg = registry.lock().await;
        let registered = reg.get_identity(&response.agent_id).ok_or_else(|| {
            ProxyError::Protocol(format!(
                "agent '{}' is not registered with the MCP proxy",
                response.agent_id
            ))
        })?;
        if registered.to_bytes() != pubkey_bytes {
            return Err(ProxyError::Protocol(format!(
                "agent '{}' presented a public key that does not match its registered identity",
                response.agent_id
            )));
        }
    }

    // 5. Verify the signature over (domain || agent_id || nonce).
    //    See `wire::handshake_signed_payload` for rationale.
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| ProxyError::Protocol(format!("invalid ed25519 public key: {e}")))?;
    let signature = Signature::from_bytes(&sig_bytes);
    let signed = handshake_signed_payload(&response.agent_id, &nonce);
    verifying_key
        .verify(&signed, &signature)
        .map_err(|_| ProxyError::Protocol("ed25519 signature verification failed".into()))?;

    Ok(response.agent_id)
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
async fn read_line<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
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

async fn write_line<W, T>(writer: &mut W, value: &T) -> Result<(), ProxyError>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let mut bytes =
        serde_json::to_vec(value).map_err(|e| ProxyError::Protocol(format!("serialize: {e}")))?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

fn hex_decode_fixed<const N: usize>(hex: &str) -> Result<[u8; N], String> {
    if hex.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, hex.len()));
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("hex decode: {e}"))?;
    }
    Ok(out)
}
