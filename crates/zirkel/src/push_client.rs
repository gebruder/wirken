//! Client for the orchestrator → gateway push socket.
//!
//! Connects to `<data_dir>/sockets/orchestrator.sock` (the same path
//! the running gateway daemon binds in `wirken run`), sends one
//! line-delimited JSON [`OrchestratorPushRequest`], reads one
//! [`OrchestratorPushResponse`], and disconnects.
//!
//! See `crates/ipc/src/orchestrator.rs` for the wire types and the
//! "this is not an adapter" trust posture; see
//! `crates/cli/src/commands/run.rs` for the server side.

use std::path::Path;

use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use wirken_ipc::orchestrator::{OrchestratorPushRequest, OrchestratorPushResponse};

#[derive(Debug, Error)]
pub enum PushError {
    #[error("connect to {path}: {source}")]
    Connect {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("gateway returned no response (connection closed before reply)")]
    NoResponse,
    #[error("gateway rejected push: {0}")]
    Rejected(String),
}

/// Push one outbound message to the running gateway.
///
/// On success the gateway has handed the frame to the live adapter
/// writer for `channel`; the adapter is responsible for the actual
/// delivery to the third-party platform. A successful return here
/// therefore means "queued for the adapter," not "delivered to the
/// recipient."
pub async fn push(
    socket_path: &Path,
    channel: &str,
    conversation_id: &str,
    text: &str,
) -> Result<(), PushError> {
    push_with_reply_to(socket_path, channel, conversation_id, text, "").await
}

/// Same as [`push`] but lets the caller set `reply_to_id` (Slack
/// thread root, Telegram reply target, etc.). Empty string means
/// "no thread."
pub async fn push_with_reply_to(
    socket_path: &Path,
    channel: &str,
    conversation_id: &str,
    text: &str,
    reply_to_id: &str,
) -> Result<(), PushError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| PushError::Connect {
            path: socket_path.display().to_string(),
            source: e,
        })?;
    let (reader, mut writer) = stream.into_split();

    let req = OrchestratorPushRequest {
        channel: channel.to_string(),
        conversation_id: conversation_id.to_string(),
        text: text.to_string(),
        reply_to_id: reply_to_id.to_string(),
    };
    let mut line = serde_json::to_string(&req)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    // Half-close so the server's `read_line` returns rather than
    // blocking; we still hold the read half.
    writer.shutdown().await.ok();

    let mut br = BufReader::new(reader);
    let mut resp_line = String::new();
    let n = br.read_line(&mut resp_line).await?;
    if n == 0 {
        return Err(PushError::NoResponse);
    }
    let resp: OrchestratorPushResponse = serde_json::from_str(resp_line.trim_end())?;
    if resp.ok {
        Ok(())
    } else {
        Err(PushError::Rejected(
            resp.error.unwrap_or_else(|| "(no message)".into()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    /// Spin up a fake server on a temp socket that reads one JSON
    /// line and writes back a fixed response.
    async fn spawn_fake_server(
        socket_path: std::path::PathBuf,
        response: OrchestratorPushResponse,
    ) -> tokio::task::JoinHandle<Option<OrchestratorPushRequest>> {
        let listener = UnixListener::bind(&socket_path).expect("bind fake server");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.ok()?;
            let (reader, mut writer) = stream.into_split();
            let mut br = BufReader::new(reader);
            let mut line = String::new();
            br.read_line(&mut line).await.ok()?;
            let req: OrchestratorPushRequest = serde_json::from_str(line.trim_end()).ok()?;
            let mut out = serde_json::to_string(&response).unwrap();
            out.push('\n');
            writer.write_all(out.as_bytes()).await.ok()?;
            writer.shutdown().await.ok();
            Some(req)
        })
    }

    #[tokio::test]
    async fn push_sends_request_and_parses_ok_response() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("orch.sock");
        let server = spawn_fake_server(
            sock.clone(),
            OrchestratorPushResponse {
                ok: true,
                error: None,
            },
        )
        .await;

        push(&sock, "signal", "+15551234567", "hi").await.unwrap();
        let req = server.await.unwrap().expect("server received request");
        assert_eq!(req.channel, "signal");
        assert_eq!(req.conversation_id, "+15551234567");
        assert_eq!(req.text, "hi");
        assert_eq!(req.reply_to_id, "");
    }

    #[tokio::test]
    async fn push_surfaces_rejected_response() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("orch.sock");
        let _server = spawn_fake_server(
            sock.clone(),
            OrchestratorPushResponse {
                ok: false,
                error: Some("no adapter connected on channel 'signal'".into()),
            },
        )
        .await;

        let err = push(&sock, "signal", "+15551234567", "hi")
            .await
            .unwrap_err();
        match err {
            PushError::Rejected(msg) => {
                assert!(msg.contains("no adapter connected"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn push_with_reply_to_propagates() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("orch.sock");
        let server = spawn_fake_server(
            sock.clone(),
            OrchestratorPushResponse {
                ok: true,
                error: None,
            },
        )
        .await;

        push_with_reply_to(&sock, "slack", "C123", "hello", "1234.5678")
            .await
            .unwrap();
        let req = server.await.unwrap().unwrap();
        assert_eq!(req.reply_to_id, "1234.5678");
    }

    #[tokio::test]
    async fn missing_socket_returns_connect_error() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("does-not-exist.sock");
        let err = push(&sock, "signal", "+1", "hi").await.unwrap_err();
        assert!(matches!(err, PushError::Connect { .. }));
    }
}
