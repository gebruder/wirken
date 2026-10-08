//! Operator ↔ gateway handshake for the line-delimited JSON sockets,
//! `orchestrator.sock` and `gateway-permissions.sock`.
//!
//! An operator tool (the `wirken` CLI, `wirken-zirkel`) signs a fresh
//! gateway challenge with the operator key, and the gateway accepts
//! only the key it pinned at startup. What that buys is attribution and
//! refusal, not confidentiality. Every push and every approval decision
//! is recorded against a verified key, and a process running as the
//! operator's user that does not hold the key is refused. A process
//! that can read the key file, which is any process at that UID, can
//! sign; the separation that would stop it is a different user.
//!
//! Wire, one JSON object per line:
//!
//! ```text
//! gateway  -> {"challenge": "<64 hex>"}
//! operator -> {"public_key": "<64 hex>", "signature": "<128 hex>"}
//! gateway  -> {"handshake": "ok"} | {"handshake": "refused", "reason": "..."}
//! ```
//!
//! The socket's request and response follow on the same connection.
//! The signature covers `DOMAIN || socket || 0x00 || nonce`, so one
//! signed for one socket does not verify on the other, nor on the
//! adapter or MCP handshakes.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

const DOMAIN: &[u8] = b"wirken-ipc-operator-handshake-v1\x00";
const NONCE_SIZE: usize = 32;
/// How long the gateway waits for the signed answer.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// The socket names the signature is bound to.
pub const ORCHESTRATOR_SOCKET: &str = "orchestrator";
pub const PERMISSIONS_SOCKET: &str = "permissions";

/// Where the operator key lives under the data dir.
pub fn operator_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("operator").join("operator.key")
}

/// The operator's Ed25519 key, stored hex-encoded at
/// [`operator_key_path`] with owner-only permissions.
pub struct OperatorKey {
    signing: SigningKey,
}

impl OperatorKey {
    /// Load the key, creating it on first use. The gateway and the
    /// operator tools all call this, so whichever runs first creates it
    /// and the rest read the same file.
    pub fn load_or_create(data_dir: &Path) -> std::io::Result<Self> {
        let path = operator_key_path(data_dir);
        match std::fs::read_to_string(&path) {
            Ok(body) => Self::parse(&body, &path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::create(&path),
            Err(e) => Err(e),
        }
    }

    fn parse(body: &str, path: &Path) -> std::io::Result<Self> {
        let bytes = hex_decode::<32>(body.trim()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: not a 32-byte hex key", path.display()),
            )
        })?;
        Ok(Self::from_bytes(&bytes))
    }

    fn create(path: &Path) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        let key = Self::generate();
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(path) {
            Ok(mut file) => {
                file.write_all(hex_encode(&key.signing.to_bytes()).as_bytes())?;
                Ok(key)
            }
            // Another process created it first: use theirs.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Self::parse(&std::fs::read_to_string(path)?, path)
            }
            Err(e) => Err(e),
        }
    }

    pub fn generate() -> Self {
        let secret: [u8; 32] = rand::rng().random();
        Self::from_bytes(&secret)
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(secret),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Short identifier recorded with what this key did.
    pub fn key_id(&self) -> String {
        key_id(&self.verifying_key())
    }
}

/// The first eight bytes of the public key, hex. Enough to tell keys
/// apart on an audit row; the full key is in the data dir.
pub fn key_id(key: &VerifyingKey) -> String {
    hex_encode(&key.to_bytes()[..8])
}

#[derive(Debug, thiserror::Error)]
pub enum OperatorHandshakeError {
    #[error("operator handshake I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("operator handshake: connection closed")]
    Closed,
    #[error("operator handshake: malformed message: {0}")]
    Malformed(String),
    #[error("operator handshake: no answer within {0:?}")]
    Timeout(Duration),
    #[error("operator handshake: key is not the operator key")]
    UnknownKey,
    #[error("operator handshake: signature does not verify")]
    BadSignature,
    #[error("operator handshake refused by the gateway: {0}")]
    Refused(String),
}

impl OperatorHandshakeError {
    /// Stable reason for audit rows and the refusal line.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::Closed => "closed",
            Self::Malformed(_) => "malformed",
            Self::Timeout(_) => "timeout",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::Refused(_) => "refused",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Challenge {
    challenge: String,
}

#[derive(Serialize, Deserialize)]
struct Answer {
    public_key: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "handshake", rename_all = "snake_case")]
enum Verdict {
    Ok,
    Refused { reason: String },
}

fn signed_payload(socket: &str, nonce: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DOMAIN.len() + socket.len() + 1 + nonce.len());
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(socket.as_bytes());
    msg.push(0x00);
    msg.extend_from_slice(nonce);
    msg
}

async fn write_line<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), OperatorHandshakeError> {
    let mut line = serde_json::to_string(value)
        .map_err(|e| OperatorHandshakeError::Malformed(e.to_string()))?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_line<R: AsyncBufRead + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<T, OperatorHandshakeError> {
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Err(OperatorHandshakeError::Closed);
    }
    serde_json::from_str(line.trim_end())
        .map_err(|e| OperatorHandshakeError::Malformed(e.to_string()))
}

/// The operator side: answer the gateway's challenge with `key`.
pub async fn handshake_as_operator<R, W>(
    reader: &mut R,
    writer: &mut W,
    key: &OperatorKey,
    socket: &str,
) -> Result<(), OperatorHandshakeError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let challenge: Challenge = read_line(reader).await?;
    let nonce = hex_decode::<NONCE_SIZE>(&challenge.challenge)
        .ok_or_else(|| OperatorHandshakeError::Malformed("challenge".into()))?;
    let signature = key.signing.sign(&signed_payload(socket, &nonce));
    write_line(
        writer,
        &Answer {
            public_key: hex_encode(&key.verifying_key().to_bytes()),
            signature: hex_encode(&signature.to_bytes()),
        },
    )
    .await?;
    match read_line::<_, Verdict>(reader).await? {
        Verdict::Ok => Ok(()),
        Verdict::Refused { reason } => Err(OperatorHandshakeError::Refused(reason)),
    }
}

/// The gateway side: challenge the caller and accept only `expected`.
/// On success returns the caller's [`key_id`]; on failure the caller has
/// been sent a refusal line, and the error says why.
pub async fn handshake_as_gateway<R, W>(
    reader: &mut R,
    writer: &mut W,
    expected: &VerifyingKey,
    socket: &str,
) -> Result<String, OperatorHandshakeError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let nonce: [u8; NONCE_SIZE] = rand::rng().random();
    write_line(
        writer,
        &Challenge {
            challenge: hex_encode(&nonce),
        },
    )
    .await?;
    let verdict = match tokio::time::timeout(ANSWER_TIMEOUT, read_line::<_, Answer>(reader)).await {
        Err(_) => Err(OperatorHandshakeError::Timeout(ANSWER_TIMEOUT)),
        Ok(Err(e)) => Err(e),
        Ok(Ok(answer)) => verify(&answer, expected, socket, &nonce),
    };
    match &verdict {
        Ok(_) => write_line(writer, &Verdict::Ok).await?,
        Err(e) => {
            let _ = write_line(
                writer,
                &Verdict::Refused {
                    reason: e.reason().to_string(),
                },
            )
            .await;
        }
    }
    verdict
}

fn verify(
    answer: &Answer,
    expected: &VerifyingKey,
    socket: &str,
    nonce: &[u8],
) -> Result<String, OperatorHandshakeError> {
    let public = hex_decode::<32>(&answer.public_key)
        .ok_or_else(|| OperatorHandshakeError::Malformed("public_key".into()))?;
    if public != expected.to_bytes() {
        return Err(OperatorHandshakeError::UnknownKey);
    }
    let signature = hex_decode::<64>(&answer.signature)
        .ok_or_else(|| OperatorHandshakeError::Malformed("signature".into()))?;
    expected
        .verify_strict(
            &signed_payload(socket, nonce),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| OperatorHandshakeError::BadSignature)?;
    Ok(key_id(expected))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let bytes: Vec<u8> = s
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect::<Option<_>>()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{BufReader, duplex, split};

    #[test]
    fn hex_decode_rejects_non_ascii() {
        // 64 bytes, the expected length, with every two-byte chunk
        // splitting a character.
        let hex = format!("a{}a", "\u{e9}".repeat(31));
        assert_eq!(hex.len(), 64);
        assert!(hex_decode::<32>(&hex).is_none());
    }

    /// Run both sides over an in-memory pipe.
    async fn handshake(
        operator_key: &OperatorKey,
        operator_socket: &str,
        expected: &VerifyingKey,
        gateway_socket: &str,
    ) -> (
        Result<(), OperatorHandshakeError>,
        Result<String, OperatorHandshakeError>,
    ) {
        let (a, b) = duplex(4096);
        let (ar, mut aw) = split(a);
        let (br, mut bw) = split(b);
        let mut ar = BufReader::new(ar);
        let mut br = BufReader::new(br);
        tokio::join!(
            handshake_as_operator(&mut ar, &mut aw, operator_key, operator_socket),
            handshake_as_gateway(&mut br, &mut bw, expected, gateway_socket),
        )
    }

    #[tokio::test]
    async fn the_operator_key_is_accepted_and_named() {
        let key = OperatorKey::generate();
        let (operator, gateway) = handshake(
            &key,
            ORCHESTRATOR_SOCKET,
            &key.verifying_key(),
            ORCHESTRATOR_SOCKET,
        )
        .await;
        operator.unwrap();
        assert_eq!(gateway.unwrap(), key.key_id());
    }

    #[tokio::test]
    async fn another_key_is_refused_and_told_so() {
        let operator = OperatorKey::generate();
        let pinned = OperatorKey::generate().verifying_key();
        let (op, gw) = handshake(&operator, PERMISSIONS_SOCKET, &pinned, PERMISSIONS_SOCKET).await;
        assert!(
            matches!(gw, Err(OperatorHandshakeError::UnknownKey)),
            "{gw:?}"
        );
        assert!(
            matches!(op, Err(OperatorHandshakeError::Refused(ref r)) if r == "unknown_key"),
            "{op:?}"
        );
    }

    #[tokio::test]
    async fn a_signature_for_one_socket_does_not_open_the_other() {
        let key = OperatorKey::generate();
        let (_, gw) = handshake(
            &key,
            ORCHESTRATOR_SOCKET,
            &key.verifying_key(),
            PERMISSIONS_SOCKET,
        )
        .await;
        assert!(
            matches!(gw, Err(OperatorHandshakeError::BadSignature)),
            "{gw:?}"
        );
    }

    #[tokio::test]
    async fn a_caller_that_sends_the_request_instead_is_refused() {
        // The old protocol: the request line straight away.
        let key = OperatorKey::generate();
        let (a, b) = duplex(4096);
        let (_ar, mut aw) = split(a);
        let (br, mut bw) = split(b);
        let mut br = BufReader::new(br);
        aw.write_all(b"{\"channel\":\"signal\",\"conversation_id\":\"x\",\"text\":\"hi\"}\n")
            .await
            .unwrap();
        let gw =
            handshake_as_gateway(&mut br, &mut bw, &key.verifying_key(), ORCHESTRATOR_SOCKET).await;
        assert!(
            matches!(gw, Err(OperatorHandshakeError::Malformed(_))),
            "{gw:?}"
        );
    }

    #[test]
    fn the_key_is_created_once_owner_only_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let first = OperatorKey::load_or_create(dir.path()).unwrap();
        let again = OperatorKey::load_or_create(dir.path()).unwrap();
        assert_eq!(first.key_id(), again.key_id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(operator_key_path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
