use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::HandshakeError;
use crate::transport::{FrameReader, FrameWriter};
use crate::wirken_capnp::frame;

const CHALLENGE_NONCE_SIZE: usize = 32;

/// Domain-separated prefix for handshake signatures. Distinct from
/// the MCP proxy's `HANDSHAKE_DOMAIN` so a signature from one
/// handshake cannot be replayed on the other even if the same
/// signing key is reused across both.
const HANDSHAKE_DOMAIN: &[u8] = b"wirken-ipc-adapter-handshake-v1\x00";

/// Build the signed payload. `HANDSHAKE_DOMAIN || adapter_id || 0x00 || nonce`.
/// Binds the signature to (a) this protocol, (b) the claimed
/// adapter identity, and (c) this specific challenge. Without the
/// `adapter_id` binding, a compromise of the pubkey-registration
/// lookup (or any future refactor that loosens per-adapter
/// matching) would let a sig produced for one adapter verify
/// under another. The binding is now at the crypto layer, not
/// only in the lookup.
fn signed_payload(adapter_id: &str, nonce: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + adapter_id.len() + 1 + nonce.len());
    msg.extend_from_slice(HANDSHAKE_DOMAIN);
    msg.extend_from_slice(adapter_id.as_bytes());
    msg.push(0x00);
    msg.extend_from_slice(nonce);
    msg
}

/// An adapter's Ed25519 identity (keypair + identifier).
pub struct AdapterIdentity {
    signing_key: SigningKey,
    adapter_id: String,
}

impl AdapterIdentity {
    /// Generate a new random adapter identity.
    pub fn generate(adapter_id: impl Into<String>) -> Self {
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        Self {
            signing_key,
            adapter_id: adapter_id.into(),
        }
    }

    /// Create from an existing secret key (32 bytes).
    pub fn from_bytes(secret: &[u8; 32], adapter_id: impl Into<String>) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        Self {
            signing_key,
            adapter_id: adapter_id.into(),
        }
    }

    /// Get the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the secret key bytes (32 bytes).
    pub fn secret_key_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    /// Get the adapter identifier.
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    /// Sign a message.
    fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

/// Adapter side of the handshake.
///
/// 1. Receive AuthChallenge (nonce) from gateway
/// 2. Sign nonce with Ed25519 private key
/// 3. Send AuthResponse (public key + signature + adapter ID)
/// 4. Receive AuthResult (accepted/rejected)
pub async fn perform_adapter_handshake<R, W>(
    reader: &mut FrameReader<R>,
    writer: &mut FrameWriter<W>,
    identity: &AdapterIdentity,
) -> Result<(), HandshakeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // 1. Read challenge
    let challenge_msg = reader
        .read_message()
        .await
        .map_err(|e| HandshakeError::Protocol(format!("read challenge: {e}")))?;
    let frame_reader = challenge_msg
        .get_root::<frame::Reader<'_>>()
        .map_err(|e| HandshakeError::Protocol(format!("parse challenge frame: {e}")))?;

    let nonce = match frame_reader
        .which()
        .map_err(|e| HandshakeError::Protocol(format!("challenge frame variant: {e}")))?
    {
        frame::AuthChallenge(challenge) => {
            let c =
                challenge.map_err(|e| HandshakeError::Protocol(format!("read challenge: {e}")))?;
            let nonce = c
                .get_nonce()
                .map_err(|e| HandshakeError::Protocol(format!("get nonce: {e}")))?;
            nonce.to_vec()
        }
        _ => return Err(HandshakeError::Protocol("expected AuthChallenge".into())),
    };

    // 2. Sign (domain || adapter_id || nonce). See `signed_payload`.
    let payload = signed_payload(identity.adapter_id(), &nonce);
    let signature = identity.sign(&payload);

    // 3. Send response
    let mut response_msg = capnp::message::Builder::new_default();
    {
        let frame_builder = response_msg.init_root::<frame::Builder<'_>>();
        let mut auth_resp = frame_builder.init_auth_response();
        auth_resp.set_public_key(&identity.public_key_bytes());
        auth_resp.set_signature(&signature.to_bytes());
        auth_resp.set_adapter_id(&identity.adapter_id);
    }
    writer
        .write_message(&response_msg)
        .await
        .map_err(|e| HandshakeError::Protocol(format!("write response: {e}")))?;

    // 4. Read result
    let result_msg = reader
        .read_message()
        .await
        .map_err(|e| HandshakeError::Protocol(format!("read result: {e}")))?;
    let result_reader = result_msg
        .get_root::<frame::Reader<'_>>()
        .map_err(|e| HandshakeError::Protocol(format!("parse result frame: {e}")))?;

    match result_reader
        .which()
        .map_err(|e| HandshakeError::Protocol(format!("result frame variant: {e}")))?
    {
        frame::AuthResult(result) => {
            let r = result.map_err(|e| HandshakeError::Protocol(format!("read result: {e}")))?;
            if r.get_accepted() {
                Ok(())
            } else {
                let reason = r
                    .get_reason()
                    .map_err(|e| HandshakeError::Protocol(format!("get reason: {e}")))?
                    .to_string()
                    .unwrap_or_default();
                Err(HandshakeError::Rejected(reason))
            }
        }
        _ => Err(HandshakeError::Protocol("expected AuthResult".into())),
    }
}

/// Gateway side of the handshake.
///
/// 1. Send AuthChallenge (random nonce)
/// 2. Receive AuthResponse (public key + signature + adapter ID)
/// 3. Verify signature against registered public key
/// 4. Send AuthResult
///
/// `verify_adapter` is called with (adapter_id, public_key_bytes) and should
/// return Ok(()) if the adapter is registered and the public key matches.
///
/// Accepts adapters only; [`perform_gateway_peer_handshake`] also
/// accepts the terminal channel.
pub async fn perform_gateway_handshake<R, W, F>(
    reader: &mut FrameReader<R>,
    writer: &mut FrameWriter<W>,
    verify_adapter: F,
) -> Result<(String, [u8; 32]), HandshakeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnOnce(&str, &[u8; 32]) -> Result<(), HandshakeError>,
{
    // With no operator key the terminal answer is refused as a
    // protocol error, so only an adapter comes back.
    match perform_gateway_peer_handshake(reader, writer, None, verify_adapter, |_| Ok(())).await? {
        GatewayPeer::Adapter {
            adapter_id,
            public_key,
        } => Ok((adapter_id, public_key)),
        GatewayPeer::Terminal { .. } => {
            Err(HandshakeError::Protocol("expected AuthResponse".into()))
        }
    }
}

/// Who completed the handshake on the gateway socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayPeer {
    /// A registered adapter: the id it signed for and its key.
    Adapter {
        adapter_id: String,
        public_key: [u8; 32],
    },
    /// The terminal channel, `wirken chat`, holding the operator key.
    Terminal {
        /// [`crate::operator::key_id`] of the operator key.
        key_id: String,
        public_key: [u8; 32],
        /// The agent asked for, empty for the router's choice. Already
        /// accepted by the caller's `verify_agent`.
        agent: String,
    },
}

/// The answer to the challenge, before it is checked.
enum Answer {
    Adapter {
        adapter_id: String,
        public_key: [u8; 32],
        signature: [u8; 64],
    },
    Terminal {
        public_key: [u8; 32],
        signature: [u8; 64],
        agent: String,
    },
}

fn key_and_signature(pk: &[u8], sig: &[u8]) -> Result<([u8; 32], [u8; 64]), HandshakeError> {
    let public_key: [u8; 32] = pk.try_into().map_err(|_| {
        HandshakeError::Protocol(format!("public key must be 32 bytes, got {}", pk.len()))
    })?;
    let signature: [u8; 64] = sig.try_into().map_err(|_| {
        HandshakeError::Protocol(format!("signature must be 64 bytes, got {}", sig.len()))
    })?;
    Ok((public_key, signature))
}

/// Gateway side of the handshake on the gateway socket, for adapters
/// and for the terminal channel.
///
/// The challenge is the same for both. An adapter answers with
/// `AuthResponse` and is checked as in [`perform_gateway_handshake`].
/// The terminal answers with `TerminalAuthResponse`, signed with the
/// operator key under the operator handshake's domain for
/// [`crate::operator::TERMINAL_SOCKET`]; it is accepted only when
/// `operator_key` is given, only for that key, and only if
/// `verify_agent` accepts the agent it asks for. A terminal that is
/// refused is told why in the `AuthResult`, so `wirken chat` can say
/// it; an adapter that is refused is not, as before.
pub async fn perform_gateway_peer_handshake<R, W, F, G>(
    reader: &mut FrameReader<R>,
    writer: &mut FrameWriter<W>,
    operator_key: Option<&VerifyingKey>,
    verify_adapter: F,
    verify_agent: G,
) -> Result<GatewayPeer, HandshakeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnOnce(&str, &[u8; 32]) -> Result<(), HandshakeError>,
    G: FnOnce(&str) -> Result<(), HandshakeError>,
{
    // 1. Generate and send challenge
    let mut nonce = [0u8; CHALLENGE_NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);

    let mut challenge_msg = capnp::message::Builder::new_default();
    {
        let frame_builder = challenge_msg.init_root::<frame::Builder<'_>>();
        let mut challenge = frame_builder.init_auth_challenge();
        challenge.set_nonce(&nonce);
    }
    writer
        .write_message(&challenge_msg)
        .await
        .map_err(|e| HandshakeError::Protocol(format!("write challenge: {e}")))?;

    // 2. Read response
    let response_msg = reader
        .read_message()
        .await
        .map_err(|e| HandshakeError::Protocol(format!("read response: {e}")))?;
    let response_reader = response_msg
        .get_root::<frame::Reader<'_>>()
        .map_err(|e| HandshakeError::Protocol(format!("parse response frame: {e}")))?;

    let answer = match response_reader
        .which()
        .map_err(|e| HandshakeError::Protocol(format!("response frame variant: {e}")))?
    {
        frame::AuthResponse(response) => {
            let r =
                response.map_err(|e| HandshakeError::Protocol(format!("read response: {e}")))?;
            let pk = r
                .get_public_key()
                .map_err(|e| HandshakeError::Protocol(format!("get public key: {e}")))?;
            let sig = r
                .get_signature()
                .map_err(|e| HandshakeError::Protocol(format!("get signature: {e}")))?;
            let adapter_id = r
                .get_adapter_id()
                .map_err(|e| HandshakeError::Protocol(format!("get adapter id: {e}")))?
                .to_string()
                .map_err(|e| HandshakeError::Protocol(format!("adapter id not utf8: {e}")))?;
            let (public_key, signature) = key_and_signature(pk, sig)?;
            Answer::Adapter {
                adapter_id,
                public_key,
                signature,
            }
        }
        frame::TerminalAuthResponse(response) if operator_key.is_some() => {
            let r =
                response.map_err(|e| HandshakeError::Protocol(format!("read response: {e}")))?;
            let pk = r
                .get_public_key()
                .map_err(|e| HandshakeError::Protocol(format!("get public key: {e}")))?;
            let sig = r
                .get_signature()
                .map_err(|e| HandshakeError::Protocol(format!("get signature: {e}")))?;
            let agent = r
                .get_agent()
                .map_err(|e| HandshakeError::Protocol(format!("get agent: {e}")))?
                .to_string()
                .map_err(|e| HandshakeError::Protocol(format!("agent not utf8: {e}")))?;
            let (public_key, signature) = key_and_signature(pk, sig)?;
            Answer::Terminal {
                public_key,
                signature,
                agent,
            }
        }
        _ => return Err(HandshakeError::Protocol("expected AuthResponse".into())),
    };
    drop(response_msg);

    let peer = match answer {
        Answer::Adapter {
            adapter_id,
            public_key,
            signature,
        } => {
            // 3. Verify the adapter is registered
            verify_adapter(&adapter_id, &public_key)?;

            // 4. Verify the signature over (domain || adapter_id || nonce).
            //    See `signed_payload` for rationale.
            let verifying_key = VerifyingKey::from_bytes(&public_key)
                .map_err(|_| HandshakeError::InvalidSignature)?;
            let payload = signed_payload(&adapter_id, &nonce);
            verifying_key
                .verify_strict(&payload, &Signature::from_bytes(&signature))
                .map_err(|_| HandshakeError::InvalidSignature)?;
            GatewayPeer::Adapter {
                adapter_id,
                public_key,
            }
        }
        Answer::Terminal {
            public_key,
            signature,
            agent,
        } => {
            // The match arm above admits this answer only with a key.
            let Some(expected) = operator_key else {
                return Err(HandshakeError::Protocol("expected AuthResponse".into()));
            };
            let checked = crate::operator::verify_challenge(
                expected,
                &public_key,
                &signature,
                crate::operator::TERMINAL_SOCKET,
                &nonce,
            )
            .map_err(|e| match e {
                crate::operator::OperatorHandshakeError::UnknownKey => {
                    HandshakeError::NotOperatorKey
                }
                _ => HandshakeError::InvalidSignature,
            })
            .and_then(|key_id| verify_agent(&agent).map(|()| key_id));
            match checked {
                Ok(key_id) => GatewayPeer::Terminal {
                    key_id,
                    public_key,
                    agent,
                },
                Err(e) => {
                    let _ = send_rejection(writer, &e.to_string()).await;
                    return Err(e);
                }
            }
        }
    };

    // 5. Send success
    let mut result_msg = capnp::message::Builder::new_default();
    {
        let frame_builder = result_msg.init_root::<frame::Builder<'_>>();
        let mut result = frame_builder.init_auth_result();
        result.set_accepted(true);
        result.set_reason("");
    }
    writer
        .write_message(&result_msg)
        .await
        .map_err(|e| HandshakeError::Protocol(format!("write result: {e}")))?;

    Ok(peer)
}

/// Terminal side of the handshake: answer the gateway's challenge with
/// the operator key, asking for `agent` (empty for the router's
/// choice). A refusal comes back as [`HandshakeError::Rejected`]
/// carrying the gateway's reason.
pub async fn perform_terminal_handshake<R, W>(
    reader: &mut FrameReader<R>,
    writer: &mut FrameWriter<W>,
    key: &crate::operator::OperatorKey,
    agent: &str,
) -> Result<(), HandshakeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let challenge_msg = reader
        .read_message()
        .await
        .map_err(|e| HandshakeError::Protocol(format!("read challenge: {e}")))?;
    let nonce = match challenge_msg
        .get_root::<frame::Reader<'_>>()
        .map_err(|e| HandshakeError::Protocol(format!("parse challenge frame: {e}")))?
        .which()
        .map_err(|e| HandshakeError::Protocol(format!("challenge frame variant: {e}")))?
    {
        frame::AuthChallenge(challenge) => challenge
            .and_then(|c| c.get_nonce())
            .map_err(|e| HandshakeError::Protocol(format!("get nonce: {e}")))?
            .to_vec(),
        _ => return Err(HandshakeError::Protocol("expected AuthChallenge".into())),
    };

    let signature = key.sign_challenge(crate::operator::TERMINAL_SOCKET, &nonce);
    let mut response_msg = capnp::message::Builder::new_default();
    {
        let frame_builder = response_msg.init_root::<frame::Builder<'_>>();
        let mut resp = frame_builder.init_terminal_auth_response();
        resp.set_public_key(&key.verifying_key().to_bytes());
        resp.set_signature(&signature.to_bytes());
        resp.set_agent(agent);
    }
    writer
        .write_message(&response_msg)
        .await
        .map_err(|e| HandshakeError::Protocol(format!("write response: {e}")))?;

    let result_msg = reader
        .read_message()
        .await
        .map_err(|e| HandshakeError::Protocol(format!("read result: {e}")))?;
    match result_msg
        .get_root::<frame::Reader<'_>>()
        .map_err(|e| HandshakeError::Protocol(format!("parse result frame: {e}")))?
        .which()
        .map_err(|e| HandshakeError::Protocol(format!("result frame variant: {e}")))?
    {
        frame::AuthResult(result) => {
            let r = result.map_err(|e| HandshakeError::Protocol(format!("read result: {e}")))?;
            if r.get_accepted() {
                Ok(())
            } else {
                let reason = r
                    .get_reason()
                    .map_err(|e| HandshakeError::Protocol(format!("get reason: {e}")))?
                    .to_string()
                    .unwrap_or_default();
                Err(HandshakeError::Rejected(reason))
            }
        }
        _ => Err(HandshakeError::Protocol("expected AuthResult".into())),
    }
}

/// Send a rejection result (gateway helper).
pub async fn send_rejection<W>(
    writer: &mut FrameWriter<W>,
    reason: &str,
) -> Result<(), HandshakeError>
where
    W: AsyncWrite + Unpin,
{
    let mut msg = capnp::message::Builder::new_default();
    {
        let frame_builder = msg.init_root::<frame::Builder<'_>>();
        let mut result = frame_builder.init_auth_result();
        result.set_accepted(false);
        result.set_reason(reason);
    }
    writer
        .write_message(&msg)
        .await
        .map_err(|e| HandshakeError::Protocol(format!("write rejection: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Hook handshake
// ---------------------------------------------------------------------------

/// Domain-separated prefix for the hook handshake signature. Distinct
/// from `HANDSHAKE_DOMAIN` so an adapter signature can never replay
/// against the hook acceptor even if the same Ed25519 keypair is
/// reused across both surfaces. Hooks bind to a separate listener
/// (`gateway-hooks.sock`) but the cryptographic separator is the real
/// load-bearing piece.
const HOOK_HANDSHAKE_DOMAIN: &[u8] = b"wirken-ipc-hook-handshake-v1\x00";

/// Build the signed payload for a hook handshake.
/// `HOOK_HANDSHAKE_DOMAIN || hook_id || 0x00 || nonce`. Same
/// rationale as [`signed_payload`]: binds the signature to this
/// protocol and to the claimed hook identity at the crypto layer.
fn signed_payload_hook(hook_id: &str, nonce: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(HOOK_HANDSHAKE_DOMAIN.len() + hook_id.len() + 1 + nonce.len());
    msg.extend_from_slice(HOOK_HANDSHAKE_DOMAIN);
    msg.extend_from_slice(hook_id.as_bytes());
    msg.push(0x00);
    msg.extend_from_slice(nonce);
    msg
}

/// What kind of hook a connection identifies as. Carried on the
/// [`HookAuthResponse`] wire frame and matched against the
/// gateway's `hook_registry` entry at handshake-verify time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookType {
    /// Observe-only: pulls audit events via `SessionLogTail`. No
    /// return path on dispatch.
    Observe,
    /// Veto: receives synchronous `VetoRequest` and replies
    /// `Allow` or `Deny { reason }`. Runs after Wirken's built-in
    /// permission gate, before the tool dispatches.
    Veto,
    /// Egress: receives synchronous `EgressRequest` after the tool
    /// has produced output, before that output enters the LLM
    /// conversation. Replies `Allow`, `Replace { bytes }`, or
    /// `Refuse { reason }`. The pipeline mutates the working
    /// output bytes hook by hook; the final working copy is what
    /// lands on the `ToolResult` row and in the conversation.
    Egress,
}

impl HookType {
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Veto => "veto",
            Self::Egress => "egress",
        }
    }

    pub fn from_wire(s: &str) -> Result<Self, HandshakeError> {
        match s {
            "observe" => Ok(Self::Observe),
            "veto" => Ok(Self::Veto),
            "egress" => Ok(Self::Egress),
            other => Err(HandshakeError::Protocol(format!(
                "unknown hook_type on wire: {other:?}"
            ))),
        }
    }
}

/// A hook process's Ed25519 identity. Parallels [`AdapterIdentity`]
/// but the signing key is bound under [`HOOK_HANDSHAKE_DOMAIN`].
pub struct HookIdentity {
    signing_key: SigningKey,
    hook_id: String,
    hook_type: HookType,
}

impl HookIdentity {
    pub fn generate(hook_id: impl Into<String>, hook_type: HookType) -> Self {
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        Self {
            signing_key,
            hook_id: hook_id.into(),
            hook_type,
        }
    }

    pub fn from_bytes(secret: &[u8; 32], hook_id: impl Into<String>, hook_type: HookType) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        Self {
            signing_key,
            hook_id: hook_id.into(),
            hook_type,
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn secret_key_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    pub fn hook_id(&self) -> &str {
        &self.hook_id
    }

    pub fn hook_type(&self) -> HookType {
        self.hook_type
    }

    fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

/// Hook side of the handshake. Mirrors [`perform_adapter_handshake`]
/// but sends a [`HookAuthResponse`] (carries `hook_type`) and signs
/// under [`HOOK_HANDSHAKE_DOMAIN`].
pub async fn perform_hook_handshake<R, W>(
    reader: &mut FrameReader<R>,
    writer: &mut FrameWriter<W>,
    identity: &HookIdentity,
) -> Result<(), HandshakeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let challenge_msg = reader
        .read_message()
        .await
        .map_err(|e| HandshakeError::Protocol(format!("read challenge: {e}")))?;
    let frame_reader = challenge_msg
        .get_root::<frame::Reader<'_>>()
        .map_err(|e| HandshakeError::Protocol(format!("parse challenge frame: {e}")))?;

    let nonce = match frame_reader
        .which()
        .map_err(|e| HandshakeError::Protocol(format!("challenge frame variant: {e}")))?
    {
        frame::AuthChallenge(challenge) => {
            let c =
                challenge.map_err(|e| HandshakeError::Protocol(format!("read challenge: {e}")))?;
            let nonce = c
                .get_nonce()
                .map_err(|e| HandshakeError::Protocol(format!("get nonce: {e}")))?;
            nonce.to_vec()
        }
        _ => return Err(HandshakeError::Protocol("expected AuthChallenge".into())),
    };

    let payload = signed_payload_hook(identity.hook_id(), &nonce);
    let signature = identity.sign(&payload);

    let mut response_msg = capnp::message::Builder::new_default();
    {
        let frame_builder = response_msg.init_root::<frame::Builder<'_>>();
        let mut resp = frame_builder.init_hook_auth_response();
        resp.set_public_key(&identity.public_key_bytes());
        resp.set_signature(&signature.to_bytes());
        resp.set_hook_id(&identity.hook_id);
        resp.set_hook_type(identity.hook_type.as_wire());
    }
    writer
        .write_message(&response_msg)
        .await
        .map_err(|e| HandshakeError::Protocol(format!("write hook response: {e}")))?;

    let result_msg = reader
        .read_message()
        .await
        .map_err(|e| HandshakeError::Protocol(format!("read result: {e}")))?;
    let result_reader = result_msg
        .get_root::<frame::Reader<'_>>()
        .map_err(|e| HandshakeError::Protocol(format!("parse result frame: {e}")))?;

    match result_reader
        .which()
        .map_err(|e| HandshakeError::Protocol(format!("result frame variant: {e}")))?
    {
        frame::AuthResult(result) => {
            let r = result.map_err(|e| HandshakeError::Protocol(format!("read result: {e}")))?;
            if r.get_accepted() {
                Ok(())
            } else {
                let reason = r
                    .get_reason()
                    .map_err(|e| HandshakeError::Protocol(format!("get reason: {e}")))?
                    .to_string()
                    .unwrap_or_default();
                Err(HandshakeError::Rejected(reason))
            }
        }
        _ => Err(HandshakeError::Protocol("expected AuthResult".into())),
    }
}

/// Verified identity returned by [`perform_gateway_hook_handshake`].
pub struct VerifiedHook {
    pub hook_id: String,
    pub public_key: [u8; 32],
    pub hook_type: HookType,
}

/// Gateway side of the hook handshake. Same shape as
/// [`perform_gateway_handshake`] but reads [`HookAuthResponse`] and
/// verifies under [`HOOK_HANDSHAKE_DOMAIN`].
///
/// `verify_hook` is called with `(hook_id, public_key, hook_type)` and
/// returns `Ok(())` if the hook is registered, the pubkey matches,
/// and the registered type matches the wire-claimed type.
pub async fn perform_gateway_hook_handshake<R, W, F>(
    reader: &mut FrameReader<R>,
    writer: &mut FrameWriter<W>,
    verify_hook: F,
) -> Result<VerifiedHook, HandshakeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnOnce(&str, &[u8; 32], HookType) -> Result<(), HandshakeError>,
{
    let mut nonce = [0u8; CHALLENGE_NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);

    let mut challenge_msg = capnp::message::Builder::new_default();
    {
        let frame_builder = challenge_msg.init_root::<frame::Builder<'_>>();
        let mut challenge = frame_builder.init_auth_challenge();
        challenge.set_nonce(&nonce);
    }
    writer
        .write_message(&challenge_msg)
        .await
        .map_err(|e| HandshakeError::Protocol(format!("write challenge: {e}")))?;

    let response_msg = reader
        .read_message()
        .await
        .map_err(|e| HandshakeError::Protocol(format!("read response: {e}")))?;
    let response_reader = response_msg
        .get_root::<frame::Reader<'_>>()
        .map_err(|e| HandshakeError::Protocol(format!("parse response frame: {e}")))?;

    let (hook_id, pub_key_bytes, sig_bytes, hook_type) = match response_reader
        .which()
        .map_err(|e| HandshakeError::Protocol(format!("response frame variant: {e}")))?
    {
        frame::HookAuthResponse(response) => {
            let r =
                response.map_err(|e| HandshakeError::Protocol(format!("read response: {e}")))?;
            let pk = r
                .get_public_key()
                .map_err(|e| HandshakeError::Protocol(format!("get public key: {e}")))?;
            let sig = r
                .get_signature()
                .map_err(|e| HandshakeError::Protocol(format!("get signature: {e}")))?;
            let id = r
                .get_hook_id()
                .map_err(|e| HandshakeError::Protocol(format!("get hook id: {e}")))?
                .to_string()
                .map_err(|e| HandshakeError::Protocol(format!("hook id not utf8: {e}")))?;
            let ty_str = r
                .get_hook_type()
                .map_err(|e| HandshakeError::Protocol(format!("get hook type: {e}")))?
                .to_string()
                .map_err(|e| HandshakeError::Protocol(format!("hook type not utf8: {e}")))?;
            let ty = HookType::from_wire(&ty_str)?;

            let mut pk_arr = [0u8; 32];
            if pk.len() != 32 {
                return Err(HandshakeError::Protocol(format!(
                    "public key must be 32 bytes, got {}",
                    pk.len()
                )));
            }
            pk_arr.copy_from_slice(pk);

            let mut sig_arr = [0u8; 64];
            if sig.len() != 64 {
                return Err(HandshakeError::Protocol(format!(
                    "signature must be 64 bytes, got {}",
                    sig.len()
                )));
            }
            sig_arr.copy_from_slice(sig);

            (id, pk_arr, sig_arr, ty)
        }
        _ => return Err(HandshakeError::Protocol("expected HookAuthResponse".into())),
    };

    verify_hook(&hook_id, &pub_key_bytes, hook_type)?;

    let verifying_key =
        VerifyingKey::from_bytes(&pub_key_bytes).map_err(|_| HandshakeError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let payload = signed_payload_hook(&hook_id, &nonce);
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|_| HandshakeError::InvalidSignature)?;

    let mut result_msg = capnp::message::Builder::new_default();
    {
        let frame_builder = result_msg.init_root::<frame::Builder<'_>>();
        let mut result = frame_builder.init_auth_result();
        result.set_accepted(true);
        result.set_reason("");
    }
    writer
        .write_message(&result_msg)
        .await
        .map_err(|e| HandshakeError::Protocol(format!("write result: {e}")))?;

    Ok(VerifiedHook {
        hook_id,
        public_key: pub_key_bytes,
        hook_type,
    })
}

#[cfg(test)]
mod hook_handshake_tests {
    use super::*;
    use crate::transport::{FrameReader, FrameWriter};
    use tokio::io::duplex;

    #[cfg_attr(miri, ignore = "needs a real socket; miri has no I/O")]
    #[tokio::test]
    async fn registered_hook_handshake_round_trips() {
        let (client, server) = duplex(4096);
        let (cr, cw) = tokio::io::split(client);
        let (sr, sw) = tokio::io::split(server);
        let mut cr = FrameReader::new(cr);
        let mut cw = FrameWriter::new(cw);
        let mut sr = FrameReader::new(sr);
        let mut sw = FrameWriter::new(sw);

        let identity = HookIdentity::generate("policy-eval", HookType::Veto);
        let expected_pk = identity.public_key_bytes();

        let client_task =
            tokio::spawn(async move { perform_hook_handshake(&mut cr, &mut cw, &identity).await });

        let verified = perform_gateway_hook_handshake(&mut sr, &mut sw, |id, pk, ty| {
            assert_eq!(id, "policy-eval");
            assert_eq!(*pk, expected_pk);
            assert_eq!(ty, HookType::Veto);
            Ok(())
        })
        .await
        .expect("gateway handshake succeeds");

        client_task.await.unwrap().unwrap();
        assert_eq!(verified.hook_id, "policy-eval");
        assert_eq!(verified.hook_type, HookType::Veto);
        assert_eq!(verified.public_key, expected_pk);
    }

    #[cfg_attr(miri, ignore = "needs a real socket; miri has no I/O")]
    #[tokio::test]
    async fn unregistered_hook_rejected_by_verify_closure() {
        let (client, server) = duplex(4096);
        let (cr, cw) = tokio::io::split(client);
        let (sr, sw) = tokio::io::split(server);
        let mut cr = FrameReader::new(cr);
        let mut cw = FrameWriter::new(cw);
        let mut sr = FrameReader::new(sr);
        let mut sw = FrameWriter::new(sw);

        let identity = HookIdentity::generate("unknown", HookType::Observe);

        let client_task = tokio::spawn(async move {
            let result = perform_hook_handshake(&mut cr, &mut cw, &identity).await;
            // The client either reads a Rejected result, or the
            // gateway drops the connection before sending one.
            // Either is a rejection from the client's perspective.
            assert!(result.is_err(), "client must observe rejection");
        });

        let result = perform_gateway_hook_handshake(&mut sr, &mut sw, |_, _, _| {
            Err(HandshakeError::Rejected("hook not registered".into()))
        })
        .await;
        assert!(matches!(result, Err(HandshakeError::Rejected(_))));
        // Send the explicit rejection over the wire so the client task
        // sees it (otherwise it would block on read).
        let _ = send_rejection(&mut sw, "hook not registered").await;
        client_task.await.unwrap();
    }

    #[cfg_attr(miri, ignore = "needs a real socket; miri has no I/O")]
    #[tokio::test]
    async fn adapter_domain_signature_does_not_verify_against_hook_acceptor() {
        // Reuse the same Ed25519 keypair for an adapter and a hook
        // identity, then sign a hook nonce with the adapter domain
        // separator. The gateway's hook handshake must reject because
        // the signature payload is constructed under a different
        // domain. This is the crypto-layer separation property.
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let adapter_identity = AdapterIdentity::from_bytes(&secret, "policy-eval");
        let hook_identity = HookIdentity::from_bytes(&secret, "policy-eval", HookType::Veto);
        assert_eq!(
            adapter_identity.public_key_bytes(),
            hook_identity.public_key_bytes(),
            "test premise: keypairs match"
        );

        let nonce = [0u8; CHALLENGE_NONCE_SIZE];
        let adapter_payload = signed_payload(adapter_identity.adapter_id(), &nonce);
        let adapter_sig = adapter_identity.sign(&adapter_payload);

        let verifying_key = VerifyingKey::from_bytes(&hook_identity.public_key_bytes()).unwrap();
        let hook_payload = signed_payload_hook(hook_identity.hook_id(), &nonce);
        assert!(
            verifying_key
                .verify_strict(&hook_payload, &adapter_sig)
                .is_err(),
            "adapter-domain signature must not verify against hook-domain payload"
        );
    }
}

#[cfg(test)]
mod terminal_handshake_tests {
    use super::*;
    use crate::operator::{ORCHESTRATOR_SOCKET, OperatorKey, TERMINAL_SOCKET};
    use crate::transport::{FrameReader, FrameWriter};
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf, duplex};

    type Ends = (
        FrameReader<ReadHalf<DuplexStream>>,
        FrameWriter<WriteHalf<DuplexStream>>,
    );

    fn pipe() -> (Ends, Ends) {
        let (client, server) = duplex(4096);
        let (cr, cw) = tokio::io::split(client);
        let (sr, sw) = tokio::io::split(server);
        (
            (FrameReader::new(cr), FrameWriter::new(cw)),
            (FrameReader::new(sr), FrameWriter::new(sw)),
        )
    }

    /// Run `wirken chat`'s side with `key` against a gateway pinned to
    /// `pinned` that knows the agents in `agents`.
    async fn terminal_against(
        key: &OperatorKey,
        agent: &str,
        pinned: Option<&VerifyingKey>,
        agents: &[&str],
    ) -> (
        Result<(), HandshakeError>,
        Result<GatewayPeer, HandshakeError>,
    ) {
        let ((mut cr, mut cw), (mut sr, mut sw)) = pipe();
        tokio::join!(
            perform_terminal_handshake(&mut cr, &mut cw, key, agent),
            perform_gateway_peer_handshake(
                &mut sr,
                &mut sw,
                pinned,
                |id, _| Err(HandshakeError::UnknownAdapter(id.into())),
                |a| {
                    if a.is_empty() || agents.contains(&a) {
                        Ok(())
                    } else {
                        Err(HandshakeError::UnknownAgent(a.into()))
                    }
                },
            ),
        )
    }

    #[cfg_attr(miri, ignore = "needs a real socket; miri has no I/O")]
    #[tokio::test]
    async fn the_operator_key_opens_the_terminal_channel_for_the_agent_asked() {
        let key = OperatorKey::generate();
        let (client, gateway) =
            terminal_against(&key, "alice", Some(&key.verifying_key()), &["alice"]).await;
        client.unwrap();
        assert_eq!(
            gateway.unwrap(),
            GatewayPeer::Terminal {
                key_id: key.key_id(),
                public_key: key.verifying_key().to_bytes(),
                agent: "alice".into(),
            }
        );
    }

    #[cfg_attr(miri, ignore = "needs a real socket; miri has no I/O")]
    #[tokio::test]
    async fn another_key_is_refused_and_told_so() {
        let key = OperatorKey::generate();
        let pinned = OperatorKey::generate().verifying_key();
        let (client, gateway) = terminal_against(&key, "", Some(&pinned), &[]).await;
        assert!(
            matches!(gateway, Err(HandshakeError::NotOperatorKey)),
            "{gateway:?}"
        );
        assert!(
            matches!(client, Err(HandshakeError::Rejected(ref r)) if r.contains("operator key")),
            "{client:?}"
        );
    }

    #[cfg_attr(miri, ignore = "needs a real socket; miri has no I/O")]
    #[tokio::test]
    async fn an_agent_the_gateway_does_not_know_is_refused() {
        let key = OperatorKey::generate();
        let (client, gateway) =
            terminal_against(&key, "mallory", Some(&key.verifying_key()), &["alice"]).await;
        assert!(
            matches!(gateway, Err(HandshakeError::UnknownAgent(ref a)) if a == "mallory"),
            "{gateway:?}"
        );
        assert!(
            matches!(client, Err(HandshakeError::Rejected(ref r)) if r.contains("mallory")),
            "{client:?}"
        );
    }

    #[cfg_attr(miri, ignore = "needs a real socket; miri has no I/O")]
    #[tokio::test]
    async fn a_gateway_without_an_operator_key_takes_no_terminal() {
        let key = OperatorKey::generate();
        let ((mut cr, mut cw), (mut sr, mut sw)) = pipe();
        let (_client, gateway) = tokio::join!(
            perform_terminal_handshake(&mut cr, &mut cw, &key, ""),
            async move {
                let r = perform_gateway_peer_handshake(
                    &mut sr,
                    &mut sw,
                    None,
                    |_, _| Ok(()),
                    |_| Ok(()),
                )
                .await;
                // As the gateway does: the connection ends here.
                drop((sr, sw));
                r
            },
        );
        assert!(
            matches!(gateway, Err(HandshakeError::Protocol(_))),
            "{gateway:?}"
        );
    }

    #[cfg_attr(miri, ignore = "needs a real socket; miri has no I/O")]
    #[tokio::test]
    async fn the_adapter_only_handshake_takes_no_terminal() {
        let key = OperatorKey::generate();
        let ((mut cr, mut cw), (mut sr, mut sw)) = pipe();
        let (_client, gateway) = tokio::join!(
            perform_terminal_handshake(&mut cr, &mut cw, &key, ""),
            async move {
                let r = perform_gateway_handshake(&mut sr, &mut sw, |_, _| Ok(())).await;
                drop((sr, sw));
                r
            },
        );
        assert!(
            matches!(gateway, Err(HandshakeError::Protocol(_))),
            "{gateway:?}"
        );
    }

    /// A signature the operator key made for another socket does not
    /// open this one, though the key is the right one.
    #[cfg_attr(miri, ignore = "needs a real socket; miri has no I/O")]
    #[tokio::test]
    async fn a_signature_for_another_socket_is_refused() {
        let key = OperatorKey::generate();
        let ((mut cr, mut cw), (mut sr, mut sw)) = pipe();
        let client = async {
            let msg = cr.read_message().await.unwrap();
            let nonce = match msg
                .get_root::<frame::Reader<'_>>()
                .unwrap()
                .which()
                .unwrap()
            {
                frame::AuthChallenge(c) => c.unwrap().get_nonce().unwrap().to_vec(),
                _ => panic!("expected a challenge"),
            };
            assert_ne!(ORCHESTRATOR_SOCKET, TERMINAL_SOCKET);
            let signature = key.sign_challenge(ORCHESTRATOR_SOCKET, &nonce);
            let mut answer = capnp::message::Builder::new_default();
            {
                let mut r = answer
                    .init_root::<frame::Builder<'_>>()
                    .init_terminal_auth_response();
                r.set_public_key(&key.verifying_key().to_bytes());
                r.set_signature(&signature.to_bytes());
                r.set_agent("");
            }
            cw.write_message(&answer).await.unwrap();
        };
        let pinned = key.verifying_key();
        let (_, gateway) = tokio::join!(
            client,
            perform_gateway_peer_handshake(
                &mut sr,
                &mut sw,
                Some(&pinned),
                |_, _| Ok(()),
                |_| Ok(()),
            ),
        );
        assert!(
            matches!(gateway, Err(HandshakeError::InvalidSignature)),
            "{gateway:?}"
        );
    }

    /// An adapter still completes the handshake on a gateway that takes
    /// the terminal too.
    #[cfg_attr(miri, ignore = "needs a real socket; miri has no I/O")]
    #[tokio::test]
    async fn an_adapter_is_unchanged_beside_the_terminal() {
        let identity = AdapterIdentity::generate("telegram");
        let expected = identity.public_key_bytes();
        let operator = OperatorKey::generate().verifying_key();
        let ((mut cr, mut cw), (mut sr, mut sw)) = pipe();
        let (client, gateway) = tokio::join!(
            perform_adapter_handshake(&mut cr, &mut cw, &identity),
            perform_gateway_peer_handshake(
                &mut sr,
                &mut sw,
                Some(&operator),
                |id, pk| {
                    assert_eq!((id, pk), ("telegram", &expected));
                    Ok(())
                },
                |_| panic!("an adapter names no agent"),
            ),
        );
        client.unwrap();
        assert_eq!(
            gateway.unwrap(),
            GatewayPeer::Adapter {
                adapter_id: "telegram".into(),
                public_key: expected,
            }
        );
    }
}
