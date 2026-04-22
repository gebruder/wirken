use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;

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
pub async fn perform_adapter_handshake(
    reader: &mut FrameReader,
    writer: &mut FrameWriter,
    identity: &AdapterIdentity,
) -> Result<(), HandshakeError> {
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
pub async fn perform_gateway_handshake<F>(
    reader: &mut FrameReader,
    writer: &mut FrameWriter,
    verify_adapter: F,
) -> Result<(String, [u8; 32]), HandshakeError>
where
    F: FnOnce(&str, &[u8; 32]) -> Result<(), HandshakeError>,
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

    let (adapter_id, pub_key_bytes, sig_bytes) = match response_reader
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
            let id = r
                .get_adapter_id()
                .map_err(|e| HandshakeError::Protocol(format!("get adapter id: {e}")))?
                .to_string()
                .map_err(|e| HandshakeError::Protocol(format!("adapter id not utf8: {e}")))?;

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

            (id, pk_arr, sig_arr)
        }
        _ => return Err(HandshakeError::Protocol("expected AuthResponse".into())),
    };

    // 3. Verify the adapter is registered
    verify_adapter(&adapter_id, &pub_key_bytes)?;

    // 4. Verify the signature over (domain || adapter_id || nonce).
    //    See `signed_payload` for rationale.
    let verifying_key =
        VerifyingKey::from_bytes(&pub_key_bytes).map_err(|_| HandshakeError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let payload = signed_payload(&adapter_id, &nonce);
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| HandshakeError::InvalidSignature)?;

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

    Ok((adapter_id, pub_key_bytes))
}

/// Send a rejection result (gateway helper).
pub async fn send_rejection(writer: &mut FrameWriter, reason: &str) -> Result<(), HandshakeError> {
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
