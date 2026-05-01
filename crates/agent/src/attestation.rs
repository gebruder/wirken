//! Session attestation: sign the chain head of a session log so an
//! external auditor with the agent's public key can prove the
//! transcript is intact and untampered.
//!
//! This is item 8 of the Managed Agents parity work
//! (`docs/managed-agents-parity.md`). It is a leapfrog primitive —
//! no hosted agent service can offer it because they hold the
//! signing key inside their own infrastructure. A self-hosted
//! operator's key on the operator's hardware is qualitatively
//! different.
//!
//! ## What gets signed
//!
//! The signed message is built from a fixed domain separator plus
//! the session id, the chain head sequence, and the chain head hash.
//! The exact byte layout is:
//!
//! ```text
//! signed_msg =
//!     b"wirken/session-attest/v1\0"        // 25-byte domain separator
//!  || u32_le(session_id.len())
//!  || session_id.as_bytes()
//!  || u64_le(chain_head_seq)
//!  || chain_head_hash.as_bytes()             // 64 ASCII hex chars
//! ```
//!
//! The domain separator means the same Ed25519 key cannot produce
//! signatures that collide with messages from another protocol.
//! Bumping the version suffix (`v1` → `v2`) is the canonical way to
//! retire an old format.
//!
//! ## Slice 1 scope
//!
//! Slice 1 ships the library primitives only. There is no auto-trigger
//! from a harness loop yet — `attest_session` is called manually.
//! When item 2 (stateless harness/wake) lands, the harness will call
//! `attest_session` every N events / K seconds / on close. CLI
//! commands (`wirken session attest`, `wirken session
//! verify-attestations`, `wirken keys export-pubkey`) ship in a
//! follow-up alongside item 2 so they have real sessions to operate on.

use ed25519_dalek::{Signature, VerifyingKey};

use wirken_audit::{
    AuditError, HashHex, HexBytes, OwnSession, SessionEvent, SessionHandle, SessionLog,
    SessionVerifyResult, TrustLevel,
};

use crate::error::AgentError;
use crate::identity::AgentIdentity;

const DOMAIN: &[u8] = b"wirken/session-attest/v1\0";

/// Result of verifying every attestation in a session.
#[derive(Debug, PartialEq, Eq)]
pub enum AttestationVerifyResult {
    /// Every attestation in the session was verified successfully.
    /// `attestations_verified` is the count; `chain_rows_verified`
    /// is the count returned by the inner [`SessionLog::verify`]
    /// call. `0` attestations is a successful result for a session
    /// that has no attestations yet.
    Ok {
        attestations_verified: usize,
        chain_rows_verified: usize,
    },
    /// The session log itself failed verification before any
    /// attestation was checked. The chain is broken; attestations
    /// cannot be evaluated.
    ChainBroken { seq: u64, reason: String },
    /// One attestation event failed verification. Earlier
    /// attestations may have passed; the count is included.
    Broken {
        attestation_seq: u64,
        attestations_verified_before: usize,
        reason: String,
    },
}

/// Sign the current chain head of `session` and append an
/// `Attestation` event to the same session. The attestation event
/// itself becomes the new chain head, so a subsequent attestation
/// transitively covers it.
///
/// Returns the sequence number of the newly appended attestation
/// event, or `None` if the session is empty (nothing to attest).
pub fn attest_session<L: SessionLog + ?Sized>(
    log: &L,
    session: &SessionHandle<OwnSession>,
    identity: &AgentIdentity,
) -> Result<Option<u64>, AgentError> {
    let last = log.last_index(session).map_err(map_audit_err)?;
    let last_seq = match last {
        Some(s) => s,
        None => return Ok(None),
    };

    // Read the chain head row to capture its hash. We fetch a
    // 1-element range so we don't pull the whole session.
    let head_rows = log
        .get_range(session, last_seq..(last_seq + 1))
        .map_err(map_audit_err)?;
    let head = head_rows.into_iter().next().ok_or_else(|| {
        AgentError::Identity(format!(
            "session {} reports last_seq={last_seq} but row is missing",
            session.id()
        ))
    })?;
    let chain_head_hash = head.hash;

    let signed_msg = build_signed_message(session.id().as_str(), last_seq, &chain_head_hash);
    let signature = identity.sign(&signed_msg);

    let event = SessionEvent::Attestation {
        chain_head_seq: last_seq,
        chain_head_hash: chain_head_hash.clone(),
        signature: HexBytes::from_bytes(&signature.to_bytes()),
        signer_pubkey: HashHex::from_bytes(&identity.public_key_bytes()),
    };

    let new_seq = log
        .append(session, TrustLevel::System, event)
        .map_err(map_audit_err)?;
    Ok(Some(new_seq))
}

/// Walk every event in `session`, find every `Attestation` event,
/// and verify each signature against `verifying_key`.
///
/// Calls [`SessionLog::verify`] first to confirm the underlying
/// chain is intact — attestations against a tampered chain are
/// meaningless. If the chain is broken, returns
/// [`AttestationVerifyResult::ChainBroken`] without checking any
/// signatures.
pub fn verify_session_attestations<L: SessionLog + ?Sized>(
    log: &L,
    session: &SessionHandle<OwnSession>,
    verifying_key: &VerifyingKey,
) -> Result<AttestationVerifyResult, AgentError> {
    // Step 1: chain integrity.
    let chain = log.verify(session).map_err(map_audit_err)?;
    let chain_rows_verified = match chain {
        SessionVerifyResult::Ok { rows_verified } => rows_verified,
        SessionVerifyResult::Empty => 0,
        SessionVerifyResult::Broken {
            seq,
            expected_hash,
            actual_hash,
            verified_count: _,
        } => {
            let reason = format!("expected hash {expected_hash}, got {actual_hash}");
            return Ok(AttestationVerifyResult::ChainBroken { seq, reason });
        }
    };

    // Step 2: walk events, verify attestations as we encounter them.
    let rows = log.get_since(session, 0).map_err(map_audit_err)?;

    // Build a seq → hash lookup so each attestation can confirm
    // its chain_head_hash matches the row at chain_head_seq.
    let mut hashes_by_seq = std::collections::HashMap::new();
    for r in &rows {
        hashes_by_seq.insert(r.seq, r.hash.clone());
    }

    let mut attestations_verified = 0usize;

    for row in &rows {
        let SessionEvent::Attestation {
            chain_head_seq,
            chain_head_hash,
            signature,
            signer_pubkey,
        } = &row.event
        else {
            continue;
        };

        // Pubkey on the event must match the verifier's key.
        let event_pubkey_hex = HashHex::from_bytes(&verifying_key.to_bytes());
        if signer_pubkey != &event_pubkey_hex {
            return Ok(AttestationVerifyResult::Broken {
                attestation_seq: row.seq,
                attestations_verified_before: attestations_verified,
                reason: format!(
                    "signer pubkey mismatch: event {} vs verifier {}",
                    signer_pubkey.0, event_pubkey_hex.0
                ),
            });
        }

        // chain_head_hash must match the actual hash of the row at
        // chain_head_seq in this session.
        let actual_head_hash = match hashes_by_seq.get(chain_head_seq) {
            Some(h) => h,
            None => {
                return Ok(AttestationVerifyResult::Broken {
                    attestation_seq: row.seq,
                    attestations_verified_before: attestations_verified,
                    reason: format!("chain_head_seq {chain_head_seq} not present in session"),
                });
            }
        };
        if actual_head_hash != chain_head_hash {
            return Ok(AttestationVerifyResult::Broken {
                attestation_seq: row.seq,
                attestations_verified_before: attestations_verified,
                reason: format!(
                    "chain_head_hash {} does not match actual hash {} at seq {chain_head_seq}",
                    chain_head_hash.0, actual_head_hash.0
                ),
            });
        }

        // Reconstruct the signed message and verify the signature.
        let signed_msg =
            build_signed_message(session.id().as_str(), *chain_head_seq, chain_head_hash);
        let sig_bytes = match decode_hex(&signature.0) {
            Ok(b) if b.len() == 64 => b,
            Ok(b) => {
                return Ok(AttestationVerifyResult::Broken {
                    attestation_seq: row.seq,
                    attestations_verified_before: attestations_verified,
                    reason: format!("signature length {} != 64", b.len()),
                });
            }
            Err(e) => {
                return Ok(AttestationVerifyResult::Broken {
                    attestation_seq: row.seq,
                    attestations_verified_before: attestations_verified,
                    reason: format!("signature hex decode: {e}"),
                });
            }
        };
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);

        if let Err(e) = verifying_key.verify_strict(&signed_msg, &sig) {
            return Ok(AttestationVerifyResult::Broken {
                attestation_seq: row.seq,
                attestations_verified_before: attestations_verified,
                reason: format!("ed25519 verify failed: {e}"),
            });
        }

        attestations_verified += 1;
    }

    Ok(AttestationVerifyResult::Ok {
        attestations_verified,
        chain_rows_verified,
    })
}

/// Build the canonical signed message. See module-level docs for the
/// exact byte layout.
fn build_signed_message(
    session_id: &str,
    chain_head_seq: u64,
    chain_head_hash: &HashHex,
) -> Vec<u8> {
    let id_bytes = session_id.as_bytes();
    let hash_bytes = chain_head_hash.0.as_bytes();
    let mut out = Vec::with_capacity(DOMAIN.len() + 4 + id_bytes.len() + 8 + hash_bytes.len());
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(id_bytes);
    out.extend_from_slice(&chain_head_seq.to_le_bytes());
    out.extend_from_slice(hash_bytes);
    out
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn map_audit_err(e: AuditError) -> AgentError {
    AgentError::Identity(format!("session log: {e}"))
}

/// Walk every session in `session_log` and verify each session's
/// embedded attestations against the `signer_pubkey` carried on the
/// attestation event itself.
///
/// **Trust model:** this verifies internal consistency — that each
/// attestation's signature was produced by the key claimed on the
/// event, and that the chain_head_hash matches the row at
/// chain_head_seq. It does *not* anchor to an out-of-band trust
/// source. An attacker who rotates the agent's identity key on disk
/// and re-signs the entire transcript end-to-end will pass this
/// check. Operator-pinned signer keys are required for stronger
/// guarantees; that work is a separate item.
///
/// Returns the aggregate result. The first session whose attestations
/// fail to verify produces a `Broken` result and the walk stops there.
pub fn verify_recent_attestations(
    session_log: &dyn SessionLog,
    session_ids: &[String],
) -> Result<RecentAttestationResult, AgentError> {
    let mut sessions_checked: usize = 0;
    let mut attestations_verified: usize = 0;
    for sid in session_ids {
        let handle = session_log.handle_for(wirken_audit::SessionId::new(sid.clone()));
        let pubkey = match find_session_pubkey(session_log, &handle)? {
            Some(k) => k,
            None => {
                // No attestation in this session — nothing to verify.
                continue;
            }
        };
        sessions_checked += 1;
        match verify_session_attestations(session_log, &handle, &pubkey)? {
            AttestationVerifyResult::Ok {
                attestations_verified: n,
                ..
            } => {
                attestations_verified += n;
            }
            AttestationVerifyResult::ChainBroken { seq, reason } => {
                return Ok(RecentAttestationResult::ChainBroken {
                    session_id: sid.clone(),
                    seq,
                    reason,
                });
            }
            AttestationVerifyResult::Broken {
                attestation_seq,
                attestations_verified_before,
                reason,
            } => {
                return Ok(RecentAttestationResult::Broken {
                    session_id: sid.clone(),
                    attestation_seq,
                    attestations_verified_before,
                    reason,
                });
            }
        }
    }
    Ok(RecentAttestationResult::Ok {
        sessions_checked,
        attestations_verified,
    })
}

/// Aggregate result of [`verify_recent_attestations`].
#[derive(Debug, PartialEq, Eq)]
pub enum RecentAttestationResult {
    Ok {
        sessions_checked: usize,
        attestations_verified: usize,
    },
    ChainBroken {
        session_id: String,
        seq: u64,
        reason: String,
    },
    Broken {
        session_id: String,
        attestation_seq: u64,
        attestations_verified_before: usize,
        reason: String,
    },
}

fn find_session_pubkey(
    log: &dyn SessionLog,
    session: &SessionHandle<OwnSession>,
) -> Result<Option<VerifyingKey>, AgentError> {
    let rows = log.get_since(session, 0).map_err(map_audit_err)?;
    for row in rows.iter().rev() {
        if let SessionEvent::Attestation { signer_pubkey, .. } = &row.event {
            let bytes = decode_hex(&signer_pubkey.0)
                .map_err(|e| AgentError::Identity(format!("attestation pubkey hex: {e}")))?;
            if bytes.len() != 32 {
                return Err(AgentError::Identity(format!(
                    "attestation pubkey length {} != 32",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let key = VerifyingKey::from_bytes(&arr)
                .map_err(|e| AgentError::Identity(format!("invalid attestation pubkey: {e}")))?;
            return Ok(Some(key));
        }
    }
    Ok(None)
}
