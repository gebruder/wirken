//! Resolves human caller identity to OTel `user.id` for the
//! `invoke_agent` root span.
//!
//! Wirken's chat-platform callers (Telegram, Discord, Signal,
//! WhatsApp, Matrix, Google Chat, iMessage) have no Microsoft Entra
//! identity by construction. Microsoft Teams is the exception:
//! inbound Teams activities carry a `from.aadObjectId` natively.
//! The [`UserResolver`] trait abstracts over these cases so the
//! projector fills `user.id` through one call regardless of source.
//!
//! ## Separation from `FederatedIdentity`
//!
//! Deliberately separate from [`crate::FederatedIdentity`]. Who a
//! Telegram sender is has nothing to do with whether wirken
//! authenticates the agent's own credential against Entra or
//! Keycloak; bundling a `resolve_user` method into
//! `FederatedIdentity` would make both implementations carry an
//! identical federation-irrelevant method, which is the
//! abstraction-around-a-nonexistent-boundary anti-pattern.
//!
//! ## Module status
//!
//! Third commit on issue #130. Lands the trait, a `UserId`
//! newtype, and [`DeterministicUserResolver`] as a deterministic
//! default. The full resolver (Teams adapter `from.aadObjectId`
//! extraction, operator `user_map.json` overlay, keyed-synthetic
//! with vault-held salt) lands in issue #132.

use sha2::{Digest, Sha256};

/// A resolved user identifier, formatted as a UUID-shape string
/// for the OTel `user.id` attribute. The Agent 365 ingestion
/// endpoint expects an Entra-object-id shape; this newtype carries
/// that shape without claiming the value resolves to a real Entra
/// principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserId(String);

impl UserId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Resolves `(adapter_id, sender_id)` into a [`UserId`] suitable
/// for the OTel `user.id` attribute on `invoke_agent` root spans.
///
/// Implementations consult sources in a precedence the trait does
/// not specify (each implementation documents its own precedence).
/// The trait promises only that the same `(adapter_id, sender_id)`
/// input maps to the same `UserId` across calls so longitudinal
/// pivot in Defender stays stable per caller.
pub trait UserResolver: Send + Sync {
    fn resolve_user(&self, adapter_id: Option<&str>, sender_id: Option<&str>) -> UserId;
}

/// Default `UserResolver` implementation: SHA-256 of the
/// concatenated `(adapter_id, sender_id)` tuple, formatted as a
/// UUIDv4-shape string.
///
/// **Not keyed.** The output is recomputable from
/// `(adapter_id, sender_id)` alone, which means a third party
/// holding a chat-platform sender id (a phone number for Signal or
/// WhatsApp, a Telegram numeric id) can recompute the pseudonym.
/// Acceptable for a development collector that does not leave the
/// deployment; not acceptable for shipping telemetry to a
/// third-party cloud against an external IdP.
///
/// Issue #132 lands the keyed-synthetic variant with a vault-held
/// salt so the pseudonym is reproducible only inside the
/// deployment that holds the salt, plus the precedence chain
/// (Teams adapter-supplied real OID, then operator-supplied
/// `user_map.json` overlay, then keyed synthetic).
pub struct DeterministicUserResolver;

impl UserResolver for DeterministicUserResolver {
    fn resolve_user(&self, adapter_id: Option<&str>, sender_id: Option<&str>) -> UserId {
        let mut hasher = Sha256::new();
        hasher.update(adapter_id.unwrap_or("").as_bytes());
        hasher.update([0x00]);
        hasher.update(sender_id.unwrap_or("").as_bytes());
        let digest = hasher.finalize();
        let bytes: [u8; 16] = digest[..16]
            .try_into()
            .expect("SHA-256 yields 32 bytes, taking the first 16 is infallible");
        UserId::new(format_uuid_v4_shape(bytes))
    }
}

/// Format 16 bytes as a UUIDv4-shape string. Sets the version
/// nibble (high nibble of byte 6) to 4 and the variant nibble
/// (high two bits of byte 8) to the RFC 4122 variant. Output:
/// `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` where y is one of 8, 9,
/// a, b. Used by both [`DeterministicUserResolver`] and the
/// per-wake `microsoft.session.id` allocation in the projector.
pub(crate) fn format_uuid_v4_shape(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_resolver_stable_across_calls_for_same_input() {
        let resolver = DeterministicUserResolver;
        let a = resolver.resolve_user(Some("telegram"), Some("user-42"));
        let b = resolver.resolve_user(Some("telegram"), Some("user-42"));
        assert_eq!(a, b);
    }

    #[test]
    fn deterministic_resolver_diverges_across_adapters() {
        let resolver = DeterministicUserResolver;
        let telegram = resolver.resolve_user(Some("telegram"), Some("user-42"));
        let discord = resolver.resolve_user(Some("discord"), Some("user-42"));
        assert_ne!(telegram, discord);
    }

    #[test]
    fn deterministic_resolver_diverges_across_senders() {
        let resolver = DeterministicUserResolver;
        let a = resolver.resolve_user(Some("telegram"), Some("user-42"));
        let b = resolver.resolve_user(Some("telegram"), Some("user-43"));
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_resolver_handles_missing_adapter_or_sender() {
        let resolver = DeterministicUserResolver;
        let id = resolver.resolve_user(None, None);
        assert_eq!(id.as_str().len(), 36);
    }

    #[test]
    fn user_id_has_uuid_v4_layout() {
        let resolver = DeterministicUserResolver;
        let id = resolver.resolve_user(Some("telegram"), Some("user-42"));
        let s = id.as_str();
        assert_eq!(s.len(), 36, "UUIDv4 shape is 36 characters with dashes");
        assert_eq!(&s[8..9], "-");
        assert_eq!(&s[13..14], "-");
        assert_eq!(&s[18..19], "-");
        assert_eq!(&s[23..24], "-");
        assert_eq!(&s[14..15], "4", "version nibble must be 4");
        let variant = s[19..20].chars().next().unwrap();
        assert!(
            matches!(variant, '8' | '9' | 'a' | 'b'),
            "RFC 4122 variant nibble must be one of 8, 9, a, b; saw {variant}"
        );
    }

    #[test]
    fn format_uuid_v4_shape_forces_version_and_variant_bits() {
        // All-zeroes input proves the version/variant bits are
        // forced even when the source has no bits set there.
        let s = format_uuid_v4_shape([0u8; 16]);
        assert_eq!(s, "00000000-0000-4000-8000-000000000000");

        // All-0xFF input proves the version/variant bits are
        // forced even when the source has all bits set there.
        let s = format_uuid_v4_shape([0xffu8; 16]);
        assert_eq!(s, "ffffffff-ffff-4fff-bfff-ffffffffffff");
    }
}
