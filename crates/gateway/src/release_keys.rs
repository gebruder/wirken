//! The release signing keys this binary trusts.
//!
//! A release is signed offline with `ssh-keygen -Y sign`; the public
//! half is published in `KEYS`, embedded in `install.sh`, and pinned
//! here, so `wirken update` checks a release against keys compiled
//! into the binary doing the checking rather than against anything
//! fetched alongside the release. There is no runtime override. A key
//! is added by a release that carries it here; after the loss or
//! compromise of a key, the path is a reinstall with `install.sh`.

use crate::sshsig::{SshSigError, parse_public_key};

/// One trusted release key: the signer identity and the OpenSSH
/// public key line, both as `KEYS` carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedKey {
    pub identity: &'static str,
    pub key: &'static str,
}

/// Every key a release may be signed with. One line per key.
pub const RELEASE_KEYS: &[PinnedKey] = &[PinnedKey {
    identity: "releases@gebruder.ottenheimer.app",
    key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPcGuqLSfpN+ibltPVbif7i9LgclLtRIaL+1TuYp+RjV",
}];

/// The namespace the release manifest is signed under. Distinct from
/// `file`, which signs `checksums.sha256`, so a signature over one
/// can never be presented as a signature over the other.
pub const MANIFEST_NAMESPACE: &str = "wirken-release-manifest";

/// The pinned keys as Ed25519 public keys.
pub fn pinned(keys: &[PinnedKey]) -> Result<Vec<[u8; 32]>, SshSigError> {
    keys.iter().map(|k| parse_public_key(k.key)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sshsig::fingerprint;

    /// `identity ssh-ed25519 <base64> [comment]` lines of an
    /// allowed_signers file, as (identity, key line).
    fn allowed_signers(text: &str) -> Vec<(String, String)> {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                let mut parts = l.split_whitespace();
                let identity = parts.next().unwrap().to_string();
                let kind = parts.next().unwrap();
                let blob = parts.next().unwrap();
                (identity, format!("{kind} {blob}"))
            })
            .collect()
    }

    fn pinned_pairs() -> Vec<(String, String)> {
        RELEASE_KEYS
            .iter()
            .map(|k| (k.identity.to_string(), k.key.to_string()))
            .collect()
    }

    #[test]
    fn the_pinned_keys_are_the_keys_in_keys() {
        let keys = allowed_signers(include_str!("../../../KEYS"));
        assert_eq!(pinned_pairs(), keys);
    }

    #[test]
    fn the_pinned_keys_are_the_ones_install_sh_verifies_with() {
        let install = include_str!("../../../install.sh");
        let line = install
            .lines()
            .find_map(|l| l.strip_prefix("ALLOWED_SIGNERS='"))
            .and_then(|l| l.strip_suffix('\''))
            .expect("install.sh carries ALLOWED_SIGNERS");
        assert_eq!(pinned_pairs(), allowed_signers(line));
    }

    #[test]
    fn the_pinned_key_has_the_published_fingerprint() {
        let keys = pinned(RELEASE_KEYS).unwrap();
        assert_eq!(keys.len(), 1);
        // KEYS, SECURITY.md and docs/signing.md all name this one.
        let published = "SHA256:tzlfNHy4G1KIsmAR+cM3MGwVndheh2ak/usA6rw7SuE";
        assert_eq!(fingerprint(&keys[0]), published);
        assert!(include_str!("../../../KEYS").contains(published));
        assert!(include_str!("../../../SECURITY.md").contains(published));
    }
}
