//! The release manifest, `releases.json`: what releases exist, which
//! carried security fixes, and the sha256 of every artifact.
//!
//! Nothing in it is read until its signature has verified against a
//! pinned release key under the `wirken-release-manifest` namespace.
//! A verified manifest is then held to the newest one this install has
//! already verified: one carrying an older top-level `issued_at` is
//! refused, so an old but genuinely signed manifest cannot be replayed
//! to hide a newer release.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wirken_gateway::release_keys::MANIFEST_NAMESPACE;
use wirken_gateway::sshsig;

/// The largest manifest accepted. A manifest lists every release with
/// five artifacts; at a few hundred bytes an entry this leaves room for
/// thousands of releases.
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
/// The largest manifest signature accepted.
pub const MAX_SIGNATURE_BYTES: usize = 16 * 1024;

/// A `X.Y.Z` release version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u64, pub u64, pub u64);

impl Version {
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        let [a, b, c] = parts.as_slice() else {
            bail!("version {s:?} is not X.Y.Z");
        };
        let num = |p: &str| -> Result<u64> {
            if p.is_empty()
                || !p.bytes().all(|b| b.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
            {
                bail!("version {s:?} is not X.Y.Z");
            }
            Ok(p.parse()?)
        };
        Ok(Version(num(a)?, num(b)?, num(c)?))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// One release as the manifest lists it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Release {
    pub version: String,
    pub issued_at: DateTime<Utc>,
    pub security: bool,
    pub summary: String,
    /// Artifact name (`wirken-<target>`) to its sha256, lowercase hex.
    pub artifacts: BTreeMap<String, String>,
}

impl Release {
    pub fn parsed_version(&self) -> Version {
        Version::parse(&self.version).expect("checked at verify")
    }
}

/// A manifest whose signature verified and whose entries are well
/// formed. Releases are ordered newest first.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Manifest {
    pub issued_at: DateTime<Utc>,
    pub releases: Vec<Release>,
}

impl Manifest {
    pub fn latest(&self) -> &Release {
        &self.releases[0]
    }
}

/// The verified manifest and the key that signed it.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    pub manifest: Manifest,
    pub key_fingerprint: String,
}

/// Verify `signature` over `body` against `keys`, then parse and check
/// the manifest. The body is not parsed until the signature verifies.
pub fn verify(body: &[u8], signature: &[u8], keys: &[[u8; 32]]) -> Result<VerifiedManifest> {
    if body.len() > MAX_MANIFEST_BYTES {
        bail!("releases.json is larger than {MAX_MANIFEST_BYTES} bytes");
    }
    let signature = std::str::from_utf8(signature).context("releases.json.sig is not text")?;
    let verified = sshsig::verify(signature, body, MANIFEST_NAMESPACE, keys)
        .context("releases.json is not signed by a pinned release key")?;
    let mut manifest: Manifest =
        serde_json::from_slice(body).context("releases.json is signed but does not parse")?;
    if manifest.releases.is_empty() {
        bail!("releases.json lists no releases");
    }
    let mut seen = std::collections::BTreeSet::new();
    for r in &manifest.releases {
        let v = Version::parse(&r.version)?;
        if !seen.insert(v) {
            bail!("releases.json lists {v} twice");
        }
        for (name, sha) in &r.artifacts {
            if !name.starts_with("wirken-") || name.contains('/') || name.contains("..") {
                bail!("releases.json names an artifact {name:?}");
            }
            if sha.len() != 64
                || !sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                bail!(
                    "releases.json gives {name} in {v} a sha256 that is not 64 lowercase hex digits"
                );
            }
        }
    }
    manifest
        .releases
        .sort_by_key(|r| std::cmp::Reverse(r.parsed_version()));
    Ok(VerifiedManifest {
        manifest,
        key_fingerprint: verified.fingerprint,
    })
}

/// The newest manifest this install has verified, kept so an older one
/// is refused later.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FreezeState {
    pub issued_at: DateTime<Utc>,
    pub key_fingerprint: String,
}

/// Where the freeze state lives.
pub fn freeze_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("update").join("manifest-state.json")
}

/// Refuse `manifest` if it is older than the newest one this install
/// has verified, then record it when it is newer. A state file that
/// cannot be read refuses rather than starting over: deleting the
/// record of what was seen is not a way past it.
pub fn check_and_record_freshness(data_dir: &Path, verified: &VerifiedManifest) -> Result<()> {
    let path = freeze_state_path(data_dir);
    let stored: Option<FreezeState> = match std::fs::read(&path) {
        Ok(bytes) => Some(serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "{} does not parse; remove it only if you know why it is damaged",
                path.display()
            )
        })?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let issued = verified.manifest.issued_at;
    if let Some(stored) = &stored {
        if issued < stored.issued_at {
            bail!(
                "releases.json was issued {issued}, older than the one this install already \
                 verified ({}); a stale or replayed manifest is refused",
                stored.issued_at
            );
        }
        if issued == stored.issued_at {
            return Ok(());
        }
    }
    let state = FreezeState {
        issued_at: issued,
        key_fingerprint: verified.key_fingerprint.clone(),
    };
    let dir = path.parent().expect("state path has a parent");
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let tmp = dir.join(format!(".manifest-state.{}.tmp", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec_pretty(&state)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Test-only signing: an armored SSH signature over `message` by
    /// `key`, the way `ssh-keygen -Y sign -n <namespace>` makes one.
    pub(crate) fn sign(key: &ed25519_dalek::SigningKey, namespace: &str, message: &[u8]) -> String {
        use ed25519_dalek::Signer;
        use sha2::Digest;
        fn put(out: &mut Vec<u8>, s: &[u8]) {
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend_from_slice(s);
        }
        let digest = sha2::Sha512::digest(message);
        let mut signed = b"SSHSIG".to_vec();
        put(&mut signed, namespace.as_bytes());
        put(&mut signed, b"");
        put(&mut signed, b"sha512");
        put(&mut signed, &digest);
        let sig = key.sign(&signed);

        let mut pubkey = Vec::new();
        put(&mut pubkey, b"ssh-ed25519");
        put(&mut pubkey, key.verifying_key().as_bytes());
        let mut sigblob = Vec::new();
        put(&mut sigblob, b"ssh-ed25519");
        put(&mut sigblob, &sig.to_bytes());
        let mut blob = b"SSHSIG".to_vec();
        blob.extend_from_slice(&1u32.to_be_bytes());
        put(&mut blob, &pubkey);
        put(&mut blob, namespace.as_bytes());
        put(&mut blob, b"");
        put(&mut blob, b"sha512");
        put(&mut blob, &sigblob);

        let b64 = base64_padded(&blob);
        let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
        for chunk in b64.as_bytes().chunks(70) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END SSH SIGNATURE-----\n");
        out
    }

    fn base64_padded(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for k in 0..4 {
                if k <= chunk.len() {
                    out.push(A[((n >> (18 - 6 * k)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    pub(crate) fn test_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    pub(crate) fn release(version: &str, security: bool, artifacts: &[(&str, &str)]) -> Release {
        Release {
            version: version.into(),
            issued_at: "2026-10-01T00:00:00Z".parse().unwrap(),
            security,
            summary: format!("release {version}"),
            artifacts: artifacts
                .iter()
                .map(|(n, s)| (n.to_string(), s.to_string()))
                .collect(),
        }
    }

    pub(crate) fn manifest_body(issued_at: &str, releases: &[Release]) -> Vec<u8> {
        serde_json::to_vec_pretty(&serde_json::json!({
            "issued_at": issued_at,
            "releases": releases,
        }))
        .unwrap()
    }

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn signed(issued_at: &str) -> (Vec<u8>, String) {
        let body = manifest_body(
            issued_at,
            &[
                release("2.2.0", true, &[("wirken-x86_64-unknown-linux-musl", SHA)]),
                release("2.3.0", false, &[("wirken-x86_64-unknown-linux-musl", SHA)]),
            ],
        );
        let sig = sign(&test_key(1), MANIFEST_NAMESPACE, &body);
        (body, sig)
    }

    #[test]
    fn a_manifest_signed_by_a_pinned_key_verifies_and_is_ordered_newest_first() {
        let (body, sig) = signed("2026-10-20T00:00:00Z");
        let keys = [test_key(1).verifying_key().to_bytes()];
        let v = verify(&body, sig.as_bytes(), &keys).unwrap();
        assert_eq!(v.manifest.latest().version, "2.3.0");
        assert_eq!(v.key_fingerprint, sshsig::fingerprint(&keys[0]));
    }

    #[test]
    fn a_manifest_signed_by_the_wrong_key_is_refused() {
        let (body, sig) = signed("2026-10-20T00:00:00Z");
        let pinned = [test_key(2).verifying_key().to_bytes()];
        let err = verify(&body, sig.as_bytes(), &pinned).unwrap_err();
        assert!(format!("{err:#}").contains("not a pinned key"), "{err:#}");
    }

    #[test]
    fn a_manifest_signed_under_another_namespace_is_refused() {
        let (body, _) = signed("2026-10-20T00:00:00Z");
        let sig = sign(&test_key(1), "file", &body);
        let keys = [test_key(1).verifying_key().to_bytes()];
        assert!(verify(&body, sig.as_bytes(), &keys).is_err());
    }

    #[test]
    fn a_tampered_manifest_is_refused_before_it_is_parsed() {
        let (mut body, sig) = signed("2026-10-20T00:00:00Z");
        let keys = [test_key(1).verifying_key().to_bytes()];
        body.extend_from_slice(b" ");
        assert!(verify(&body, sig.as_bytes(), &keys).is_err());
    }

    #[test]
    fn malformed_entries_are_refused_even_when_signed() {
        let keys = [test_key(1).verifying_key().to_bytes()];
        for bad in [
            release("2.3", false, &[]),
            release("2.3.0", false, &[("wirken-x", "ABC")]),
            release("2.3.0", false, &[("../wirken", SHA)]),
        ] {
            let body = manifest_body("2026-10-20T00:00:00Z", &[bad]);
            let sig = sign(&test_key(1), MANIFEST_NAMESPACE, &body);
            assert!(verify(&body, sig.as_bytes(), &keys).is_err());
        }
    }

    #[test]
    fn a_stale_manifest_is_refused_and_a_newer_one_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let keys = [test_key(1).verifying_key().to_bytes()];
        let verified = |at: &str| {
            let (body, sig) = signed(at);
            verify(&body, sig.as_bytes(), &keys).unwrap()
        };
        check_and_record_freshness(tmp.path(), &verified("2026-10-20T00:00:00Z")).unwrap();
        // The same one again is fine.
        check_and_record_freshness(tmp.path(), &verified("2026-10-20T00:00:00Z")).unwrap();
        let err =
            check_and_record_freshness(tmp.path(), &verified("2026-10-19T00:00:00Z")).unwrap_err();
        assert!(err.to_string().contains("stale or replayed"), "{err:#}");
        check_and_record_freshness(tmp.path(), &verified("2026-10-21T00:00:00Z")).unwrap();
        let state: FreezeState =
            serde_json::from_slice(&std::fs::read(freeze_state_path(tmp.path())).unwrap()).unwrap();
        assert_eq!(
            state.issued_at,
            "2026-10-21T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        // And the one that was newest before is now stale too.
        assert!(check_and_record_freshness(tmp.path(), &verified("2026-10-20T00:00:00Z")).is_err());
    }

    #[test]
    fn a_damaged_state_file_refuses_rather_than_resets() {
        let tmp = tempfile::tempdir().unwrap();
        let path = freeze_state_path(tmp.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not json").unwrap();
        let (body, sig) = signed("2026-10-20T00:00:00Z");
        let keys = [test_key(1).verifying_key().to_bytes()];
        let v = verify(&body, sig.as_bytes(), &keys).unwrap();
        assert!(check_and_record_freshness(tmp.path(), &v).is_err());
    }

    #[test]
    fn versions_parse_strictly_and_order_numerically() {
        assert!(Version::parse("2.10.0").unwrap() > Version::parse("2.9.9").unwrap());
        for bad in ["2.3", "2.3.0.1", "v2.3.0", "02.3.0", "2.3.x", "", "2..0"] {
            assert!(Version::parse(bad).is_err(), "{bad}");
        }
    }
}
