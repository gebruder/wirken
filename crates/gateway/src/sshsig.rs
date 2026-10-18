//! OpenSSH signatures (`ssh-keygen -Y sign`), verified in-process.
//!
//! Wirken releases are signed with `ssh-keygen -Y sign` under an
//! Ed25519 key, so a binary that checks a release has to read that
//! format. The format is OpenSSH's `PROTOCOL.sshsig`:
//!
//! ```text
//! armor     -----BEGIN SSH SIGNATURE----- / base64 / -----END SSH SIGNATURE-----
//! blob      "SSHSIG" | uint32 version (1) | string publickey | string namespace
//!           | string reserved | string hash_algorithm | string signature
//! signed    "SSHSIG" | string namespace | string reserved
//!           | string hash_algorithm | string H(message)
//! ```
//!
//! where `string` is a big-endian `uint32` length followed by that
//! many bytes, `publickey` is `string "ssh-ed25519" | string key(32)`
//! and `signature` is `string "ssh-ed25519" | string sig(64)`.
//!
//! This is a trust path, so it depends on nothing past what it must:
//! ed25519-dalek 3 for the signature and sha2 for the message hash.
//! Base64 is decoded here, strictly, rather than through a 0.x crate.
//! Only Ed25519 keys and the two hash algorithms `ssh-keygen` emits
//! are accepted; anything else is refused, not skipped.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const ARMOR_END: &str = "-----END SSH SIGNATURE-----";
const MAGIC: &[u8; 6] = b"SSHSIG";
const VERSION: u32 = 1;
const KEY_TYPE: &[u8] = b"ssh-ed25519";
/// An armored signature over a Wirken release is a few hundred bytes.
/// Anything far larger is not one, and is refused before decoding.
const MAX_ARMOR_BYTES: usize = 16 * 1024;

/// Why a signature was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshSigError {
    #[error("not an SSH signature: {0}")]
    Armor(&'static str),
    #[error("SSH signature is not valid base64")]
    Base64,
    #[error("SSH signature is malformed: {0}")]
    Malformed(&'static str),
    #[error("SSH signature version {0} is not supported")]
    Version(u32),
    #[error("SSH signature key type {0:?} is not supported; only ssh-ed25519 is")]
    KeyType(String),
    #[error("SSH signature hash algorithm {0:?} is not supported")]
    HashAlgorithm(String),
    #[error("signed for namespace {found:?}, expected {expected:?}")]
    Namespace { expected: String, found: String },
    #[error("signed by {fingerprint}, which is not a pinned key")]
    UnknownKey { fingerprint: String },
    #[error("signature does not verify")]
    BadSignature,
}

/// The hash algorithm the signer applied to the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    fn name(self) -> &'static [u8] {
        match self {
            HashAlgorithm::Sha256 => b"sha256",
            HashAlgorithm::Sha512 => b"sha512",
        }
    }

    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => Sha256::digest(message).to_vec(),
            HashAlgorithm::Sha512 => Sha512::digest(message).to_vec(),
        }
    }
}

/// A parsed SSH signature, not yet verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSignature {
    pub public_key: [u8; 32],
    pub namespace: Vec<u8>,
    pub reserved: Vec<u8>,
    pub hash_algorithm: HashAlgorithm,
    pub signature: [u8; 64],
}

/// What a successful verification establishes: which pinned key
/// signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub public_key: [u8; 32],
    /// `SHA256:<base64>` as `ssh-keygen -l` prints it.
    pub fingerprint: String,
}

/// Verify `armored` as a signature over `message` under `namespace`
/// by one of `keys`. Every check refuses: armor, encoding, structure,
/// key type, hash algorithm, namespace, key, signature.
pub fn verify(
    armored: &str,
    message: &[u8],
    namespace: &str,
    keys: &[[u8; 32]],
) -> Result<Verified, SshSigError> {
    let sig = parse_armored(armored)?;
    if sig.namespace != namespace.as_bytes() {
        return Err(SshSigError::Namespace {
            expected: namespace.to_string(),
            found: String::from_utf8_lossy(&sig.namespace).into_owned(),
        });
    }
    let fingerprint = fingerprint(&sig.public_key);
    if !keys.contains(&sig.public_key) {
        return Err(SshSigError::UnknownKey { fingerprint });
    }
    let key = VerifyingKey::from_bytes(&sig.public_key).map_err(|_| SshSigError::BadSignature)?;
    let signed = signed_data(&sig, message);
    key.verify_strict(&signed, &Signature::from_bytes(&sig.signature))
        .map_err(|_| SshSigError::BadSignature)?;
    Ok(Verified {
        public_key: sig.public_key,
        fingerprint,
    })
}

/// The bytes the signer signed for `message`.
fn signed_data(sig: &SshSignature, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    put_string(&mut out, &sig.namespace);
    put_string(&mut out, &sig.reserved);
    put_string(&mut out, sig.hash_algorithm.name());
    put_string(&mut out, &sig.hash_algorithm.digest(message));
    out
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Parse an armored SSH signature. Line endings may be `\n` or
/// `\r\n` and surrounding whitespace is ignored; anything else
/// outside the base64 body is refused.
pub fn parse_armored(armored: &str) -> Result<SshSignature, SshSigError> {
    if armored.len() > MAX_ARMOR_BYTES {
        return Err(SshSigError::Armor("too large"));
    }
    let mut lines = armored.trim().lines().map(|l| l.trim_end_matches('\r'));
    if lines.next() != Some(ARMOR_BEGIN) {
        return Err(SshSigError::Armor("missing BEGIN line"));
    }
    let mut body = String::new();
    let mut ended = false;
    for line in lines {
        if ended {
            return Err(SshSigError::Armor("content after END line"));
        }
        if line == ARMOR_END {
            ended = true;
            continue;
        }
        body.push_str(line);
    }
    if !ended {
        return Err(SshSigError::Armor("missing END line"));
    }
    parse_blob(&decode_base64(&body).ok_or(SshSigError::Base64)?)
}

/// Parse the decoded signature blob.
pub fn parse_blob(blob: &[u8]) -> Result<SshSignature, SshSigError> {
    let mut r = Reader(blob);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(SshSigError::Malformed("bad magic"));
    }
    let version = r.u32()?;
    if version != VERSION {
        return Err(SshSigError::Version(version));
    }
    let public_key = ed25519_from(r.string()?, 32, "public key")?;
    let namespace = r.string()?.to_vec();
    let reserved = r.string()?.to_vec();
    let hash_algorithm = match r.string()? {
        b"sha256" => HashAlgorithm::Sha256,
        b"sha512" => HashAlgorithm::Sha512,
        other => {
            return Err(SshSigError::HashAlgorithm(
                String::from_utf8_lossy(other).into_owned(),
            ));
        }
    };
    let signature = ed25519_from(r.string()?, 64, "signature")?;
    if !r.0.is_empty() {
        return Err(SshSigError::Malformed("trailing bytes"));
    }
    if namespace.is_empty() {
        return Err(SshSigError::Malformed("empty namespace"));
    }
    Ok(SshSignature {
        public_key: public_key.try_into().expect("length checked"),
        namespace,
        reserved,
        hash_algorithm,
        signature: signature.try_into().expect("length checked"),
    })
}

/// `string "ssh-ed25519" | string bytes(len)`, returning the bytes.
fn ed25519_from<'a>(
    field: &'a [u8],
    len: usize,
    what: &'static str,
) -> Result<&'a [u8], SshSigError> {
    let mut r = Reader(field);
    let key_type = r.string()?;
    if key_type != KEY_TYPE {
        return Err(SshSigError::KeyType(
            String::from_utf8_lossy(key_type).into_owned(),
        ));
    }
    let bytes = r.string()?;
    if bytes.len() != len || !r.0.is_empty() {
        return Err(SshSigError::Malformed(what));
    }
    Ok(bytes)
}

/// Parse an OpenSSH public key line, `ssh-ed25519 <base64> [comment]`,
/// as `ssh-keygen` and an allowed_signers file carry it.
pub fn parse_public_key(line: &str) -> Result<[u8; 32], SshSigError> {
    let mut parts = line.split_whitespace();
    if parts.next() != Some("ssh-ed25519") {
        return Err(SshSigError::Malformed("not an ssh-ed25519 key line"));
    }
    let blob = decode_base64(parts.next().ok_or(SshSigError::Malformed("no key"))?)
        .ok_or(SshSigError::Base64)?;
    let key = ed25519_from(&blob, 32, "public key")?;
    Ok(key.try_into().expect("length checked"))
}

/// The key's fingerprint as `ssh-keygen -l` prints it: `SHA256:`
/// followed by the unpadded base64 of the SHA-256 of its wire form.
pub fn fingerprint(key: &[u8; 32]) -> String {
    let mut wire = Vec::new();
    put_string(&mut wire, KEY_TYPE);
    put_string(&mut wire, key);
    format!("SHA256:{}", encode_base64_unpadded(&Sha256::digest(&wire)))
}

/// A cursor over SSH wire encoding. Every read is bounds-checked.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SshSigError> {
        if self.0.len() < n {
            return Err(SshSigError::Malformed("truncated"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, SshSigError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> Result<&'a [u8], SshSigError> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict standard base64: whole quantums, `=` only at the end, and
/// no stray bits in a padded quantum, so each input has one decoding.
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.is_empty() || !s.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let quantums = s.len() / 4;
    for (i, q) in s.as_chunks::<4>().0.iter().enumerate() {
        let last = i + 1 == quantums;
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut v = [0u8; 4];
        for (j, &c) in q[..4 - pad].iter().enumerate() {
            v[j] = sextet(c)?;
        }
        let n = (u32::from(v[0]) << 18)
            | (u32::from(v[1]) << 12)
            | (u32::from(v[2]) << 6)
            | u32::from(v[3]);
        match pad {
            0 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]),
            1 if n & 0xff == 0 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8]),
            2 if n & 0xffff == 0 => out.push((n >> 16) as u8),
            _ => return None,
        }
    }
    Some(out)
}

fn encode_base64_unpadded(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for k in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * k)) & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Produced by `ssh-keygen -Y sign` from two throwaway keys whose
    // private halves were discarded. See testdata/sshsig/.
    const KEY_A: &str = include_str!("../testdata/sshsig/key_a.pub");
    const KEY_B: &str = include_str!("../testdata/sshsig/key_b.pub");
    const MESSAGE: &[u8] = include_bytes!("../testdata/sshsig/message.txt");
    const A_SHA512: &str = include_str!("../testdata/sshsig/a_manifest_sha512.sig");
    const A_SHA256: &str = include_str!("../testdata/sshsig/a_manifest_sha256.sig");
    const A_FILE: &str = include_str!("../testdata/sshsig/a_file.sig");
    const B_MANIFEST: &str = include_str!("../testdata/sshsig/b_manifest.sig");
    const NS: &str = "wirken-release-manifest";

    fn key(line: &str) -> [u8; 32] {
        parse_public_key(line).unwrap()
    }

    #[test]
    fn a_valid_signature_verifies_under_either_hash() {
        for armored in [A_SHA512, A_SHA256] {
            let v = verify(armored, MESSAGE, NS, &[key(KEY_A)]).unwrap();
            assert_eq!(v.public_key, key(KEY_A));
        }
    }

    #[test]
    fn the_fingerprint_matches_ssh_keygen() {
        // `ssh-keygen -lf key_a.pub`
        assert_eq!(
            fingerprint(&key(KEY_A)),
            "SHA256:kMnAkfgDYmbrYpGM0BC3gckTl3sSdn69QbdbXxMzRhU"
        );
    }

    #[test]
    fn a_wrong_namespace_is_refused() {
        assert_eq!(
            verify(A_FILE, MESSAGE, NS, &[key(KEY_A)]),
            Err(SshSigError::Namespace {
                expected: NS.into(),
                found: "file".into()
            })
        );
    }

    #[test]
    fn a_key_that_is_not_pinned_is_refused() {
        assert_eq!(
            verify(B_MANIFEST, MESSAGE, NS, &[key(KEY_A)]),
            Err(SshSigError::UnknownKey {
                fingerprint: fingerprint(&key(KEY_B))
            })
        );
        // And a signature by a pinned key verifies only if it is the
        // key in the signature: B's key pinned does not admit A's.
        assert!(matches!(
            verify(A_SHA512, MESSAGE, NS, &[key(KEY_B)]),
            Err(SshSigError::UnknownKey { .. })
        ));
    }

    #[test]
    fn a_tampered_message_is_refused() {
        let mut tampered = MESSAGE.to_vec();
        tampered[2] ^= 1;
        assert_eq!(
            verify(A_SHA512, &tampered, NS, &[key(KEY_A)]),
            Err(SshSigError::BadSignature)
        );
        assert_eq!(
            verify(A_SHA512, b"", NS, &[key(KEY_A)]),
            Err(SshSigError::BadSignature)
        );
    }

    #[test]
    fn a_signature_naming_a_pinned_key_with_another_keys_bytes_is_refused() {
        // B's signature bytes spliced into A's blob: the key matches,
        // the signature does not.
        let a = parse_armored(A_SHA512).unwrap();
        let b = parse_armored(B_MANIFEST).unwrap();
        let mut spliced = a.clone();
        spliced.signature = b.signature;
        let signed = signed_data(&spliced, MESSAGE);
        let k = VerifyingKey::from_bytes(&a.public_key).unwrap();
        assert!(
            k.verify_strict(&signed, &Signature::from_bytes(&spliced.signature))
                .is_err()
        );
    }

    #[test]
    fn malformed_armor_is_refused() {
        let body: String = A_SHA512
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let cases: Vec<(String, &str)> = vec![
            (String::new(), "empty"),
            (body.clone(), "no armor lines"),
            (A_SHA512.replace(ARMOR_END, ""), "no END line"),
            (A_SHA512.replace(ARMOR_BEGIN, ""), "no BEGIN line"),
            (format!("{A_SHA512}\nextra"), "content after END"),
            (A_SHA512.replacen('A', "!", 1), "non-base64 byte"),
            (A_SHA512.replacen("==", "=", 1), "bad padding"),
            (
                format!("{ARMOR_BEGIN}\n{}\n{ARMOR_END}", &body[..body.len() - 8]),
                "truncated",
            ),
            (
                format!("{ARMOR_BEGIN}\nAAAA\n{ARMOR_END}"),
                "too short for magic",
            ),
            ("x".repeat(MAX_ARMOR_BYTES + 1), "oversize"),
        ];
        for (armored, why) in cases {
            assert!(
                verify(&armored, MESSAGE, NS, &[key(KEY_A)]).is_err(),
                "{why} was accepted"
            );
        }
    }

    #[test]
    fn crlf_line_endings_are_accepted() {
        let crlf = A_SHA512.replace('\n', "\r\n");
        assert!(verify(&crlf, MESSAGE, NS, &[key(KEY_A)]).is_ok());
    }

    #[test]
    fn trailing_bytes_and_bad_version_are_refused() {
        let blob = decode_base64(
            &A_SHA512
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<String>(),
        )
        .unwrap();
        let mut trailing = blob.clone();
        trailing.push(0);
        assert_eq!(
            parse_blob(&trailing),
            Err(SshSigError::Malformed("trailing bytes"))
        );
        let mut v2 = blob.clone();
        v2[9] = 2;
        assert_eq!(parse_blob(&v2), Err(SshSigError::Version(2)));
    }

    #[test]
    fn base64_round_trips_and_is_strict() {
        assert_eq!(decode_base64("TWFu").unwrap(), b"Man");
        assert_eq!(decode_base64("TWE=").unwrap(), b"Ma");
        assert_eq!(decode_base64("TQ==").unwrap(), b"M");
        // Stray bits in a padded quantum.
        assert_eq!(decode_base64("TR=="), None);
        assert_eq!(decode_base64("TQ=="), Some(b"M".to_vec()));
        assert_eq!(decode_base64("T==="), None);
        assert_eq!(decode_base64("TQ==TWFu"), None);
        assert_eq!(encode_base64_unpadded(b"Man"), "TWFu");
        assert_eq!(encode_base64_unpadded(b"Ma"), "TWE");
        assert_eq!(encode_base64_unpadded(b"M"), "TQ");
    }
}
