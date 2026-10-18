//! SSH signature parsing and verification, as `wirken update` runs it
//! on a release manifest's `.sig`.
//!
//! The signature file arrives over the network before anything about
//! it is trusted, so the parser sees attacker bytes first. Each input
//! is tried as an armored signature over a fixed message and, as raw
//! bytes, as a decoded signature blob.
//!
//! Asserted, beyond no panic:
//!
//! - A signature that verifies names the one pinned key and was made
//!   under the expected namespace. Nothing else may come back `Ok`.
//! - Verification of a parsed signature never succeeds for a message
//!   other than the one it was made over.
//!
//! The corpus seeds are the `ssh-keygen -Y sign` vectors under
//! crates/gateway/testdata/sshsig/. A crash is a finding. Do not
//! weaken an assertion to make a case pass.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wirken_gateway::sshsig::{parse_armored, parse_blob, parse_public_key, verify};

const KEY_A: &str = include_str!("../../crates/gateway/testdata/sshsig/key_a.pub");
const MESSAGE: &[u8] = include_bytes!("../../crates/gateway/testdata/sshsig/message.txt");
const NS: &str = "wirken-release-manifest";

fuzz_target!(|data: &[u8]| {
    let key = parse_public_key(KEY_A).expect("test key parses");

    let text = String::from_utf8_lossy(data);
    if let Ok(v) = verify(&text, MESSAGE, NS, &[key]) {
        assert_eq!(v.public_key, key, "verified under a key that is not pinned");
        let sig = parse_armored(&text).expect("a verified signature parses");
        assert_eq!(sig.namespace, NS.as_bytes(), "verified under another namespace");
        let mut other = MESSAGE.to_vec();
        other.push(b'\n');
        assert!(
            verify(&text, &other, NS, &[key]).is_err(),
            "one signature verified for two messages"
        );
    }

    let _ = parse_blob(data);
});
