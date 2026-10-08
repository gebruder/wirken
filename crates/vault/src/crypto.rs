use crate::VaultError;
use crate::secret::VaultSecret;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::Rng;
use zeroize::{Zeroize, Zeroizing};

/// Nonce size for XChaCha20-Poly1305 (24 bytes).
const NONCE_SIZE: usize = 24;

/// Encrypt a plaintext secret using XChaCha20-Poly1305.
/// Returns nonce || ciphertext.
/// The key must be a 64-char hex string (encoding 32 bytes).
///
/// `name` is bound into the AEAD additional-authenticated-data field
/// so a ciphertext can only be decrypted under the same name. Pasting
/// a row's ciphertext under a different `name` (a "splice" attack)
/// fails the AEAD tag check rather than silently re-keying the slot.
pub fn encrypt(
    name: &str,
    plaintext: &VaultSecret,
    key: &VaultSecret,
) -> Result<Vec<u8>, VaultError> {
    let key_bytes = Zeroizing::new(
        hex_decode(key.expose())
            .map_err(|e| VaultError::Encryption(format!("invalid hex key: {e}")))?,
    );
    if key_bytes.len() != 32 {
        return Err(VaultError::Encryption(format!(
            "key must be 32 bytes (64 hex chars), got {} bytes",
            key_bytes.len()
        )));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.expose().as_bytes(),
                aad: name.as_bytes(),
            },
        )
        .map_err(|e| VaultError::Encryption(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a nonce || ciphertext blob using XChaCha20-Poly1305.
/// Returns the plaintext as a VaultSecret (zeroed on drop).
/// The key must be a 64-char hex string (encoding 32 bytes).
///
/// `name` must match the value passed to [`encrypt`] for the same
/// row. A mismatch fails the AEAD tag check.
pub fn decrypt(name: &str, encrypted: &[u8], key: &VaultSecret) -> Result<VaultSecret, VaultError> {
    if encrypted.len() < NONCE_SIZE {
        return Err(VaultError::Decryption(
            "ciphertext too short to contain nonce".into(),
        ));
    }

    let key_bytes = Zeroizing::new(
        hex_decode(key.expose())
            .map_err(|e| VaultError::Decryption(format!("invalid hex key: {e}")))?,
    );
    if key_bytes.len() != 32 {
        return Err(VaultError::Decryption(format!(
            "key must be 32 bytes (64 hex chars), got {} bytes",
            key_bytes.len()
        )));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| VaultError::Decryption(e.to_string()))?;

    let nonce = XNonce::try_from(&encrypted[..NONCE_SIZE])
        .map_err(|e| VaultError::Decryption(e.to_string()))?;
    let ciphertext = &encrypted[NONCE_SIZE..];

    let plaintext_bytes = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: name.as_bytes(),
            },
        )
        .map_err(|e| VaultError::Decryption(e.to_string()))?;

    let plaintext =
        String::from_utf8(plaintext_bytes).map_err(|e| VaultError::Decryption(e.to_string()))?;

    Ok(VaultSecret::new(plaintext))
}

/// Generate a random 32-byte key as a VaultSecret.
pub fn generate_key() -> VaultSecret {
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *key_bytes);
    let hex = hex_encode(&*key_bytes);
    // key_bytes zeroed on drop by Zeroizing
    VaultSecret::new(hex)
}

/// Lowercase hex encoding into a buffer sized up front, so the
/// returned `String` is the only heap copy of the encoded bytes.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Hex decoding into a buffer sized up front, so the returned `Vec`
/// is the only heap copy of the decoded bytes. On error the partial
/// buffer is zeroed before it drops.
pub(crate) fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    // Slicing below is by byte offset; a multi-byte character would
    // put a slice boundary inside it and panic.
    if !hex.is_ascii() {
        return Err("non-ASCII hex string".into());
    }
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        match u8::from_str_radix(&hex[i..i + 2], 16) {
            Ok(b) => out.push(b),
            Err(e) => {
                out.zeroize();
                return Err(e.to_string());
            }
        }
    }
    Ok(out)
}

/// Derive a 32-byte key from a passphrase using Argon2id.
/// Returns a hex-encoded 32-byte key as a VaultSecret.
pub fn derive_key_from_passphrase(
    passphrase: &str,
    salt: &[u8],
) -> Result<VaultSecret, VaultError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    // Argon2id: 64MB memory, 3 iterations — matches spec
    let params =
        Params::new(65536, 3, 1, Some(32)).map_err(|e| VaultError::Derivation(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *output)
        .map_err(|e| VaultError::Derivation(e.to_string()))?;

    let hex = hex_encode(&*output);
    // output zeroed on drop by Zeroizing
    Ok(VaultSecret::new(hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_buffers_are_exactly_sized() {
        let bytes: Vec<u8> = (0..=255).collect();

        let hex = hex_encode(&bytes);
        assert_eq!(hex.capacity(), hex.len());
        let expected: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);

        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded.capacity(), decoded.len());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn hex_decode_rejects_non_ascii() {
        // Even byte length, with a character spanning offsets 1..3.
        assert!(hex_decode("a\u{e9}a").is_err());
    }
}
