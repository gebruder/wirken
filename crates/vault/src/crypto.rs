use crate::VaultError;
use crate::secret::VaultSecret;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::Rng;
use zeroize::Zeroizing;

/// Nonce size for XChaCha20-Poly1305 (24 bytes).
const NONCE_SIZE: usize = 24;

/// Encrypt a plaintext secret using XChaCha20-Poly1305.
/// Returns nonce || ciphertext.
/// The key must be a 64-char hex string (encoding 32 bytes).
pub fn encrypt(plaintext: &VaultSecret, key: &VaultSecret) -> Result<Vec<u8>, VaultError> {
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
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.expose().as_bytes())
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
pub fn decrypt(encrypted: &[u8], key: &VaultSecret) -> Result<VaultSecret, VaultError> {
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

    let nonce = XNonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];

    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
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
