use secrecy::{ExposeSecret, SecretString};

/// A vault-managed secret value.
///
/// Cannot be logged, serialized, printed, or cloned.
/// The only way to access the inner value is via `expose()`,
/// which returns a short-lived `&str` reference.
/// Memory is zeroed on drop via the `Zeroize` trait.
pub struct VaultSecret {
    inner: SecretString,
}

impl VaultSecret {
    /// Create a new vault secret from a string value.
    /// The input string is consumed — the caller cannot reuse it.
    pub fn new(value: String) -> Self {
        Self {
            inner: SecretString::from(value),
        }
    }

    /// Expose the secret value as a short-lived reference.
    /// Use immediately (e.g., set an HTTP header) and let the reference drop.
    pub fn expose(&self) -> &str {
        self.inner.expose_secret()
    }

    /// Consume the VaultSecret and return the inner SecretString.
    /// For passing to APIs that accept SecretString directly.
    pub fn into_inner(self) -> SecretString {
        self.inner
    }

    /// Get a reference to the inner SecretString.
    pub fn as_secret_string(&self) -> &SecretString {
        &self.inner
    }
}

// VaultSecret intentionally does NOT implement:
// - Display (prevents accidental printing)
// - Debug (prevents accidental logging)
// - Clone (prevents accidental copies)
// - Serialize (prevents accidental persistence)
//
// These omissions are compile-time guarantees, not runtime conventions.
