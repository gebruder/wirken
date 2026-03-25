mod crypto;
mod error;
mod keychain;
mod secret;
mod store;

pub use crypto::{decrypt, encrypt};
pub use error::VaultError;
pub use keychain::{probe_keychain, Keychain, KeychainKind};
pub use secret::VaultSecret;
pub use store::{CredentialMetadata, CredentialStore};

#[cfg(test)]
mod tests;
