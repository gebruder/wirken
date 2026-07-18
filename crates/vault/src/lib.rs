mod crypto;
mod error;
mod keychain;
mod secret;
mod store;

pub use crypto::{decrypt, encrypt};
pub use error::VaultError;
pub use keychain::{
    AgeFileKeychain, Keychain, KeychainKind, load_or_create_alarm_log_key, probe_keychain,
};
pub use secret::VaultSecret;
pub use store::{CredentialMetadata, CredentialStore, ResetPlan, reset, reset_plan};

#[cfg(test)]
mod tests;
