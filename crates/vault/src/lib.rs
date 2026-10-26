// Slicing a str off a character boundary panics. Each slice that
// stays carries an allow naming why its offsets are boundaries.
#![cfg_attr(not(test), deny(clippy::string_slice))]

mod binding;
mod crypto;
mod error;
mod keychain;
mod kind;
mod secret;
mod store;

pub use binding::{Binding, Destination, McpServerGrant, ProviderGrant, origin_of};
pub use crypto::{decrypt, encrypt};
pub use error::VaultError;
pub use keychain::{
    AgeFileKeychain, Keychain, KeychainKind, load_or_create_alarm_log_key,
    load_or_create_imported_search_key, probe_keychain,
};
pub use kind::{
    BUILTIN_IDENTIFIERS, CredentialKind, MIN_MATCH_BYTES, MatchableSecret, default_kind,
    matchable_parts, matchable_secret,
};
pub use secret::VaultSecret;
pub use store::{
    ADAPTERS, BOUND_FORMAT, CredentialMetadata, CredentialStore, EntryFingerprint, ExclusiveUpdate,
    Migration, MigrationRow, ResetPlan, backup_vault, default_binding, reset, reset_plan,
    restore_vault,
};

#[cfg(test)]
mod tests;
