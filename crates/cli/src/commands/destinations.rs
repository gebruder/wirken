//! Where credentials are handed, and the rows that record it.

use wirken_audit::{CREDENTIALS_SESSION, SessionEvent, SessionId, SessionLog, TrustLevel};
use wirken_vault::{
    Binding, CredentialStore, Destination, McpServerGrant, ProviderGrant, VaultError, VaultSecret,
    default_kind, origin_of,
};

/// A model provider's key, sent to the origin of `base_url`.
pub fn provider(provider: &str, base_url: &str) -> Destination {
    Destination::Provider(ProviderGrant {
        provider: provider.to_string(),
        origin: origin_of(base_url).unwrap_or_default(),
    })
}

/// An MCP server by name and the digest of its signed `mcp.json` entry.
pub fn mcp_server(name: &str, entry_digest: &str) -> Destination {
    Destination::McpServer(McpServerGrant {
        name: name.to_string(),
        entry: entry_digest.to_string(),
    })
}

/// Log a refused handoff with the command that would allow it, and
/// record it when a log is given.
pub fn refused(
    log: Option<&dyn SessionLog>,
    credential: &str,
    destination: &Destination,
    named_by: &str,
) {
    tracing::warn!(
        credential,
        destination = %destination.describe(),
        named_by,
        "credential not handed out: its binding does not allow this destination. \
         Allow it with `wirken credentials grant {credential} {}`",
        destination.grant_flags()
    );
    if let Some(log) = log {
        record_refused(log, credential, destination, named_by);
    }
}

/// Record a refusal already logged.
pub fn record_refused(
    log: &dyn SessionLog,
    credential: &str,
    destination: &Destination,
    named_by: &str,
) {
    append(
        log,
        SessionEvent::CredentialDestinationRefused {
            credential: credential.to_string(),
            destination_kind: destination.kind().to_string(),
            destination: destination.describe(),
            named_by: named_by.to_string(),
        },
    );
}

/// Record that `credential` was handed to `destination`.
pub fn handed_out(log: &dyn SessionLog, credential: &str, destination: &Destination) {
    append(
        log,
        SessionEvent::CredentialHandedOut {
            credential: credential.to_string(),
            destination_kind: destination.kind().to_string(),
            destination: destination.describe(),
        },
    );
}

fn append(log: &dyn SessionLog, event: SessionEvent) {
    let handle = log.handle_for(SessionId::new(CREDENTIALS_SESSION.to_string()));
    if let Err(e) = log.append(&handle, TrustLevel::System, event) {
        tracing::error!(error = %e, "could not record a credential handoff row");
    }
}

/// Store a model provider's key, allowed to that provider at
/// `base_url`.
pub fn store_provider_key(
    store: &CredentialStore,
    name: &str,
    provider_id: &str,
    base_url: &str,
    secret: &VaultSecret,
    rotation_due_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), VaultError> {
    let mut binding = Binding::default();
    binding.grant(provider(provider_id, base_url));
    store.store_bound(
        name,
        provider_id,
        secret,
        None,
        rotation_due_at,
        &binding,
        default_kind(name),
    )
}
