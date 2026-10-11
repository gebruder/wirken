//! Which stored values are secrets, and the parts of a secret that leak
//! detection matches.
//!
//! The vault holds secrets (tokens, app secrets, passwords, API keys)
//! and identifiers (phone numbers, URLs, usernames, project numbers)
//! that legitimately appear in messages. Each row carries a `kind`; a
//! row with none is a secret. Leak detection matches only secrets, on
//! their exact bytes, and only parts at least [`MIN_MATCH_BYTES`] long.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// What a stored value is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// A value that must not leave through model-authored content.
    #[default]
    Secret,
    /// A value that may appear in messages: an address, a number, a URL.
    Identifier,
}

impl CredentialKind {
    /// The column value, and what `wirken credentials list` shows.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Identifier => "identifier",
        }
    }

    /// The kind a column value names. Anything but `identifier`, an
    /// absent value included, is a secret.
    pub(crate) fn from_column(value: Option<&str>) -> Self {
        match value {
            Some("identifier") => Self::Identifier,
            _ => Self::Secret,
        }
    }
}

/// The adapter entries that are identifiers. Every other name an
/// adapter starts with is a secret.
pub const BUILTIN_IDENTIFIERS: &[&str] = &[
    "teams-app-id",
    "matrix-homeserver",
    "matrix-username",
    "whatsapp-phone-number-id",
    "signal-endpoint",
    "signal-phone-number",
    "signal-allowed-senders",
    "google-chat-project-number",
    "imessage-bluebubbles-url",
];

/// The kind a value stored under `name` gets unless it is given one.
pub fn default_kind(name: &str) -> CredentialKind {
    if BUILTIN_IDENTIFIERS.contains(&name) {
        CredentialKind::Identifier
    } else {
        CredentialKind::Secret
    }
}

/// One stored secret as leak detection matches it: its name, for the
/// audit row, and the parts it can appear as.
pub struct MatchableSecret {
    pub name: String,
    pub parts: Vec<Zeroizing<String>>,
}

/// A secret part shorter than this is not matched: short values would
/// match ordinary text.
pub const MIN_MATCH_BYTES: usize = 8;

/// The parts of a stored secret that can appear on their own in model
/// content.
///
/// - An OAuth credential is stored as JSON; its `access_token` and
///   `refresh_token` are matched, not the JSON around them.
/// - A Bedrock key is `access_key_id:secret_access_key[:session_token]`;
///   the secret access key and the session token are matched. The key
///   id names the key and is not itself secret.
/// - Anything else is matched whole.
///
/// Empty parts are dropped; the length floor is applied by the caller,
/// which reports what it drops.
pub fn matchable_parts(value: &str) -> Vec<Zeroizing<String>> {
    if let Some(parts) = oauth_parts(value) {
        return parts;
    }
    if let Some(parts) = bedrock_parts(value) {
        return parts;
    }
    if value.is_empty() {
        Vec::new()
    } else {
        vec![Zeroizing::new(value.to_string())]
    }
}

fn oauth_parts(value: &str) -> Option<Vec<Zeroizing<String>>> {
    let json: Zeroizing<String> = Zeroizing::new(value.trim_start().to_string());
    if !json.starts_with('{') {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_str(&json).ok()?;
    let access = parsed.get("access_token")?.as_str()?;
    let mut parts = vec![Zeroizing::new(access.to_string())];
    if let Some(refresh) = parsed.get("refresh_token").and_then(|r| r.as_str()) {
        parts.push(Zeroizing::new(refresh.to_string()));
    }
    parts.retain(|p| !p.is_empty());
    Some(parts)
}

fn bedrock_parts(value: &str) -> Option<Vec<Zeroizing<String>>> {
    let mut fields = value.split(':');
    let key_id = fields.next()?;
    let secret = fields.next()?;
    let session = fields.next();
    if fields.next().is_some() || !is_aws_key_id(key_id) || secret.is_empty() {
        return None;
    }
    let mut parts = vec![Zeroizing::new(secret.to_string())];
    if let Some(session) = session.filter(|s| !s.is_empty()) {
        parts.push(Zeroizing::new(session.to_string()));
    }
    Some(parts)
}

/// An AWS access key id: 16 to 128 upper-case letters and digits,
/// starting with `A` (`AKIA…`, `ASIA…`).
fn is_aws_key_id(id: &str) -> bool {
    (16..=128).contains(&id.len())
        && id.starts_with('A')
        && id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(value: &str) -> Vec<String> {
        matchable_parts(value)
            .iter()
            .map(|p| p.to_string())
            .collect()
    }

    #[test]
    fn the_nine_builtin_identifiers_default_to_identifier_and_the_rest_to_secret() {
        for name in BUILTIN_IDENTIFIERS {
            assert_eq!(default_kind(name), CredentialKind::Identifier, "{name}");
        }
        assert_eq!(BUILTIN_IDENTIFIERS.len(), 9);
        for name in [
            "telegram-token",
            "slack-adapter-key",
            "whatsapp-verify-token",
            "anthropic-api-key",
            "my-mcp-token",
        ] {
            assert_eq!(default_kind(name), CredentialKind::Secret, "{name}");
        }
    }

    #[test]
    fn an_unknown_column_value_is_a_secret() {
        assert_eq!(CredentialKind::from_column(None), CredentialKind::Secret);
        assert_eq!(
            CredentialKind::from_column(Some("secret")),
            CredentialKind::Secret
        );
        assert_eq!(
            CredentialKind::from_column(Some("something")),
            CredentialKind::Secret
        );
        assert_eq!(
            CredentialKind::from_column(Some("identifier")),
            CredentialKind::Identifier
        );
    }

    #[test]
    fn an_oauth_credential_is_matched_on_its_tokens() {
        let stored = r#"{"access_token":"at-1234567890","refresh_token":"rt-0987654321","expires_at":1,"scope":"read","provider":"linear"}"#;
        assert_eq!(parts(stored), ["at-1234567890", "rt-0987654321"]);
        let no_refresh = r#"{"access_token":"at-1234567890","refresh_token":"","expires_at":1,"scope":"","provider":"x"}"#;
        assert_eq!(parts(no_refresh), ["at-1234567890"]);
    }

    #[test]
    fn a_bedrock_key_is_matched_on_its_secret_and_session_token() {
        assert_eq!(
            parts("AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
        );
        assert_eq!(
            parts("ASIAIOSFODNN7EXAMPLE:secret-access-key:session-token-value"),
            ["secret-access-key", "session-token-value"]
        );
    }

    #[test]
    fn anything_else_is_matched_whole() {
        assert_eq!(parts("xoxb-123-456-abc"), ["xoxb-123-456-abc"]);
        // A colon alone does not make a Bedrock key.
        assert_eq!(parts("user:password-value"), ["user:password-value"]);
        assert_eq!(parts("{not json"), ["{not json"]);
        assert!(parts("").is_empty());
    }
}
