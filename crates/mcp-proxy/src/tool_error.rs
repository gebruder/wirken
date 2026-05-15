//! Typed MCP tool-call error variants.
//!
//! Bundle A follow-up: previously the only typed error a tool call
//! could surface was `ProxyError` (transport/protocol/io) plus a flat
//! `McpToolResult { success: false, output: String }` for JSON-RPC
//! errors. The agent runtime had no way to distinguish "credential
//! lacks the scope this tool needs" from any other failure, so the
//! operator saw the provider's raw auth-error response and had to
//! know to run `wirken credentials rescope <name>` themselves.
//!
//! This module adds:
//!
//! - [`McpToolError`]: typed variant carried on [`crate::mcp_client::McpToolResult`]
//!   as `error_kind: Option<McpToolError>`. Today the only variant is
//!   [`McpToolError::ScopeNotGranted`]; the enum is left non-exhaustive
//!   in spirit so future detection (rate-limit, token-revoked, etc.)
//!   can land without breaking call sites.
//!
//! - Per-provider detectors that classify the MCP server's auth-error
//!   response body into [`McpToolError::ScopeNotGranted`] when the
//!   response shape matches the provider's known scope-error format.
//!   Each detector is conservative: when the response shape is
//!   ambiguous the detector returns `None` and the tool result falls
//!   through to the generic error path. Detection covers Linear,
//!   GitHub, and Google (the three OAuth providers with scope
//!   catalogs in `crate::oauth`; Notion does not use OAuth scopes and
//!   has no detector).
//!
//! Detection is source-derived in this slice: the parser shapes are
//! drawn from each provider's documented REST / GraphQL error format
//! (GitHub REST API, Linear GraphQL extensions, Google REST error
//! envelope). The first real-world failure that hits a detector
//! either confirms the shape or refines the parser. Detectors are
//! tested against representative response fixtures inline below.

use std::fmt;

/// Typed classification of an MCP tool-call failure. Populated on
/// [`crate::mcp_client::McpToolResult`] by [`detect_scope_not_granted`]
/// when the underlying error body matches a known provider's
/// scope-not-granted shape. Programmatic callers (e.g. agent runtime,
/// future auto-rescope wiring) dispatch on the variant; humans see
/// the `Display` rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpToolError {
    /// The MCP server returned an auth error that a per-provider
    /// detector recognised as "the credential is missing a scope
    /// the tool needs." `scope_hint` is `Some` when the provider's
    /// response named the specific scope and `None` when the
    /// response indicated insufficient scope generically.
    ScopeNotGranted {
        credential: String,
        provider: String,
        scope_hint: Option<String>,
    },
}

impl fmt::Display for McpToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScopeNotGranted {
                credential,
                scope_hint,
                ..
            } => match scope_hint {
                Some(hint) => write!(
                    f,
                    "Tool call refused: credential '{credential}' missing scope {hint}. \
                     Run: wirken credentials rescope {credential}"
                ),
                None => write!(
                    f,
                    "Tool call refused: credential '{credential}' may be missing required scope. \
                     Run: wirken credentials rescope {credential} to review."
                ),
            },
        }
    }
}

/// Dispatch to the per-provider detector for `provider` (the OAuth
/// provider name from [`crate::oauth::OAuthProvider::name`]).
/// `credential` is the vault credential name and surfaces in the
/// typed variant verbatim so the operator-facing `Display` can name
/// the right credential in the rescope hint.
///
/// Returns `None` when:
/// - the provider is not in the OAuth registry that wirken supports
///   for scope detection (Notion, custom, etc.),
/// - or the provider's detector cannot match the response shape with
///   confidence (the generic error path applies).
///
/// The function never guesses: a `Some(ScopeNotGranted)` return
/// means the provider's documented error shape was matched.
pub fn detect_scope_not_granted(
    provider: &str,
    credential: &str,
    error_text: &str,
) -> Option<McpToolError> {
    match provider {
        "github" => detect_github(provider, credential, error_text),
        "linear" => detect_linear(provider, credential, error_text),
        "google" => detect_google(provider, credential, error_text),
        // Notion grants permissions per workspace, not via OAuth
        // scopes; no detector. Any other / unknown provider also
        // falls through.
        _ => None,
    }
}

/// GitHub REST API insufficient-scope detection.
///
/// GitHub returns HTTP 403 with a JSON body like
/// `{"message": "Resource not accessible by integration", ...}` or
/// `{"message": "Resource not accessible by personal access token",
/// ...}` when an OAuth token / personal access token lacks a
/// required scope. The X-Accepted-OAuth-Scopes response header
/// carries the required scope but is not typically forwarded by the
/// MCP server, so detection runs on the body message text.
///
/// GitHub uses 401 for "Bad credentials" (token invalid) and 403 for
/// scope / permission issues; this detector intentionally fires only
/// on the 403 family. The MCP server typically surfaces the body
/// message verbatim in the JSON-RPC error or tool-result text.
fn detect_github(provider: &str, credential: &str, error_text: &str) -> Option<McpToolError> {
    let lower = error_text.to_lowercase();

    // Conservative match on documented GitHub error phrases that
    // specifically indicate scope / permission insufficiency rather
    // than token validity. Each phrase below is drawn from the
    // GitHub REST API documentation or github-mcp-server's error
    // pass-through path.
    let scope_phrase_matches = lower.contains("resource not accessible by integration")
        || lower.contains("resource not accessible by personal access token")
        || lower.contains("must have admin rights")
        || lower.contains("must have push access")
        || (lower.contains("requires authentication") && lower.contains("oauth"))
        || (lower.contains("scope") && lower.contains("required"));

    if !scope_phrase_matches {
        return None;
    }

    Some(McpToolError::ScopeNotGranted {
        credential: credential.to_string(),
        provider: provider.to_string(),
        scope_hint: extract_quoted_scope(error_text),
    })
}

/// Linear GraphQL insufficient-scope detection.
///
/// Linear uses GraphQL; auth errors arrive as HTTP 200 with a body
/// shaped
/// `{"errors": [{"message": "...", "extensions": {"code": "...",
/// "type": "..."}}]}`. The `extensions.code` is typically
/// `"FORBIDDEN"` or `"AUTHENTICATION_ERROR"`; the
/// `extensions.type` is one of `"InsufficientPermissions"`,
/// `"InvalidInput"`, etc. The MCP server commonly stringifies the
/// errors array into a single text response.
///
/// Detection looks for the combination of (forbidden | auth error)
/// plus an insufficient-permissions / scope mention. Both halves
/// must match to avoid false positives on plain auth failures.
fn detect_linear(provider: &str, credential: &str, error_text: &str) -> Option<McpToolError> {
    let lower = error_text.to_lowercase();

    let forbidden_phrase = lower.contains("forbidden") || lower.contains("authentication_error");
    let scope_phrase = lower.contains("insufficientpermissions")
        || lower.contains("insufficient permissions")
        || lower.contains("scope")
        || lower.contains("does not have permission");

    if !(forbidden_phrase && scope_phrase) {
        return None;
    }

    Some(McpToolError::ScopeNotGranted {
        credential: credential.to_string(),
        provider: provider.to_string(),
        scope_hint: extract_quoted_scope(error_text),
    })
}

/// Google REST API insufficient-scope detection.
///
/// Google APIs use a standard error envelope. For OAuth scope
/// errors the body shape is
/// `{"error": {"code": 403, "message": "Request had insufficient
/// authentication scopes.", "status": "PERMISSION_DENIED",
/// "errors": [{"reason": "insufficientPermissions", ...}], ...}}`.
/// The distinctive strings are `"Request had insufficient
/// authentication scopes"` and the `errors[].reason` value
/// `"insufficientPermissions"` (sometimes `"insufficient_scope"`
/// in OAuth-protocol-level errors).
///
/// Google often names the required scope URL in the error message
/// or in `details[]` for some APIs; [`extract_google_scope`]
/// attempts to pull it out and populate `scope_hint`.
fn detect_google(provider: &str, credential: &str, error_text: &str) -> Option<McpToolError> {
    let lower = error_text.to_lowercase();

    // Scope-specific signatures only. `PERMISSION_DENIED` as a Google
    // status code is too broad: it fires on quota, billing, and
    // project-level access denials. Stick to terminology that
    // distinguishes scope issues specifically.
    let matches = lower.contains("insufficientpermissions")
        || lower.contains("insufficient_scope")
        || lower.contains("insufficientscope")
        || lower.contains("request had insufficient authentication scopes");

    if !matches {
        return None;
    }

    Some(McpToolError::ScopeNotGranted {
        credential: credential.to_string(),
        provider: provider.to_string(),
        scope_hint: extract_google_scope(error_text).or_else(|| extract_quoted_scope(error_text)),
    })
}

/// Pull a quoted scope name out of an error message. Matches the
/// first occurrence of a backtick- or single-quoted token after a
/// "scope" keyword. Returns the raw token (without quotes). When no
/// quoted token follows "scope", returns `None`.
///
/// Examples that match:
///   - `... scope 'repo' is required ...`           -> Some("repo")
///   - `... missing scope `write:issues` ...`       -> Some("write:issues")
///
/// Examples that don't match:
///   - `... insufficient permissions ...`           -> None
///   - `... requires `read:user` ...` (no "scope")  -> None
fn extract_quoted_scope(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    let scope_idx = lower.find("scope")?;
    let tail = &text[scope_idx..];
    // Single-quote first.
    if let Some(start) = tail.find('\'') {
        let after = &tail[start + 1..];
        if let Some(end) = after.find('\'') {
            let token = &after[..end];
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    // Backtick fallback.
    if let Some(start) = tail.find('`') {
        let after = &tail[start + 1..];
        if let Some(end) = after.find('`') {
            let token = &after[..end];
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Pull a Google scope URL (https://www.googleapis.com/auth/...) out
/// of an error body. Google's error messages sometimes embed the
/// required scope URL inline (e.g. "Request had insufficient
/// authentication scopes. Required scope:
/// https://www.googleapis.com/auth/drive.file"). When present this
/// is a more useful hint than a quoted-name extraction.
fn extract_google_scope(text: &str) -> Option<String> {
    const PREFIX: &str = "https://www.googleapis.com/auth/";
    let start = text.find(PREFIX)?;
    let tail = &text[start..];
    // Scope URL terminates at whitespace, a quote, or a comma.
    let end = tail
        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ')')
        .unwrap_or(tail.len());
    let scope = &tail[..end];
    if scope.len() <= PREFIX.len() {
        return None;
    }
    Some(scope.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Display
    // ---------------------------------------------------------------

    #[test]
    fn display_with_scope_hint_names_credential_and_scope() {
        let err = McpToolError::ScopeNotGranted {
            credential: "alice-github".into(),
            provider: "github".into(),
            scope_hint: Some("repo".into()),
        };
        let s = format!("{err}");
        assert!(s.contains("alice-github"));
        assert!(s.contains("repo"));
        assert!(s.contains("wirken credentials rescope alice-github"));
    }

    #[test]
    fn display_without_scope_hint_uses_generic_rescope_message() {
        let err = McpToolError::ScopeNotGranted {
            credential: "alice-google".into(),
            provider: "google".into(),
            scope_hint: None,
        };
        let s = format!("{err}");
        assert!(s.contains("alice-google"));
        assert!(s.contains("may be missing required scope"));
        assert!(s.contains("wirken credentials rescope alice-google to review"));
    }

    // ---------------------------------------------------------------
    // GitHub detector
    // ---------------------------------------------------------------

    #[test]
    fn github_resource_not_accessible_matches() {
        let body = r#"{"message":"Resource not accessible by integration","documentation_url":"https://docs.github.com/rest"}"#;
        let err = detect_scope_not_granted("github", "alice", body).expect("github detector fires");
        match err {
            McpToolError::ScopeNotGranted {
                credential,
                provider,
                scope_hint,
            } => {
                assert_eq!(credential, "alice");
                assert_eq!(provider, "github");
                // GitHub's standard 403 body does not name the
                // required scope; hint is None.
                assert!(scope_hint.is_none(), "got {scope_hint:?}");
            }
        }
    }

    #[test]
    fn github_personal_access_token_message_matches() {
        let body = r#"{"message":"Resource not accessible by personal access token","documentation_url":"..."}"#;
        let err = detect_scope_not_granted("github", "bob", body);
        assert!(err.is_some());
    }

    #[test]
    fn github_must_have_admin_rights_matches() {
        let body = r#"{"message":"Must have admin rights to Repository."}"#;
        assert!(detect_scope_not_granted("github", "x", body).is_some());
    }

    #[test]
    fn github_quoted_scope_in_message_populates_hint() {
        // Hypothetical hand-crafted message naming the scope. The
        // extractor is conservative: it only fires when the message
        // contains "scope" plus a quoted token after it.
        let body = r#"{"message":"Resource not accessible by integration; required scope 'repo' is missing"}"#;
        let err = detect_scope_not_granted("github", "alice", body).unwrap();
        match err {
            McpToolError::ScopeNotGranted { scope_hint, .. } => {
                assert_eq!(scope_hint.as_deref(), Some("repo"));
            }
        }
    }

    #[test]
    fn github_bad_credentials_does_not_match() {
        // 401 / invalid-token errors must NOT fire the scope detector;
        // they are a different failure mode (the credential itself is
        // wrong, not under-scoped).
        let body = r#"{"message":"Bad credentials","documentation_url":"..."}"#;
        assert!(detect_scope_not_granted("github", "x", body).is_none());
    }

    #[test]
    fn github_unrelated_error_does_not_match() {
        let body = r#"{"message":"Not Found"}"#;
        assert!(detect_scope_not_granted("github", "x", body).is_none());
    }

    // ---------------------------------------------------------------
    // Linear detector
    // ---------------------------------------------------------------

    #[test]
    fn linear_forbidden_with_insufficient_permissions_matches() {
        let body = r#"{"errors":[{"message":"Forbidden: You don't have permission to perform this action","extensions":{"code":"FORBIDDEN","type":"InsufficientPermissions"}}]}"#;
        let err = detect_scope_not_granted("linear", "alice-linear", body).expect("matches");
        match err {
            McpToolError::ScopeNotGranted {
                credential,
                provider,
                ..
            } => {
                assert_eq!(credential, "alice-linear");
                assert_eq!(provider, "linear");
            }
        }
    }

    #[test]
    fn linear_authentication_error_with_scope_mention_matches() {
        let body = r#"{"errors":[{"message":"This operation requires the write scope.","extensions":{"code":"AUTHENTICATION_ERROR"}}]}"#;
        assert!(detect_scope_not_granted("linear", "x", body).is_some());
    }

    #[test]
    fn linear_forbidden_alone_does_not_match() {
        // FORBIDDEN code without any scope / permission mention
        // could be a row-level access denial, not a scope error.
        // Detector requires both halves.
        let body = r#"{"errors":[{"message":"You cannot access this project","extensions":{"code":"FORBIDDEN"}}]}"#;
        assert!(detect_scope_not_granted("linear", "x", body).is_none());
    }

    #[test]
    fn linear_unrelated_error_does_not_match() {
        let body = r#"{"errors":[{"message":"Validation failed: title required","extensions":{"code":"INVALID_INPUT"}}]}"#;
        assert!(detect_scope_not_granted("linear", "x", body).is_none());
    }

    // ---------------------------------------------------------------
    // Google detector
    // ---------------------------------------------------------------

    #[test]
    fn google_insufficient_scopes_message_matches() {
        let body = r#"{"error":{"code":403,"message":"Request had insufficient authentication scopes.","status":"PERMISSION_DENIED","errors":[{"reason":"insufficientPermissions","domain":"global"}]}}"#;
        let err = detect_scope_not_granted("google", "alice-google", body).expect("matches");
        match err {
            McpToolError::ScopeNotGranted {
                credential,
                provider,
                ..
            } => {
                assert_eq!(credential, "alice-google");
                assert_eq!(provider, "google");
            }
        }
    }

    #[test]
    fn google_insufficient_permissions_reason_matches() {
        let body = r#"{"error":{"code":403,"message":"The user does not have sufficient permissions.","errors":[{"reason":"insufficientPermissions"}]}}"#;
        assert!(detect_scope_not_granted("google", "x", body).is_some());
    }

    #[test]
    fn google_scope_url_in_message_populates_hint() {
        let body = r#"{"error":{"code":403,"message":"Request had insufficient authentication scopes. Required scope: https://www.googleapis.com/auth/drive.file","status":"PERMISSION_DENIED","errors":[{"reason":"insufficientPermissions"}]}}"#;
        let err = detect_scope_not_granted("google", "alice", body).unwrap();
        match err {
            McpToolError::ScopeNotGranted { scope_hint, .. } => {
                assert_eq!(
                    scope_hint.as_deref(),
                    Some("https://www.googleapis.com/auth/drive.file")
                );
            }
        }
    }

    #[test]
    fn google_unrelated_403_does_not_match() {
        // A 403 with no scope-related reason is e.g. project / quota /
        // billing denial. Detector must not fire.
        let body = r#"{"error":{"code":403,"message":"The caller does not have permission.","status":"PERMISSION_DENIED","errors":[{"reason":"forbidden"}]}}"#;
        // "forbidden" reason without "insufficient" terminology is
        // not a scope error; detector must not fire.
        assert!(detect_scope_not_granted("google", "x", body).is_none());
    }

    #[test]
    fn google_500_does_not_match() {
        let body = r#"{"error":{"code":500,"message":"Backend Error","status":"INTERNAL"}}"#;
        assert!(detect_scope_not_granted("google", "x", body).is_none());
    }

    // ---------------------------------------------------------------
    // Cross-provider dispatch
    // ---------------------------------------------------------------

    #[test]
    fn notion_provider_never_matches() {
        // Notion has no OAuth scope concept; even a body that
        // contains scope-shaped keywords must not produce a
        // ScopeNotGranted variant for it.
        let body = r#"{"object":"error","status":403,"code":"restricted_resource","message":"Insufficient permissions for this endpoint."}"#;
        assert!(detect_scope_not_granted("notion", "x", body).is_none());
    }

    #[test]
    fn unknown_provider_never_matches() {
        let body = r#"{"message":"Resource not accessible by integration"}"#;
        assert!(detect_scope_not_granted("custom-provider", "x", body).is_none());
    }

    // ---------------------------------------------------------------
    // Quoted-scope extraction
    // ---------------------------------------------------------------

    #[test]
    fn extract_quoted_scope_single_quotes() {
        let text = "scope 'repo' is required";
        assert_eq!(extract_quoted_scope(text).as_deref(), Some("repo"));
    }

    #[test]
    fn extract_quoted_scope_backticks() {
        let text = "missing scope `write:issues`";
        assert_eq!(extract_quoted_scope(text).as_deref(), Some("write:issues"));
    }

    #[test]
    fn extract_quoted_scope_returns_none_when_no_scope_keyword() {
        assert!(extract_quoted_scope("requires 'admin'").is_none());
    }

    #[test]
    fn extract_quoted_scope_returns_none_when_no_quotes() {
        assert!(extract_quoted_scope("scope is missing").is_none());
    }

    // ---------------------------------------------------------------
    // Google scope URL extraction
    // ---------------------------------------------------------------

    #[test]
    fn extract_google_scope_finds_url_in_sentence() {
        let text = "Required scope: https://www.googleapis.com/auth/drive.file for this call";
        assert_eq!(
            extract_google_scope(text).as_deref(),
            Some("https://www.googleapis.com/auth/drive.file")
        );
    }

    #[test]
    fn extract_google_scope_terminates_on_comma() {
        let text = r#""scope":"https://www.googleapis.com/auth/calendar.events","more":"x""#;
        assert_eq!(
            extract_google_scope(text).as_deref(),
            Some("https://www.googleapis.com/auth/calendar.events")
        );
    }

    #[test]
    fn extract_google_scope_returns_none_without_prefix() {
        assert!(extract_google_scope("nothing here").is_none());
    }
}
