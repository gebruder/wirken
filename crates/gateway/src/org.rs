//! Organization policy: centralized config pulled from a company endpoint.
//!
//! IT manages one JSON document at a URL. Each developer's wirken instance
//! pulls it on setup and periodically on run.
//!
//! Example org config served at https://wirken.corp.example.com/config:
//!
//! ```json
//! {
//!     "provider": {
//!         "provider": "openai",
//!         "model": "gpt-4o",
//!         "base_url": "https://api.openai.com/v1"
//!     },
//!     "api_key_name": "openai-api-key",
//!     "siem": {
//!         "target": "datadog",
//!         "endpoint": "https://http-intake.logs.datadoghq.com/api/v2/logs",
//!         "api_key": "dd-org-key",
//!         "service": "wirken",
//!         "environment": "production"
//!     },
//!     "mcp": {
//!         "servers": {
//!             "datadog": {
//!                 "command": "npx",
//!                 "args": ["-y", "@datadog/mcp-server"],
//!                 "env": {}
//!             }
//!         }
//!     },
//!     "permissions": {
//!         "sandbox_mode": "exec-only",
//!         "allowed_tools": ["exec", "read_file", "write_file", "list_files", "web_search"],
//!         "blocked_tools": ["generate_image"]
//!     }
//! }
//! ```

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Filename in the gateway data directory that holds the operator-pinned
/// Ed25519 public key used to verify org-config responses. The file
/// contains a 64-character lowercase hex string with optional surrounding
/// whitespace.
pub const ORG_CONFIG_PUBKEY_FILE: &str = "org-config-pubkey.pub";

/// HTTP header carrying the Ed25519 signature over the raw response
/// body. Base64-encoded, no whitespace.
pub const ORG_CONFIG_SIGNATURE_HEADER: &str = "X-Wirken-Org-Signature";

fn load_org_pubkey(data_dir: &Path) -> Result<VerifyingKey, String> {
    let path = data_dir.join(ORG_CONFIG_PUBKEY_FILE);
    let body = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "read {}: {e} (place a 64-char hex-encoded ed25519 public key here, \
             or set WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG=1 to opt out)",
            path.display()
        )
    })?;
    let hex_str = body.trim();
    if hex_str.len() != 64 {
        return Err(format!(
            "{}: expected 64 hex chars, got {} chars",
            path.display(),
            hex_str.len()
        ));
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)
            .map_err(|_| format!("{}: non-utf8 hex byte at offset {i}", path.display()))?;
        bytes[i] = u8::from_str_radix(s, 16)
            .map_err(|_| format!("{}: invalid hex byte '{s}' at offset {i}", path.display()))?;
    }
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn verify_org_config_signature(
    body: &[u8],
    sig_b64: &str,
    pubkey: &VerifyingKey,
) -> Result<(), String> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .map_err(|e| format!("decode signature: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature length: expected 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    pubkey
        .verify_strict(body, &sig)
        .map_err(|e| format!("signature verification failed: {e}"))
}

/// Parse a boolean-shaped environment variable used as an
/// escape-hatch gate. Recognizes `"1"`, `"true"`, `"yes"`, and
/// `"on"` (case-insensitive) as truthy. Recognizes the unset case
/// and `"0"`, `"false"`, `"no"`, `"off"`, empty as falsy. Any other
/// non-empty value is treated as falsy and emits a `tracing::warn!`
/// so an operator who typo'd `"yEs!"` or `"enable"` sees their
/// intent did not engage rather than discovering it months later.
pub fn parse_boolean_escape(name: &str) -> bool {
    let raw = match std::env::var(name) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => {
            tracing::warn!(
                env_var = name,
                value = %raw,
                "{name} is set but not a recognized boolean (1/true/yes/on or \
                 0/false/no/off, case-insensitive); treating as unset"
            );
            false
        }
    }
}

fn unsigned_allowed() -> bool {
    parse_boolean_escape("WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG")
}

fn stale_allowed() -> bool {
    parse_boolean_escape("WIRKEN_ALLOW_STALE_ORG_CONFIG")
}

/// Reject a bundle whose `signed_at` is older than `max_age_seconds`.
/// Both fields must be present for the freshness check to engage; a
/// bundle without either is treated as having no freshness claim.
/// Returns `Ok(())` when fresh OR when the operator opted into stale
/// acceptance via `WIRKEN_ALLOW_STALE_ORG_CONFIG=1` (which logs a
/// warn). Errors otherwise with a structured message.
fn check_org_config_freshness(config: &OrgConfig) -> Result<(), String> {
    let (signed_at, max_age) = match (config.signed_at, config.max_age_seconds) {
        (Some(ts), Some(age)) => (ts, age),
        _ => return Ok(()),
    };
    let now = chrono::Utc::now();
    let age_seconds = (now - signed_at).num_seconds();
    if age_seconds < 0 {
        // Clock skew: bundle claims to be from the future. Reject
        // unless the operator opted into stale-mode (which we treat
        // as "trust the bundle", same as the past-stale case).
        if stale_allowed() {
            tracing::warn!(
                signed_at = %signed_at,
                now = %now,
                "WIRKEN_ALLOW_STALE_ORG_CONFIG=1: accepting org-config bundle whose \
                 signed_at is in the future (clock skew or replay)"
            );
            return Ok(());
        }
        return Err(format!(
            "org config signed_at {signed_at} is in the future (now {now}); \
             refusing. Set WIRKEN_ALLOW_STALE_ORG_CONFIG=1 to opt out"
        ));
    }
    if (age_seconds as u64) > max_age {
        if stale_allowed() {
            tracing::warn!(
                age_seconds,
                max_age_seconds = max_age,
                signed_at = %signed_at,
                "WIRKEN_ALLOW_STALE_ORG_CONFIG=1: accepting org-config bundle past \
                 its max_age_seconds; the bundle's freshness window has expired"
            );
            return Ok(());
        }
        return Err(format!(
            "org config bundle is stale: signed_at {signed_at} is {age_seconds}s old, \
             max_age_seconds is {max_age}. Refresh the upstream signed bundle, or \
             set WIRKEN_ALLOW_STALE_ORG_CONFIG=1 to opt out"
        ));
    }
    Ok(())
}

/// Write `contents` to `path` with mode 0o600 on unix. On non-unix
/// platforms falls back to `std::fs::write` and emits a tracing warning
/// noting that owner-only file permissions could not be enforced.
///
/// Public so `wirken-cli`'s setup flow lands the same posture as the
/// org-config refresh path; both write the same set of trust files
/// under the data directory and should not differ in mode.
pub fn write_with_secret_perms(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .mode(0o600)
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        f.write_all(contents)?;
        // OpenOptions::mode only applies on file creation. A
        // pre-existing file would keep its previous (looser) mode on
        // rewrite. Re-chmod unconditionally so an upgrade path that
        // ever landed a 0o644 file converges back to 0o600.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tracing::warn!(
            "writing {} without 0o600-equivalent file permissions; \
             relying on user profile isolation for confidentiality",
            path.display()
        );
        std::fs::write(path, contents)
    }
}

/// Organization config pulled from a central endpoint.
///
/// `deny_unknown_fields` rejects any key the binary does not implement
/// (for example a `skills` block) as a parse error, so a restriction the
/// gateway cannot enforce surfaces as a config error instead of being
/// silently dropped.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OrgConfig {
    /// LLM provider configuration (provider, model, base_url).
    #[serde(default)]
    pub provider: Option<serde_json::Value>,

    /// Vault credential name for the org API key.
    /// If set, the developer is prompted to enter it during setup.
    #[serde(default)]
    pub api_key_name: Option<String>,

    /// SIEM forwarding configuration.
    #[serde(default)]
    pub siem: Option<serde_json::Value>,

    /// MCP server configuration.
    #[serde(default)]
    pub mcp: Option<serde_json::Value>,

    /// Permission policy.
    #[serde(default)]
    pub permissions: Option<OrgPermissions>,

    /// RFC 3339 timestamp when this config bundle was signed. Lives
    /// inside the signed body so a same-UID attacker who replaces the
    /// HTTP response cannot trim it without invalidating the
    /// signature. Optional for back-compat with older bundles; the
    /// gateway treats `None` as "no freshness claim" and falls back
    /// to whatever the operator set via `WIRKEN_ALLOW_STALE_ORG_CONFIG`.
    #[serde(default)]
    pub signed_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Maximum age in seconds the gateway will accept for this
    /// bundle. Together with `signed_at`, lets an org pin a TTL on
    /// signed config so a paused-then-resumed adversary can't replay
    /// an old bundle indefinitely. Honored only when `signed_at` is
    /// also set.
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
}

/// Organization-level permission controls.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrgPermissions {
    /// Sandbox mode: "off", "exec-only", "gvisor"
    #[serde(default)]
    pub sandbox_mode: Option<String>,

    /// Tools the agent is allowed to use. Empty means all.
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// Tools explicitly blocked.
    #[serde(default)]
    pub blocked_tools: Vec<String>,
}

/// Fetch org config from a URL and verify it against the operator-pinned
/// Ed25519 public key at `<data_dir>/org-config-pubkey.pub`.
///
/// The endpoint must serve the response body together with a detached
/// Ed25519 signature in the `X-Wirken-Org-Signature` HTTP header,
/// base64-encoded, computed over the raw body bytes. The body is parsed
/// only after signature verification succeeds.
///
/// Verification can be disabled by setting
/// `WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG=1`. Each fetch in that mode emits
/// a `tracing::warn!` so the operator-visible posture is unmistakable.
pub async fn fetch_org_config(url: &str, data_dir: &Path) -> Result<OrgConfig, String> {
    let http = reqwest::Client::new();
    let resp = http
        .get(url)
        .header("User-Agent", "wirken")
        .send()
        .await
        .map_err(|e| format!("fetch org config: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("org config returned HTTP {}", resp.status()));
    }

    let sig_header = resp
        .headers()
        .get(ORG_CONFIG_SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body = resp
        .bytes()
        .await
        .map_err(|e| format!("read org config body: {e}"))?;

    if unsigned_allowed() {
        tracing::warn!(
            "WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG=1: skipping org-config signature \
             verification — the response body is trusted as-is"
        );
    } else {
        let sig = sig_header.ok_or_else(|| {
            format!(
                "org config response missing {ORG_CONFIG_SIGNATURE_HEADER} header; \
                 set WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG=1 to opt out"
            )
        })?;
        let pubkey = load_org_pubkey(data_dir)?;
        verify_org_config_signature(&body, &sig, &pubkey)?;
    }

    let config =
        serde_json::from_slice::<OrgConfig>(&body).map_err(|e| format!("parse org config: {e}"))?;

    // Freshness binding. Both fields live inside the signed body, so
    // a tampered timestamp fails the signature check above before we
    // reach this gate. The gate exists for the legitimate-but-stale
    // case: a bundle whose signature is valid but whose declared
    // `signed_at` + `max_age_seconds` window has expired.
    check_org_config_freshness(&config)?;

    Ok(config)
}

/// Save the org endpoint URL for periodic refresh. The file ends up at
/// `<data_dir>/org.url` with mode 0o600 on unix; the URL itself is not
/// secret but the `exec=Off` audit (`docs/security-properties.md`)
/// names it as one of the trust files an unsandboxed shell can rewrite,
/// so it follows the same posture as the other org-config files.
pub fn save_org_url(data_dir: &Path, url: &str) -> std::io::Result<()> {
    write_with_secret_perms(&data_dir.join("org.url"), url.as_bytes())
}

/// Load the saved org endpoint URL.
pub fn load_org_url(data_dir: &Path) -> Option<String> {
    let path = data_dir.join("org.url");
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Failure return for [`apply_org_config`]. Carries the partial
/// list of sections that were applied before the failure so callers
/// can emit a structured `org-config.apply-failed` audit row showing
/// which writes already landed.
#[derive(Debug, Clone)]
pub struct ApplyError {
    /// Sections that were written successfully before the failure.
    pub applied: Vec<String>,
    /// Section name that failed, e.g. `"sandbox"` or `"tool_policy"`.
    pub section: String,
    /// Display string for the underlying I/O / serialization error.
    pub error: String,
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "apply org config section {}: {}",
            self.section, self.error
        )
    }
}

impl std::error::Error for ApplyError {}

/// Apply org config to the local data directory.
/// Writes provider.json, siem.json, mcp.json as appropriate.
/// Does not overwrite files that already exist unless force is true.
///
/// On a per-section failure the partial list of already-applied
/// sections is returned alongside the failed section name. The caller
/// uses this to emit a structured audit row so an operator can
/// reconstruct what landed before the abort.
pub fn apply_org_config(
    data_dir: &Path,
    org: &OrgConfig,
    force: bool,
) -> Result<Vec<String>, ApplyError> {
    let mut applied: Vec<String> = Vec::new();

    fn write_section(
        applied: &mut Vec<String>,
        section: &str,
        path: &Path,
        body: &[u8],
    ) -> Result<(), ApplyError> {
        write_with_secret_perms(path, body).map_err(|e| ApplyError {
            applied: applied.clone(),
            section: section.into(),
            error: e.to_string(),
        })?;
        applied.push(section.into());
        Ok(())
    }

    // Provider
    if let Some(ref provider) = org.provider {
        let path = data_dir.join("provider.json");
        if force || !path.exists() {
            let body = serde_json::to_string_pretty(provider).unwrap_or_default();
            write_section(&mut applied, "provider", &path, body.as_bytes())?;
        }
    }

    // SIEM
    if let Some(ref siem) = org.siem {
        let path = data_dir.join("siem.json");
        if force || !path.exists() {
            let body = serde_json::to_string_pretty(siem).unwrap_or_default();
            write_section(&mut applied, "siem", &path, body.as_bytes())?;
        }
    }

    // MCP
    if let Some(ref mcp) = org.mcp {
        let path = data_dir.join("mcp.json");
        if force || !path.exists() {
            let body = serde_json::to_string_pretty(mcp).unwrap_or_default();
            write_section(&mut applied, "mcp", &path, body.as_bytes())?;
        }
    }

    // Sandbox mode, driven by `permissions.sandbox_mode` on the pulled
    // org config. Stored as a separate `sandbox.json` file so an org
    // update does not disturb unrelated provider config. The CLI's
    // `load_sandbox_config` helper reads this file on each gateway
    // start.
    if let Some(ref perms) = org.permissions
        && let Some(ref mode) = perms.sandbox_mode
    {
        let path = data_dir.join("sandbox.json");
        if force || !path.exists() {
            let body = serde_json::to_string_pretty(&serde_json::json!({ "mode": mode }))
                .unwrap_or_default();
            write_section(&mut applied, "sandbox", &path, body.as_bytes())?;
        }
    }

    // Tool allow/deny policy. Persisted to `tool_policy.json` on the
    // same principle as `sandbox.json`: a single-purpose file the
    // gateway reads on every start. Absent or empty lists disable
    // the corresponding check in `crates/agent/src/runtime.rs::execute_tool`.
    if let Some(ref perms) = org.permissions
        && (!perms.allowed_tools.is_empty() || !perms.blocked_tools.is_empty())
    {
        let path = data_dir.join("tool_policy.json");
        if force || !path.exists() {
            let body = serde_json::to_string_pretty(&serde_json::json!({
                "allowed_tools": perms.allowed_tools,
                "blocked_tools": perms.blocked_tools,
            }))
            .unwrap_or_default();
            write_section(&mut applied, "tool_policy", &path, body.as_bytes())?;
        }
    }

    Ok(applied)
}

/// Read `tool_policy.json` from the gateway data directory and
/// return it as an [`OrgPermissions`] carrying only the allow/deny
/// lists (sandbox_mode is None — sandbox is already loaded separately).
/// Returns `None` if the file is absent or unreadable; malformed
/// JSON is logged and treated as absent (fail-open on policy load is
/// intentional: a corrupted policy file should not brick the
/// gateway, but the operator sees a warning).
pub fn load_tool_policy(data_dir: &Path) -> Option<OrgPermissions> {
    let path = data_dir.join("tool_policy.json");
    let body = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<OrgPermissions>(&body) {
        Ok(perms) => Some(perms),
        Err(e) => {
            tracing::warn!(
                "tool_policy.json at {} is malformed: {e}; \
                 continuing with no org tool policy",
                path.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_config_with_age(
        signed_at: chrono::DateTime<chrono::Utc>,
        max_age_secs: u64,
    ) -> OrgConfig {
        OrgConfig {
            signed_at: Some(signed_at),
            max_age_seconds: Some(max_age_secs),
            ..Default::default()
        }
    }

    /// Reset both stale-related env vars between tests so default
    /// behavior is deterministic. The escape hatches are process-wide
    /// `std::env::var` reads; we run tests serially via a Mutex to
    /// avoid clobbering each other.
    fn with_no_stale_env<F: FnOnce()>(f: F) {
        // Save and clear.
        let prior = std::env::var("WIRKEN_ALLOW_STALE_ORG_CONFIG").ok();
        // SAFETY: tests use this only in a serialized harness; see
        // STALE_ENV_LOCK below.
        unsafe {
            std::env::remove_var("WIRKEN_ALLOW_STALE_ORG_CONFIG");
        }
        f();
        unsafe {
            match prior {
                Some(v) => std::env::set_var("WIRKEN_ALLOW_STALE_ORG_CONFIG", v),
                None => std::env::remove_var("WIRKEN_ALLOW_STALE_ORG_CONFIG"),
            }
        }
    }

    fn with_stale_env<F: FnOnce()>(f: F) {
        let prior = std::env::var("WIRKEN_ALLOW_STALE_ORG_CONFIG").ok();
        unsafe {
            std::env::set_var("WIRKEN_ALLOW_STALE_ORG_CONFIG", "1");
        }
        f();
        unsafe {
            match prior {
                Some(v) => std::env::set_var("WIRKEN_ALLOW_STALE_ORG_CONFIG", v),
                None => std::env::remove_var("WIRKEN_ALLOW_STALE_ORG_CONFIG"),
            }
        }
    }

    /// Serialize tests that mutate WIRKEN_ALLOW_STALE_ORG_CONFIG so
    /// they don't race against each other under `cargo test`'s default
    /// multi-threaded harness.
    static STALE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Same idea as STALE_ENV_LOCK but for the boolean-escape parser
    /// tests, which set and read a dedicated env var name.
    static BOOL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_test_env<F: FnOnce()>(name: &str, value: Option<&str>, f: F) {
        let prior = std::env::var(name).ok();
        unsafe {
            match value {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
        f();
        unsafe {
            match prior {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
    }

    #[test]
    fn parse_boolean_escape_unset_is_false() {
        let _g = BOOL_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_test_env("WIRKEN_TEST_PARSE_BOOL", None, || {
            assert!(!parse_boolean_escape("WIRKEN_TEST_PARSE_BOOL"));
        });
    }

    #[test]
    fn parse_boolean_escape_recognizes_truthy_variants() {
        let _g = BOOL_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for value in [
            "1", "true", "TRUE", "True", "yes", "Yes", "on", "ON", "  on  ",
        ] {
            with_test_env("WIRKEN_TEST_PARSE_BOOL", Some(value), || {
                assert!(
                    parse_boolean_escape("WIRKEN_TEST_PARSE_BOOL"),
                    "value {value:?} should be truthy"
                );
            });
        }
    }

    #[test]
    fn parse_boolean_escape_recognizes_falsy_variants() {
        let _g = BOOL_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for value in ["0", "false", "FALSE", "no", "off", "Off", ""] {
            with_test_env("WIRKEN_TEST_PARSE_BOOL", Some(value), || {
                assert!(
                    !parse_boolean_escape("WIRKEN_TEST_PARSE_BOOL"),
                    "value {value:?} should be falsy"
                );
            });
        }
    }

    #[test]
    fn parse_boolean_escape_unrecognized_treated_as_false() {
        let _g = BOOL_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for value in ["enable", "y", "n", "yEs!", "garbage", "2"] {
            with_test_env("WIRKEN_TEST_PARSE_BOOL", Some(value), || {
                assert!(
                    !parse_boolean_escape("WIRKEN_TEST_PARSE_BOOL"),
                    "value {value:?} should not engage the gate"
                );
            });
        }
    }

    #[test]
    fn freshness_check_passes_when_fields_absent() {
        let cfg = OrgConfig::default();
        assert!(check_org_config_freshness(&cfg).is_ok());
    }

    #[test]
    fn freshness_check_passes_within_window() {
        let _g = STALE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_no_stale_env(|| {
            let cfg =
                fresh_config_with_age(chrono::Utc::now() - chrono::Duration::seconds(60), 3600);
            assert!(check_org_config_freshness(&cfg).is_ok());
        });
    }

    #[test]
    fn freshness_check_rejects_stale_without_escape() {
        let _g = STALE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_no_stale_env(|| {
            let cfg =
                fresh_config_with_age(chrono::Utc::now() - chrono::Duration::seconds(7200), 3600);
            let err = check_org_config_freshness(&cfg).unwrap_err();
            assert!(err.contains("stale"), "got {err}");
        });
    }

    #[test]
    fn freshness_check_accepts_stale_with_escape_hatch() {
        let _g = STALE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_stale_env(|| {
            let cfg =
                fresh_config_with_age(chrono::Utc::now() - chrono::Duration::seconds(7200), 3600);
            assert!(check_org_config_freshness(&cfg).is_ok());
        });
    }

    #[test]
    fn freshness_check_rejects_future_signed_at() {
        let _g = STALE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_no_stale_env(|| {
            let cfg =
                fresh_config_with_age(chrono::Utc::now() + chrono::Duration::seconds(7200), 3600);
            let err = check_org_config_freshness(&cfg).unwrap_err();
            assert!(err.contains("future"), "got {err}");
        });
    }

    #[test]
    fn signed_payload_with_freshness_round_trips_signature() {
        // The freshness fields live inside the signed body, so a
        // round-trip through verify must accept the canonical bytes
        // and reject any mutation of either field.
        use ed25519_dalek::{Signer, SigningKey};
        let mut secret = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let pk = sk.verifying_key();

        let cfg = OrgConfig {
            signed_at: Some(chrono::Utc::now()),
            max_age_seconds: Some(3600),
            ..Default::default()
        };
        let body = serde_json::to_vec(&cfg).unwrap();
        let sig = sk.sign(&body);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        // Pristine body verifies.
        verify_org_config_signature(&body, &sig_b64, &pk).expect("pristine body must verify");

        // Mutate the timestamp field in the body; signature must fail.
        let mutated = String::from_utf8(body.clone()).unwrap().replacen(
            "\"max_age_seconds\":3600",
            "\"max_age_seconds\":99999",
            1,
        );
        let err = verify_org_config_signature(mutated.as_bytes(), &sig_b64, &pk).unwrap_err();
        assert!(err.contains("signature verification failed"), "got {err}");
    }

    #[test]
    fn apply_org_config_writes_sandbox_json_from_permissions() {
        let tmp = TempDir::new().unwrap();
        let org = OrgConfig {
            permissions: Some(OrgPermissions {
                sandbox_mode: Some("gvisor".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let applied = apply_org_config(tmp.path(), &org, true).unwrap();
        assert!(applied.contains(&"sandbox".to_string()));
        let body = std::fs::read_to_string(tmp.path().join("sandbox.json")).unwrap();
        let val: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(val["mode"].as_str(), Some("gvisor"));
    }

    #[test]
    fn apply_org_config_no_sandbox_without_permissions() {
        let tmp = TempDir::new().unwrap();
        let org = OrgConfig::default();
        let applied = apply_org_config(tmp.path(), &org, true).unwrap();
        assert!(!applied.contains(&"sandbox".to_string()));
        assert!(!tmp.path().join("sandbox.json").exists());
    }

    #[test]
    fn org_config_rejects_unimplemented_skills_key() {
        // `deny_unknown_fields`: a key the gateway does not implement is
        // a parse error, not a silently dropped field. A `skills` block
        // must surface as a config error rather than appear to apply, so
        // an operator cannot believe a skill restriction is in force when
        // none is enforced.
        let body = r#"{"skills":{"auto_install":["github"],"blocked":[]}}"#;
        let err = serde_json::from_str::<OrgConfig>(body).unwrap_err();
        assert!(err.to_string().contains("skills"), "got {err}");
    }

    #[test]
    fn apply_org_config_writes_tool_policy_when_lists_non_empty() {
        let tmp = TempDir::new().unwrap();
        let org = OrgConfig {
            permissions: Some(OrgPermissions {
                sandbox_mode: None,
                allowed_tools: vec!["read_file".into(), "web_search".into()],
                blocked_tools: vec!["exec".into()],
            }),
            ..Default::default()
        };
        let applied = apply_org_config(tmp.path(), &org, true).unwrap();
        assert!(applied.contains(&"tool_policy".to_string()));
        let loaded = load_tool_policy(tmp.path()).unwrap();
        assert_eq!(loaded.allowed_tools, vec!["read_file", "web_search"]);
        assert_eq!(loaded.blocked_tools, vec!["exec"]);
    }

    #[test]
    fn apply_org_config_skips_tool_policy_when_both_lists_empty() {
        let tmp = TempDir::new().unwrap();
        let org = OrgConfig {
            permissions: Some(OrgPermissions {
                sandbox_mode: Some("gvisor".into()),
                allowed_tools: vec![],
                blocked_tools: vec![],
            }),
            ..Default::default()
        };
        let applied = apply_org_config(tmp.path(), &org, true).unwrap();
        assert!(!applied.contains(&"tool_policy".to_string()));
        assert!(!tmp.path().join("tool_policy.json").exists());
    }

    #[test]
    fn apply_org_config_returns_all_applied_section_names() {
        // The CLI's `run` command emits an `org-config.applied` audit
        // event with this Vec as a structured field. Lock in the names
        // so a reviewer scanning the audit log sees a known vocabulary.
        let tmp = TempDir::new().unwrap();
        let org = OrgConfig {
            provider: Some(serde_json::json!({"provider": "ollama", "model": "x"})),
            siem: Some(serde_json::json!({"target": "datadog"})),
            mcp: Some(serde_json::json!({"servers": {}})),
            permissions: Some(OrgPermissions {
                sandbox_mode: Some("gvisor".into()),
                allowed_tools: vec!["read_file".into()],
                blocked_tools: vec![],
            }),
            ..Default::default()
        };
        let applied = apply_org_config(tmp.path(), &org, true).unwrap();
        for name in ["provider", "siem", "mcp", "sandbox", "tool_policy"] {
            assert!(
                applied.contains(&name.to_string()),
                "expected {name} in {applied:?}"
            );
        }
    }

    #[test]
    fn load_tool_policy_returns_none_for_missing_file() {
        let tmp = TempDir::new().unwrap();
        assert!(load_tool_policy(tmp.path()).is_none());
    }

    #[test]
    fn load_tool_policy_returns_none_for_malformed_json() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("tool_policy.json"), "{ not json").unwrap();
        assert!(load_tool_policy(tmp.path()).is_none());
    }

    #[test]
    fn apply_org_config_preserves_existing_sandbox_when_not_forced() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("sandbox.json"), r#"{"mode":"exec-only"}"#).unwrap();
        let org = OrgConfig {
            permissions: Some(OrgPermissions {
                sandbox_mode: Some("gvisor".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        apply_org_config(tmp.path(), &org, false).unwrap();
        let body = std::fs::read_to_string(tmp.path().join("sandbox.json")).unwrap();
        let val: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(val["mode"].as_str(), Some("exec-only"));
    }

    // ---------------------------------------------------------------
    // Signature verification
    // ---------------------------------------------------------------

    use ed25519_dalek::{Signer, SigningKey};

    fn write_pubkey_file(dir: &Path, key: &VerifyingKey) {
        let bytes = key.to_bytes();
        let mut hex = String::with_capacity(64);
        for b in bytes {
            hex.push_str(&format!("{b:02x}"));
        }
        std::fs::write(dir.join(ORG_CONFIG_PUBKEY_FILE), hex).unwrap();
    }

    #[test]
    fn signature_verifies_with_pinned_key() {
        let tmp = TempDir::new().unwrap();
        let mut bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
        let signing = SigningKey::from_bytes(&bytes);
        write_pubkey_file(tmp.path(), &signing.verifying_key());

        let body = b"{}";
        let sig = signing.sign(body);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let pubkey = load_org_pubkey(tmp.path()).unwrap();
        verify_org_config_signature(body, &sig_b64, &pubkey).unwrap();
    }

    #[test]
    fn signature_rejected_with_wrong_key() {
        let tmp = TempDir::new().unwrap();
        let mut bytes_a = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes_a);
        let signing_a = SigningKey::from_bytes(&bytes_a);
        let mut bytes_b = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes_b);
        let signing_b = SigningKey::from_bytes(&bytes_b);
        write_pubkey_file(tmp.path(), &signing_b.verifying_key());

        let body = b"{}";
        let sig = signing_a.sign(body);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let pubkey = load_org_pubkey(tmp.path()).unwrap();
        let err = verify_org_config_signature(body, &sig_b64, &pubkey).unwrap_err();
        assert!(err.contains("verification failed"), "got {err}");
    }

    #[test]
    fn signature_rejected_when_malformed() {
        let tmp = TempDir::new().unwrap();
        let mut bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
        let signing = SigningKey::from_bytes(&bytes);
        write_pubkey_file(tmp.path(), &signing.verifying_key());
        let pubkey = load_org_pubkey(tmp.path()).unwrap();

        // Wrong length
        let err = verify_org_config_signature(b"{}", "AAAA", &pubkey).unwrap_err();
        assert!(err.contains("signature length"), "got {err}");
        // Not base64
        let err = verify_org_config_signature(b"{}", "@@@@", &pubkey).unwrap_err();
        assert!(err.contains("decode signature"), "got {err}");
    }

    #[test]
    fn pubkey_file_missing_returns_error() {
        let tmp = TempDir::new().unwrap();
        let err = load_org_pubkey(tmp.path()).unwrap_err();
        assert!(err.contains(ORG_CONFIG_PUBKEY_FILE), "got {err}");
    }

    #[test]
    fn pubkey_file_wrong_length_returns_error() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(ORG_CONFIG_PUBKEY_FILE), "deadbeef").unwrap();
        let err = load_org_pubkey(tmp.path()).unwrap_err();
        assert!(err.contains("expected 64 hex chars"), "got {err}");
    }

    #[cfg(unix)]
    #[test]
    fn write_with_secret_perms_chmods_existing_loose_file_back_to_0o600() {
        // Regression: OpenOptions::mode is only honored on file
        // creation. If an upgrade window ever produced a file at
        // 0o644, a subsequent write through this helper must converge
        // it back to 0o600 rather than silently inherit the loose
        // mode.
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("provider.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_with_secret_perms(&path, b"new").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got 0o{mode:o}");
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn write_with_secret_perms_lands_0o600_for_setup_files() {
        // The CLI setup flow writes provider.json, sandbox.json, and
        // updates provider.json with channel_overrides via this same
        // helper. Exercise the helper directly on those filenames so
        // the perms property is locked in regardless of the
        // interactive caller.
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        for name in ["provider.json", "sandbox.json", "channel_overrides.json"] {
            let path = tmp.path().join(name);
            write_with_secret_perms(&path, b"{}").unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name}: expected 0o600, got 0o{mode:o}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn apply_org_config_writes_with_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let org = OrgConfig {
            siem: Some(serde_json::json!({"target": "datadog", "api_key": "redacted"})),
            mcp: Some(serde_json::json!({"servers": {}})),
            provider: Some(serde_json::json!({"provider": "openai", "model": "gpt-4o"})),
            permissions: Some(OrgPermissions {
                sandbox_mode: Some("gvisor".into()),
                allowed_tools: vec!["read_file".into()],
                blocked_tools: vec![],
            }),
            ..Default::default()
        };
        apply_org_config(tmp.path(), &org, true).unwrap();
        for name in [
            "provider.json",
            "siem.json",
            "mcp.json",
            "sandbox.json",
            "tool_policy.json",
        ] {
            let mode = std::fs::metadata(tmp.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name}: expected 0o600, got 0o{mode:o}");
        }
    }
}
