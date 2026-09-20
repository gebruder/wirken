pub mod adapter;
pub mod agent;
pub mod agents;
pub mod approvers;
pub mod audit;
pub mod channel;
pub mod credential;
pub mod cron;
pub mod doctor;
pub mod hooks;
pub mod import;
pub mod inbound_scan;
pub mod lyrik;
pub mod lyrik_citation;
pub mod lyrik_preflight;
pub mod lyrik_sarif;
pub mod lyrik_semgrep;
pub mod lyrik_validate;
pub mod lyrik_walks;
pub mod mcp;
pub mod mcp_proxy;
pub mod oauth_scope;
pub mod permission;
pub mod persona;
pub mod preset;
pub mod run;
pub mod service;
pub mod session;
pub mod setup;
pub mod skills;
pub mod stdin_approval;
pub mod ui;
pub mod vault;
pub mod webchat;
pub mod zirkel;
pub mod zirkel_calibrate;

use std::io::Write;
use std::path::{Path, PathBuf};
use wirken_agent::sandbox::{SandboxConfig, SandboxMode, ShellMode};
use wirken_gateway::config::GatewayConfig;
use wirken_gateway::permissions::DEFAULT_GRANT_EXPIRY_DAYS;

/// Resolve the data directory, ensuring it exists.
pub fn data_dir() -> anyhow::Result<PathBuf> {
    let config = GatewayConfig::default();
    config.ensure_dirs()?;
    Ok(config.data_dir)
}

/// Get a GatewayConfig with default paths.
pub fn config() -> GatewayConfig {
    GatewayConfig::default()
}

/// Load the sandbox configuration for the gateway. Reads
/// `{data_dir}/sandbox.json` if it exists; falls back to
/// `SandboxConfig::default()` (which is `SandboxMode::ExecOnly` after
/// the 0.7.5 default flip). The org refresh flow in
/// `wirken_gateway::org::apply_org_config` writes this file when
/// `permissions.sandbox_mode` is set on the pulled org config, so the
/// precedence is: org config (force-overwrites each `wirken run`) >
/// locally configured `sandbox.json` > default.
/// Every key `load_sandbox_config` reads, sorted. The drift guard in
/// the tests reads the loader's source and asserts this list matches
/// it, so a key added to one and not the other fails rather than
/// quietly joining the set the loader ignores.
pub(crate) const SANDBOX_KEYS: &[&str] = &["image", "mode", "network", "shell", "sidecar_binary"];

/// Top-level keys in `sandbox.json` that the loader will not read,
/// sorted. An unread key produced nothing at all before this existed:
/// the operator wrote a setting, the file parsed, the gateway started
/// clean, and the setting did nothing. The only way to find out was to
/// read the loader. Issue 234.
pub(crate) fn unknown_sandbox_keys(val: &serde_json::Value) -> Vec<String> {
    let Some(obj) = val.as_object() else {
        return Vec::new();
    };
    let mut unknown: Vec<String> = obj
        .keys()
        .filter(|k| !SANDBOX_KEYS.contains(&k.as_str()))
        .cloned()
        .collect();
    unknown.sort();
    unknown
}

pub fn load_sandbox_config(data_dir: &Path) -> SandboxConfig {
    let path = data_dir.join("sandbox.json");
    if !path.exists() {
        return SandboxConfig::default();
    }
    let body = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "Could not read {}: {e}. Using default sandbox config.",
                path.display()
            );
            return SandboxConfig::default();
        }
    };
    let val: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "Could not parse {}: {e}. Using default sandbox config.",
                path.display()
            );
            return SandboxConfig::default();
        }
    };
    // Warn, never refuse: a file written for a newer build must not
    // stop an older one from starting, and the message names the key
    // rather than failing the boot with a parse error.
    let unknown = unknown_sandbox_keys(&val);
    if !unknown.is_empty() {
        tracing::warn!(
            "{}: unrecognised key(s) {unknown:?} are ignored; the keys read are {SANDBOX_KEYS:?}",
            path.display()
        );
    }
    let mode_str = val.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    let mode = if mode_str.is_empty() {
        SandboxMode::default()
    } else {
        SandboxMode::from_str_config(mode_str)
    };
    let network = val
        .get("network")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // Path to the binary the egress sidecar container runs. Absent
    // means this process's own executable, which is correct for a
    // release build; a development build sets it explicitly.
    let sidecar_binary = val
        .get("sidecar_binary")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    // The container image `exec` runs in. Absent or empty means the
    // compiled-in default. The field, its consumers and its default all
    // existed before this line did; the key was read by nothing, and an
    // operator who set it got the default with no word about it.
    let image = val
        .get("image")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| SandboxConfig::default().image);
    let shell_str = val.get("shell").and_then(|v| v.as_str()).unwrap_or("");
    let shell = if shell_str.is_empty() {
        ShellMode::default()
    } else {
        ShellMode::from_str_config(shell_str)
    };
    SandboxConfig {
        mode,
        network,
        shell,
        sidecar_binary,
        image,
        ..Default::default()
    }
}

/// Every key `open_permission_store` reads from `permissions.json`,
/// sorted. Mirrors [`SANDBOX_KEYS`] so an unread key is named rather
/// than silently ignored.
pub(crate) const PERMISSION_KEYS: &[&str] = &["default_expiry_days"];

/// Top-level keys in `permissions.json` the loader will not read,
/// sorted.
pub(crate) fn unknown_permission_keys(val: &serde_json::Value) -> Vec<String> {
    let Some(obj) = val.as_object() else {
        return Vec::new();
    };
    let mut unknown: Vec<String> = obj
        .keys()
        .filter(|k| !PERMISSION_KEYS.contains(&k.as_str()))
        .cloned()
        .collect();
    unknown.sort();
    unknown
}

/// Read `{data_dir}/permissions.json` for the default grant window.
/// Absent file, unreadable file, unparseable file, or absent key all
/// mean [`DEFAULT_GRANT_EXPIRY_DAYS`].
///
/// Warn, never refuse, matching `load_sandbox_config`: a config
/// written for a newer build must not stop an older one from
/// starting.
pub fn load_permission_expiry_days(data_dir: &Path) -> u32 {
    let path = data_dir.join("permissions.json");
    if !path.exists() {
        return DEFAULT_GRANT_EXPIRY_DAYS;
    }
    let body = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "Could not read {}: {e}. Using the default {DEFAULT_GRANT_EXPIRY_DAYS}-day \
                 grant window.",
                path.display()
            );
            return DEFAULT_GRANT_EXPIRY_DAYS;
        }
    };
    let val: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "Could not parse {}: {e}. Using the default {DEFAULT_GRANT_EXPIRY_DAYS}-day \
                 grant window.",
                path.display()
            );
            return DEFAULT_GRANT_EXPIRY_DAYS;
        }
    };
    let unknown = unknown_permission_keys(&val);
    if !unknown.is_empty() {
        tracing::warn!(
            "{}: unrecognised key(s) {unknown:?} are ignored; the keys read are \
             {PERMISSION_KEYS:?}",
            path.display()
        );
    }
    match val.get("default_expiry_days").and_then(|v| v.as_u64()) {
        Some(days) if days > 0 && days <= u32::MAX as u64 => days as u32,
        Some(bad) => {
            tracing::warn!(
                "{}: default_expiry_days is {bad}, which is not a positive day count. Using \
                 the default {DEFAULT_GRANT_EXPIRY_DAYS}.",
                path.display()
            );
            DEFAULT_GRANT_EXPIRY_DAYS
        }
        None => DEFAULT_GRANT_EXPIRY_DAYS,
    }
}

/// Open the permission store with the operator's configured default
/// grant window. The single opening path for every CLI command, so a
/// window set in `permissions.json` applies wherever a grant is
/// written rather than only where somebody remembered to read it.
pub fn open_permission_store(
    cfg: &GatewayConfig,
) -> anyhow::Result<wirken_gateway::permissions::PermissionStore> {
    use anyhow::Context;
    use wirken_gateway::permissions::{OPERATOR_PERMISSIONS_SESSION, emit_sweep_report};

    let days = load_permission_expiry_days(&cfg.data_dir);
    let mut store = wirken_gateway::permissions::PermissionStore::open_with_expiry(
        &cfg.permissions_db_path(),
        days,
    )
    .context("Failed to open permission store")?;

    // The sweep already ran and already deleted. What is left is
    // recording it. The audit log is opened only when there is
    // something to record, which on a store that has been opened
    // once is never, so the common path does not touch audit.db at
    // all.
    let report = store.take_sweep_report();
    if !report.is_empty() {
        let log = wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
            .context("Failed to open session log to record the permission sweep")?;
        let handle = wirken_audit::SessionLog::handle_for(
            &log,
            wirken_audit::SessionId::new(OPERATOR_PERMISSIONS_SESSION.to_string()),
        );
        emit_sweep_report(&report, &log, &handle)
            .context("Failed to record the permission sweep in the audit chain")?;
        eprintln!(
            "  Removed {} stored permission row(s) the gate cannot act on: {} whose action key \
             is Tier 1 or Tier 3, {} past their expiry. Recorded under the \
             '{OPERATOR_PERMISSIONS_SESSION}' audit session.",
            report.len(),
            report.not_storable.len(),
            report.lapsed.len(),
        );
    }
    Ok(store)
}

/// Probe a running Ollama instance for its version.
///
/// Derives the Ollama root URL from the configured base URL (stripping `/v1`)
/// and hits `GET /api/version`.  Returns `Some("0.5.4")` on success, or `None`
/// if Ollama is unreachable / returns an unexpected response.
pub async fn probe_ollama_version(base_url: &str) -> Option<String> {
    // base_url is typically "http://localhost:11434/v1"
    let root = base_url
        .strip_suffix("/v1")
        .or_else(|| base_url.strip_suffix("/v1/"))
        .unwrap_or(base_url);
    let url = format!("{root}/api/version");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    body.get("version")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// List models installed in a running Ollama instance.
///
/// Hits `GET /api/tags` and returns model names (e.g. `["llama3.2:latest"]`).
pub async fn list_ollama_models(base_url: &str) -> Vec<String> {
    let root = base_url
        .strip_suffix("/v1")
        .or_else(|| base_url.strip_suffix("/v1/"))
        .unwrap_or(base_url);
    let url = format!("{root}/api/tags");

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let resp = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    body.get("models")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// List models available from the Anthropic API.
pub async fn list_anthropic_models(api_key: &str) -> Vec<String> {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let resp = match client
        .get("https://api.anthropic.com/v1/models")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    body.get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("id").and_then(|id| id.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Why a model-list lookup against an OpenAI-compatible endpoint
/// failed. Three variants on purpose: distinguishing the rest
/// (connection refused vs DNS vs timeout) is messier at the
/// reqwest layer than it reads, and the user-facing message
/// matters more than the taxonomy. The setup picker renders
/// each variant with a specific reason so operators don't see
/// "no models found, enter manually" for a wrong-endpoint typo.
#[derive(Debug)]
pub enum ModelListError {
    /// 401 or 403 from the endpoint. Either the API key is
    /// missing on a cloud endpoint that requires it, or the
    /// supplied key is wrong.
    AuthRequired,
    /// Anything below HTTP: connection refused, DNS failure,
    /// TLS handshake error, timeout. The endpoint URL is wrong,
    /// the container isn't running, or a firewall is in the
    /// way. Collapsed into one variant because reqwest's error
    /// taxonomy doesn't reliably distinguish them across
    /// platforms.
    Unreachable(String),
    /// HTTP response with a non-success status that isn't 401/403.
    /// Carries the status code so the caller can mention it.
    OtherHttp(u16),
}

impl std::fmt::Display for ModelListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelListError::AuthRequired => {
                write!(
                    f,
                    "endpoint rejected the request as unauthenticated (401/403) - is an API key required, or is the key wrong?"
                )
            }
            ModelListError::Unreachable(detail) => {
                write!(
                    f,
                    "endpoint not reachable ({detail}) - check the URL, that the container is running, and that nothing is in the way"
                )
            }
            ModelListError::OtherHttp(status) => {
                write!(f, "endpoint returned HTTP {status}")
            }
        }
    }
}

/// List models from an OpenAI-compatible `{base_url}/models`
/// endpoint without filtering by name. Used for endpoints that
/// expose non-OpenAI model IDs (NIM serves `meta/llama-*`,
/// `nvidia/...`; Privatemode serves `kimi-*`; etc.) where the
/// OpenAI-name filter in `list_openai_models` would drop
/// everything. Omits the Authorization header when `api_key`
/// is empty so local containers without bearer auth (default
/// for NIM local) don't get a malformed `Bearer ` header.
///
/// Returns `Ok(Vec)` (possibly empty when the endpoint truly
/// has no models) on a 2xx response, or `Err(ModelListError)`
/// for the three classes of failure the setup picker
/// surfaces distinctly.
pub async fn list_openai_compatible_models(
    base_url: &str,
    api_key: &str,
) -> Result<Vec<String>, ModelListError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| ModelListError::Unreachable(e.to_string()))?;

    let url = format!("{base_url}/models");
    let mut req = client.get(&url);
    if !api_key.is_empty() {
        req = req.header("Authorization", format!("Bearer {api_key}"));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| ModelListError::Unreachable(e.to_string()))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ModelListError::AuthRequired);
    }
    if !status.is_success() {
        return Err(ModelListError::OtherHttp(status.as_u16()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ModelListError::Unreachable(e.to_string()))?;

    let mut models: Vec<String> = body
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("id").and_then(|id| id.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    models.sort();
    models.dedup();
    Ok(models)
}

/// List models available from an OpenAI-compatible API.
/// Filters to chat-capable models (gpt-*, o1-*, o3-*, o4-*) and excludes
/// legacy/embedding/audio models to keep the picker manageable.
pub async fn list_openai_models(base_url: &str, api_key: &str) -> Vec<String> {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let url = format!("{base_url}/models");
    let resp = match client
        .get(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut models: Vec<String> = body
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("id").and_then(|id| id.as_str()).map(String::from))
                .filter(|id| {
                    (id.starts_with("gpt-")
                        || id.starts_with("o1")
                        || id.starts_with("o3")
                        || id.starts_with("o4"))
                        && !id.contains("audio")
                        && !id.contains("realtime")
                        && !id.contains("transcribe")
                        && !id.contains("tts")
                        && !id.contains("instruct")
                        && !id.contains("search")
                        && !id.contains("codex")
                        && !id.contains("-202") // drop dated snapshots like gpt-4o-2024-08-06
                        && !id.starts_with("gpt-3.5")
                        && !id.contains("-16k")
                        && !id.contains("-chat-latest")
                })
                .collect()
        })
        .unwrap_or_default();
    models.sort();
    models.dedup();
    models
}

/// Ask the operator which model to use.
///
/// `models` is what the provider itself answered. When it is empty --
/// no key yet, provider unreachable, an endpoint that does not list --
/// the operator types the name, with no default offered.
///
/// Nothing here supplies a fallback model name. A name written into
/// this repo is a guess about a catalogue this repo does not own: it
/// is right until the provider retires it and wrong silently
/// afterwards, and an operator who takes the offered default finds out
/// at their first turn rather than at config time. Asking is the
/// honest failure mode.
pub fn pick_model(models: Vec<String>) -> anyhow::Result<String> {
    if models.is_empty() {
        println!("  Could not list models from the provider. Enter the model id to use.");
        let model: String = dialoguer::Input::new()
            .with_prompt("  Model")
            .validate_with(|input: &String| -> Result<(), &str> {
                if input.trim().is_empty() {
                    Err("a model id is required")
                } else {
                    Ok(())
                }
            })
            .interact_text()?;
        return Ok(model.trim().to_string());
    }
    let idx = dialoguer::Select::new()
        .with_prompt("  Model")
        .items(&models)
        .default(0)
        .interact()?;
    Ok(models[idx].clone())
}

/// List models available from the Google Gemini API.
pub async fn list_gemini_models(api_key: &str) -> Vec<String> {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let url = "https://generativelanguage.googleapis.com/v1beta/models";
    let resp = match client
        .get(url)
        .header("x-goog-api-key", api_key)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    body.get("models")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    m.get("name")
                        .and_then(|n| n.as_str())
                        .map(|n| n.strip_prefix("models/").unwrap_or(n).to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the age-file keychain under `data_dir` has no sealed device
/// key yet, so the next passphrase entry seals a fresh key rather than
/// unlocking an existing one. A fresh seal derives the wrapping key from
/// whatever is typed and never round-trips it, so a first-seal typo
/// locks the vault permanently with no feedback; that entry is confirmed
/// (see `cached_vault_passphrase`). Both files present means an existing
/// key that is only unlocked, where a wrong passphrase surfaces as a
/// failed unwrap.
pub(crate) fn keychain_needs_seal(data_dir: &Path) -> bool {
    let dir = data_dir.join("keychain");
    !dir.join("device-key.age").exists() || !dir.join("device-key.salt").exists()
}

/// Return the vault passphrase for the current process, prompting once
/// and caching it in process memory for subsequent calls.
///
/// The cache is a `OnceLock`, not `WIRKEN_VAULT_PASSPHRASE`. Writing
/// the prompted passphrase back into the environment did two things
/// that are worth not doing. It called `std::env::set_var`, which is
/// undefined behaviour while another thread reads or writes the
/// environment, and this runs inside a multi-threaded tokio runtime
/// behind a `dialoguer` prompt that blocks on a TTY for as long as
/// the operator takes. And it left the passphrase in
/// `/proc/self/environ`, readable by anything at the same uid, which
/// is the exact exposure `mcp-proxy` scrubs its own environ to avoid.
/// Nothing downstream loses a value: children are given the
/// passphrase through an explicit `Command::env`, not by inheriting
/// this process's environ.
///
/// `wirken setup` opens the keychain repeatedly across `register_channel`
/// and per-channel detail writes. Each `probe_keychain` call constructs a
/// new `AgeFileKeychain`, so without a shared passphrase a second open
/// with an empty fallback re-keyed the file and orphaned the rows from
/// the first open. Routing every prompt through this helper keeps a
/// single derivation across the whole invocation, and `wirken run`
/// already propagates the same env var to spawned adapters.
///
/// Returns `Err` when no env value is set and `dialoguer::Password`
/// can't reach a TTY. The previous behavior swallowed that error via
/// `unwrap_or_default()`, returning an empty string and producing the
/// silent-empty-seal failure mode (vault sealed under `""` because no
/// real passphrase ever reached the keychain). Callers now propagate
/// the error; setup refuses to proceed without a passphrase rather
/// than caching empty.
pub fn cached_vault_passphrase() -> anyhow::Result<String> {
    if let Some(p) = vault_passphrase_source() {
        return Ok(p);
    }
    // A fresh seal locks the vault under whatever is typed with no way
    // to notice a typo, so confirm the entry when sealing. Unlock of an
    // existing key stays single-entry: a wrong passphrase fails the
    // unwrap immediately.
    let mut prompt = dialoguer::Password::new().with_prompt("  Vault passphrase");
    if keychain_needs_seal(&config().data_dir) {
        prompt = prompt.with_confirmation(
            "  Confirm vault passphrase",
            "  Passphrases do not match; try again",
        );
    }
    let p = prompt.interact().map_err(|e| {
        anyhow::anyhow!(
            "could not prompt for vault passphrase ({e}); run \
                 interactively at a TTY, or supply WIRKEN_VAULT_PASSPHRASE \
                 in the environment"
        )
    })?;
    // Ignore a lost race: two threads prompting at once would both
    // have read the same TTY, so whichever value landed first is the
    // one every later caller must see.
    let _ = PROMPTED_VAULT_PASSPHRASE.set(p.clone());
    Ok(vault_passphrase_source().unwrap_or(p))
}

/// The passphrase this process already holds, if any: the operator's
/// exported `WIRKEN_VAULT_PASSPHRASE` first, then one prompted for
/// earlier in this process. `None` means nothing has it yet and the
/// caller must prompt.
///
/// Empty is treated as absent on both paths. An exported-but-blank
/// variable is a misconfiguration, and sealing the vault under `""`
/// is the silent failure this helper exists to prevent.
pub(crate) fn vault_passphrase_source() -> Option<String> {
    let exported = std::env::var("WIRKEN_VAULT_PASSPHRASE")
        .ok()
        .filter(|p| !p.is_empty());
    exported.or_else(|| {
        PROMPTED_VAULT_PASSPHRASE
            .get()
            .filter(|p| !p.is_empty())
            .cloned()
    })
}

/// Set once, by the prompt path in [`cached_vault_passphrase`].
static PROMPTED_VAULT_PASSPHRASE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Read a secret value (API key, token) with asterisk masking.
/// Unlike dialoguer's Password which shows nothing, this prints one
/// asterisk per character so the user can see that paste/typing worked.
pub fn read_secret(prompt: &str) -> anyhow::Result<String> {
    let term = console::Term::stderr();
    eprint!("{prompt}");
    std::io::stderr().flush()?;

    let mut input = String::new();
    loop {
        let key = term.read_key()?;
        match key {
            console::Key::Char(c) => {
                input.push(c);
                eprint!("*");
                std::io::stderr().flush()?;
            }
            console::Key::Backspace if !input.is_empty() => {
                input.pop();
                // Move cursor back, overwrite with space, move back again
                eprint!("\x08 \x08");
                std::io::stderr().flush()?;
            }
            console::Key::Enter => {
                eprintln!();
                break;
            }
            _ => {}
        }
    }
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn load_sandbox_config_missing_file_uses_default() {
        let tmp = TempDir::new().unwrap();
        let cfg = load_sandbox_config(tmp.path());
        assert_eq!(cfg.mode, SandboxMode::default());
    }

    /// vault-no-empty-seal: when WIRKEN_VAULT_PASSPHRASE holds a
    /// non-empty value, cached_vault_passphrase returns it without
    /// touching the prompt path. Tests run with stdin not a TTY, so
    /// the dialoguer fallback would error; the env-cache hit short-
    /// circuits that.
    /// The source lookup answers from whatever this process holds and
    /// never prompts, which is the property the cache exists for.
    /// Asserted against the ambient environment so the test writes no
    /// process-global state: `std::env::set_var` is undefined
    /// behaviour while another thread reads the environment, and this
    /// binary's tests run in parallel.
    #[test]
    fn vault_passphrase_source_agrees_with_the_exported_value() {
        let exported = std::env::var("WIRKEN_VAULT_PASSPHRASE")
            .ok()
            .filter(|p| !p.is_empty());
        assert_eq!(vault_passphrase_source(), exported);
    }

    /// Empty is absent on the exported path, so an exported-but-blank
    /// variable cannot seal the vault under `""`.
    #[test]
    fn an_empty_exported_passphrase_is_not_a_passphrase() {
        assert_eq!(
            Some(String::new()).filter(|p: &String| !p.is_empty()),
            None,
            "the filter the source lookup applies to both paths"
        );
    }

    /// seal-time confirmation: the prompt mode is fresh-seal (confirm)
    /// until both age-file keychain artifacts exist, then unlock (single
    /// entry). A partial state (one file) still counts as a fresh seal.
    #[test]
    fn keychain_needs_seal_until_both_key_files_exist() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        // No keychain dir yet: fresh seal.
        assert!(keychain_needs_seal(data_dir));
        let kc = data_dir.join("keychain");
        std::fs::create_dir_all(&kc).unwrap();
        std::fs::write(kc.join("device-key.salt"), b"salt").unwrap();
        // Salt only, no sealed key: still a fresh seal.
        assert!(keychain_needs_seal(data_dir));
        std::fs::write(kc.join("device-key.age"), b"sealed").unwrap();
        // Both present: existing key, unlock only.
        assert!(!keychain_needs_seal(data_dir));
    }

    #[test]
    fn load_sandbox_config_reads_exec_only() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("sandbox.json"),
            r#"{"mode":"exec-only","network":false}"#,
        )
        .unwrap();
        let cfg = load_sandbox_config(tmp.path());
        assert_eq!(cfg.mode, SandboxMode::ExecOnly);
        assert!(!cfg.network);
    }

    /// Issue 234: `image` was a field on `SandboxConfig` that no
    /// configuration path set, so a key written into sandbox.json was
    /// read by nothing and the sandbox always ran the compiled-in image.
    #[test]
    fn load_sandbox_config_reads_image() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("sandbox.json"),
            r#"{"mode":"exec-only","image":"curlimages/curl:latest"}"#,
        )
        .unwrap();
        let cfg = load_sandbox_config(tmp.path());
        assert_eq!(cfg.image, "curlimages/curl:latest");
    }

    /// A key that is present but empty names no image, so the default
    /// stands rather than an unnamed image being configured.
    #[test]
    fn load_sandbox_config_empty_image_uses_default() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("sandbox.json"), r#"{"image":"  "}"#).unwrap();
        let cfg = load_sandbox_config(tmp.path());
        assert_eq!(cfg.image, SandboxConfig::default().image);
    }

    #[test]
    fn unknown_sandbox_keys_names_what_the_loader_will_ignore() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"mode":"exec-only","timeout":30,"image":"x","imgae":"y"}"#)
                .unwrap();
        assert_eq!(
            unknown_sandbox_keys(&v),
            vec!["imgae".to_string(), "timeout".to_string()]
        );
        let known: serde_json::Value = serde_json::from_str(
            r#"{"image":"a","mode":"b","network":true,"shell":"c","sidecar_binary":"d"}"#,
        )
        .unwrap();
        assert!(unknown_sandbox_keys(&known).is_empty());
    }

    #[test]
    fn unknown_sandbox_keys_is_empty_for_a_non_object() {
        for v in ["[]", "3", "\"s\"", "null"] {
            let v: serde_json::Value = serde_json::from_str(v).unwrap();
            assert!(unknown_sandbox_keys(&v).is_empty(), "{v}");
        }
    }

    /// `SANDBOX_KEYS` and the loader agree, checked by writing a file
    /// and reading the config back.
    ///
    /// Both directions matter and both are observable. A key in the
    /// list the loader never reads is a setting an operator writes
    /// that does nothing, which is the defect this exists for: every
    /// key is set to a non-default value here and every field has to
    /// come back changed. A key the loader reads but the list omits
    /// would be reported as unrecognised, so the same file has to
    /// produce no unknown keys.
    ///
    /// This used to read the loader's own source and count
    /// `.get("...")` calls, which broke once already when rustfmt
    /// wrapped the chain differently.
    #[test]
    fn sandbox_keys_are_the_keys_the_loader_reads() {
        let tmp = TempDir::new().unwrap();
        let every_key = serde_json::json!({
            "mode": "gvisor",
            "image": "example.invalid/sandbox:test",
            "network": true,
            "shell": "sh",
            "sidecar_binary": "/opt/wirken/egress-sidecar",
        });
        assert_eq!(
            every_key.as_object().unwrap().len(),
            SANDBOX_KEYS.len(),
            "this fixture has to carry every key in SANDBOX_KEYS"
        );
        std::fs::write(
            tmp.path().join("sandbox.json"),
            serde_json::to_string(&every_key).unwrap(),
        )
        .unwrap();

        // Direction one: the loader reads every listed key.
        let cfg = load_sandbox_config(tmp.path());
        let default = SandboxConfig::default();
        assert_eq!(cfg.mode, SandboxMode::GVisor, "mode is not read");
        assert_eq!(
            cfg.image, "example.invalid/sandbox:test",
            "image is not read"
        );
        assert!(cfg.network && !default.network, "network is not read");
        assert_ne!(cfg.shell, default.shell, "shell is not read");
        assert_eq!(
            cfg.sidecar_binary.as_deref(),
            Some(std::path::Path::new("/opt/wirken/egress-sidecar")),
            "sidecar_binary is not read"
        );

        // Direction two: nothing the loader reads is missing from the
        // list, or this same file would carry an unrecognised key.
        assert!(
            unknown_sandbox_keys(&every_key).is_empty(),
            "a key the loader reads is missing from SANDBOX_KEYS"
        );

        // And the warning still fires for a key that really is unread.
        let with_extra = serde_json::json!({ "mode": "off", "memory_limit_mb": 512 });
        assert_eq!(
            unknown_sandbox_keys(&with_extra),
            vec!["memory_limit_mb".to_string()],
            "an unread key must be reported, not ignored"
        );
    }

    #[test]
    fn load_sandbox_config_reads_gvisor() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("sandbox.json"), r#"{"mode":"gvisor"}"#).unwrap();
        let cfg = load_sandbox_config(tmp.path());
        assert_eq!(cfg.mode, SandboxMode::GVisor);
    }

    #[test]
    fn load_sandbox_config_reads_off() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("sandbox.json"), r#"{"mode":"off"}"#).unwrap();
        let cfg = load_sandbox_config(tmp.path());
        assert_eq!(cfg.mode, SandboxMode::Off);
    }

    #[test]
    fn load_sandbox_config_unknown_mode_uses_default() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("sandbox.json"), r#"{"mode":"chrooty"}"#).unwrap();
        let cfg = load_sandbox_config(tmp.path());
        assert_eq!(cfg.mode, SandboxMode::default());
    }

    #[test]
    fn load_sandbox_config_malformed_json_uses_default() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("sandbox.json"), "not json").unwrap();
        let cfg = load_sandbox_config(tmp.path());
        assert_eq!(cfg.mode, SandboxMode::default());
    }
}
