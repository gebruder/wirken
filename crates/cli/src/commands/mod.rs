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
/// and caching in `WIRKEN_VAULT_PASSPHRASE` for subsequent calls.
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
    if let Ok(p) = std::env::var("WIRKEN_VAULT_PASSPHRASE")
        && !p.is_empty()
    {
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
    // Setup runs single-threaded before any adapter or agent spawn, so
    // there are no concurrent readers of the process environment here.
    unsafe {
        std::env::set_var("WIRKEN_VAULT_PASSPHRASE", &p);
    }
    Ok(p)
}

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
    #[test]
    fn cached_vault_passphrase_returns_env_value_when_set() {
        // SAFETY: the cargo test harness for this binary crate runs
        // tests in parallel by default, so we must use a unique env
        // var name per test if we touch globals. cached_vault_passphrase
        // reads exactly WIRKEN_VAULT_PASSPHRASE; serialise via the
        // function's contract.
        unsafe {
            std::env::set_var("WIRKEN_VAULT_PASSPHRASE", "test-passphrase-cache-hit");
        }
        let p = cached_vault_passphrase().expect("env-set non-empty must return Ok");
        assert_eq!(p, "test-passphrase-cache-hit");
        unsafe {
            std::env::remove_var("WIRKEN_VAULT_PASSPHRASE");
        }
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

    /// The key list and the loader must not drift. This reads the
    /// loader's own source, collects every `val.get("...")` it makes,
    /// and asserts that set is exactly SANDBOX_KEYS. A key read by the
    /// loader but missing from the list would be warned about as
    /// unknown; a key in the list the loader never reads would be
    /// silently ignored again, which is the defect this exists for.
    #[test]
    fn sandbox_keys_matches_what_the_loader_reads() {
        let src = include_str!("mod.rs");
        let start = src
            .find("pub fn load_sandbox_config(")
            .expect("loader present");
        let end = src[start..].find("\n}\n").expect("loader closes") + start;
        let body = &src[start..end];
        let mut read: Vec<&str> = body
            .split("val.get(\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .collect();
        read.sort();
        read.dedup();
        assert_eq!(
            read, SANDBOX_KEYS,
            "SANDBOX_KEYS and the loader's reads have drifted"
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

    /// No model name is written into the paths that configure one.
    ///
    /// A model id in this repo is a guess about a catalogue this repo
    /// does not own. It is correct until the provider retires it and
    /// wrong silently afterwards: the operator accepts the offered
    /// default and finds out at their first turn. `pick_model` offers
    /// what the provider itself listed and otherwise asks.
    ///
    /// The needles are assembled at runtime so this test's own source
    /// does not contain them.
    /// No keychain probe in this crate supplies an empty passphrase,
    /// except the two named here with their reason.
    ///
    /// `prompt_vault_passphrase` in `run.rs` carries the rule and its
    /// casualties: an empty supplier cannot unwrap a device key wrapped
    /// under a real passphrase on the age-file backend, so the
    /// subsystem that probed with one degrades silently. The rule was
    /// written for `run`, and a guard scoped to `run.rs` let two probes
    /// elsewhere pass. Issue 233. This reads every source file in the
    /// crate, so a new file cannot start outside the rule.
    ///
    /// Each allowance is asserted to still hold exactly its offenders.
    /// An allowance that stopped matching would otherwise stay in the
    /// list as a hole for the next offender to hide in, and a fix that
    /// removed an offender would leave a stale reason behind.
    #[test]
    fn no_keychain_probe_supplies_an_empty_passphrase_outside_the_named_allowances() {
        // Needles assembled at runtime so this test's own source does
        // not contain either and match itself.
        let probe = format!("probe_{}(", "keychain");
        let empty = format!("String::{}", "new");

        // (file relative to src/, offenders it may hold, why)
        let allowances: &[(&str, usize, &str)] = &[
            (
                "commands/doctor.rs",
                1,
                "a diagnostic must not prompt, and it reports the posture it lands in: \
                 the surrounding comment says so and is_signed() is printed",
            ),
            (
                "commands/zirkel.rs",
                1,
                "open decision under issue 233: whether zirkel prompts, refuses, or \
                 degrades-and-reports depends on whether it runs non-interactively, \
                 a zirkel product question rather than a keychain-rule fix. Left \
                 exactly as found until that is decided.",
            ),
        ];

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        assert!(
            files.len() > 10,
            "the walker saw too few files to be trusted: {files:?}"
        );

        let mut seen_rules_home = false;
        for path in &files {
            let rel = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "commands/run.rs" {
                seen_rules_home = true;
            }
            let src = std::fs::read_to_string(path).unwrap();
            let offenders: Vec<&str> = src
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with("//"))
                .filter(|l| l.contains(&probe) && l.contains(&empty))
                .collect();
            match allowances.iter().find(|(f, _, _)| *f == rel) {
                Some((_, expected, why)) => assert_eq!(
                    offenders.len(),
                    *expected,
                    "{rel}: the allowance ({why}) no longer matches what the file holds. \
                     If the probe was fixed, remove the allowance with it. Found: {offenders:?}",
                ),
                None => assert!(
                    offenders.is_empty(),
                    "{rel}: a keychain probe supplies an empty passphrase, which cannot \
                     unwrap a device key on the age-file backend and degrades that \
                     subsystem silently. Use prompt_vault_passphrase, or name an \
                     allowance here with its reason. Offending lines: {offenders:?}",
                ),
            }
        }
        assert!(seen_rules_home, "the walker never reached commands/run.rs");
    }

    fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_rs(&p, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }

    #[test]
    fn no_model_name_is_stored_in_the_config_paths() {
        // The paths that choose a model to store. `mod.rs` is not one
        // of them: its listers filter what a provider returned, and
        // `"gpt-"` there is a prefix test over the provider's own
        // answer rather than a name this repo offers anyone.
        let sources = [
            ("agents.rs", include_str!("agents.rs")),
            ("setup.rs", include_str!("setup.rs")),
        ];
        // Vendor names a versioned model id starts with.
        let vendors = ["claude", "gpt", "gemini", "llama", "mistral"];
        for (name, src) in sources {
            for line in src.lines() {
                // Only string literals matter; prose about a provider
                // is not a stored configuration value.
                let Some((_, after)) = line.split_once('"') else {
                    continue;
                };
                let Some((literal, _)) = after.split_once('"') else {
                    continue;
                };
                // A vendor name plus a digit is a version: "gpt-4o",
                // "llama3", "claude-sonnet-4-20250514". A bare vendor
                // word in prose or a url is not.
                if !literal.chars().any(|c| c.is_ascii_digit()) {
                    continue;
                }
                for vendor in vendors {
                    assert!(
                        !literal.contains(vendor),
                        "{name} stores a model name in a literal: {literal:?}. \
                         Offer the provider's own list, or ask.",
                    );
                }
            }
        }
    }
}
