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
pub mod lyrik;
pub mod lyrik_sarif;
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
pub mod webchat;
pub mod zirkel;

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
    let p = dialoguer::Password::new()
        .with_prompt("  Vault passphrase")
        .interact()
        .map_err(|e| {
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
