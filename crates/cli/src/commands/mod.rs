pub mod adapter;
pub mod agent;
pub mod agents;
pub mod audit;
pub mod channel;
pub mod credential;
pub mod cron;
pub mod doctor;
pub mod permission;
pub mod run;
pub mod service;
pub mod session;
pub mod setup;
pub mod skills;
pub mod webchat;

use std::io::Write;
use std::path::PathBuf;
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
