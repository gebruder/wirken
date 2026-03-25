use anyhow::{Context, Result};

use wirken_agent::llm::LlmConfig;
use wirken_agent::Agent;
use wirken_vault::{CredentialStore, probe_keychain};

use super::config;

pub async fn send(message: &str) -> Result<()> {
    let cfg = config();

    // Load provider config
    let provider_path = cfg.data_dir.join("provider.json");
    if !provider_path.exists() {
        anyhow::bail!(
            "No AI provider configured. Run `wirken setup` first."
        );
    }

    let provider_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&provider_path)?
    )?;

    let provider = provider_json["provider"].as_str().unwrap_or("ollama");
    let model = provider_json["model"].as_str().unwrap_or("llama3");
    let base_url = provider_json["base_url"].as_str().unwrap_or("http://localhost:11434/v1");

    let llm_config = LlmConfig::custom(base_url, model);

    // Get API key from vault if needed
    let api_key = if provider != "ollama" {
        let keychain = probe_keychain(&cfg.data_dir, || {
            dialoguer::Password::new()
                .with_prompt("  Vault passphrase")
                .interact()
                .unwrap_or_default()
        });

        let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
            .context("Failed to open credential store")?;

        let cred_name = format!("{provider}-api-key");
        match store.retrieve(&cred_name) {
            Ok((secret, _)) => Some(secret.expose().to_string()),
            Err(_) => {
                eprintln!("  Warning: no API key found for '{provider}'. Proceeding without auth.");
                None
            }
        }
    } else {
        None
    };

    // Create agent
    let workspace = cfg.data_dir.join("workspace");
    std::fs::create_dir_all(&workspace)?;

    let mut agent = Agent::new(
        "default".into(),
        workspace.clone(),
        llm_config,
        api_key,
    );

    // Load skills if directory exists
    let skills_dir = cfg.data_dir.join("skills");
    if skills_dir.is_dir() {
        match agent.load_skills(&skills_dir) {
            Ok(count) => {
                if count > 0 {
                    tracing::info!("Loaded {count} skills");
                }
            }
            Err(e) => tracing::warn!("Failed to load skills: {e}"),
        }
    }

    // Process message
    println!();
    match agent.process_message(message).await {
        Ok(response) => {
            println!("{response}");
        }
        Err(e) => {
            eprintln!("  Error: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}
