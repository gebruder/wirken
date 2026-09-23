//! The provider menu `wirken setup` and `wirken agents add` both ask.
//!
//! The two commands kept separate copies of this list, and they drifted:
//! `agents add` offered four providers while setup grew to eleven.
//! Choosing a provider, its endpoint, its key and its model is one job
//! and lives here. Storing the key is the caller's, because setup files
//! it as `<provider>-api-key` and an agent under its own name.

use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Select};
use wirken_gateway::config::GatewayConfig;
use wirken_vault::{CredentialStore, probe_keychain};

/// The menu, in the order it is shown.
const LABELS: &[&str] = &[
    "Ollama (local)",
    "NIM (local or cloud)",
    "Anthropic",
    "OpenAI",
    "Google Gemini",
    "AWS Bedrock",
    "Tinfoil (confidential)",
    "Privatemode (confidential)",
    "Infomaniak (Swiss)",
    "Hetzner (EU)",
    "Custom endpoint",
];

/// Provider ids a flag may name. NIM and Privatemode are not among
/// them: they are stored as `custom` and `openai` with their own
/// endpoint, which is how a flag names them too.
pub const IDS: &[&str] = &[
    "openai",
    "anthropic",
    "gemini",
    "bedrock",
    "ollama",
    "tinfoil",
    "infomaniak",
    "hetzner",
    "custom",
];

/// The provider's own API base, for the providers whose endpoint is
/// fixed. Bedrock carries its region in the URL, Infomaniak an account
/// id, and `custom` is whatever it points at, so those three must be
/// given one.
pub fn default_base_url(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" => Some("https://api.openai.com/v1"),
        "anthropic" => Some("https://api.anthropic.com/v1"),
        "gemini" => Some("https://generativelanguage.googleapis.com/v1beta"),
        "ollama" => Some("http://localhost:11434/v1"),
        "tinfoil" => Some("https://inference.tinfoil.sh/v1"),
        "hetzner" => Some("https://inference.hetzner.com/api/v1"),
        _ => None,
    }
}

/// What the operator chose.
pub struct ProviderChoice {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub region: Option<String>,
    /// The key this provider takes, if it takes one.
    pub key: Option<ChosenKey>,
}

pub struct ChosenKey {
    pub secret: String,
    /// Typed now rather than kept from the vault. Setup stores only a
    /// new key, so keeping one leaves it and its rotation date alone.
    pub fresh: bool,
}

/// The models a provider lists for this endpoint and key. Bedrock has
/// no listing reachable with the credentials wirken holds, so it lists
/// nothing and the id is typed.
pub async fn list_models(provider: &str, base_url: &str, api_key: &str) -> Vec<String> {
    match provider {
        "openai" | "tinfoil" => super::list_openai_models(base_url, api_key).await,
        "anthropic" => super::list_anthropic_models(api_key).await,
        "gemini" => super::list_gemini_models(api_key).await,
        "ollama" => super::list_ollama_models(base_url).await,
        "bedrock" => Vec::new(),
        _ => super::list_openai_compatible_models(base_url, api_key)
            .await
            .unwrap_or_default(),
    }
}

/// Ask for a provider and everything it needs.
pub async fn pick(cfg: &GatewayConfig) -> Result<ProviderChoice> {
    let idx = Select::new()
        .with_prompt("  Provider")
        .items(LABELS)
        .default(0)
        .interact()?;

    let choice =
        |provider: &str, model: String, base_url: String, key: Option<ChosenKey>| ProviderChoice {
            provider: provider.to_string(),
            model,
            base_url,
            region: None,
            key,
        };
    let fresh = |secret: String| ChosenKey {
        secret,
        fresh: true,
    };

    Ok(match idx {
        0 => {
            // Ollama. The endpoint is asked because the inference host
            // is often another machine; Enter keeps the local one.
            let url: String = Input::new()
                .with_prompt("  Ollama URL")
                .default("http://localhost:11434/v1".into())
                .interact_text()?;
            match super::probe_ollama_version(&url).await {
                Some(version) => println!("  Ollama {version} detected."),
                None => {
                    println!("  Warning: could not reach Ollama. Is it running?");
                }
            }
            let models = super::list_ollama_models(&url).await;
            let model = if models.is_empty() {
                super::pick_model(models.clone())?
            } else {
                let idx = Select::new()
                    .with_prompt("  Model")
                    .items(&models)
                    .default(0)
                    .interact()?;
                models[idx]
                    .strip_suffix(":latest")
                    .unwrap_or(&models[idx])
                    .to_string()
            };
            choice("ollama", model, url, None)
        }
        1 => {
            // NIM (NVIDIA inference runtime; OpenAI-compatible HTTP).
            // Stored as provider="custom" because llm.rs already handles
            // the bearer-auth + OpenAI-compat request shape via the `_`
            // arm in its provider dispatch. No new match arm or
            // cost-table entry.
            println!("  NIM serves open-weight models with an OpenAI-compatible API.");
            println!("  Local containers default to no auth; the cloud endpoint at");
            println!("  https://integrate.api.nvidia.com/v1 takes `nvapi-...` keys.");

            // Retry loop: each iteration prompts for endpoint + key and
            // tries the model listing. On any failure the operator picks
            // between retry-with-new-input and manual model-id entry
            // against the URL+key they just typed, with a specific error
            // label for each failure class so a wrong-endpoint typo isn't
            // surfaced as the same "no models found" message as a 401.
            let (url, api_key, models, manual_model) = loop {
                let url: String = Input::new()
                    .with_prompt("  Endpoint")
                    .default("http://localhost:8000/v1".into())
                    .interact_text()?;
                let api_key: String = Input::new()
                    .with_prompt("  API key (blank for local)")
                    .allow_empty(true)
                    .interact_text()?;

                let summary = match super::list_openai_compatible_models(&url, &api_key).await {
                    Ok(models) if models.is_empty() => {
                        "endpoint reachable but /models returned no entries".to_string()
                    }
                    Ok(models) => break (url, api_key, models, None),
                    Err(e) => e.to_string(),
                };

                println!("  {summary}");
                let retry = Confirm::new()
                    .with_prompt("  Re-enter endpoint and key")
                    .default(true)
                    .interact()?;
                if retry {
                    continue;
                }
                let model: String = Input::new().with_prompt("  Model ID").interact_text()?;
                break (url, api_key, Vec::new(), Some(model));
            };

            let model = match manual_model {
                Some(manual) => manual,
                None if api_key.is_empty() => {
                    let idx = Select::new()
                        .with_prompt("  Model")
                        .items(&models)
                        .default(0)
                        .interact()?;
                    models[idx].clone()
                }
                None => super::pick_model(models)?,
            };
            // A blank key is a local container with no auth: nothing
            // to store.
            let key = (!api_key.is_empty()).then(|| fresh(api_key));
            choice("custom", model, url, key)
        }
        2 => {
            // Anthropic
            let key = api_key_for(cfg, "anthropic", "  API key: ")?;
            let models = super::list_anthropic_models(&key.secret).await;
            let model = super::pick_model(models)?;
            choice(
                "anthropic",
                model,
                "https://api.anthropic.com/v1".to_string(),
                Some(key),
            )
        }
        3 => {
            // OpenAI
            let key = api_key_for(cfg, "openai", "  API key: ")?;
            let models = super::list_openai_models("https://api.openai.com/v1", &key.secret).await;
            let model = super::pick_model(models)?;
            choice(
                "openai",
                model,
                "https://api.openai.com/v1".to_string(),
                Some(key),
            )
        }
        4 => {
            // Google Gemini
            let key = api_key_for(cfg, "gemini", "  API key: ")?;
            let models = super::list_gemini_models(&key.secret).await;
            let model = super::pick_model(models)?;
            choice(
                "gemini",
                model,
                "https://generativelanguage.googleapis.com/v1beta".to_string(),
                Some(key),
            )
        }
        5 => {
            // AWS Bedrock
            let r: String = Input::new()
                .with_prompt("  AWS region")
                .default("us-east-1".into())
                .interact_text()?;
            let base = format!("https://bedrock-runtime.{r}.amazonaws.com");
            println!("  Bedrock uses AWS credentials (access key ID : secret access key).");
            // Bedrock has no listing endpoint reachable with the
            // credentials collected here, so the id is typed. No
            // default: a model id written into this repo is a guess
            // about someone else's catalogue.
            let model: String = super::pick_model(Vec::new())?;
            let key = match offer_stored_key(cfg, "bedrock")? {
                Some(secret) => ChosenKey {
                    secret,
                    fresh: false,
                },
                None => {
                    let access_key: String = Input::new()
                        .with_prompt("  AWS Access Key ID")
                        .interact_text()?;
                    let secret_key = super::read_secret("  AWS Secret Access Key: ")?;
                    fresh(format!("{access_key}:{secret_key}"))
                }
            };
            ProviderChoice {
                region: Some(r),
                ..choice("bedrock", model, base, Some(key))
            }
        }
        6 => {
            // Tinfoil
            println!(
                "  Tinfoil runs open-source LLMs inside hardware enclaves (AMD SEV-SNP + NVIDIA H100)."
            );
            println!("  Wirken dispatches through the tinfoil-rs SDK: each session gates on a");
            println!("  hardware attestation (AMD SEV-SNP) plus Sigstore code-provenance check");
            println!("  against the published enclave repo, then pins TLS to the attested cert.");
            println!("  See docs/reference/tinfoil.md for the trust model and model list.");
            println!("  Get an API key at https://dash.tinfoil.sh");
            let key = api_key_for(cfg, "tinfoil", "  API key: ")?;
            let models =
                super::list_openai_models("https://inference.tinfoil.sh/v1", &key.secret).await;
            let model = super::pick_model(models)?;
            choice(
                "tinfoil",
                model,
                "https://inference.tinfoil.sh/v1".to_string(),
                Some(key),
            )
        }
        7 => {
            // Privatemode
            println!(
                "  Privatemode runs open-source LLMs inside confidential enclaves (AMD SEV-SNP + Intel TDX)."
            );
            println!("  The local proxy handles attestation and end-to-end encryption.");
            println!("  Start it first:");
            println!(
                "    docker run -p 127.0.0.1:8080:8080 ghcr.io/edgelesssys/privatemode/privatemode-proxy:latest --apiKey <key>"
            );
            println!("  Get an API key at https://www.privatemode.ai");
            println!();
            let proxy_url: String = Input::new()
                .with_prompt("  Proxy URL")
                .default("http://localhost:8080".into())
                .interact_text()?;
            let base_url = format!("{}/v1", proxy_url.trim_end_matches('/'));
            let models = super::list_openai_models(&base_url, "").await;
            let model = if models.is_empty() {
                Input::new()
                    .with_prompt("  Model")
                    .default("kimi-k2.5".into())
                    .interact_text()?
            } else {
                let idx = Select::new()
                    .with_prompt("  Model")
                    .items(&models)
                    .default(0)
                    .interact()?;
                models[idx].clone()
            };
            choice("openai", model, base_url, None)
        }
        8 => {
            // Infomaniak AI (Swiss-hosted, OpenAI-compatible). The
            // account-specific product_id is a path segment, not a
            // secret, so it folds into the base_url the way Bedrock's
            // region does; only the bearer token reaches the vault. The
            // OpenAI-compat `_` arm in llm.rs handles the request shape,
            // so no new dispatch arm is needed - just the streaming arm
            // in llm_stream.rs.
            println!(
                "  Infomaniak serves open-weight models (incl. Swiss Apertus) from Switzerland,"
            );
            println!("  behind an OpenAI-compatible API. Create a token with the `ai-tools`");
            println!(
                "  scope at https://manager.infomaniak.com; find your product_id via GET /1/ai."
            );

            // Retry loop mirrors the NIM arm: product_id + token, try
            // the model listing, and on any failure let the operator
            // retry or type a model id against the URL + token they just
            // entered, so a wrong product_id isn't surfaced as the same
            // message as a bad token. The stored token is offered on the
            // first pass only; a retry asks.
            let mut offer_stored = true;
            let (base_url, key, models, manual_model) = loop {
                let product_id: String =
                    Input::new().with_prompt("  Product ID").interact_text()?;
                let key = if std::mem::take(&mut offer_stored) {
                    api_key_for(cfg, "infomaniak", "  API token: ")?
                } else {
                    fresh(super::read_secret("  API token: ")?)
                };
                let base_url = format!("https://api.infomaniak.com/2/ai/{product_id}/openai/v1");

                let summary =
                    match super::list_openai_compatible_models(&base_url, &key.secret).await {
                        Ok(models) if models.is_empty() => {
                            "endpoint reachable but /models returned no entries".to_string()
                        }
                        Ok(models) => break (base_url, key, models, None),
                        Err(e) => e.to_string(),
                    };

                println!("  {summary}");
                let retry = Confirm::new()
                    .with_prompt("  Re-enter product ID and token")
                    .default(true)
                    .interact()?;
                if retry {
                    continue;
                }
                let model: String = Input::new().with_prompt("  Model ID").interact_text()?;
                break (base_url, key, Vec::new(), Some(model));
            };

            let model = match manual_model {
                Some(manual) => manual,
                None => super::pick_model(models)?,
            };
            choice("infomaniak", model, base_url, Some(key))
        }
        9 => {
            // Hetzner AI inference (OpenAI-compatible, bearer token).
            // The base URL is fixed, so there is neither an
            // account-specific path segment to fold in the way
            // Infomaniak's product_id is, nor an endpoint to prompt for
            // the way NIM's is; the token is the only input. The
            // OpenAI-compat `_` arm in llm.rs handles the request shape,
            // so no new dispatch arm is needed - just the streaming arm
            // in llm_stream.rs.
            let base_url = "https://inference.hetzner.com/api/v1";
            println!("  Experimental, EU-hosted (Germany and Finland).");
            println!("  Create a token at https://experiments.hetzner.com (Inference, APPS).");

            // Retry loop mirrors the NIM and Infomaniak arms, minus the
            // URL prompt: try the model listing, and on any failure let
            // the operator re-enter the token or type a model id against
            // the token they just entered, so a rejected token isn't
            // surfaced as the same message as an endpoint that listed
            // nothing. The stored token is offered on the first pass
            // only; a retry asks.
            let mut offer_stored = true;
            let (key, models, manual_model) = loop {
                let key = if std::mem::take(&mut offer_stored) {
                    api_key_for(cfg, "hetzner", "  API token: ")?
                } else {
                    fresh(super::read_secret("  API token: ")?)
                };

                let summary =
                    match super::list_openai_compatible_models(base_url, &key.secret).await {
                        Ok(models) if models.is_empty() => {
                            "endpoint reachable but /models returned no entries".to_string()
                        }
                        Ok(models) => break (key, models, None),
                        Err(e) => e.to_string(),
                    };

                println!("  {summary}");
                let retry = Confirm::new()
                    .with_prompt("  Re-enter token")
                    .default(true)
                    .interact()?;
                if retry {
                    continue;
                }
                let model: String = Input::new().with_prompt("  Model ID").interact_text()?;
                break (key, Vec::new(), Some(model));
            };

            let model = match manual_model {
                Some(manual) => manual,
                None => super::pick_model(models)?,
            };
            choice("hetzner", model, base_url.to_string(), Some(key))
        }
        10 => {
            // Custom
            let url: String = Input::new().with_prompt("  API base URL").interact_text()?;
            let has_key = Confirm::new()
                .with_prompt("  Requires API key?")
                .default(true)
                .interact()?;
            if has_key {
                let key = api_key_for(cfg, "custom", "  API key: ")?;
                let models = super::list_openai_models(&url, &key.secret).await;
                let model = super::pick_model(models)?;
                choice("custom", model, url, Some(key))
            } else {
                let model: String = Input::new().with_prompt("  Model ID").interact_text()?;
                choice("custom", model, url, None)
            }
        }
        _ => unreachable!(),
    })
}

/// A live key for this provider, if the vault holds one and the
/// operator wants to keep it. Re-running setup to switch providers
/// used to ask for a key the vault already had, and storing the answer
/// reset the key's rotation date. The names are read first, which
/// needs no passphrase, so a first setup is not asked for one here.
/// An expired key reads as absent.
fn offer_stored_key(cfg: &GatewayConfig, provider_name: &str) -> Result<Option<String>> {
    let name = format!("{provider_name}-api-key");
    let names = CredentialStore::names(&cfg.vault_db_path()).unwrap_or_default();
    if !names.contains(&name) {
        return Ok(None);
    }
    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(&cfg.data_dir, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    let Some(key) = stored_api_key(&store, provider_name) else {
        return Ok(None);
    };
    let keep = Confirm::new()
        .with_prompt(format!("  Use the stored {provider_name} key?"))
        .default(true)
        .interact()?;
    Ok(keep.then_some(key))
}

/// The provider's key as the vault holds it, or `None` when there is
/// no key under that name or it has expired.
fn stored_api_key(store: &CredentialStore, provider_name: &str) -> Option<String> {
    store
        .retrieve(&format!("{provider_name}-api-key"))
        .ok()
        .map(|(secret, _)| secret.expose().to_string())
}

/// The stored key if the operator keeps it, otherwise what they type.
fn api_key_for(cfg: &GatewayConfig, provider_name: &str, prompt: &str) -> Result<ChosenKey> {
    Ok(match offer_stored_key(cfg, provider_name)? {
        Some(secret) => ChosenKey {
            secret,
            fresh: false,
        },
        None => ChosenKey {
            secret: super::read_secret(prompt)?,
            fresh: true,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::{IDS, default_base_url, stored_api_key};
    use wirken_vault::{CredentialStore, VaultSecret};

    fn store() -> (tempfile::TempDir, CredentialStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = CredentialStore::open_with_key(
            &tmp.path().join("vault.db"),
            VaultSecret::new("0".repeat(64)),
        )
        .unwrap();
        (tmp, store)
    }

    #[test]
    fn a_live_key_is_offered() {
        let (_tmp, store) = store();
        store
            .store(
                "anthropic-api-key",
                "anthropic",
                &VaultSecret::new("sk-stored".into()),
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            stored_api_key(&store, "anthropic").as_deref(),
            Some("sk-stored")
        );
    }

    #[test]
    fn another_providers_key_is_not() {
        let (_tmp, store) = store();
        store
            .store(
                "openai-api-key",
                "openai",
                &VaultSecret::new("sk-openai".into()),
                None,
                None,
            )
            .unwrap();
        assert_eq!(stored_api_key(&store, "anthropic"), None);
    }

    #[test]
    fn an_expired_key_is_not() {
        let (_tmp, store) = store();
        store
            .store(
                "anthropic-api-key",
                "anthropic",
                &VaultSecret::new("sk-old".into()),
                Some(chrono::Utc::now() - chrono::Duration::days(1)),
                None,
            )
            .unwrap();
        assert_eq!(stored_api_key(&store, "anthropic"), None);
    }

    /// A provider with a fixed endpoint needs no `--base-url`; the
    /// three without one must be told.
    #[test]
    fn every_flag_provider_has_an_endpoint_or_needs_one() {
        let needs_url: Vec<&str> = IDS
            .iter()
            .copied()
            .filter(|p| default_base_url(p).is_none())
            .collect();
        assert_eq!(needs_url, ["bedrock", "infomaniak", "custom"]);
        assert_eq!(
            default_base_url("openai"),
            Some("https://api.openai.com/v1")
        );
        assert_eq!(
            default_base_url("anthropic"),
            Some("https://api.anthropic.com/v1")
        );
        assert_eq!(
            default_base_url("ollama"),
            Some("http://localhost:11434/v1")
        );
    }
}
