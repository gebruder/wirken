//! The `chatgpt` provider's operator side: Sign in with ChatGPT, the
//! vault entry it produces, and the token source the gateway hands
//! every agent that runs on the plan.
//!
//! OpenAI's program lets an open-source, locally run app use the
//! operator's ChatGPT plan for inference
//! (<https://developers.openai.com/siwc/token-sharing-open-source>).
//! The credential is an OAuth grant like an MCP server's, kept in the
//! vault under [`DEFAULT_CREDENTIAL`] and refreshed by the process that
//! opens the vault. What differs from an API key is that the access
//! token lives an hour, so an agent asks for the current one before
//! each call instead of holding a key for the process lifetime.
//!
//! The grant is the operator's own plan. It is meant for a personal
//! gateway, bound to one agent; the weekly cap the operator sets for
//! the app at [`MANAGE_USAGE`] is the limit on what that agent can
//! spend of it.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use wirken_agent::error::AgentError;
use wirken_agent::llm::ProviderTokenSource;
use wirken_gateway::config::GatewayConfig;
use wirken_gateway::leak::LeakMatcher;
use wirken_mcp_proxy::{
    OAuthCredential, PLAN_USAGE_SCOPE, SignInOptions, load_oauth, refresh_oauth_token,
    revoke_oauth_token, run_authorization_code_flow_with, store_oauth,
};
use wirken_vault::{CredentialStore, probe_keychain};

use super::config;

/// The provider id in `provider.json` and `agent_config.db`.
pub const PROVIDER: &str = "chatgpt";
/// The vault entry the sign-in writes and the gateway reads.
pub const DEFAULT_CREDENTIAL: &str = "chatgpt-plan";
/// Where the user caps this app's share of the plan.
pub const MANAGE_USAGE: &str = "chatgpt.com/settings/usage";
/// What the provider shows the operator as the app's name.
const APP_NAME: &str = "Wirken";
/// Refresh this long before the access token expires.
const REFRESH_LEAD_SECS: u64 = 300;
/// The file the host identifier is kept in, under the data directory.
const HOST_ID_FILE: &str = "chatgpt-host-id";

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The stable identifier the provider attributes this host's usage to,
/// created on the first sign-in and reused by every later one from the
/// same data directory. Not a credential: an opaque label, kept out of
/// the vault so a copied credential does not carry another host's id.
pub fn host_id(data_dir: &Path) -> Result<String> {
    let path = data_dir.join(HOST_ID_FILE);
    if let Ok(existing) = std::fs::read_to_string(&path)
        && !existing.trim().is_empty()
    {
        return Ok(existing.trim().to_string());
    }
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    wirken_gateway::org::write_with_secret_perms(&path, id.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(id)
}

/// The grant `name` holds, checked to be a ChatGPT sign-in that permits
/// plan usage. Anything else is a configuration error that names the
/// command fixing it.
pub fn plan_credential(store: &CredentialStore, name: &str) -> Result<OAuthCredential> {
    let cred = load_oauth(store, name).map_err(|e| {
        anyhow!(
            "credential '{name}' is not a ChatGPT sign-in ({e}). \
             Run `wirken credentials authorize chatgpt --name {name}`."
        )
    })?;
    if cred.provider != PROVIDER {
        anyhow::bail!(
            "credential '{name}' is an OAuth grant for '{}', not a ChatGPT sign-in",
            cred.provider
        );
    }
    if !cred.grants(PLAN_USAGE_SCOPE) {
        anyhow::bail!(
            "credential '{name}' signs in to ChatGPT but does not grant plan usage \
             ({PLAN_USAGE_SCOPE}). Run `wirken credentials authorize chatgpt --name {name}` \
             and allow the app to use your plan."
        );
    }
    Ok(cred)
}

/// Signs in and keeps the grant under `name`. Shared by `wirken
/// credentials authorize`, `wirken setup` and `wirken credentials
/// rescope`. A grant without plan usage is not stored: the operator
/// declined the one thing the credential is for. A later sign-in from
/// the same data directory reuses the client id the first one was
/// issued, as the provider asks.
pub async fn sign_in(
    cfg: &GatewayConfig,
    store: &CredentialStore,
    name: &str,
    port: Option<u16>,
    open_browser: bool,
) -> Result<OAuthCredential> {
    let saved_client_id = load_oauth(store, name)
        .ok()
        .filter(|c| c.provider == PROVIDER)
        .and_then(|c| c.client_id);
    let opts = SignInOptions {
        port,
        client_id: saved_client_id,
        host_id: Some(host_id(&cfg.data_dir)?),
        app_name: Some(APP_NAME.to_string()),
        open_browser,
    };
    println!();
    println!("  Continue with ChatGPT");
    let cred = run_authorization_code_flow_with(PROVIDER, &[], &opts)
        .await
        .map_err(|e| anyhow!("ChatGPT sign-in failed: {e}"))?;
    if !cred.grants(PLAN_USAGE_SCOPE) {
        anyhow::bail!(
            "Signed in, but the app was not allowed to use your ChatGPT plan \
             ({PLAN_USAGE_SCOPE} was not granted); nothing was stored. Run the command \
             again and allow plan usage, or use the OpenAI provider with an API key."
        );
    }
    store_oauth(store, name, &cred).map_err(|e| anyhow!("store credential '{name}': {e}"))?;
    println!("  Signed in. Plan usage: granted. Stored as '{name}'.");
    println!(
        "  Requests from this gateway now use your ChatGPT plan. Set a weekly cap for \
         \"{APP_NAME}\" at {MANAGE_USAGE}."
    );
    Ok(cred)
}

/// `wirken credentials authorize <provider>`.
pub async fn authorize(
    provider: &str,
    name: Option<&str>,
    port: Option<u16>,
    open_browser: bool,
) -> Result<()> {
    if provider != PROVIDER {
        anyhow::bail!(
            "`wirken credentials authorize` signs in to ChatGPT; for an MCP server's OAuth \
             provider use `wirken mcp authorize <server>`."
        );
    }
    let cfg = config();
    cfg.ensure_dirs()?;
    let name = name.unwrap_or(DEFAULT_CREDENTIAL);

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(&cfg.data_dir, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    let cred = sign_in(&cfg, &store, name, port, open_browser).await?;
    println!("  Scopes: {}", cred.scope);
    println!(
        "  Access token valid for {} min; refreshed by the gateway as needed.",
        cred.expires_at.saturating_sub(unix_now()) / 60
    );
    // The models the plan serves this account, so an operator writing
    // `provider.json` by hand, or `agents add --model`, has the slugs
    // without going through the setup picker.
    let models = list_models(wirken_mcp_proxy::CHATGPT_RESOURCE, &cred.access_token).await;
    if models.is_empty() {
        println!("  Models: none listed for this account yet.");
    } else {
        println!("  Models on your plan: {}", models.join(", "));
    }
    println!();
    Ok(())
}

/// Before a credential is removed: when it is a ChatGPT grant, revoke
/// it at the provider, best effort. Anything else is left alone.
pub async fn revoke_before_remove(store: &CredentialStore, name: &str) {
    let Ok(cred) = load_oauth(store, name) else {
        return;
    };
    if cred.provider != PROVIDER {
        return;
    }
    match revoke_oauth_token(PROVIDER, &cred).await {
        Ok(()) => println!("  ChatGPT grant revoked at the provider."),
        Err(e) => println!(
            "  Could not confirm revocation at the provider ({e}). Disconnect the app under \
             ChatGPT Settings, Security and login, Login connections."
        ),
    }
}

/// The models the signed-in account may use on the plan: `/models`
/// with the bearer, kept to those the provider lists, in its order,
/// each as the slug `model` takes.
pub async fn list_models(base_url: &str, bearer: &str) -> Vec<String> {
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    else {
        return Vec::new();
    };
    let Ok(resp) = client
        .get(format!("{base_url}/models"))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
    else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    let Ok(body) = resp.json::<serde_json::Value>().await else {
        return Vec::new();
    };
    plan_models(&body)
}

/// The slugs of the models a `/models` body lists for the plan. The
/// plan route answers a `models` array of `{slug, display_name,
/// visibility}`; the standard `data` array of `{id}` is read as a
/// fallback.
fn plan_models(body: &serde_json::Value) -> Vec<String> {
    if let Some(models) = body.get("models").and_then(|m| m.as_array()) {
        return models
            .iter()
            .filter(|m| {
                m.get("visibility")
                    .and_then(|v| v.as_str())
                    .is_none_or(|v| v == "list")
            })
            .filter_map(|m| m.get("slug").and_then(|s| s.as_str()).map(String::from))
            .collect();
    }
    body.get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("id").and_then(|id| id.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// The bearer source for an agent on the plan: the vault entry, read
/// before each call and refreshed here when it is about to expire.
/// Refreshes are serialised per entry, since the provider rotates the
/// refresh token on every use and two racing refreshes would
/// invalidate each other's result.
pub struct VaultOAuthTokenSource {
    store: Arc<Mutex<CredentialStore>>,
    name: String,
    leak: Arc<LeakMatcher>,
    serial: tokio::sync::Mutex<()>,
}

impl VaultOAuthTokenSource {
    /// Checks the entry once, so a missing or scope-less grant stops
    /// the start rather than the first turn.
    pub fn open(
        store: Arc<Mutex<CredentialStore>>,
        name: &str,
        leak: Arc<LeakMatcher>,
    ) -> Result<Arc<Self>> {
        {
            let guard = store.lock().map_err(|_| anyhow!("vault lock poisoned"))?;
            plan_credential(&guard, name)?;
        }
        Ok(Arc::new(Self {
            store,
            name: name.to_string(),
            leak,
            serial: tokio::sync::Mutex::new(()),
        }))
    }
}

#[async_trait::async_trait]
impl ProviderTokenSource for VaultOAuthTokenSource {
    async fn bearer(&self) -> Result<String, AgentError> {
        let _serial = self.serial.lock().await;
        let cred = {
            let store = self
                .store
                .lock()
                .map_err(|_| AgentError::Llm("vault lock poisoned".into()))?;
            load_oauth(&store, &self.name).map_err(|e| {
                AgentError::Llm(format!("ChatGPT plan credential '{}': {e}", self.name))
            })?
        };
        let now = unix_now();
        if cred.expires_at > now + REFRESH_LEAD_SECS {
            return Ok(cred.access_token);
        }
        match refresh_oauth_token(&cred.provider, &cred).await {
            Ok(fresh) => {
                let json = serde_json::to_string(&fresh)
                    .map_err(|e| AgentError::Llm(format!("serialize refreshed credential: {e}")))?;
                {
                    let store = self
                        .store
                        .lock()
                        .map_err(|_| AgentError::Llm("vault lock poisoned".into()))?;
                    store_oauth(&store, &self.name, &fresh).map_err(|e| {
                        AgentError::Llm(format!("store refreshed credential '{}': {e}", self.name))
                    })?;
                }
                self.leak
                    .learn(&self.name, &json, wirken_vault::CredentialKind::Secret);
                tracing::info!(credential = %self.name, "ChatGPT plan token refreshed");
                Ok(fresh.access_token)
            }
            Err(e) if cred.expires_at > now => {
                tracing::warn!(
                    credential = %self.name,
                    "ChatGPT plan token refresh failed; using the current token until it expires: {e}"
                );
                Ok(cred.access_token)
            }
            Err(e) => Err(AgentError::Llm(format!(
                "ChatGPT sign-in could not be refreshed ({e}). Run `wirken credentials rescope {}` \
                 to sign in again.",
                self.name
            ))),
        }
    }

    fn credential_name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_models_keeps_listed_slugs_in_order_and_falls_back_to_data_ids() {
        let plan = serde_json::json!({"models": [
            {"slug": "gpt-a", "display_name": "GPT A", "visibility": "list"},
            {"slug": "gpt-hidden", "display_name": "Hidden", "visibility": "hidden"},
            {"slug": "gpt-b", "display_name": "GPT B", "visibility": "list"},
        ]});
        assert_eq!(plan_models(&plan), vec!["gpt-a", "gpt-b"]);
        let standard = serde_json::json!({"data": [{"id": "gpt-x"}, {"id": "gpt-y"}]});
        assert_eq!(plan_models(&standard), vec!["gpt-x", "gpt-y"]);
        assert!(plan_models(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn the_host_id_is_minted_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let first = host_id(dir.path()).unwrap();
        assert!(first.starts_with("urn:uuid:"), "{first}");
        assert_eq!(host_id(dir.path()).unwrap(), first);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(HOST_ID_FILE)).unwrap(),
            first
        );
    }

    fn vault(dir: &Path) -> CredentialStore {
        let keychain =
            wirken_vault::AgeFileKeychain::new(dir.join("keychain"), "test-passphrase".into());
        CredentialStore::open(&dir.join("vault.db"), &keychain).unwrap()
    }

    fn grant(scope: &str, expires_at: u64) -> OAuthCredential {
        OAuthCredential {
            access_token: "at-live".into(),
            refresh_token: "rt-live".into(),
            expires_at,
            scope: scope.into(),
            provider: PROVIDER.into(),
            client_id: Some("oaiapp_test".into()),
        }
    }

    #[test]
    fn a_grant_without_plan_usage_or_for_another_provider_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = vault(dir.path());
        store_oauth(&store, "signed-in-only", &grant("openid profile email", 10)).unwrap();
        let err = plan_credential(&store, "signed-in-only").unwrap_err();
        assert!(format!("{err}").contains(PLAN_USAGE_SCOPE), "{err}");

        let mut other = grant(PLAN_USAGE_SCOPE, 10);
        other.provider = "linear".into();
        store_oauth(&store, "linear-oauth", &other).unwrap();
        let err = plan_credential(&store, "linear-oauth").unwrap_err();
        assert!(format!("{err}").contains("not a ChatGPT sign-in"), "{err}");

        store
            .store(
                "openai-api-key",
                "openai",
                &wirken_vault::VaultSecret::new("sk-raw".into()),
                None,
                None,
            )
            .unwrap();
        let err = plan_credential(&store, "openai-api-key").unwrap_err();
        assert!(
            format!("{err}").contains("credentials authorize chatgpt"),
            "{err}"
        );

        store_oauth(&store, DEFAULT_CREDENTIAL, &grant(PLAN_USAGE_SCOPE, 10)).unwrap();
        assert!(plan_credential(&store, DEFAULT_CREDENTIAL).is_ok());
    }

    #[tokio::test]
    async fn a_token_with_time_left_is_handed_out_without_a_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let store = vault(dir.path());
        store_oauth(
            &store,
            DEFAULT_CREDENTIAL,
            &grant(PLAN_USAGE_SCOPE, unix_now() + 3600),
        )
        .unwrap();
        let source = VaultOAuthTokenSource::open(
            Arc::new(Mutex::new(store)),
            DEFAULT_CREDENTIAL,
            Arc::new(LeakMatcher::new()),
        )
        .unwrap();
        assert_eq!(source.bearer().await.unwrap(), "at-live");
        assert_eq!(source.credential_name(), DEFAULT_CREDENTIAL);
    }

    #[test]
    fn opening_the_source_refuses_a_missing_grant() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(vault(dir.path())));
        let err =
            VaultOAuthTokenSource::open(store, DEFAULT_CREDENTIAL, Arc::new(LeakMatcher::new()))
                .err()
                .expect("no grant stored");
        assert!(
            format!("{err}").contains("credentials authorize chatgpt"),
            "{err}"
        );
    }
}
