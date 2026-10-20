//! The operator side of plan mode: signing in,
//! signing out, moving a sign-in to a headless host, and reading the
//! signed-in account's models.
//!
//! The protocol is `wirken_agent::plan_auth`; this module is the
//! commands around it. A sign-in is stored as an OAuth entry in the
//! vault (default name [`DEFAULT_ENTRY`]). The host id stays in the
//! data directory, outside the vault.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use wirken_agent::llm_responses::{PlanModel, list_plan_models};
pub use wirken_agent::plan_auth::DEFAULT_ENTRY;
use wirken_agent::plan_auth::{
    self, CALLBACK_TIMEOUT, PendingSignIn, PlanTokenSource, Revocation, SignInRequest, USAGE_URL,
};
use wirken_gateway::agent_config::ProviderAuth;
use wirken_gateway::config::GatewayConfig;
use wirken_mcp_proxy::OAuthCredential;
use wirken_vault::{CredentialStore, probe_keychain};

use super::config;

/// The file under the data directory whose presence records that the
/// plan-usage notice was shown once.
const NOTICE_SHOWN_FILE: &str = "plan-notice-shown";

fn open_store(cfg: &GatewayConfig) -> Result<CredentialStore> {
    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(&cfg.data_dir, move || pp);
    CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")
}

/// The entry `name` holds, when it is a plan sign-in. `Ok(None)` when
/// there is no entry under that name; an entry holding anything else is
/// an error, so a sign-in never overwrites an unrelated credential.
fn saved_registration(store: &CredentialStore, name: &str) -> Result<Option<OAuthCredential>> {
    if store.peek(name).is_err() {
        return Ok(None);
    }
    let cred = plan_auth::load_plan(store, name).map_err(|_| {
        anyhow!(
            "credential '{name}' holds something other than a plan sign-in; choose another name"
        )
    })?;
    if !plan_auth::is_plan_credential(&cred) {
        anyhow::bail!(
            "credential '{name}' holds something other than a plan sign-in; choose another name"
        );
    }
    Ok(Some(cred))
}

/// Show the plan-usage notice the first time a sign-in on this data
/// directory grants plan usage, and never again.
fn notice_once(data_dir: &Path) {
    let marker = data_dir.join(NOTICE_SHOWN_FILE);
    if marker.exists() {
        return;
    }
    println!();
    println!("  You're using your ChatGPT plan");
    println!("  Eligible usage in this app uses your ChatGPT plan. Manage usage in your ChatGPT");
    println!("  settings: {USAGE_URL}");
    if let Err(e) = wirken_gateway::org::write_with_secret_perms(&marker, b"") {
        tracing::warn!("could not record that the plan notice was shown: {e}");
    }
}

/// Sign in and store the result under `entry`. Shared by `wirken
/// credentials authorize`, `wirken setup` and `wirken agents add`.
///
/// The host id is created first, before anything is sent. A grant
/// without plan usage is never stored as a usable credential: on a
/// first sign-in the registration is kept without tokens, so the next
/// attempt reuses its client id; on a reauthorization the entry is left
/// as it was. Any failure leaves the entry as it was.
pub async fn sign_in(
    cfg: &GatewayConfig,
    entry: &str,
    port: Option<u16>,
    open_browser: bool,
) -> Result<OAuthCredential> {
    cfg.ensure_dirs()?;
    let host_id = plan_auth::host_id(&cfg.data_dir).map_err(|e| anyhow!("{e}"))?;
    let store = open_store(cfg)?;
    let saved = saved_registration(&store, entry)?;

    let pending = PendingSignIn::start(SignInRequest {
        host_id,
        saved: saved.clone(),
        port: port.unwrap_or(0),
    })
    .await
    .map_err(|e| anyhow!("{e}"))?;

    println!();
    println!("  Continue with ChatGPT");
    // The URL carries the ID token hint on a reauthorization. It is
    // shown to the operator here and goes to no log.
    let opened = open_browser && open::that(pending.authorize_url()).is_ok();
    if !opened {
        println!("  Open this URL in a browser on this machine:");
        println!();
        println!("    {}", pending.authorize_url());
    }
    println!();
    println!(
        "  Waiting for the sign-in to return to {} (5 minute timeout)...",
        pending.redirect_uri()
    );

    let signed = pending
        .finish(CALLBACK_TIMEOUT)
        .await
        .map_err(|e| anyhow!("Sign-in did not complete: {e}"))?;
    let account = signed
        .credential
        .email
        .clone()
        .or_else(|| signed.credential.subject.clone())
        .unwrap_or_default();

    if !signed.plan_granted() {
        // The new tokens are not kept, so they are revoked rather than
        // left live at the provider.
        let revocation = plan_auth::revoke(&signed.credential).await;
        if saved.is_none() {
            plan_store(
                &store,
                entry,
                &plan_auth::without_tokens(&signed.credential),
            )?;
        }
        if let Revocation::Unconfirmed(reason) = revocation {
            println!("  The unused session was not confirmed revoked ({reason}).");
        }
        anyhow::bail!(
            "signed in as {account}, but plan usage was not granted ({} was not in the token \
             response), so no usable credential was stored. Run `wirken credentials authorize \
             {entry}` again and allow plan usage, or configure the openai provider with an API \
             key.",
            plan_auth::PLAN_SCOPE
        );
    }

    plan_store(&store, entry, &signed.credential)?;
    println!("  Signed in as {account}. Plan usage: granted. Stored as '{entry}'.");
    if signed.registered {
        println!(
            "  Registered as client {}.",
            signed.credential.client_id.as_deref().unwrap_or("")
        );
    }
    notice_once(&cfg.data_dir);
    Ok(signed.credential)
}

fn plan_store(store: &CredentialStore, entry: &str, cred: &OAuthCredential) -> Result<()> {
    plan_auth::store_plan(store, entry, cred).map_err(|e| anyhow!("{e}"))
}

/// `wirken credentials authorize [entry]`.
pub async fn authorize(entry: &str, port: Option<u16>, open_browser: bool) -> Result<()> {
    let cfg = config();
    sign_in(&cfg, entry, port, open_browser).await?;
    match models(&cfg, entry).await {
        Ok(models) if !models.is_empty() => {
            let slugs: Vec<&str> = models.iter().map(|m| m.slug.as_str()).collect();
            println!("  Models: {}", slugs.join(", "));
        }
        Ok(_) => println!("  Models: none listed for this account."),
        Err(e) => println!("  Models could not be listed: {e}"),
    }
    println!(
        "  Use it with `wirken setup` (Continue with ChatGPT) or `wirken agents add --provider \
         openai --auth plan --credential {entry} --model <slug>`."
    );
    println!("  Manage usage: {USAGE_URL}");
    println!();
    Ok(())
}

/// Report a revocation to the operator.
fn report_revocation(entry: &str, revocation: &Revocation) {
    match revocation {
        Revocation::Confirmed => {
            println!("  The provider confirmed the session for '{entry}' ended.")
        }
        Revocation::NothingToRevoke => println!("  '{entry}' held no session to revoke."),
        Revocation::Unconfirmed(reason) => {
            println!(
                "  Remote revocation was NOT confirmed ({reason}). The local tokens are cleared; \
                 to end the session at the provider, remove this app's access at {USAGE_URL}."
            );
        }
    }
}

/// `wirken credentials sign-out [entry]`: clear the tokens, then revoke
/// the session; the registration and the host id are kept.
pub async fn sign_out(entry: &str) -> Result<()> {
    let cfg = config();
    let store = open_store(&cfg)?;
    if saved_registration(&store, entry)?.is_none() {
        anyhow::bail!("no plan sign-in is stored as '{entry}'");
    }
    let revocation = plan_auth::sign_out(Arc::new(Mutex::new(store)), &cfg.data_dir, entry)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    println!("  Signed out of '{entry}'. The registration is kept for the next sign-in.");
    report_revocation(entry, &revocation);
    Ok(())
}

/// Before `wirken credentials remove` deletes `entry`: when it is a
/// plan sign-in, clear its tokens and revoke its session first, and
/// report whether the provider confirmed. Anything else is left alone.
/// Returns the store for the delete that follows.
pub async fn revoke_before_remove(store: CredentialStore, entry: &str) -> Result<CredentialStore> {
    let is_plan = plan_auth::load_plan(&store, entry)
        .map(|c| plan_auth::is_plan_credential(&c))
        .unwrap_or(false);
    if !is_plan {
        return Ok(store);
    }
    let shared = Arc::new(Mutex::new(store));
    let revocation = plan_auth::sign_out(shared.clone(), &config().data_dir, entry)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    report_revocation(entry, &revocation);
    let store = Arc::try_unwrap(shared)
        .map_err(|_| anyhow!("vault handle still shared"))?
        .into_inner()
        .map_err(|_| anyhow!("vault lock poisoned"))?;
    Ok(store)
}

/// The signed-in account's models, read with the entry's current
/// bearer (refreshed first when due). Opens its own token source, so it
/// takes part in the cross-process refresh like the gateway does.
pub async fn models(cfg: &GatewayConfig, entry: &str) -> Result<Vec<PlanModel>> {
    let store = open_store(cfg)?;
    let source = PlanTokenSource::open(
        store,
        &cfg.data_dir,
        entry,
        Arc::new(wirken_gateway::leak::LeakMatcher::new()),
    )
    .map_err(|e| anyhow!("{e}"))?;
    list_plan_models(&source).await.map_err(|e| anyhow!("{e}"))
}

/// Ask for a model from the signed-in account's catalogue, showing each
/// model's display name. An empty catalogue falls back to typing a
/// slug.
pub fn pick_plan_model(models: Vec<PlanModel>) -> Result<String> {
    if models.is_empty() {
        return super::pick_model(Vec::new());
    }
    let labels: Vec<String> = models
        .iter()
        .map(|m| {
            if m.display_name == m.slug {
                m.slug.clone()
            } else {
                format!("{} ({})", m.display_name, m.slug)
            }
        })
        .collect();
    let idx = dialoguer::Select::new()
        .with_prompt("  Model")
        .items(&labels)
        .default(0)
        .interact()?;
    Ok(models[idx].slug.clone())
}

/// `wirken credentials export-plan <entry> --out <file>`: hand a sign-in
/// to another host, as the provider documents for self-hosted VMs.
///
/// Writes the entry to a new owner-only file and clears its tokens
/// here, keeping the registration: the refresh token rotates on every
/// use, so only one host may hold it. The file carries no host id; the
/// receiving host keeps its own.
pub async fn export(entry: &str, out: &Path) -> Result<()> {
    let cfg = config();
    let store = open_store(&cfg)?;
    let cred = saved_registration(&store, entry)?
        .ok_or_else(|| anyhow!("no plan sign-in is stored as '{entry}'"))?;
    if let Some(reason) = plan_auth::unusable_reason(&cred, entry) {
        anyhow::bail!("{reason}");
    }
    let json = serde_json::to_string_pretty(&cred)?;
    write_new_owner_only(out, json.as_bytes())?;
    plan_store(&store, entry, &plan_auth::without_tokens(&cred))?;
    println!("  Wrote '{entry}' to {} (owner-only).", out.display());
    println!("  The tokens are cleared here; the other host now owns the session.");
    println!("  Copy the file over a secure channel, then on that host run:");
    println!("    wirken credentials import-plan {entry} --from <file>");
    println!("  and delete the file on both hosts.");
    Ok(())
}

/// `wirken credentials import-plan <entry> --from <file>`: store a
/// sign-in exported on another host. This host's id is created first if
/// it has none, and is never taken from the file.
pub async fn import(entry: &str, from: &Path) -> Result<()> {
    let cfg = config();
    cfg.ensure_dirs()?;
    plan_auth::host_id(&cfg.data_dir).map_err(|e| anyhow!("{e}"))?;
    let raw = std::fs::read_to_string(from).with_context(|| format!("read {}", from.display()))?;
    let cred: OAuthCredential = serde_json::from_str(&raw)
        .map_err(|e| anyhow!("{} is not an exported plan sign-in: {e}", from.display()))?;
    if let Some(reason) = plan_auth::unusable_reason(&cred, entry) {
        anyhow::bail!("{} cannot be imported: {reason}", from.display());
    }
    let store = open_store(&cfg)?;
    if let Some(existing) = saved_registration(&store, entry)?
        && existing.subject != cred.subject
    {
        anyhow::bail!(
            "'{entry}' already holds a sign-in for another account; import under another name"
        );
    }
    plan_store(&store, entry, &cred)?;
    println!(
        "  Imported '{entry}'. This host keeps its own host id and owns refreshes from now on."
    );
    println!("  Delete {}.", from.display());
    Ok(())
}

fn write_new_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {} (it must not exist yet)", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// How `provider.json` says the default agent authenticates. `auth` is
/// absent for every file written before plan mode, which reads as an
/// API key. Plan mode is valid only on [`plan_auth::PROVIDER`]. Its
/// endpoint is fixed: `base_url` is absent or [`plan_auth::PLAN_BASE_URL`],
/// which is not an endpoint, and a file that names a real one is refused
/// rather than half-honored.
pub fn provider_auth(provider_json: &serde_json::Value) -> Result<ProviderAuth> {
    let auth = ProviderAuth::parse(provider_json.get("auth").and_then(|v| v.as_str()))
        .map_err(|e| anyhow!("provider.json: {e}"))?;
    if auth.is_plan() {
        let provider = provider_json.get("provider").and_then(|v| v.as_str());
        if provider != Some(plan_auth::PROVIDER) {
            anyhow::bail!(
                "provider.json: auth 'plan' applies to provider 'openai' only, not '{}'",
                provider.unwrap_or("")
            );
        }
        if let Some(url) = provider_json.get("base_url").and_then(|v| v.as_str())
            && url != plan_auth::PLAN_BASE_URL
        {
            anyhow::bail!(
                "provider.json: base_url '{url}' does not apply in plan mode, whose endpoint is \
                 fixed; set it to '{}'",
                plan_auth::PLAN_BASE_URL
            );
        }
    }
    Ok(auth)
}

/// The vault entry a plan-mode `provider.json` names, or the default.
pub fn provider_plan_entry(provider_json: &serde_json::Value) -> String {
    provider_json
        .get("credential")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_ENTRY)
        .to_string()
}

/// The `provider.json` a plan-mode default agent is written as. The
/// `base_url` marker is what makes a build that predates plan mode
/// refuse the file instead of sending to its default endpoint.
pub fn provider_json_for_plan(entry: &str, model: &str) -> serde_json::Value {
    serde_json::json!({
        "provider": plan_auth::PROVIDER,
        "auth": ProviderAuth::Plan.as_str(),
        "credential": entry,
        "model": model,
        "base_url": plan_auth::PLAN_BASE_URL,
    })
}

/// The vault entry a plan-mode agent row names, or the default.
pub fn agent_plan_entry(agent: &wirken_gateway::agent_config::AgentConfig) -> String {
    if agent.api_key_credential.is_empty() {
        DEFAULT_ENTRY.to_string()
    } else {
        agent.api_key_credential.clone()
    }
}

/// Whether the vault value `secret` is a plan sign-in. A channel
/// override and an API-key prompt refuse one: it is not a key.
pub fn is_plan_secret(secret: &str) -> bool {
    serde_json::from_str::<OAuthCredential>(secret)
        .map(|c| plan_auth::is_plan_credential(&c))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_json_without_auth_is_a_key_and_plan_is_pinned_to_its_provider() {
        let key =
            serde_json::json!({"provider": "anthropic", "model": "m", "base_url": "https://x"});
        assert_eq!(provider_auth(&key).unwrap(), ProviderAuth::Key);

        let plan = provider_json_for_plan("openai-plan", "m");
        assert_eq!(provider_auth(&plan).unwrap(), ProviderAuth::Plan);
        assert_eq!(plan["base_url"], plan_auth::PLAN_BASE_URL);
        assert_eq!(provider_plan_entry(&plan), "openai-plan");
        let mut bare = plan.clone();
        bare.as_object_mut().unwrap().remove("base_url");
        assert_eq!(provider_auth(&bare).unwrap(), ProviderAuth::Plan);

        let mut moved = plan.clone();
        moved["base_url"] = "http://127.0.0.1:9/v1".into();
        let err = provider_auth(&moved).unwrap_err().to_string();
        assert!(err.contains("does not apply in plan mode"), "{err}");

        let mut other = plan.clone();
        other["provider"] = "anthropic".into();
        assert!(provider_auth(&other).is_err());

        let mut unknown = plan;
        unknown["auth"] = "token".into();
        assert!(provider_auth(&unknown).is_err());
    }

    #[test]
    fn a_plan_entry_is_told_apart_from_a_key_and_an_mcp_grant() {
        let plan = OAuthCredential {
            access_token: "at".into(),
            refresh_token: "rt".into(),
            provider: "openai".into(),
            client_id: Some("oaiapp_x".into()),
            subject: Some("user-1".into()),
            ..Default::default()
        };
        assert!(is_plan_secret(&serde_json::to_string(&plan).unwrap()));
        let mcp = OAuthCredential {
            provider: "linear".into(),
            ..Default::default()
        };
        assert!(!is_plan_secret(&serde_json::to_string(&mcp).unwrap()));
        assert!(!is_plan_secret("sk-raw-key"));
    }

    #[test]
    fn the_plan_notice_is_shown_once_per_data_directory() {
        let dir = tempfile::tempdir().unwrap();
        notice_once(dir.path());
        assert!(dir.path().join(NOTICE_SHOWN_FILE).exists());
        // A second call finds the marker and prints nothing; it must
        // not fail either.
        notice_once(dir.path());
    }

    #[test]
    fn an_export_file_is_created_owner_only_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plan.json");
        write_new_owner_only(&path, b"{}").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(write_new_owner_only(&path, b"{}").is_err());
    }
}
