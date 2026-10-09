use anyhow::{Context, Result};

use wirken_gateway::adapter_registry::AdapterRegistry;
use wirken_gateway::config::GatewayConfig;
use wirken_ipc::AdapterIdentity;
use wirken_vault::{CredentialStore, VaultSecret, probe_keychain};

use super::{config, data_dir};

/// Brand-canonical display name for a channel id. Internal ids are
/// stable lowercase identifiers (used in config files, audit events,
/// `wirken channel add <id>`); display names follow each platform's
/// trademark casing (iMessage, WhatsApp, Microsoft Teams). Unknown
/// ids pass through unchanged so a new adapter does not silently
/// render as "unknown" before this table catches up.
pub fn display_name(id: &str) -> &str {
    match id {
        "telegram" => "Telegram",
        "discord" => "Discord",
        "slack" => "Slack",
        "teams" => "Microsoft Teams",
        "matrix" => "Matrix",
        "signal" => "Signal",
        "google-chat" => "Google Chat",
        "imessage" => "iMessage",
        "whatsapp" => "WhatsApp",
        other => other,
    }
}

/// Non-interactive flags for `wirken channel add`. Flags that are
/// `None` fall through to the matching `WIRKEN_<CHANNEL>_*` env var
/// (where applicable) and then to an interactive prompt. Validation
/// runs on whichever source provided the value.
#[derive(Debug, Default)]
pub struct AddFlags {
    pub token: Option<String>,
    pub phone_number_id: Option<String>,
    pub verify_token: Option<String>,
    pub app_secret: Option<String>,
    pub project_number: Option<String>,
    pub app_id: Option<String>,
    pub homeserver: Option<String>,
    pub username: Option<String>,
    pub bluebubbles_url: Option<String>,
    pub app_token: Option<String>,
    pub phone_number: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_senders: Option<String>,
}

pub async fn add(channel: &str, flags: AddFlags) -> Result<()> {
    let cfg = config();
    let data = data_dir()?;

    match channel {
        "whatsapp" => add_whatsapp(&cfg, &data, flags).await,
        "slack" => add_slack(&cfg, &data, flags).await,
        "signal" => add_signal(&cfg, &data, flags).await,
        "google-chat" => add_google_chat(&cfg, &data, flags).await,
        "teams" => add_teams(&cfg, &data, flags).await,
        "matrix" => add_matrix(&cfg, &data, flags).await,
        "imessage" => add_imessage(&cfg, &data, flags).await,
        _ => add_simple(channel, &cfg, &data, flags).await,
    }
}

/// Collect signal-cli socket path, account phone number, and sender
/// allowlist from the operator. Shared between `wirken channel add
/// signal` and the setup wizard's Signal arm so both paths produce the
/// same vault state.
pub struct SignalCreds {
    pub phone: String,
    pub endpoint: String,
    pub allowlist_csv: String,
}

pub fn collect_signal_creds(
    phone: Option<String>,
    endpoint: Option<String>,
    allowed_senders: Option<String>,
) -> Result<SignalCreds> {
    println!("  Signal requires signal-cli running as a JSON-RPC daemon.");
    println!("  See docs/channels/signal.md for the full setup and threat model.");

    let phone = resolve_with_validation(
        "Registered phone number (e.g., +15551234567)",
        phone,
        "WIRKEN_SIGNAL_PHONE_NUMBER",
        false,
        validate_non_empty,
    )?;

    // Validate on input so the adapter never starts against an HTTP URL
    // the transport no longer speaks. Accept bare paths and `unix://`.
    let given = endpoint.or_else(|| std::env::var("WIRKEN_SIGNAL_ENDPOINT").ok());
    let endpoint: String = match given.map(|e| e.trim().to_string()) {
        Some(e) => {
            validate_signal_endpoint(&e).context("Invalid --endpoint / WIRKEN_SIGNAL_ENDPOINT")?;
            e
        }
        None if !std::io::IsTerminal::is_terminal(&std::io::stdin()) => {
            DEFAULT_SIGNAL_ENDPOINT.to_string()
        }
        None => loop {
            let e: String = dialoguer::Input::new()
                .with_prompt("  signal-cli socket path")
                .default(DEFAULT_SIGNAL_ENDPOINT.into())
                .interact_text()?;
            let trimmed = e.trim();
            match validate_signal_endpoint(trimmed) {
                Ok(()) => break trimmed.to_string(),
                Err(err) => println!("  {err}"),
            }
        },
    };

    let given = allowed_senders.or_else(|| std::env::var("WIRKEN_SIGNAL_ALLOWED_SENDERS").ok());
    let allowlist_csv: String = match given {
        Some(csv) => csv,
        // No terminal and nothing given: an empty allowlist, as an empty
        // answer at the prompt leaves it.
        None if !std::io::IsTerminal::is_terminal(&std::io::stdin()) => String::new(),
        None => {
            println!();
            println!("  Sender allowlist (REQUIRED):");
            println!("  Only messages from these senders will reach the agent.");
            println!("  Enter E.164 phone numbers for DMs and/or Signal group IDs,");
            println!("  comma-separated. Leave empty to drop every inbound message.");
            dialoguer::Input::new()
                .with_prompt("  Allowed senders (comma-separated)")
                .allow_empty(true)
                .interact_text()?
        }
    };

    let allowlist_trimmed = allowlist_csv.trim();
    if allowlist_trimmed.is_empty() {
        println!(
            "  Warning: empty allowlist. The Signal adapter will drop every \
             inbound message until you add entries via `wirken credentials \
             add signal-allowed-senders --channel signal`."
        );
    } else {
        let count = allowlist_trimmed
            .split(',')
            .filter(|e| !e.trim().is_empty())
            .count();
        println!("  signal: allowlist configured with {count} entries.");
    }

    Ok(SignalCreds {
        phone,
        endpoint,
        allowlist_csv: allowlist_trimmed.to_string(),
    })
}

/// The signal-cli socket path when none is given.
const DEFAULT_SIGNAL_ENDPOINT: &str = "/tmp/signal-cli.sock";

/// The Signal adapter speaks JSON-RPC over a Unix socket: refuse an
/// empty path and an HTTP URL.
fn validate_signal_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        anyhow::bail!(
            "The signal adapter speaks JSON-RPC over a Unix socket now. \
             Restart signal-cli with `daemon --socket /path/to/signal-cli.sock` \
             and supply that path here, not an HTTP URL."
        );
    }
    if endpoint.is_empty() {
        anyhow::bail!("Socket path cannot be empty.");
    }
    Ok(())
}

/// Persist the three signal-specific credential rows (phone, endpoint,
/// allowlist) plus the adapter keypair. `register_channel` must have
/// already stored `signal-token` and registered the adapter identity in
/// the registry; this function fills in the remaining fields the
/// adapter needs at runtime.
pub fn store_signal_creds(store: &CredentialStore, creds: &SignalCreds) -> Result<()> {
    store
        .store(
            "signal-phone-number",
            "signal",
            &VaultSecret::new(creds.phone.clone()),
            None,
            None,
        )
        .context("Failed to store phone number")?;
    store
        .store(
            "signal-endpoint",
            "signal",
            &VaultSecret::new(creds.endpoint.clone()),
            None,
            None,
        )
        .context("Failed to store endpoint")?;
    store
        .store(
            "signal-allowed-senders",
            "signal",
            &VaultSecret::new(creds.allowlist_csv.clone()),
            None,
            None,
        )
        .context("Failed to store allowlist")?;
    Ok(())
}

async fn add_signal(cfg: &GatewayConfig, data: &std::path::Path, flags: AddFlags) -> Result<()> {
    let creds = collect_signal_creds(flags.phone_number, flags.endpoint, flags.allowed_senders)?;
    // register_channel stores signal-token (value is the endpoint) and
    // the adapter keypair. Must run before store_signal_creds so both
    // writes share the same cached vault passphrase.
    register_channel("signal", &creds.endpoint, cfg, data).await?;

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(data, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    store_signal_creds(&store, &creds)?;

    println!("  signal: credentials encrypted.");
    println!("  Channel 'signal' added.");
    println!("  `wirken run` starts its adapter; restart it if it is already running.");
    Ok(())
}

async fn add_simple(
    channel: &str,
    cfg: &GatewayConfig,
    data: &std::path::Path,
    flags: AddFlags,
) -> Result<()> {
    let token = resolve_token(channel, flags.token.as_deref(), true)?;
    register_channel(channel, &token, cfg, data).await?;
    println!("  Channel '{channel}' added.");
    println!("  `wirken run` starts its adapter; restart it if it is already running.");
    Ok(())
}

/// Teams needs the App Password, stored as `teams-token`, and the App
/// ID before the adapter will run. Collect both before registering, so a
/// refused value leaves nothing half-written.
async fn add_teams(cfg: &GatewayConfig, data: &std::path::Path, flags: AddFlags) -> Result<()> {
    let password = resolve_with_validation(
        "Microsoft App Password",
        flags.token,
        "WIRKEN_TEAMS_TOKEN",
        true,
        validate_non_empty,
    )?;
    let app_id = resolve_with_validation(
        "Microsoft App ID",
        flags.app_id,
        "WIRKEN_TEAMS_APP_ID",
        false,
        validate_non_empty,
    )?;

    register_channel("teams", &password, cfg, data).await?;

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(data, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    store_teams_app_id(&store, &app_id)?;

    println!("  teams: app ID and password encrypted.");
    println!("  Channel 'teams' added.");
    println!("  `wirken run` starts its adapter; restart it if it is already running.");
    Ok(())
}

/// Write the Teams App ID under the name and channel the adapter reads.
/// Shared by `wirken channel add teams` and the setup wizard.
pub fn store_teams_app_id(store: &CredentialStore, app_id: &str) -> Result<()> {
    store
        .store(
            "teams-app-id",
            "teams",
            &VaultSecret::new(app_id.to_string()),
            None,
            None,
        )
        .context("Failed to store Teams app ID")
}

/// Matrix needs the account password, stored as `matrix-token`, the
/// homeserver URL and the username before the adapter will run. Collect
/// all three before registering, so a refused value leaves nothing
/// half-written.
async fn add_matrix(cfg: &GatewayConfig, data: &std::path::Path, flags: AddFlags) -> Result<()> {
    let homeserver = resolve_with_validation(
        "Matrix homeserver URL (e.g., https://matrix.org)",
        flags.homeserver,
        "WIRKEN_MATRIX_HOMESERVER",
        false,
        validate_non_empty,
    )?;
    let username = resolve_with_validation(
        "Matrix username (e.g., @wirken:matrix.org)",
        flags.username,
        "WIRKEN_MATRIX_USERNAME",
        false,
        validate_non_empty,
    )?;
    let password = resolve_with_validation(
        "Matrix password",
        flags.token,
        "WIRKEN_MATRIX_TOKEN",
        true,
        validate_non_empty,
    )?;

    register_channel("matrix", &password, cfg, data).await?;

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(data, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    store_matrix_account(&store, &homeserver, &username)?;

    println!("  matrix: credentials encrypted.");
    println!("  Channel 'matrix' added.");
    println!("  `wirken run` starts its adapter; restart it if it is already running.");
    Ok(())
}

/// Write the Matrix homeserver URL and username under the names and
/// channel the adapter reads. Shared by `wirken channel add matrix` and
/// the setup wizard.
pub fn store_matrix_account(
    store: &CredentialStore,
    homeserver: &str,
    username: &str,
) -> Result<()> {
    store
        .store(
            "matrix-homeserver",
            "matrix",
            &VaultSecret::new(homeserver.to_string()),
            None,
            None,
        )
        .context("Failed to store homeserver URL")?;
    store
        .store(
            "matrix-username",
            "matrix",
            &VaultSecret::new(username.to_string()),
            None,
            None,
        )
        .context("Failed to store username")
}

/// The BlueBubbles server URL when none is given.
const DEFAULT_BLUEBUBBLES_URL: &str = "http://localhost:1234";

/// iMessage needs the BlueBubbles server password, stored as both
/// `imessage-token` and `imessage-server-password`, and the server URL,
/// as the setup wizard writes them. Collect both before registering, so
/// a refused value leaves nothing half-written.
async fn add_imessage(cfg: &GatewayConfig, data: &std::path::Path, flags: AddFlags) -> Result<()> {
    let password = resolve_with_validation(
        "BlueBubbles server password",
        flags.token,
        "WIRKEN_IMESSAGE_TOKEN",
        true,
        validate_non_empty,
    )?;
    let url = resolve_bluebubbles_url(flags.bluebubbles_url)?;

    register_channel("imessage", &password, cfg, data).await?;

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(data, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    store_imessage_server(&store, &url, &password)?;

    println!("  imessage: credentials encrypted.");
    println!("  Channel 'imessage' added.");
    println!("  `wirken run` starts its adapter; restart it if it is already running.");
    Ok(())
}

/// The BlueBubbles server URL from `--bluebubbles-url`, then
/// `WIRKEN_IMESSAGE_BLUEBUBBLES_URL`, then a prompt offering the default.
/// Without a terminal to prompt on, the default.
fn resolve_bluebubbles_url(flag: Option<String>) -> Result<String> {
    let given = flag.or_else(|| std::env::var("WIRKEN_IMESSAGE_BLUEBUBBLES_URL").ok());
    if let Some(url) = given
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
    {
        return Ok(url);
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Ok(DEFAULT_BLUEBUBBLES_URL.to_string());
    }
    Ok(dialoguer::Input::new()
        .with_prompt("  BlueBubbles server URL")
        .default(DEFAULT_BLUEBUBBLES_URL.to_string())
        .interact_text()?)
}

/// Write the BlueBubbles server URL and password under the names and
/// channel the adapter reads. Shared by `wirken channel add imessage`
/// and the setup wizard.
pub fn store_imessage_server(store: &CredentialStore, url: &str, password: &str) -> Result<()> {
    store
        .store(
            "imessage-bluebubbles-url",
            "imessage",
            &VaultSecret::new(url.to_string()),
            None,
            None,
        )
        .context("Failed to store BlueBubbles URL")?;
    store
        .store(
            "imessage-server-password",
            "imessage",
            &VaultSecret::new(password.to_string()),
            None,
            None,
        )
        .context("Failed to store server password")
}

/// Google Chat needs two vault entries before the adapter will run:
/// the service-account bearer token (outbound REST) and the Cloud
/// project number (the audience every inbound webhook JWT is checked
/// against). The adapter hard-fails at construction when the project
/// number is absent, so collect and persist both here instead of
/// registering a channel that cannot start. Mirrors the WhatsApp
/// multi-field path.
async fn add_google_chat(
    cfg: &GatewayConfig,
    data: &std::path::Path,
    flags: AddFlags,
) -> Result<()> {
    let token = resolve_token("google-chat", flags.token.as_deref(), true)?;
    let project_number = collect_google_chat_project_number(flags.project_number)?;

    register_channel("google-chat", &token, cfg, data).await?;

    // register_channel opened the vault with the cached passphrase;
    // re-open the same way so the project-number write re-derives the
    // identical wrapping key (see register_channel's comment).
    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(data, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;
    store_google_chat_project_number(&store, &project_number)?;

    println!("  google-chat: project number encrypted.");
    println!("  Channel 'google-chat' added.");
    println!("  `wirken run` starts its adapter; restart it if it is already running.");
    Ok(())
}

async fn add_slack(cfg: &GatewayConfig, data: &std::path::Path, flags: AddFlags) -> Result<()> {
    let token = resolve_with_validation(
        "Slack bot token (xoxb-...)",
        flags.token.clone(),
        "WIRKEN_SLACK_TOKEN",
        true,
        validate_slack_bot_token,
    )?;
    let app_token = resolve_with_validation(
        "Slack app token (xapp-...)",
        flags.app_token,
        "WIRKEN_SLACK_APP_TOKEN",
        true,
        validate_slack_app_token,
    )?;

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(data, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    store
        .store(
            "slack-token",
            "slack",
            &VaultSecret::new(token.clone()),
            None,
            None,
        )
        .context("Failed to store Slack token")?;
    store
        .store(
            "slack-app-token",
            "slack",
            &VaultSecret::new(app_token),
            None,
            None,
        )
        .context("Failed to store Slack app token")?;

    register_adapter_identity("slack", cfg, &store)?;
    println!("  slack: tokens encrypted, adapter keypair generated, registered.");
    println!("  Channel 'slack' added.");
    println!("  `wirken run` starts its adapter; restart it if it is already running.");
    Ok(())
}

/// Collect and persist WhatsApp Cloud API credentials. The adapter
/// needs four fields — access token, phone number ID, verify token,
/// app secret — all in the vault before `wirken run` will start the
/// listener. Values come from, in order: CLI flag, env var
/// (`WIRKEN_WHATSAPP_*`), interactive prompt. Validation runs on
/// whichever source supplied the value so a bad flag fails as loudly
/// as a bad prompt entry.
async fn add_whatsapp(cfg: &GatewayConfig, data: &std::path::Path, flags: AddFlags) -> Result<()> {
    let creds = collect_whatsapp_creds(flags).context("Failed to collect WhatsApp credentials")?;

    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(data, move || pp);
    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    store_whatsapp_creds(&store, &creds)?;
    register_adapter_identity("whatsapp", cfg, &store)?;
    println!("  whatsapp: credentials encrypted, adapter keypair generated, registered.");
    println!("  Channel 'whatsapp' added.");
    println!("  `wirken run` starts its adapter; restart it if it is already running.");
    Ok(())
}

/// The four vault entries a WhatsApp adapter needs. Named to match
/// the keys `crates/cli/src/commands/adapter.rs` already retrieves.
#[derive(Debug, Clone)]
pub struct WhatsAppCreds {
    pub token: String,
    pub phone_number_id: String,
    pub verify_token: String,
    pub app_secret: String,
}

/// Resolve the WhatsApp credential set from flags, env vars, and
/// prompts. The collection order is the same for every field:
/// CLI flag → `WIRKEN_WHATSAPP_*` env var → interactive prompt.
/// Validation is applied to whichever source provided the value,
/// and in the interactive case the user is re-prompted until a
/// valid value lands or they abort. Pure in the non-interactive
/// sense: if all four fields are supplied via flag or env and all
/// pass validation, no prompt runs.
pub fn collect_whatsapp_creds(flags: AddFlags) -> Result<WhatsAppCreds> {
    let token = resolve_with_validation(
        "WhatsApp access token",
        flags.token,
        "WIRKEN_WHATSAPP_TOKEN",
        true,
        validate_non_empty,
    )?;
    let phone_number_id = resolve_with_validation(
        "WhatsApp phone number ID",
        flags.phone_number_id,
        "WIRKEN_WHATSAPP_PHONE_NUMBER_ID",
        false,
        validate_phone_number_id,
    )?;
    let verify_token = resolve_with_validation(
        "WhatsApp verify token",
        flags.verify_token,
        "WIRKEN_WHATSAPP_VERIFY_TOKEN",
        true,
        validate_non_empty,
    )?;
    let app_secret = resolve_with_validation(
        "WhatsApp app secret",
        flags.app_secret,
        "WIRKEN_WHATSAPP_APP_SECRET",
        true,
        validate_app_secret,
    )?;
    Ok(WhatsAppCreds {
        token,
        phone_number_id,
        verify_token,
        app_secret,
    })
}

/// Write the four WhatsApp credentials to the vault under the keys
/// the adapter reads in `crates/cli/src/commands/adapter.rs`.
pub fn store_whatsapp_creds(store: &CredentialStore, creds: &WhatsAppCreds) -> Result<()> {
    store
        .store(
            "whatsapp-token",
            "whatsapp",
            &VaultSecret::new(creds.token.clone()),
            None,
            None,
        )
        .context("Failed to store WhatsApp token")?;
    store
        .store(
            "whatsapp-phone-number-id",
            "whatsapp",
            &VaultSecret::new(creds.phone_number_id.clone()),
            None,
            None,
        )
        .context("Failed to store WhatsApp phone number ID")?;
    store
        .store(
            "whatsapp-verify-token",
            "whatsapp",
            &VaultSecret::new(creds.verify_token.clone()),
            None,
            None,
        )
        .context("Failed to store WhatsApp verify token")?;
    store
        .store(
            "whatsapp-app-secret",
            "whatsapp",
            &VaultSecret::new(creds.app_secret.clone()),
            None,
            None,
        )
        .context("Failed to store WhatsApp app secret")?;
    Ok(())
}

/// Resolve the Google Chat Cloud project number from flag, env var
/// (`WIRKEN_GOOGLE_CHAT_PROJECT_NUMBER`), or interactive prompt. This
/// is the audience claim every inbound webhook JWT must carry; the
/// adapter refuses to start without it (see
/// `crates/adapter-google-chat/src/auth.rs`). Shared by `wirken
/// channel add google-chat` and the setup wizard so both produce the
/// same vault state.
pub fn collect_google_chat_project_number(flag: Option<String>) -> Result<String> {
    resolve_with_validation(
        "Google Chat Cloud project number (inbound JWT audience)",
        flag,
        "WIRKEN_GOOGLE_CHAT_PROJECT_NUMBER",
        false,
        validate_project_number,
    )
}

/// Write the Google Chat project number to the vault under the exact
/// key the adapter retrieves at startup in
/// `crates/cli/src/commands/adapter.rs`.
pub fn store_google_chat_project_number(
    store: &CredentialStore,
    project_number: &str,
) -> Result<()> {
    store
        .store(
            "google-chat-project-number",
            "google-chat",
            &VaultSecret::new(project_number.to_string()),
            None,
            None,
        )
        .context("Failed to store Google Chat project number")?;
    Ok(())
}

fn register_adapter_identity(
    channel: &str,
    cfg: &GatewayConfig,
    store: &CredentialStore,
) -> Result<()> {
    let identity = AdapterIdentity::generate(channel);
    let pub_key = identity.public_key_bytes();

    let secret_key_hex: String = identity
        .secret_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    store
        .store(
            &format!("{channel}-adapter-key"),
            channel,
            &VaultSecret::new(secret_key_hex),
            None,
            None,
        )
        .context("Failed to store adapter key")?;

    let registry = AdapterRegistry::open(&cfg.adapters_db_path())
        .context("Failed to open adapter registry")?;
    let _ = registry.unregister(channel);
    registry
        .register(channel, &pub_key, channel)
        .context("Failed to register adapter")?;
    Ok(())
}

fn resolve_token(channel: &str, flag: Option<&str>, secret: bool) -> Result<String> {
    let env_var = format!("WIRKEN_{}_TOKEN", channel.to_uppercase().replace('-', "_"));
    if let Some(t) = flag {
        let t = t.trim().to_string();
        validate_non_empty(&t)?;
        return Ok(t);
    }
    if let Ok(v) = std::env::var(&env_var) {
        let v = v.trim().to_string();
        if !v.is_empty() {
            // Token came from the process environment rather than an
            // interactive prompt. Operators who rely on this branch
            // for unattended setup should know it landed: env vars
            // are visible in /proc/<pid>/environ to other processes
            // running at the same UID, and a stale exported value can
            // silently overwrite a freshly minted credential. The
            // value still ends up encrypted in the vault; this only
            // logs the source.
            tracing::warn!(
                channel = %channel,
                env_var = %env_var,
                "{env_var} resolved from process environment; the value will be \
                 encrypted in the vault but the env var is visible to other \
                 processes at the same UID for the lifetime of this shell"
            );
            return Ok(v);
        }
    }
    let label = format!("  {channel} bot token");
    loop {
        let value = if secret {
            super::read_secret(&format!("{label}: "))?
        } else {
            dialoguer::Input::<String>::new()
                .with_prompt(&label)
                .interact_text()?
        };
        match validate_non_empty(&value) {
            Ok(()) => return Ok(value),
            Err(e) => {
                println!("  {e}");
                continue;
            }
        }
    }
}

fn resolve_with_validation(
    label: &str,
    flag: Option<String>,
    env_var: &str,
    secret: bool,
    validate: fn(&str) -> Result<()>,
) -> Result<String> {
    if let Some(v) = flag {
        let v = v.trim().to_string();
        validate(&v).with_context(|| format!("Invalid --{} flag", env_var))?;
        return Ok(v);
    }
    if let Ok(v) = std::env::var(env_var) {
        let v = v.trim().to_string();
        if !v.is_empty() {
            validate(&v).with_context(|| format!("Invalid {env_var} env var"))?;
            // See `resolve_token` for why env-var sourcing is logged.
            // Same posture: the value lands in the vault, but the env
            // var was readable by anything sharing the UID up to this
            // point.
            tracing::warn!(
                env_var = %env_var,
                label = %label,
                "{env_var} resolved from process environment; the value will be \
                 encrypted in the vault but the env var is visible to other \
                 processes at the same UID for the lifetime of this shell"
            );
            return Ok(v);
        }
    }
    prompt_with_validation(label, secret, validate)
}

/// Prompt until `validate` accepts, printing the rejection and asking
/// again. Shared by `wirken channel add` and `wirken setup` so a
/// mistyped value re-prompts in both rather than ending the flow: a
/// bail partway through setup leaves the operator to restart a wizard
/// that has already written earlier answers.
pub fn prompt_with_validation(
    label: &str,
    secret: bool,
    validate: fn(&str) -> Result<()>,
) -> Result<String> {
    loop {
        let prompt_label = format!("  {label}");
        let value = if secret {
            super::read_secret(&format!("{prompt_label}: "))?
        } else {
            dialoguer::Input::<String>::new()
                .with_prompt(&prompt_label)
                .interact_text()?
        };
        match validate(&value) {
            Ok(()) => return Ok(value),
            Err(e) => {
                println!("  {e}");
                continue;
            }
        }
    }
}

// -- Validators ---------------------------------------------------------

/// A token / secret must have at least one non-whitespace character.
/// The prompt helpers trim before calling, so this rejects the
/// empty string and nothing else.
pub fn validate_non_empty(s: &str) -> Result<()> {
    if s.trim().is_empty() {
        anyhow::bail!("value cannot be empty");
    }
    Ok(())
}

/// Slack issues two tokens with different prefixes and the pair is easy
/// to transpose: `xoxb-` is the bot user token under OAuth &
/// Permissions, `xapp-` the app-level token under Basic Information.
/// Either one stores cleanly in the other's slot and the mismatch only
/// surfaces later, as an auth failure at connect time, so each prompt
/// rejects the other's token and names the prompt it belongs to.
pub fn validate_slack_bot_token(s: &str) -> Result<()> {
    validate_non_empty(s)?;
    if s.trim().starts_with("xapp-") {
        anyhow::bail!(
            "that is an app-level token; it belongs at the \
             'Slack app token (xapp-...)' prompt"
        );
    }
    Ok(())
}

/// Counterpart to [`validate_slack_bot_token`]; see there for why the
/// two prompts cross-check each other.
pub fn validate_slack_app_token(s: &str) -> Result<()> {
    validate_non_empty(s)?;
    if s.trim().starts_with("xoxb-") {
        anyhow::bail!(
            "that is a bot user token; it belongs at the \
             'Slack bot token (xoxb-...)' prompt"
        );
    }
    Ok(())
}

/// WhatsApp Cloud API phone-number-id: numeric, 15 or 16 digits.
/// Meta's IDs are 64-bit-ish integers rendered decimal; we range-
/// check length rather than parsing into u64 to keep the rejection
/// message intelligible.
pub fn validate_phone_number_id(s: &str) -> Result<()> {
    let trimmed = s.trim();
    if !(15..=16).contains(&trimmed.len()) {
        anyhow::bail!(
            "phone number ID must be 15-16 digits (got {} chars)",
            trimmed.len()
        );
    }
    if !trimmed.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!("phone number ID must be numeric");
    }
    Ok(())
}

/// Meta app secret as shown in the Meta Developer portal: 32
/// characters, lowercase hex. Anything else is either a copy-paste
/// mistake (leading whitespace, wrong field) or a mis-configured
/// app. Fail at entry rather than at first webhook delivery.
pub fn validate_app_secret(s: &str) -> Result<()> {
    let trimmed = s.trim();
    if trimmed.len() != 32 {
        anyhow::bail!(
            "app secret must be exactly 32 characters (got {})",
            trimmed.len()
        );
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        anyhow::bail!("app secret must be lowercase hex (0-9, a-f)");
    }
    Ok(())
}

/// Google Cloud project number: a non-empty decimal integer. The
/// inbound webhook JWT's `aud` claim is compared against it as an
/// exact string, so a transposed or mistyped digit silently drops
/// every inbound message rather than erroring. Reject non-numeric
/// input at entry. Note this is the project *number* (all digits),
/// not the project *ID* (which may contain letters and hyphens).
pub fn validate_project_number(s: &str) -> Result<()> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        anyhow::bail!("project number cannot be empty");
    }
    if !trimmed.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!(
            "project number must be numeric (the Google Cloud project number, not the project ID)"
        );
    }
    Ok(())
}

pub async fn list() -> Result<()> {
    let cfg = config();
    let registry = AdapterRegistry::open(&cfg.adapters_db_path())
        .context("Failed to open adapter registry")?;

    let adapters = registry.list();
    if adapters.is_empty() {
        println!("  No channels configured.");
        println!("  Run `wirken setup` or `wirken channel add <channel>`.");
        return Ok(());
    }

    // Connection state comes from the audit log. The registry's
    // `connected` flag is the gateway's in-memory view and reads false
    // from here.
    let statuses = super::adapter_state::AdapterStatuses::read_path(&cfg.audit_db_path());
    let entries: Vec<(String, String)> = adapters
        .into_iter()
        .map(|a| (a.adapter_id, a.channel))
        .collect();
    println!("  Configured channels:");
    println!();
    for line in list_lines(&entries, &statuses) {
        println!("{line}");
    }
    println!();
    Ok(())
}

/// The table `wirken channel list` prints: a header, then one line per
/// `(adapter id, channel)` with its state and when that was recorded.
fn list_lines(
    entries: &[(String, String)],
    statuses: &super::adapter_state::AdapterStatuses,
) -> Vec<String> {
    let line = |id: &str, channel: &str, state: &str, recorded: &str| {
        format!("  {id:12} {channel:12} {state:42} {recorded}")
    };
    let mut lines = vec![line("ADAPTER", "CHANNEL", "STATE", "RECORDED")];
    for (id, channel) in entries {
        let status = statuses.of(id);
        lines.push(line(id, channel, &status.label(), &status.recorded()));
    }
    lines
}

pub async fn remove(channel: &str) -> Result<()> {
    let cfg = config();

    let registry = AdapterRegistry::open(&cfg.adapters_db_path())
        .context("Failed to open adapter registry")?;

    registry
        .unregister(channel)
        .context(format!("Failed to remove channel '{channel}'"))?;

    // Remove every credential tagged with this channel — `<channel>-token`,
    // `<channel>-adapter-key`, plus any per-channel detail rows (signal's
    // endpoint/phone/allowlist, slack's app-token, whatsapp's four keys,
    // etc.). Vault open is best-effort: if the device key cannot be
    // unwrapped (e.g. the operator re-keyed the vault), the registry
    // entry still goes away and the encrypted rows can be cleared with
    // `wirken credentials remove <name>`.
    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(&cfg.data_dir, move || pp);
    let removed = match CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref()) {
        Ok(store) => store.delete_by_channel(channel).unwrap_or(0),
        Err(_) => 0,
    };

    if removed > 0 {
        println!("  Channel '{channel}' removed ({removed} credentials cleared).");
    } else {
        println!("  Channel '{channel}' removed.");
    }
    Ok(())
}

/// Register a channel: store token in vault, generate adapter keypair, register in adapter registry.
pub async fn register_channel(
    channel: &str,
    token: &str,
    cfg: &GatewayConfig,
    data: &std::path::Path,
) -> Result<()> {
    // Store token in vault. Use the shared cached-passphrase helper so
    // the immediately-following per-channel detail writes in `setup`
    // re-derive the same wrapping key.
    let pp = super::cached_vault_passphrase()?;
    let keychain = probe_keychain(data, move || pp);

    let store = CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")?;

    let secret = VaultSecret::new(token.to_string());
    store
        .store(&format!("{channel}-token"), channel, &secret, None, None)
        .context("Failed to store channel token")?;

    register_adapter_identity(channel, cfg, &store)?;
    println!("  {channel}: token encrypted, adapter keypair generated, registered.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Validators ---------------------------------------------------

    // Low-entropy fixtures, as above: the validators read the prefix
    // and nothing else.
    #[test]
    fn slack_bot_token_rejects_the_app_token() {
        let e = validate_slack_bot_token("xapp-aaaa")
            .unwrap_err()
            .to_string();
        assert!(e.contains("Slack app token (xapp-...)"), "{e}");
    }

    #[test]
    fn slack_app_token_rejects_the_bot_token() {
        let e = validate_slack_app_token("xoxb-aaaa")
            .unwrap_err()
            .to_string();
        assert!(e.contains("Slack bot token (xoxb-...)"), "{e}");
    }

    #[test]
    fn slack_tokens_accept_their_own_prefix() {
        assert!(validate_slack_bot_token("xoxb-aaaa").is_ok());
        assert!(validate_slack_app_token("xapp-aaaa").is_ok());
    }

    #[test]
    fn slack_tokens_reject_empty() {
        assert!(validate_slack_bot_token("").is_err());
        assert!(validate_slack_app_token("   ").is_err());
    }

    #[test]
    fn phone_number_id_accepts_15_and_16_digits() {
        assert!(validate_phone_number_id("123456789012345").is_ok());
        assert!(validate_phone_number_id("1234567890123456").is_ok());
    }

    #[test]
    fn phone_number_id_rejects_wrong_length() {
        assert!(validate_phone_number_id("12345678901234").is_err());
        assert!(validate_phone_number_id("12345678901234567").is_err());
        assert!(validate_phone_number_id("").is_err());
    }

    #[test]
    fn phone_number_id_rejects_non_numeric() {
        assert!(validate_phone_number_id("12345678901234a").is_err());
        assert!(validate_phone_number_id("12345-67890123456").is_err());
    }

    #[test]
    fn app_secret_accepts_32_lowercase_hex() {
        // Low-entropy fixtures so gitleaks' generic-api-key rule
        // does not treat them as real secrets. The validator only
        // cares about char class and length, not distribution.
        assert!(validate_app_secret("abababababababababababababababab").is_ok());
        assert!(validate_app_secret("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_ok());
    }

    #[test]
    fn app_secret_rejects_wrong_length() {
        assert!(validate_app_secret("abababab").is_err());
        assert!(validate_app_secret("abababababababababababababababababab").is_err());
    }

    #[test]
    fn app_secret_rejects_uppercase_and_non_hex() {
        assert!(validate_app_secret("ABABABABABABABABABABABABABABABAB").is_err());
        assert!(validate_app_secret("abababababababababababababababaZ").is_err());
    }

    #[test]
    fn non_empty_rejects_whitespace_only() {
        assert!(validate_non_empty("").is_err());
        assert!(validate_non_empty("   ").is_err());
        assert!(validate_non_empty("\t\n").is_err());
        assert!(validate_non_empty("x").is_ok());
    }

    // -- Non-interactive end-to-end -----------------------------------

    fn good_flags() -> AddFlags {
        // All fixture values are intentionally low-entropy so the
        // gitleaks scanner does not flag them as `generic-api-key`.
        AddFlags {
            token: Some("fake_token_value".into()),
            phone_number_id: Some("123456789012345".into()),
            verify_token: Some("my_verify_token".into()),
            app_secret: Some("00000000000000000000000000000000".into()),
            project_number: None,
            app_id: None,
            homeserver: None,
            username: None,
            bluebubbles_url: None,
            app_token: None,
            phone_number: None,
            endpoint: None,
            allowed_senders: None,
        }
    }

    #[test]
    fn collect_whatsapp_creds_from_flags_succeeds() {
        let creds = collect_whatsapp_creds(good_flags()).expect("flags should validate");
        assert_eq!(creds.token, "fake_token_value");
        assert_eq!(creds.phone_number_id, "123456789012345");
        assert_eq!(creds.verify_token, "my_verify_token");
        assert_eq!(creds.app_secret, "00000000000000000000000000000000");
    }

    #[test]
    fn collect_whatsapp_creds_rejects_bad_phone_number_id_flag() {
        let mut flags = good_flags();
        flags.phone_number_id = Some("short".into());
        let err = collect_whatsapp_creds(flags).expect_err("short id must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("phone number ID"),
            "error should name the field, got: {msg}"
        );
    }

    #[test]
    fn collect_whatsapp_creds_rejects_bad_app_secret_flag() {
        let mut flags = good_flags();
        flags.app_secret = Some("not-hex-at-all".into());
        let err = collect_whatsapp_creds(flags).expect_err("non-hex secret must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("app secret") || msg.contains("APP_SECRET"),
            "error should name the field, got: {msg}"
        );
    }

    #[test]
    fn non_interactive_end_to_end_persists_all_four_vault_keys() {
        // The full non-interactive path: flags in, validation passes,
        // credentials land in the vault under the exact keys the
        // adapter reads at startup.
        use tempfile::TempDir;
        use wirken_vault::{AgeFileKeychain, CredentialStore};

        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");

        let keychain = AgeFileKeychain::new(tmp.path().join("keychain"), "test-passphrase".into());
        let store = CredentialStore::open(&vault_path, &keychain).expect("open credential store");

        let creds = collect_whatsapp_creds(good_flags()).expect("flags validate");
        store_whatsapp_creds(&store, &creds).expect("store round-trip");

        for key in [
            "whatsapp-token",
            "whatsapp-phone-number-id",
            "whatsapp-verify-token",
            "whatsapp-app-secret",
        ] {
            let (secret, _) = store
                .retrieve(key)
                .unwrap_or_else(|e| panic!("missing {key}: {e}"));
            assert!(!secret.expose().is_empty(), "{key} round-tripped empty");
        }

        let (token, _) = store.retrieve("whatsapp-token").unwrap();
        assert_eq!(token.expose(), "fake_token_value");
        let (phone, _) = store.retrieve("whatsapp-phone-number-id").unwrap();
        assert_eq!(phone.expose(), "123456789012345");
    }

    // -- Google Chat --------------------------------------------------

    #[test]
    fn project_number_accepts_numeric() {
        assert!(validate_project_number("1234567890").is_ok());
        assert!(validate_project_number("  1234567890  ").is_ok());
    }

    #[test]
    fn project_number_rejects_empty_and_non_numeric() {
        assert!(validate_project_number("").is_err());
        assert!(validate_project_number("   ").is_err());
        assert!(validate_project_number("123-456").is_err());
        // The project ID form (letters/hyphens) is the common mix-up.
        assert!(validate_project_number("my-project-123").is_err());
    }

    #[test]
    fn collect_google_chat_project_number_from_flag_succeeds() {
        let n = collect_google_chat_project_number(Some("1234567890".into()))
            .expect("flag should validate");
        assert_eq!(n, "1234567890");
    }

    #[test]
    fn google_chat_setup_persists_project_number_vault_key() {
        // Regression: the adapter hard-fails at startup without
        // `google-chat-project-number` in the vault. Lock the key the
        // collect+store path writes so neither `channel add` nor the
        // setup wizard can drop it again.
        use tempfile::TempDir;
        use wirken_vault::{AgeFileKeychain, CredentialStore};

        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.db");
        let keychain = AgeFileKeychain::new(tmp.path().join("keychain"), "test-passphrase".into());
        let store = CredentialStore::open(&vault_path, &keychain).expect("open credential store");

        let n = collect_google_chat_project_number(Some("1234567890".into())).expect("validate");
        store_google_chat_project_number(&store, &n).expect("store round-trip");

        let (secret, _) = store
            .retrieve("google-chat-project-number")
            .expect("adapter startup key must be present");
        assert_eq!(secret.expose(), "1234567890");
    }

    /// Each row sequence in the audit log prints as its state, with the
    /// time the deciding row was written.
    #[tokio::test]
    async fn list_prints_each_adapter_state_from_the_audit_log() {
        use crate::commands::adapter_state::tests::{
            abandoned, connect, disconnect, restart, statuses,
        };
        let statuses = statuses(vec![
            connect("telegram"),
            connect("slack"),
            disconnect("slack"),
            connect("discord"),
            restart("discord", 3),
            abandoned("matrix", 8),
        ])
        .await;
        let entries: Vec<(String, String)> = ["telegram", "slack", "discord", "matrix", "signal"]
            .iter()
            .map(|c| (c.to_string(), c.to_string()))
            .collect();
        let lines = list_lines(&entries, &statuses);

        assert!(
            lines[0].starts_with("  ADAPTER      CHANNEL      STATE"),
            "{lines:?}"
        );
        let state_of = |line: &str| line[28..].split("  ").next().unwrap().trim().to_string();
        let recorded_of = |line: &str| line.split_whitespace().last().unwrap().to_string();
        assert_eq!(state_of(&lines[1]), "connected");
        let since = recorded_of(&lines[2]);
        assert_eq!(state_of(&lines[2]), format!("disconnected (since {since})"));
        assert_eq!(state_of(&lines[3]), "restarting (attempt 3)");
        assert_eq!(state_of(&lines[4]), "abandoned (attempts 8)");
        assert_eq!(state_of(&lines[5]), "no record");
        assert_eq!(recorded_of(&lines[5]), "-");
        for line in &lines[1..5] {
            let recorded = recorded_of(line);
            assert!(
                chrono::DateTime::parse_from_rfc3339(&recorded).is_ok(),
                "{line}"
            );
        }
    }
}
