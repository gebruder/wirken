use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::io::Write;

use wirken_audit::{CREDENTIALS_SESSION, SessionEvent, SessionId, SessionLog as _, TrustLevel};
use wirken_vault::{Binding, CredentialStore, Destination, probe_keychain};

use super::config;

/// `wirken vault reset`: destroy the device key and every stored
/// credential so the vault can be rebuilt from scratch. This is the
/// documented way out of a forgotten passphrase, where
/// `CredentialStore::open` refuses to overwrite the keychain it cannot
/// unwrap. The operator must type `reset`; there is no `--force` bypass.
pub fn reset() -> Result<()> {
    let cfg = config();
    let db_path = cfg.vault_db_path();
    let plan = wirken_vault::reset_plan(&cfg.data_dir, &db_path);

    if plan.keychain_dir.is_none() && plan.db_files.is_empty() {
        println!(
            "  No vault state found at {}; nothing to reset.",
            cfg.data_dir.display()
        );
        return Ok(());
    }

    println!("  This will permanently destroy:");
    if let Some(dir) = &plan.keychain_dir {
        println!("    keychain directory: {}", dir.display());
        println!(
            "      the device key, its salt, and all aux keys (including the alarm-log HMAC key)"
        );
    }
    for f in &plan.db_files {
        println!("    credential db: {}", f.display());
    }
    if let Some(n) = plan.credential_rows {
        println!("    {n} stored credential row(s) will be lost");
    }
    println!();
    println!("  All stored credentials become unrecoverable. The secrets");
    println!("  themselves remain live at their providers — rotate them there.");
    println!("  The alarm-log key regenerates on next use. The audit log is");
    println!("  not touched.");
    println!();
    print!("  Type `reset` to confirm: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !reset_confirmed(&input) {
        println!("  Aborted. No changes made.");
        return Ok(());
    }

    let removed = wirken_vault::reset(&cfg.data_dir, &db_path)?;
    for p in &removed {
        println!("  removed {}", p.display());
    }
    println!("  Vault reset. The next vault open creates a fresh empty store.");
    Ok(())
}

/// The confirmation gate. Only the exact word `reset`, ignoring the
/// trailing line terminator from the prompt, proceeds; every other input
/// aborts with no deletion. Deliberately strict: surrounding whitespace
/// or any other token does not count.
/// The bindings a migration proposes, from the configuration as it
/// stands: `allowed_hosts`; each signed `mcp.json` entry that reads the
/// name; each provider key's provider and base URL in `provider.json`
/// and the agent store; an adapter's own credentials; a plan sign-in.
pub(crate) fn propose_bindings(
    data_dir: &std::path::Path,
    rows: &[wirken_vault::MigrationRow],
) -> BTreeMap<String, Binding> {
    let mut grants: BTreeMap<String, Vec<Destination>> = BTreeMap::new();
    let mut add = |name: &str, d: Destination| {
        grants.entry(name.to_string()).or_default().push(d);
    };

    for (name, server, digest) in &wirken_mcp_proxy::configured_credentials(data_dir).uses {
        if let Some(digest) = digest {
            add(name, super::destinations::mcp_server(server, digest));
        }
    }

    if let Ok(raw) = std::fs::read_to_string(data_dir.join("provider.json"))
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw)
    {
        if let (Some(provider), Some(base_url)) = (
            json.get("provider").and_then(|v| v.as_str()),
            json.get("base_url").and_then(|v| v.as_str()),
        ) {
            add(
                &format!("{provider}-api-key"),
                super::destinations::provider(provider, base_url),
            );
        }
        if let Some(overrides) = json.get("channel_overrides").and_then(|v| v.as_object()) {
            for o in overrides.values() {
                if let (Some(name), Some(provider)) = (
                    o.get("api_key_name").and_then(|v| v.as_str()),
                    o.get("provider").and_then(|v| v.as_str()),
                ) {
                    let base_url = o.get("base_url").and_then(|v| v.as_str()).unwrap_or("");
                    add(name, super::destinations::provider(provider, base_url));
                }
            }
        }
    }

    if let Ok(keyed) =
        wirken_zirkel::orchestrator::keyed_source_hosts(&data_dir.join("presets").join("zirkel"))
    {
        for (source, hosts) in keyed {
            for host in hosts {
                add(&format!("zirkel-{source}-api-key"), Destination::Host(host));
            }
        }
    }

    let agents_db = data_dir.join("agent_config.db");
    if agents_db.exists()
        && let Ok(store) = wirken_gateway::agent_config::AgentConfigStore::open(&agents_db)
    {
        for agent in store.list().unwrap_or_default() {
            if !agent.api_key_credential.is_empty() && !agent.auth.is_plan() {
                add(
                    &agent.api_key_credential,
                    super::destinations::provider(&agent.provider, &agent.base_url),
                );
            }
        }
    }

    let mut out = BTreeMap::new();
    for (name, channel, kind, hosts) in rows {
        let mut binding = Binding::hosts(hosts);
        let adapter_binding = wirken_vault::default_binding(name, channel);
        for d in adapter_binding.destinations() {
            binding.grant(d);
        }
        for adapter in wirken_vault::ADAPTERS {
            if super::adapter_handoff::credential_names(adapter).contains(name) {
                binding.grant(Destination::Adapter(adapter.to_string()));
            }
        }
        if *kind == wirken_vault::CredentialKind::PlanSignIn {
            binding.grant(Destination::Plan);
        }
        for d in grants.get(name).into_iter().flatten() {
            binding.grant(d.clone());
        }
        out.insert(name.clone(), binding);
    }
    out
}

/// `wirken vault migrate`: re-seal a vault from before destination
/// binding, at a terminal, after a backup, with the operator's
/// confirmation of every destination.
pub fn migrate(edit: Option<std::path::PathBuf>) -> Result<()> {
    if std::env::var_os(wirken_agent::tool::EXEC_MARKER_ENV).is_some() {
        bail!("wirken vault migrate refuses to run inside a Wirken exec; run it from a terminal");
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!("wirken vault migrate takes the vault passphrase at a terminal");
    }
    let cfg = config();
    let db = cfg.vault_db_path();
    match CredentialStore::format_at(&db)? {
        None => {
            println!("  No vault at {}; nothing to migrate.", db.display());
            return Ok(());
        }
        Some(f) if f >= wirken_vault::BOUND_FORMAT => {
            println!("  The vault is already migrated.");
            return Ok(());
        }
        Some(_) => {}
    }
    println!("  Stop `wirken run` before migrating; it cannot use the vault until this is done.");

    // 1. Backup, before anything touches the vault.
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let backup = db.with_file_name(format!("vault.db.pre-binding-{stamp}.bak"));
    let live_rows = {
        let conn =
            rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.query_row("SELECT COUNT(*) FROM credentials", [], |r| {
            r.get::<_, i64>(0)
        })?
    };
    let backed_up = wirken_vault::backup_vault(&db, &backup)
        .with_context(|| format!("back up the vault to {}", backup.display()))?;
    if i64::try_from(backed_up).ok() != Some(live_rows) {
        bail!(
            "the backup at {} holds {backed_up} rows, the vault {live_rows}; nothing changed",
            backup.display()
        );
    }
    println!("  Backup: {} ({backed_up} rows)", backup.display());

    // 2. Proposed bindings.
    let keychain = probe_keychain(&cfg.data_dir, || {
        dialoguer::Password::new()
            .with_prompt("  Vault passphrase")
            .interact()
            .unwrap_or_default()
    });
    let mut store = CredentialStore::open_any_format(&db, keychain.as_ref())
        .context("Failed to open credential store")?;
    let rows = store.rows_for_migration()?;
    let proposal = match &edit {
        Some(path) if path.exists() => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            let mut edited: BTreeMap<String, Binding> = serde_json::from_str(&raw)
                .with_context(|| format!("{} is not a binding proposal", path.display()))?;
            edited.retain(|name, _| rows.iter().any(|(n, ..)| n == name));
            edited
        }
        Some(path) => {
            let proposal = propose_bindings(&cfg.data_dir, &rows);
            std::fs::write(path, serde_json::to_string_pretty(&proposal)?)
                .with_context(|| format!("write {}", path.display()))?;
            println!(
                "  Wrote the proposal to {}. Remove what should not be there, then run                  `wirken vault migrate --edit {}` again.",
                path.display(),
                path.display()
            );
            return Ok(());
        }
        None => propose_bindings(&cfg.data_dir, &rows),
    };

    println!();
    println!("  Each credential will go only to these destinations:");
    for (name, ..) in &rows {
        let destinations = proposal
            .get(name)
            .map(Binding::destinations)
            .unwrap_or_default();
        if destinations.is_empty() {
            println!("    {name:32}  (nothing)");
        }
        for d in destinations {
            println!("    {name:32}  {:10}  {}", d.kind(), d.describe());
        }
    }
    println!();
    print!("  Type `yes` to re-seal the vault with these: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim_end_matches(['\n', '\r']) != "yes" {
        println!("  Aborted. The vault is unchanged; the backup stays.");
        return Ok(());
    }

    // 3. Re-seal in one transaction; any error leaves format 1.
    let migration = match store.migrate_to_bound(&proposal) {
        Ok(m) => m,
        Err(e) => {
            bail!(
                "the re-seal failed and was rolled back; the vault is unchanged: {e}.                  Backup: {}",
                backup.display()
            );
        }
    };
    drop(store);

    // 4. Verify, and restore the backup if it does not hold.
    let verified = CredentialStore::open(&db, keychain.as_ref())
        .and_then(|s| s.plaintext_digests())
        .map(|digests| digests == migration.digests);
    if !matches!(verified, Ok(true)) {
        let why = match verified {
            Ok(_) => "a re-sealed value does not match its original".to_string(),
            Err(e) => e.to_string(),
        };
        wirken_vault::restore_vault(&backup, &db)?;
        let restored = CredentialStore::format_at(&db)?;
        bail!(
            "verification failed after the re-seal ({why}); the backup was restored              (format {restored:?}). Backup: {}",
            backup.display()
        );
    }

    // 5. The record.
    let operator = super::local_operator();
    let mut events = vec![SessionEvent::VaultMigrated {
        rows: u64::try_from(migration.digests.len()).unwrap_or(u64::MAX),
        from_format: 1,
        to_format: wirken_vault::BOUND_FORMAT,
        backup: backup
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
    }];
    for (name, binding) in &proposal {
        for d in binding.destinations() {
            events.push(SessionEvent::CredentialDestinationGranted {
                credential: name.clone(),
                destination_kind: d.kind().to_string(),
                destination: d.describe(),
                granted_by: operator.clone(),
            });
        }
    }
    let recorded = super::open_signed_session_log(&cfg).and_then(|log| {
        let handle = log.handle_for(SessionId::new(CREDENTIALS_SESSION.to_string()));
        for event in events {
            log.append(&handle, TrustLevel::User, event)?;
        }
        super::seal_operator_lane(&log, CREDENTIALS_SESSION);
        Ok(())
    });
    if let Err(e) = recorded {
        eprintln!("  The vault is migrated, but its audit rows could not be written: {e:#}");
    }
    println!(
        "  Migrated {} credentials. The backup stays at {}.",
        migration.digests.len(),
        backup.display()
    );
    Ok(())
}

fn reset_confirmed(input: &str) -> bool {
    input.trim_end_matches(['\n', '\r']) == "reset"
}

#[cfg(test)]
mod tests {
    use super::reset_confirmed;

    /// The proposal takes each credential's destinations from the
    /// configuration: hosts, the default provider, an agent's key, an
    /// adapter's own names and a plan sign-in. Anything else gets none.
    #[test]
    fn a_proposal_reads_the_configuration() {
        use wirken_vault::{CredentialKind, Destination};
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("provider.json"),
            r#"{"provider": "openai", "model": "m", "base_url": "https://api.openai.com/v1"}"#,
        )
        .unwrap();
        let rows = vec![
            (
                "gh".to_string(),
                String::new(),
                CredentialKind::Secret,
                vec!["api.github.com".to_string()],
            ),
            (
                "openai-api-key".to_string(),
                "openai".to_string(),
                CredentialKind::Secret,
                vec![],
            ),
            (
                "telegram-token".to_string(),
                String::new(),
                CredentialKind::Secret,
                vec![],
            ),
            (
                "openai-plan".to_string(),
                "oauth".to_string(),
                CredentialKind::PlanSignIn,
                vec![],
            ),
            (
                "stray".to_string(),
                String::new(),
                CredentialKind::Secret,
                vec![],
            ),
        ];
        let p = super::propose_bindings(dir.path(), &rows);
        assert!(p["gh"].permits(&Destination::Host("api.github.com".into())));
        assert!(
            p["openai-api-key"].permits(&crate::commands::destinations::provider(
                "openai",
                "https://api.openai.com/v1"
            ))
        );
        assert!(p["telegram-token"].permits(&Destination::Adapter("telegram".into())));
        assert!(p["openai-plan"].permits(&Destination::Plan));
        assert!(p["stray"].is_empty());
    }

    #[test]
    fn reset_confirmed_accepts_exact_word_with_line_terminator() {
        assert!(reset_confirmed("reset\n"));
        assert!(reset_confirmed("reset\r\n"));
        assert!(reset_confirmed("reset"));
    }

    #[test]
    fn reset_confirmed_rejects_anything_else() {
        assert!(!reset_confirmed(""));
        assert!(!reset_confirmed("\n"));
        assert!(!reset_confirmed("yes\n"));
        assert!(!reset_confirmed("Reset\n"));
        assert!(!reset_confirmed("resett\n"));
        assert!(!reset_confirmed("reset now\n"));
        // Surrounding whitespace is not the exact word.
        assert!(!reset_confirmed(" reset\n"));
        assert!(!reset_confirmed("reset \n"));
    }
}
