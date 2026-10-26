//! `wirken credentials grant` and `revoke`: where a credential may go.

use anyhow::{Context, Result, bail};

use wirken_audit::{CREDENTIALS_SESSION, SessionEvent, SessionId, SessionLog as _, TrustLevel};
use wirken_vault::{CredentialStore, Destination, probe_keychain};

use super::{config, local_operator, open_signed_session_log, seal_operator_lane};

/// How long a grant waits for the vault's write lock.
const WRITE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The destinations named on the command line.
#[derive(Default, Clone)]
pub struct Destinations {
    pub hosts: Vec<String>,
    pub mcp_servers: Vec<String>,
    pub provider: Option<String>,
    pub base_url: Option<String>,
    pub adapters: Vec<String>,
    pub plan: bool,
}

impl Destinations {
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
            && self.mcp_servers.is_empty()
            && self.provider.is_none()
            && self.adapters.is_empty()
            && !self.plan
    }

    /// Resolve against the current configuration. An MCP server pins its
    /// entry's current verified digest; an unsigned entry is refused.
    pub fn resolve(&self, data_dir: &std::path::Path) -> Result<Vec<Destination>> {
        let mut out: Vec<Destination> = self
            .hosts
            .iter()
            .map(|h| super::credential::normalize_host(h).map(Destination::Host))
            .collect::<Result<_>>()?;
        if !self.mcp_servers.is_empty() {
            let entries = wirken_mcp_proxy::server_entries(data_dir);
            for server in &self.mcp_servers {
                let digests = entries
                    .get(server)
                    .with_context(|| format!("no MCP server '{server}' in mcp.json"))?;
                let signed: Vec<&String> = digests.iter().flatten().collect();
                match (signed.as_slice(), digests.contains(&None)) {
                    ([digest], false) => {
                        out.push(super::destinations::mcp_server(server, digest));
                    }
                    (_, true) => bail!(
                        "MCP server '{server}' has an entry whose signature does not verify; \
                         sign it with `wirken mcp sign {server}` first"
                    ),
                    _ => bail!(
                        "MCP server '{server}' has differing entries in more than one agent's \
                         mcp.json; give them distinct names"
                    ),
                }
            }
        }
        match (&self.provider, &self.base_url) {
            (Some(provider), Some(url)) => {
                if wirken_vault::origin_of(url).is_none() {
                    bail!("--base-url must be a URL with a scheme and host");
                }
                out.push(super::destinations::provider(provider, url));
            }
            (None, None) => {}
            _ => bail!("--provider and --base-url go together"),
        }
        for adapter in &self.adapters {
            if !wirken_vault::ADAPTERS.contains(&adapter.as_str()) {
                bail!(
                    "'{adapter}' is not a channel adapter; use one of: {}",
                    wirken_vault::ADAPTERS.join(", ")
                );
            }
            out.push(Destination::Adapter(adapter.clone()));
        }
        if self.plan {
            out.push(Destination::Plan);
        }
        Ok(out)
    }
}

/// Refuse inside a Wirken `exec`, and without a terminal.
fn require_operator_terminal(command: &str) -> Result<()> {
    if std::env::var_os(wirken_agent::tool::EXEC_MARKER_ENV).is_some() {
        bail!(
            "wirken credentials {command} refuses to run inside a Wirken exec ({} is set); \
             run it yourself, from a terminal",
            wirken_agent::tool::EXEC_MARKER_ENV
        );
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!("wirken credentials {command} takes the vault passphrase at a terminal");
    }
    Ok(())
}

/// Open the vault with the passphrase typed at the terminal, never
/// `WIRKEN_VAULT_PASSPHRASE`.
fn open_at_terminal() -> Result<CredentialStore> {
    let cfg = config();
    let keychain = probe_keychain(&cfg.data_dir, || {
        dialoguer::Password::new()
            .with_prompt("  Vault passphrase")
            .interact()
            .unwrap_or_default()
    });
    CredentialStore::open(&cfg.vault_db_path(), keychain.as_ref())
        .context("Failed to open credential store")
}

fn record(log: &wirken_audit::SqliteSessionLog, events: Vec<SessionEvent>) -> Result<()> {
    let handle = log.handle_for(SessionId::new(CREDENTIALS_SESSION.to_string()));
    for event in events {
        log.append(&handle, TrustLevel::User, event)
            .context("append the credential row")?;
    }
    seal_operator_lane(log, CREDENTIALS_SESSION);
    Ok(())
}

/// Allow `name` the destinations given. Not committed when its rows
/// cannot be written.
pub fn grant(name: &str, wanted: &Destinations) -> Result<()> {
    require_operator_terminal("grant")?;
    if wanted.is_empty() {
        bail!(
            "name at least one destination: --host, --mcp-server, --provider, --adapter or --plan"
        );
    }
    let cfg = config();
    let destinations = wanted.resolve(&cfg.data_dir)?;
    let store = open_at_terminal()?;
    let before = store
        .peek(name)
        .with_context(|| format!("credential '{name}' not found"))?
        .1
        .binding;
    let mut added = Vec::new();
    let after = store.update_binding_exclusive(name, WRITE_WAIT, |current| {
        let mut next = current.clone();
        for d in &destinations {
            if next.grant(d.clone()) {
                added.push(d.clone());
            }
        }
        (next != *current).then_some(next)
    })?;
    if added.is_empty() {
        println!("  '{name}' already allows every destination given.");
        return Ok(());
    }
    let operator = local_operator();
    let rows = added
        .iter()
        .map(|d| SessionEvent::CredentialDestinationGranted {
            credential: name.to_string(),
            destination_kind: d.kind().to_string(),
            destination: d.describe(),
            granted_by: operator.clone(),
        })
        .collect();
    if let Err(e) = open_signed_session_log(&cfg).and_then(|log| record(&log, rows)) {
        store
            .update_binding_exclusive(name, WRITE_WAIT, |_| Some(before.clone()))
            .context("put the binding back after its row could not be written")?;
        return Err(e.context("the grant's audit row could not be written; nothing changed"));
    }
    for d in &added {
        println!("  '{name}' may now go to {} ({}).", d.describe(), d.kind());
    }
    print_binding(&after);
    Ok(())
}

/// Remove the destinations given from `name`. Stands even if its rows
/// cannot be written.
pub fn revoke(name: &str, wanted: &Destinations) -> Result<()> {
    require_operator_terminal("revoke")?;
    if wanted.is_empty() {
        bail!(
            "name at least one destination: --host, --mcp-server, --provider, --adapter or --plan"
        );
    }
    let cfg = config();
    let mut destinations: Vec<Destination> = wanted
        .hosts
        .iter()
        .cloned()
        .map(Destination::Host)
        .collect();
    destinations.extend(
        wanted
            .mcp_servers
            .iter()
            .map(|s| super::destinations::mcp_server(s, "")),
    );
    if let (Some(p), Some(u)) = (&wanted.provider, &wanted.base_url) {
        destinations.push(super::destinations::provider(p, u));
    }
    destinations.extend(wanted.adapters.iter().cloned().map(Destination::Adapter));
    if wanted.plan {
        destinations.push(Destination::Plan);
    }
    let store = open_at_terminal()?;
    let mut removed = Vec::new();
    let after = store.update_binding_exclusive(name, WRITE_WAIT, |current| {
        let mut next = current.clone();
        for d in &destinations {
            if next.revoke(d) {
                removed.push(d.clone());
            }
        }
        (next != *current).then_some(next)
    })?;
    if removed.is_empty() {
        println!("  '{name}' allowed none of the destinations given.");
        return Ok(());
    }
    let operator = local_operator();
    let rows = removed
        .iter()
        .map(|d| SessionEvent::CredentialDestinationRevoked {
            credential: name.to_string(),
            destination_kind: d.kind().to_string(),
            destination: d.describe(),
            revoked_by: operator.clone(),
        })
        .collect();
    if let Err(e) = open_signed_session_log(&cfg).and_then(|log| record(&log, rows)) {
        eprintln!(
            "  The revoke stands, but its {CREDENTIALS_SESSION} row could not be written: {e:#}"
        );
    }
    for d in &removed {
        println!(
            "  '{name}' may no longer go to {} ({}).",
            d.describe(),
            d.kind()
        );
    }
    print_binding(&after);
    println!("  A running gateway hands it out as before until it restarts.");
    Ok(())
}

/// Print where a credential may go.
/// The destinations, one line for an audit row: `host x, adapter y`.
pub fn binding_summary(binding: &wirken_vault::Binding) -> String {
    let destinations = binding.destinations();
    if destinations.is_empty() {
        return "no destinations".to_string();
    }
    destinations
        .iter()
        .map(|d| format!("{} {}", d.kind(), d.describe()))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn print_binding(binding: &wirken_vault::Binding) {
    let destinations = binding.destinations();
    if destinations.is_empty() {
        println!("    destinations:   (none; it is handed to nothing)");
        return;
    }
    println!("    destinations:");
    for d in destinations {
        println!("      {:10}  {}", d.kind(), d.describe());
    }
}

/// After `server`'s entry is signed again, offer to move the credentials
/// pinned to its previous entry onto the signed one. Only credentials
/// already pinned to `server` move.
pub fn offer_repin(server: &str, names: &[String]) {
    let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin())
        && std::env::var_os(wirken_agent::tool::EXEC_MARKER_ENV).is_none();
    let hint = format!(
        "  Credentials pinned to the previous '{server}' entry go nowhere until re-granted: \
         `wirken credentials grant <name> --mcp-server {server}` for {}.",
        names.join(", ")
    );
    if !interactive {
        println!("{hint}");
        return;
    }
    let ask = dialoguer::Confirm::new()
        .with_prompt(format!(
            "  Move the credentials pinned to '{server}' ({}) onto the signed entry?",
            names.join(", ")
        ))
        .default(false)
        .interact()
        .unwrap_or(false);
    if !ask {
        println!("{hint}");
        return;
    }
    let cfg = config();
    let destination = match (Destinations {
        mcp_servers: vec![server.to_string()],
        ..Destinations::default()
    })
    .resolve(&cfg.data_dir)
    {
        Ok(mut d) if d.len() == 1 => d.remove(0),
        Ok(_) => return,
        Err(e) => {
            println!("  {e:#}");
            return;
        }
    };
    let store = match open_at_terminal() {
        Ok(s) => s,
        Err(e) => {
            println!("  {e:#}");
            return;
        }
    };
    for name in names {
        let moved = store.update_binding_exclusive(name, WRITE_WAIT, |b| {
            if !b.mcp_servers.iter().any(|s| s.name == server) || b.permits(&destination) {
                return None;
            }
            let mut b = b.clone();
            b.grant(destination.clone());
            Some(b)
        });
        match moved {
            Ok(b) if b.permits(&destination) => {
                let row = SessionEvent::CredentialDestinationGranted {
                    credential: name.clone(),
                    destination_kind: destination.kind().to_string(),
                    destination: destination.describe(),
                    granted_by: local_operator(),
                };
                if let Err(e) =
                    open_signed_session_log(&cfg).and_then(|log| record(&log, vec![row]))
                {
                    eprintln!("  '{name}' moved, but its row could not be written: {e:#}");
                }
                println!("  '{name}' may go to the signed '{server}' entry.");
            }
            Ok(_) => {}
            Err(e) => println!("  '{name}': {e}"),
        }
    }
}

/// Record that `name` was allowed `destination`, on the credentials lane.
pub fn record_granted(name: &str, destination: &Destination) -> Result<()> {
    let row = SessionEvent::CredentialDestinationGranted {
        credential: name.to_string(),
        destination_kind: destination.kind().to_string(),
        destination: destination.describe(),
        granted_by: local_operator(),
    };
    open_signed_session_log(&config()).and_then(|log| record(&log, vec![row]))
}
