//! Changes another process makes, taken up by the running gateway.
//!
//! Every two seconds the gateway compares what it trusts with what is on
//! disk: each vault entry's sealed value and binding, the adapter
//! registry and the hook registry. A changed credential is read again
//! where it is used: a model key is already read per call, an adapter
//! is respawned, and the MCP proxy is told. An adapter or hook removed
//! or re-keyed loses its connection. Each change is one
//! `authority_reloaded` row naming what changed and what took it up.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, broadcast};
use wirken_audit::{LIVE_RELOAD_SESSION, SessionEvent, SessionId, SessionLog, TrustLevel};
use wirken_gateway::adapter_registry::AdapterRegistry;
use wirken_gateway::hook_registry::HookRegistry;
use wirken_vault::{CredentialStore, EntryFingerprint};

use super::run::{AdapterLifeline, LifelineOrder};

/// How often the gateway looks.
pub(crate) const POLL: Duration = Duration::from_secs(2);

/// A connection the registry no longer admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Revoked {
    Adapter(String),
    Hook(String),
}

/// Tells live connections that the registry no longer admits them.
pub(crate) struct Revocations {
    tx: broadcast::Sender<Revoked>,
}

impl Default for Revocations {
    fn default() -> Self {
        Self {
            tx: broadcast::channel(64).0,
        }
    }
}

impl Revocations {
    pub(crate) fn revoke(&self, who: Revoked) {
        let _ = self.tx.send(who);
    }

    /// Taken before the connection checks the registry, so a revocation
    /// that lands between the check and the wait is not missed.
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Revoked> {
        self.tx.subscribe()
    }
}

/// Resolves when `who` is revoked. Missed notices end the connection
/// too: it is the side that fails closed, and an adapter the gateway
/// runs is respawned.
pub(crate) async fn until_revoked(mut rx: broadcast::Receiver<Revoked>, who: Revoked) {
    loop {
        match rx.recv().await {
            Ok(r) if r == who => return,
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => return,
            Err(broadcast::error::RecvError::Closed) => std::future::pending().await,
        }
    }
}

/// What the live reload acts on.
pub(crate) struct LiveReload {
    pub vault_db: PathBuf,
    pub adapters: Arc<Mutex<AdapterRegistry>>,
    pub hooks: Arc<Mutex<HookRegistry>>,
    pub veto: Arc<wirken_gateway::hook_dispatcher::HookDispatcher>,
    pub egress: Arc<wirken_gateway::egress_dispatcher::EgressDispatcher>,
    pub lifelines: Arc<HashMap<String, Arc<AdapterLifeline>>>,
    pub revocations: Arc<Revocations>,
    pub mcp: Option<Arc<wirken_mcp_proxy::refresh_service::RefreshService>>,
    /// Model keys by vault entry, each with what it feeds.
    pub provider_keys: HashMap<String, Vec<String>>,
    pub log: Arc<dyn SessionLog>,
}

impl LiveReload {
    /// Look every [`POLL`] until the task is dropped.
    pub(crate) async fn run(self) {
        let mut seen = self.fingerprints().unwrap_or_default();
        loop {
            tokio::time::sleep(POLL).await;
            // The registries first: an adapter removed with its
            // credentials is stopped, not respawned for them.
            self.reload_adapters().await;
            self.reload_hooks().await;
            if let Some(now) = self.fingerprints() {
                for (name, change) in changes(&seen, &now) {
                    self.credential_changed(&name, change).await;
                }
                seen = now;
            }
        }
    }

    fn fingerprints(&self) -> Option<BTreeMap<String, EntryFingerprint>> {
        match CredentialStore::fingerprints(&self.vault_db) {
            Ok(f) => Some(f),
            Err(e) => {
                tracing::warn!("could not read the vault to look for changes: {e}");
                None
            }
        }
    }

    /// Pass a changed credential to everything here that holds or reads
    /// it.
    async fn credential_changed(&self, name: &str, change: &str) {
        let mut reloaded: Vec<String> = self
            .provider_keys
            .get(name)
            .map(|users| {
                users
                    .iter()
                    .map(|u| format!("{u}: read per call"))
                    .collect()
            })
            .unwrap_or_default();
        let registered = self.adapters.lock().await.list();
        for (adapter_id, lifeline) in self.lifelines.iter() {
            if registered.iter().any(|a| &a.adapter_id == adapter_id)
                && super::adapter_handoff::credential_names(adapter_id)
                    .iter()
                    .any(|n| n == name)
            {
                lifeline.order(LifelineOrder::Respawn);
                reloaded.push(format!("adapter {adapter_id}: respawned"));
            }
        }
        if let Some(mcp) = &self.mcp
            && mcp.notify_changed(name)
        {
            reloaded.push("mcp proxy: sent again or withdrawn".to_string());
        }
        if reloaded.is_empty() {
            return;
        }
        tracing::info!(
            credential = name,
            change,
            ?reloaded,
            "credential changed in the vault"
        );
        self.record("credential", name, change, reloaded);
    }

    async fn reload_adapters(&self) {
        let revoked = match self.adapters.lock().await.reload() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("could not read the adapter registry: {e}");
                return;
            }
        };
        let now = self.adapters.lock().await;
        for adapter_id in revoked {
            let change = if now.get(&adapter_id).is_some() {
                "rekeyed"
            } else {
                "removed"
            };
            let mut reloaded = vec!["connection dropped".to_string()];
            if let Some(lifeline) = self.lifelines.get(&adapter_id) {
                if change == "removed" {
                    lifeline.order(LifelineOrder::Stop);
                    reloaded.push("process stopped".to_string());
                } else {
                    lifeline.order(LifelineOrder::Respawn);
                    reloaded.push("respawned".to_string());
                }
            }
            self.revocations
                .revoke(Revoked::Adapter(adapter_id.clone()));
            tracing::warn!(adapter_id, change, "adapter changed in the registry");
            self.record("adapter", &adapter_id, change, reloaded);
        }
    }

    async fn reload_hooks(&self) {
        let (revoked, registered) = {
            let registry = self.hooks.lock().await;
            match registry.reload() {
                Ok(r) => (r, registry.list()),
                Err(e) => {
                    tracing::warn!("could not read the hook registry: {e}");
                    return;
                }
            }
        };
        if revoked.is_empty() {
            return;
        }
        // Waited for only while registered, before the connection goes.
        let of = |ty: wirken_ipc::HookType| {
            registered
                .iter()
                .filter(|e| e.hook_type == ty)
                .map(|e| e.hook_id.clone())
                .collect::<Vec<_>>()
        };
        self.veto.expect(of(wirken_ipc::HookType::Veto)).await;
        self.egress.expect(of(wirken_ipc::HookType::Egress)).await;
        let still: BTreeSet<&str> = registered.iter().map(|e| e.hook_id.as_str()).collect();
        for hook_id in revoked {
            let change = if still.contains(hook_id.as_str()) {
                "rekeyed"
            } else {
                "removed"
            };
            self.revocations.revoke(Revoked::Hook(hook_id.clone()));
            tracing::warn!(hook_id, change, "hook changed in the registry");
            self.record(
                "hook",
                &hook_id,
                change,
                vec!["connection dropped".to_string()],
            );
        }
    }

    fn record(&self, subject_kind: &str, subject: &str, change: &str, reloaded: Vec<String>) {
        let lane = self
            .log
            .handle_for(SessionId::new(LIVE_RELOAD_SESSION.to_string()));
        let event = SessionEvent::AuthorityReloaded {
            subject_kind: subject_kind.to_string(),
            subject: subject.to_string(),
            change: change.to_string(),
            reloaded,
        };
        if let Err(e) = self.log.append(&lane, TrustLevel::System, event) {
            tracing::error!("could not record a live reload of {subject_kind} {subject}: {e}");
        }
    }
}

/// What changed between two looks, by entry: `rotated`, `rebound`,
/// `removed`, or `added` for an entry that was not there before, such as
/// one removed and stored again.
fn changes(
    before: &BTreeMap<String, EntryFingerprint>,
    after: &BTreeMap<String, EntryFingerprint>,
) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = before
        .iter()
        .filter_map(|(name, old)| match after.get(name) {
            None => Some((name.clone(), "removed")),
            Some(new) if new.binding != old.binding => Some((name.clone(), "rebound")),
            Some(new) if new.value != old.value => Some((name.clone(), "rotated")),
            Some(_) => None,
        })
        .collect();
    out.extend(
        after
            .keys()
            .filter(|name| !before.contains_key(*name))
            .map(|name| (name.clone(), "added")),
    );
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn print(value: u8, binding: u8) -> EntryFingerprint {
        EntryFingerprint {
            value: [value; 32],
            binding: [binding; 32],
        }
    }

    #[test]
    fn a_rotation_a_rebinding_a_removal_and_an_addition_are_told_apart() {
        let before = BTreeMap::from([
            ("same".to_string(), print(1, 1)),
            ("rotated".to_string(), print(1, 1)),
            ("rebound".to_string(), print(1, 1)),
            ("removed".to_string(), print(1, 1)),
        ]);
        let after = BTreeMap::from([
            ("same".to_string(), print(1, 1)),
            ("rotated".to_string(), print(2, 1)),
            ("rebound".to_string(), print(2, 2)),
            ("added".to_string(), print(1, 1)),
        ]);
        assert_eq!(
            changes(&before, &after),
            vec![
                ("added".to_string(), "added"),
                ("rebound".to_string(), "rebound"),
                ("removed".to_string(), "removed"),
                ("rotated".to_string(), "rotated"),
            ]
        );
    }

    #[tokio::test]
    async fn a_connection_ends_on_its_own_revocation_only() {
        let revocations = Revocations::default();
        let rx = revocations.subscribe();
        let wait = tokio::spawn(until_revoked(rx, Revoked::Adapter("slack".into())));
        revocations.revoke(Revoked::Adapter("signal".into()));
        revocations.revoke(Revoked::Hook("slack".into()));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!wait.is_finished(), "another's revocation leaves it be");
        revocations.revoke(Revoked::Adapter("slack".into()));
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .expect("its own revocation ends it")
            .unwrap();
    }
}
