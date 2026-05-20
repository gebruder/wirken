//! Hook registry. SQLite-backed `(hook_id, public_key, hook_type)`
//! table that authenticates inbound hook connections, mirroring
//! `adapter_registry.rs`.
//!
//! Trust model: the hook process holds an Ed25519 keypair, presents
//! its public key during the `wirken-ipc-hook-handshake-v1`
//! handshake, and the gateway looks the pubkey up in this table to
//! decide accept/reject. Hook binaries are not read by the gateway;
//! the registered public key is the entire trust artifact.
//!
//! `WIRKEN_ALLOW_UNREGISTERED_HOOKS=1` is the dev-mode escape
//! hatch wired at the accept-loop layer, not here. This module
//! always refuses an unregistered hook.

use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use wirken_ipc::HookType;

use crate::error::GatewayError;

/// A registered hook's metadata.
#[derive(Debug, Clone)]
pub struct HookEntry {
    pub hook_id: String,
    pub public_key: [u8; 32],
    pub hook_type: HookType,
    pub connected: bool,
}

/// Registry of known hooks and their public keys. SQLite-backed with
/// an in-memory cache.
pub struct HookRegistry {
    conn: Connection,
    cache: Arc<RwLock<HashMap<String, HookEntry>>>,
}

impl HookRegistry {
    /// Open or create the hook registry at `db_path`.
    pub fn open(db_path: &Path) -> Result<Self, GatewayError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS hooks (
                 hook_id TEXT PRIMARY KEY,
                 public_key BLOB NOT NULL,
                 hook_type TEXT NOT NULL
             );",
        )?;

        let mut cache = HashMap::new();
        {
            let mut stmt = conn.prepare("SELECT hook_id, public_key, hook_type FROM hooks")?;
            let rows = stmt.query_map([], |row| {
                let id: String = row.get(0)?;
                let pk_blob: Vec<u8> = row.get(1)?;
                let ty: String = row.get(2)?;
                Ok((id, pk_blob, ty))
            })?;
            for row in rows {
                let (id, pk_blob, ty_str) = row?;
                if pk_blob.len() != 32 {
                    return Err(GatewayError::Config(format!(
                        "hook {id}: stored public key is not 32 bytes ({} bytes)",
                        pk_blob.len()
                    )));
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&pk_blob);
                let hook_type = match ty_str.as_str() {
                    "observe" => HookType::Observe,
                    "veto" => HookType::Veto,
                    "egress" => HookType::Egress,
                    other => {
                        return Err(GatewayError::Config(format!(
                            "hook {id}: unknown hook_type {other:?} in database"
                        )));
                    }
                };
                cache.insert(
                    id.clone(),
                    HookEntry {
                        hook_id: id,
                        public_key: pk,
                        hook_type,
                        connected: false,
                    },
                );
            }
        }

        Ok(Self {
            conn,
            cache: Arc::new(RwLock::new(cache)),
        })
    }

    pub fn register(
        &self,
        hook_id: &str,
        public_key: &[u8; 32],
        hook_type: HookType,
    ) -> Result<(), GatewayError> {
        if self.cache.read().unwrap().contains_key(hook_id) {
            return Err(GatewayError::HookAlreadyRegistered(hook_id.to_string()));
        }
        self.conn.execute(
            "INSERT INTO hooks (hook_id, public_key, hook_type) VALUES (?1, ?2, ?3)",
            params![hook_id, &public_key[..], hook_type.as_wire()],
        )?;
        let entry = HookEntry {
            hook_id: hook_id.to_string(),
            public_key: *public_key,
            hook_type,
            connected: false,
        };
        self.cache
            .write()
            .unwrap()
            .insert(hook_id.to_string(), entry);
        Ok(())
    }

    pub fn unregister(&self, hook_id: &str) -> Result<(), GatewayError> {
        let changes = self
            .conn
            .execute("DELETE FROM hooks WHERE hook_id = ?1", params![hook_id])?;
        if changes == 0 {
            return Err(GatewayError::HookNotRegistered(hook_id.to_string()));
        }
        self.cache.write().unwrap().remove(hook_id);
        Ok(())
    }

    pub fn get(&self, hook_id: &str) -> Option<HookEntry> {
        self.cache.read().unwrap().get(hook_id).cloned()
    }

    /// Verify a hook's claimed identity during handshake. Reuses
    /// `wirken_ipc::HandshakeError` variants so the gateway accept
    /// loop's verify closure can pass this through directly.
    ///
    /// Returns `Ok(())` iff `hook_id` is registered, `public_key`
    /// matches the registered key, AND the wire-claimed `hook_type`
    /// matches the registered type. A type-mismatch returns the
    /// dedicated `HookTypeMismatch` variant so an operator who
    /// re-registered a hook as observe but the process binary still
    /// presents itself as veto (or vice versa) sees a precise error.
    pub fn verify(
        &self,
        hook_id: &str,
        public_key: &[u8; 32],
        hook_type: HookType,
    ) -> Result<(), wirken_ipc::HandshakeError> {
        let cache = self.cache.read().unwrap();
        match cache.get(hook_id) {
            None => Err(wirken_ipc::HandshakeError::UnknownHook(hook_id.to_string())),
            Some(entry) => {
                if &entry.public_key != public_key {
                    return Err(wirken_ipc::HandshakeError::InvalidSignature);
                }
                if entry.hook_type != hook_type {
                    return Err(wirken_ipc::HandshakeError::HookTypeMismatch {
                        hook_id: hook_id.to_string(),
                        registered: entry.hook_type.as_wire().to_string(),
                        claimed: hook_type.as_wire().to_string(),
                    });
                }
                Ok(())
            }
        }
    }

    pub fn set_connected(&self, hook_id: &str, connected: bool) {
        if let Some(entry) = self.cache.write().unwrap().get_mut(hook_id) {
            entry.connected = connected;
        }
    }

    pub fn list(&self) -> Vec<HookEntry> {
        self.cache.read().unwrap().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh() -> (TempDir, HookRegistry) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hooks.db");
        let reg = HookRegistry::open(&path).unwrap();
        (tmp, reg)
    }

    #[test]
    fn register_then_get_round_trips() {
        let (_tmp, reg) = fresh();
        let pk = [7u8; 32];
        reg.register("policy-eval", &pk, HookType::Veto).unwrap();
        let entry = reg.get("policy-eval").unwrap();
        assert_eq!(entry.hook_id, "policy-eval");
        assert_eq!(entry.public_key, pk);
        assert_eq!(entry.hook_type, HookType::Veto);
        assert!(!entry.connected);
    }

    #[test]
    fn duplicate_registration_refuses() {
        let (_tmp, reg) = fresh();
        let pk = [1u8; 32];
        reg.register("h1", &pk, HookType::Observe).unwrap();
        let err = reg.register("h1", &pk, HookType::Observe).unwrap_err();
        assert!(matches!(err, GatewayError::HookAlreadyRegistered(_)));
    }

    #[test]
    fn unregister_then_get_returns_none() {
        let (_tmp, reg) = fresh();
        let pk = [2u8; 32];
        reg.register("h1", &pk, HookType::Veto).unwrap();
        reg.unregister("h1").unwrap();
        assert!(reg.get("h1").is_none());
    }

    #[test]
    fn unregister_unknown_returns_error() {
        let (_tmp, reg) = fresh();
        let err = reg.unregister("does-not-exist").unwrap_err();
        assert!(matches!(err, GatewayError::HookNotRegistered(_)));
    }

    #[test]
    fn verify_accepts_registered_pubkey_and_type() {
        let (_tmp, reg) = fresh();
        let pk = [3u8; 32];
        reg.register("h1", &pk, HookType::Observe).unwrap();
        reg.verify("h1", &pk, HookType::Observe).unwrap();
    }

    #[test]
    fn verify_rejects_unknown_hook() {
        let (_tmp, reg) = fresh();
        let err = reg
            .verify("unknown", &[0u8; 32], HookType::Observe)
            .unwrap_err();
        assert!(matches!(err, wirken_ipc::HandshakeError::UnknownHook(_)));
    }

    #[test]
    fn verify_rejects_mismatched_pubkey() {
        let (_tmp, reg) = fresh();
        let pk = [4u8; 32];
        reg.register("h1", &pk, HookType::Veto).unwrap();
        let err = reg.verify("h1", &[5u8; 32], HookType::Veto).unwrap_err();
        assert!(matches!(err, wirken_ipc::HandshakeError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_type_mismatch() {
        let (_tmp, reg) = fresh();
        let pk = [6u8; 32];
        reg.register("h1", &pk, HookType::Veto).unwrap();
        let err = reg.verify("h1", &pk, HookType::Observe).unwrap_err();
        match err {
            wirken_ipc::HandshakeError::HookTypeMismatch {
                hook_id,
                registered,
                claimed,
            } => {
                assert_eq!(hook_id, "h1");
                assert_eq!(registered, "veto");
                assert_eq!(claimed, "observe");
            }
            other => panic!("expected HookTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn cache_persists_across_reopen() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hooks.db");
        let pk = [9u8; 32];
        {
            let reg = HookRegistry::open(&path).unwrap();
            reg.register("h1", &pk, HookType::Veto).unwrap();
            reg.register("h2", &[10u8; 32], HookType::Observe).unwrap();
        }
        let reg = HookRegistry::open(&path).unwrap();
        let mut list = reg.list();
        list.sort_by(|a, b| a.hook_id.cmp(&b.hook_id));
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].hook_id, "h1");
        assert_eq!(list[0].hook_type, HookType::Veto);
        assert_eq!(list[1].hook_id, "h2");
        assert_eq!(list[1].hook_type, HookType::Observe);
    }
}
