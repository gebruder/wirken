use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::error::GatewayError;

/// A registered adapter's metadata.
#[derive(Debug, Clone)]
pub struct AdapterEntry {
    /// Adapter identifier (e.g., "telegram", "discord").
    pub adapter_id: String,
    /// Ed25519 public key (32 bytes).
    pub public_key: [u8; 32],
    /// Channel this adapter serves.
    pub channel: String,
    /// Whether this adapter is currently connected.
    pub connected: bool,
}

/// Registry of known adapters and their public keys.
/// Backed by SQLite for persistence, with an in-memory cache.
pub struct AdapterRegistry {
    conn: Connection,
    cache: Arc<RwLock<HashMap<String, AdapterEntry>>>,
}

impl AdapterRegistry {
    /// Open or create the adapter registry.
    pub fn open(db_path: &Path) -> Result<Self, GatewayError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS adapters (
                 adapter_id TEXT PRIMARY KEY,
                 public_key BLOB NOT NULL,
                 channel TEXT NOT NULL
             );",
        )?;

        let mut cache = HashMap::new();
        {
            let mut stmt = conn.prepare("SELECT adapter_id, public_key, channel FROM adapters")?;
            let rows = stmt.query_map([], |row| {
                let id: String = row.get(0)?;
                let pk_blob: Vec<u8> = row.get(1)?;
                let channel: String = row.get(2)?;
                Ok((id, pk_blob, channel))
            })?;

            for row in rows {
                let (id, pk_blob, channel) = row?;
                let mut pk = [0u8; 32];
                if pk_blob.len() == 32 {
                    pk.copy_from_slice(&pk_blob);
                }
                cache.insert(
                    id.clone(),
                    AdapterEntry {
                        adapter_id: id,
                        public_key: pk,
                        channel,
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

    /// Register a new adapter.
    pub fn register(
        &self,
        adapter_id: &str,
        public_key: &[u8; 32],
        channel: &str,
    ) -> Result<(), GatewayError> {
        {
            let cache = self.cache.read().unwrap();
            if cache.contains_key(adapter_id) {
                return Err(GatewayError::AdapterAlreadyRegistered(
                    adapter_id.to_string(),
                ));
            }
        }

        self.conn.execute(
            "INSERT INTO adapters (adapter_id, public_key, channel) VALUES (?1, ?2, ?3)",
            params![adapter_id, &public_key[..], channel],
        )?;

        let entry = AdapterEntry {
            adapter_id: adapter_id.to_string(),
            public_key: *public_key,
            channel: channel.to_string(),
            connected: false,
        };
        self.cache
            .write()
            .unwrap()
            .insert(adapter_id.to_string(), entry);
        Ok(())
    }

    /// Unregister an adapter.
    pub fn unregister(&self, adapter_id: &str) -> Result<(), GatewayError> {
        let changes = self.conn.execute(
            "DELETE FROM adapters WHERE adapter_id = ?1",
            params![adapter_id],
        )?;

        if changes == 0 {
            return Err(GatewayError::AdapterNotRegistered(adapter_id.to_string()));
        }

        self.cache.write().unwrap().remove(adapter_id);
        Ok(())
    }

    /// Look up an adapter by ID.
    pub fn get(&self, adapter_id: &str) -> Option<AdapterEntry> {
        self.cache.read().unwrap().get(adapter_id).cloned()
    }

    /// Verify an adapter's identity during handshake.
    /// Returns Ok(()) if the adapter is registered and the public key matches.
    pub fn verify(
        &self,
        adapter_id: &str,
        public_key: &[u8; 32],
    ) -> Result<(), wirken_ipc::HandshakeError> {
        let cache = self.cache.read().unwrap();
        match cache.get(adapter_id) {
            None => Err(wirken_ipc::HandshakeError::UnknownAdapter(
                adapter_id.to_string(),
            )),
            Some(entry) => {
                if &entry.public_key == public_key {
                    Ok(())
                } else {
                    Err(wirken_ipc::HandshakeError::InvalidSignature)
                }
            }
        }
    }

    /// Mark an adapter as connected/disconnected.
    pub fn set_connected(&self, adapter_id: &str, connected: bool) {
        if let Some(entry) = self.cache.write().unwrap().get_mut(adapter_id) {
            entry.connected = connected;
        }
    }

    /// List all registered adapters.
    pub fn list(&self) -> Vec<AdapterEntry> {
        self.cache.read().unwrap().values().cloned().collect()
    }
}
