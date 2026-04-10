use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use crate::error::GatewayError;
use crate::permissions::PermissionTier;

/// Per-child ceiling for [`AgentConfig::allowed_subagents`]. Item 6
/// slice 1 of `docs/managed-agents-parity.md`. The parent harness
/// uses these caps to clamp anything the LLM passes to
/// `spawn_subagent` — the LLM cannot widen the child's tools or
/// permission tier, only narrow within the ceiling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubagentCeiling {
    /// Hard tool allowlist. Tools the parent's LLM passes are
    /// intersected with this list; anything outside is silently
    /// dropped (and logged at debug level).
    pub tool_allowlist: Vec<String>,
    /// Hard permission tier cap. Any tool inside the child whose
    /// action exceeds this tier is auto-denied at the child's
    /// session level — children run headless, no interactive
    /// approvals.
    pub max_permission_tier: PermissionTier,
    /// Maximum number of LLM rounds the child may run before the
    /// parent gives up and reports `status: "rounds_exceeded"`.
    pub max_rounds: usize,
    /// Wall-clock timeout for the entire child invocation. On
    /// elapse the parent reports `status: "timeout"` and the child's
    /// session log is preserved for offline inspection.
    pub max_runtime_secs: u64,
}

/// Persistent configuration for a registered agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Unique agent identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// LLM provider (openai, anthropic, ollama, custom).
    pub provider: String,
    /// Model ID.
    pub model: String,
    /// API base URL.
    pub base_url: String,
    /// Vault credential name for the API key (empty for ollama).
    pub api_key_credential: String,
    /// Channels bound to this agent (wildcard routing).
    pub channels: Vec<String>,
    /// Item 6 slice 1: child agents this agent is allowed to spawn
    /// via the built-in `spawn_subagent` tool, keyed by child agent
    /// id, with a per-child capability ceiling. Empty by default —
    /// when empty, the harness omits the `spawn_subagent` tool from
    /// the LLM's tool list entirely.
    #[serde(default)]
    pub allowed_subagents: BTreeMap<String, SubagentCeiling>,
    /// Item 6 slice 2: per-agent override for `LlmConfig.tools_enabled`.
    /// `Some(true)` forces tools on (useful for ollama models that
    /// support tool calling). `Some(false)` forces off. `None` uses
    /// the provider default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools_enabled: Option<bool>,
}

/// Persistent registry of agent configurations.
pub struct AgentConfigStore {
    conn: Connection,
}

impl AgentConfigStore {
    pub fn open(db_path: &Path) -> Result<Self, GatewayError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS agents (
                 id TEXT PRIMARY KEY,
                 name TEXT NOT NULL,
                 provider TEXT NOT NULL,
                 model TEXT NOT NULL,
                 base_url TEXT NOT NULL,
                 api_key_credential TEXT NOT NULL DEFAULT ''
             );
             CREATE TABLE IF NOT EXISTS agent_channels (
                 agent_id TEXT NOT NULL,
                 channel TEXT NOT NULL,
                 PRIMARY KEY (agent_id, channel),
                 FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
             );",
        )?;

        // Item 6 slice 1: additive migration for the
        // `allowed_subagents` JSON column. SQLite has no IF NOT
        // EXISTS for ALTER TABLE; ignore the duplicate-column error
        // when the column is already present.
        if let Err(e) = conn.execute(
            "ALTER TABLE agents ADD COLUMN allowed_subagents TEXT NOT NULL DEFAULT '{}'",
            [],
        ) && !e.to_string().contains("duplicate column")
        {
            return Err(e.into());
        }

        // Item 6 slice 2: additive migration for the per-agent
        // tools_enabled override.
        if let Err(e) = conn.execute(
            "ALTER TABLE agents ADD COLUMN tools_enabled TEXT DEFAULT NULL",
            [],
        ) && !e.to_string().contains("duplicate column")
        {
            return Err(e.into());
        }

        Ok(Self { conn })
    }

    /// Register a new agent.
    pub fn register(&self, config: &AgentConfig) -> Result<(), GatewayError> {
        let allowed_subagents_json = serde_json::to_string(&config.allowed_subagents)
            .map_err(|e| GatewayError::Config(format!("serialize allowed_subagents: {e}")))?;
        let tools_enabled_str = config
            .tools_enabled
            .map(|b| if b { "true" } else { "false" });
        self.conn.execute(
            "INSERT INTO agents (id, name, provider, model, base_url, api_key_credential, allowed_subagents, tools_enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                config.id,
                config.name,
                config.provider,
                config.model,
                config.base_url,
                config.api_key_credential,
                allowed_subagents_json,
                tools_enabled_str,
            ],
        )?;

        for channel in &config.channels {
            self.conn.execute(
                "INSERT OR REPLACE INTO agent_channels (agent_id, channel) VALUES (?1, ?2)",
                params![config.id, channel],
            )?;
        }

        Ok(())
    }

    /// Remove an agent and its channel bindings.
    pub fn remove(&self, agent_id: &str) -> Result<(), GatewayError> {
        let changes = self
            .conn
            .execute("DELETE FROM agents WHERE id = ?1", params![agent_id])?;
        if changes == 0 {
            return Err(GatewayError::Config(format!(
                "agent '{agent_id}' not found"
            )));
        }
        self.conn.execute(
            "DELETE FROM agent_channels WHERE agent_id = ?1",
            params![agent_id],
        )?;
        Ok(())
    }

    /// Bind a channel to an agent. Unbinds it from any other agent first.
    pub fn bind_channel(&self, agent_id: &str, channel: &str) -> Result<(), GatewayError> {
        // Remove from any existing agent
        self.conn.execute(
            "DELETE FROM agent_channels WHERE channel = ?1",
            params![channel],
        )?;
        self.conn.execute(
            "INSERT INTO agent_channels (agent_id, channel) VALUES (?1, ?2)",
            params![agent_id, channel],
        )?;
        Ok(())
    }

    /// Unbind a channel from its agent.
    pub fn unbind_channel(&self, channel: &str) -> Result<(), GatewayError> {
        self.conn.execute(
            "DELETE FROM agent_channels WHERE channel = ?1",
            params![channel],
        )?;
        Ok(())
    }

    /// Get a single agent config.
    pub fn get(&self, agent_id: &str) -> Result<AgentConfig, GatewayError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, name, provider, model, base_url, api_key_credential, allowed_subagents, tools_enabled
                 FROM agents WHERE id = ?1",
                params![agent_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                },
            )
            .map_err(|_| GatewayError::Config(format!("agent '{agent_id}' not found")))?;

        let channels = self.get_channels(agent_id)?;
        let allowed_subagents = parse_allowed_subagents(&row.6)?;
        let tools_enabled = parse_tools_enabled(row.7.as_deref());

        Ok(AgentConfig {
            id: row.0,
            name: row.1,
            provider: row.2,
            model: row.3,
            base_url: row.4,
            api_key_credential: row.5,
            channels,
            allowed_subagents,
            tools_enabled,
        })
    }

    /// List all agent configs.
    pub fn list(&self) -> Result<Vec<AgentConfig>, GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, provider, model, base_url, api_key_credential, allowed_subagents, tools_enabled
             FROM agents ORDER BY id",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })?;

        let mut agents = Vec::new();
        for row in rows {
            let (
                id,
                name,
                provider,
                model,
                base_url,
                api_key_credential,
                allowed_subagents_json,
                tools_enabled_raw,
            ) = row?;
            let channels = self.get_channels(&id)?;
            let allowed_subagents = parse_allowed_subagents(&allowed_subagents_json)?;
            let tools_enabled = parse_tools_enabled(tools_enabled_raw.as_deref());
            agents.push(AgentConfig {
                id,
                name,
                provider,
                model,
                base_url,
                api_key_credential,
                channels,
                allowed_subagents,
                tools_enabled,
            });
        }

        Ok(agents)
    }

    /// Replace the `allowed_subagents` ceilings for an existing
    /// agent. Used by tests today; CLI plumbing for editing
    /// ceilings is slice 2 work.
    pub fn set_allowed_subagents(
        &self,
        agent_id: &str,
        allowed_subagents: &BTreeMap<String, SubagentCeiling>,
    ) -> Result<(), GatewayError> {
        let json = serde_json::to_string(allowed_subagents)
            .map_err(|e| GatewayError::Config(format!("serialize allowed_subagents: {e}")))?;
        let changes = self.conn.execute(
            "UPDATE agents SET allowed_subagents = ?1 WHERE id = ?2",
            params![json, agent_id],
        )?;
        if changes == 0 {
            return Err(GatewayError::Config(format!(
                "agent '{agent_id}' not found"
            )));
        }
        Ok(())
    }

    fn get_channels(&self, agent_id: &str) -> Result<Vec<String>, GatewayError> {
        let mut stmt = self
            .conn
            .prepare("SELECT channel FROM agent_channels WHERE agent_id = ?1 ORDER BY channel")?;
        let rows = stmt.query_map(params![agent_id], |row| row.get::<_, String>(0))?;
        let mut channels = Vec::new();
        for row in rows {
            channels.push(row?);
        }
        Ok(channels)
    }
}

/// Decode the `tools_enabled` column. NULL → None, "true" → Some(true), "false" → Some(false).
fn parse_tools_enabled(raw: Option<&str>) -> Option<bool> {
    match raw {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    }
}

/// Decode the `allowed_subagents` column. Empty / NULL / `'{}'` all
/// map to an empty map without error.
fn parse_allowed_subagents(raw: &str) -> Result<BTreeMap<String, SubagentCeiling>, GatewayError> {
    if raw.is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str(raw)
        .map_err(|e| GatewayError::Config(format!("decode allowed_subagents: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn register_and_get_agent() {
        let tmp = TempDir::new().unwrap();
        let store = AgentConfigStore::open(&tmp.path().join("agents.db")).unwrap();

        let config = AgentConfig {
            id: "work".into(),
            name: "Work Agent".into(),
            provider: "openai".into(),
            model: "gpt-4o".into(),
            base_url: "https://api.openai.com/v1".into(),
            api_key_credential: "work-openai-key".into(),
            channels: vec!["slack".into(), "teams".into()],
            allowed_subagents: Default::default(),
            tools_enabled: None,
        };

        store.register(&config).unwrap();
        let got = store.get("work").unwrap();

        assert_eq!(got.id, "work");
        assert_eq!(got.name, "Work Agent");
        assert_eq!(got.model, "gpt-4o");
        assert_eq!(got.channels, vec!["slack", "teams"]);
    }

    #[test]
    fn register_and_list_multiple() {
        let tmp = TempDir::new().unwrap();
        let store = AgentConfigStore::open(&tmp.path().join("agents.db")).unwrap();

        store
            .register(&AgentConfig {
                id: "personal".into(),
                name: "Personal".into(),
                provider: "anthropic".into(),
                model: "claude-sonnet-4-20250514".into(),
                base_url: "https://api.anthropic.com/v1".into(),
                api_key_credential: "personal-anthropic-key".into(),
                channels: vec!["telegram".into(), "discord".into()],
                allowed_subagents: Default::default(),
                tools_enabled: None,
            })
            .unwrap();

        store
            .register(&AgentConfig {
                id: "work".into(),
                name: "Work".into(),
                provider: "openai".into(),
                model: "gpt-4o".into(),
                base_url: "https://api.openai.com/v1".into(),
                api_key_credential: "work-openai-key".into(),
                channels: vec!["slack".into()],
                allowed_subagents: Default::default(),
                tools_enabled: None,
            })
            .unwrap();

        let agents = store.list().unwrap();
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].id, "personal");
        assert_eq!(agents[1].id, "work");
    }

    #[test]
    fn remove_agent() {
        let tmp = TempDir::new().unwrap();
        let store = AgentConfigStore::open(&tmp.path().join("agents.db")).unwrap();

        store
            .register(&AgentConfig {
                id: "temp".into(),
                name: "Temp".into(),
                provider: "ollama".into(),
                model: "llama3".into(),
                base_url: "http://localhost:11434/v1".into(),
                api_key_credential: String::new(),
                channels: vec!["telegram".into()],
                allowed_subagents: Default::default(),
                tools_enabled: None,
            })
            .unwrap();

        store.remove("temp").unwrap();
        assert!(store.get("temp").is_err());
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn bind_channel_moves_between_agents() {
        let tmp = TempDir::new().unwrap();
        let store = AgentConfigStore::open(&tmp.path().join("agents.db")).unwrap();

        store
            .register(&AgentConfig {
                id: "a".into(),
                name: "A".into(),
                provider: "ollama".into(),
                model: "m".into(),
                base_url: "u".into(),
                api_key_credential: String::new(),
                channels: vec!["telegram".into()],
                allowed_subagents: Default::default(),
                tools_enabled: None,
            })
            .unwrap();
        store
            .register(&AgentConfig {
                id: "b".into(),
                name: "B".into(),
                provider: "ollama".into(),
                model: "m".into(),
                base_url: "u".into(),
                api_key_credential: String::new(),
                channels: vec![],
                allowed_subagents: Default::default(),
                tools_enabled: None,
            })
            .unwrap();

        // Move telegram from agent A to agent B
        store.bind_channel("b", "telegram").unwrap();

        let a = store.get("a").unwrap();
        let b = store.get("b").unwrap();
        assert!(a.channels.is_empty());
        assert_eq!(b.channels, vec!["telegram"]);
    }

    #[test]
    fn persists_across_opens() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("agents.db");

        {
            let store = AgentConfigStore::open(&path).unwrap();
            store
                .register(&AgentConfig {
                    id: "persist".into(),
                    name: "P".into(),
                    provider: "ollama".into(),
                    model: "m".into(),
                    base_url: "u".into(),
                    api_key_credential: String::new(),
                    channels: vec!["discord".into()],
                    allowed_subagents: Default::default(),
                    tools_enabled: None,
                })
                .unwrap();
        }

        let store = AgentConfigStore::open(&path).unwrap();
        let got = store.get("persist").unwrap();
        assert_eq!(got.channels, vec!["discord"]);
    }

    // Item 6 slice 1: allowed_subagents column / round-trip.

    #[test]
    fn allowed_subagents_round_trip_through_store() {
        let tmp = TempDir::new().unwrap();
        let store = AgentConfigStore::open(&tmp.path().join("agents.db")).unwrap();

        let mut ceilings = BTreeMap::new();
        ceilings.insert(
            "researcher".to_string(),
            SubagentCeiling {
                tool_allowlist: vec!["read_file".into(), "web_search".into()],
                max_permission_tier: PermissionTier::Tier2,
                max_rounds: 8,
                max_runtime_secs: 60,
            },
        );
        let cfg = AgentConfig {
            id: "boss".into(),
            name: "Boss".into(),
            provider: "openai".into(),
            model: "gpt-4o".into(),
            base_url: "https://api.openai.com/v1".into(),
            api_key_credential: "boss-key".into(),
            channels: vec!["slack".into()],
            allowed_subagents: ceilings,
            tools_enabled: None,
        };
        store.register(&cfg).unwrap();

        let got = store.get("boss").unwrap();
        assert_eq!(got.allowed_subagents.len(), 1);
        let r = got.allowed_subagents.get("researcher").unwrap();
        assert_eq!(r.tool_allowlist, vec!["read_file", "web_search"]);
        assert_eq!(r.max_permission_tier, PermissionTier::Tier2);
        assert_eq!(r.max_rounds, 8);
        assert_eq!(r.max_runtime_secs, 60);
    }

    #[test]
    fn allowed_subagents_default_empty_for_legacy_rows() {
        // A pre-item-6 row written before the migration column was
        // added; the additive ALTER preserves it with the default
        // empty JSON.
        let tmp = TempDir::new().unwrap();
        let store = AgentConfigStore::open(&tmp.path().join("agents.db")).unwrap();
        store
            .register(&AgentConfig {
                id: "legacy".into(),
                name: "Legacy".into(),
                provider: "ollama".into(),
                model: "m".into(),
                base_url: "u".into(),
                api_key_credential: String::new(),
                channels: vec![],
                allowed_subagents: Default::default(),
                tools_enabled: None,
            })
            .unwrap();
        let got = store.get("legacy").unwrap();
        assert!(got.allowed_subagents.is_empty());
    }

    #[test]
    fn set_allowed_subagents_replaces_existing() {
        let tmp = TempDir::new().unwrap();
        let store = AgentConfigStore::open(&tmp.path().join("agents.db")).unwrap();
        store
            .register(&AgentConfig {
                id: "boss".into(),
                name: "Boss".into(),
                provider: "ollama".into(),
                model: "m".into(),
                base_url: "u".into(),
                api_key_credential: String::new(),
                channels: vec![],
                allowed_subagents: Default::default(),
                tools_enabled: None,
            })
            .unwrap();
        let mut ceilings = BTreeMap::new();
        ceilings.insert(
            "child".into(),
            SubagentCeiling {
                tool_allowlist: vec!["read_file".into()],
                max_permission_tier: PermissionTier::Tier1,
                max_rounds: 3,
                max_runtime_secs: 10,
            },
        );
        store.set_allowed_subagents("boss", &ceilings).unwrap();
        let got = store.get("boss").unwrap();
        assert_eq!(got.allowed_subagents.len(), 1);
        assert!(got.allowed_subagents.contains_key("child"));
    }
}
