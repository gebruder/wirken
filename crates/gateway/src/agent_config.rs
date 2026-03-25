use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::GatewayError;

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

        Ok(Self { conn })
    }

    /// Register a new agent.
    pub fn register(&self, config: &AgentConfig) -> Result<(), GatewayError> {
        self.conn.execute(
            "INSERT INTO agents (id, name, provider, model, base_url, api_key_credential)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                config.id,
                config.name,
                config.provider,
                config.model,
                config.base_url,
                config.api_key_credential,
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
                "SELECT id, name, provider, model, base_url, api_key_credential
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
                    ))
                },
            )
            .map_err(|_| GatewayError::Config(format!("agent '{agent_id}' not found")))?;

        let channels = self.get_channels(agent_id)?;

        Ok(AgentConfig {
            id: row.0,
            name: row.1,
            provider: row.2,
            model: row.3,
            base_url: row.4,
            api_key_credential: row.5,
            channels,
        })
    }

    /// List all agent configs.
    pub fn list(&self) -> Result<Vec<AgentConfig>, GatewayError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, provider, model, base_url, api_key_credential FROM agents ORDER BY id",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;

        let mut agents = Vec::new();
        for row in rows {
            let (id, name, provider, model, base_url, api_key_credential) = row?;
            let channels = self.get_channels(&id)?;
            agents.push(AgentConfig {
                id,
                name,
                provider,
                model,
                base_url,
                api_key_credential,
                channels,
            });
        }

        Ok(agents)
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
                })
                .unwrap();
        }

        let store = AgentConfigStore::open(&path).unwrap();
        let got = store.get("persist").unwrap();
        assert_eq!(got.channels, vec!["discord"]);
    }
}
