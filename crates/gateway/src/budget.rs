//! Per-agent spend budgets and the durable spend ledger.
//!
//! A budget caps how much an agent may spend on LLM calls within a
//! fixed calendar window. Enforcement is opt-in: [`BudgetMode::Off`]
//! is the default, so a budget never activates on upgrade. The
//! runtime's pre-LLM-call gate reads the ledger, compares the
//! window's accumulated spend to the ceiling, and either alerts or
//! blocks. Spend is metered in USD micros (1 USD = 1_000_000), the
//! same unit as the `*_cost_usd_micros` fields on
//! `SessionEvent::LlmResponse`.
//!
//! A budget may also, or instead, cap model time: the wall-clock
//! seconds the agent's model calls took in the window, as the runtime
//! measured them. That needs nothing from the provider, so it holds
//! for a provider with no price, where the USD ceiling never moves.
//!
//! Budgets are configured in `budget.json` (a global default plus
//! per-agent overrides, [`BudgetConfig`]); the durable ledger lives in
//! `budget.db` ([`BudgetStore`]). The effective budget for an agent is
//! [`BudgetConfig::resolve`]-d from its per-agent entry and the global
//! default.

use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::error::GatewayError;

/// Enforcement posture for a budget. `Off` is the default so
/// enforcement never activates without an explicit operator opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BudgetMode {
    /// No enforcement. The gate is a no-op.
    #[default]
    Off,
    /// Emit a `BudgetExceeded` audit event when the window ceiling is
    /// crossed, once per window, but let the call proceed. The
    /// recommended starting posture.
    Alert,
    /// Refuse the call when the window ceiling is reached, emit a
    /// `BudgetExceeded` audit event, and return a visible block
    /// message. Fails closed on ledger errors.
    Block,
}

/// Fixed calendar window a budget ceiling applies over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BudgetWindow {
    Hour,
    #[default]
    Day,
    Week,
}

impl BudgetWindow {
    /// Window length in seconds.
    pub fn seconds(self) -> i64 {
        match self {
            BudgetWindow::Hour => 3_600,
            BudgetWindow::Day => 86_400,
            BudgetWindow::Week => 604_800,
        }
    }

    /// Wire label carried on the `BudgetExceeded` audit row.
    pub fn label(self) -> &'static str {
        match self {
            BudgetWindow::Hour => "hour",
            BudgetWindow::Day => "day",
            BudgetWindow::Week => "week",
        }
    }

    /// Start (unix seconds) of the fixed window containing `now_secs`.
    /// Fixed calendar bucketing: `[start, start + seconds())`.
    pub fn window_start(self, now_secs: i64) -> i64 {
        let w = self.seconds();
        (now_secs / w) * w
    }
}

/// A per-agent budget: a ceiling over a window, plus the enforcement
/// mode. Configured in `budget.json`; the effective budget is resolved
/// by [`BudgetConfig::resolve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentBudget {
    #[serde(default)]
    pub mode: BudgetMode,
    /// Window ceiling in USD micros. Ignored when `mode` is `Off`.
    /// Absent means no USD ceiling, which an active budget may be
    /// only when it sets [`Self::ceiling_model_seconds`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceiling_usd_micros: Option<u64>,
    /// Window ceiling on model time: the wall-clock seconds the
    /// agent's model calls took, failed calls included. Absent means
    /// no model-time ceiling. Ignored when `mode` is `Off`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceiling_model_seconds: Option<u64>,
    #[serde(default)]
    pub window: BudgetWindow,
}

impl AgentBudget {
    /// True when the budget enforces (alert or block).
    pub fn is_active(&self) -> bool {
        self.mode != BudgetMode::Off
    }

    /// The model-time ceiling in milliseconds, the unit the ledger
    /// keeps.
    pub fn ceiling_model_millis(&self) -> Option<u64> {
        self.ceiling_model_seconds.map(|s| s.saturating_mul(1_000))
    }

    /// An active budget has to cap something. One with neither ceiling
    /// would read as enforcement and enforce nothing.
    fn check(&self, name: &str) -> Result<(), GatewayError> {
        if self.is_active()
            && self.ceiling_usd_micros.is_none()
            && self.ceiling_model_seconds.is_none()
        {
            return Err(GatewayError::Config(format!(
                "{name} is in {} mode and sets neither ceiling_usd_micros nor \
                 ceiling_model_seconds",
                match self.mode {
                    BudgetMode::Alert => "alert",
                    _ => "block",
                }
            )));
        }
        Ok(())
    }
}

/// Resolve the effective budget from a per-agent override and a global
/// default: the override wins; with neither active, `None` (no
/// enforcement). An explicit per-agent `Off` overrides an active
/// global default, so an operator can opt a single agent out.
pub fn resolve(per_agent: Option<AgentBudget>, global: Option<AgentBudget>) -> Option<AgentBudget> {
    per_agent.or(global).filter(AgentBudget::is_active)
}

/// Budget configuration loaded from `budget.json`: an optional global
/// default plus per-agent overrides keyed by base agent id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Applied to any agent without a per-agent entry. Absent means no
    /// global default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<AgentBudget>,
    /// Per-agent overrides, keyed by base agent id.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub agents: HashMap<String, AgentBudget>,
}

impl BudgetConfig {
    /// The effective budget for `agent_id`: a per-agent override wins
    /// over the global default; an explicit per-agent `off` opts the
    /// agent out even when a global default is set.
    pub fn resolve(&self, agent_id: &str) -> Option<AgentBudget> {
        resolve(self.agents.get(agent_id).copied(), self.default)
    }

    /// Refuse an active entry that sets no ceiling, naming it.
    pub fn validate(&self) -> Result<(), GatewayError> {
        if let Some(default) = &self.default {
            default.check("the default budget")?;
        }
        let mut ids: Vec<&String> = self.agents.keys().collect();
        ids.sort();
        for id in ids {
            self.agents[id].check(&format!("the budget agents.{id}"))?;
        }
        Ok(())
    }

    /// True if any configured budget (the default or a per-agent
    /// entry) uses block mode. Used at startup: if the spend ledger
    /// cannot be opened while a block budget is configured, the
    /// gateway refuses to start rather than silently downgrade block
    /// to off.
    pub fn has_block_mode(&self) -> bool {
        self.default.is_some_and(|b| b.mode == BudgetMode::Block)
            || self.agents.values().any(|b| b.mode == BudgetMode::Block)
    }

    /// True if any configured budget (the default or a per-agent
    /// entry) enforces (alert or block).
    pub fn has_active(&self) -> bool {
        self.default.is_some_and(|b| b.is_active())
            || self.agents.values().any(AgentBudget::is_active)
    }
}

/// Load `budget.json`. An absent file yields an empty config (no
/// enforcement). A present-but-unparseable file is an error so a
/// misconfiguration surfaces loudly rather than silently disabling
/// enforcement.
pub fn load_budget_config(path: &Path) -> Result<BudgetConfig, GatewayError> {
    match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BudgetConfig::default()),
        Err(e) => Err(GatewayError::Config(format!(
            "read {}: {e}",
            path.display()
        ))),
        Ok(s) => {
            let config: BudgetConfig = serde_json::from_str(&s)
                .map_err(|e| GatewayError::Config(format!("parse {}: {e}", path.display())))?;
            config
                .validate()
                .map_err(|e| GatewayError::Config(format!("{}: {e}", path.display())))?;
            Ok(config)
        }
    }
}

/// Current wall-clock time in unix seconds. Returns 0 if the clock is
/// before the epoch (it never is in practice); a 0 window start still
/// buckets consistently.
pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Durable per-agent spend ledger, one row per `(agent_id,
/// window_start)`. Backed by its own SQLite database so budget
/// accounting survives a gateway restart.
pub struct BudgetStore {
    conn: Connection,
}

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS agent_spend (
        agent_id TEXT NOT NULL,
        window_start INTEGER NOT NULL,
        spend_micros INTEGER NOT NULL DEFAULT 0,
        alerted INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (agent_id, window_start)
    );
";

/// Columns added after the first release of the ledger: model time
/// in the window, in milliseconds, and its own once-per-window alert
/// flag.
const ADDED_COLUMNS: &[&str] = &[
    "model_millis INTEGER NOT NULL DEFAULT 0",
    "model_time_alerted INTEGER NOT NULL DEFAULT 0",
];

impl BudgetStore {
    /// Open (creating if absent) the ledger database.
    pub fn open(db_path: &Path) -> Result<Self, GatewayError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(&format!("PRAGMA journal_mode=WAL;{SCHEMA}"))?;
        Self::add_columns(&conn)?;
        Ok(Self { conn })
    }

    /// Open an in-memory ledger. Test helper; not durable.
    pub fn open_in_memory() -> Result<Self, GatewayError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Self::add_columns(&conn)?;
        Ok(Self { conn })
    }

    /// Additive migration. SQLite has no IF NOT EXISTS for ALTER
    /// TABLE, so a column already there is told from a real failure by
    /// the error text; anything else propagates.
    fn add_columns(conn: &Connection) -> Result<(), GatewayError> {
        for column in ADDED_COLUMNS {
            if let Err(e) =
                conn.execute(&format!("ALTER TABLE agent_spend ADD COLUMN {column}"), [])
                && !e.to_string().contains("duplicate column name")
            {
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Model time (milliseconds) the agent's calls took in the window.
    /// Absent row reads as 0.
    pub fn window_model_millis(
        &self,
        agent_id: &str,
        window_start: i64,
    ) -> Result<u64, GatewayError> {
        let millis: Option<i64> = self
            .conn
            .query_row(
                "SELECT model_millis FROM agent_spend WHERE agent_id = ?1 AND window_start = ?2",
                params![agent_id, window_start],
                |row| row.get(0),
            )
            .optional()?;
        Ok(millis.unwrap_or(0).max(0) as u64)
    }

    /// Add `millis` of model time to the agent's window, creating the
    /// row if absent.
    pub fn add_model_millis(
        &self,
        agent_id: &str,
        window_start: i64,
        millis: u64,
    ) -> Result<(), GatewayError> {
        self.conn.execute(
            "INSERT INTO agent_spend (agent_id, window_start, model_millis)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(agent_id, window_start)
             DO UPDATE SET model_millis = model_millis + excluded.model_millis",
            params![
                agent_id,
                window_start,
                i64::try_from(millis).unwrap_or(i64::MAX)
            ],
        )?;
        Ok(())
    }

    /// [`Self::try_mark_alerted`] for the model-time ceiling, which
    /// alerts once per window on its own flag.
    pub fn try_mark_model_time_alerted(
        &self,
        agent_id: &str,
        window_start: i64,
    ) -> Result<bool, GatewayError> {
        self.conn.execute(
            "INSERT INTO agent_spend (agent_id, window_start) VALUES (?1, ?2)
             ON CONFLICT(agent_id, window_start) DO NOTHING",
            params![agent_id, window_start],
        )?;
        let changed = self.conn.execute(
            "UPDATE agent_spend SET model_time_alerted = 1
             WHERE agent_id = ?1 AND window_start = ?2 AND model_time_alerted = 0",
            params![agent_id, window_start],
        )?;
        Ok(changed > 0)
    }

    /// Accumulated spend (USD micros) for the agent in the window.
    /// Absent row reads as 0.
    pub fn window_spend(&self, agent_id: &str, window_start: i64) -> Result<u64, GatewayError> {
        let micros: Option<i64> = self
            .conn
            .query_row(
                "SELECT spend_micros FROM agent_spend WHERE agent_id = ?1 AND window_start = ?2",
                params![agent_id, window_start],
                |row| row.get(0),
            )
            .optional()?;
        Ok(micros.unwrap_or(0).max(0) as u64)
    }

    /// Add `micros` to the agent's spend in the window, creating the
    /// row if absent.
    pub fn add_spend(
        &self,
        agent_id: &str,
        window_start: i64,
        micros: u64,
    ) -> Result<(), GatewayError> {
        self.conn.execute(
            "INSERT INTO agent_spend (agent_id, window_start, spend_micros)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(agent_id, window_start)
             DO UPDATE SET spend_micros = spend_micros + excluded.spend_micros",
            params![agent_id, window_start, micros as i64],
        )?;
        Ok(())
    }

    /// Flip the window's `alerted` flag from 0 to 1. Returns `true`
    /// only on the transition, so alert mode emits at most one
    /// `BudgetExceeded` per window.
    pub fn try_mark_alerted(
        &self,
        agent_id: &str,
        window_start: i64,
    ) -> Result<bool, GatewayError> {
        self.conn.execute(
            "INSERT INTO agent_spend (agent_id, window_start, spend_micros, alerted)
             VALUES (?1, ?2, 0, 0)
             ON CONFLICT(agent_id, window_start) DO NOTHING",
            params![agent_id, window_start],
        )?;
        let changed = self.conn.execute(
            "UPDATE agent_spend SET alerted = 1
             WHERE agent_id = ?1 AND window_start = ?2 AND alerted = 0",
            params![agent_id, window_start],
        )?;
        Ok(changed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(mode: BudgetMode, ceiling: u64) -> AgentBudget {
        AgentBudget {
            mode,
            ceiling_usd_micros: Some(ceiling),
            ceiling_model_seconds: None,
            window: BudgetWindow::Day,
        }
    }

    /// An entry with only a model-time ceiling parses, and an existing
    /// entry reads as it did: a USD ceiling and no model-time one.
    #[test]
    fn an_entry_may_set_either_ceiling_or_both() {
        let cfg: BudgetConfig = serde_json::from_str(
            r#"{
                "default": { "mode": "alert", "ceiling_usd_micros": 5000000, "window": "day" },
                "agents": {
                    "local": { "mode": "block", "ceiling_model_seconds": 3600, "window": "hour" },
                    "both": { "mode": "block", "ceiling_usd_micros": 1, "ceiling_model_seconds": 60 }
                }
            }"#,
        )
        .unwrap();
        cfg.validate().unwrap();
        let local = cfg.resolve("local").unwrap();
        assert_eq!(local.ceiling_usd_micros, None);
        assert_eq!(local.ceiling_model_seconds, Some(3_600));
        assert_eq!(local.ceiling_model_millis(), Some(3_600_000));
        let both = cfg.resolve("both").unwrap();
        assert_eq!(
            (both.ceiling_usd_micros, both.ceiling_model_seconds),
            (Some(1), Some(60))
        );
        let existing = cfg.resolve("other").unwrap();
        assert_eq!(
            (existing.ceiling_usd_micros, existing.ceiling_model_seconds),
            (Some(5_000_000), None)
        );
        // An existing entry serializes without the new key.
        assert!(
            !serde_json::to_string(&existing)
                .unwrap()
                .contains("ceiling_model_seconds")
        );
    }

    /// An active entry with no ceiling is refused when the file is
    /// loaded, by name. An `off` entry needs none.
    #[test]
    fn an_active_entry_with_neither_ceiling_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budget.json");
        std::fs::write(
            &path,
            r#"{ "agents": { "work": { "mode": "block", "window": "day" } } }"#,
        )
        .unwrap();
        let err = load_budget_config(&path).unwrap_err().to_string();
        assert!(
            err.contains("agents.work") && err.contains("ceiling_model_seconds"),
            "{err}"
        );

        std::fs::write(&path, r#"{ "default": { "mode": "alert" } }"#).unwrap();
        let err = load_budget_config(&path).unwrap_err().to_string();
        assert!(err.contains("the default budget"), "{err}");

        std::fs::write(&path, r#"{ "agents": { "idle": { "mode": "off" } } }"#).unwrap();
        assert_eq!(load_budget_config(&path).unwrap().resolve("idle"), None);
    }

    #[test]
    fn model_time_accumulates_beside_spend_and_alerts_on_its_own_flag() {
        let s = BudgetStore::open_in_memory().unwrap();
        assert_eq!(s.window_model_millis("a", 0).unwrap(), 0);
        s.add_model_millis("a", 0, 1_500).unwrap();
        s.add_spend("a", 0, 7).unwrap();
        s.add_model_millis("a", 0, 500).unwrap();
        assert_eq!(s.window_model_millis("a", 0).unwrap(), 2_000);
        assert_eq!(s.window_spend("a", 0).unwrap(), 7);
        assert_eq!(s.window_model_millis("a", 86_400).unwrap(), 0);
        assert_eq!(s.window_model_millis("b", 0).unwrap(), 0);

        assert!(s.try_mark_alerted("a", 0).unwrap());
        assert!(s.try_mark_model_time_alerted("a", 0).unwrap());
        assert!(!s.try_mark_model_time_alerted("a", 0).unwrap());
        assert_eq!(s.window_model_millis("a", 0).unwrap(), 2_000);
    }

    /// A ledger written before model time was kept opens, keeps its
    /// spend, and takes model time.
    #[test]
    fn a_ledger_from_before_model_time_is_migrated_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budget.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA).unwrap();
            conn.execute(
                "INSERT INTO agent_spend (agent_id, window_start, spend_micros, alerted)
                 VALUES ('a', 0, 42, 1)",
                [],
            )
            .unwrap();
        }
        for _ in 0..2 {
            let s = BudgetStore::open(&path).unwrap();
            assert_eq!(s.window_spend("a", 0).unwrap(), 42);
            assert!(!s.try_mark_alerted("a", 0).unwrap());
            s.add_model_millis("a", 0, 10).unwrap();
        }
        let s = BudgetStore::open(&path).unwrap();
        assert_eq!(s.window_model_millis("a", 0).unwrap(), 20);
    }

    #[test]
    fn window_start_buckets_to_fixed_calendar() {
        // Day window: 90_061s = 1 day + 1 min + 1s -> bucket start at
        // exactly one day.
        assert_eq!(BudgetWindow::Day.window_start(90_061), 86_400);
        assert_eq!(BudgetWindow::Hour.window_start(3_661), 3_600);
        assert_eq!(BudgetWindow::Week.window_start(604_800), 604_800);
        assert_eq!(BudgetWindow::Week.window_start(604_799), 0);
    }

    #[test]
    fn add_spend_accumulates_within_window() {
        let s = BudgetStore::open_in_memory().unwrap();
        assert_eq!(s.window_spend("a", 0).unwrap(), 0);
        s.add_spend("a", 0, 1_000).unwrap();
        s.add_spend("a", 0, 500).unwrap();
        assert_eq!(s.window_spend("a", 0).unwrap(), 1_500);
        // A different window is independent (window reset).
        assert_eq!(s.window_spend("a", 86_400).unwrap(), 0);
        // A different agent is independent.
        assert_eq!(s.window_spend("b", 0).unwrap(), 0);
    }

    #[test]
    fn try_mark_alerted_fires_once_per_window() {
        let s = BudgetStore::open_in_memory().unwrap();
        assert!(s.try_mark_alerted("a", 0).unwrap());
        assert!(!s.try_mark_alerted("a", 0).unwrap());
        // New window re-arms.
        assert!(s.try_mark_alerted("a", 86_400).unwrap());
    }

    #[test]
    fn resolve_prefers_per_agent_then_global_then_off() {
        let block = budget(BudgetMode::Block, 10);
        let alert = budget(BudgetMode::Alert, 5);
        let off = budget(BudgetMode::Off, 0);
        // Per-agent wins.
        assert_eq!(resolve(Some(block), Some(alert)), Some(block));
        // Falls back to global.
        assert_eq!(resolve(None, Some(alert)), Some(alert));
        // An explicit per-agent Off overrides an active global: the
        // agent is opted out even though a global default is set.
        assert_eq!(resolve(Some(off), Some(block)), None);
        // An explicit per-agent Off with no global is also off.
        assert_eq!(resolve(Some(off), None), None);
        // Neither set.
        assert_eq!(resolve(None, None), None);
    }

    #[test]
    fn budget_config_resolves_per_agent_over_default() {
        let cfg: BudgetConfig = serde_json::from_str(
            r#"{
                "default": { "mode": "alert", "ceiling_usd_micros": 5000000, "window": "day" },
                "agents": {
                    "work": { "mode": "block", "ceiling_usd_micros": 10000000, "window": "day" },
                    "scratch": { "mode": "off", "ceiling_usd_micros": 0, "window": "day" }
                }
            }"#,
        )
        .unwrap();
        // Per-agent block overrides the global alert default.
        assert_eq!(cfg.resolve("work").unwrap().mode, BudgetMode::Block);
        // Explicit per-agent off opts out despite the global default.
        assert_eq!(cfg.resolve("scratch"), None);
        // No entry falls back to the global default.
        assert_eq!(cfg.resolve("other").unwrap().mode, BudgetMode::Alert);
    }

    #[test]
    fn empty_budget_config_resolves_to_none() {
        let cfg = BudgetConfig::default();
        assert_eq!(cfg.resolve("any"), None);
        assert!(!cfg.has_active());
        assert!(!cfg.has_block_mode());
    }

    #[test]
    fn config_block_and_active_detection() {
        let mut per_agent_block = BudgetConfig {
            default: Some(budget(BudgetMode::Alert, 5)),
            ..Default::default()
        };
        // Alert default: active but no block.
        assert!(per_agent_block.has_active());
        assert!(!per_agent_block.has_block_mode());
        // A per-agent block makes has_block_mode true.
        per_agent_block
            .agents
            .insert("work".into(), budget(BudgetMode::Block, 10));
        assert!(per_agent_block.has_block_mode());

        // A block default is detected too.
        let default_block = BudgetConfig {
            default: Some(budget(BudgetMode::Block, 10)),
            ..Default::default()
        };
        assert!(default_block.has_block_mode());

        // An all-off config is neither active nor block.
        let off = BudgetConfig {
            default: Some(budget(BudgetMode::Off, 0)),
            ..Default::default()
        };
        assert!(!off.has_active());
        assert!(!off.has_block_mode());
    }
}
