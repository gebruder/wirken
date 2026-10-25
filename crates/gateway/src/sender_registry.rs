//! Inbound sender allowlist for channel adapters.
//!
//! An inbound message is admitted when its sender id is a sender entry for
//! its channel, or its conversation id is a group entry. A channel with no
//! entries admits nobody. Ids are compared exactly.
//!
//! The registry is read on every message, so `wirken senders` changes apply
//! without a restart. [`RefusalLimiter`] bounds the refusal rows.

use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use wirken_audit::InboundRefusalReason;

use crate::error::GatewayError;

/// Channels the allowlist applies to. The terminal and webchat are not
/// among them.
pub const CHANNELS: [&str; 9] = [
    "telegram",
    "discord",
    "slack",
    "teams",
    "matrix",
    "whatsapp",
    "signal",
    "google-chat",
    "imessage",
];

/// How long SQLite waits on a lock held by another connection.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Refuse a channel no bundled adapter delivers.
pub fn validate_channel(channel: &str) -> Result<(), GatewayError> {
    if CHANNELS.contains(&channel) {
        Ok(())
    } else {
        Err(GatewayError::Config(format!(
            "'{channel}' is not a channel the sender allowlist applies to; use one of: {}",
            CHANNELS.join(", ")
        )))
    }
}

/// Refuse an empty id, one padded with whitespace, or one with a control
/// character.
pub fn validate_id(id: &str) -> Result<(), GatewayError> {
    if id.is_empty() {
        return Err(GatewayError::Config("the id is empty".into()));
    }
    if id.trim() != id {
        return Err(GatewayError::Config(format!(
            "'{id}' has leading or trailing whitespace; ids are compared exactly"
        )));
    }
    if id.chars().any(char::is_control) {
        return Err(GatewayError::Config(
            "the id contains a control character".into(),
        ));
    }
    Ok(())
}

/// One allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderEntry {
    pub channel: String,
    pub id: String,
    /// The id is a conversation id; admits every member.
    pub group: bool,
    /// Operator label. Not matched on.
    pub label: String,
    pub added_at: String,
}

/// Which entry admitted a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The sender's own id.
    Sender,
    /// The conversation it arrived in.
    Group,
}

impl Admission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Group => "group",
        }
    }
}

/// SQLite-backed allowlist at `<data_dir>/senders.db`.
pub struct SenderRegistry {
    conn: Mutex<Connection>,
}

impl SenderRegistry {
    /// Open or create the allowlist at `db_path`.
    pub fn open(db_path: &Path) -> Result<Self, GatewayError> {
        let conn = Connection::open(db_path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS senders (
                 channel TEXT NOT NULL,
                 id TEXT NOT NULL,
                 is_group INTEGER NOT NULL CHECK (is_group IN (0, 1)),
                 label TEXT NOT NULL DEFAULT '',
                 added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 PRIMARY KEY (channel, is_group, id)
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Add an entry, or update the label of one already present.
    /// Returns whether the entry is new.
    pub fn add(
        &self,
        channel: &str,
        id: &str,
        group: bool,
        label: &str,
    ) -> Result<bool, GatewayError> {
        validate_channel(channel)?;
        validate_id(id)?;
        let conn = self.conn();
        let existed = Self::exists(&conn, channel, id, group)?;
        conn.execute(
            "INSERT INTO senders (channel, id, is_group, label) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(channel, is_group, id) DO UPDATE SET label = excluded.label",
            params![channel, id, group, label],
        )?;
        Ok(!existed)
    }

    /// Remove an entry. Returns whether one was there.
    pub fn remove(&self, channel: &str, id: &str, group: bool) -> Result<bool, GatewayError> {
        let changes = self.conn().execute(
            "DELETE FROM senders WHERE channel = ?1 AND id = ?2 AND is_group = ?3",
            params![channel, id, group],
        )?;
        Ok(changes > 0)
    }

    fn exists(
        conn: &Connection,
        channel: &str,
        id: &str,
        group: bool,
    ) -> Result<bool, GatewayError> {
        Ok(conn
            .query_row(
                "SELECT 1 FROM senders WHERE channel = ?1 AND id = ?2 AND is_group = ?3",
                params![channel, id, group],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Every entry, or one channel's, ordered by channel, kind and id.
    pub fn list(&self, channel: Option<&str>) -> Result<Vec<SenderEntry>, GatewayError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT channel, id, is_group, label, added_at FROM senders \
             WHERE ?1 IS NULL OR channel = ?1 ORDER BY channel, is_group, id",
        )?;
        let rows = stmt.query_map(params![channel], |row| {
            Ok(SenderEntry {
                channel: row.get(0)?,
                id: row.get(1)?,
                group: row.get(2)?,
                label: row.get(3)?,
                added_at: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// How many entries `channel` has.
    pub fn count(&self, channel: &str) -> Result<usize, GatewayError> {
        let n: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM senders WHERE channel = ?1",
            params![channel],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// The entry that admits a message, or `None`. A sender entry wins
    /// when both match.
    pub fn admits(
        &self,
        channel: &str,
        sender_id: &str,
        conversation_id: &str,
    ) -> Result<Option<Admission>, GatewayError> {
        let group: Option<bool> = self
            .conn()
            .query_row(
                "SELECT is_group FROM senders WHERE channel = ?1 AND \
                 ((is_group = 0 AND id = ?2) OR (is_group = 1 AND id = ?3)) \
                 ORDER BY is_group LIMIT 1",
                params![channel, sender_id, conversation_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(group.map(|g| {
            if g {
                Admission::Group
            } else {
                Admission::Sender
            }
        }))
    }
}

/// Bounds on refusal rows: one per sender per `per_sender`, and at most
/// `lane_cap` per `lane_window` across all senders.
#[derive(Debug, Clone, Copy)]
pub struct RefusalLimits {
    pub per_sender: Duration,
    pub lane_window: Duration,
    pub lane_cap: u32,
    /// Senders tracked at once. Past this, stale entries are dropped.
    pub max_tracked: usize,
}

impl Default for RefusalLimits {
    fn default() -> Self {
        Self {
            per_sender: Duration::from_secs(60),
            lane_window: Duration::from_secs(60),
            lane_cap: 30,
            max_tracked: 4096,
        }
    }
}

/// Refusals counted without a row of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusalCounts {
    /// This sender's refusals since its previous row.
    pub suppressed: u64,
    /// Every sender's refusals since the lane's previous row.
    pub suppressed_on_lane: u64,
}

#[derive(Debug, Default)]
struct SenderState {
    last_row: Option<Instant>,
    suppressed: u64,
}

/// Decides which refusals get a row.
#[derive(Debug)]
pub struct RefusalLimiter {
    limits: RefusalLimits,
    senders: HashMap<(String, String), SenderState>,
    window_start: Option<Instant>,
    rows_in_window: u32,
    suppressed_on_lane: u64,
}

impl RefusalLimiter {
    pub fn new(limits: RefusalLimits) -> Self {
        Self {
            limits,
            senders: HashMap::new(),
            window_start: None,
            rows_in_window: 0,
            suppressed_on_lane: 0,
        }
    }

    /// Count a refusal. Returns the counts to record when it gets a row.
    pub fn refuse(
        &mut self,
        channel: &str,
        sender_id: &str,
        now: Instant,
    ) -> Option<RefusalCounts> {
        if self
            .window_start
            .is_none_or(|start| now.duration_since(start) >= self.limits.lane_window)
        {
            self.window_start = Some(now);
            self.rows_in_window = 0;
        }
        let key = (channel.to_string(), sender_id.to_string());
        let sender_due = self.senders.get(&key).is_none_or(|s| {
            s.last_row
                .is_none_or(|t| now.duration_since(t) >= self.limits.per_sender)
        });
        if !sender_due || self.rows_in_window >= self.limits.lane_cap {
            self.suppressed_on_lane += 1;
            if let Some(state) = self.senders.get_mut(&key) {
                state.suppressed += 1;
            } else if self.make_room(now) {
                self.senders.insert(
                    key,
                    SenderState {
                        last_row: None,
                        suppressed: 1,
                    },
                );
            }
            return None;
        }
        let suppressed = self.senders.remove(&key).map_or(0, |s| s.suppressed);
        if self.make_room(now) {
            self.senders.insert(
                key,
                SenderState {
                    last_row: Some(now),
                    suppressed: 0,
                },
            );
        }
        self.rows_in_window += 1;
        Some(RefusalCounts {
            suppressed,
            suppressed_on_lane: std::mem::take(&mut self.suppressed_on_lane),
        })
    }

    /// Whether another sender can be tracked, dropping stale entries
    /// when full.
    fn make_room(&mut self, now: Instant) -> bool {
        if self.senders.len() < self.limits.max_tracked {
            return true;
        }
        let per_sender = self.limits.per_sender;
        self.senders.retain(|_, s| {
            s.last_row
                .is_some_and(|t| now.duration_since(t) < per_sender)
        });
        self.senders.len() < self.limits.max_tracked
    }
}

/// The outcome of the inbound sender check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Admitted(Admission),
    /// Dropped. `record` is `Some` when this refusal gets a row.
    Refused {
        reason: InboundRefusalReason,
        record: Option<RefusalCounts>,
    },
}

/// The inbound sender check: the allowlist and the refusal limiter.
pub struct InboundGate {
    registry: SenderRegistry,
    limiter: Mutex<RefusalLimiter>,
}

impl InboundGate {
    pub fn new(registry: SenderRegistry, limits: RefusalLimits) -> Self {
        Self {
            registry,
            limiter: Mutex::new(RefusalLimiter::new(limits)),
        }
    }

    pub fn registry(&self) -> &SenderRegistry {
        &self.registry
    }

    /// Decide a message. An unreadable allowlist admits nobody.
    pub fn check(&self, channel: &str, sender_id: &str, conversation_id: &str) -> Verdict {
        self.check_at(channel, sender_id, conversation_id, Instant::now())
    }

    pub fn check_at(
        &self,
        channel: &str,
        sender_id: &str,
        conversation_id: &str,
        now: Instant,
    ) -> Verdict {
        let reason = match self.registry.admits(channel, sender_id, conversation_id) {
            Ok(Some(admission)) => return Verdict::Admitted(admission),
            Ok(None) => InboundRefusalReason::NotAllowed,
            Err(e) => {
                tracing::error!(
                    channel,
                    error = %e,
                    "inbound sender allowlist could not be read; refusing the message"
                );
                InboundRefusalReason::AllowlistUnreadable
            }
        };
        let record = self
            .limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .refuse(channel, sender_id, now);
        Verdict::Refused { reason, record }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh() -> (TempDir, SenderRegistry) {
        let tmp = TempDir::new().unwrap();
        let reg = SenderRegistry::open(&tmp.path().join("senders.db")).unwrap();
        (tmp, reg)
    }

    #[test]
    fn an_empty_allowlist_admits_nobody() {
        let (_tmp, reg) = fresh();
        for channel in CHANNELS {
            assert_eq!(reg.admits(channel, "anyone", "anywhere").unwrap(), None);
        }
    }

    #[test]
    fn a_sender_entry_admits_that_sender_in_any_conversation() {
        let (_tmp, reg) = fresh();
        assert!(reg.add("telegram", "111", false, "me").unwrap());
        assert_eq!(
            reg.admits("telegram", "111", "-100500").unwrap(),
            Some(Admission::Sender)
        );
        assert_eq!(reg.admits("telegram", "222", "-100500").unwrap(), None);
    }

    #[test]
    fn a_group_entry_admits_every_member_of_that_conversation_only() {
        let (_tmp, reg) = fresh();
        reg.add("signal", "group-abc=", true, "team").unwrap();
        assert_eq!(
            reg.admits("signal", "+15550001", "group-abc=").unwrap(),
            Some(Admission::Group)
        );
        assert_eq!(
            reg.admits("signal", "+15550002", "group-abc=").unwrap(),
            Some(Admission::Group)
        );
        assert_eq!(
            reg.admits("signal", "+15550001", "group-other=").unwrap(),
            None
        );
    }

    #[test]
    fn an_entry_matches_only_in_the_role_it_was_added_in() {
        let (_tmp, reg) = fresh();
        reg.add("slack", "C123", true, "").unwrap();
        reg.add("slack", "U123", false, "").unwrap();
        // A sender whose id is the group's id, elsewhere.
        assert_eq!(reg.admits("slack", "C123", "D999").unwrap(), None);
        // A conversation whose id is the sender's id, from someone else.
        assert_eq!(reg.admits("slack", "U999", "U123").unwrap(), None);
    }

    #[test]
    fn an_entry_admits_on_its_own_channel_only() {
        let (_tmp, reg) = fresh();
        reg.add("slack", "U123", false, "").unwrap();
        assert_eq!(reg.admits("discord", "U123", "U123").unwrap(), None);
    }

    #[test]
    fn ids_are_compared_exactly() {
        let (_tmp, reg) = fresh();
        reg.add("matrix", "@alice:example.org", false, "").unwrap();
        assert_eq!(
            reg.admits("matrix", "@Alice:example.org", "!r").unwrap(),
            None
        );
        assert_eq!(
            reg.admits("matrix", "@alice:example.org ", "!r").unwrap(),
            None
        );
    }

    #[test]
    fn a_removal_is_seen_by_another_connection_on_its_next_read() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("senders.db");
        let gateway = SenderRegistry::open(&path).unwrap();
        let cli = SenderRegistry::open(&path).unwrap();
        cli.add("telegram", "111", false, "").unwrap();
        assert!(gateway.admits("telegram", "111", "111").unwrap().is_some());
        assert!(cli.remove("telegram", "111", false).unwrap());
        assert_eq!(gateway.admits("telegram", "111", "111").unwrap(), None);
    }

    #[test]
    fn add_validates_channel_and_id() {
        let (_tmp, reg) = fresh();
        assert!(reg.add("telegrm", "1", false, "").is_err());
        assert!(reg.add("webchat", "1", false, "").is_err());
        assert!(reg.add("terminal", "1", false, "").is_err());
        assert!(reg.add("telegram", "", false, "").is_err());
        assert!(reg.add("telegram", " 1", false, "").is_err());
        assert!(reg.add("telegram", "1\n", false, "").is_err());
        assert!(reg.list(None).unwrap().is_empty());
    }

    #[test]
    fn re_adding_updates_the_label_and_is_not_new() {
        let (_tmp, reg) = fresh();
        assert!(reg.add("discord", "42", false, "old").unwrap());
        assert!(!reg.add("discord", "42", false, "new").unwrap());
        let entries = reg.list(Some("discord")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].label, "new");
        assert_eq!(reg.count("discord").unwrap(), 1);
        assert_eq!(reg.count("slack").unwrap(), 0);
    }

    #[test]
    fn remove_names_the_kind() {
        let (_tmp, reg) = fresh();
        reg.add("telegram", "-100", true, "").unwrap();
        assert!(!reg.remove("telegram", "-100", false).unwrap());
        assert!(reg.remove("telegram", "-100", true).unwrap());
        assert!(!reg.remove("telegram", "-100", true).unwrap());
    }

    fn limits() -> RefusalLimits {
        RefusalLimits {
            per_sender: Duration::from_secs(60),
            lane_window: Duration::from_secs(60),
            lane_cap: 3,
            max_tracked: 8,
        }
    }

    #[test]
    fn one_row_per_sender_per_interval_and_the_next_counts_the_rest() {
        let mut lim = RefusalLimiter::new(limits());
        let t0 = Instant::now();
        assert_eq!(
            lim.refuse("telegram", "9", t0),
            Some(RefusalCounts {
                suppressed: 0,
                suppressed_on_lane: 0
            })
        );
        for i in 1..=5 {
            assert_eq!(
                lim.refuse("telegram", "9", t0 + Duration::from_secs(i)),
                None
            );
        }
        assert_eq!(
            lim.refuse("telegram", "9", t0 + Duration::from_secs(61)),
            Some(RefusalCounts {
                suppressed: 5,
                suppressed_on_lane: 5
            })
        );
    }

    #[test]
    fn the_lane_cap_bounds_a_flood_from_many_senders() {
        let mut lim = RefusalLimiter::new(limits());
        let t0 = Instant::now();
        let rows = (0..100)
            .filter(|i| lim.refuse("telegram", &format!("s{i}"), t0).is_some())
            .count();
        assert_eq!(rows, 3);
        // The next window writes again and reports what the cap dropped.
        let next = lim
            .refuse("telegram", "late", t0 + Duration::from_secs(60))
            .unwrap();
        assert_eq!(next.suppressed_on_lane, 97);
        assert_eq!(next.suppressed, 0);
    }

    #[test]
    fn a_sender_held_back_by_the_cap_reports_its_count_on_its_row() {
        let mut lim = RefusalLimiter::new(limits());
        let t0 = Instant::now();
        for i in 0..3 {
            assert!(lim.refuse("slack", &format!("s{i}"), t0).is_some());
        }
        assert_eq!(lim.refuse("slack", "x", t0), None);
        assert_eq!(lim.refuse("slack", "x", t0), None);
        let row = lim
            .refuse("slack", "x", t0 + Duration::from_secs(60))
            .unwrap();
        assert_eq!(row.suppressed, 2);
    }

    #[test]
    fn senders_are_counted_per_channel() {
        let mut lim = RefusalLimiter::new(limits());
        let t0 = Instant::now();
        assert!(lim.refuse("slack", "U1", t0).is_some());
        assert!(lim.refuse("discord", "U1", t0).is_some());
    }

    #[test]
    fn the_tracked_table_stays_bounded() {
        let mut lim = RefusalLimiter::new(RefusalLimits {
            lane_cap: u32::MAX,
            ..limits()
        });
        let t0 = Instant::now();
        for i in 0..1000u64 {
            lim.refuse("telegram", &format!("s{i}"), t0 + Duration::from_secs(i));
        }
        assert!(lim.senders.len() <= 8);
    }

    #[test]
    fn the_gate_admits_refuses_and_limits() {
        let tmp = TempDir::new().unwrap();
        let reg = SenderRegistry::open(&tmp.path().join("senders.db")).unwrap();
        reg.add("telegram", "111", false, "").unwrap();
        let gate = InboundGate::new(reg, limits());
        let t0 = Instant::now();
        assert_eq!(
            gate.check_at("telegram", "111", "111", t0),
            Verdict::Admitted(Admission::Sender)
        );
        assert!(matches!(
            gate.check_at("telegram", "222", "222", t0),
            Verdict::Refused {
                reason: InboundRefusalReason::NotAllowed,
                record: Some(_)
            }
        ));
        assert!(matches!(
            gate.check_at("telegram", "222", "222", t0),
            Verdict::Refused { record: None, .. }
        ));
    }
}
