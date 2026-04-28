//! Inbound interceptor: parses keep/skip replies on the agent
//! receiving the digest, resolves the most recent unresolved digest
//! for that agent, and short-circuits the LLM for this turn.
//!
//! Registered on the agent that's bound to the operator's digest
//! channel (today: a single conversation per zirkel binding — see
//! piece 5). Free-text replies that aren't keep/skip commands fall
//! through to the LLM as normal.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use wirken_agent::inbound_interceptor::{InboundInterceptor, InterceptResult, InterceptorContext};
use wirken_audit::{HashHex, SessionEvent};

use crate::digest_log::{Decision, DigestLogError, DigestRecord, most_recent_unresolved, resolve};
use crate::keep_skip::{KeepSkipCmd, KeepSkipTargets, parse};

/// Per-instance keep/skip handler. Holds an open SQLite handle to
/// zirkel's per-skill DB; intercept calls take a brief sync mutex
/// and don't await across SQL.
pub struct KeepSkipInterceptor {
    db_path: PathBuf,
    conn: Mutex<Connection>,
}

impl KeepSkipInterceptor {
    /// Open the zirkel aggregator DB. Migrations are the
    /// orchestrator's responsibility — `open` does not run them.
    pub fn open(db_path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(db_path)?;
        Ok(Self {
            db_path: db_path.to_path_buf(),
            conn: Mutex::new(conn),
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}

impl InboundInterceptor for KeepSkipInterceptor {
    fn name(&self) -> &'static str {
        "keep-skip"
    }

    fn intercept(&self, message: &str, ctx: &InterceptorContext<'_>) -> InterceptResult {
        let Some(cmd) = parse(message) else {
            return InterceptResult::Pass;
        };
        let mut guard = self.conn.lock().unwrap();
        // The conn is held inside a Mutex; we need a &mut Connection
        // for transactions inside resolve(). Take the lock for the
        // duration of the SQL.
        match handle(&mut guard, ctx.agent_id, cmd) {
            Ok(outcome) => InterceptResult::Handle {
                reply: outcome.reply,
                audit_events: outcome.events,
            },
            Err(HandleError::NoActiveDigest) => InterceptResult::Handle {
                reply: "No digest awaiting reply. The next daily digest will arrive on schedule."
                    .to_string(),
                audit_events: vec![],
            },
            Err(HandleError::IndexOutOfRange { idx, total }) => InterceptResult::Handle {
                reply: format!(
                    "Index {idx} is out of range — the most recent digest has {total} item{}.",
                    if total == 1 { "" } else { "s" }
                ),
                audit_events: vec![],
            },
            Err(HandleError::Sqlite(e)) => {
                tracing::error!("keep-skip: sqlite error: {e}");
                InterceptResult::Handle {
                    reply: format!("Could not record decision: {e}"),
                    audit_events: vec![],
                }
            }
        }
    }
}

struct Outcome {
    reply: String,
    events: Vec<SessionEvent>,
}

#[derive(Debug, thiserror::Error)]
enum HandleError {
    #[error("no active digest")]
    NoActiveDigest,
    #[error("index {idx} out of range (digest has {total} items)")]
    IndexOutOfRange { idx: u32, total: u32 },
    #[error("sqlite: {0}")]
    Sqlite(#[from] DigestLogError),
}

fn handle(conn: &mut Connection, agent_id: &str, cmd: KeepSkipCmd) -> Result<Outcome, HandleError> {
    let digest = match most_recent_unresolved(conn, agent_id)? {
        Some(d) => d,
        None => return Err(HandleError::NoActiveDigest),
    };
    let total = digest.items.len() as u32;

    // Validate listed indices before any write.
    let listed = listed_indices(&cmd);
    if let Some(out_of_range) = listed.iter().copied().find(|i| *i == 0 || *i > total) {
        return Err(HandleError::IndexOutOfRange {
            idx: out_of_range,
            total,
        });
    }

    // Materialise the per-item decision for every position in the
    // digest, then apply.
    let decisions = expand_decisions(&cmd, total);
    let listed_unique = unique_listed(&cmd);

    // Map idx → candidate_id once for the audit-event pass.
    let idx_to_candidate: std::collections::HashMap<u32, i64> = digest
        .items
        .iter()
        .map(|it| (it.idx, it.candidate_id))
        .collect();

    resolve(conn, digest.id, &decisions)?;

    let events = build_session_events(conn, &digest, &decisions, &idx_to_candidate)?;
    let reply = format_reply(&cmd, total, &listed_unique, &decisions);
    Ok(Outcome { reply, events })
}

/// Indices the user named explicitly (as opposed to `all`). Empty
/// for `keep all` / `skip all`.
fn listed_indices(cmd: &KeepSkipCmd) -> Vec<u32> {
    match cmd {
        KeepSkipCmd::Keep(KeepSkipTargets::Indices(v))
        | KeepSkipCmd::Skip(KeepSkipTargets::Indices(v)) => v.clone(),
        _ => vec![],
    }
}

/// De-duplicated, sorted version of `listed_indices`.
fn unique_listed(cmd: &KeepSkipCmd) -> Vec<u32> {
    let mut v = listed_indices(cmd);
    v.sort_unstable();
    v.dedup();
    v
}

/// Materialise a decision for every position 1..=total based on the
/// command. `keep N,M` means N+M kept and the rest skipped; `skip
/// N,M` means N+M skipped and the rest kept; `keep all` / `skip all`
/// is blanket.
fn expand_decisions(cmd: &KeepSkipCmd, total: u32) -> Vec<(u32, Decision)> {
    match cmd {
        KeepSkipCmd::Keep(KeepSkipTargets::All) => {
            (1..=total).map(|i| (i, Decision::Kept)).collect()
        }
        KeepSkipCmd::Skip(KeepSkipTargets::All) => {
            (1..=total).map(|i| (i, Decision::Skipped)).collect()
        }
        KeepSkipCmd::Keep(KeepSkipTargets::Indices(v)) => {
            let kept: std::collections::HashSet<u32> = v.iter().copied().collect();
            (1..=total)
                .map(|i| {
                    if kept.contains(&i) {
                        (i, Decision::Kept)
                    } else {
                        (i, Decision::Skipped)
                    }
                })
                .collect()
        }
        KeepSkipCmd::Skip(KeepSkipTargets::Indices(v)) => {
            let skipped: std::collections::HashSet<u32> = v.iter().copied().collect();
            (1..=total)
                .map(|i| {
                    if skipped.contains(&i) {
                        (i, Decision::Skipped)
                    } else {
                        (i, Decision::Kept)
                    }
                })
                .collect()
        }
    }
}

fn build_session_events(
    conn: &Connection,
    digest: &DigestRecord,
    decisions: &[(u32, Decision)],
    idx_to_candidate: &std::collections::HashMap<u32, i64>,
) -> Result<Vec<SessionEvent>, HandleError> {
    let mut events = Vec::with_capacity(decisions.len());
    for (idx, decision) in decisions {
        let candidate_id = match idx_to_candidate.get(idx) {
            Some(c) => *c,
            None => continue,
        };
        match decision {
            Decision::Kept => events.push(SessionEvent::CandidateKept {
                run_id: digest.run_id.clone(),
                candidate_id,
                via: "signal-keep".into(),
            }),
            Decision::Skipped => {
                let (url, source_name) = read_candidate_url(conn, candidate_id)?;
                events.push(SessionEvent::CandidateSkipped {
                    run_id: digest.run_id.clone(),
                    url_hash: HashHex(hash_hex(url.as_bytes())),
                    source: source_name,
                    reason: "user_skipped".into(),
                });
            }
        }
    }
    Ok(events)
}

fn read_candidate_url(
    conn: &Connection,
    candidate_id: i64,
) -> Result<(String, String), HandleError> {
    let row = conn.query_row(
        "SELECT url, source_name FROM candidates WHERE id = ?1",
        params![candidate_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    );
    match row {
        Ok(t) => Ok(t),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok((String::new(), String::new())),
        Err(e) => Err(HandleError::Sqlite(DigestLogError::Sqlite(e))),
    }
}

fn hash_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut s, "{byte:02x}").unwrap();
    }
    s
}

fn format_reply(
    cmd: &KeepSkipCmd,
    total: u32,
    listed_unique: &[u32],
    decisions: &[(u32, Decision)],
) -> String {
    let kept_count = decisions
        .iter()
        .filter(|(_, d)| matches!(d, Decision::Kept))
        .count();
    let skipped_count = decisions.len() - kept_count;
    match cmd {
        KeepSkipCmd::Keep(KeepSkipTargets::All) => {
            format!("✓ kept all {total}")
        }
        KeepSkipCmd::Skip(KeepSkipTargets::All) => {
            format!("✓ skipped all {total}")
        }
        KeepSkipCmd::Keep(KeepSkipTargets::Indices(_)) => {
            format!(
                "✓ kept {} ({} skipped)",
                format_idx_list(listed_unique),
                skipped_count
            )
        }
        KeepSkipCmd::Skip(KeepSkipTargets::Indices(_)) => {
            format!(
                "✓ skipped {} ({} kept)",
                format_idx_list(listed_unique),
                kept_count
            )
        }
    }
}

fn format_idx_list(v: &[u32]) -> String {
    v.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest_log::record_sent;
    use crate::schema::AGGREGATOR_MIGRATIONS;
    use tempfile::TempDir;
    use wirken_agent::skill::Skill;

    fn open_migrated_with_seed(db_path: &Path, seed_candidates: &[(&str, &str)]) {
        let mut conn = Connection::open(db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE _migrations (idx INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))",
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        for (idx, sql) in AGGREGATOR_MIGRATIONS.iter().enumerate() {
            tx.execute_batch(sql).unwrap();
            tx.execute(
                "INSERT INTO _migrations (idx) VALUES (?1)",
                params![idx as i64],
            )
            .unwrap();
        }
        // Seed candidate rows so CandidateSkipped events can read
        // url + source_name.
        for (url, source) in seed_candidates {
            tx.execute(
                "INSERT INTO candidates (source_name, url, body, run_id, title) \
                 VALUES (?1, ?2, '', 'run-1', 'title')",
                params![source, url],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    fn ctx<'a>(agent_id: &'a str, skills: &'a [Skill]) -> InterceptorContext<'a> {
        InterceptorContext { agent_id, skills }
    }

    fn make_three_item_digest(db_path: &Path) -> i64 {
        open_migrated_with_seed(
            db_path,
            &[
                ("https://a.example/1", "src-a"),
                ("https://a.example/2", "src-a"),
                ("https://b.example/3", "src-b"),
            ],
        );
        let mut conn = Connection::open(db_path).unwrap();
        record_sent(&mut conn, "run-1", "default", &[1, 2, 3]).unwrap()
    }

    #[test]
    fn pass_through_for_unrelated_message() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("agg.db");
        make_three_item_digest(&db);
        let interceptor = KeepSkipInterceptor::open(&db).unwrap();
        let r = interceptor.intercept("hi there", &ctx("default", &[]));
        assert!(matches!(r, InterceptResult::Pass));
    }

    #[test]
    fn keep_indices_resolves_digest_and_emits_events() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("agg.db");
        let _digest_id = make_three_item_digest(&db);
        let interceptor = KeepSkipInterceptor::open(&db).unwrap();
        let r = interceptor.intercept("keep 1,3", &ctx("default", &[]));
        match r {
            InterceptResult::Handle {
                reply,
                audit_events,
            } => {
                assert!(reply.starts_with("✓ kept"), "reply was: {reply}");
                assert_eq!(audit_events.len(), 3);
                let kept = audit_events
                    .iter()
                    .filter(|e| matches!(e, SessionEvent::CandidateKept { .. }))
                    .count();
                let skipped = audit_events
                    .iter()
                    .filter(|e| matches!(e, SessionEvent::CandidateSkipped { .. }))
                    .count();
                assert_eq!(kept, 2);
                assert_eq!(skipped, 1);
            }
            other => panic!("expected Handle, got {other:?}"),
        }
        // Subsequent reply gets "no active digest" — proves resolved.
        let r2 = interceptor.intercept("keep 1", &ctx("default", &[]));
        match r2 {
            InterceptResult::Handle { reply, .. } => {
                assert!(reply.starts_with("No digest"), "reply was: {reply}");
            }
            other => panic!("expected Handle, got {other:?}"),
        }
    }

    #[test]
    fn skip_all_marks_all_skipped() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("agg.db");
        make_three_item_digest(&db);
        let interceptor = KeepSkipInterceptor::open(&db).unwrap();
        let r = interceptor.intercept("skip all", &ctx("default", &[]));
        match r {
            InterceptResult::Handle {
                reply,
                audit_events,
            } => {
                assert_eq!(reply, "✓ skipped all 3");
                assert_eq!(audit_events.len(), 3);
                assert!(
                    audit_events
                        .iter()
                        .all(|e| matches!(e, SessionEvent::CandidateSkipped { .. }))
                );
            }
            other => panic!("expected Handle, got {other:?}"),
        }
    }

    #[test]
    fn keep_all_marks_all_kept() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("agg.db");
        make_three_item_digest(&db);
        let interceptor = KeepSkipInterceptor::open(&db).unwrap();
        let r = interceptor.intercept("keep all", &ctx("default", &[]));
        match r {
            InterceptResult::Handle {
                reply,
                audit_events,
            } => {
                assert_eq!(reply, "✓ kept all 3");
                assert!(
                    audit_events
                        .iter()
                        .all(|e| matches!(e, SessionEvent::CandidateKept { .. }))
                );
            }
            other => panic!("expected Handle, got {other:?}"),
        }
    }

    #[test]
    fn out_of_range_index_surfaces_helpful_reply() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("agg.db");
        make_three_item_digest(&db);
        let interceptor = KeepSkipInterceptor::open(&db).unwrap();
        let r = interceptor.intercept("keep 99", &ctx("default", &[]));
        match r {
            InterceptResult::Handle { reply, .. } => {
                assert!(reply.contains("99"), "reply was: {reply}");
                assert!(reply.contains("3"), "reply was: {reply}");
            }
            other => panic!("expected Handle, got {other:?}"),
        }
        // The digest should NOT be resolved on out-of-range error.
        let mut conn = Connection::open(&db).unwrap();
        assert!(most_recent_unresolved(&conn, "default").unwrap().is_some());
        // Hush unused-must-use warnings on our reborrow.
        let _ = &mut conn;
    }

    #[test]
    fn no_active_digest_yields_friendly_reply() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("agg.db");
        // Migrations only — no digest sent.
        open_migrated_with_seed(&db, &[]);
        let interceptor = KeepSkipInterceptor::open(&db).unwrap();
        let r = interceptor.intercept("keep 1", &ctx("default", &[]));
        match r {
            InterceptResult::Handle { reply, .. } => {
                assert!(reply.starts_with("No digest"), "reply was: {reply}");
            }
            other => panic!("expected Handle, got {other:?}"),
        }
    }

    #[test]
    fn agent_id_scopes_lookup() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("agg.db");
        // A digest exists for agent "alpha", but the interceptor is
        // serving agent "beta" — beta should see "no active digest."
        open_migrated_with_seed(&db, &[("https://x", "src-x")]);
        let mut conn = Connection::open(&db).unwrap();
        record_sent(&mut conn, "run-1", "alpha", &[1]).unwrap();
        drop(conn);

        let interceptor = KeepSkipInterceptor::open(&db).unwrap();
        let r = interceptor.intercept("keep 1", &ctx("beta", &[]));
        match r {
            InterceptResult::Handle { reply, .. } => {
                assert!(reply.starts_with("No digest"), "reply was: {reply}");
            }
            other => panic!("expected Handle, got {other:?}"),
        }
        // Alpha still has its digest pending.
        let conn = Connection::open(&db).unwrap();
        assert!(most_recent_unresolved(&conn, "alpha").unwrap().is_some());
    }
}
