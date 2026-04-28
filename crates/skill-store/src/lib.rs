//! Per-skill SQLite store, permission-gated.
//!
//! Skills that need local state (Zirkel's aggregator + librarian, future
//! presets that hold caches or seen-sets) own their own SQLite database.
//! [`SkillStore::open`] verifies the database path falls within the
//! skill's declared `permissions.filesystem.write_paths` allow-set
//! before creating or opening the file. A skill cannot write its store
//! anywhere outside the surface its frontmatter declared.
//!
//! ## What this crate is, and isn't
//!
//! **Is:** path resolution against a skill's permission profile,
//! [`Connection`] handle, idempotent migration runner that records
//! applied migrations in a `_migrations` table.
//!
//! **Isn't:** a connection pool, an ORM, a query builder, a caching
//! layer. Skills that need higher-level helpers build them on top of
//! the [`Connection`] this crate hands back. Keeping the API minimal
//! is deliberate — Zirkel is the first user, not the last; an API
//! shaped only by Zirkel is the wrong shape for the second user.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use thiserror::Error;
use wirken_agent::skill_perms::PermissionProfile;

/// A skill's per-skill SQLite store.
#[derive(Debug)]
pub struct SkillStore {
    conn: Connection,
    path: PathBuf,
    skill_name: String,
}

/// Reasons [`SkillStore::open`] can fail.
#[derive(Debug, Error)]
pub enum SkillStoreError {
    #[error(
        "skill store path '{path}' is not within the skill's \
         permissions.filesystem.write_paths allow-set"
    )]
    PathNotInWriteAllowlist { path: PathBuf },
    #[error("skill '{skill}' has an empty filesystem.write_paths allow-set; cannot open a store")]
    EmptyWriteAllowlist { skill: String },
    #[error("create parent directory for skill store at '{path}': {source}")]
    CreateParent {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("open SQLite at '{path}': {source}")]
    OpenSqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("migrate skill store: {0}")]
    Migrate(#[source] rusqlite::Error),
}

impl SkillStore {
    /// Open or create the SQLite file at `<base_dir>/<skill_name>.db`.
    /// Verifies the path is within `profile.filesystem.write_paths`
    /// before opening — a permissions edit that removes write access
    /// to the chosen directory fails the store open at startup
    /// instead of silently letting the orchestrator write to a path
    /// the skill is no longer allowed to touch.
    ///
    /// `profile` must be the resolved-and-expanded permission profile
    /// for the skill (any `<workspace>` token already substituted).
    /// The orchestrator handles expansion before calling this.
    pub fn open(
        skill_name: &str,
        base_dir: &Path,
        profile: &PermissionProfile,
    ) -> Result<Self, SkillStoreError> {
        let path = base_dir.join(format!("{skill_name}.db"));

        if profile.filesystem.write_paths.is_empty() {
            return Err(SkillStoreError::EmptyWriteAllowlist {
                skill: skill_name.to_string(),
            });
        }
        if !path_under_any(&path, &profile.filesystem.write_paths) {
            return Err(SkillStoreError::PathNotInWriteAllowlist { path });
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SkillStoreError::CreateParent {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let conn = Connection::open(&path).map_err(|e| SkillStoreError::OpenSqlite {
            path: path.clone(),
            source: e,
        })?;

        Ok(Self {
            conn,
            path,
            skill_name: skill_name.to_string(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn skill_name(&self) -> &str {
        &self.skill_name
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Apply versioned migrations. Each migration is a SQL statement
    /// (or batch). Migrations are addressed by their index in the
    /// slice and recorded in a `_migrations` table; repeat calls are
    /// idempotent. Adding a new migration means appending to the
    /// slice — never reordering or replacing existing entries (the
    /// recorded indexes would point at different SQL).
    pub fn migrate(&mut self, migrations: &[&str]) -> Result<(), SkillStoreError> {
        let tx = self.conn.transaction().map_err(SkillStoreError::Migrate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS _migrations ( \
                idx INTEGER PRIMARY KEY, \
                applied_at TEXT NOT NULL DEFAULT (datetime('now')) \
            )",
        )
        .map_err(SkillStoreError::Migrate)?;

        let already_applied: std::collections::BTreeSet<i64> = tx
            .prepare("SELECT idx FROM _migrations")
            .and_then(|mut stmt| {
                stmt.query_map([], |row| row.get::<_, i64>(0))
                    .and_then(|r| r.collect())
            })
            .map_err(SkillStoreError::Migrate)?;

        for (idx, sql) in migrations.iter().enumerate() {
            let idx_i64 = idx as i64;
            if already_applied.contains(&idx_i64) {
                continue;
            }
            tx.execute_batch(sql).map_err(SkillStoreError::Migrate)?;
            tx.execute(
                "INSERT INTO _migrations (idx) VALUES (?1)",
                rusqlite::params![idx_i64],
            )
            .map_err(SkillStoreError::Migrate)?;
        }

        tx.commit().map_err(SkillStoreError::Migrate)?;
        Ok(())
    }
}

fn path_under_any(path: &Path, allowed: &std::collections::BTreeSet<PathBuf>) -> bool {
    allowed.iter().any(|root| path.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use wirken_agent::skill_perms::{
        AllowSet, EgressMode, EgressPolicy, FilesystemPolicy, InferencePolicy, PermissionProfile,
        ToolPolicy,
    };

    fn profile_with_writes(paths: Vec<PathBuf>) -> PermissionProfile {
        PermissionProfile {
            tools: ToolPolicy::default(),
            egress: EgressPolicy {
                mode: EgressMode::Deny,
                domains: AllowSet::default(),
            },
            filesystem: FilesystemPolicy {
                write_paths: paths.into_iter().collect::<BTreeSet<_>>(),
                read_paths: BTreeSet::new(),
            },
            inference: InferencePolicy::default(),
        }
    }

    #[test]
    fn open_creates_db_under_allowed_path() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("zirkel");
        let profile = profile_with_writes(vec![base.clone()]);
        let store = SkillStore::open("aggregator", &base, &profile).unwrap();
        assert!(store.path().exists(), "db file should exist on disk");
        assert_eq!(store.skill_name(), "aggregator");
    }

    #[test]
    fn open_rejects_path_outside_write_allowlist() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("not_allowed");
        // Allow some other directory.
        let profile = profile_with_writes(vec![tmp.path().join("allowed")]);
        let err = SkillStore::open("aggregator", &base, &profile).unwrap_err();
        assert!(matches!(
            err,
            SkillStoreError::PathNotInWriteAllowlist { .. }
        ));
    }

    #[test]
    fn open_rejects_empty_write_allowlist() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = profile_with_writes(vec![]);
        let err = SkillStore::open("aggregator", tmp.path(), &profile).unwrap_err();
        assert!(matches!(err, SkillStoreError::EmptyWriteAllowlist { .. }));
    }

    #[test]
    fn migrate_runs_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = profile_with_writes(vec![tmp.path().to_path_buf()]);
        let mut store = SkillStore::open("aggregator", tmp.path(), &profile).unwrap();

        let m0 = "CREATE TABLE candidates (id INTEGER PRIMARY KEY, url TEXT NOT NULL)";
        let m1 = "ALTER TABLE candidates ADD COLUMN score REAL NOT NULL DEFAULT 0";
        store.migrate(&[m0, m1]).unwrap();

        // Second call must not error and must not re-apply.
        store.migrate(&[m0, m1]).unwrap();

        // Verify the schema is the post-m1 shape.
        let cnt: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('candidates') WHERE name = 'score'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cnt, 1, "score column should exist after migration");

        // Verify both migrations are recorded.
        let applied: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM _migrations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(applied, 2);
    }

    #[test]
    fn migrate_appending_new_migration_runs_only_the_new_one() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = profile_with_writes(vec![tmp.path().to_path_buf()]);
        let mut store = SkillStore::open("aggregator", tmp.path(), &profile).unwrap();

        let m0 = "CREATE TABLE candidates (id INTEGER PRIMARY KEY, url TEXT NOT NULL)";
        store.migrate(&[m0]).unwrap();

        let m1 = "ALTER TABLE candidates ADD COLUMN score REAL NOT NULL DEFAULT 0";
        store.migrate(&[m0, m1]).unwrap();

        let applied: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM _migrations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(applied, 2);
    }

    #[test]
    fn db_persists_across_open_calls() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = profile_with_writes(vec![tmp.path().to_path_buf()]);
        {
            let mut store = SkillStore::open("aggregator", tmp.path(), &profile).unwrap();
            store
                .migrate(&["CREATE TABLE seen (url TEXT PRIMARY KEY)"])
                .unwrap();
            store
                .conn()
                .execute(
                    "INSERT INTO seen (url) VALUES (?1)",
                    rusqlite::params!["https://example.com/a"],
                )
                .unwrap();
        }
        let store = SkillStore::open("aggregator", tmp.path(), &profile).unwrap();
        let cnt: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM seen", [], |row| row.get(0))
            .unwrap();
        assert_eq!(cnt, 1);
    }
}
