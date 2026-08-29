//! `wirken import` - bring an assistant data-export archive into the
//! local store.
//!
//! # What this prints
//!
//! Counts and stable identifiers, and nothing else. No conversation
//! title, no message text, and no excerpt of either reaches stdout or
//! the tracing log. The identifiers that do appear are the archive
//! hash, the source account, and the source id.
//!
//! That is not a formatting preference. The whole point of importing an
//! archive into a gated store is that its contents stay behind the
//! gate; a command that echoed titles while importing would leak past
//! the control on the way in.

use std::path::Path;

use anyhow::{Context, Result, bail};

use wirken_gateway::imported::ImportStore;

use super::config;

/// Open the import store and report what it holds.
///
/// Archive ingestion is not wired up here yet: this opens the store,
/// applies any pending migrations, and reports the result, which is
/// what makes migration application observable against a fresh data
/// directory and against an existing one.
pub async fn run(archive: &Path) -> Result<()> {
    if !archive.exists() {
        bail!("archive not found: {}", archive.display());
    }
    if !archive.is_file() {
        bail!("archive is not a file: {}", archive.display());
    }

    let cfg = config();
    // The store lives in the data directory, which may not exist on a
    // machine that has not run the gateway yet. ensure_dirs also lands
    // the 0o700 mode the other stores rely on, so the import store is
    // not the one file created under a looser umask.
    cfg.ensure_dirs()
        .context("Failed to create the data directory")?;
    let db_path = cfg.imported_db_path();
    let (store, migrations_applied) =
        ImportStore::open(&db_path).context("Failed to open the imported-archive store")?;

    println!("Import store: {}", db_path.display());
    println!("Migrations applied this run: {migrations_applied}");

    let sources = store.sources().context("Failed to list import sources")?;
    if sources.is_empty() {
        println!("Sources: none");
    } else {
        println!("Sources:");
        for source in &sources {
            let counts = store
                .counts(&source.id)
                .with_context(|| format!("Failed to count records for source {}", source.id))?;
            let seal = if source.sealed { "sealed" } else { "live" };
            println!(
                "  {} provider={} account={} archive={} imported_at={} {seal}",
                source.id,
                source.provider,
                source.source_account,
                source.archive_sha256,
                source.imported_at,
            );
            println!(
                "    conversations={} messages={}",
                counts.conversations, counts.messages
            );
        }
    }

    println!("Archive ingestion is not implemented yet; the archive was not read.");
    Ok(())
}
