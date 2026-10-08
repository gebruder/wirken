use anyhow::Result;

use wirken_gateway::cron::CronStore;

use super::config;

pub async fn list(agent_id: Option<&str>) -> Result<()> {
    let cfg = config();
    let store = CronStore::open(&cfg.cron_db_path())?;

    let jobs = store.list(agent_id)?;

    if jobs.is_empty() {
        println!("  No cron jobs.");
        return Ok(());
    }

    println!(
        "  {:20}  {:12}  {:20}  {:6}  {:5}  MESSAGE",
        "ID", "AGENT", "SCHEDULE", "RUNS", "STATE"
    );
    println!(
        "  {}  {}  {}  {}  {}  {}",
        "─".repeat(20),
        "─".repeat(12),
        "─".repeat(20),
        "─".repeat(6),
        "─".repeat(5),
        "─".repeat(30)
    );

    for job in &jobs {
        let state = if job.paused { "pause" } else { "  ok " };
        let msg = short_message(&job.message);
        println!(
            "  {:20}  {:12}  {:20}  {:6}  {}  {}",
            job.id, job.agent_id, job.schedule, job.run_count, state, msg
        );
    }

    println!();
    println!("  {} cron jobs.", jobs.len());
    Ok(())
}

pub async fn create(
    schedule: &str,
    message: &str,
    agent_id: &str,
    description: &str,
) -> Result<()> {
    let cfg = config();
    let store = CronStore::open(&cfg.cron_db_path())?;

    let job = store.create(agent_id, schedule, message, description, "cli")?;

    println!("  Created cron job: {}", job.id);
    println!("  Schedule: {}", job.schedule);
    println!("  Agent: {}", job.agent_id);
    println!(
        "  Next run: {}",
        job.next_run_at.format("%Y-%m-%d %H:%M UTC")
    );
    println!("  Message: {}", job.message);
    Ok(())
}

pub async fn delete(id: &str) -> Result<()> {
    let cfg = config();
    let store = CronStore::open(&cfg.cron_db_path())?;

    store.delete(id)?;
    println!("  Deleted cron job: {id}");
    Ok(())
}

pub async fn pause(id: &str) -> Result<()> {
    let cfg = config();
    let store = CronStore::open(&cfg.cron_db_path())?;

    store.pause(id)?;
    println!("  Paused cron job: {id}");
    Ok(())
}

pub async fn resume(id: &str) -> Result<()> {
    let cfg = config();
    let store = CronStore::open(&cfg.cron_db_path())?;

    store.resume(id)?;
    println!("  Resumed cron job: {id}");
    Ok(())
}

/// `message` as listed: a message over 40 bytes is cut to at most 37,
/// at a character boundary, with `...` appended.
fn short_message(message: &str) -> String {
    if message.len() <= 40 {
        return message.to_string();
    }
    let cut = message.floor_char_boundary(37);
    format!("{}...", message.get(..cut).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::short_message;

    #[test]
    fn short_message_cuts_at_a_character_boundary() {
        assert_eq!(short_message("short"), "short");
        assert_eq!(
            short_message(&"a".repeat(41)),
            format!("{}...", "a".repeat(37))
        );
        // Byte 37 falls inside the two-byte character at 36..38.
        let message = format!("{}\u{e9}{}", "a".repeat(36), "a".repeat(10));
        assert_eq!(short_message(&message), format!("{}...", "a".repeat(36)));
    }
}
