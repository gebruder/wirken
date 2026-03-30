//! Cron scheduler design.
//!
//! The scheduler loop runs inside the gateway process (see `cli/src/commands/run.rs`).
//! It checks for due jobs every 30 seconds using `CronStore::due_jobs()`,
//! marks them as run, and dispatches the job message to the appropriate agent.
//!
//! The loop is inlined in the gateway's `run` command rather than exported as a
//! function, because it needs access to the agent map which is owned by the CLI crate.
