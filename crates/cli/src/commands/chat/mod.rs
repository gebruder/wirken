//! `wirken chat`: a full-screen terminal chat.
//!
//! Agents are resolved as `wirken ask` resolves them and woken through
//! one `AgentFactory` (see `agent::chat_agents`), each conversation on
//! its own audit lane `{agent}/chat/c-<id>`, delegated runs on
//! `{parent}#sub-N`. What the chat adds is a screen: a transcript that
//! streams the reply and shows tool activity as the runtime writes it to
//! the chain, an approval card that asks what the `ask` prompt asks, a
//! sidebar of agents and conversations, and a panel. It opens no socket
//! and holds no secret the agents do not already hold.
//!
//! Everything that can block on the operator before the screen exists
//! (the vault passphrase prompt, the first-run wizard) runs before the
//! alternate screen is entered, in the terminal as it is.

mod app;
mod gate;
mod markdown;
mod slash;
mod view;
mod wrap;

use std::sync::Mutex;

use anyhow::Result;

use super::config;

/// Log text written while the screen is up, or `None` when it is not.
static HELD_LOGS: Mutex<Option<String>> = Mutex::new(None);

fn held() -> std::sync::MutexGuard<'static, Option<String>> {
    HELD_LOGS.lock().unwrap_or_else(|e| e.into_inner())
}

/// The process's log writer: stdout, unless the chat holds the screen.
pub fn log_writer() -> LogSink {
    LogSink
}

pub struct LogSink;

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(text) = held().as_mut() {
            text.push_str(&String::from_utf8_lossy(buf));
            return Ok(buf.len());
        }
        std::io::stdout().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

/// Start holding log text instead of printing it.
pub(crate) fn hold_logs() {
    held().get_or_insert_with(String::new);
}

/// Hold one line, as the log writer would, when the chat holds the
/// screen; false when it does not, and the caller prints it itself.
pub(crate) fn hold_line(line: &str) -> bool {
    match held().as_mut() {
        Some(text) => {
            text.push_str(line.trim_end());
            text.push('\n');
            true
        }
        None => false,
    }
}

/// Stop holding; what was held and not yet taken is returned.
pub(crate) fn release_logs() -> Vec<String> {
    let text = held().take().unwrap_or_default();
    text.lines().map(str::to_string).collect()
}

/// Complete lines held so far; a partial last line stays held.
pub(crate) fn take_logs() -> Vec<String> {
    let mut guard = held();
    let Some(text) = guard.as_mut() else {
        return Vec::new();
    };
    let Some(end) = text.rfind('\n') else {
        return Vec::new();
    };
    let rest = text.split_off(end + 1);
    let done = std::mem::replace(text, rest);
    done.lines().map(str::to_string).collect()
}

pub async fn run(agent: &str, first_message: Option<String>) -> Result<()> {
    use std::io::IsTerminal as _;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "wirken chat needs a terminal on stdin and stdout; from a script or a \
             pipe use `wirken ask -m <message>`"
        );
    }

    let cfg = config();
    if nothing_configured(&cfg) {
        println!();
        println!("  No AI provider is configured yet, so setup runs first.");
        super::setup::run(false, None).await?;
        if nothing_configured(&cfg) {
            anyhow::bail!("no AI provider configured; run `wirken setup`");
        }
    }

    app::run(cfg, agent.to_string(), first_message).await
}

/// True when neither the legacy `provider.json` nor any agent row
/// exists: a first run gets the wizard rather than a refusal.
fn nothing_configured(cfg: &wirken_gateway::config::GatewayConfig) -> bool {
    if cfg.data_dir.join("provider.json").exists() {
        return false;
    }
    // Any agent at all counts: a mistyped `--agent` is an error to
    // report, not a reason to run setup.
    let path = cfg.agent_config_db_path();
    !(path.exists()
        && wirken_gateway::agent_config::AgentConfigStore::open(&path)
            .and_then(|store| store.list())
            .is_ok_and(|agents| !agents.is_empty()))
}
