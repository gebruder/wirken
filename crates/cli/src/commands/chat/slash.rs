//! The chat's own commands, typed as `/name` in the draft.
//!
//! A chat command is recognised only at the start of the draft and only
//! by its exact lowercase name. Anything else that starts `/word` goes to
//! the gateway as typed, where the runtime's `SlashInterceptor` expands a
//! known skill and refuses an unknown one. So a skill can never shadow a
//! chat command, and a typo in one reaches the runtime, which names the
//! skills it knows.

use super::panels::{Status, Verified, panels};

/// What a chat command does. None of them sends anything to the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Help,
    /// Ask the gateway for the panels and note the one with this title
    /// in [`panels`], or every one for `None`.
    Panel(Option<&'static str>),
    Verify,
    Clear,
    Quit,
}

/// Every name the chat recognises, with what it does, in the order
/// `/help` lists them.
pub(crate) const COMMANDS: [(&str, Command, &str); 11] = [
    ("/help", Command::Help, "these commands and the keys"),
    (
        "/status",
        Command::Panel(None),
        "every panel, as the gateway reports it now",
    ),
    (
        "/context",
        Command::Panel(Some("Context")),
        "how full the model's context is",
    ),
    (
        "/cost",
        Command::Panel(Some("Cost and tokens")),
        "calls, tokens and spend in this conversation",
    ),
    (
        "/tools",
        Command::Panel(Some("Tools")),
        "what the agent can use, and what asks first",
    ),
    (
        "/approvals",
        Command::Panel(Some("Approvals")),
        "approved and denied here, and the stored grants",
    ),
    (
        "/audit",
        Command::Panel(Some("Audit")),
        "rows and chain heads of this conversation",
    ),
    (
        "/verify",
        Command::Verify,
        "check this conversation's chain now (Ctrl+K)",
    ),
    (
        "/clear",
        Command::Clear,
        "new conversation with the same agent (Ctrl+N)",
    ),
    ("/quit", Command::Quit, "leave the chat (Ctrl+C)"),
    ("/exit", Command::Quit, "same as /quit"),
];

/// The keys, as docs/cli.md lists them.
const KEYS: [(&str, &str); 9] = [
    ("Enter", "send the message, or answer the card"),
    ("Ctrl+J", "new line in the message"),
    ("PgUp / PgDn", "scroll the transcript"),
    ("Ctrl+U", "clear the message or the answer"),
    (
        "Ctrl+F",
        "search the sidebar; arrows select, Enter opens, Esc leaves",
    ),
    ("Ctrl+N", "new conversation with the same agent"),
    ("Ctrl+B / Ctrl+P", "show or hide the sidebar / the panels"),
    ("Ctrl+K", "verify this conversation's chain"),
    ("Ctrl+C", "leave the chat"),
];

/// The chat command `draft` starts with, if it is one. Text after the
/// name is ignored.
pub(crate) fn parse(draft: &str) -> Option<Command> {
    let name = draft.split_whitespace().next()?;
    COMMANDS
        .iter()
        .find(|(n, ..)| *n == name)
        .map(|(_, command, _)| *command)
}

/// What `/help` notes: the commands, then the keys.
pub(crate) fn help() -> String {
    let mut lines = vec!["commands".to_string()];
    for (name, _, what) in COMMANDS {
        lines.push(format!("  {name:<11} {what}"));
    }
    lines.push(
        "  /<skill>    any other /word goes to the gateway as typed, for a skill".to_string(),
    );
    lines.push("keys".to_string());
    for (key, what) in KEYS {
        lines.push(format!("  {key:<16} {what}"));
    }
    lines.join("\n")
}

/// The panel titled `title`, or every panel for `None`, as one note:
/// each title, then its lines indented.
pub(crate) fn panel_note(
    status: &Status,
    verified: Option<&Verified>,
    title: Option<&str>,
) -> String {
    let mut lines = Vec::new();
    for panel in panels(status, verified) {
        if title.is_none_or(|t| t == panel.title) {
            lines.push(panel.title.to_string());
            lines.extend(panel.lines.iter().map(|l| format!("  {l}")));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_parses_by_its_exact_name() {
        for (name, command, _) in COMMANDS {
            assert_eq!(parse(name), Some(command), "{name}");
        }
        assert_eq!(parse("/exit"), Some(Command::Quit));
    }

    #[test]
    fn surrounding_space_and_text_after_the_name_are_not_part_of_it() {
        assert_eq!(parse("  /help \n"), Some(Command::Help));
        assert_eq!(
            parse("/cost please"),
            Some(Command::Panel(Some("Cost and tokens")))
        );
    }

    /// Everything else goes to the gateway as typed: a skill, a typo,
    /// another case, a path, a slash later in the line.
    #[test]
    fn anything_else_is_not_a_chat_command() {
        for draft in [
            "/weather in Berlin",
            "/HELP",
            "/Help",
            "/helpme",
            "/hel",
            "//help",
            "/ help",
            "/",
            "/etc/hosts",
            "see /help",
            "",
        ] {
            assert_eq!(parse(draft), None, "{draft:?}");
        }
    }

    #[test]
    fn every_panel_a_command_names_exists() {
        let titles: Vec<&str> = panels(&Status::default(), None)
            .iter()
            .map(|p| p.title)
            .collect();
        for (name, command, _) in COMMANDS {
            if let Command::Panel(Some(title)) = command {
                assert!(titles.contains(&title), "{name} names {title}");
            }
        }
    }

    #[test]
    fn help_lists_every_command_and_key() {
        let help = help();
        for (name, ..) in COMMANDS {
            assert!(help.contains(name), "{name}");
        }
        for (key, _) in KEYS {
            assert!(help.contains(key), "{key}");
        }
    }

    #[test]
    fn a_panel_note_holds_that_panel_and_status_holds_all() {
        let mut status = Status::default();
        status.cost.calls = 2;
        status.audit.rows = 14;
        let cost = panel_note(&status, None, Some("Cost and tokens"));
        assert!(cost.starts_with("Cost and tokens\n  2 calls"), "{cost}");
        assert!(!cost.contains("Audit"), "{cost}");
        let all = panel_note(&status, None, None);
        for p in panels(&status, None) {
            assert!(all.contains(p.title), "{all}");
        }
        assert!(all.contains("  14 rows"), "{all}");
    }
}
