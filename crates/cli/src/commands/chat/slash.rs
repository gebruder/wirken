//! Slash commands typed in the chat draft.
//!
//! A command counts only as the first word of the draft, by its exact
//! lowercase name. Text after it is ignored. Any other `/word` (a skill,
//! `/HELP`, `/etc/hosts`) is not a command: it goes to the gateway as typed,
//! so skills keep working and a skill cannot shadow a command.

/// One slash command the chat handles itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    /// Every panel, from the gateway's current answer.
    Status,
    /// One panel, named by its title.
    Panel(&'static str),
    /// The command table and the keys.
    Help,
    /// The chain check, as Ctrl+K runs it.
    Verify,
    /// A new conversation, as Ctrl+N opens one.
    Clear,
    /// Leave the chat, as Ctrl+C does.
    Quit,
}

/// The command table, in the order `/help` lists it. The description is
/// what the line says after the name.
pub(crate) const COMMANDS: &[(&str, &str)] = &[
    ("/status", "every panel, as the gateway has them now"),
    ("/context", "the context window and what fills it"),
    ("/cost", "tokens and cost for this conversation"),
    ("/tools", "the tools this agent can use"),
    ("/approvals", "approvals waiting on you"),
    ("/audit", "the audit trail and its chain"),
    ("/verify", "check this conversation's chain"),
    ("/clear", "start a new conversation"),
    ("/help", "this list and the keys"),
    ("/quit", "leave the chat"),
];

/// The command the draft names, when its first word is one. `/exit` is an
/// alias of `/quit`.
pub(crate) fn parse(draft: &str) -> Option<Command> {
    let word = draft.split_whitespace().next()?;
    Some(match word {
        "/status" => Command::Status,
        "/context" => Command::Panel("Context"),
        "/cost" => Command::Panel("Cost and tokens"),
        "/tools" => Command::Panel("Tools"),
        "/approvals" => Command::Panel("Approvals"),
        "/audit" => Command::Panel("Audit"),
        "/verify" => Command::Verify,
        "/clear" => Command::Clear,
        "/help" => Command::Help,
        "/quit" | "/exit" => Command::Quit,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_is_its_exact_lowercase_first_word() {
        assert_eq!(parse("/status"), Some(Command::Status));
        assert_eq!(parse("  /cost  "), Some(Command::Panel("Cost and tokens")));
        assert_eq!(parse("/quit"), Some(Command::Quit));
        assert_eq!(parse("/exit"), Some(Command::Quit));
    }

    #[test]
    fn text_after_the_name_is_ignored() {
        assert_eq!(parse("/status now please"), Some(Command::Status));
        assert_eq!(parse("/help me"), Some(Command::Help));
    }

    #[test]
    fn any_other_slash_word_is_not_a_command() {
        assert_eq!(parse("/summarize this week"), None);
        assert_eq!(parse("/HELP"), None);
        assert_eq!(parse("/etc/hosts"), None);
        assert_eq!(parse("say /status"), None);
        assert_eq!(parse(""), None);
    }

    #[test]
    fn every_listed_command_parses() {
        for (name, _) in COMMANDS {
            assert!(parse(name).is_some(), "{name} is listed but does not parse");
        }
    }
}
