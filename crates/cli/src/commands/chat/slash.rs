//! What the operator typed, sorted into the chat's own commands, a
//! skill invocation the runtime handles, or a message.
//!
//! A chat command is recognised only at the start of the draft and only
//! by its exact lowercase name; anything else that starts `/word` goes
//! to the agent, whose `SlashInterceptor` rewrites a known skill and
//! rejects an unknown one. The chat never guesses which of the two a
//! name is: a skill cannot shadow a chat command, and a typo in a chat
//! command reaches the runtime, which names the skills it knows.

/// The chat's own commands. Everything here runs in the chat process
/// and sends nothing to the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Builtin {
    Help,
    Status,
    Skills,
    Agents,
    Permissions,
    Sessions,
    Context,
    Cost,
    Verify,
    Tools,
    Safety,
    Runs,
    Export,
    Setup,
    Clear,
    Quit,
}

impl Builtin {
    /// Every name the chat recognises, with what it does. `/exit` is an
    /// alias of `/quit`; both are listed so completion offers both.
    pub(crate) const ALL: [(&'static str, Builtin, &'static str); 17] = [
        (
            "/help",
            Builtin::Help,
            "commands, keys and the loaded skills",
        ),
        (
            "/status",
            Builtin::Status,
            "agent, provider, sandbox, budget, audit",
        ),
        ("/skills", Builtin::Skills, "skills attached to this agent"),
        ("/agents", Builtin::Agents, "configured agents"),
        (
            "/permissions",
            Builtin::Permissions,
            "stored grants for this agent",
        ),
        (
            "/sessions",
            Builtin::Sessions,
            "this conversation and the gateway's sessions",
        ),
        (
            "/context",
            Builtin::Context,
            "how full the model's context is",
        ),
        (
            "/cost",
            Builtin::Cost,
            "calls, tokens and spend in this conversation",
        ),
        (
            "/verify",
            Builtin::Verify,
            "check this conversation's audit chain now",
        ),
        (
            "/tools",
            Builtin::Tools,
            "what the agent can use, and what asks you",
        ),
        (
            "/safety",
            Builtin::Safety,
            "what weakens a guarantee here, and how to undo it",
        ),
        (
            "/runs",
            Builtin::Runs,
            "runs this conversation delegated, and how each stands",
        ),
        (
            "/export",
            Builtin::Export,
            "save this conversation as Markdown under exports/",
        ),
        (
            "/setup",
            Builtin::Setup,
            "run the setup wizard, then rebuild the agent",
        ),
        (
            "/clear",
            Builtin::Clear,
            "seal this conversation and start a new one",
        ),
        ("/quit", Builtin::Quit, "seal this conversation and leave"),
        ("/exit", Builtin::Quit, "same as /quit"),
    ];
}

/// One submitted draft, classified.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parsed<'a> {
    /// A chat command; any text after the name is ignored.
    Builtin(Builtin),
    /// `/word …` the chat does not own: sent to the agent as typed.
    Skill(&'a str),
    /// A message for the agent.
    Text(&'a str),
}

pub(crate) fn parse(draft: &str) -> Parsed<'_> {
    let line = draft.trim();
    let Some(rest) = line.strip_prefix('/') else {
        return Parsed::Text(line);
    };
    let name = rest.split(char::is_whitespace).next().unwrap_or("");
    let is_word = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !is_word {
        // `//…` and a bare `/` are text: nothing routes on them.
        return Parsed::Text(line);
    }
    for (full, builtin, _) in Builtin::ALL {
        if full.strip_prefix('/') == Some(name) {
            return Parsed::Builtin(builtin);
        }
    }
    Parsed::Skill(line)
}

/// Names that complete `draft` while it is a lone `/word` with no
/// space yet: the chat's commands first, then the agent's slash
/// skills. Empty when the draft is not a command prefix.
pub(crate) fn completions(draft: &str, skills: &[String]) -> Vec<String> {
    if !draft.starts_with('/') || draft.contains(char::is_whitespace) {
        return Vec::new();
    }
    let mut out: Vec<String> = Builtin::ALL
        .iter()
        .map(|(name, _, _)| (*name).to_string())
        .chain(skills.iter().map(|s| format!("/{s}")))
        .filter(|name| name.starts_with(draft))
        .collect();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_parses_by_its_exact_name() {
        for (name, builtin, _) in Builtin::ALL {
            assert_eq!(parse(name), Parsed::Builtin(builtin), "{name}");
        }
    }

    #[test]
    fn exit_is_an_alias_of_quit() {
        assert_eq!(parse("/exit"), Parsed::Builtin(Builtin::Quit));
    }

    #[test]
    fn text_after_a_builtin_is_ignored() {
        assert_eq!(parse("/status please"), Parsed::Builtin(Builtin::Status));
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_the_name() {
        assert_eq!(parse("  /help \n"), Parsed::Builtin(Builtin::Help));
    }

    /// Case is not folded: the runtime's skill names are lowercase and
    /// exact, and the chat follows the same rule rather than owning a
    /// second one.
    #[test]
    fn an_uppercase_name_goes_to_the_agent() {
        assert_eq!(parse("/HELP"), Parsed::Skill("/HELP"));
    }

    #[test]
    fn an_unknown_slash_word_is_a_skill_invocation_with_its_arguments() {
        assert_eq!(
            parse("/weather in Berlin"),
            Parsed::Skill("/weather in Berlin")
        );
    }

    #[test]
    fn a_double_slash_and_a_bare_slash_are_text() {
        assert_eq!(parse("//not a command"), Parsed::Text("//not a command"));
        assert_eq!(parse("/ not a command"), Parsed::Text("/ not a command"));
        assert_eq!(parse("/"), Parsed::Text("/"));
    }

    #[test]
    fn a_slash_later_in_the_line_is_text() {
        assert_eq!(parse("see /etc/hosts"), Parsed::Text("see /etc/hosts"));
    }

    #[test]
    fn completions_offer_builtins_then_skills_on_a_prefix() {
        let skills = vec!["summarise".to_string(), "status-report".to_string()];
        assert_eq!(
            completions("/s", &skills),
            vec![
                "/status",
                "/skills",
                "/sessions",
                "/safety",
                "/setup",
                "/summarise",
                "/status-report"
            ]
        );
        assert_eq!(completions("/q", &skills), vec!["/quit"]);
    }

    #[test]
    fn completions_stop_once_the_name_is_followed_by_a_space() {
        assert!(completions("/status ", &[]).is_empty());
        assert!(completions("hello", &[]).is_empty());
    }
}
