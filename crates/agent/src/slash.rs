//! Slash-command invocation surface for explicit-only skills (#79).
//!
//! Skills declared `disable-model-invocation: true` are excluded from the
//! system prompt's auto-pickable set ([`crate::skill::SkillLoader::build_prompt`]).
//! To reach them, the user types `/<skill-name>` as a prefix on a message.
//! The agent detects the prefix, looks up the named skill, prepends the
//! skill's body to the user message for that turn, and strips the prefix
//! from what the LLM sees in subsequent context.
//!
//! ## Strict, not fuzzy
//!
//! The parser detects the `^/<name>(\s|$)` shape only — leading slash,
//! one identifier-shaped name, then whitespace or end of string. It does
//! not match mentions of a skill name elsewhere in the message
//! (`"thanks for using lyrik"` is not an invocation), nor does it
//! interpret `use lyrik to ...` as explicit invocation. Fuzzy invocation
//! turns "explicit" into "unpredictable"; the slash prefix is the contract.

use crate::error::AgentError;
use crate::inbound_interceptor::{InboundInterceptor, InterceptResult, InterceptorContext};
use crate::skill::Skill;

/// [`InboundInterceptor`] that handles `/<skill-name> ...` invocations.
/// First registered interceptor on the agent — others (e.g. Zirkel's
/// keep/skip) plug in alongside.
pub struct SlashInterceptor;

impl InboundInterceptor for SlashInterceptor {
    fn name(&self) -> &'static str {
        "slash"
    }

    fn intercept(&self, message: &str, ctx: &InterceptorContext<'_>) -> InterceptResult {
        match parse(message, ctx.skills) {
            SlashResult::None => InterceptResult::Pass,
            SlashResult::Invoked { skill, remainder } => {
                InterceptResult::Rewrite(rewrite_with_skill_body(skill, &remainder))
            }
            SlashResult::UnknownSkill { name } => {
                let known: Vec<String> = ctx.skills.iter().map(|s| s.name.clone()).collect();
                InterceptResult::Reject(AgentError::UnknownSlashSkill { name, known })
            }
        }
    }
}

/// Result of running [`parse`] on a user message.
#[derive(Debug)]
pub enum SlashResult<'a> {
    /// No `/<name>` prefix on the message — pass through unchanged.
    None,
    /// Prefix matched and named skill is loaded. The agent should
    /// prepend `skill.body` to the rewritten message before adding it
    /// to the conversation.
    Invoked {
        skill: &'a Skill,
        /// Message body with the `/<name>` prefix and any single
        /// trailing whitespace stripped.
        remainder: String,
    },
    /// Prefix matched but the named skill is not loaded. The agent
    /// should fail the user message rather than silently treating it
    /// as plain text — a typo'd or out-of-scope slash is exactly the
    /// case where silent fall-through is dangerous.
    UnknownSkill { name: String },
}

/// Parse a user message for a leading `/<skill-name>` invocation.
pub fn parse<'a>(message: &str, skills: &'a [Skill]) -> SlashResult<'a> {
    let trimmed = message.trim_start();
    let Some(after_slash) = trimmed.strip_prefix('/') else {
        return SlashResult::None;
    };
    // Skill name is the prefix up to the first whitespace. Empty name
    // (a bare `/`) is not an invocation — pass through.
    let (name, rest) = match after_slash.find(char::is_whitespace) {
        Some(idx) => (&after_slash[..idx], &after_slash[idx + 1..]),
        None => (after_slash, ""),
    };
    if name.is_empty() {
        return SlashResult::None;
    }
    if !is_skill_name_shape(name) {
        return SlashResult::None;
    }
    match skills.iter().find(|s| s.name == name) {
        Some(skill) => SlashResult::Invoked {
            skill,
            remainder: rest.to_string(),
        },
        None => SlashResult::UnknownSkill {
            name: name.to_string(),
        },
    }
}

/// Skill names follow the same shape as bundled skills: alphanumeric,
/// hyphens, underscores. Anything outside this is not a skill name and
/// the slash prefix is treated as ordinary text (e.g., a Markdown
/// quotation or a leading-slash URL fragment).
fn is_skill_name_shape(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Rewrite a slash-invoked user message so the LLM sees the skill body
/// before the user's request. The returned string is what gets added
/// to the conversation in place of the raw user message.
pub fn rewrite_with_skill_body(skill: &Skill, remainder: &str) -> String {
    let mut out = String::with_capacity(skill.body.len() + remainder.len() + 64);
    out.push_str("# Skill: ");
    out.push_str(&skill.name);
    out.push_str("\n\n");
    out.push_str(&skill.body);
    out.push_str("\n\n---\n\n");
    out.push_str(remainder);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skill_perms::PermissionProfile;
    use std::path::PathBuf;

    fn skill(name: &str) -> Skill {
        Skill {
            name: name.to_string(),
            description: format!("desc for {name}"),
            required_bins: vec![],
            body: format!("body of {name}"),
            path: PathBuf::new(),
            available: true,
            permissions: PermissionProfile::default(),
            disable_model_invocation: true,
        }
    }

    #[test]
    fn no_slash_prefix_returns_none() {
        let s = vec![skill("lyrik")];
        assert!(matches!(parse("audit src/", &s), SlashResult::None));
    }

    #[test]
    fn slash_prefix_with_known_skill_invokes() {
        let s = vec![skill("lyrik")];
        match parse("/lyrik audit src/", &s) {
            SlashResult::Invoked { skill, remainder } => {
                assert_eq!(skill.name, "lyrik");
                assert_eq!(remainder, "audit src/");
            }
            other => panic!("expected Invoked, got {other:?}"),
        }
    }

    #[test]
    fn slash_prefix_with_no_remainder_invokes_with_empty_remainder() {
        let s = vec![skill("lyrik")];
        match parse("/lyrik", &s) {
            SlashResult::Invoked { skill, remainder } => {
                assert_eq!(skill.name, "lyrik");
                assert_eq!(remainder, "");
            }
            other => panic!("expected Invoked, got {other:?}"),
        }
    }

    #[test]
    fn slash_prefix_with_unknown_skill_reports_unknown() {
        let s = vec![skill("lyrik")];
        match parse("/nonexistent do something", &s) {
            SlashResult::UnknownSkill { name } => assert_eq!(name, "nonexistent"),
            other => panic!("expected UnknownSkill, got {other:?}"),
        }
    }

    #[test]
    fn slash_in_middle_of_message_is_not_an_invocation() {
        let s = vec![skill("lyrik")];
        assert!(matches!(parse("please /lyrik this", &s), SlashResult::None));
    }

    #[test]
    fn skill_name_mention_without_slash_is_not_an_invocation() {
        let s = vec![skill("lyrik")];
        assert!(matches!(
            parse("use lyrik to audit src/", &s),
            SlashResult::None
        ));
    }

    #[test]
    fn bare_slash_passes_through() {
        let s = vec![skill("lyrik")];
        assert!(matches!(parse("/", &s), SlashResult::None));
    }

    #[test]
    fn slash_followed_by_invalid_name_passes_through() {
        let s = vec![skill("lyrik")];
        // URL-shaped leading slash, code blocks, etc. are ordinary text.
        assert!(matches!(parse("/path/to/file", &s), SlashResult::None));
    }

    #[test]
    fn leading_whitespace_is_tolerated() {
        let s = vec![skill("lyrik")];
        match parse("  /lyrik audit", &s) {
            SlashResult::Invoked { skill, remainder } => {
                assert_eq!(skill.name, "lyrik");
                assert_eq!(remainder, "audit");
            }
            other => panic!("expected Invoked, got {other:?}"),
        }
    }

    #[test]
    fn rewrite_inlines_skill_body_before_remainder() {
        let s = skill("lyrik");
        let out = rewrite_with_skill_body(&s, "audit src/");
        assert!(out.starts_with("# Skill: lyrik"));
        assert!(out.contains("body of lyrik"));
        assert!(out.contains("audit src/"));
        // Body must precede remainder so the LLM reads instructions
        // before the request.
        let body_idx = out.find("body of lyrik").unwrap();
        let req_idx = out.find("audit src/").unwrap();
        assert!(body_idx < req_idx);
    }
}
