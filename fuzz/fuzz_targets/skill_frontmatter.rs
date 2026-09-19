//! `SKILL.md` frontmatter parsing and the envelope gate.
//!
//! A skill bundle is third-party content. The signature gate decides
//! whether to parse it at all; this is what runs once that gate has
//! said yes, on bytes an author controls. It is reached here directly
//! rather than through `SkillLoader::load_file` because that would
//! stage a signed bundle on disk per iteration and spend the run
//! testing the signature gate instead of the parser.
//!
//! Asserted, beyond no panic:
//!
//! - The returned body is a suffix of the trimmed input. The parser
//!   splits, it does not synthesise, so no byte can appear in a skill
//!   body that the author did not write.
//! - Any content carrying an envelope marker is refused. That marker
//!   delimits untrusted skill text in the system prompt, so a skill
//!   that can write one can forge the boundary.
//!
//! A crash is a finding. Do not weaken an assertion to make a case
//! pass.

#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use wirken_agent::skill::{envelope_collision_check, parse_frontmatter};

/// The tokens that delimit third-party skill text in the assembled
/// system prompt.
const ENVELOPE_TOKENS: &[&str] = &["BEGIN UNTRUSTED SKILL", "END UNTRUSTED SKILL"];

fuzz_target!(|data: &[u8]| {
    let content = String::from_utf8_lossy(data).into_owned();

    let Ok((frontmatter, body)) = parse_frontmatter(&content) else {
        // A parse refusal is a correct outcome, not a finding.
        return;
    };

    assert!(
        content.trim().ends_with(&body),
        "the parsed body must be a suffix of the input: the parser splits \
         content, it never synthesises it"
    );

    let name = frontmatter.name.clone().unwrap_or_else(|| "fuzz".to_string());
    let description = frontmatter.description.clone().unwrap_or_default();

    let verdict = envelope_collision_check(&name, &description, &body, Path::new("SKILL.md"));
    let carries_marker = ENVELOPE_TOKENS
        .iter()
        .any(|t| name.contains(t) || description.contains(t) || body.contains(t));
    if carries_marker {
        assert!(
            verdict.is_err(),
            "content carrying an envelope marker must be refused; \
             name {name:?} description {description:?}"
        );
    }
});
