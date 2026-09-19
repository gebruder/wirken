//! `InjectionDetector::scan` on arbitrary inbound text.
//!
//! Every message a channel user sends reaches this before the agent
//! sees it, so it runs on text nobody vetted, from anyone who can
//! reach an adapter. It is pattern matching over attacker-chosen
//! input, which is the shape that decays into a quadratic scan or an
//! out-of-bounds slice on a multi-byte boundary.
//!
//! Asserted, beyond no panic:
//!
//! - The scan is deterministic. It is documented as stateless, so the
//!   same text twice is the same verdict twice; a difference means
//!   hidden state and a detector whose answer depends on what it saw
//!   before.
//! - A reported indicator's evidence is text the scanner was given,
//!   never something it composed.
//!
//! A crash is a finding. Do not relax a pattern to make a case pass.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wirken_gateway::injection_detect::InjectionDetector;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data).into_owned();
    let detector = InjectionDetector::new();

    let first = detector.scan(&text);
    let second = detector.scan(&text);
    assert_eq!(
        first.as_ref().map(|r| r.to_detail_json()),
        second.as_ref().map(|r| r.to_detail_json()),
        "scan is documented as stateless, so two scans of one text must \
         produce the same verdict"
    );

    if let Some(result) = first {
        assert!(
            !result.indicators.is_empty(),
            "a detection must carry at least one indicator; an empty one \
             reports a threat with nothing behind it"
        );
        for ind in &result.indicators {
            // `position` is documented as the byte offset of the match
            // in the original message, and `matched_text` as the
            // substring that triggered it, truncated. So the evidence
            // has to start where the offset says it does. An audit row
            // whose offset points somewhere else is evidence about a
            // different part of the message than the one it names.
            assert!(
                text.len() >= ind.position,
                "indicator position {} is past the end of a {}-byte message",
                ind.position,
                text.len()
            );
            assert!(
                text.is_char_boundary(ind.position),
                "indicator position {} is not a character boundary",
                ind.position
            );
            assert!(
                text[ind.position..].starts_with(&ind.matched_text),
                "the evidence at position {} is not what the message holds there",
                ind.position
            );
        }
    }
});
