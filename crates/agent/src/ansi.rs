//! Strip ANSI / C1 control sequences from untrusted text before it
//! crosses a trust boundary.
//!
//! Two sites need this in 1.3.0:
//!
//! - `crates/cli/src/commands/agent.rs` prints `result.response` to
//!   the operator's terminal. A skill body in the system prompt can
//!   instruct the LLM to emit an escape sequence (clear-line +
//!   carriage-return + fake `sudo password:`); without a strip pass
//!   the operator's terminal would render the impersonation.
//! - `crates/agent/src/tool.rs::exec_command` captures the child
//!   process's stdout / stderr and feeds it back to the model. A
//!   command whose output carries escape sequences can confuse the
//!   model's view of what ran. The strip happens at the
//!   model-input boundary; the audit chain records the raw bytes
//!   from before the strip.
//!
//! Sequences stripped:
//!
//! - CSI: `ESC '[' ... <final-byte-0x40..0x7E>`
//! - OSC: `ESC ']' ... <BEL | ESC '\\'>`
//! - SS2 / SS3: `ESC 'N' .` and `ESC 'O' .` (single-char follow-up)
//! - Other 2-byte `ESC <c>` introducers terminate with the second
//!   byte and that pair is dropped.
//! - 8-bit C1 control bytes 0x80..0x9F are dropped as bare bytes.
//! - 7-bit C0 controls (0x00..0x1F) and DEL (0x7F) are dropped
//!   except for `\n`, `\r`, `\t` which carry text-shape information.
//!
//! Bare CR (`\r`) is preserved because trailing-CR lines are
//! commonplace in legitimate stdout, but the fake-sudo prompt the
//! `crypto-walk` audit identified needs CSI removal to defang.
//!
//! This is a small state machine, not a regex, so it composes with
//! streaming output without backtracking.

/// Strip ANSI / C1 control sequences from `s`. Allocates a new
/// String only on the rare path; if `s` contains no escape
/// introducers, the returned String is a fresh clone (callers that
/// need zero-allocation behaviour on the hot path should pre-check
/// with [`contains_control_sequence`]).
pub fn strip_control_sequences(s: &str) -> String {
    if !contains_control_sequence(s) {
        return s.to_string();
    }

    // Iterate over chars, not bytes: UTF-8 lead bytes in
    // 0xC2..0xDF must not be confused with C1 controls
    // (0x80..0x9F), which only appear as `char` codepoints at the
    // Unicode level. Char iteration assembles the multi-byte
    // sequences correctly before the state machine sees them.
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\x1B' => {
                // ESC introducer. Consume the next char to classify.
                match chars.next() {
                    Some('[') => {
                        // CSI: ESC '[' params* final-byte (0x40..0x7E)
                        for p in chars.by_ref() {
                            if matches!(p, '\x40'..='\x7E') {
                                break;
                            }
                        }
                    }
                    Some(']') => {
                        // OSC: ESC ']' ... terminated by BEL or ESC '\\'
                        loop {
                            match chars.next() {
                                Some('\x07') | None => break,
                                Some('\x1B') => {
                                    let _ = chars.next();
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Some('N' | 'O') => {
                        // SS2 / SS3 are 2-byte introducers consuming one follow-up byte.
                        let _ = chars.next();
                    }
                    Some(_) | None => {
                        // Any other 2-byte ESC sequence: drop the
                        // pair and continue.
                    }
                }
            }
            // C1 controls (8-bit) as Unicode codepoints.
            '\u{0080}'..='\u{009F}' => {}
            // C0 controls and DEL, except whitespace that carries
            // text-shape information.
            '\x00'..='\x08' | '\x0B' | '\x0C' | '\x0E'..='\x1A' | '\x1C'..='\x1F' | '\x7F' => {}
            _ => out.push(c),
        }
    }
    out
}

/// Fast pre-check used by [`strip_control_sequences`] to skip
/// allocation when the input has no escape introducers and no C0
/// control bytes other than `\n` / `\r` / `\t`.
pub fn contains_control_sequence(s: &str) -> bool {
    s.bytes().any(|b| {
        matches!(b,
            0x1B
            | 0x00..=0x08
            | 0x0B..=0x0C
            | 0x0E..=0x1A
            | 0x1C..=0x1F
            | 0x7F
            | 0x80..=0x9F
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_passes_through() {
        assert_eq!(strip_control_sequences("hello world"), "hello world");
    }

    #[test]
    fn newlines_carriage_returns_and_tabs_are_preserved() {
        assert_eq!(
            strip_control_sequences("a\nb\rc\td"),
            "a\nb\rc\td",
            "shape-bearing whitespace must survive"
        );
    }

    #[test]
    fn csi_sequences_are_stripped() {
        let fake_sudo = "\x1b[2K\rsudo password:";
        let cleaned = strip_control_sequences(fake_sudo);
        assert_eq!(
            cleaned, "\rsudo password:",
            "CSI removed, bare CR preserved"
        );
        assert!(!cleaned.contains('\x1b'));
    }

    #[test]
    fn osc_sequences_terminated_by_bel_are_stripped() {
        // Set window title via OSC 0 ; ... BEL
        let s = "before\x1b]0;malicious title\x07after";
        assert_eq!(strip_control_sequences(s), "beforeafter");
    }

    #[test]
    fn osc_sequences_terminated_by_string_terminator_are_stripped() {
        let s = "before\x1b]0;malicious title\x1b\\after";
        assert_eq!(strip_control_sequences(s), "beforeafter");
    }

    #[test]
    fn c1_control_bytes_are_dropped() {
        let s = "x\u{0085}y";
        assert_eq!(strip_control_sequences(s), "xy");
    }

    #[test]
    fn other_c0_controls_are_dropped() {
        // BEL alone, backspace, vertical tab.
        let s = "a\x07b\x08c\x0bd";
        assert_eq!(strip_control_sequences(s), "abcd");
    }

    #[test]
    fn no_allocation_when_no_control_bytes() {
        assert!(!contains_control_sequence("plain ascii\nwith newline"));
    }
}
