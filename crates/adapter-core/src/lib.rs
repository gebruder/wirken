//! Channel-specific outbound formatters.
//!
//! Agents emit markdown. Each channel has its own rendering dialect
//! (Signal: single-asterisk bold, no fenced blocks; Slack: mrkdwn;
//! Telegram: MarkdownV2 with escape rules; …). Rendering each dialect
//! in the agent core would couple it to every downstream channel. Keep
//! the agent channel-agnostic; adapters apply their own [`OutboundFormatter`]
//! on the way out.
//!
//! Scope: trait + [`PlainFormatter`] + [`SignalFormatter`] + [`SlackFormatter`].
//! Discord, Telegram, Matrix adapters still ship raw markdown. Their
//! formatters are tracked as follow-ups in #71.

/// Transform agent-emitted markdown into a string suitable for the
/// target channel's plain-text or rich-text envelope.
///
/// Implementations must be side-effect-free and deterministic — the
/// adapter calls `format()` on every outbound message and the result
/// is written into the channel SDK's send call verbatim.
pub trait OutboundFormatter: Send + Sync {
    fn format(&self, markdown: &str) -> String;
}

/// Pass-through formatter. Used as the explicit default for any
/// adapter without a channel-specific formatter. Explicit because the
/// alternative (implicit pass-through when no formatter is wired) is
/// exactly how markdown ended up in Signal messages in the first
/// place — the bug that motivated this module.
pub struct PlainFormatter;

impl OutboundFormatter for PlainFormatter {
    fn format(&self, markdown: &str) -> String {
        markdown.to_string()
    }
}

/// Render markdown to Signal's sparse formatting dialect.
///
/// Signal's client renders `*bold*`, `_italic_`, `~strike~`, and
/// ```code blocks``` (with triple backticks) as formatting. Everything
/// else arrives as literal text. This formatter narrows the agent's
/// markdown down to that dialect:
///
/// - `# H` / `## H` / `### H` → `*H*` on its own line
/// - `**x**` → `*x*`
/// - `_x_` / `__x__` → `_x_`
/// - `` `x` `` → `x` (inline code, backticks stripped)
/// - Fenced code blocks ` ``` ` → content kept, fence lines dropped
/// - GFM tables → flattened to `header: value` lines per row;
///   delimiter row (`---|---`) is dropped
/// - Bullet lists `- ` / `* ` → `• `
/// - Numbered lists → unchanged
/// - Links `[text](url)` → `text (url)`
/// - Horizontal rules (`---`, `***`, `___`) → blank line
///
/// Tables are flattened, not rendered. Signal is a plain-text channel
/// and a fixed-width table is unreadable on mobile; a cell-per-line
/// "Header: value" format keeps the content accessible.
pub struct SignalFormatter;

impl OutboundFormatter for SignalFormatter {
    fn format(&self, markdown: &str) -> String {
        let mut out = String::with_capacity(markdown.len());
        let mut lines = markdown.lines().peekable();
        let mut in_code_fence = false;
        let mut table_header: Option<Vec<String>> = None;

        while let Some(line) = lines.next() {
            let trimmed = line.trim_end();

            // Fenced code blocks: strip the fence lines, keep the
            // content. Signal shows inline ``` but we do not wrap
            // the block here — the agent can mark code with
            // single-backtick inline spans per line if needed.
            if trimmed.trim_start().starts_with("```") {
                in_code_fence = !in_code_fence;
                continue;
            }
            if in_code_fence {
                out.push_str(line);
                out.push('\n');
                continue;
            }

            // Horizontal rule.
            if is_hr(trimmed) {
                out.push('\n');
                continue;
            }

            // Heading.
            if let Some(stripped) = strip_heading(trimmed) {
                if !stripped.is_empty() {
                    out.push('*');
                    out.push_str(&apply_inline(stripped));
                    out.push('*');
                }
                out.push('\n');
                continue;
            }

            // GFM table handling. A table is a sequence of lines
            // each starting with '|' (or containing '|' separators);
            // the second line is a delimiter of dashes and colons.
            // We flatten to `Header: value` per cell, drop the
            // delimiter row, and buffer the header row until the
            // first body row.
            if is_table_row(trimmed) {
                let cells = split_table_row(trimmed, &apply_inline);
                if table_header.is_none() {
                    // Peek at next line: if it's a delimiter, this
                    // is a real table header. Otherwise treat as
                    // body and flatten straight through.
                    match lines.peek().map(|s| s.trim_end()) {
                        Some(next) if is_table_delimiter(next) => {
                            table_header = Some(cells);
                            lines.next(); // consume delimiter
                            continue;
                        }
                        _ => {
                            emit_flat_row(&mut out, None, &cells);
                            continue;
                        }
                    }
                }
                emit_flat_row(&mut out, table_header.as_deref(), &cells);
                continue;
            } else {
                // Exiting a table on the first non-table line.
                table_header = None;
            }

            // Bullet list.
            if let Some(rest) = strip_bullet(trimmed) {
                out.push_str("• ");
                out.push_str(&apply_inline(rest));
                out.push('\n');
                continue;
            }

            // Default: inline transforms only.
            out.push_str(&apply_inline(line));
            out.push('\n');
        }

        // Trim trailing blank lines so Signal does not show an
        // awkward gap at the bottom of every reply.
        while out.ends_with("\n\n") {
            out.pop();
        }
        if out.ends_with('\n') {
            out.pop();
        }
        out
    }
}

fn is_hr(line: &str) -> bool {
    let t = line.trim();
    if t.is_empty() {
        return false;
    }
    matches!(t, "---" | "***" | "___")
        || t.chars().all(|c| c == '-')
        || t.chars().all(|c| c == '*')
        || t.chars().all(|c| c == '_')
}

fn strip_heading(line: &str) -> Option<&str> {
    let t = line.trim_start();
    for depth in (1..=6).rev() {
        let prefix: String = "#".repeat(depth) + " ";
        if let Some(rest) = t.strip_prefix(prefix.as_str()) {
            return Some(rest.trim_end_matches('#').trim());
        }
    }
    None
}

fn strip_bullet(line: &str) -> Option<&str> {
    let t = line.trim_start();
    if let Some(rest) = t.strip_prefix("- ") {
        return Some(rest);
    }
    if let Some(rest) = t.strip_prefix("* ") {
        return Some(rest);
    }
    if let Some(rest) = t.strip_prefix("+ ") {
        return Some(rest);
    }
    None
}

fn is_table_row(line: &str) -> bool {
    let t = line.trim();
    t.starts_with('|') && t.matches('|').count() >= 2
}

fn is_table_delimiter(line: &str) -> bool {
    let t = line.trim();
    if !t.starts_with('|') {
        return false;
    }
    t.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ' | '\t')) && t.contains('-')
}

fn split_table_row(line: &str, inline: &dyn Fn(&str) -> String) -> Vec<String> {
    let t = line.trim();
    let inner = t.trim_start_matches('|').trim_end_matches('|');
    inner.split('|').map(|cell| inline(cell.trim())).collect()
}

fn emit_flat_row(out: &mut String, header: Option<&[String]>, cells: &[String]) {
    match header {
        Some(h) => {
            for (i, cell) in cells.iter().enumerate() {
                let label = h.get(i).map(|s| s.as_str()).unwrap_or("");
                if label.is_empty() {
                    out.push_str(cell);
                } else {
                    out.push_str(label);
                    out.push_str(": ");
                    out.push_str(cell);
                }
                out.push('\n');
            }
        }
        None => {
            // No header: join cells with " | " so the row stays
            // readable. Tables without a header row are unusual in
            // GFM but not invalid.
            out.push_str(&cells.join(" | "));
            out.push('\n');
        }
    }
    out.push('\n');
}

/// Apply inline transforms to a single line of text.
///
/// Order: links first (so their label text does not accidentally get
/// bold-stripped mid-replace), then bold, then inline code. Italic
/// (`_x_`) passes through because Signal's dialect already reads it
/// the same way. Bold-italic `***x***` collapses to `*x*` — Signal
/// has no combined bold-italic marker, bold takes priority.
fn apply_inline(line: &str) -> String {
    let linked = replace_links(line);
    let bolded = replace_bold(&linked);
    replace_inline_code(&bolded)
}

/// `[text](url)` → `text (url)`. Minimal parser: finds `[`, matches a
/// `]` before a `(`, and a closing `)` — nested brackets are treated
/// as literal text.
fn replace_links(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'['
            && let Some(close) = find_byte(bytes, b']', i + 1)
            && close + 1 < bytes.len()
            && bytes[close + 1] == b'('
            && let Some(paren_close) = find_byte(bytes, b')', close + 2)
        {
            let text = &input[i + 1..close];
            let url = &input[close + 2..paren_close];
            out.push_str(text);
            if !url.is_empty() {
                out.push_str(" (");
                out.push_str(url);
                out.push(')');
            }
            i = paren_close + 1;
            continue;
        }
        // Copy the next full UTF-8 codepoint, not the next byte.
        // `bytes[i] as char` only works for ASCII; for any multi-byte
        // sequence (Devanagari, CJK, emoji, accented letters, curly
        // quotes, em-dashes) it corrupts each continuation byte into
        // garbage. Walking to the next `is_char_boundary` and slicing
        // the &str preserves codepoints intact.
        let next = next_char_boundary(input, i);
        out.push_str(&input[i..next]);
        i = next;
    }
    out
}

fn find_byte(bytes: &[u8], needle: u8, start: usize) -> Option<usize> {
    bytes
        .iter()
        .skip(start)
        .position(|b| *b == needle)
        .map(|p| p + start)
}

fn next_char_boundary(s: &str, i: usize) -> usize {
    let mut j = i + 1;
    while j < s.len() && !s.is_char_boundary(j) {
        j += 1;
    }
    j
}

/// `**x**` → `*x*`. Also collapses `***x***` → `*x*`. Single `*x*`
/// passes through (Signal already reads it as bold).
fn replace_bold(input: &str) -> String {
    // Two passes. First normalize `***` sequences down to `**` so
    // the second pass can do a clean `**` → `*` swap without eating
    // italic markers. Order matters because `***` overlaps both.
    let pass1 = input.replace("***", "**");
    pass1.replace("**", "*")
}

/// `` `x` `` → `x`. Backtick runs are stripped. Matching pairs
/// preserve the enclosed content.
fn replace_inline_code(input: &str) -> String {
    input.replace('`', "")
}

/// Render markdown to Slack's `mrkdwn` dialect.
///
/// Slack's API renders `mrkdwn` in `text` payloads (default for Bolt).
/// The dialect overlaps Signal in some places (`*bold*`, `_italic_`)
/// and diverges in others — most importantly links use the angle-pipe
/// form `<url|text>` and code blocks render natively, so neither inline
/// backticks nor fenced blocks should be stripped.
///
/// - `# H` / `## H` / `### H` → `*H*` on its own line, blank line
///   following (Slack has no native heading; the blank line keeps
///   subsequent content visually separated)
/// - `**x**` → `*x*` (Slack reads single-asterisk as bold)
/// - `_x_` / `__x__` → `_x_`
/// - `` `x` `` → `` `x` `` (kept; Slack renders inline code)
/// - Fenced code blocks ` ``` ` → kept verbatim (Slack renders them)
/// - GFM tables → flattened to `header: value` lines per row, same as
///   Signal — Slack `mrkdwn` has no table primitive
/// - Bullet lists `- ` / `* ` → `• `
/// - Numbered lists → unchanged
/// - Links `[text](url)` → `<url|text>`
/// - Horizontal rules → blank line
///
/// Mentions (`<@user_id>`) and channel refs (`<#channel_id>`) pass
/// through verbatim because the inline pipeline only rewrites the
/// `[text](url)` form; raw `<@…>` strings are not matched.
pub struct SlackFormatter;

impl OutboundFormatter for SlackFormatter {
    fn format(&self, markdown: &str) -> String {
        let mut out = String::with_capacity(markdown.len());
        let mut lines = markdown.lines().peekable();
        let mut in_code_fence = false;
        let mut table_header: Option<Vec<String>> = None;

        while let Some(line) = lines.next() {
            let trimmed = line.trim_end();

            // Fenced code blocks: keep the fence and content. Slack
            // renders triple-backtick blocks natively.
            if trimmed.trim_start().starts_with("```") {
                in_code_fence = !in_code_fence;
                out.push_str(line);
                out.push('\n');
                continue;
            }
            if in_code_fence {
                out.push_str(line);
                out.push('\n');
                continue;
            }

            if is_hr(trimmed) {
                out.push('\n');
                continue;
            }

            // Heading: emit `*H*` on its own line followed by a blank
            // line. The trailing blank line replaces the visual weight
            // a real heading would carry in a rendered document.
            if let Some(stripped) = strip_heading(trimmed) {
                if !stripped.is_empty() {
                    out.push('*');
                    out.push_str(&apply_inline_slack(stripped));
                    out.push('*');
                }
                out.push('\n');
                out.push('\n');
                continue;
            }

            if is_table_row(trimmed) {
                let cells = split_table_row(trimmed, &apply_inline_slack);
                if table_header.is_none() {
                    match lines.peek().map(|s| s.trim_end()) {
                        Some(next) if is_table_delimiter(next) => {
                            table_header = Some(cells);
                            lines.next();
                            continue;
                        }
                        _ => {
                            emit_flat_row(&mut out, None, &cells);
                            continue;
                        }
                    }
                }
                emit_flat_row(&mut out, table_header.as_deref(), &cells);
                continue;
            } else {
                table_header = None;
            }

            if let Some(rest) = strip_bullet(trimmed) {
                out.push_str("• ");
                out.push_str(&apply_inline_slack(rest));
                out.push('\n');
                continue;
            }

            out.push_str(&apply_inline_slack(line));
            out.push('\n');
        }

        // Headings emit `*H*\n\n`; if the source markdown also had a
        // blank line after the heading the buffer accumulates a triple
        // newline. Collapse runs of three or more newlines down to a
        // paragraph break.
        while let Some(idx) = out.find("\n\n\n") {
            out.replace_range(idx..idx + 3, "\n\n");
        }

        while out.ends_with("\n\n") {
            out.pop();
        }
        if out.ends_with('\n') {
            out.pop();
        }
        out
    }
}

/// Slack inline pipeline: links → bold collapse. Inline code is left
/// alone because Slack renders single-backtick spans.
fn apply_inline_slack(line: &str) -> String {
    let linked = replace_links_slack(line);
    replace_bold(&linked)
}

/// `[text](url)` → `<url|text>` (Slack mrkdwn link form). Same byte-
/// walking shape as [`replace_links`], but emits the angle-pipe
/// dialect Slack expects. UTF-8 codepoints are preserved verbatim
/// outside the matched bracket pattern — see `replace_links` for the
/// rationale on `next_char_boundary` over `bytes[i] as char`.
fn replace_links_slack(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'['
            && let Some(close) = find_byte(bytes, b']', i + 1)
            && close + 1 < bytes.len()
            && bytes[close + 1] == b'('
            && let Some(paren_close) = find_byte(bytes, b')', close + 2)
        {
            let text = &input[i + 1..close];
            let url = &input[close + 2..paren_close];
            if url.is_empty() {
                // No URL — render the bracket text plain. A bare `[x]()`
                // would otherwise produce `<|x>`, which Slack renders
                // as nothing at all.
                out.push_str(text);
            } else {
                out.push('<');
                out.push_str(url);
                if !text.is_empty() {
                    out.push('|');
                    out.push_str(text);
                }
                out.push('>');
            }
            i = paren_close + 1;
            continue;
        }
        let next = next_char_boundary(input, i);
        out.push_str(&input[i..next]);
        i = next;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig() -> SignalFormatter {
        SignalFormatter
    }

    fn no_forbidden_markdown(s: &str) {
        assert!(
            !s.contains("##"),
            "Signal output must not contain `##`: {s:?}"
        );
        assert!(
            !s.contains("**"),
            "Signal output must not contain `**`: {s:?}"
        );
        assert!(
            !s.contains("```"),
            "Signal output must not contain ```` ``` ````: {s:?}"
        );
        assert!(
            !s.contains('`'),
            "Signal output must not contain backticks: {s:?}"
        );
        // `|` is allowed in plain text but a table pipe row with
        // the leading `|` must be gone.
        for line in s.lines() {
            assert!(
                !line.trim_start().starts_with('|'),
                "Signal output must not start a line with `|`: {line:?}"
            );
        }
    }

    #[test]
    fn plain_formatter_is_pass_through() {
        let input = "# heading\n**bold**\n`code`";
        assert_eq!(PlainFormatter.format(input), input);
    }

    #[test]
    fn headings_become_asterisk_bold() {
        let out = sig().format("# Title\n## Sub\n### Deep");
        assert_eq!(out, "*Title*\n*Sub*\n*Deep*");
    }

    #[test]
    fn bold_double_asterisks_collapse_to_single() {
        let out = sig().format("This is **bold** and **very bold**.");
        assert_eq!(out, "This is *bold* and *very bold*.");
    }

    #[test]
    fn italic_single_underscore_passes_through() {
        let out = sig().format("A _note_ on _emphasis_.");
        assert_eq!(out, "A _note_ on _emphasis_.");
    }

    #[test]
    fn inline_code_backticks_stripped() {
        let out = sig().format("Call `send()` with `params`.");
        assert_eq!(out, "Call send() with params.");
    }

    #[test]
    fn fenced_code_block_content_kept_fence_dropped() {
        let out = sig().format("```rust\nfn main() {}\n```");
        assert_eq!(out, "fn main() {}");
    }

    #[test]
    fn gfm_table_flattens_to_header_value_per_cell() {
        let out = sig()
            .format("| Fruit | Color |\n|-------|-------|\n| Apple | Red   |\n| Lime  | Green |");
        no_forbidden_markdown(&out);
        assert!(out.contains("Fruit: Apple"));
        assert!(out.contains("Color: Red"));
        assert!(out.contains("Fruit: Lime"));
        assert!(out.contains("Color: Green"));
    }

    #[test]
    fn bullet_list_becomes_round_bullets() {
        let out = sig().format("- one\n- two\n* three");
        assert_eq!(out, "• one\n• two\n• three");
    }

    #[test]
    fn numbered_list_passes_through() {
        let out = sig().format("1. first\n2. second");
        assert_eq!(out, "1. first\n2. second");
    }

    #[test]
    fn links_flatten_to_text_paren_url() {
        let out = sig().format("See [docs](https://wirken.app/docs).");
        assert_eq!(out, "See docs (https://wirken.app/docs).");
    }

    #[test]
    fn horizontal_rule_becomes_blank_line() {
        let out = sig().format("before\n---\nafter");
        assert!(out.contains("before"));
        assert!(out.contains("after"));
        no_forbidden_markdown(&out);
    }

    #[test]
    fn signal_output_never_contains_table_pipes_or_heading_marks() {
        // Representative of the real LLM reply that triggered this
        // work: mixed markdown with a comparison table, bold, and
        // an inline code sample.
        let input = "\
## Protein sources\n\
\n\
Common high-protein foods include **chicken breast**, `lentils`, and tofu.\n\
\n\
| Food          | Protein (g/100g) | Notes                       |\n\
|---------------|-----------------:|-----------------------------|\n\
| Chicken breast| 31               | Lean, moderate fat          |\n\
| Lentils       | 9                | Also fiber-dense            |\n\
| Tofu          | 8                | Check for calcium fortified |\n\
\n\
- Prioritize variety.\n\
- See [the guide](https://example.com/protein) for more.\n\
";
        let out = sig().format(input);
        no_forbidden_markdown(&out);
        assert!(out.contains("*Protein sources*"));
        assert!(out.contains("*chicken breast*"));
        assert!(out.contains("lentils"));
        assert!(out.contains("Food: Chicken breast"));
        assert!(out.contains("• Prioritize variety."));
        assert!(out.contains("the guide (https://example.com/protein)"));
    }

    #[test]
    fn triple_asterisk_bold_italic_collapses_to_bold() {
        let out = sig().format("That is ***critical*** to note.");
        assert_eq!(out, "That is *critical* to note.");
    }

    #[test]
    fn empty_input_yields_empty_output() {
        assert_eq!(sig().format(""), "");
    }

    #[test]
    fn non_ascii_text_preserved_verbatim() {
        // Regression: `replace_links` used to byte-walk and push each
        // byte as a char, which corrupted every multi-byte codepoint
        // into garbage chars. Real live smoke test surfaced this the
        // moment the LLM reply contained smart quotes, em-dashes, or
        // any non-Latin script.
        let input = "café — don't forget the apostrophe: “quote” 🦀";
        let out = sig().format(input);
        assert_eq!(out, input);
    }

    #[test]
    fn devanagari_survives_link_rewrite() {
        let input = "देखें [डॉक्स](https://wirken.app/hi/docs).";
        let out = sig().format(input);
        assert_eq!(out, "देखें डॉक्स (https://wirken.app/hi/docs).");
    }

    #[test]
    fn cjk_survives_heading_and_bold() {
        let input = "## 重要事项\n\nこれは **大切** です.";
        let out = sig().format(input);
        assert_eq!(out, "*重要事项*\n\nこれは *大切* です.");
    }

    #[test]
    fn emoji_in_bullet_list_roundtrips() {
        let input = "- 🦀 first\n- 🚀 second";
        let out = sig().format(input);
        assert_eq!(out, "• 🦀 first\n• 🚀 second");
    }

    // -------- Slack formatter ----------------------------------------

    fn slack() -> SlackFormatter {
        SlackFormatter
    }

    #[test]
    fn slack_bold_double_asterisks_collapse_to_single() {
        let out = slack().format("This is **bold** and **very bold**.");
        assert_eq!(out, "This is *bold* and *very bold*.");
    }

    #[test]
    fn slack_italic_single_underscore_passes_through() {
        let out = slack().format("A _note_ on _emphasis_.");
        assert_eq!(out, "A _note_ on _emphasis_.");
    }

    #[test]
    fn slack_inline_code_is_kept() {
        // Slack mrkdwn renders single-backtick spans natively.
        let out = slack().format("Call `send()` with `params`.");
        assert_eq!(out, "Call `send()` with `params`.");
    }

    #[test]
    fn slack_fenced_code_block_kept_verbatim() {
        // Slack renders triple-backtick blocks. The fence lines and
        // content both pass through.
        let out = slack().format("```rust\nfn main() {}\n```");
        assert_eq!(out, "```rust\nfn main() {}\n```");
    }

    #[test]
    fn slack_links_use_angle_pipe_form() {
        let out = slack().format("See [docs](https://wirken.app/docs).");
        assert_eq!(out, "See <https://wirken.app/docs|docs>.");
    }

    #[test]
    fn slack_link_with_empty_url_falls_back_to_plain_text() {
        // `[x]()` would render as `<|x>` and disappear in Slack. Treat
        // an empty URL as a plain text segment.
        let out = slack().format("[orphan]()");
        assert_eq!(out, "orphan");
    }

    #[test]
    fn slack_link_with_empty_text_keeps_url_visible() {
        // `[](https://x)` renders the bare URL — better than dropping
        // the line silently.
        let out = slack().format("[](https://wirken.app)");
        assert_eq!(out, "<https://wirken.app>");
    }

    #[test]
    fn slack_headings_become_bold_with_blank_line_after() {
        // Each heading emits `*H*` followed by a blank line so the
        // following content gets visual separation Slack lacks for
        // headings natively.
        let out = slack().format("# Title\nbody");
        assert_eq!(out, "*Title*\n\nbody");
    }

    #[test]
    fn slack_gfm_table_flattens_to_header_value_per_cell() {
        let out = slack()
            .format("| Fruit | Color |\n|-------|-------|\n| Apple | Red   |\n| Lime  | Green |");
        assert!(out.contains("Fruit: Apple"));
        assert!(out.contains("Color: Red"));
        assert!(out.contains("Fruit: Lime"));
        assert!(out.contains("Color: Green"));
        // No leftover pipe rows.
        for line in out.lines() {
            assert!(!line.trim_start().starts_with('|'), "leaked pipe: {line:?}");
        }
    }

    #[test]
    fn slack_bullet_list_becomes_round_bullets() {
        let out = slack().format("- one\n- two\n* three");
        assert_eq!(out, "• one\n• two\n• three");
    }

    #[test]
    fn slack_user_and_channel_mentions_pass_through_unchanged() {
        // Agents that emit `<@U12345>` / `<#C67890>` Slack handles
        // expect them to arrive verbatim. The link rewrite only
        // matches `[text](url)`, so raw angle-bracket forms are
        // outside its lookahead and survive.
        let input = "Hi <@U12345>, see <#C67890> for details.";
        let out = slack().format(input);
        assert_eq!(out, input);
    }

    #[test]
    fn slack_horizontal_rule_becomes_blank_line() {
        let out = slack().format("before\n---\nafter");
        assert!(out.contains("before"));
        assert!(out.contains("after"));
    }

    #[test]
    fn slack_triple_asterisk_bold_italic_collapses_to_bold() {
        let out = slack().format("That is ***critical*** to note.");
        assert_eq!(out, "That is *critical* to note.");
    }

    #[test]
    fn slack_empty_input_yields_empty_output() {
        assert_eq!(slack().format(""), "");
    }

    #[test]
    fn slack_non_ascii_text_preserved_verbatim() {
        // UTF-8 parity with the Signal formatter. Multi-byte
        // codepoints (smart quotes, em-dashes, accented characters,
        // emoji, Devanagari, CJK) survive the link-rewrite byte walk
        // intact.
        let input = "café — don't forget the apostrophe: “quote” 🦀";
        let out = slack().format(input);
        assert_eq!(out, input);
    }

    #[test]
    fn slack_devanagari_survives_link_rewrite() {
        let input = "देखें [डॉक्स](https://wirken.app/hi/docs).";
        let out = slack().format(input);
        assert_eq!(out, "देखें <https://wirken.app/hi/docs|डॉक्स>.");
    }

    #[test]
    fn slack_cjk_survives_heading_and_bold() {
        let input = "## 重要事项\n\nこれは **大切** です.";
        let out = slack().format(input);
        assert_eq!(out, "*重要事项*\n\nこれは *大切* です.");
    }

    #[test]
    fn slack_emoji_in_bullet_list_roundtrips() {
        let input = "- 🦀 first\n- 🚀 second";
        let out = slack().format(input);
        assert_eq!(out, "• 🦀 first\n• 🚀 second");
    }

    #[test]
    fn slack_full_message_round_trip() {
        // Representative LLM reply: heading, bold, inline code,
        // table, bullets, link. Locks in the integration shape.
        let input = "\
## Protein sources\n\
\n\
Common high-protein foods include **chicken breast**, `lentils`, and tofu.\n\
\n\
| Food          | Protein (g/100g) |\n\
|---------------|-----------------:|\n\
| Chicken breast| 31               |\n\
| Lentils       | 9                |\n\
\n\
- Prioritize variety.\n\
- See [the guide](https://example.com/protein) for more.\n\
";
        let out = slack().format(input);
        assert!(out.contains("*Protein sources*"));
        assert!(out.contains("*chicken breast*"));
        assert!(out.contains("`lentils`"), "inline code must be kept");
        assert!(out.contains("Food: Chicken breast"));
        assert!(out.contains("Protein (g/100g): 31"));
        assert!(out.contains("• Prioritize variety."));
        assert!(out.contains("<https://example.com/protein|the guide>"));
        for line in out.lines() {
            assert!(!line.trim_start().starts_with('|'), "leaked pipe: {line:?}");
        }
    }
}
