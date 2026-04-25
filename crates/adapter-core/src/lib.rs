//! Channel-specific outbound formatters.
//!
//! Agents emit markdown. Each channel has its own rendering dialect
//! (Signal: single-asterisk bold, no fenced blocks; Slack: mrkdwn;
//! Telegram: MarkdownV2 with escape rules; …). Rendering each dialect
//! in the agent core would couple it to every downstream channel. Keep
//! the agent channel-agnostic; adapters apply their own [`OutboundFormatter`]
//! on the way out.
//!
//! Scope: trait + [`PlainFormatter`] + [`SignalFormatter`] + [`SlackFormatter`]
//! + [`DiscordFormatter`] + [`TelegramFormatter`].
//!
//! [`TelegramFormatter`] emits HTML, not MarkdownV2, because the escape
//! surface is bounded (three characters: `<`, `>`, `&`) and the
//! converter shares structure with the Matrix HTML path. MarkdownV2's
//! escape table covers fifteen-plus characters and is the kind of
//! perfect-parser-over-hostile-input that fails silently on a single
//! missed character; HTML mode collapses that surface.
//!
//! The Matrix adapter still ships raw markdown. Its formatter is
//! tracked as a follow-up in #71.

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

/// Render markdown to Discord's flavor.
///
/// Discord renders a CommonMark-shaped subset natively, plus its own
/// `**bold**`, `_italic_`, `~~strike~~`, and `>` blockquote. Most of
/// the markdown vocabulary an agent emits passes through unchanged.
/// Concentrate work on the two things Discord *does not* render:
/// GFM tables (no native primitive — flatten to `header: value`) and
/// horizontal rules (collapse to a blank line).
///
/// - `# H` / `## H` / `### H` → kept verbatim (native heading support
///   landed in Discord 2023)
/// - `**x**` → kept (Discord reads double-asterisk as bold; this is
///   the *opposite* of the Signal/Slack collapse to single asterisk)
/// - `_x_` / `*x*` → kept
/// - `~~x~~` → kept (Discord strikethrough)
/// - `> x` → kept (Discord blockquote)
/// - `` `x` `` → kept
/// - Fenced code blocks ` ``` ` (with optional language tag) → kept
///   verbatim
/// - GFM tables → flattened to `header: value` lines per row
/// - Bullet / numbered lists → kept (Discord renders both natively)
/// - Links `[text](url)` → kept
/// - Mentions and channel refs (`<@id>`, `<#id>`) → kept (the link
///   rewrite that mangles `<…>` strings on Slack is absent here)
/// - Horizontal rules (`---`, `***`, `___`) → blank line (Discord
///   does not render an HR)
pub struct DiscordFormatter;

impl OutboundFormatter for DiscordFormatter {
    fn format(&self, markdown: &str) -> String {
        let mut out = String::with_capacity(markdown.len());
        let mut lines = markdown.lines().peekable();
        let mut in_code_fence = false;
        let mut table_header: Option<Vec<String>> = None;

        while let Some(line) = lines.next() {
            let trimmed = line.trim_end();

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

            // GFM tables only — Discord's other markdown vocabulary
            // is left alone above.
            if is_table_row(trimmed) {
                let cells = split_table_row(trimmed, &apply_inline_discord);
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

            // Default: pass the line through unchanged. Headings,
            // bold, italic, strikethrough, blockquote, lists, links,
            // and mentions all render in Discord as written.
            out.push_str(line);
            out.push('\n');
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

/// Discord inline pipeline: identity. Discord renders the markdown
/// the agent emits; the only block-level transform is table flatten,
/// which still needs an inline closure for `split_table_row` so cell
/// contents reach the output unmangled.
fn apply_inline_discord(line: &str) -> String {
    line.to_string()
}

/// Render markdown to Telegram's HTML mode.
///
/// Telegram bots accept either `MarkdownV2` or `HTML` as the message
/// `parse_mode`. We pick HTML because the escape surface is bounded
/// to three characters (`<`, `>`, `&`); MarkdownV2 escapes fifteen-
/// plus characters with strict positional rules and silently breaks
/// on one missed character of user content. HTML mode also shares
/// structure with the planned Matrix HTML path, so this converter is
/// reusable with a different tag whitelist.
///
/// Tag whitelist (per Telegram Bot API):
/// `<b>`, `<i>`, `<u>`, `<s>`, `<code>`, `<pre>`, `<blockquote>`,
/// `<a href="...">`. The agent's outbound message must arrive at the
/// adapter with `parse_mode = "HTML"` set on the send call —
/// `wirken-adapter-telegram` does that wiring on the consuming side.
///
/// - `# H` / `## H` / `### H` → `<b>H</b>` on its own line, blank line
///   following (Telegram has no native heading tag)
/// - `**x**` / `__x__` → `<b>x</b>`
/// - `*x*` / `_x_` → `<i>x</i>`
/// - `~~x~~` → `<s>x</s>`
/// - `` `x` `` → `<code>x</code>`
/// - Fenced code blocks ` ```lang ` → `<pre><code class="language-lang">…</code></pre>`
/// - Fenced code blocks ` ``` ` (no lang) → `<pre><code>…</code></pre>`
/// - GFM tables → flattened to `header: value` lines per row,
///   inline-formatted per cell
/// - Bullet lists `- ` / `* ` → `• ` (Telegram has no list primitive)
/// - Numbered lists → unchanged
/// - Links `[text](url)` → `<a href="url">text</a>`. URL `"` are
///   escaped to `&quot;` to keep the attribute sealed; `<>&` are
///   already escaped by the body pass.
/// - Blockquotes `> x` → `<blockquote>x</blockquote>`
/// - Horizontal rules → blank line
/// - Literal `<`, `>`, `&` in agent output → escaped to `&lt;`,
///   `&gt;`, `&amp;` (so an agent emitting `<script>` sends literal
///   text, not an injected tag)
pub struct TelegramFormatter;

impl OutboundFormatter for TelegramFormatter {
    fn format(&self, markdown: &str) -> String {
        let mut out = String::with_capacity(markdown.len());
        let mut lines = markdown.lines().peekable();
        let mut in_code_fence = false;
        let mut code_lang: Option<String> = None;
        let mut code_buf = String::new();
        let mut table_header: Option<Vec<String>> = None;

        while let Some(line) = lines.next() {
            let trimmed = line.trim_end();

            // Fenced code blocks: collect content into a buffer,
            // emit a single `<pre><code>` element on close. The
            // content is HTML-escaped on emit so `<`, `>`, `&` in
            // code reach Telegram as literals.
            if trimmed.trim_start().starts_with("```") {
                if !in_code_fence {
                    let lang = trimmed.trim_start().trim_start_matches('`').trim();
                    code_lang = if lang.is_empty() {
                        None
                    } else {
                        Some(lang.to_string())
                    };
                    code_buf.clear();
                    in_code_fence = true;
                } else {
                    out.push_str("<pre>");
                    match &code_lang {
                        Some(l) => {
                            out.push_str("<code class=\"language-");
                            out.push_str(&html_escape_attr(l));
                            out.push_str("\">");
                        }
                        None => out.push_str("<code>"),
                    }
                    // Strip the trailing newline added when buffering
                    // the last line so the closing tag sits on the
                    // same line as the final code line.
                    let body = code_buf.trim_end_matches('\n');
                    out.push_str(&html_escape(body));
                    out.push_str("</code></pre>\n");
                    in_code_fence = false;
                    code_lang = None;
                    code_buf.clear();
                }
                continue;
            }
            if in_code_fence {
                code_buf.push_str(line);
                code_buf.push('\n');
                continue;
            }

            if is_hr(trimmed) {
                out.push('\n');
                continue;
            }

            if let Some(stripped) = strip_heading(trimmed) {
                if !stripped.is_empty() {
                    out.push_str("<b>");
                    out.push_str(&apply_inline_telegram(stripped));
                    out.push_str("</b>");
                }
                out.push('\n');
                out.push('\n');
                continue;
            }

            if is_table_row(trimmed) {
                let cells = split_table_row(trimmed, &apply_inline_telegram);
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
                out.push_str(&apply_inline_telegram(rest));
                out.push('\n');
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("> ") {
                out.push_str("<blockquote>");
                out.push_str(&apply_inline_telegram(rest));
                out.push_str("</blockquote>\n");
                continue;
            }
            if trimmed == ">" {
                out.push_str("<blockquote></blockquote>\n");
                continue;
            }

            out.push_str(&apply_inline_telegram(line));
            out.push('\n');
        }

        // If a fence never closed (malformed input), flush whatever
        // we buffered as a plain code block. Better than dropping the
        // content silently.
        if in_code_fence && !code_buf.is_empty() {
            out.push_str("<pre><code>");
            out.push_str(&html_escape(code_buf.trim_end_matches('\n')));
            out.push_str("</code></pre>\n");
        }

        // Heading + a literal blank line in source markdown produces
        // three newlines; collapse to a paragraph break.
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

/// Telegram inline pipeline. Single-pass tokenizer over the
/// HTML-escaped input so that markdown markers inside an inline-code
/// span are NOT re-tokenized as bold/italic/etc. — a multi-pass
/// regex-style approach would mistake `*x*` inside ` ``...*x*...`` `
/// for italic.
///
/// Order of recognition at each cursor position:
/// 1. inline code (`` ` ``)
/// 2. link (`[`)
/// 3. bold (`**` or `__`)
/// 4. strikethrough (`~~`)
/// 5. italic (`*` or `_`, single-char, only when the closing marker
///    is not part of a doubled run)
///
/// Falls through to a UTF-8-safe codepoint copy when no marker
/// matches.
fn apply_inline_telegram(input: &str) -> String {
    let escaped = html_escape(input);
    let bytes = escaped.as_bytes();
    let mut out = String::with_capacity(escaped.len());
    let mut i = 0;
    while i < bytes.len() {
        // Inline code: ``…``  (single backtick, no nested backticks).
        if bytes[i] == b'`'
            && let Some(close) = find_byte(bytes, b'`', i + 1)
        {
            out.push_str("<code>");
            out.push_str(&escaped[i + 1..close]);
            out.push_str("</code>");
            i = close + 1;
            continue;
        }
        // Link: [text](url)
        if bytes[i] == b'['
            && let Some(close) = find_byte(bytes, b']', i + 1)
            && close + 1 < bytes.len()
            && bytes[close + 1] == b'('
            && let Some(paren_close) = find_byte(bytes, b')', close + 2)
        {
            let text = &escaped[i + 1..close];
            let url = &escaped[close + 2..paren_close];
            if url.is_empty() {
                out.push_str(text);
            } else {
                let url_attr = url.replace('"', "&quot;");
                out.push_str("<a href=\"");
                out.push_str(&url_attr);
                out.push_str("\">");
                out.push_str(if text.is_empty() { url } else { text });
                out.push_str("</a>");
            }
            i = paren_close + 1;
            continue;
        }
        // Bold: **x** or __x__
        if i + 1 < bytes.len()
            && (bytes[i] == b'*' || bytes[i] == b'_')
            && bytes[i + 1] == bytes[i]
            && let Some(close) = find_doubled(bytes, bytes[i], i + 2)
        {
            out.push_str("<b>");
            out.push_str(&escaped[i + 2..close]);
            out.push_str("</b>");
            i = close + 2;
            continue;
        }
        // Strikethrough: ~~x~~
        if i + 1 < bytes.len()
            && bytes[i] == b'~'
            && bytes[i + 1] == b'~'
            && let Some(close) = find_doubled(bytes, b'~', i + 2)
        {
            out.push_str("<s>");
            out.push_str(&escaped[i + 2..close]);
            out.push_str("</s>");
            i = close + 2;
            continue;
        }
        // Italic: *x* or _x_ (single-char). Only when neither the
        // opener nor the closer is part of a doubled run, to avoid
        // mis-pairing with leftover bold markers.
        if (bytes[i] == b'*' || bytes[i] == b'_')
            && (i + 1 >= bytes.len() || bytes[i + 1] != bytes[i])
            && let Some(close) = find_byte(bytes, bytes[i], i + 1)
            && close > i + 1
            && (close + 1 >= bytes.len() || bytes[close + 1] != bytes[i])
        {
            out.push_str("<i>");
            out.push_str(&escaped[i + 1..close]);
            out.push_str("</i>");
            i = close + 1;
            continue;
        }
        let next = next_char_boundary(&escaped, i);
        out.push_str(&escaped[i..next]);
        i = next;
    }
    out
}

/// Find the next position of two consecutive bytes equal to `c`.
/// Used to locate the closing `**`, `__`, or `~~` marker for the
/// Telegram inline tokenizer.
fn find_doubled(bytes: &[u8], c: u8, start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < bytes.len() {
        if bytes[i] == c && bytes[i + 1] == c {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Escape `<`, `>`, `&` in body text. These three characters carry
/// HTML semantics in Telegram's HTML parse mode; nothing else needs
/// escaping outside attribute contexts.
fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            other => out.push(other),
        }
    }
    out
}

/// Escape a value embedded in an HTML attribute. Same as
/// [`html_escape`] plus `"` → `&quot;` so quotation marks can't
/// terminate the attribute early. Used for `<code class="…">`
/// language hints; URL attribute escaping is handled inline at the
/// link-rewrite site so an empty/invalid URL does not produce a
/// dangling tag.
fn html_escape_attr(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    for c in input.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
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

    // -------- Discord formatter --------------------------------------

    fn discord() -> DiscordFormatter {
        DiscordFormatter
    }

    #[test]
    fn discord_double_asterisk_bold_is_kept() {
        // Opposite of Signal/Slack: Discord reads `**bold**` natively,
        // so the formatter must NOT collapse it to single asterisk.
        let out = discord().format("This is **bold** text.");
        assert_eq!(out, "This is **bold** text.");
    }

    #[test]
    fn discord_single_asterisk_italic_is_kept() {
        let out = discord().format("This is *italic* and _also italic_.");
        assert_eq!(out, "This is *italic* and _also italic_.");
    }

    #[test]
    fn discord_strikethrough_is_kept() {
        let out = discord().format("Was ~~important~~ now retired.");
        assert_eq!(out, "Was ~~important~~ now retired.");
    }

    #[test]
    fn discord_blockquote_is_kept() {
        let out = discord().format("> a quoted line\n> a second one");
        assert_eq!(out, "> a quoted line\n> a second one");
    }

    #[test]
    fn discord_inline_code_is_kept() {
        let out = discord().format("Use `cargo build` then `cargo test`.");
        assert_eq!(out, "Use `cargo build` then `cargo test`.");
    }

    #[test]
    fn discord_fenced_code_block_kept_with_language_tag() {
        let out = discord().format("```rust\nfn main() {}\n```");
        assert_eq!(out, "```rust\nfn main() {}\n```");
    }

    #[test]
    fn discord_headings_pass_through() {
        // Discord renders `# H` natively (since 2023). No rewrite.
        let out = discord().format("# Title\n## Sub\n### Deep");
        assert_eq!(out, "# Title\n## Sub\n### Deep");
    }

    #[test]
    fn discord_links_pass_through() {
        let out = discord().format("See [docs](https://wirken.app/docs).");
        assert_eq!(out, "See [docs](https://wirken.app/docs).");
    }

    #[test]
    fn discord_user_and_channel_mentions_pass_through_unchanged() {
        // Discord mentions arrive as `<@123>` / `<#456>`. The
        // formatter has no link-rewrite pass that would mangle the
        // angle-bracket form, so they survive intact.
        let input = "Hi <@123456789>, see <#987654321> for details.";
        let out = discord().format(input);
        assert_eq!(out, input);
    }

    #[test]
    fn discord_bullet_list_passes_through() {
        // Discord renders `- ` and `* ` as native list markers. Don't
        // rewrite to `•` like Signal/Slack do; that would break the
        // visual hierarchy in the rendered message.
        let out = discord().format("- one\n- two\n* three");
        assert_eq!(out, "- one\n- two\n* three");
    }

    #[test]
    fn discord_numbered_list_passes_through() {
        let out = discord().format("1. first\n2. second");
        assert_eq!(out, "1. first\n2. second");
    }

    #[test]
    fn discord_gfm_table_flattens_to_header_value_per_cell() {
        // Discord has no table primitive; flatten to `Header: value`
        // lines so the data is at least readable.
        let out = discord()
            .format("| Fruit | Color |\n|-------|-------|\n| Apple | Red   |\n| Lime  | Green |");
        assert!(out.contains("Fruit: Apple"));
        assert!(out.contains("Color: Red"));
        assert!(out.contains("Fruit: Lime"));
        assert!(out.contains("Color: Green"));
        for line in out.lines() {
            assert!(!line.trim_start().starts_with('|'), "leaked pipe: {line:?}");
        }
    }

    #[test]
    fn discord_horizontal_rule_becomes_blank_line() {
        // Discord does not render `---` as a horizontal rule. Drop
        // to a blank line so the surrounding paragraphs still have
        // visual separation.
        let out = discord().format("before\n---\nafter");
        assert!(out.contains("before"));
        assert!(out.contains("after"));
        assert!(!out.lines().any(|l| l.trim() == "---"));
    }

    #[test]
    fn discord_bold_inside_table_cell_survives_flatten() {
        // The flatten pass copies cell contents verbatim; markdown
        // inside cells must reach Discord intact so the rendered
        // `header: value` lines still show inline formatting.
        let out = discord().format("| Item | Note |\n|------|------|\n| **A** | first |");
        assert!(out.contains("Item: **A**"));
        assert!(out.contains("Note: first"));
    }

    #[test]
    fn discord_empty_input_yields_empty_output() {
        assert_eq!(discord().format(""), "");
    }

    #[test]
    fn discord_non_ascii_text_preserved_verbatim() {
        let input = "café — don't forget the apostrophe: “quote” 🦀";
        let out = discord().format(input);
        assert_eq!(out, input);
    }

    #[test]
    fn discord_devanagari_passes_through_links() {
        // No link rewrite for Discord, so the entire string is
        // identity-mapped. Locked in to catch any future regression
        // that adds a link transform without UTF-8 awareness.
        let input = "देखें [डॉक्स](https://wirken.app/hi/docs).";
        let out = discord().format(input);
        assert_eq!(out, input);
    }

    #[test]
    fn discord_cjk_in_heading_passes_through() {
        let input = "## 重要事项\n\nこれは **大切** です.";
        let out = discord().format(input);
        assert_eq!(out, input);
    }

    #[test]
    fn discord_emoji_in_bullet_list_passes_through() {
        let input = "- 🦀 first\n- 🚀 second";
        let out = discord().format(input);
        assert_eq!(out, input);
    }

    #[test]
    fn discord_full_message_round_trip() {
        // Same shape as the Slack/Signal end-to-end test: heading,
        // bold, inline code, table, bullets, link. Locks in that
        // Discord keeps everything except tables.
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
        let out = discord().format(input);
        assert!(out.contains("## Protein sources"));
        assert!(out.contains("**chicken breast**"));
        assert!(out.contains("`lentils`"));
        assert!(out.contains("Food: Chicken breast"));
        assert!(out.contains("Protein (g/100g): 31"));
        assert!(out.contains("- Prioritize variety."));
        assert!(out.contains("[the guide](https://example.com/protein)"));
        for line in out.lines() {
            assert!(!line.trim_start().starts_with('|'), "leaked pipe: {line:?}");
        }
    }

    // -------- Telegram formatter -------------------------------------

    fn tg() -> TelegramFormatter {
        TelegramFormatter
    }

    #[test]
    fn telegram_html_special_chars_in_text_are_escaped() {
        // Agent emits a literal `<script>` tag in a reply; output
        // must be inert (rendered as text), not injected.
        let out = tg().format("<script>alert(1)</script>");
        assert_eq!(out, "&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    #[test]
    fn telegram_ampersand_in_text_is_escaped() {
        let out = tg().format("R&D budget");
        assert_eq!(out, "R&amp;D budget");
    }

    #[test]
    fn telegram_bold_double_asterisk() {
        let out = tg().format("This is **bold** text.");
        assert_eq!(out, "This is <b>bold</b> text.");
    }

    #[test]
    fn telegram_bold_double_underscore() {
        let out = tg().format("This is __bold__ text.");
        assert_eq!(out, "This is <b>bold</b> text.");
    }

    #[test]
    fn telegram_italic_single_asterisk_and_underscore() {
        let out = tg().format("Maybe *italic* or _italic_.");
        assert_eq!(out, "Maybe <i>italic</i> or <i>italic</i>.");
    }

    #[test]
    fn telegram_strikethrough() {
        let out = tg().format("Was ~~important~~ now retired.");
        assert_eq!(out, "Was <s>important</s> now retired.");
    }

    #[test]
    fn telegram_inline_code() {
        let out = tg().format("Use `cargo build`.");
        assert_eq!(out, "Use <code>cargo build</code>.");
    }

    #[test]
    fn telegram_inline_code_shields_inner_markdown() {
        // Critical correctness: `*foo*` inside a code span must NOT
        // be re-tokenized as italic. The single-pass tokenizer
        // consumes the code span first and skips its contents.
        let out = tg().format("Avoid `*foo*` rendering as italic.");
        assert_eq!(out, "Avoid <code>*foo*</code> rendering as italic.");
    }

    #[test]
    fn telegram_inline_code_with_html_special_chars_escaped() {
        // The body-escape pass runs before tokenization, so `<` and
        // `>` inside backticks reach Telegram as `&lt;` / `&gt;`
        // wrapped in <code>.
        let out = tg().format("Pattern: `<int>`");
        assert_eq!(out, "Pattern: <code>&lt;int&gt;</code>");
    }

    #[test]
    fn telegram_fenced_code_block_with_language_tag() {
        let out = tg().format("```rust\nfn main() {}\n```");
        assert_eq!(
            out,
            "<pre><code class=\"language-rust\">fn main() {}</code></pre>"
        );
    }

    #[test]
    fn telegram_fenced_code_block_without_language_tag() {
        let out = tg().format("```\nplain text\n```");
        assert_eq!(out, "<pre><code>plain text</code></pre>");
    }

    #[test]
    fn telegram_fenced_code_block_escapes_html_in_content() {
        // Code blocks frequently contain `<` and `>`. Those must be
        // escaped on emit; otherwise the bot API rejects the message
        // for malformed HTML.
        let out = tg().format("```\nif x < y && y > 0 { ok }\n```");
        assert_eq!(
            out,
            "<pre><code>if x &lt; y &amp;&amp; y &gt; 0 { ok }</code></pre>"
        );
    }

    #[test]
    fn telegram_unclosed_fence_still_emits_a_code_block() {
        // Defense against malformed input from the agent. Better to
        // ship the partial body wrapped in <pre><code> than to drop
        // it from the buffer.
        let out = tg().format("```\nhalf finished\n");
        assert_eq!(out, "<pre><code>half finished</code></pre>");
    }

    #[test]
    fn telegram_links_use_anchor_tag() {
        let out = tg().format("See [docs](https://wirken.app/docs).");
        assert_eq!(out, "See <a href=\"https://wirken.app/docs\">docs</a>.");
    }

    #[test]
    fn telegram_link_url_with_ampersand_is_attribute_safe() {
        // `&` in the URL gets `&amp;` from the body-escape pass; that
        // is the correct HTML attribute encoding, so the anchor
        // attribute remains valid.
        let out = tg().format("[search](https://example.com/?a=b&c=d)");
        assert_eq!(
            out,
            "<a href=\"https://example.com/?a=b&amp;c=d\">search</a>"
        );
    }

    #[test]
    fn telegram_link_url_with_quote_is_attribute_safe() {
        // `"` is not in the body-escape set, so the link rewrite
        // adds an attribute-context escape. Without this, a URL
        // containing `"` would close the href= attribute early and
        // leak the rest as injected attributes.
        let out = tg().format(r#"[x](https://e.com/")"#);
        assert_eq!(out, r#"<a href="https://e.com/&quot;">x</a>"#);
    }

    #[test]
    fn telegram_link_with_empty_url_falls_back_to_text() {
        let out = tg().format("[orphan]()");
        assert_eq!(out, "orphan");
    }

    #[test]
    fn telegram_link_with_empty_text_uses_url_as_label() {
        let out = tg().format("[](https://wirken.app)");
        assert_eq!(out, "<a href=\"https://wirken.app\">https://wirken.app</a>");
    }

    #[test]
    fn telegram_headings_become_bold_with_blank_line_after() {
        let out = tg().format("# Title\nbody");
        assert_eq!(out, "<b>Title</b>\n\nbody");
    }

    #[test]
    fn telegram_blockquote_is_native_tag() {
        let out = tg().format("> a quoted line\n> a second one");
        assert_eq!(
            out,
            "<blockquote>a quoted line</blockquote>\n<blockquote>a second one</blockquote>"
        );
    }

    #[test]
    fn telegram_bullet_list_becomes_round_bullets() {
        // Telegram HTML mode has no list primitive; render with `•`
        // for visual consistency with Signal/Slack.
        let out = tg().format("- one\n- two\n* three");
        assert_eq!(out, "• one\n• two\n• three");
    }

    #[test]
    fn telegram_numbered_list_passes_through() {
        let out = tg().format("1. first\n2. second");
        assert_eq!(out, "1. first\n2. second");
    }

    #[test]
    fn telegram_horizontal_rule_becomes_blank_line() {
        let out = tg().format("before\n---\nafter");
        assert!(out.contains("before"));
        assert!(out.contains("after"));
        assert!(!out.lines().any(|l| l.trim() == "---"));
    }

    #[test]
    fn telegram_gfm_table_flattens_with_html_escaped_cells() {
        let out = tg()
            .format("| Fruit | Color |\n|-------|-------|\n| Apple | Red   |\n| Lime  | Green |");
        assert!(out.contains("Fruit: Apple"));
        assert!(out.contains("Color: Red"));
        for line in out.lines() {
            assert!(!line.trim_start().starts_with('|'), "leaked pipe: {line:?}");
        }
    }

    #[test]
    fn telegram_table_cell_with_html_chars_is_escaped() {
        // Defense against an agent that produces a table cell
        // containing literal `<` or `>`. The cell content goes
        // through `apply_inline_telegram` which escapes first, so
        // the flatten emits safe text.
        let out = tg().format("| Tag | Form |\n|-----|------|\n| open | <b> |");
        assert!(
            out.contains("Form: &lt;b&gt;"),
            "unexpected output: {out:?}"
        );
    }

    #[test]
    fn telegram_empty_input_yields_empty_output() {
        assert_eq!(tg().format(""), "");
    }

    #[test]
    fn telegram_non_ascii_text_preserved_verbatim() {
        let input = "café — don't forget the apostrophe: “quote” 🦀";
        let out = tg().format(input);
        assert_eq!(out, input);
    }

    #[test]
    fn telegram_devanagari_survives_link_rewrite() {
        let input = "देखें [डॉक्स](https://wirken.app/hi/docs).";
        let out = tg().format(input);
        assert_eq!(out, "देखें <a href=\"https://wirken.app/hi/docs\">डॉक्स</a>.");
    }

    #[test]
    fn telegram_cjk_in_heading_and_bold() {
        let input = "## 重要事项\n\nこれは **大切** です.";
        let out = tg().format(input);
        assert_eq!(out, "<b>重要事项</b>\n\nこれは <b>大切</b> です.");
    }

    #[test]
    fn telegram_emoji_in_bullet_list() {
        let input = "- 🦀 first\n- 🚀 second";
        let out = tg().format(input);
        assert_eq!(out, "• 🦀 first\n• 🚀 second");
    }

    #[test]
    fn telegram_full_message_round_trip() {
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
        let out = tg().format(input);
        assert!(out.contains("<b>Protein sources</b>"));
        assert!(out.contains("<b>chicken breast</b>"));
        assert!(out.contains("<code>lentils</code>"));
        assert!(out.contains("Food: Chicken breast"));
        assert!(out.contains("Protein (g/100g): 31"));
        assert!(out.contains("• Prioritize variety."));
        assert!(out.contains("<a href=\"https://example.com/protein\">the guide</a>"));
        for line in out.lines() {
            assert!(!line.trim_start().starts_with('|'), "leaked pipe: {line:?}");
        }
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
