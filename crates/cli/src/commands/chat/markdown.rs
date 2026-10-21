//! Light Markdown for the agent's replies: `#` headings, `-`, `*` and
//! `+` bullets, numbered items, fenced code, `inline code` and
//! **bold**. Anything else is text, shown as written. A marker is read
//! as one only when its closer is on the same line, so `2 ** 3` or a
//! lone backtick stays as typed.
//!
//! The text arrives sanitized and the rows are laid out by [`wrap`], so
//! this module decides markers and styles and nothing else.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_segmentation::UnicodeSegmentation;

use super::text::{width, wrap};

fn code_style() -> Style {
    Style::default().fg(Color::LightBlue)
}

/// The rule beside a code block, and its language label.
fn rule_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

/// `text`, already sanitized, as rows of at most `cols` cells.
pub(crate) fn render(text: &str, cols: usize) -> Vec<Line<'static>> {
    let cols = cols.max(1);
    let mut lines = Vec::new();
    let mut fenced = false;
    for raw in text.split('\n') {
        let line = raw.trim_start();
        if let Some(lang) = line.strip_prefix("```") {
            fenced = !fenced;
            if fenced && !lang.trim().is_empty() {
                lines.push(code_row(lang.trim().to_string(), rule_style()));
            }
            continue;
        }
        if fenced {
            // As written, indentation and all: it is part of the code.
            for row in wrap(raw, cols.saturating_sub(2)) {
                lines.push(code_row(row, code_style()));
            }
            continue;
        }
        if let Some(title) = heading(line) {
            let bold = Style::default().add_modifier(Modifier::BOLD);
            lines.extend(
                styled(&inline(title, bold), cols)
                    .into_iter()
                    .map(Line::from),
            );
            continue;
        }
        let (marker, body) = list_marker(line).unwrap_or((String::new(), line));
        // An indent past half the width is drawn as half, so the text
        // after it always has room.
        let indent = (width(raw) - width(line)).min(cols / 2);
        let lead = format!("{}{marker}", " ".repeat(indent));
        let room = cols.saturating_sub(width(&lead));
        for (i, mut spans) in styled(&inline(body, Style::default()), room)
            .into_iter()
            .enumerate()
        {
            let pad = if i == 0 {
                lead.clone()
            } else {
                " ".repeat(width(&lead))
            };
            spans.insert(0, Span::raw(pad));
            lines.push(Line::from(spans));
        }
    }
    lines
}

/// One row of a code block, behind its rule.
fn code_row(text: String, style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled("│ ", rule_style()),
        Span::styled(text, style),
    ])
}

/// `## Title` to `Title`, for one to six `#`.
fn heading(line: &str) -> Option<&str> {
    let hashes = line.bytes().take_while(|b| *b == b'#').count();
    if (1..=6).contains(&hashes) {
        line.get(hashes..)?.strip_prefix(' ')
    } else {
        None
    }
}

/// `- x`, `* x` and `+ x` become `• x`; `12. x` keeps its number.
fn list_marker(line: &str) -> Option<(String, &str)> {
    for bullet in ["- ", "* ", "+ "] {
        if let Some(body) = line.strip_prefix(bullet) {
            return Some(("• ".to_string(), body));
        }
    }
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let body = line.get(digits..)?.strip_prefix(". ")?;
    Some((format!("{}. ", line.get(..digits)?), body))
}

/// `body` split into styled runs at its `code` and **bold** markers,
/// the markers dropped. Text outside both is in `base`.
fn inline(body: &str, base: Style) -> Vec<(String, Style)> {
    let mut runs: Vec<(String, Style)> = Vec::new();
    let (mut code, mut bold) = (false, false);
    let mut rest = body;
    loop {
        let mut chars = rest.chars();
        let Some(c) = chars.next() else { break };
        let after = chars.as_str();
        if c == '`' && (code || after.contains('`')) {
            code = !code;
            rest = after;
            continue;
        }
        if !code
            && let Some(after) = rest.strip_prefix("**")
            && (bold || after.contains("**"))
        {
            bold = !bold;
            rest = after;
            continue;
        }
        let style = if code {
            code_style()
        } else if bold {
            base.add_modifier(Modifier::BOLD)
        } else {
            base
        };
        match runs.last_mut() {
            Some((text, s)) if *s == style => text.push(c),
            _ => runs.push((c.to_string(), style)),
        }
        rest = after;
    }
    runs
}

/// `runs` in rows of at most `cols` cells, laid out by [`wrap`], each
/// grapheme in its run's style. `wrap` leaves out only spaces, where it
/// breaks a row, so walking the runs and passing over what a row lacks
/// finds each grapheme's style. The text is always the row's: should
/// the walk lose its place, the rest of the line is plain, never lost.
fn styled(runs: &[(String, Style)], cols: usize) -> Vec<Vec<Span<'static>>> {
    let plain: String = runs.iter().map(|(text, _)| text.as_str()).collect();
    let mut styles = runs
        .iter()
        .flat_map(|(text, style)| text.graphemes(true).map(move |g| (g, *style)));
    wrap(&plain, cols)
        .into_iter()
        .map(|row| {
            let mut spans: Vec<Span<'static>> = Vec::new();
            for g in row.graphemes(true) {
                let style = styles
                    .by_ref()
                    .find(|(run, _)| *run == g)
                    .map_or_else(Style::default, |(_, style)| style);
                match spans.last_mut() {
                    Some(span) if span.style == style => span.content.to_mut().push_str(g),
                    _ => spans.push(Span::styled(g.to_string(), style)),
                }
            }
            spans
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(lines: &[Line<'_>]) -> Vec<String> {
        lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    fn style_of(lines: &[Line<'_>], text: &str) -> Style {
        lines
            .iter()
            .flat_map(|l| &l.spans)
            .find(|s| s.content == text)
            .unwrap_or_else(|| panic!("{text:?} is not a span of {lines:?}"))
            .style
    }

    #[test]
    fn inline_code_and_bold_lose_their_markers_and_keep_their_style() {
        let lines = render("run `ls -la` **now**", 40);
        assert_eq!(plain(&lines), ["run ls -la now"]);
        assert_eq!(style_of(&lines, "ls -la"), code_style());
        assert!(
            style_of(&lines, "now")
                .add_modifier
                .contains(Modifier::BOLD)
        );
    }

    #[test]
    fn a_marker_without_its_closer_is_text() {
        for typed in ["2 ** 3 = 8", "a ` b", "`", "**", "x ** `y"] {
            assert_eq!(plain(&render(typed, 40)), [typed], "{typed:?}");
        }
    }

    #[test]
    fn bullets_become_dots_with_a_hanging_indent() {
        assert_eq!(
            plain(&render("- one two three four", 12)),
            ["• one two", "  three four"]
        );
        assert_eq!(plain(&render("* a\n+ b", 12)), ["• a", "• b"]);
        assert_eq!(
            plain(&render("  - nested item here", 13)),
            ["  • nested", "    item here"]
        );
    }

    #[test]
    fn numbered_items_keep_their_number() {
        assert_eq!(
            plain(&render("12. twelfth item", 12)),
            ["12. twelfth", "    item"]
        );
        assert_eq!(
            plain(&render("3.5 is not a list", 40)),
            ["3.5 is not a list"]
        );
    }

    #[test]
    fn headings_drop_their_hashes_and_are_bold() {
        let lines = render("## Summary of `ls`", 40);
        assert_eq!(plain(&lines), ["Summary of ls"]);
        assert!(
            style_of(&lines, "Summary of ")
                .add_modifier
                .contains(Modifier::BOLD)
        );
        assert_eq!(style_of(&lines, "ls"), code_style());
        assert_eq!(plain(&render("#hashtag", 40)), ["#hashtag"]);
        assert_eq!(plain(&render("####### seven", 40)), ["####### seven"]);
    }

    #[test]
    fn fenced_code_is_shown_as_written_behind_a_rule() {
        let lines = render("```bash\n  echo **not bold** `x`\n```\nafter", 40);
        assert_eq!(
            plain(&lines),
            ["│ bash", "│   echo **not bold** `x`", "after"]
        );
        assert_eq!(style_of(&lines, "bash"), rule_style());
        assert_eq!(style_of(&lines, "  echo **not bold** `x`"), code_style());
        // A long code line is wrapped, not cut: nothing in it is hidden.
        let long = render("```\nfind . -name '*.log' -delete\n```", 16);
        let shown: String = plain(&long).concat().replace(['│', ' '], "");
        assert_eq!(shown, "find.-name'*.log'-delete");
    }

    #[test]
    fn an_unclosed_fence_runs_to_the_end_while_the_reply_streams() {
        assert_eq!(
            plain(&render("look:\n```\n- not a bullet", 40)),
            ["look:", "│ - not a bullet"]
        );
    }

    #[test]
    fn rows_stay_inside_the_width_and_no_text_is_lost() {
        let text = "## 世界 heading\n- **bold 世界 words** and `code 🙂 here` \
                    then a verylongwordthatneverfits and more\n\n1. 終わり";
        for cols in [8, 13, 21, 40] {
            let lines = render(text, cols);
            for line in &lines {
                let w: usize = line.spans.iter().map(|s| width(&s.content)).sum();
                assert!(w <= cols, "{w} > {cols}: {line:?}");
            }
            let kept: String = plain(&lines).concat().replace([' ', '•'], "");
            let want = "世界heading**bold世界words**and`code🙂here`thenaverylongwordthatneverfitsandmore1.終わり"
                .replace(['*', '`'], "");
            assert_eq!(kept, want, "at {cols}");
        }
    }
}
