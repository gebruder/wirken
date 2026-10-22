//! Light Markdown for the agent's replies: `#` headings, `-`, `*` and
//! `+` bullets, numbered items, fenced code, tables, rules (`---`),
//! `inline code`, **bold**, *italics* and [links](url). Anything else is
//! text, shown as written. A marker is read as one only when its closer
//! is on the same line, so `2 ** 3` or a lone backtick stays as typed,
//! and `_` marks italics only at the edges of a word, so `snake_case`
//! does not. A link keeps its address on screen, after its text.
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
    let source: Vec<&str> = text.split('\n').collect();
    let mut lines = Vec::new();
    let mut fenced = false;
    let mut at = 0;
    while let Some(raw) = source.get(at).copied() {
        at += 1;
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
        if is_table_row(line) && source.get(at).is_some_and(|next| is_delimiter_row(next)) {
            let mut rows = vec![cells(line)];
            at += 1;
            while let Some(next) = source.get(at).map(|l| l.trim_start()) {
                if !is_table_row(next) {
                    break;
                }
                rows.push(cells(next));
                at += 1;
            }
            lines.extend(table(&rows, cols));
            continue;
        }
        if is_rule(line) {
            lines.push(Line::styled("─".repeat(cols), rule_style()));
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

/// `---`, `***` or `___`, three or more, spaces allowed between.
fn is_rule(line: &str) -> bool {
    let marks: Vec<char> = line.chars().filter(|c| !c.is_whitespace()).collect();
    marks.len() >= 3
        && matches!(marks.first(), Some('-' | '*' | '_'))
        && marks.iter().all(|c| Some(c) == marks.first())
}

/// A row of a pipe table: `| a | b |`.
fn is_table_row(line: &str) -> bool {
    line.starts_with('|') && line.trim_end().len() > 1
}

/// The row under a table's header: `|---|:--:|`.
fn is_delimiter_row(line: &str) -> bool {
    let line = line.trim();
    is_table_row(line)
        && cells(line).iter().all(|cell| {
            let dashes = cell.trim_matches(':');
            !dashes.is_empty() && dashes.chars().all(|c| c == '-')
        })
}

/// A table row's cells, trimmed, without the outer pipes.
fn cells(line: &str) -> Vec<&str> {
    let line = line.trim();
    let line = line.strip_prefix('|').unwrap_or(line);
    let line = line.strip_suffix('|').unwrap_or(line);
    line.split('|').map(str::trim).collect()
}

/// A table in columns: each as wide as its widest cell, or, when the
/// table is wider than `cols`, a share of the width with its cells
/// wrapped. The header is bold and ruled off from the body. Too narrow
/// for even that, each row is one line with its cells apart.
fn table(rows: &[Vec<&str>], cols: usize) -> Vec<Line<'static>> {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let n = rows.iter().map(Vec::len).max().unwrap_or(0);
    let runs: Vec<Vec<Vec<(String, Style)>>> = rows
        .iter()
        .enumerate()
        .map(|(r, row)| {
            let base = if r == 0 { bold } else { Style::default() };
            (0..n)
                .map(|c| inline(row.get(c).copied().unwrap_or(""), base))
                .collect()
        })
        .collect();
    let natural: Vec<usize> = (0..n)
        .map(|c| {
            runs.iter()
                .map(|row| row.get(c).map_or(0, |cell| width(&plain_text(cell))))
                .max()
                .unwrap_or(0)
                .max(1)
        })
        .collect();
    let sep = || Span::styled(" │ ", rule_style());
    let Some(widths) = shares(&natural, cols.saturating_sub(3 * n.saturating_sub(1))) else {
        return runs
            .iter()
            .flat_map(|row| {
                let mut joined: Vec<(String, Style)> = Vec::new();
                for (c, cell) in row.iter().enumerate() {
                    if c > 0 {
                        joined.push((" │ ".to_string(), rule_style()));
                    }
                    joined.extend(cell.iter().cloned());
                }
                styled(&joined, cols).into_iter().map(Line::from)
            })
            .collect();
    };
    let mut lines = Vec::new();
    for (r, row) in runs.iter().enumerate() {
        let wrapped: Vec<Vec<Vec<Span<'static>>>> = row
            .iter()
            .zip(&widths)
            .map(|(cell, w)| styled(cell, *w))
            .collect();
        let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
        for k in 0..height {
            let mut spans = Vec::new();
            for (c, (cell, w)) in wrapped.iter().zip(&widths).enumerate() {
                if c > 0 {
                    spans.push(sep());
                }
                let part = cell.get(k).cloned().unwrap_or_default();
                let used: usize = part.iter().map(|s| width(&s.content)).sum();
                spans.extend(part);
                if c + 1 < n {
                    spans.push(Span::raw(" ".repeat(w.saturating_sub(used))));
                }
            }
            lines.push(Line::from(spans));
        }
        if r == 0 {
            let rule: Vec<String> = widths.iter().map(|w| "─".repeat(*w)).collect();
            lines.push(Line::styled(rule.join("─┼─"), rule_style()));
        }
    }
    lines
}

/// Column widths that fit `room`: every column its natural width when
/// all fit; otherwise the narrow columns keep theirs and the rest share
/// what is left evenly. `None` when `room` cannot give each column a
/// few cells.
fn shares(natural: &[usize], room: usize) -> Option<Vec<usize>> {
    const NARROWEST: usize = 4;
    if room < NARROWEST * natural.len() {
        return None;
    }
    let mut widths = natural.to_vec();
    if natural.iter().sum::<usize>() <= room {
        return Some(widths);
    }
    let mut order: Vec<usize> = (0..natural.len()).collect();
    order.sort_by_key(|c| natural.get(*c).copied().unwrap_or(0));
    let mut left = room;
    for (k, c) in order.iter().enumerate() {
        let share = left / (order.len() - k);
        if let (Some(w), Some(want)) = (widths.get_mut(*c), natural.get(*c)) {
            *w = (*want).min(share);
            left -= *w;
        }
    }
    Some(widths)
}

fn plain_text(runs: &[(String, Style)]) -> String {
    runs.iter().map(|(text, _)| text.as_str()).collect()
}

/// `body` split into styled runs at its `code`, **bold**, *italic* and
/// [link](url) markers, the markers dropped. Text outside them is in
/// `base`.
fn inline(body: &str, base: Style) -> Vec<(String, Style)> {
    let chars: Vec<char> = body.chars().collect();
    let mut runs: Vec<(String, Style)> = Vec::new();
    let mut push = |text: &str, style: Style| match runs.last_mut() {
        Some((run, s)) if *s == style => run.push_str(text),
        _ => runs.push((text.to_string(), style)),
    };
    let (mut code, mut bold) = (false, false);
    // The marker that opened the italics, `*` or `_`.
    let mut italic: Option<char> = None;
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        let rest = chars.get(at + 1..).unwrap_or_default();
        if c == '`' && (code || rest.contains(&'`')) {
            code = !code;
            at += 1;
            continue;
        }
        if !code {
            if c == '*'
                && rest.first() == Some(&'*')
                && (bold
                    || rest
                        .get(1..)
                        .unwrap_or_default()
                        .windows(2)
                        .any(|w| w == ['*', '*']))
            {
                bold = !bold;
                at += 2;
                continue;
            }
            if c == '['
                && let Some((text, url, end)) = link(&chars, at)
            {
                for (part, style) in inline(&text, base.add_modifier(Modifier::UNDERLINED)) {
                    push(&part, style);
                }
                if url != text {
                    push(&format!(" ({url})"), rule_style());
                }
                at = end;
                continue;
            }
            if (c == '*' || c == '_') && emphasis(&chars, at, italic) {
                italic = if italic.is_some() { None } else { Some(c) };
                at += 1;
                continue;
            }
        }
        let style = if code {
            code_style()
        } else {
            let mut style = base;
            if bold {
                style = style.add_modifier(Modifier::BOLD);
            }
            if italic.is_some() {
                style = style.add_modifier(Modifier::ITALIC);
            }
            style
        };
        push(c.encode_utf8(&mut [0u8; 4]), style);
        at += 1;
    }
    runs
}

/// `[text](url)` starting at `at`: its text, its address and the index
/// after it. The address has no spaces, and neither part is empty.
fn link(chars: &[char], at: usize) -> Option<(String, String, usize)> {
    let close = at + 1 + chars.get(at + 1..)?.iter().position(|c| *c == ']')?;
    if chars.get(close + 1) != Some(&'(') {
        return None;
    }
    let end = close + 2 + chars.get(close + 2..)?.iter().position(|c| *c == ')')?;
    let text: String = chars.get(at + 1..close)?.iter().collect();
    let url: String = chars.get(close + 2..end)?.iter().collect();
    (!text.trim().is_empty() && !url.is_empty() && !url.contains(char::is_whitespace)).then_some((
        text,
        url,
        end + 1,
    ))
}

/// Whether the `*` or `_` at `at` opens or closes italics. It closes
/// what the same character opened, after a non-space; it opens before a
/// non-space when a closer follows on the line. A doubled marker is
/// neither, and `_` counts only at the edge of a word, so `snake_case`
/// and `__init__` are text.
fn emphasis(chars: &[char], at: usize, open: Option<char>) -> bool {
    let Some(&c) = chars.get(at) else {
        return false;
    };
    let at_ = |i: Option<usize>| i.and_then(|i| chars.get(i)).copied();
    let word = |i: Option<usize>| at_(i).is_some_and(char::is_alphanumeric);
    let closes = |i: usize| {
        let (before, after) = (at_(i.checked_sub(1)), at_(Some(i + 1)));
        chars.get(i) == Some(&c)
            && before.is_some_and(|b| !b.is_whitespace() && b != c)
            && after != Some(c)
            && (c != '_' || !word(Some(i + 1)))
    };
    match open {
        Some(opened) => opened == c && closes(at),
        None => {
            at_(Some(at + 1)).is_some_and(|a| !a.is_whitespace() && a != c)
                && at_(at.checked_sub(1)) != Some(c)
                && (c != '_' || !word(at.checked_sub(1)))
                && (at + 2..chars.len()).any(closes)
        }
    }
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
        for typed in [
            "2 ** 3 = 8",
            "a ` b",
            "`",
            "**",
            "x ** `y",
            "2 * 3 * 4",
            "a *b",
            "[1] and [x] (y)",
            "[text](with space)",
        ] {
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
    fn italics_mark_words_and_leave_snake_case_alone() {
        let lines = render("*one* and _two_ but snake_case_name and __init__", 60);
        assert_eq!(
            plain(&lines),
            ["one and two but snake_case_name and __init__"]
        );
        for word in ["one", "two"] {
            assert!(
                style_of(&lines, word)
                    .add_modifier
                    .contains(Modifier::ITALIC),
                "{word}"
            );
        }
    }

    #[test]
    fn a_link_keeps_its_address_after_its_text() {
        let lines = render(
            "see [the `log` page](https://ss64.com/mac/log.html) now",
            80,
        );
        assert_eq!(
            plain(&lines),
            ["see the log page (https://ss64.com/mac/log.html) now"]
        );
        assert!(
            style_of(&lines, "the ")
                .add_modifier
                .contains(Modifier::UNDERLINED)
        );
        assert_eq!(style_of(&lines, "log"), code_style());
        assert_eq!(
            style_of(&lines, " (https://ss64.com/mac/log.html)"),
            rule_style()
        );
        // An address shown as its own text is shown once.
        assert_eq!(
            plain(&render("[https://a.example](https://a.example)", 40)),
            ["https://a.example"]
        );
    }

    #[test]
    fn a_rule_is_a_line_across() {
        for rule in ["---", "***", "_ _ _", "-----"] {
            let lines = render(rule, 12);
            assert_eq!(plain(&lines), ["─".repeat(12)], "{rule:?}");
            assert_eq!(lines[0].style, rule_style());
        }
        assert_eq!(plain(&render("--", 12)), ["--"]);
        assert_eq!(plain(&render("-*-", 12)), ["-*-"]);
    }

    #[test]
    fn a_table_lines_its_columns_up_under_a_bold_header() {
        let text =
            "| Tool | Use |\n|---|:--|\n| `log stream` | live, **filtered** |\n| grep | search |";
        let lines = render(text, 60);
        assert_eq!(
            plain(&lines),
            [
                "Tool       │ Use",
                &format!("{}─┼─{}", "─".repeat(10), "─".repeat(14)),
                "log stream │ live, filtered",
                "grep       │ search",
            ]
        );
        assert!(
            style_of(&lines, "Tool")
                .add_modifier
                .contains(Modifier::BOLD)
        );
        assert_eq!(style_of(&lines, "log stream"), code_style());
        assert!(
            style_of(&lines, "filtered")
                .add_modifier
                .contains(Modifier::BOLD)
        );
        assert_eq!(style_of(&lines, " │ "), rule_style());
        // A row of pipes with no delimiter under it is not a table.
        assert_eq!(plain(&render("| a | b |", 40)), ["| a | b |"]);
    }

    #[test]
    fn a_table_wider_than_the_screen_wraps_its_cells() {
        let text = "| Command | What it does |\n|---|---|\n\
                    | tail -f | follows a file as it grows, printing new lines |\n\
                    | log stream | streams the unified log live |";
        for cols in [24, 30, 41] {
            let lines = render(text, cols);
            for line in &lines {
                let w: usize = line.spans.iter().map(|s| width(&s.content)).sum();
                assert!(w <= cols, "{w} > {cols}: {line:?}");
            }
            let kept: String = plain(&lines).concat().replace([' ', '│', '─', '┼'], "");
            assert_eq!(
                kept,
                "CommandWhatitdoestail-ffollowsafileasitgrows,printingnewlineslogstreamstreamstheunifiedloglive",
                "at {cols}"
            );
        }
        // Too narrow for columns, each row is one line, cells apart.
        assert_eq!(
            plain(&render("| a | b | c |\n|---|---|---|\n| 1 | 2 | 3 |", 12)),
            ["a │ b │ c", "1 │ 2 │ 3"]
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
