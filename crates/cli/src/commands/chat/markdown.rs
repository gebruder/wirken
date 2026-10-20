//! Light markdown for replies: headings, bullets, numbered items, fenced
//! code, `inline code` and **bold**. Anything else is text. Works on
//! characters, never on byte offsets.

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use super::wrap;

pub(crate) struct Styles {
    pub text: Style,
    pub code: Style,
    /// The left rule and label of a fenced block.
    pub rule: Style,
    pub bold: Style,
    pub heading: Style,
    pub marker: Style,
}

/// `wrap_code` wraps long code lines; otherwise they are cut with `→`,
/// so a block keeps its shape.
pub(crate) fn render(text: &str, width: usize, s: &Styles, wrap_code: bool) -> Vec<Line<'static>> {
    let width = width.max(8);
    let mut out = Vec::new();
    let mut fenced = false;
    for raw in text.split('\n') {
        let indent: String = raw.chars().take_while(|c| *c == ' ').collect();
        let line = raw.trim_start();
        if let Some(lang) = line.strip_prefix("```") {
            fenced = !fenced;
            let lang = lang.trim();
            if fenced && !lang.is_empty() {
                out.push(band(lang, width, s.rule, s.rule));
            }
            continue;
        }
        if fenced {
            let room = width.saturating_sub(3);
            let pieces = if wrap_code {
                wrap::chunk(raw, room)
            } else if wrap::width(raw) > room {
                let mut cut = wrap::fit(raw, room);
                cut.pop();
                cut.push('→');
                vec![cut]
            } else {
                vec![raw.to_string()]
            };
            for piece in pieces {
                out.push(band(&piece, width, s.rule, s.code));
            }
            continue;
        }
        if let Some(title) = heading(line) {
            out.extend(wrap_spans(
                vec![(title.to_string(), s.heading)],
                width,
                (String::new(), s.text),
                "",
            ));
            continue;
        }
        let (marker, body) = match list_marker(line) {
            Some((marker, body)) => (marker, body),
            None => (String::new(), line),
        };
        // An indent wider than half the pane is drawn as half of it, so
        // the text after it always has room.
        let indent = if wrap::width(&indent) > width / 2 {
            " ".repeat(width / 2)
        } else {
            indent
        };
        let lead = format!("{indent}{marker}");
        let hang = " ".repeat(wrap::width(&lead));
        out.extend(wrap_spans(inline(body, s), width, (lead, s.marker), &hang));
    }
    out
}

/// One row of a code block: a left rule, the text, and the code
/// background carried to the full width.
fn band(text: &str, width: usize, rule: Style, body: Style) -> Line<'static> {
    let fill = width.saturating_sub(wrap::width(text) + 2);
    Line::from(vec![
        Span::styled("▎ ", rule),
        Span::styled(format!("{text}{}", " ".repeat(fill)), body),
    ])
}

/// `# Title` to `Title`, for one to six `#`.
fn heading(line: &str) -> Option<&str> {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    if (1..=6).contains(&hashes) {
        line.get(hashes..)?.strip_prefix(' ')
    } else {
        None
    }
}

/// `- x`, `* x`, `+ x` become `• x`; `12. x` keeps its number.
fn list_marker(line: &str) -> Option<(String, &str)> {
    for bullet in ["- ", "* ", "+ "] {
        if let Some(body) = line.strip_prefix(bullet) {
            return Some(("• ".to_string(), body));
        }
    }
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    if digits > 0 {
        // `digits` counts ASCII characters, each one byte, so the
        // offset is a character boundary.
        let rest = line.get(digits..)?;
        if let Some(body) = rest.strip_prefix(". ") {
            return Some((format!("{}. ", line.get(..digits)?), body));
        }
    }
    None
}

/// Split `body` into runs by its `code` and **bold** markers.
fn inline(body: &str, s: &Styles) -> Vec<(String, Style)> {
    let chars: Vec<char> = body.chars().collect();
    let mut runs = Vec::new();
    let mut current = String::new();
    let (mut code, mut bold) = (false, false);
    let style = |code: bool, bold: bool| {
        if code {
            s.code
        } else if bold {
            s.bold
        } else {
            s.text
        }
    };
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let toggle_bold = !code && c == '*' && chars.get(i + 1) == Some(&'*');
        if c == '`' || toggle_bold {
            if !current.is_empty() {
                runs.push((std::mem::take(&mut current), style(code, bold)));
            }
            if c == '`' {
                code = !code;
                i += 1;
            } else {
                bold = !bold;
                i += 2;
            }
            continue;
        }
        current.push(c);
        i += 1;
    }
    if !current.is_empty() {
        runs.push((current, style(code, bold)));
    }
    runs
}

/// Fill lines of `width` from styled runs, breaking at spaces, and inside
/// a word only when it is wider than a line. The first line starts with
/// `first`, the rest with `hang`.
fn wrap_spans(
    runs: Vec<(String, Style)>,
    width: usize,
    first: (String, Style),
    hang: &str,
) -> Vec<Line<'static>> {
    // Words with their style, and whether a space came before them.
    let mut words: Vec<(String, Style, bool)> = Vec::new();
    let mut space = false;
    for (text, style) in runs {
        for (k, word) in text.split(' ').enumerate() {
            if k > 0 {
                space = true;
            }
            if !word.is_empty() {
                words.push((word.to_string(), style, space));
                space = false;
            }
        }
    }
    let first_len = wrap::width(&first.0);
    let hang_len = wrap::width(hang);
    let cells = |cs: &[String]| cs.iter().map(|g| wrap::cell(g)).sum::<usize>();
    let mut lines = Vec::new();
    let mut spans = vec![Span::styled(first.0, first.1)];
    let mut used = first_len;
    let mut start = first_len;
    for (word, style, spaced) in words {
        let mut chars: Vec<String> = wrap::graphemes(&word).map(str::to_string).collect();
        let gap = usize::from(spaced && used > start);
        // A word no line can hold is broken where it stands, so it does
        // not leave its neighbour alone on the line above.
        let never_fits = cells(&chars) > width.saturating_sub(hang_len);
        if used > start && used + gap + cells(&chars) > width && !never_fits {
            lines.push(Line::from(std::mem::take(&mut spans)));
            spans.push(Span::raw(hang.to_string()));
            used = hang_len;
            start = hang_len;
        } else if gap == 1 {
            spans.push(Span::raw(" "));
            used += 1;
        }
        // A line already full starts the next before a word is split
        // across it; without this a word that never fits would be laid
        // past the edge.
        if used >= width && used > start {
            lines.push(Line::from(std::mem::take(&mut spans)));
            spans.push(Span::raw(hang.to_string()));
            used = hang_len;
            start = hang_len;
        }
        while used + cells(&chars) > width && width > used {
            // As many characters as fit in the cells left; a wide one
            // that does not fit starts the next line, and on a line too
            // narrow for it at all it stands alone.
            let room = width - used;
            let mut take = 0;
            let mut taken = 0;
            while take < chars.len() && taken + wrap::cell(&chars[take]) <= room {
                taken += wrap::cell(&chars[take]);
                take += 1;
            }
            if take == 0 {
                if used > hang_len {
                    lines.push(Line::from(std::mem::take(&mut spans)));
                    spans.push(Span::raw(hang.to_string()));
                    used = hang_len;
                    start = hang_len;
                    continue;
                }
                take = 1;
            }
            let head: String = chars.drain(..take).collect::<Vec<_>>().concat();
            spans.push(Span::styled(head, style));
            lines.push(Line::from(std::mem::take(&mut spans)));
            spans.push(Span::raw(hang.to_string()));
            used = hang_len;
            start = hang_len;
        }
        used += cells(&chars);
        spans.push(Span::styled(chars.concat(), style));
    }
    lines.push(Line::from(spans));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::{Color, Modifier};

    fn styles() -> Styles {
        Styles {
            text: Style::default(),
            code: Style::default().fg(Color::Yellow),
            rule: Style::default().fg(Color::DarkGray),
            bold: Style::default().add_modifier(Modifier::BOLD),
            heading: Style::default().fg(Color::Blue),
            marker: Style::default().fg(Color::Magenta),
        }
    }

    fn plain(lines: &[Line]) -> Vec<String> {
        lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    #[test]
    fn inline_code_and_bold_lose_their_markers_and_keep_their_style() {
        let s = styles();
        let lines = render("run `ls -la` **now**", 80, &s, false);
        assert_eq!(plain(&lines), vec!["run ls -la now"]);
        let spans = &lines[0].spans;
        assert!(
            spans
                .iter()
                .any(|sp| sp.content == "ls" && sp.style == s.code)
        );
        assert!(
            spans
                .iter()
                .any(|sp| sp.content == "now" && sp.style == s.bold)
        );
    }

    #[test]
    fn bullets_become_dots_with_a_hanging_indent() {
        let lines = render("- one two three four", 12, &styles(), false);
        assert_eq!(plain(&lines), vec!["• one two", "  three four"]);
    }

    #[test]
    fn numbered_items_keep_their_number() {
        assert_eq!(
            plain(&render("3. third", 40, &styles(), false)),
            vec!["3. third"]
        );
    }

    #[test]
    fn headings_drop_their_hashes() {
        let s = styles();
        let lines = render("## Summary", 40, &s, false);
        assert_eq!(plain(&lines), vec!["Summary"]);
        assert!(lines[0].spans.iter().any(|sp| sp.style == s.heading));
    }

    fn trimmed(lines: &[Line]) -> Vec<String> {
        plain(lines)
            .into_iter()
            .map(|l| l.trim_end().to_string())
            .collect()
    }

    #[test]
    fn a_word_that_never_fits_starts_after_a_full_line() {
        let text = format!("{} {}", "a".repeat(19), "b".repeat(30));
        let lines = render(&text, 20, &styles(), false);
        for l in &lines {
            let w: usize = l.spans.iter().map(|s| wrap::width(&s.content)).sum();
            assert!(w <= 20, "{w}: {l:?}");
        }
        let all: String = plain(&lines).join("");
        assert_eq!(all.matches('b').count(), 30);
    }

    #[test]
    fn fenced_code_is_a_full_width_band_shown_as_written() {
        let lines = render("```\n**not bold** `x`\n```", 40, &styles(), false);
        assert_eq!(trimmed(&lines), vec!["▎ **not bold** `x`"]);
        let width: usize = lines[0].spans.iter().map(|s| wrap::width(&s.content)).sum();
        assert_eq!(width, 40);
    }

    #[test]
    fn a_fence_names_its_language_and_cuts_long_lines() {
        let lines = render(
            "```bash\nfind . -name '*.log' -delete\n```",
            20,
            &styles(),
            false,
        );
        assert_eq!(trimmed(&lines), vec!["▎ bash", "▎ find . -name '*.→"]);
        let wrapped = render(
            "```\nfind . -name '*.log' -delete\n```",
            20,
            &styles(),
            true,
        );
        assert_eq!(wrapped.len(), 2);
    }

    #[test]
    fn a_word_no_line_holds_does_not_orphan_its_neighbour() {
        let lines = render("- A abcdefghijklmnopqrst", 12, &styles(), false);
        assert_eq!(plain(&lines)[0], "• A abcdefgh");
    }

    #[test]
    fn a_word_wider_than_the_line_is_broken() {
        assert_eq!(
            plain(&render("abcdefghij", 8, &styles(), false)),
            vec!["abcdefgh", "ij"]
        );
    }

    #[test]
    fn non_ascii_text_wraps_by_characters() {
        assert_eq!(
            plain(&render("ééééé ü", 8, &styles(), false)),
            vec!["ééééé ü"]
        );
    }
}
