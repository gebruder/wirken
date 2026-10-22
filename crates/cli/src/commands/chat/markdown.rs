//! Markdown in agent replies, drawn as styled terminal lines.
//!
//! The renderer drops the markers and picks styles. It breaks rows the way
//! `text::wrap` does, at a space where one is on the row, and keeps each
//! item's indent on the rows it wraps to. A marker counts only when its
//! closer is on the same line, so `2 ** 3` and a lone backtick stay as typed.
//! Anything not recognised is shown as written.
//!
//! Not drawn, on purpose: blockquotes, images, HTML, setext headings,
//! table alignment and `***both***`. They are rare in replies, and their
//! plain form reads fine.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_segmentation::UnicodeSegmentation;

use super::text::width;

/// One grapheme and the style it is drawn in.
type Piece = (String, Style);

fn dim() -> Style {
    Style::default().add_modifier(Modifier::DIM)
}

/// The reply as terminal lines of at most `cols` cells.
pub(crate) fn lines(source: &str, cols: usize) -> Vec<Line<'static>> {
    let cols = cols.max(8);
    let src: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < src.len() {
        let line = src[i];
        let trimmed = line.trim();
        if let Some(lang) = fence_open(trimmed) {
            let start = i + 1;
            i = start;
            while i < src.len() && !is_fence_close(src[i].trim()) {
                i += 1;
            }
            fenced(&mut out, lang, &src[start..i], cols);
        } else if is_table_start(&src, i) {
            let start = i;
            while i < src.len() && src[i].trim().starts_with('|') {
                i += 1;
            }
            table(&mut out, &src[start..i], cols);
            continue;
        } else if is_rule(trimmed) {
            out.push(Line::styled("─".repeat(cols), dim()));
        } else if let Some(rest) = heading(trimmed) {
            let bold = Style::default().add_modifier(Modifier::BOLD);
            paragraph(&mut out, rest, cols, "", "", bold);
        } else if let Some((indent, glyph, rest)) = list_item(line) {
            let first = format!("{}{glyph} ", " ".repeat(indent));
            let rest_indent = " ".repeat(width(&first));
            paragraph(&mut out, rest, cols, &first, &rest_indent, Style::default());
        } else {
            paragraph(&mut out, line, cols, "", "", Style::default());
        }
        i += 1;
    }
    out
}

/// Whether a table starts at line `i`: a pipe row, then a delimiter row.
fn is_table_start(src: &[&str], i: usize) -> bool {
    let header = src[i].trim();
    header.starts_with('|')
        && src
            .get(i + 1)
            .is_some_and(|next| is_delimiter(&split_row(next)))
}

/// A delimiter row: every cell is dashes, with optional alignment colons.
fn is_delimiter(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells.iter().all(|c| {
            let inner = c.trim_matches(':');
            !inner.is_empty() && inner.chars().all(|ch| ch == '-')
        })
}

/// The cells of a pipe row, outer pipes dropped and each cell trimmed.
fn split_row(line: &str) -> Vec<String> {
    let t = line.trim();
    let t = t.strip_prefix('|').unwrap_or(t);
    let t = t.strip_suffix('|').unwrap_or(t);
    t.split('|').map(|c| c.trim().to_string()).collect()
}

/// A table: the header bold and ruled off from the body. Columns take their
/// natural width when the table fits in `cols`. Otherwise each takes a share
/// and its cells wrap. When even the minimum share does not fit, each row is
/// one line with its cells apart.
fn table(out: &mut Vec<Line<'static>>, block: &[&str], cols: usize) {
    const GAP: usize = 2;
    const MIN_SHARE: usize = 4;
    let rows: Vec<Vec<String>> = block
        .iter()
        .enumerate()
        .filter(|(n, _)| *n != 1)
        .map(|(_, line)| split_row(line))
        .collect();
    let ncols = rows.iter().map(Vec::len).max().unwrap_or(0).max(1);
    let cells: Vec<Vec<Vec<Piece>>> = rows
        .iter()
        .enumerate()
        .map(|(r, row)| {
            (0..ncols)
                .map(|c| {
                    let base = if r == 0 {
                        Style::default().add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    inline(row.get(c).map_or("", String::as_str), base)
                })
                .collect()
        })
        .collect();

    let natural: Vec<usize> = (0..ncols)
        .map(|c| {
            cells
                .iter()
                .map(|r| pieces_width(&r[c]))
                .max()
                .unwrap_or(0)
                .max(1)
        })
        .collect();
    let gaps = GAP * (ncols - 1);
    let total: usize = natural.iter().sum::<usize>() + gaps;
    let avail = cols.saturating_sub(gaps);
    let widths: Vec<usize> = if total <= cols {
        natural.clone()
    } else if avail >= MIN_SHARE * ncols {
        let sum: usize = natural.iter().sum();
        natural
            .iter()
            .map(|w| (w * avail / sum).max(MIN_SHARE))
            .collect()
    } else {
        for row in &cells {
            let mut spans: Vec<Span<'static>> = Vec::new();
            for (c, cell) in row.iter().enumerate() {
                if c > 0 {
                    spans.push(Span::raw(" ".repeat(GAP)));
                }
                spans.extend(to_line(cell.clone()).spans);
            }
            out.push(Line::from(spans));
        }
        return;
    };

    for (r, row) in cells.iter().enumerate() {
        let wrapped: Vec<Vec<Vec<Piece>>> = row
            .iter()
            .enumerate()
            .map(|(c, cell)| wrap_pieces(cell.clone(), widths[c], "", ""))
            .collect();
        let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
        for h in 0..height {
            let mut spans: Vec<Span<'static>> = Vec::new();
            for (c, cell_rows) in wrapped.iter().enumerate() {
                if c > 0 {
                    spans.push(Span::raw(" ".repeat(GAP)));
                }
                let piece_row = cell_rows.get(h).cloned().unwrap_or_default();
                let used = pieces_width(&piece_row);
                spans.extend(to_line(piece_row).spans);
                if c + 1 < ncols {
                    spans.push(Span::raw(" ".repeat(widths[c].saturating_sub(used))));
                }
            }
            out.push(Line::from(spans));
        }
        if r == 0 {
            out.push(Line::styled("─".repeat(total.min(cols)), dim()));
        }
    }
}

fn pieces_width(pieces: &[Piece]) -> usize {
    pieces.iter().map(|(g, _)| width(g)).sum()
}

/// The language of a fence that opens on this line, or `None`.
fn fence_open(trimmed: &str) -> Option<&str> {
    let rest = trimmed.strip_prefix("```")?;
    if rest.contains('`') {
        return None;
    }
    Some(rest.trim())
}

fn is_fence_close(trimmed: &str) -> bool {
    trimmed.len() >= 3 && trimmed.chars().all(|c| c == '`')
}

/// A thematic break: three or more of one of `-`, `*`, `_`, spaces allowed.
fn is_rule(trimmed: &str) -> bool {
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    let Some(first) = compact.chars().next() else {
        return false;
    };
    matches!(first, '-' | '*' | '_') && compact.len() >= 3 && compact.chars().all(|c| c == first)
}

/// The text of an ATX heading, its hashes dropped, or `None`.
fn heading(trimmed: &str) -> Option<&str> {
    let rest = trimmed.trim_start_matches('#');
    let hashes = trimmed.len() - rest.len();
    if !(1..=6).contains(&hashes) {
        return None;
    }
    rest.strip_prefix(' ').map(str::trim)
}

/// A list item: its source indent in cells, the glyph drawn for it, and its
/// text. Bullets become `•`; numbers are shown as written.
fn list_item(line: &str) -> Option<(usize, String, &str)> {
    let rest = line.trim_start();
    let indent = line.len() - rest.len();
    for marker in ["- ", "* ", "+ "] {
        if let Some(text) = rest.strip_prefix(marker) {
            return Some((indent, "•".to_string(), text));
        }
    }
    let number: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if number.is_empty() {
        return None;
    }
    let after = rest.strip_prefix(number.as_str())?;
    let (marker, text) = match (after.strip_prefix('.'), after.strip_prefix(')')) {
        (Some(text), _) => ('.', text),
        (None, Some(text)) => (')', text),
        (None, None) => return None,
    };
    let text = text.strip_prefix(' ')?;
    Some((indent, format!("{number}{marker}"), text))
}

/// A fenced block, as written: a dim rule, the language as a label when
/// there is one, the lines wrapped rather than cut, and a closing rule.
fn fenced(out: &mut Vec<Line<'static>>, lang: &str, body: &[&str], cols: usize) {
    out.push(Line::styled("─".repeat(cols), dim()));
    if !lang.is_empty() {
        out.push(Line::styled(lang.to_string(), dim()));
    }
    let code = Style::default().fg(Color::Yellow);
    for line in body {
        for row in super::text::wrap(line, cols) {
            out.push(Line::styled(row, code));
        }
    }
    out.push(Line::styled("─".repeat(cols), dim()));
}

/// A paragraph: inline styles applied, then laid out in rows of at most
/// `cols` cells. The first row starts with `first`, the rest with `rest`.
fn paragraph(
    out: &mut Vec<Line<'static>>,
    text: &str,
    cols: usize,
    first: &str,
    rest: &str,
    base: Style,
) {
    let pieces = inline(text, base);
    for row in wrap_pieces(pieces, cols, first, rest) {
        out.push(to_line(row));
    }
}

/// Lay styled graphemes out in rows, breaking at a space where one is on
/// the row and inside a word where none is, as `text::wrap` does.
fn wrap_pieces(pieces: Vec<Piece>, cols: usize, first: &str, rest: &str) -> Vec<Vec<Piece>> {
    let prefix = |s: &str| -> Vec<Piece> {
        s.graphemes(true)
            .map(|g| (g.to_string(), Style::default()))
            .collect()
    };
    let rest_prefix = prefix(rest);
    let mut rows: Vec<Vec<Piece>> = Vec::new();
    let mut row = prefix(first);
    let mut row_w = width(first);
    let mut cur_prefix = row.len();
    for (g, style) in pieces {
        let w = width(&g);
        let has_content = row.len() > cur_prefix;
        if row_w + w > cols && has_content {
            let break_at = row
                .iter()
                .rposition(|(s, _)| s == " ")
                .filter(|&sp| sp >= cur_prefix && sp > 0);
            match break_at {
                Some(sp) => {
                    let carry = row.split_off(sp + 1);
                    row.pop();
                    rows.push(row);
                    row = rest_prefix.clone();
                    row.extend(carry);
                }
                None => {
                    rows.push(row);
                    row = rest_prefix.clone();
                }
            }
            cur_prefix = rest_prefix.len();
            row_w = row.iter().map(|(s, _)| width(s)).sum();
        }
        if g == " " && row.len() == cur_prefix {
            continue;
        }
        row.push((g, style));
        row_w += w;
    }
    rows.push(row);
    rows
}

/// Merge runs of one style into spans.
fn to_line(row: Vec<Piece>) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    for (g, style) in row {
        match spans.last_mut() {
            Some(last) if last.style == style => last.content.to_mut().push_str(&g),
            _ => spans.push(Span::styled(g, style)),
        }
    }
    Line::from(spans)
}

/// The inline styles of one line: code spans, bold, italic, and links. A
/// marker opens only before a non-space and closes only after one.
fn inline(text: &str, base: Style) -> Vec<Piece> {
    let g: Vec<&str> = text.graphemes(true).collect();
    let mut out: Vec<Piece> = Vec::new();
    let mut i = 0;
    while i < g.len() {
        if g[i] == "`"
            && let Some(j) = (i + 1..g.len()).find(|&j| g[j] == "`")
            && j > i + 1
        {
            push_all(&mut out, &g[i + 1..j], base.fg(Color::Yellow));
            i = j + 1;
            continue;
        }
        if g[i] == "["
            && let Some(close) = (i + 1..g.len()).find(|&j| g[j] == "]")
            && g.get(close + 1) == Some(&"(")
            && let Some(end) = (close + 2..g.len()).find(|&j| g[j] == ")")
        {
            let label = g[i + 1..close].concat();
            let url = g[close + 2..end].concat();
            push_all(
                &mut out,
                &[label.as_str()],
                base.add_modifier(Modifier::UNDERLINED),
            );
            out.push((" (".into(), dim()));
            out.push((url, dim()));
            out.push((")".into(), dim()));
            i = end + 1;
            continue;
        }
        if g[i] == "*" || g[i] == "_" {
            let marker = g[i];
            let double = g.get(i + 1) == Some(&marker);
            let open_at = if double { i + 2 } else { i + 1 };
            let opens = g.get(open_at).is_some_and(|c| *c != " ")
                && (marker == "*" || i == 0 || !is_word(g[i - 1]));
            // `_` emphasis needs a space inside it, so a single identifier such
            // as `__init__` stays as written.
            if opens
                && let Some(close) = find_closer(&g, open_at, marker, double)
                && (marker == "*" || g[open_at..close].contains(&" "))
            {
                let style = if double {
                    base.add_modifier(Modifier::BOLD)
                } else {
                    base.add_modifier(Modifier::ITALIC)
                };
                push_all(&mut out, &g[open_at..close], style);
                i = close + if double { 2 } else { 1 };
                continue;
            }
        }
        out.push((g[i].to_string(), base));
        i += 1;
    }
    out
}

/// The index where a `marker` (double when `double`) closes, searching from
/// `from`: a run whose preceding grapheme is not a space, and which for `_`
/// is not followed by a word character.
fn find_closer(g: &[&str], from: usize, marker: &str, double: bool) -> Option<usize> {
    let run = if double { 2 } else { 1 };
    (from + 1..g.len()).find(|&j| {
        let here = (0..run).all(|k| g.get(j + k) == Some(&marker));
        here && g[j - 1] != " " && (marker == "*" || g.get(j + run).is_none_or(|c| !is_word(c)))
    })
}

fn is_word(g: &str) -> bool {
    g.chars().any(char::is_alphanumeric)
}

fn push_all(out: &mut Vec<Piece>, graphemes: &[&str], style: Style) {
    out.extend(graphemes.iter().map(|g| (g.to_string(), style)));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain text of each rendered line, with styles dropped.
    fn plain(source: &str, cols: usize) -> Vec<String> {
        lines(source, cols)
            .into_iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    fn styled_span(source: &str, cols: usize, text: &str) -> Style {
        lines(source, cols)
            .into_iter()
            .flat_map(|l| l.spans)
            .find(|s| s.content.contains(text))
            .unwrap_or_else(|| panic!("no span with {text:?}"))
            .style
    }

    #[test]
    fn headings_lose_their_hashes_and_are_bold() {
        assert_eq!(plain("## Results", 40), vec!["Results"]);
        assert!(
            styled_span("## Results", 40, "Results")
                .add_modifier
                .contains(Modifier::BOLD)
        );
        assert_eq!(plain("####### seven", 40), vec!["####### seven"]);
    }

    #[test]
    fn bullets_and_numbers_hang_under_their_text() {
        let out = plain(
            "- one\n- a long item that wraps onto a second row\n3. third",
            20,
        );
        assert_eq!(out[0], "• one");
        assert!(out[1].starts_with("• a long item"), "{out:?}");
        assert!(out[2].starts_with("  "), "wrapped row hangs: {out:?}");
        assert_eq!(out.last().unwrap(), "3. third");
    }

    #[test]
    fn nested_bullets_keep_their_source_indent() {
        assert_eq!(plain("- a\n  - b", 20), vec!["• a", "  • b"]);
    }

    #[test]
    fn a_fence_is_a_dim_rule_with_its_language_and_wrapped_code() {
        let out = plain("```rust\nlet x = 1;\n```", 12);
        assert_eq!(
            out,
            vec![
                "─".repeat(12),
                "rust".to_string(),
                "let x = 1;".to_string(),
                "─".repeat(12)
            ]
        );
        let long = plain("```\nabcdefghijklmnopqrstuvwxyz\n```", 10);
        assert_eq!(long.len(), 2 + 3, "{long:?}");
        assert_eq!(long[1..4].concat(), "abcdefghijklmnopqrstuvwxyz");
    }

    #[test]
    fn a_rule_is_drawn_across() {
        for source in ["---", "***", "___", "- - -"] {
            assert_eq!(plain(source, 9), vec!["─".repeat(9)], "{source}");
        }
    }

    #[test]
    fn emphasis_and_code_drop_their_markers() {
        assert_eq!(
            plain("a **bold** and *it* and `x`", 40),
            vec!["a bold and it and x"]
        );
        assert_eq!(styled_span("**b**", 40, "b").add_modifier, Modifier::BOLD);
        assert_eq!(styled_span("`x`", 40, "x").fg, Some(Color::Yellow));
    }

    #[test]
    fn a_marker_without_a_closer_on_its_line_stays_as_typed() {
        assert_eq!(
            plain("2 ** 3 and a lone ` here", 40),
            vec!["2 ** 3 and a lone ` here"]
        );
        assert_eq!(plain("a **open", 40), vec!["a **open"]);
    }

    #[test]
    fn underscores_inside_words_stay_as_written() {
        assert_eq!(
            plain("snake_case and __init__", 40),
            vec!["snake_case and __init__"]
        );
    }

    #[test]
    fn a_link_shows_its_text_then_its_address() {
        assert_eq!(
            plain("see [the docs](https://example.org/x)", 60),
            vec!["see the docs (https://example.org/x)"]
        );
        assert!(
            styled_span("[docs](u)", 40, "docs")
                .add_modifier
                .contains(Modifier::UNDERLINED)
        );
    }

    #[test]
    fn no_text_is_lost_when_rows_break() {
        let source = "one two three four five six seven eight nine ten";
        let joined = plain(source, 11).join(" ");
        assert_eq!(
            joined.split_whitespace().collect::<Vec<_>>().join(" "),
            source
        );
    }

    #[test]
    fn a_table_that_fits_keeps_its_columns_and_rules_off_the_header() {
        let out = plain("| name | n |\n|---|:-:|\n| ab | 1 |\n| c | 22 |", 40);
        assert_eq!(out[0], "name  n");
        assert_eq!(out[1], "─".repeat(8));
        assert_eq!(out[2], "ab    1");
        assert_eq!(out[3], "c     22");
    }

    #[test]
    fn a_table_wider_than_the_transcript_wraps_its_cells_and_keeps_every_word() {
        let source = "| item | notes |\n|---|---|\n| one | a long note that must wrap |";
        let out = plain(source, 20);
        assert!(out.iter().all(|l| width(l) <= 20), "{out:?}");
        let joined: String = out.join(" ");
        for word in ["one", "a", "long", "note", "that", "must", "wrap"] {
            assert!(joined.contains(word), "{word} lost: {out:?}");
        }
        // Header, rule, then the body row over two lines.
        assert!(out.len() > 3, "the row took more than one line: {out:?}");
    }

    #[test]
    fn a_table_too_narrow_for_any_share_is_one_line_per_row() {
        let source = "| a | b | c | d | e |\n|---|---|---|---|---|\n| 1 | 2 | 3 | 4 | 5 |";
        assert_eq!(plain(source, 12), vec!["a  b  c  d  e", "1  2  3  4  5"]);
    }

    #[test]
    fn a_pipe_line_without_a_delimiter_row_is_not_a_table() {
        assert_eq!(plain("a | b", 20), vec!["a | b"]);
    }

    #[test]
    fn a_table_header_is_bold() {
        let out = lines("| h |\n|---|\n| v |", 20);
        let header = out[0]
            .spans
            .iter()
            .find(|s| s.content.contains('h'))
            .unwrap();
        assert!(header.style.add_modifier.contains(Modifier::BOLD));
    }
}
