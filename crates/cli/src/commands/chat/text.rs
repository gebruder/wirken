//! Text as the chat screen handles it: what may be shown, how it is
//! laid out in cells, and what an answer to an approval card means.

use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

/// Text from the model, a tool or the chain, as the screen may show
/// it. Escape sequences go whole, so nothing it carries can move the
/// cursor, repaint the card or set the window title. Then the
/// characters that make text read differently from what it is go:
/// bidirectional overrides, isolates and marks, the zero-width
/// characters (joiners included, so an emoji sequence shows as its
/// parts) and the invisible tag characters. Carriage returns go, and a
/// tab becomes spaces, so what remains lays out cell by cell.
pub(crate) fn sanitize(text: &str) -> String {
    wirken_agent::ansi::strip_control_sequences(text)
        .chars()
        .filter(|c| !is_hidden(*c))
        .flat_map(|c| {
            let tab = c == '\t';
            std::iter::repeat_n(' ', if tab { 4 } else { 0 })
                .chain((!tab && c != '\r').then_some(c))
        })
        .collect()
}

fn is_hidden(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}'
    ) || (c.is_control() && c != '\n' && c != '\t' && c != '\r')
}

/// Cells `s` takes on screen.
pub(crate) fn width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// Lay `text` out in rows of at most `cols` cells, breaking at a space
/// where one is on the row and inside a word where none is. Each `\n`
/// starts a row. Measured grapheme by grapheme, so a wide character is
/// never split and never overhangs.
pub(crate) fn wrap(text: &str, cols: usize) -> Vec<String> {
    let cols = cols.max(1);
    let mut rows = Vec::new();
    for line in text.split('\n') {
        let mut row = String::new();
        let mut row_width = 0;
        for g in line.graphemes(true) {
            let w = width(g);
            if row_width + w > cols && !row.is_empty() {
                match row.rfind(' ') {
                    Some(space) if space > 0 && g != " " => {
                        // Carry the word begun on this row to the next.
                        let rest = row.split_off(space + 1);
                        rows.push(row.trim_end().to_string());
                        row = rest;
                    }
                    _ => rows.push(std::mem::take(&mut row)),
                }
                row_width = width(&row);
                if g == " " && row.is_empty() {
                    continue;
                }
            }
            row.push_str(g);
            row_width += w;
        }
        rows.push(row);
    }
    rows
}

/// The draft as the input box shows it: rows of at most `cols` cells,
/// broken at `\n` and wherever a row is full, and the row and column
/// the cursor at byte `cursor` stands on.
pub(crate) fn layout_input(
    draft: &str,
    cursor: usize,
    cols: usize,
) -> (Vec<String>, (usize, usize)) {
    let cols = cols.max(1);
    let mut rows = vec![String::new()];
    let mut col = 0;
    let mut at = None;
    for (i, g) in draft.grapheme_indices(true) {
        if i == cursor {
            at = Some((rows.len() - 1, col));
        }
        if g == "\n" {
            rows.push(String::new());
            col = 0;
            continue;
        }
        let w = width(g);
        if col + w > cols {
            rows.push(String::new());
            col = 0;
            if i == cursor {
                at = Some((rows.len() - 1, 0));
            }
        }
        rows.last_mut().expect("never empty").push_str(g);
        col += w;
    }
    let at = at.unwrap_or_else(|| {
        if col >= cols {
            rows.push(String::new());
            (rows.len() - 1, 0)
        } else {
            (rows.len() - 1, col)
        }
    });
    (rows, at)
}

/// The byte offset of the grapheme before `at`, or 0.
pub(crate) fn prev_boundary(s: &str, at: usize) -> usize {
    s.grapheme_indices(true)
        .map(|(i, _)| i)
        .take_while(|i| *i < at)
        .last()
        .unwrap_or(0)
}

/// The byte offset of the grapheme after `at`, or the end.
pub(crate) fn next_boundary(s: &str, at: usize) -> usize {
    s.grapheme_indices(true)
        .map(|(i, _)| i)
        .find(|i| *i > at)
        .unwrap_or(s.len())
}

/// What an answer typed on an approval card decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Answer {
    Approve,
    /// With the reason typed, if there was one.
    Deny(Option<String>),
}

/// Only a lone `y` or `yes`, in any case, approves. `n` or `no`
/// followed by text denies with that text as the reason; anything else
/// denies with what was typed as the reason, and an empty answer
/// denies with none. `y please` denies: an answer that is more than the
/// one word is not read as consent.
pub(crate) fn parse_answer(input: &str) -> Answer {
    let typed = input.trim();
    if typed.eq_ignore_ascii_case("y") || typed.eq_ignore_ascii_case("yes") {
        return Answer::Approve;
    }
    if typed.is_empty() {
        return Answer::Deny(None);
    }
    let (head, rest) = typed.split_once(char::is_whitespace).unwrap_or((typed, ""));
    if head.eq_ignore_ascii_case("n") || head.eq_ignore_ascii_case("no") {
        let rest = rest.trim();
        return Answer::Deny((!rest.is_empty()).then(|| rest.to_string()));
    }
    Answer::Deny(Some(typed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_bidi_controls_and_zero_width_characters_are_stripped() {
        let hostile = "ok\x1b[2K\x1b]0;title\x07 \u{202E}gnp.exe\u{202C} a\u{200B}b\u{2066}c\u{2069} \
                       d\u{200D}e\u{FEFF}f\u{E0041}\r\n\tx\u{0007}";
        let shown = sanitize(hostile);
        assert_eq!(shown, "ok gnp.exe abc def\n    x");
        assert!(!shown.chars().any(is_hidden));
    }

    #[test]
    fn plain_text_and_wide_characters_pass() {
        assert_eq!(sanitize("héllo 世界 🙂\nnext"), "héllo 世界 🙂\nnext");
    }

    #[test]
    fn only_a_lone_y_or_yes_approves() {
        for yes in ["y", "Y", "yes", " YES ", "Yes\n"] {
            assert_eq!(parse_answer(yes), Answer::Approve, "{yes:?}");
        }
        for not in ["y please", "yes!", "yy", "ye", "ok", "sure", "yes yes"] {
            assert!(matches!(parse_answer(not), Answer::Deny(_)), "{not:?}");
        }
        assert_eq!(parse_answer(""), Answer::Deny(None));
        assert_eq!(parse_answer("n"), Answer::Deny(None));
        assert_eq!(
            parse_answer("no  not on prod"),
            Answer::Deny(Some("not on prod".into()))
        );
        assert_eq!(
            parse_answer("y please"),
            Answer::Deny(Some("y please".into()))
        );
    }

    #[test]
    fn wrapping_breaks_at_spaces_and_measures_wide_characters() {
        assert_eq!(wrap("the quick brown fox", 10), ["the quick", "brown fox"]);
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap("a\n\nb", 5), ["a", "", "b"]);
        // Two cells each: three fit in six, the fourth goes down.
        assert_eq!(wrap("世界世界", 6), ["世界世", "界"]);
        for row in wrap("世界 hello 世界 wide text", 5) {
            assert!(width(&row) <= 5, "{row:?}");
        }
    }

    #[test]
    fn the_cursor_is_placed_by_cells_not_bytes() {
        let draft = "ab世\ncd";
        let (rows, at) = layout_input(draft, draft.len(), 10);
        assert_eq!(rows, ["ab世", "cd"]);
        assert_eq!(at, (1, 2));
        let (_, at) = layout_input(draft, "ab".len(), 10);
        assert_eq!(at, (0, 2));
        let (rows, at) = layout_input("abcd", 4, 4);
        assert_eq!(rows, ["abcd", ""]);
        assert_eq!(at, (1, 0));
    }

    #[test]
    fn boundaries_step_over_whole_graphemes() {
        let s = "a🙂b";
        assert_eq!(next_boundary(s, 1), 5);
        assert_eq!(prev_boundary(s, 5), 1);
        assert_eq!(prev_boundary(s, 0), 0);
        assert_eq!(next_boundary(s, s.len()), s.len());
    }
}
