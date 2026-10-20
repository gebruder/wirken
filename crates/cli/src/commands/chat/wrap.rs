//! Width arithmetic for the screen: display cells, not characters or
//! bytes (a CJK character or an emoji takes two cells), never slicing a
//! `&str` by byte offset; and the scroll position that follows output.

use unicode_segmentation::UnicodeSegmentation as _;
use unicode_width::UnicodeWidthStr as _;

/// The graphemes of `s`: what a terminal draws as one glyph, an emoji
/// with its variation selector or a joined emoji sequence included.
pub(crate) fn graphemes(s: &str) -> impl Iterator<Item = &str> {
    s.graphemes(true)
}

/// Cells one grapheme takes, as ratatui measures it.
pub(crate) fn cell(g: &str) -> usize {
    g.width()
}

/// Cells `s` takes on a terminal.
pub(crate) fn width(s: &str) -> usize {
    graphemes(s).map(cell).sum()
}

/// `s` in at most `w` cells, an ellipsis marking a cut.
pub(crate) fn fit(s: &str, w: usize) -> String {
    if width(s) <= w {
        return s.to_string();
    }
    if w == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0;
    for g in graphemes(s) {
        if used + cell(g) > w - 1 {
            break;
        }
        used += cell(g);
        out.push_str(g);
    }
    out.push('…');
    out
}

/// `s` in at most `w` cells, keeping its end.
pub(crate) fn fit_left(s: &str, w: usize) -> String {
    if width(s) <= w {
        return s.to_string();
    }
    if w == 0 {
        return String::new();
    }
    let mut tail = Vec::new();
    let mut used = 0;
    for g in s.graphemes(true).rev() {
        if used + cell(g) > w - 1 {
            break;
        }
        used += cell(g);
        tail.push(g);
    }
    tail.reverse();
    format!("…{}", tail.concat())
}

/// Wrap `text` to `width` cells per line, breaking at spaces where a
/// word fits and inside a word only when the word alone is wider than
/// the line. Every `\n` in the input starts a new line. A wide glyph
/// never straddles the edge; on a line one cell wide it stands alone.
pub(crate) fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    for raw in text.split('\n') {
        let mut line = String::new();
        let mut used = 0usize;
        for word in raw.split(' ') {
            let len = self::width(word);
            if used > 0 {
                if used + 1 + len <= width {
                    line.push(' ');
                    used += 1;
                } else {
                    out.push(std::mem::take(&mut line));
                    used = 0;
                }
            }
            for g in graphemes(word) {
                if used > 0 && used + cell(g) > width {
                    out.push(std::mem::take(&mut line));
                    used = 0;
                }
                line.push_str(g);
                used += cell(g);
            }
        }
        out.push(line);
    }
    out
}

/// `text` cut into pieces of at most `width` cells, every character kept
/// where it is, spaces included: for code, whose indentation is meaning.
pub(crate) fn chunk(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    let mut line = String::new();
    let mut used = 0;
    for g in graphemes(text) {
        if used > 0 && used + cell(g) > width {
            out.push(std::mem::take(&mut line));
            used = 0;
        }
        line.push_str(g);
        used += cell(g);
    }
    out.push(line);
    out
}

/// The first visible line of a transcript `total` lines long in a pane
/// `height` lines tall. Following shows the tail; otherwise `wanted` is
/// clamped so the pane never scrolls past the end.
pub(crate) fn scroll_offset(total: usize, height: usize, follow: bool, wanted: usize) -> usize {
    let max = total.saturating_sub(height);
    if follow { max } else { wanted.min(max) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breaks_at_spaces_when_a_word_fits() {
        assert_eq!(wrap("one two three", 7), vec!["one two", "three"]);
    }

    #[test]
    fn breaks_inside_a_word_wider_than_the_line() {
        assert_eq!(wrap("abcdefgh", 3), vec!["abc", "def", "gh"]);
    }

    #[test]
    fn keeps_explicit_newlines_and_empty_lines() {
        assert_eq!(wrap("a\n\nb", 10), vec!["a", "", "b"]);
    }

    #[test]
    fn counts_characters_not_bytes() {
        assert_eq!(wrap("ééé ü", 3), vec!["ééé", "ü"]);
    }

    #[test]
    fn wide_characters_take_two_cells() {
        assert_eq!(width("日本"), 4);
        assert_eq!(wrap("日本語の文", 4), vec!["日本", "語の", "文"]);
        assert_eq!(wrap("日本", 1), vec!["日", "本"]);
        assert_eq!(fit("日本語", 5), "日本…");
        assert_eq!(width(&fit("日本語", 4)), 3);
        assert_eq!(fit_left("ab日本", 4), "…本");
        assert_eq!(fit("hello", 0), "");
    }

    #[test]
    fn an_emoji_sequence_is_one_glyph() {
        // A sign with its variation selector, and a joined family: one
        // glyph of two cells each, as the terminal draws them.
        assert_eq!(width("⚠\u{fe0f}"), 2);
        assert_eq!(width("👨\u{200d}👩\u{200d}👧"), 2);
        assert_eq!(fit("⚠\u{fe0f}⚠\u{fe0f}⚠\u{fe0f}", 5), "⚠\u{fe0f}⚠\u{fe0f}…");
        assert_eq!(chunk("    return x", 6), vec!["    re", "turn x"]);
    }

    #[test]
    fn a_zero_width_never_loops() {
        assert_eq!(wrap("ab", 0), vec!["a", "b"]);
    }

    #[test]
    fn following_shows_the_tail_and_a_wanted_offset_is_clamped() {
        assert_eq!(scroll_offset(10, 4, true, 0), 6);
        assert_eq!(scroll_offset(10, 4, false, 2), 2);
        assert_eq!(scroll_offset(10, 4, false, 99), 6);
        assert_eq!(scroll_offset(3, 4, true, 0), 0);
    }
}
