//! Drawing: a sidebar of conversations and agents, the conversation (or
//! the greeting, a centred composer and ways to start while it is empty),
//! and a panel of cards. Colours are Wirken's own, from the WebChat
//! page's tokens, with fixed xterm-256 fallbacks.
//!
//! Everything model-sourced passes through `app::plain` on its way to a
//! cell, so a reply or a tool output cannot repaint the screen it is
//! shown on or read differently from what it is.

use std::sync::OnceLock;
use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Paragraph};

use super::app::{App, Asks, CardKind, ChildRun, Focus, Hit, Row, kfmt, tool_summary, usd};
use super::markdown;
use super::slash::Builtin;
use super::wrap;

// ----- palette -----

fn truecolor() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        matches!(
            std::env::var("COLORTERM").as_deref(),
            Ok("truecolor") | Ok("24bit")
        )
    })
}

/// A palette colour: the 24-bit value where the terminal says it takes
/// one, else a fixed xterm-256 entry chosen so the three pane shades stay
/// apart (nearest-match collapses them onto one grey).
fn tone(r: u8, g: u8, b: u8, xterm: u8) -> Color {
    if truecolor() {
        Color::Rgb(r, g, b)
    } else {
        Color::Indexed(xterm)
    }
}

fn bg() -> Color {
    tone(0x16, 0x18, 0x26, 234)
}
fn bg2() -> Color {
    tone(0x13, 0x15, 0x23, 233)
}
fn surface() -> Color {
    tone(0x1b, 0x1c, 0x2c, 235)
}
fn user_bg() -> Color {
    tone(0x2b, 0x27, 0x41, 237)
}
fn text() -> Color {
    tone(0xe9, 0xe9, 0xed, 255)
}
fn accent() -> Color {
    tone(0x91, 0x84, 0xd9, 104)
}
fn accent_300() -> Color {
    tone(0xd2, 0xce, 0xfd, 189)
}
fn accent_400() -> Color {
    tone(0xb5, 0xab, 0xfc, 147)
}
fn accent_700() -> Color {
    tone(0x5d, 0x52, 0x94, 60)
}
/// Secondary text, about 5.5:1 on the background.
fn n600() -> Color {
    tone(0x8b, 0x8f, 0xa3, 246)
}
fn n800() -> Color {
    tone(0x3f, 0x42, 0x4d, 239)
}
fn danger() -> Color {
    tone(0xe8, 0xa1, 0x9d, 174)
}
fn amber() -> Color {
    tone(0xe5, 0xc0, 0x7b, 179)
}
fn success() -> Color {
    tone(0x9f, 0xd8, 0xb0, 151)
}

fn fg(c: Color) -> Style {
    Style::default().fg(c)
}

fn dim() -> Style {
    fg(n600())
}

fn clean(text: &str) -> String {
    super::app::plain(text)
}

fn one_line(text: &str) -> String {
    clean(text).replace(['\n', '\r', '\t'], " ")
}

use wrap::{fit, fit_left};

/// Cells `s` takes on the terminal.
fn len(s: &str) -> usize {
    wrap::width(s)
}

fn spans_len(spans: &[Span]) -> usize {
    spans.iter().map(|s| len(&s.content)).sum()
}

/// `n` and the word, singular for one.
fn count(n: u64, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

/// A size in a few characters: 115 B, 3.4 KB, 1.2 MB.
pub(crate) fn bytes(n: usize) -> String {
    match n {
        0..=999 => format!("{n} B"),
        1_000..=999_999 => format!("{:.1} KB", n as f64 / 1_000.0),
        _ => format!("{:.1} MB", n as f64 / 1_000_000.0),
    }
}

/// `left` and `right` on one line of `width`, right flush.
fn split_line(left: Vec<Span<'static>>, right: Vec<Span<'static>>, width: usize) -> Line<'static> {
    let mut spans = left;
    let used = spans_len(&spans) + spans_len(&right);
    spans.push(Span::raw(" ".repeat(width.saturating_sub(used))));
    spans.extend(right);
    Line::from(spans)
}

/// A footer that never collides: `left` segments carry a rank (0 is kept
/// longest) and the highest ranks are dropped until the line fits beside
/// `right`; `right` is cut only when it alone is too wide.
pub(crate) fn fitted_footer(
    left: Vec<(u8, Span<'static>)>,
    right: Vec<Span<'static>>,
    width: usize,
) -> Line<'static> {
    let mut left = left;
    let right_len = spans_len(&right);
    while !left.is_empty()
        && left.iter().map(|(_, s)| len(&s.content)).sum::<usize>() + right_len + 2 > width
    {
        let worst = left
            .iter()
            .enumerate()
            .max_by_key(|(_, (rank, _))| *rank)
            .map(|(i, _)| i)
            .unwrap_or(0);
        left.remove(worst);
    }
    if left.is_empty() && right_len > width {
        let joined: String = right.iter().map(|s| s.content.as_ref()).collect();
        return Line::from(Span::styled(fit(&joined, width), dim()));
    }
    split_line(left.into_iter().map(|(_, s)| s).collect(), right, width)
}

fn rounded(border: Color) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(fg(border))
}

/// Lines with the click targets that sit on them: line index, column,
/// width. The transcript is built off screen and scrolled, so a target is
/// placed only once its line is known to be visible.
#[derive(Default)]
struct Painted {
    lines: Vec<Line<'static>>,
    hits: Vec<(usize, u16, u16, Hit)>,
}

impl Painted {
    fn push(&mut self, line: Line<'static>) {
        self.lines.push(line);
    }

    /// A target on the line about to be pushed.
    fn target(&mut self, x: usize, w: usize, hit: Hit) {
        self.hits.push((self.lines.len(), x as u16, w as u16, hit));
    }

    fn blank(&mut self) {
        self.lines.push(Line::default());
    }
}

// ----- frame -----

pub(crate) fn draw(frame: &mut Frame, app: &mut App) {
    app.hits.clear();
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(bg()).fg(text())),
        area,
    );
    app.wide = area.width >= 100;
    let side_w = if app.sidebar && area.width >= 100 {
        30
    } else {
        0
    };
    let home = app.is_home();
    let panel_w = if !home && area.width >= 140 { 34 } else { 0 };
    let [side, centre, panel] = Layout::horizontal([
        Constraint::Length(side_w),
        Constraint::Min(20),
        Constraint::Length(panel_w),
    ])
    .areas(area);
    if side_w > 0 {
        draw_sidebar(frame, app, side);
    }
    if home {
        draw_home(frame, app, centre);
    } else {
        draw_conversation(frame, app, centre, panel_w == 0);
    }
    if panel_w > 0 {
        draw_panel(frame, app, panel);
    }
}

// ----- sidebar -----

/// When a conversation was last touched, in a few characters: the time
/// today, the weekday within the week, else the date.
pub(crate) fn when(
    at: chrono::DateTime<chrono::Local>,
    now: chrono::DateTime<chrono::Local>,
) -> String {
    match (now.date_naive() - at.date_naive()).num_days() {
        ..=0 => at.format("%H:%M"),
        1..=6 => at.format("%a"),
        _ => at.format("%b %-d"),
    }
    .to_string()
}

/// Rows for each agent's chats when `room` rows are left under the
/// headers: every group one, then the agent this chat runs (`current`)
/// as many as it wants, then the others up to three each. `wants` counts
/// a group's chats, at least one (its "no chats yet" row).
pub(crate) fn share_rows(wants: &[usize], current: usize, room: usize) -> Vec<usize> {
    let mut left = room;
    let mut out: Vec<usize> = Vec::with_capacity(wants.len());
    for w in wants {
        let one = (*w).min(1).min(left);
        out.push(one);
        left -= one;
    }
    let give = |i: usize, cap: usize, left: &mut usize, out: &mut Vec<usize>| {
        let more = wants[i].saturating_sub(out[i]).min(cap).min(*left);
        out[i] += more;
        *left -= more;
    };
    if current < wants.len() {
        give(current, usize::MAX, &mut left, &mut out);
    }
    for i in (0..wants.len()).filter(|i| *i != current) {
        give(i, 2, &mut left, &mut out);
    }
    out
}

fn draw_sidebar(frame: &mut Frame, app: &mut App, area: Rect) {
    frame.render_widget(Block::default().style(Style::default().bg(bg2())), area);
    let x = area.x + 1;
    let w = area.width.saturating_sub(2);
    let bottom = area.y + area.height;
    let mut y = area.y + 1;

    // Search.
    let focused = app.focus == Focus::Search;
    let search = Rect::new(x, y, w, 3.min(bottom.saturating_sub(y)));
    let label = if app.filter.is_empty() && !focused {
        Span::styled(" ⌕ Search  Ctrl+F", dim())
    } else {
        Span::styled(format!(" ⌕ {}", app.filter), fg(text()))
    };
    frame.render_widget(
        Paragraph::new(Line::from(label)).block(rounded(if focused { accent() } else { n800() })),
        search,
    );
    if focused {
        frame.set_cursor_position((search.x + 4 + len(&app.filter) as u16, search.y + 1));
    }
    app.hits.push((search, Hit::Search));
    y += 3;

    // New.
    let new = Rect::new(x, y, w, 1);
    frame.render_widget(
        Paragraph::new(split_line(
            vec![
                Span::styled(" + ", fg(accent_400())),
                Span::styled("New chat", fg(text())),
            ],
            vec![Span::styled("Ctrl+N ", dim())],
            w as usize,
        )),
        new,
    );
    app.hits.push((new, Hit::New));
    y += 2;

    // The operator, at the foot.
    let foot_y = bottom.saturating_sub(2);
    let initials: String = app
        .operator
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(2)
        .collect::<String>()
        .to_uppercase();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" {initials:<2} "),
                Style::default().bg(accent_700()).fg(accent_300()),
            ),
            Span::styled(format!(" {}", fit(&app.operator, 14)), fg(text())),
            Span::styled(" · local", dim()),
        ])),
        Rect::new(x, foot_y, w, 1),
    );

    // Every agent with its model, and its chats under it. Search hides
    // the agents with no match.
    let searching = !app.filter.is_empty();
    let current_title = app.rows.iter().find_map(|r| match r {
        Row::User { text, .. } => Some(one_line(text)),
        _ => None,
    });
    let unsaved = !app
        .conversations
        .iter()
        .any(|c| c.session_id == app.session_id);
    let now = chrono::Local::now();
    let listed = app.listed();
    // The conversation on screen shows its runs as the transcript has
    // them, so a run spawned this turn is listed before the turn ends.
    let live: Vec<ChildRun> = app
        .rows
        .iter()
        .filter_map(|r| match r {
            Row::Delegation {
                agent,
                task,
                session: Some(s),
                end,
                ..
            } => Some(ChildRun {
                session_id: s.clone(),
                agent: agent.clone(),
                task: task.clone(),
                depth: 1,
                end: end.as_ref().map(|e| (e.ok, e.word)),
            }),
            _ => None,
        })
        .collect();
    // The conversation on screen: what the chain lists (runs of runs
    // included), brought up to date by the transcript, plus the runs
    // spawned this turn the list has yet to see.
    let runs_of = |session: &str, listed_runs: &[ChildRun]| -> Vec<ChildRun> {
        let mut runs = listed_runs.to_vec();
        if session == app.session_id {
            for run in &live {
                match runs.iter_mut().find(|r| r.session_id == run.session_id) {
                    Some(r) => r.end = run.end,
                    None => runs.push(run.clone()),
                }
            }
        }
        runs
    };
    struct Group {
        id: String,
        model: String,
        here: bool,
        chats: Vec<Entry>,
    }
    let mut groups: Vec<Group> = Vec::new();
    for id in app.agent_order() {
        let here = id == app.requested_agent;
        let mut chats = Vec::new();
        let push_chat = |chats: &mut Vec<Entry>,
                         title: String,
                         time: String,
                         lane: Option<String>,
                         runs: Vec<ChildRun>| {
            let alert = runs.iter().any(|r| app.needs_you(&r.session_id));
            chats.push(Entry::Chat {
                title,
                time,
                lane,
                alert,
            });
            let n = runs.len();
            for (i, run) in runs.into_iter().enumerate() {
                chats.push(Entry::Run {
                    run,
                    last: i + 1 == n,
                });
            }
        };
        if here && unsaved && !searching && app.viewing.is_none() {
            push_chat(
                &mut chats,
                current_title
                    .clone()
                    .unwrap_or_else(|| "New chat".to_string()),
                String::new(),
                None,
                runs_of(&app.session_id, &[]),
            );
        }
        for c in listed.iter().filter(|c| c.agent == id) {
            let local = c.last.with_timezone(&chrono::Local);
            push_chat(
                &mut chats,
                one_line(&c.title),
                when(local, now),
                Some(c.session_id.clone()),
                runs_of(&c.session_id, &c.children),
            );
        }
        if searching && chats.is_empty() {
            continue;
        }
        let model = app.agents.iter().find(|a| a.id == id).map_or_else(
            || format!("{}/{}", app.status.provider, app.status.model),
            |a| a.model.clone(),
        );
        groups.push(Group {
            id: id.to_string(),
            model,
            here,
            chats,
        });
    }

    let end = foot_y.saturating_sub(1);
    if groups.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("   no matches", dim())),
            Rect::new(x, y, w, 1),
        );
        return;
    }
    // Headers and the gaps between groups come first; chats share the rest.
    let fixed = groups.len() * 2 - 1;
    let room = (end.saturating_sub(y) as usize).saturating_sub(fixed);
    let current = groups.iter().position(|g| g.here).unwrap_or(0);
    let wants: Vec<usize> = groups.iter().map(|g| g.chats.len().max(1)).collect();
    let budget = share_rows(&wants, current, room);

    for (i, g) in groups.iter().enumerate() {
        if y >= end {
            break;
        }
        let header = Rect::new(x, y, w, 1);
        let model = fit(&g.model, (w as usize).saturating_sub(10));
        let name = fit(&g.id, (w as usize).saturating_sub(len(&model) + 4));
        let (mark, name_style) = if g.here {
            (
                Span::styled(" ◆ ", fg(accent())),
                fg(text()).add_modifier(Modifier::BOLD),
            )
        } else {
            (Span::styled(" ◇ ", fg(accent_400())), fg(accent_300()))
        };
        frame.render_widget(
            Paragraph::new(split_line(
                vec![mark, Span::styled(name, name_style)],
                vec![Span::styled(format!("{model} "), dim())],
                w as usize,
            )),
            header,
        );
        app.hits.push((header, Hit::Agent(g.id.clone())));
        y += 1;

        let rows = budget[i];
        if g.chats.is_empty() && rows > 0 && y < end {
            let rect = Rect::new(x, y, w, 1);
            frame.render_widget(
                Paragraph::new(Span::styled("   no chats yet · click to start", dim())),
                rect,
            );
            app.hits.push((rect, Hit::Agent(g.id.clone())));
            y += 1;
        }
        let cut = g.chats.len() > rows;
        let shown = if cut && rows > 1 { rows - 1 } else { rows };
        for entry in g.chats.iter().take(shown) {
            if y >= end {
                break;
            }
            let rect = Rect::new(x, y, w, 1);
            match entry {
                Entry::Chat {
                    title,
                    time,
                    lane,
                    alert,
                } => {
                    let active = lane.as_deref().is_none_or(|id| id == app.session_id);
                    item(
                        frame,
                        rect,
                        title,
                        if *alert { "!" } else { time },
                        active,
                        *alert,
                    );
                    if let Some(id) = lane {
                        app.hits.push((rect, Hit::Open(id.clone())));
                    }
                }
                Entry::Run { run, last } => {
                    run_item(frame, rect, app, run, *last);
                    app.hits.push((rect, Hit::Open(run.session_id.clone())));
                }
            }
            y += 1;
        }
        if cut && rows > 1 && y < end {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    format!("   and {} more · Ctrl+F", g.chats.len() - shown),
                    dim(),
                )),
                Rect::new(x, y, w, 1),
            );
            y += 1;
        }
        y += 1;
    }
}

/// A sidebar row: a chat, or a run it delegated, nested under it.
enum Entry {
    Chat {
        title: String,
        time: String,
        lane: Option<String>,
        /// One of its runs waits for the operator.
        alert: bool,
    },
    Run {
        run: ChildRun,
        last: bool,
    },
}

/// How a delegated run stands, as one mark and its colour: waiting for
/// you, running, done, failed, or ended without a result.
pub(crate) fn run_mark(app: &App, run: &ChildRun) -> (String, Style) {
    if app.needs_you(&run.session_id) {
        return ("!".into(), fg(amber()).add_modifier(Modifier::BOLD));
    }
    match run.end {
        Some((true, _)) => ("✓".into(), fg(success())),
        Some((false, _)) => ("✗".into(), fg(danger())),
        None if app.busy() && run.session_id.starts_with(&app.session_id) => (
            ["◐", "◓", "◑", "◒"][app.spinner % 4].to_string(),
            fg(accent()),
        ),
        None => ("◌".into(), dim()),
    }
}

/// A delegated run under its chat: the branch, the agent, the task, and
/// its mark.
fn run_item(frame: &mut Frame, rect: Rect, app: &App, run: &ChildRun, last: bool) {
    let w = rect.width as usize;
    let active = run.session_id == app.session_id;
    let indent = format!(
        "   {}{} ",
        "│ ".repeat(run.depth.saturating_sub(1)),
        if last { "╰" } else { "├" }
    );
    let (mark, mark_style) = run_mark(app, run);
    let agent = fit(&run.agent, 9);
    let room = w.saturating_sub(len(&indent) + len(&agent) + 4);
    let task = fit(&one_line(&run.task), room);
    let bg_style = |s: Style| if active { s.bg(user_bg()) } else { s };
    let line = split_line(
        vec![
            Span::styled(indent, bg_style(fg(n800()))),
            Span::styled(agent, bg_style(fg(accent_300()))),
            Span::styled(format!(" {task}"), bg_style(dim())),
        ],
        vec![Span::styled(format!("{mark} "), bg_style(mark_style))],
        w,
    );
    let line = if active {
        line.style(Style::default().bg(user_bg()))
    } else {
        line
    };
    frame.render_widget(Paragraph::new(line), rect);
}

/// One sidebar row: a label, a short note at the right, and the bubble
/// colour behind the active one. An `alert` note is drawn to be seen.
fn item(frame: &mut Frame, rect: Rect, label: &str, note: &str, active: bool, alert: bool) {
    let w = rect.width as usize;
    let note = if note.is_empty() {
        String::new()
    } else {
        format!(" {note} ")
    };
    let label = format!("   {}", fit(label, w.saturating_sub(4 + len(&note))));
    let style = if active {
        Style::default().bg(user_bg()).fg(text())
    } else {
        fg(accent_300())
    };
    let note_style = if alert {
        let s = fg(amber()).add_modifier(Modifier::BOLD);
        if active { s.bg(user_bg()) } else { s }
    } else if active {
        style
    } else {
        dim()
    };
    let line = split_line(
        vec![Span::styled(label, style)],
        vec![Span::styled(note, note_style)],
        w,
    );
    let line = if active {
        line.style(Style::default().bg(user_bg()))
    } else {
        line
    };
    frame.render_widget(Paragraph::new(line), rect);
}

// ----- empty conversation -----

fn greeting(app: &App) -> String {
    use chrono::Timelike as _;
    let part = match chrono::Local::now().hour() {
        5..=11 => "morning",
        12..=17 => "afternoon",
        _ => "evening",
    };
    format!("Good {part}, {}", app.operator)
}

/// What the operator should know before typing, if anything.
fn notice(app: &App) -> Option<String> {
    if app.status.budget_pct.is_some_and(|p| p >= 80) {
        Some(format!("Budget nearly spent: {}", app.status.budget))
    } else if !app.status.signed {
        Some("The audit chain is unsigned: the signing key could not be loaded".to_string())
    } else {
        None
    }
}

fn draw_home(frame: &mut Frame, app: &mut App, area: Rect) {
    let width = area.width.saturating_sub(6).min(84);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let w = width as usize;
    let notice = notice(app);
    let menu = app.menu_items();
    let menu_h = if menu.is_empty() {
        0
    } else {
        menu.len().min(MENU_ROWS) as u16 + 2
    };
    // Starters side by side when they fit, else one per line.
    let chips: Vec<(String, String)> = app
        .starters
        .iter()
        .enumerate()
        .map(|(i, s)| (format!(" {}", i + 1), format!("  {} ", fit(s, 40))))
        .collect();
    let chip_len = |(n, s): &(String, String)| len(n) + len(s);
    let across = chips.iter().map(|c| chip_len(c) + 2).sum::<usize>() + 2 <= w;
    let chips_h: u16 = if chips.is_empty() || menu_h > 0 {
        0
    } else if across {
        3
    } else {
        chips.len() as u16
    };
    let height = 2 + notice.as_ref().map_or(0, |_| 4) + 5 + 1 + chips_h + 2 + menu_h;
    let mut y = area.y + area.height.saturating_sub(height) / 2;

    let hello = greeting(app);
    let pad = w.saturating_sub(len(&hello) + 2) / 2;
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw(" ".repeat(pad)),
            Span::styled("◆ ", fg(accent())),
            Span::styled(hello, fg(text()).add_modifier(Modifier::BOLD)),
        ])),
        Rect::new(x, y, width, 1),
    );
    y += 2;

    if let Some(notice) = notice {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" ! ", fg(amber()).add_modifier(Modifier::BOLD)),
                Span::styled(notice, fg(text())),
            ]))
            .block(rounded(n800())),
            Rect::new(x, y, width, 3),
        );
        y += 4;
    }

    draw_composer(frame, app, Rect::new(x, y, width, 5));
    y += 5;

    let left = vec![
        (1, Span::styled(" agent ", dim())),
        (1, Span::styled(app.status.agent.clone(), fg(accent_300()))),
    ];
    let right = vec![
        Span::styled(
            format!("{}/{}", app.status.provider, app.status.model),
            fg(text()),
        ),
        Span::styled(format!("  {} ", app.status.exec), dim()),
    ];
    frame.render_widget(
        Paragraph::new(fitted_footer(left, right, w)),
        Rect::new(x, y, width, 1),
    );
    y += 2;

    if !menu.is_empty() {
        draw_menu(frame, app, &menu, Rect::new(x, y, width, menu_h));
        return;
    }

    if chips_h > 0 {
        if across {
            let mut cx = x;
            for (i, chip) in chips.iter().enumerate() {
                let cw = chip_len(chip) as u16 + 2;
                let rect = Rect::new(cx, y, cw, 3);
                frame.render_widget(
                    Paragraph::new(Line::from(vec![
                        Span::styled(chip.0.clone(), fg(accent_400())),
                        Span::styled(chip.1.clone(), fg(text())),
                    ]))
                    .block(rounded(n800()).style(Style::default().bg(surface()))),
                    rect,
                );
                app.hits.push((rect, Hit::Starter(i)));
                cx += cw + 2;
            }
        } else {
            for (i, chip) in chips.iter().enumerate() {
                let rect = Rect::new(x, y + i as u16, width, 1);
                frame.render_widget(
                    Paragraph::new(Span::styled(
                        format!("{}{}", chip.0, chip.1),
                        fg(accent_300()),
                    )),
                    rect,
                );
                app.hits.push((rect, Hit::Starter(i)));
            }
        }
        y += chips_h + 1;
    }

    // A flash takes the hint's place here, where there is no footer.
    let flash = app
        .flash
        .as_ref()
        .filter(|(_, at)| at.elapsed() < Duration::from_secs(3));
    let hint = match flash {
        Some((msg, _)) => Span::styled(fit(msg, w), fg(accent_300())),
        None => Span::styled(
            fit(
                "click a suggestion or type its number · / for commands · Ctrl+B sidebar",
                w,
            ),
            dim(),
        ),
    };
    frame.render_widget(Paragraph::new(hint), Rect::new(x, y, width, 1));
}

// ----- conversation -----

fn draw_conversation(frame: &mut Frame, app: &mut App, area: Rect, narrow: bool) {
    let width = area.width.saturating_sub(4).min(100);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let w = width as usize;

    // Title, and who answers on what, instead of the session id.
    let title = app
        .rows
        .iter()
        .find_map(|r| match r {
            Row::User { text, .. } => Some(one_line(text)),
            _ => None,
        })
        .unwrap_or_else(|| "New chat".to_string());
    let badge = match &app.viewing {
        Some(view) => format!("◇ {} · run for {} · read-only", view.agent, view.for_agent),
        None => format!(
            "◇ {} · {}/{}",
            app.status.agent, app.status.provider, app.status.model
        ),
    };
    let badge = fit(&badge, w / 2);
    frame.render_widget(
        Paragraph::new(split_line(
            vec![Span::styled(
                fit(&title, w.saturating_sub(len(&badge) + 2)),
                dim(),
            )],
            vec![Span::styled(badge, fg(accent_300()))],
            w,
        )),
        Rect::new(x, area.y + 1, width, 1),
    );

    let draft_lines = app.draft.split('\n').count().clamp(1, 6) as u16;
    let composer_h = draft_lines + 2;
    let menu = app.menu_items();
    let menu_h = if menu.is_empty() {
        0
    } else {
        menu.len().min(MENU_ROWS) as u16 + 2
    };
    let notice = notice(app);
    let notice_h = u16::from(notice.is_some());
    let bottom = area.y + area.height;
    let footer_y = bottom.saturating_sub(2);
    let composer_y = footer_y.saturating_sub(composer_h);
    let menu_y = composer_y.saturating_sub(menu_h);
    let notice_y = menu_y.saturating_sub(notice_h);
    let top = area.y + 3;
    let transcript = Rect::new(x, top, width, notice_y.saturating_sub(top + 1));
    draw_transcript(frame, app, transcript);

    if let Some(notice) = notice {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("! ", fg(amber()).add_modifier(Modifier::BOLD)),
                Span::styled(fit(&notice, w.saturating_sub(2)), dim()),
            ])),
            Rect::new(x, notice_y, width, 1),
        );
    }
    if !menu.is_empty() {
        draw_menu(frame, app, &menu, Rect::new(x, menu_y, width, menu_h));
    }
    draw_composer(frame, app, Rect::new(x, composer_y, width, composer_h));

    // Footer: ranked segments, so a narrow terminal drops the least
    // useful instead of running them together.
    let mut left: Vec<(u8, Span<'static>)> = Vec::new();
    // A flash stands alone for its three seconds.
    let flashing = app
        .flash
        .as_ref()
        .filter(|(_, at)| at.elapsed() < Duration::from_secs(3));
    if let Some((msg, _)) = flashing {
        left.push((0, Span::styled(format!(" ✓ {msg}"), fg(success()))));
    } else {
        left.push((1, Span::styled(format!(" {}", app.status.exec), dim())));
    }
    if narrow && flashing.is_none() {
        left.push((3, Span::styled(format!(" · {}", app.status.budget), dim())));
        left.push((
            4,
            Span::styled(
                format!(
                    " · audit {}",
                    if app.status.signed {
                        "signed"
                    } else {
                        "unsigned"
                    }
                ),
                dim(),
            ),
        ));
    }
    let logs = app.rows.iter().filter(|r| matches!(r, Row::Log(_))).count();
    if logs > 0 && !app.verbose && flashing.is_none() {
        left.push((
            2,
            Span::styled(
                format!(" · {} · Ctrl+O", count(logs as u64, "log line")),
                dim(),
            ),
        ));
    }
    let ring = if app.busy() {
        ["◐", "◓", "◑", "◒"][app.spinner % 4]
    } else {
        "○"
    };
    let right = vec![
        Span::styled(
            format!("{}/{} ", app.status.provider, app.status.model),
            fg(text()),
        ),
        Span::styled(format!("{ring} "), fg(accent())),
    ];
    frame.render_widget(
        Paragraph::new(fitted_footer(left, right, w)),
        Rect::new(x, footer_y, width, 1),
    );
}

fn md_styles() -> markdown::Styles {
    markdown::Styles {
        text: fg(text()),
        code: Style::default().fg(accent_300()).bg(surface()),
        rule: Style::default().fg(accent_700()).bg(surface()),
        bold: fg(text()).add_modifier(Modifier::BOLD),
        heading: fg(accent_300()).add_modifier(Modifier::BOLD),
        marker: fg(accent_400()),
    }
}

/// A rounded box of styled rows across `width`, with an optional title
/// in the top edge and a caption in the bottom edge. Rows wider than the
/// box are cut; callers wrap first.
fn boxed_rows(
    rows: Vec<Vec<Span<'static>>>,
    width: usize,
    border: Style,
    title: &str,
    caption: &str,
) -> Vec<Line<'static>> {
    let inner = width.saturating_sub(4).max(1);
    let edge = |left: &str, label: &str, right: &str| -> Line<'static> {
        let label = if label.is_empty() {
            String::new()
        } else {
            format!(" {label} ")
        };
        let rule = "─".repeat(width.saturating_sub(len(&label) + 3));
        Line::from(Span::styled(format!("{left}─{label}{rule}{right}"), border))
    };
    let mut out = vec![edge("╭", title, "╮")];
    for row in rows {
        let mut spans = vec![Span::styled("│ ", border)];
        let mut used = 0;
        for s in row {
            let room = inner.saturating_sub(used);
            if room == 0 {
                break;
            }
            let content = fit(&s.content, room);
            used += len(&content);
            spans.push(Span::styled(content, s.style));
        }
        spans.push(Span::raw(" ".repeat(inner.saturating_sub(used))));
        spans.push(Span::styled(" │", border));
        out.push(Line::from(spans));
    }
    out.push(edge("╰", caption, "╯"));
    out
}

/// Plain lines boxed, each wrapped to the box.
fn boxed(lines: &[String], width: usize, border: Style, body: Style) -> Vec<Line<'static>> {
    let inner = width.saturating_sub(4).max(1);
    let rows = lines
        .iter()
        .flat_map(|l| wrap::wrap(&one_line(l), inner))
        .map(|piece| vec![Span::styled(piece, body)])
        .collect();
    boxed_rows(rows, width, border, "", "")
}

/// What the agent is asking to do, in words, from the tool's name.
pub(crate) fn wants(tool: &str) -> String {
    match tool {
        "exec" => "wants to run a command".to_string(),
        "write_file" => "wants to write a file".to_string(),
        "read_file" | "list_files" => "wants to read outside its workspace".to_string(),
        "http_request" => "wants to make a web request".to_string(),
        "generate_image" => "wants to create an image".to_string(),
        "memory_read_channel" => "wants to read another channel's memory".to_string(),
        t if t.starts_with("mcp_") => {
            let server = t.trim_start_matches("mcp_").split('_').next().unwrap_or(t);
            format!("wants to use the {server} connection")
        }
        t => format!("wants to use {t}"),
    }
}

fn card_lines(
    p: &mut Painted,
    card: &super::gate::ApprovalCard,
    verdict: &Option<String>,
    width: usize,
    oldest: bool,
) {
    let waiting = verdict.is_none();
    // A delegated run's card says who asked and for whom, and under
    // which ceiling the run was started.
    let delegated = card.delegated.clone();
    let border = if waiting {
        fg(accent()).add_modifier(Modifier::BOLD)
    } else {
        fg(accent_700())
    };
    let box_w = width.min(96);
    let inner = box_w.saturating_sub(4);
    // What a yes does: a Tier 2 action asks again on its next call until
    // `wirken permissions approve` stores a grant; a Tier 3 one always.
    let (badge, badge_colour) = match card.tier {
        "tier2" => ("asks until granted", amber()),
        "tier3" => ("asks every time", danger()),
        other => (other, n600()),
    };
    let header = format!("{} {}", clean(&card.agent), wants(&clean(&card.tool)));
    let mut rows: Vec<Vec<Span<'static>>> = Vec::new();
    let pad = inner.saturating_sub(len(&header) + len(badge) + 2);
    rows.push(vec![
        Span::styled(header, fg(text()).add_modifier(Modifier::BOLD)),
        Span::raw(" ".repeat(pad)),
        Span::styled(
            format!(" {badge} "),
            Style::default().fg(bg()).bg(badge_colour),
        ),
    ]);
    if let Some(args) = &card.arguments {
        rows.push(Vec::new());
        for piece in wrap::wrap(&one_line(&tool_summary(args)), inner.saturating_sub(2)) {
            let fill = " ".repeat(inner.saturating_sub(len(&piece) + 2));
            rows.push(vec![
                Span::styled("▎ ", md_styles().rule),
                Span::styled(format!("{piece}{fill}"), md_styles().code),
            ]);
        }
    }
    rows.push(Vec::new());
    if let Some((_, ceiling)) = &delegated {
        rows.push(vec![
            Span::styled(format!("{:<16}", "delegated by"), dim()),
            Span::styled(ceiling.clone(), fg(text())),
        ]);
    }
    // The `ask` prompt's lines, each as a label and a value. Its opening
    // "wirken: agent … requests …" line is what the header and badge say.
    for line in card.text.lines() {
        let line = clean(line);
        let line = line.trim_start();
        if line.starts_with("wirken:") || line.is_empty() {
            continue;
        }
        let (label, value) = match line.split_once(": ") {
            Some((l, v)) => (l.to_string(), v.trim().to_string()),
            None => (String::new(), line.to_string()),
        };
        let label_w = 16usize;
        for (i, piece) in wrap::wrap(&value, inner.saturating_sub(label_w))
            .into_iter()
            .enumerate()
        {
            let lead = if i == 0 { label.as_str() } else { "" };
            rows.push(vec![
                Span::styled(format!("{lead:<label_w$}"), dim()),
                Span::styled(piece, if label.is_empty() { dim() } else { fg(text()) }),
            ]);
        }
    }
    let caption = verdict.clone().unwrap_or_default();
    p.blank();
    let title = match &delegated {
        Some((parent, _)) => format!("Approval needed · from {}, for {parent}", card.agent),
        None => "Approval needed".to_string(),
    };
    for line in boxed_rows(rows, box_w, border, &title, &caption) {
        p.push(line);
    }
    if waiting && !oldest {
        p.push(Line::from(Span::styled(
            "  waits its turn · answer the card above first",
            dim(),
        )));
    }
    if waiting && oldest {
        let approve = " Approve  y ";
        let deny = " Deny  n ";
        p.target(2, len(approve), Hit::Approve);
        p.target(2 + len(approve) + 2, len(deny), Hit::Deny);
        p.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                approve,
                Style::default()
                    .fg(bg())
                    .bg(accent())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(deny, Style::default().fg(danger()).bg(surface())),
            Span::styled("  or type n and a reason, then Enter", dim()),
        ]));
    }
    p.blank();
}

/// A reply laid out as Markdown, from the cache when this text has been
/// laid out at this width before. The cache is dropped whole when it
/// grows large; it refills with what is on screen.
fn laid_out(app: &App, text: &str, width: usize, styles: &markdown::Styles) -> Vec<Line<'static>> {
    use std::hash::{Hash as _, Hasher as _};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    let key = (h.finish(), width, app.verbose);
    let mut cache = app.laid_out.borrow_mut();
    if let Some(lines) = cache.get(&key) {
        return lines.clone();
    }
    if cache.len() > 256 {
        cache.clear();
    }
    let lines = markdown::render(&clean(text), width, styles, app.verbose);
    cache.insert(key, lines.clone());
    lines
}

fn transcript(app: &App, width: usize) -> Painted {
    let mut p = Painted::default();
    let styles = md_styles();
    // `y` and `n` answer the oldest card still waiting.
    let first_waiting = app
        .rows
        .iter()
        .position(|r| matches!(r, Row::Card { verdict: None, .. }));
    let mut turns = 0;
    let last_user = app.rows.iter().rposition(|r| matches!(r, Row::User { .. }));
    for (index, row) in app.rows.iter().enumerate() {
        match row {
            Row::User { text: said, at } => {
                if turns > 0 {
                    p.push(Line::from(Span::styled("─".repeat(width), fg(n800()))));
                }
                turns += 1;
                p.blank();
                // A bubble takes most of a wide pane and all of a narrow one.
                let max = if width < 12 {
                    width
                } else {
                    (width * 7 / 10).clamp(12, width)
                };
                let wrapped = wrap::wrap(&clean(said), max.saturating_sub(4));
                let time = at.format("%H:%M").to_string();
                let inner = wrapped
                    .iter()
                    .map(|l| len(l))
                    .max()
                    .unwrap_or(0)
                    .max(len(&time));
                let bubble = inner + 4;
                let pad = " ".repeat(width.saturating_sub(bubble));
                let fill = Style::default().bg(user_bg()).fg(text());
                p.push(Line::from(vec![
                    Span::raw(pad.clone()),
                    Span::styled(" ".repeat(bubble), fill),
                ]));
                for l in wrapped {
                    let rest = " ".repeat(inner.saturating_sub(len(&l)));
                    p.push(Line::from(vec![
                        Span::raw(pad.clone()),
                        Span::styled(format!("  {l}{rest}  "), fill),
                    ]));
                }
                p.push(Line::from(vec![
                    Span::raw(pad),
                    Span::styled(" ".repeat(bubble - len(&time) - 2), fill),
                    Span::styled(time, Style::default().bg(user_bg()).fg(n600())),
                    Span::styled("  ", fill),
                ]));
                p.blank();
            }
            Row::Assistant { text, open, meta } => {
                if text.is_empty() {
                    if *open {
                        p.push(working_line(app));
                    }
                    continue;
                }
                // A reply still growing is laid out fresh; caching every
                // prefix would only push the finished ones out.
                let mut rendered = if *open {
                    markdown::render(&clean(text), width, &styles, app.verbose)
                } else {
                    laid_out(app, text, width, &styles)
                };
                if *open && let Some(last) = rendered.last_mut() {
                    last.spans.push(Span::styled("▍", fg(accent())));
                }
                for line in rendered {
                    p.push(line);
                }
                if let Some(meta) = meta {
                    let copy = "⧉ copy";
                    p.target(len(meta) + 2, len(copy), Hit::Copy(index));
                    p.push(Line::from(vec![
                        Span::styled(meta.clone(), dim()),
                        Span::raw("  "),
                        Span::styled(copy, fg(accent_400())),
                    ]));
                }
                p.blank();
            }
            Row::Tool {
                name,
                args,
                done,
                expanded,
                ..
            } => {
                let (pill, pill_style) = match done {
                    None => (
                        format!(" {} running ", ["◐", "◓", "◑", "◒"][app.spinner % 4]),
                        dim(),
                    ),
                    Some(d) if d.success => {
                        (format!(" ✓ {} ", bytes(d.output.len())), fg(success()))
                    }
                    Some(d) => (
                        format!(" ✗ failed · {} ", bytes(d.output.len())),
                        fg(danger()),
                    ),
                };
                let open = *expanded || app.verbose;
                let fold = if open { "▾" } else { "▸" };
                let summary = one_line(&tool_summary(args));
                let room = width.saturating_sub(len(name) + len(&pill) + 7);
                p.target(0, width, Hit::Tool(index));
                p.push(Line::from(vec![
                    Span::styled(format!("  {fold} ⚙ "), fg(accent_400())),
                    Span::styled(one_line(name), fg(accent_300())),
                    Span::styled(format!("  {}", fit(&summary, room)), fg(text())),
                    Span::styled(pill, pill_style),
                ]));
                if open {
                    let rule = Span::styled("    │ ", fg(n800()));
                    for l in wrap::wrap(&clean(args), width.saturating_sub(6)) {
                        p.push(Line::from(vec![rule.clone(), Span::styled(l, dim())]));
                    }
                    if let Some(d) = done {
                        let cleaned = clean(&d.output);
                        let all: Vec<&str> = cleaned.lines().collect();
                        for l in all.iter().take(MAX_DETAIL_LINES) {
                            p.push(Line::from(vec![
                                rule.clone(),
                                Span::styled(fit(l, width.saturating_sub(6)), fg(text())),
                            ]));
                        }
                        if all.len() > MAX_DETAIL_LINES {
                            p.push(Line::from(vec![
                                rule.clone(),
                                Span::styled(
                                    format!(
                                        "… {} more on the chain",
                                        count((all.len() - MAX_DETAIL_LINES) as u64, "line")
                                    ),
                                    dim(),
                                ),
                            ]));
                        }
                    }
                }
            }
            Row::Card { card, verdict } => {
                let oldest = first_waiting == Some(index);
                card_lines(&mut p, card, verdict, width, oldest)
            }
            Row::Delegation {
                agent,
                task,
                session,
                tools,
                max_tier,
                end,
                expanded,
                ..
            } => {
                let (pill, pill_style) = match (end, session) {
                    (_, Some(s)) if app.needs_you(s) => (
                        " ! needs you ".to_string(),
                        fg(amber()).add_modifier(Modifier::BOLD),
                    ),
                    (Some(e), _) if e.ok => (
                        format!(" ✓ done · {} ", bytes(e.output.len())),
                        fg(success()),
                    ),
                    (Some(e), _) => (format!(" ✗ {} ", e.word), fg(danger())),
                    (None, Some(_)) if app.busy() => (
                        format!(" {} running ", ["◐", "◓", "◑", "◒"][app.spinner % 4]),
                        fg(accent()),
                    ),
                    // Not spawned yet: a turn's runs go one after another.
                    (None, None) if app.busy() => (" ◌ queued ".to_string(), dim()),
                    (None, _) => (" ◌ no result ".to_string(), dim()),
                };
                let open = *expanded || app.verbose;
                let fold = if open { "▾" } else { "▸" };
                let room = width.saturating_sub(len(agent) + len(&pill) + 9);
                p.target(0, width, Hit::Tool(index));
                p.push(Line::from(vec![
                    Span::styled(format!("  {fold} ⇢ "), fg(accent_400())),
                    Span::styled(one_line(agent), fg(accent_300())),
                    Span::styled(format!("  {}", fit(&one_line(task), room)), fg(text())),
                    Span::raw(" "),
                    Span::styled(pill, pill_style),
                ]));
                if open {
                    let rule = Span::styled("    │ ", fg(n800()));
                    let mut detail = vec![
                        (format!("task: {}", one_line(task)), dim()),
                        (
                            format!(
                                "up to {} · tools {}",
                                max_tier.as_deref().unwrap_or("–"),
                                if tools.is_empty() {
                                    "none".to_string()
                                } else {
                                    tools.join(", ")
                                }
                            ),
                            dim(),
                        ),
                    ];
                    if let Some(s) = session {
                        detail.push((format!("lane {s} · open it from the sidebar"), dim()));
                    }
                    if let Some(e) = end {
                        for l in clean(&e.output).lines().take(MAX_DETAIL_LINES) {
                            detail.push((l.to_string(), fg(text())));
                        }
                    }
                    for (text_line, style) in detail {
                        for piece in wrap::wrap(&text_line, width.saturating_sub(6)) {
                            p.push(Line::from(vec![rule.clone(), Span::styled(piece, style)]));
                        }
                    }
                }
            }
            Row::Failure { explained, raw } => {
                p.blank();
                for (i, l) in wrap::wrap(explained, width.saturating_sub(2))
                    .into_iter()
                    .enumerate()
                {
                    let lead = if i == 0 { "✗ " } else { "  " };
                    p.push(Line::from(vec![
                        Span::styled(lead, fg(danger())),
                        Span::styled(l, fg(text())),
                    ]));
                }
                p.push(Line::from(Span::styled(
                    format!("  {}", fit(&one_line(raw), width.saturating_sub(2))),
                    dim(),
                )));
                if last_user.is_none_or(|u| u < index) && !app.busy() && super::app::retryable(raw)
                {
                    let label = " ↻ Retry  Ctrl+R ";
                    p.target(2, len(label), Hit::Retry);
                    p.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(label, Style::default().fg(text()).bg(accent_700())),
                    ]));
                }
                p.blank();
            }
            Row::Log(log) => {
                if app.verbose {
                    for l in wrap::wrap(&format!("log: {}", clean(log)), width.saturating_sub(2)) {
                        p.push(Line::from(Span::styled(format!("  {l}"), dim())));
                    }
                }
            }
            Row::Note(note) => {
                for (i, l) in wrap::wrap(&one_line(note), width.saturating_sub(2))
                    .into_iter()
                    .enumerate()
                {
                    let lead = if i == 0 { "· " } else { "  " };
                    p.push(Line::from(Span::styled(format!("{lead}{l}"), dim())));
                }
            }
            Row::Error(e) => {
                for (i, l) in wrap::wrap(&clean(e), width.saturating_sub(2))
                    .into_iter()
                    .enumerate()
                {
                    let lead = if i == 0 { "✗ " } else { "  " };
                    p.push(Line::from(Span::styled(format!("{lead}{l}"), fg(danger()))));
                }
            }
            Row::Panel(panel) => {
                p.blank();
                for line in boxed(panel, width, fg(n800()), fg(text())) {
                    p.push(line);
                }
            }
            Row::Queued(q) => {
                let label = format!("queued · {}", fit(&one_line(q), width.saturating_sub(10)));
                let pad = " ".repeat(width.saturating_sub(len(&label)));
                p.push(Line::from(Span::styled(format!("{pad}{label}"), dim())));
            }
        }
    }
    p
}

/// Tool output shown in detail is cut here; the chain has all of it.
const MAX_DETAIL_LINES: usize = 40;

fn working_line(app: &App) -> Line<'static> {
    // Delegated runs still out, and the ones waiting for you.
    let mut working = Vec::new();
    let mut waiting = Vec::new();
    for r in &app.rows {
        if let Row::Delegation {
            agent,
            session: Some(s),
            end: None,
            ..
        } = r
        {
            if app.needs_you(s) {
                waiting.push(agent.as_str());
            } else {
                working.push(agent.as_str());
            }
        }
    }
    let working = if working.is_empty() {
        String::new()
    } else {
        format!(" · {} working", working.join(", "))
    };
    if !app.pending.is_empty() {
        let who = match waiting.first() {
            Some(agent) => format!("{agent} waits for your answer on the card"),
            None => "waiting for your answer on the card".to_string(),
        };
        return Line::from(vec![
            Span::styled("••• ", fg(accent())),
            Span::styled(format!("{who}{working}"), dim()),
        ]);
    }
    let lit = app.spinner % 3 + 1;
    let secs = app.turn_started.map_or(0, |t| t.elapsed().as_secs());
    let doing = if app
        .rows
        .iter()
        .rev()
        .take_while(|r| !matches!(r, Row::User { .. }))
        .any(|r| matches!(r, Row::Tool { done: None, .. }))
    {
        "running a tool"
    } else if app.rows.iter().any(|r| {
        matches!(
            r,
            Row::Delegation {
                session: Some(_),
                end: None,
                ..
            }
        )
    }) {
        "delegated"
    } else {
        "waiting for the model"
    };
    Line::from(vec![
        Span::styled("•".repeat(lit), fg(accent())),
        Span::styled("•".repeat(3 - lit), fg(accent_700())),
        Span::styled(format!(" {secs}s · {doing}{working}"), dim()),
    ])
}

fn draw_transcript(frame: &mut Frame, app: &mut App, area: Rect) {
    let painted = transcript(app, area.width as usize);
    let height = area.height as usize;
    app.pane_height = height;
    let total = painted.lines.len();
    let offset = wrap::scroll_offset(total, height, app.follow, app.scroll);
    app.scroll = offset;
    // Scrolled back down to the end: follow new output again.
    if offset + height >= total {
        app.follow = true;
    }
    for (line, x, w, hit) in painted.hits {
        if line >= offset && line < offset + height {
            let rect = Rect::new(area.x + x, area.y + (line - offset) as u16, w, 1);
            app.hits.push((rect, hit));
        }
    }
    let visible: Vec<Line> = painted
        .lines
        .into_iter()
        .skip(offset)
        .take(height)
        .collect();
    frame.render_widget(Paragraph::new(Text::from(visible)), area);

    // While scrolled up: a pill back to the latest output.
    if !app.follow && height > 2 {
        let label = if app.content_mark() != app.content_when_scrolled {
            " ↓ new messages · End "
        } else {
            " ↓ back to latest · End "
        };
        let w = len(label) as u16;
        let rect = Rect::new(
            area.x + area.width.saturating_sub(w) / 2,
            area.y + area.height - 1,
            w.min(area.width),
            1,
        );
        frame.render_widget(
            Paragraph::new(Span::styled(
                label,
                Style::default().fg(text()).bg(accent_700()),
            )),
            rect,
        );
        app.hits.push((rect, Hit::Jump));
    }
}

// ----- composer and menu -----

/// The composer's hint, the longest form that fits.
pub(crate) fn hint_for(width: usize, waiting: bool, busy: bool) -> &'static str {
    let forms: &[&str] = if waiting {
        &[
            "y approves; n and a reason denies; then Enter",
            "y or n, then Enter",
        ]
    } else if busy {
        &[
            "Type to queue a message for when this turn ends",
            "Queue a message",
        ]
    } else {
        &[
            "Message the agent · Enter to send · Ctrl+J for a new line · / for commands",
            "Message the agent · Enter to send · / for commands",
            "Message the agent",
        ]
    };
    forms
        .iter()
        .find(|f| len(f) <= width)
        .copied()
        .unwrap_or(forms[forms.len() - 1])
}

fn draw_composer(frame: &mut Frame, app: &mut App, rect: Rect) {
    let waiting = !app.pending.is_empty();
    let focused = app.focus == Focus::Composer;
    let border = if waiting {
        accent()
    } else if focused {
        n600()
    } else {
        n800()
    };
    let mut block = rounded(border).style(Style::default().bg(surface()));
    if waiting {
        block = block.title(Span::styled(
            " approve? [y/N] ",
            fg(accent()).add_modifier(Modifier::BOLD),
        ));
    }
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    app.hits.push((rect, Hit::Composer));
    let inner = Rect::new(
        inner.x + 1,
        inner.y,
        inner.width.saturating_sub(2),
        inner.height,
    );

    if app.draft.is_empty() {
        let hint = if app.viewing.is_some() {
            "A delegated run, read-only · Esc goes back to its chat"
        } else {
            hint_for(inner.width as usize, waiting, app.busy())
        };
        frame.render_widget(
            Paragraph::new(Span::styled(fit(hint, inner.width as usize), dim())),
            inner,
        );
    } else {
        let draft_lines: Vec<&str> = app.draft.split('\n').collect();
        let (cursor_line, col, under) = cursor_position(&app.draft, app.cursor);
        let visible = inner.height.max(1) as usize;
        let first = cursor_line.saturating_sub(visible - 1);
        let room = inner.width as usize;
        let text: Vec<Line> = draft_lines
            .iter()
            .enumerate()
            .skip(first)
            .take(visible)
            .map(|(i, l)| {
                // The cursor's line scrolls sideways to keep the cursor
                // in view; the others show their start.
                let shown = if i == cursor_line {
                    // Cut without an ellipsis: it would sit under the cursor.
                    take_cells(&skip_cells(l, scrolled(col + under, room)).0, room)
                } else {
                    fit(l, room)
                };
                Line::from(Span::styled(shown, fg(text())))
            })
            .collect();
        frame.render_widget(Paragraph::new(Text::from(text)), inner);
    }
    if focused {
        let (line, col, under) = cursor_position(&app.draft, app.cursor);
        let visible = inner.height.max(1) as usize;
        let first = line.saturating_sub(visible - 1);
        let room = inner.width as usize;
        let line_text = app.draft.split('\n').nth(line).unwrap_or("");
        let at = col - skip_cells(line_text, scrolled(col + under, room)).1;
        let cx = inner.x + (at as u16).min(inner.width.saturating_sub(1));
        let cy = inner.y + (line - first) as u16;
        frame.set_cursor_position((cx, cy));
    }
}

/// Line, cell column, and the cells of the glyph under the cursor (at
/// least one), for a character index into a multi-line draft. Widths
/// are by grapheme, as the terminal draws them.
fn cursor_position(draft: &str, cursor: usize) -> (usize, usize, usize) {
    let at = draft
        .char_indices()
        .nth(cursor)
        .map_or(draft.len(), |(i, _)| i);
    let (before, after) = draft.split_at(at);
    let line = before.matches('\n').count();
    let col = wrap::width(before.rsplit('\n').next().unwrap_or(""));
    let under = after
        .split('\n')
        .next()
        .and_then(|rest| wrap::graphemes(rest).next())
        .map_or(1, |g| wrap::cell(g).max(1));
    (line, col, under)
}

/// Cells a line is scrolled by so that cells `col` up to `end` show in
/// `room`: the whole glyph under the cursor, not only its first cell.
fn scrolled(end: usize, room: usize) -> usize {
    end.saturating_sub(room.max(1))
}

/// `line` without its first `cells` cells, rounding up past a wide
/// character the cut would split, and the cells actually skipped.
fn skip_cells(line: &str, cells: usize) -> (String, usize) {
    let mut gone = 0;
    let mut out = String::new();
    for g in wrap::graphemes(line) {
        if gone < cells {
            gone += wrap::cell(g);
        } else {
            out.push_str(g);
        }
    }
    (out, gone)
}

/// The start of `line` that fits in `cells`, cut without a mark.
fn take_cells(line: &str, cells: usize) -> String {
    let mut used = 0;
    wrap::graphemes(line)
        .take_while(|g| {
            used += wrap::cell(g);
            used <= cells
        })
        .collect()
}

/// Rows the `/` menu shows at once; it scrolls with the selection.
const MENU_ROWS: usize = 6;

/// The `/` menu: each entry, what it does or what it takes, the chosen
/// one highlighted; Up and Down move, Enter or Tab takes it.
fn draw_menu(frame: &mut Frame, app: &App, items: &[String], rect: Rect) {
    let at = app.menu_at.min(items.len().saturating_sub(1));
    let first = at.saturating_sub(MENU_ROWS - 1);
    let w = rect.width.saturating_sub(4) as usize;
    let lines: Vec<Line> = items
        .iter()
        .enumerate()
        .skip(first)
        .take(MENU_ROWS)
        .map(|(i, name)| {
            let what = Builtin::ALL
                .iter()
                .find(|(n, _, _)| *n == name)
                .map_or("skill · type a request after it", |(_, _, what)| what);
            let style = if i == at {
                Style::default()
                    .fg(accent_300())
                    .bg(user_bg())
                    .add_modifier(Modifier::BOLD)
            } else {
                fg(text())
            };
            let line = Line::from(vec![
                Span::styled(format!(" {name:<16}"), style),
                Span::styled(
                    format!(
                        "{:<room$}",
                        fit(what, w.saturating_sub(18)),
                        room = w.saturating_sub(17)
                    ),
                    if i == at {
                        style.remove_modifier(Modifier::BOLD)
                    } else {
                        dim()
                    },
                ),
            ]);
            if i == at {
                line.style(Style::default().bg(user_bg()))
            } else {
                line
            }
        })
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(lines)).block(
            rounded(n800())
                .style(Style::default().bg(surface()))
                .title_bottom(Span::styled(
                    format!(" ↑↓ choose · Enter take · {} of {} ", at + 1, items.len()),
                    dim(),
                )),
        ),
        rect,
    );
}

// ----- panel -----

/// One card before it is drawn: what a click on it opens, its title and
/// the value right of the title, and its lines.
struct CardSpec {
    kind: CardKind,
    title: &'static str,
    title_style: Style,
    border: Color,
    right: Vec<Span<'static>>,
    lines: Vec<Line<'static>>,
}

fn draw_panel(frame: &mut Frame, app: &mut App, area: Rect) {
    let x = area.x + 1;
    let w = area.width.saturating_sub(3);
    let inner = w.saturating_sub(4) as usize;
    let cards = panel_cards(app, inner);
    let total: u16 = cards.iter().map(|c| c.lines.len() as u16 + 3).sum();
    let room = area.height.saturating_sub(1);
    // A row between cards when they all fit with it.
    let gap = u16::from(total + cards.len() as u16 <= room);
    let bottom = area.y + area.height;
    let mut y = area.y + 1;
    for spec in cards {
        let height = spec.lines.len() as u16 + 3;
        if y + height > bottom {
            break;
        }
        let rect = Rect::new(x, y, w, height);
        draw_card(frame, rect, &spec, inner);
        app.hits.push((rect, Hit::Card(spec.kind)));
        y += height + gap;
    }
}

fn draw_card(frame: &mut Frame, rect: Rect, spec: &CardSpec, inner: usize) {
    let mut body = vec![split_line(
        vec![Span::styled(spec.title, spec.title_style)],
        spec.right.clone(),
        inner,
    )];
    body.extend(spec.lines.iter().cloned());
    frame.render_widget(
        Paragraph::new(Text::from(body)).block(
            rounded(spec.border)
                .style(Style::default().bg(surface()))
                .padding(ratatui::widgets::Padding::horizontal(1)),
        ),
        rect,
    );
}

/// The `›` that says a card opens something.
fn opens() -> Span<'static> {
    Span::styled(" ›", fg(accent_400()))
}

/// A bar across `width` cells, `pct` of them filled; any use shows at
/// least one cell.
pub(crate) fn bar(pct: u8, colour: Color, width: usize) -> Line<'static> {
    let filled = (usize::from(pct) * width).div_ceil(100).min(width);
    Line::from(vec![
        Span::styled("━".repeat(filled), fg(colour)),
        Span::styled("━".repeat(width - filled), fg(n800())),
    ])
}

fn panel_cards(app: &App, inner: usize) -> Vec<CardSpec> {
    let s = &app.status;
    let title = fg(text()).add_modifier(Modifier::BOLD);
    let line = |text: String, style: Style| Line::from(Span::styled(fit(&text, inner), style));
    let row = |icon: &str, label: &str, value: String| -> Line<'static> {
        split_line(
            vec![
                Span::styled(format!("{icon} "), dim()),
                Span::styled(label.to_string(), fg(text())),
            ],
            vec![Span::styled(
                fit(&value, inner.saturating_sub(len(label) + 3)),
                dim(),
            )],
            inner,
        )
    };
    let mut cards = Vec::new();

    // Delegated runs, first: a run waiting for you is the most urgent
    // thing on the screen.
    let runs: Vec<(&str, bool, Option<bool>, bool)> = app
        .rows
        .iter()
        .filter_map(|r| match r {
            Row::Delegation {
                agent,
                session,
                end,
                ..
            } => Some((
                agent.as_str(),
                session.as_deref().is_some_and(|s| app.needs_you(s)),
                end.as_ref().map(|e| e.ok),
                session.is_some(),
            )),
            _ => None,
        })
        .collect();
    if !runs.is_empty() {
        let out = runs
            .iter()
            .filter(|(_, n, e, started)| !n && e.is_none() && *started)
            .count() as u64;
        let queued = runs
            .iter()
            .filter(|(_, _, e, started)| e.is_none() && !started)
            .count() as u64;
        let done = runs.iter().filter(|(_, _, e, _)| *e == Some(true)).count() as u64;
        let failed = runs.iter().filter(|(_, _, e, _)| *e == Some(false)).count() as u64;
        let mut summary = Vec::new();
        if out > 0 {
            summary.push(format!(
                "{out} {}",
                if app.busy() { "running" } else { "no result" }
            ));
        }
        if queued > 0 && app.busy() {
            summary.push(format!("{queued} queued"));
        }
        if done > 0 {
            summary.push(format!("{done} done"));
        }
        if failed > 0 {
            summary.push(format!("{failed} failed"));
        }
        let needs: Vec<&str> = runs
            .iter()
            .filter(|(_, n, _, _)| *n)
            .map(|(a, _, _, _)| *a)
            .collect();
        let mut lines = vec![line(
            if summary.is_empty() {
                "waiting for you".to_string()
            } else {
                summary.join(" · ")
            },
            dim(),
        )];
        lines.push(if needs.is_empty() {
            line(
                format!("{} delegated", count(runs.len() as u64, "run")),
                dim(),
            )
        } else {
            line(
                format!("! {} needs you", needs.join(", ")),
                fg(amber()).add_modifier(Modifier::BOLD),
            )
        });
        cards.push(CardSpec {
            kind: CardKind::Delegations,
            title: "Delegations",
            title_style: if needs.is_empty() {
                title
            } else {
                fg(accent_300()).add_modifier(Modifier::BOLD)
            },
            border: if needs.is_empty() { n800() } else { accent() },
            right: vec![Span::styled(runs.len().to_string(), fg(text())), opens()],
            lines,
        });
    }

    let data_dir = {
        let full = app.cfg.data_dir.display().to_string();
        match std::env::var("HOME") {
            Ok(home) if !home.is_empty() && full.starts_with(&home) => {
                format!("~{}", full.strip_prefix(home.as_str()).unwrap_or(&full))
            }
            _ => full,
        }
    };
    // A path reads by its end: keep that and cut the start.
    let data_dir = fit_left(&data_dir, inner.saturating_sub(len("data") + 4));
    let exec = s.exec.strip_prefix("exec: ").unwrap_or(s.exec).to_string();
    cards.push(CardSpec {
        kind: CardKind::Environment,
        title: "Environment",
        title_style: title,
        border: n800(),
        right: vec![opens()],
        lines: vec![
            row("▢", "data", data_dir),
            row("◇", "agent", s.agent.clone()),
            row("▣", "exec", exec),
        ],
    });

    if !s.issues.is_empty() {
        let mut lines: Vec<Line<'static>> = s
            .issues
            .iter()
            .take(2)
            .map(|i| line(format!("✗ {}", i.what), fg(danger())))
            .collect();
        if s.issues.len() > 2 {
            lines.push(line(format!("and {} more", s.issues.len() - 2), dim()));
        }
        cards.push(CardSpec {
            kind: CardKind::Safety,
            title: "Safety",
            title_style: fg(danger()).add_modifier(Modifier::BOLD),
            border: danger(),
            right: vec![
                Span::styled(format!("{} to fix", s.issues.len()), fg(danger())),
                opens(),
            ],
            lines,
        });
    }

    let (pct_span, context_lines) = match s.last_request_bytes {
        Some(bytes) => {
            let pct = super::app::context_pct(bytes, s.context_window);
            let colour = if pct >= 80 { danger() } else { accent() };
            (
                Span::styled(format!("{pct}%"), fg(text())),
                vec![
                    bar(pct, colour, inner),
                    line(
                        format!(
                            "≈{} of {} tokens",
                            kfmt(bytes / 4),
                            kfmt(s.context_window as u64)
                        ),
                        dim(),
                    ),
                ],
            )
        }
        None => (
            Span::styled("–", dim()),
            vec![
                bar(0, accent(), inner),
                line("no model call yet".to_string(), dim()),
            ],
        ),
    };
    cards.push(CardSpec {
        kind: CardKind::Context,
        title: "Context",
        title_style: title,
        border: n800(),
        right: vec![pct_span, opens()],
        lines: context_lines,
    });

    let spent = if s.llm_calls == 0 {
        Span::styled("–", dim())
    } else if s.uncosted && s.cost_micros == 0 {
        Span::styled("uncosted", dim())
    } else {
        Span::styled(usd(s.cost_micros), fg(text()))
    };
    let budget_style = if s.budget_pct.is_some_and(|p| p >= 80) {
        fg(danger())
    } else {
        dim()
    };
    cards.push(CardSpec {
        kind: CardKind::Cost,
        title: "Cost and tokens",
        title_style: title,
        border: n800(),
        right: vec![spent, opens()],
        lines: vec![
            line(
                if s.llm_calls == 0 {
                    "no model call yet".to_string()
                } else {
                    format!(
                        "{} · {} in · {} out",
                        count(u64::from(s.llm_calls), "call"),
                        kfmt(s.tokens_in),
                        kfmt(s.tokens_out)
                    )
                },
                dim(),
            ),
            line(s.budget.clone(), budget_style),
        ],
    });

    let verified = match &s.verify {
        Some((ok, summary, at)) => {
            let mut spans = vec![Span::styled(
                fit(summary, inner),
                fg(if *ok { success() } else { danger() }),
            )];
            if s.rows > *at {
                spans = vec![
                    Span::styled(
                        fit(summary, inner.saturating_sub(10)),
                        fg(if *ok { success() } else { danger() }),
                    ),
                    Span::styled(format!(" · {} new", s.rows - at), dim()),
                ];
            }
            Line::from(spans)
        }
        None => line("click to check the chain".to_string(), dim()),
    };
    cards.push(CardSpec {
        kind: CardKind::Audit,
        title: "Audit",
        title_style: title,
        border: n800(),
        right: vec![Span::styled("verify", fg(accent_300())), opens()],
        lines: vec![
            Line::from(vec![
                Span::styled(
                    if s.signed { "signed" } else { "unsigned" },
                    fg(if s.signed { success() } else { danger() }),
                ),
                Span::styled(format!(" · {}", count(s.rows, "row")), dim()),
            ]),
            verified,
        ],
    });

    let tally = |n: u32, label: &str, colour: Color| {
        Span::styled(
            format!("{n} {label}"),
            if n > 0 { fg(colour) } else { dim() },
        )
    };
    let grants = match s.grants {
        Some((n, Some(next))) if n > 0 => format!(
            "{} · next ends {}",
            count(n as u64, "stored grant"),
            next.format("%b %-d")
        ),
        _ => "no stored grants".to_string(),
    };
    cards.push(CardSpec {
        kind: CardKind::Approvals,
        title: "Approvals",
        title_style: title,
        border: n800(),
        right: vec![opens()],
        lines: vec![
            Line::from(vec![
                tally(s.approved, "approved", success()),
                Span::styled(" · ", dim()),
                tally(s.denied, "denied", danger()),
            ]),
            line(grants, dim()),
        ],
    });

    let asking: Vec<&str> = app
        .tools
        .iter()
        .filter(|t| t.asks != Asks::Never)
        .map(|t| t.name.as_str())
        .collect();
    let tool_lines = if app.tools.is_empty() {
        vec![line("reading the tool list…".to_string(), dim())]
    } else {
        vec![
            line(
                format!(
                    "{} {} you first · {}",
                    asking.len(),
                    if asking.len() == 1 { "asks" } else { "ask" },
                    count(s.skills as u64, "skill")
                ),
                dim(),
            ),
            line(
                if asking.is_empty() {
                    "nothing asks".to_string()
                } else {
                    asking.join(", ")
                },
                fg(accent_300()),
            ),
        ]
    };
    cards.push(CardSpec {
        kind: CardKind::Tools,
        title: "Tools",
        title_style: title,
        border: n800(),
        right: vec![
            Span::styled(app.tools.len().to_string(), fg(text())),
            opens(),
        ],
        lines: tool_lines,
    });

    cards
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn fit_left_keeps_the_end_of_a_path() {
        assert_eq!(fit_left("/a/b/c", 10), "/a/b/c");
        assert_eq!(fit_left("/private/tmp/x/data", 8), "…/x/data");
    }

    #[test]
    fn fit_cuts_with_an_ellipsis_by_characters() {
        assert_eq!(fit("hello", 10), "hello");
        assert_eq!(fit("héllo wörld", 6), "héllo…");
    }

    #[test]
    fn the_cursor_counts_cells_and_a_long_line_scrolls_to_it() {
        assert_eq!(cursor_position("漢字", 2), (0, 4, 1));
        assert_eq!(cursor_position("ab\n漢x", 5), (1, 3, 1));
        assert_eq!(cursor_position("ab日", 2), (0, 2, 2));
        // After a sign and its variation selector: two cells, one glyph.
        assert_eq!(cursor_position("⚠\u{fe0f}x", 2), (0, 2, 1));
        assert_eq!(scrolled(6, 10), 0);
        assert_eq!(scrolled(26, 10), 16);
        assert_eq!(skip_cells("abcdef", 2), ("cdef".to_string(), 2));
        assert_eq!(skip_cells("日本語", 1), ("本語".to_string(), 2));
        assert_eq!(take_cells("日本語", 5), "日本");
    }

    #[test]
    fn a_box_is_as_wide_as_asked_on_every_line() {
        let rows = vec![
            vec![Span::raw("one")],
            vec![Span::raw("a line far too long for the box it sits in")],
        ];
        let lines = boxed_rows(rows, 20, Style::default(), "Title", "caption");
        for l in &lines {
            assert_eq!(len(&flat(l)), 20, "{l:?}");
        }
        assert!(flat(&lines[0]).starts_with("╭─ Title "));
        assert!(flat(&lines[3]).starts_with("╰─ caption "));
    }

    #[test]
    fn split_line_pushes_the_right_side_flush() {
        let line = split_line(vec![Span::raw("left")], vec![Span::raw("right")], 12);
        assert_eq!(flat(&line), "left   right");
    }

    #[test]
    fn the_footer_drops_its_least_useful_segment_first() {
        let left = vec![
            (0, Span::raw("keep")),
            (4, Span::raw(" · drop-me-first")),
            (2, Span::raw(" · mid")),
        ];
        let right = vec![Span::raw("model")];
        let line = fitted_footer(left.clone(), right.clone(), 40);
        assert!(flat(&line).contains("drop-me-first"));
        let line = fitted_footer(left.clone(), right.clone(), 18);
        let s = flat(&line);
        assert!(
            !s.contains("drop-me-first") && s.contains("keep · mid"),
            "{s}"
        );
        assert_eq!(len(&s), 18);
        let s = flat(&fitted_footer(left, right, 3));
        assert!(len(&s) <= 3, "{s}");
    }

    #[test]
    fn plurals_and_sizes_read_as_words() {
        assert_eq!(count(1, "call"), "1 call");
        assert_eq!(count(0, "call"), "0 calls");
        assert_eq!(count(3, "row"), "3 rows");
        assert_eq!(bytes(115), "115 B");
        assert_eq!(bytes(3_400), "3.4 KB");
        assert_eq!(bytes(1_200_000), "1.2 MB");
    }

    #[test]
    fn a_bar_fills_whole_cells_across_its_width() {
        let b = bar(50, Color::Reset, 20);
        assert_eq!(len(&b.spans[0].content), 10);
        assert_eq!(len(&flat(&b)), 20);
        // Any use shows.
        assert_eq!(len(&bar(1, Color::Reset, 20).spans[0].content), 1);
        assert_eq!(len(&bar(0, Color::Reset, 20).spans[0].content), 0);
        assert_eq!(len(&bar(100, Color::Reset, 20).spans[1].content), 0);
    }

    #[test]
    fn the_hint_is_the_longest_form_that_fits() {
        let long = hint_for(200, false, false);
        assert!(long.contains("Ctrl+J"));
        let mid = hint_for(55, false, false);
        assert!(
            !mid.contains("Ctrl+J") && mid.contains("/ for commands"),
            "{mid}"
        );
        assert_eq!(hint_for(10, false, false), "Message the agent");
        assert!(hint_for(200, true, false).starts_with("y approves"));
    }

    #[test]
    fn the_card_header_says_what_the_tool_does() {
        assert_eq!(wants("exec"), "wants to run a command");
        assert_eq!(
            wants("mcp_github_create_issue"),
            "wants to use the github connection"
        );
        assert_eq!(wants("calendar"), "wants to use calendar");
    }

    #[test]
    fn a_chat_is_dated_by_time_weekday_or_date() {
        use chrono::TimeZone as _;
        let now = chrono::Local
            .with_ymd_and_hms(2026, 10, 20, 15, 0, 0)
            .unwrap();
        let at = |d, h| {
            chrono::Local
                .with_ymd_and_hms(2026, 10, d, h, 5, 0)
                .unwrap()
        };
        assert_eq!(when(at(20, 9), now), "09:05");
        assert_eq!(when(at(18, 9), now), "Sun");
        assert_eq!(when(at(1, 9), now), "Oct 1");
    }

    #[test]
    fn rows_go_to_every_agent_then_the_current_one() {
        // Room for everything: everyone gets all they want.
        assert_eq!(share_rows(&[2, 5, 1], 1, 20), vec![2, 5, 1]);
        // Tight: one each first, then the current agent, then the others
        // up to three.
        assert_eq!(share_rows(&[6, 9, 4], 1, 8), vec![1, 6, 1]);
        assert_eq!(share_rows(&[6, 2, 9], 1, 12), vec![3, 2, 3]);
        // Not even one each: the earlier groups keep theirs.
        assert_eq!(share_rows(&[3, 3, 3], 2, 2), vec![1, 1, 0]);
    }

    #[test]
    fn fallback_colours_keep_the_three_pane_shades_apart() {
        // Without truecolor the pane shades are fixed entries, not the
        // nearest grey, which collapses them.
        if !truecolor() {
            let shades = [bg(), bg2(), surface(), user_bg()];
            for (i, a) in shades.iter().enumerate() {
                for b in &shades[i + 1..] {
                    assert_ne!(a, b);
                }
            }
        }
    }
}
