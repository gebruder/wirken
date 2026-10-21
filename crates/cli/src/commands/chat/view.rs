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
use super::panels::{SideItem, panels, runtime_words};
use super::text::{layout_input, sanitize, width, wrap};

/// Rows of arguments a card shows before it says the rest is cut.
const CARD_ARGUMENT_ROWS: usize = 8;
/// Rows of anything else a card shows per field.
const CARD_FIELD_ROWS: usize = 3;
/// Rows of draft the input box grows to.
const INPUT_ROWS: usize = 6;
/// Columns the sidebar and the panels take, and the screen width each
/// needs before it is drawn.
const SIDEBAR_COLS: u16 = 30;
const SIDEBAR_FROM: u16 = 90;
const PANELS_COLS: u16 = 36;
const PANELS_FROM: u16 = 120;

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
    let full = frame.area();
    let side_cols = if app.show_sidebar && full.width >= SIDEBAR_FROM {
        SIDEBAR_COLS
    } else {
        0
    };
    let panel_cols = if app.show_panels && full.width >= PANELS_FROM {
        PANELS_COLS
    } else {
        0
    };
    let [side_area, area, panel_area] = Layout::horizontal([
        Constraint::Length(side_cols),
        Constraint::Min(30),
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

    let card = card_lines(app, inner_width, now);
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

    let [transcript_area, card_area, input_area, status_area] = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(card_height),
        Constraint::Length(input_height),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_transcript(frame, app, transcript_area);

    if card_height > 0 {
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
    }

    let input_title = if app.expired.is_some() {
        " Enter or Esc to dismiss "
    } else if app.front_card().is_some() {
        " your answer: y approves, anything else refuses "
    } else if app.busy {
        " waiting for the reply "
    } else {
        " message · /help for commands "
    };
    let rows: Vec<Line<'_>> = input_rows
        .iter()
        .skip(first_row)
        .take(shown_rows)
        .map(|r| Line::raw(r.clone()))
        .collect();
    frame.render_widget(
        Paragraph::new(rows).block(Block::default().borders(Borders::ALL).title(input_title)),
        input_area,
    );
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

    // The runtime is the one the gateway named; until it has said,
    // the line says nothing about where commands run.
    let exec = app
        .status
        .as_ref()
        .map(|s| s.environment.exec.runtime.as_str())
        .filter(|r| !r.is_empty())
        .map(|r| format!("exec: {} · ", sanitize(&runtime_words(r))))
        .unwrap_or_default();
    frame.render_widget(
        Paragraph::new(Line::styled(
            format!(
                "{exec}Enter send · Ctrl+J newline · Ctrl+F search · Ctrl+N new · Ctrl+B sidebar \
                 · Ctrl+P panels · Ctrl+K verify · Ctrl+C quit"
            ),
            Style::default().fg(Color::DarkGray),
        )),
        status_area,
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

fn draw_transcript(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let width = usize::from(area.width.saturating_sub(2)).max(1);
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
                indented(&mut lines, text, width, Style::default());
            }
            Entry::Tool {
                name,
                arguments,
                outcome,
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
            }
            Entry::Note(text) => {
                for row in wrap(&sanitize(text), width.saturating_sub(2)) {
                    lines.push(Line::styled(
                        format!("  {row}"),
                        Style::default().fg(Color::Yellow),
                    ));
                }
            }
        }
        lines.push(Line::raw(""));
    }

    let height = usize::from(area.height.saturating_sub(2));
    let total = lines.len();
    let scroll = app.scroll.min(total.saturating_sub(height));
    let end = total - scroll;
    let start = end.saturating_sub(height);
    let title = format!(" wirken chat · {} ", sanitize(&app.agent));
    frame.render_widget(
        Paragraph::new(lines[start..end].to_vec())
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn indented(lines: &mut Vec<Line<'static>>, text: &str, width: usize, style: Style) {
    for row in wrap(&sanitize(text), width.saturating_sub(2)) {
        lines.push(Line::styled(format!("  {row}"), style));
    }
}

/// The card in front as lines of at most `width` cells, or the expired
/// one, or nothing.
fn card_lines(app: &App, width: usize, now: Instant) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(ask) = &app.expired {
        lines.push(Line::raw(format!(
            "The request to run {} expired; the gateway records it as refused.",
            sanitize(&ask.tool_name)
        )));
        return lines;
    }
    let Some(card) = app.front_card() else {
        return lines;
    };
    let ask = &card.ask;
    let mut field = |name: &str, value: &str, rows: usize, style: Option<Style>| {
        let value = sanitize(value);
        if value.trim().is_empty() {
            return;
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
                "  ... (cut; refuse if you cannot see what you are approving)",
                Style::default().fg(Color::DarkGray),
            ));
        }
    };
    // What the gateway established, in plain text.
    field(
        "request",
        &format!(
            "agent {} wants to use {} ({})",
            ask.agent, ask.tool_name, ask.tier
        ),
        CARD_FIELD_ROWS,
        None,
    );
    field("action key", &ask.action_key, CARD_FIELD_ROWS, None);
    // What will run if approved, exactly as the model sent it.
    field("arguments", &ask.arguments, CARD_ARGUMENT_ROWS, None);
    field("runs", &ask.exec_location, CARD_FIELD_ROWS, None);
    field(
        "runtime",
        &runtime_words(&ask.exec_runtime),
        CARD_FIELD_ROWS,
        None,
    );
    field("in reply to", &ask.trigger, CARD_FIELD_ROWS, None);
    // The model's own account of the call, set apart: the gateway has
    // not checked it, and it is not a description of what will run.
    field(
        "model's claim (unverified)",
        &ask.assistant_text,
        CARD_FIELD_ROWS,
        Some(claim_style()),
    );

    // The two answers, drawn alike.
    lines.push(Line::from(vec![
        Span::styled("[y] approve", choice_style()),
        Span::raw("   "),
        Span::styled("[n] refuse", choice_style()),
        Span::styled(
            "   Enter with nothing typed refuses.",
            Style::default().fg(Color::DarkGray),
        ),
    ]));

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
    lines.push(Line::styled(status, Style::default().fg(Color::Yellow)));
    lines
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

    #[test]
    fn approve_and_refuse_are_drawn_alike() {
        let now = Instant::now();
        let buffer = drawn(&card_app(now), now, 80, 30);
        let approve = styles_of(&buffer, "[y] approve");
        let refuse = styles_of(&buffer, "[n] refuse");
        assert!(approve.iter().all(|s| *s == approve[0]));
        assert!(refuse.iter().all(|s| *s == refuse[0]));
        assert_eq!(approve[0], refuse[0], "neither answer is emphasised");
        find(&buffer, "Enter with nothing typed refuses");
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
        let buffer = drawn(&app, now, 200, 40);
        find(&buffer, "exec: gVisor (runsc)");
        find(&buffer, "Environment");
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
}
