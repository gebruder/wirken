//! The chat screens as the design frames draw them.
//!
//! Each fixture in `frames/` is one design frame, cut to the cells its
//! tests compare: every other cell is `░`, and a row with none is empty.
//! A test builds the state the frame shows, draws it at the frame's size
//! and compares every kept cell: its character, and its color as the
//! design's legend letter.

use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::Color;

use super::app::{App, Entry};
use super::view::{draw, palette};
use super::wire::Query;

const MASK: char = '░';

/// One fixture: the frame's size, its characters and its color letters,
/// `MASK` where a cell is not compared.
pub(crate) struct Design {
    pub w: u16,
    pub h: u16,
    chars: Vec<Vec<char>>,
    colors: Vec<Vec<char>>,
}

pub(crate) fn design(text: &str) -> Design {
    let lines: Vec<&str> = text.split('\n').collect();
    let (w, h) = lines[0].split_once('x').expect("a WxH header");
    let (w, h): (usize, usize) = (w.parse().unwrap(), h.parse().unwrap());
    let grid = |rows: &[&str]| -> Vec<Vec<char>> {
        rows.iter()
            .map(|r| {
                let mut row: Vec<char> = r.chars().collect();
                if row.is_empty() {
                    row = vec![MASK; w];
                }
                assert_eq!(row.len(), w, "a fixture row is not {w} cells: {r:?}");
                row
            })
            .collect()
    };
    let chars = grid(&lines[1..=h]);
    assert!(lines[h + 1].is_empty(), "no blank line between the grids");
    let colors = grid(&lines[h + 2..h + 2 + h]);
    Design {
        w: u16::try_from(w).unwrap(),
        h: u16::try_from(h).unwrap(),
        chars,
        colors,
    }
}

macro_rules! frame {
    ($name:literal) => {
        design(include_str!(concat!("frames/", $name, ".txt")))
    };
}

pub(crate) fn render(app: &App, now: Instant, w: u16, h: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal.draw(|f| draw(f, app, now)).unwrap();
    terminal.backend().buffer().clone()
}

/// The legend letter for a cell's colors, `?` for a pair the legend has
/// no letter for.
fn letter(fg: Color, bg: Color) -> char {
    use palette::*;
    match (fg, bg) {
        (TEXT, BG) => '.',
        (RULE, BG) => '-',
        (WHITE, BG) => 'W',
        (AMBER, BG) => 'A',
        (GRAY, BG) => 'g',
        (BLUE, BG) => 'B',
        (CYAN, BG) => 'C',
        (GRAY, BAR) => 'k',
        (BLUE, BAR) => 'K',
        (DIM, BG) => 'd',
        (BG, BLUE) => 'S',
        (BG, AMBER) => 'Y',
        (RULE, BAR) => 'r',
        (RED, BG) => 'R',
        _ => '?',
    }
}

/// Compare `buffer` with every kept cell of `design`. A color letter that
/// is a space in the design is an empty cell and is not compared.
pub(crate) fn assert_drawn(name: &str, buffer: &Buffer, design: &Design) {
    assert_eq!(
        (buffer.area.width, buffer.area.height),
        (design.w, design.h),
        "{name}: size"
    );
    let mut wrong = Vec::new();
    for y in 0..design.h {
        let (yi, mut kept) = (usize::from(y), false);
        let mut want = String::new();
        let mut got = String::new();
        let mut want_colors = String::new();
        let mut got_colors = String::new();
        let mut differs = false;
        for x in 0..design.w {
            let xi = usize::from(x);
            let c = design.chars[yi][xi];
            if c == MASK {
                want.push(' ');
                got.push(' ');
                want_colors.push(' ');
                got_colors.push(' ');
                continue;
            }
            kept = true;
            let cell = &buffer[(x, y)];
            let symbol = cell.symbol().chars().next().unwrap_or(' ');
            let expected = design.colors[yi][xi];
            let actual = letter(cell.fg, cell.bg);
            want.push(c);
            got.push(symbol);
            want_colors.push(expected);
            got_colors.push(if expected == ' ' { ' ' } else { actual });
            differs |= symbol != c || (expected != ' ' && expected != actual);
        }
        if kept && differs {
            wrong.push(format!(
                "row {y}\n  want |{want}|\n  got  |{got}|\n  want |{want_colors}|\n  got  |{got_colors}|"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{name} differs from the design:\n{}",
        wrong.join("\n")
    );
}

/// The gateway's status as the frames show it: ollama/llama3.2:3b,
/// `used` tokens of a 32.7k window, `rows` audit rows, `denied` refusals.
pub(crate) fn status(used: u64, rows: u64, denied: u64) -> serde_json::Value {
    serde_json::json!({
        "agent": "default",
        "environment": {"data_dir": "~/.wirken", "agent": "default", "provider": "ollama",
                        "model": "llama3.2:3b", "exec": {"mode": "exec_only", "runtime": "docker"}},
        "context": {"used_tokens": used, "window": 32768},
        "cost": {"calls": 2, "input_tokens": 2940, "output_tokens": 61, "budget": {"mode": "off"}},
        "audit": {"rows": rows, "heads": 1, "unsigned_tail": 12},
        "approvals": {"approved": 0, "denied": denied, "grants": []},
        "tools": {"count": 13, "ask_first": 5, "names": ["exec", "generate_image", "http_request",
                  "list_files", "read_file", "write_file"], "skills": []}
    })
}

/// A neutral sidebar: two agents on placeholder models, three
/// conversations.
pub(crate) fn directory() -> serde_json::Value {
    serde_json::json!({
        "agents": [{"id": "default", "provider": "ollama", "model": "llama3.2:3b"},
                   {"id": "work", "provider": "example", "model": "model-a"}],
        "conversations": [
            {"agent": "default", "conversation": "c-1", "title": "Use the exec tool to run this command: ls -la", "updated": "2026-11-26T10:12:00+00:00"},
            {"agent": "default", "conversation": "c-2", "title": "Write a file named notes.txt", "updated": "2026-11-25T18:40:00+00:00"},
            {"agent": "work", "conversation": "c-3", "title": "Summarize the report", "updated": "2026-11-24T09:05:00+00:00"}
        ]
    })
}

pub(crate) fn app_with(used: u64, rows: u64, denied: u64) -> App {
    let mut app = App::new(Some("default".into()), "c-1".into());
    app.on_answer(Query::Status, status(used, rows, denied));
    app.on_answer(Query::Conversations, directory());
    app
}

/// The frames' first start: nothing sent, nothing on the chain.
pub(crate) fn first_start() -> App {
    app_with(0, 0, 0)
}

/// The frames' long conversation: lists of five to eight fruits.
pub(crate) fn long_conversation() -> App {
    let mut app = app_with(1470, 14, 1);
    for n in 5..=8 {
        app.entries
            .push(Entry::User(format!("List {n} fruits, one per line.")));
        app.entries.push(Entry::Agent(
            (1..=n)
                .map(|i| format!("{i}. fruit {i}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }
    app
}

/// The frames' refusal: a Tier 3 pipeline refused at its card.
pub(crate) fn refusal() -> App {
    let mut app = app_with(1470, 14, 1);
    app.entries.push(Entry::User(
        "Use the exec tool to run this command: ls | wc -l".into(),
    ));
    app.entries.push(Entry::Tool {
        id: "call_1".into(),
        name: "exec".into(),
        arguments: r#"{"command":"ls | wc -l"}"#.into(),
        outcome: Some(false),
        output: "Permission denied: 'exec' requires tier3 approval and was refused (too risky). \
                 This action was not executed."
            .into(),
    });
    app.entries.push(Entry::Note("Refused exec.".into()));
    app.entries.push(Entry::Agent(
        "The command was not run: the operator refused it.".into(),
    ));
    app
}

/// A frame, the state it shows, and the rows that state is scrolled up.
type Case = (&'static str, Design, fn() -> App, usize);

pub(crate) fn now() -> Instant {
    Instant::now() + Duration::from_secs(1)
}

/// 01: the bottom row is the key bar at every size, Ctrl+G keys pinned at
/// its right; scrolled up, End latest leads.
#[test]
fn the_key_bar_is_the_bottom_row_at_every_size() {
    let now = now();
    let cases: [Case; 9] = [
        (
            "first-start-80x24",
            frame!("first-start-80x24"),
            first_start,
            0,
        ),
        (
            "first-start-120x24",
            frame!("first-start-120x24"),
            first_start,
            0,
        ),
        (
            "first-start-120x40",
            frame!("first-start-120x40"),
            first_start,
            0,
        ),
        ("long-80x24", frame!("long-80x24"), long_conversation, 10),
        ("long-120x24", frame!("long-120x24"), long_conversation, 10),
        ("long-120x40", frame!("long-120x40"), long_conversation, 10),
        ("refusal-80x24", frame!("refusal-80x24"), refusal, 0),
        ("refusal-120x24", frame!("refusal-120x24"), refusal, 0),
        ("refusal-120x40", frame!("refusal-120x40"), refusal, 0),
    ];
    for (name, design, make, scroll) in cases {
        let mut app = make();
        app.scroll = scroll;
        assert_drawn(name, &render(&app, now, design.w, design.h), &design);
    }
}

/// 02: the transcript and the draft are one box. Once the conversation is
/// taller than the window, a thumb in its right border and the rule above
/// the draft say how much is above and below, and name the key back.
#[test]
fn the_frame_says_where_the_view_is() {
    let now = now();
    let cases: [Case; 6] = [
        ("long-120x24", frame!("long-120x24"), long_conversation, 10),
        ("long-120x40", frame!("long-120x40"), long_conversation, 10),
        (
            "first-start-120x24",
            frame!("first-start-120x24"),
            first_start,
            0,
        ),
        (
            "first-start-120x40",
            frame!("first-start-120x40"),
            first_start,
            0,
        ),
        ("refusal-120x24", frame!("refusal-120x24"), refusal, 0),
        ("refusal-120x40", frame!("refusal-120x40"), refusal, 0),
    ];
    for (name, design, make, scroll) in cases {
        let mut app = make();
        app.scroll = scroll;
        assert_drawn(name, &render(&app, now, design.w, design.h), &design);
    }
}

fn key(code: crossterm::event::KeyCode) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
}

fn ctrl(c: char) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char(c),
        crossterm::event::KeyModifiers::CONTROL,
    )
}

fn typed(app: &mut App, text: &str, now: Instant) {
    for c in text.chars() {
        app.on_key(key(crossterm::event::KeyCode::Char(c)), now);
    }
}

/// The frames' Ctrl+F at 80 columns: the search opened over the
/// transcript, with what is typed in it.
pub(crate) fn search_compact() -> App {
    let mut app = first_start();
    app.set_columns(80);
    let now = now();
    app.on_key(ctrl('f'), now);
    typed(&mut app, "list", now);
    app
}

/// 03: under 120 columns the transcript takes the width, with the meter
/// in its top border, and Ctrl+F opens the conversations over it with the
/// search on screen.
#[test]
fn under_120_columns_the_transcript_takes_the_width() {
    let now = now();
    let cases: [Case; 4] = [
        ("long-80x24", frame!("long-80x24"), long_conversation, 10),
        ("refusal-80x24", frame!("refusal-80x24"), refusal, 0),
        (
            "first-start-80x24",
            frame!("first-start-80x24"),
            first_start,
            0,
        ),
        (
            "search-compact-80x24",
            frame!("search-compact-80x24"),
            search_compact,
            0,
        ),
    ];
    for (name, design, make, scroll) in cases {
        let mut app = make();
        app.scroll = scroll;
        assert_drawn(name, &render(&app, now, design.w, design.h), &design);
    }
}
