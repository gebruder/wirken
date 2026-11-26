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
        (WHITE, SELECT) => 'V',
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
                   {"id": "work", "provider": "exampleai", "model": "sample-medium-4-5"}],
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

/// The frames' first start: nothing sent, nothing on the chain, one
/// agent and no conversation yet.
pub(crate) fn first_start() -> App {
    let mut app = App::new(Some("default".into()), "c-1".into());
    let mut status = status(0, 0, 0);
    status["cost"] = serde_json::json!({"calls": 0, "input_tokens": 0, "output_tokens": 0,
                                        "budget": {"mode": "off"}});
    status["audit"] = serde_json::json!({"rows": 0, "heads": 0, "unsigned_tail": 0});
    app.on_answer(Query::Status, status);
    app.on_answer(
        Query::Conversations,
        serde_json::json!({"agents": [{"id": "default", "provider": "ollama", "model": "llama3.2:3b"}],
                           "conversations": []}),
    );
    app
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
    let mut app = app_with(0, 0, 0);
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

/// The frames' keys screen, opened with Ctrl+G, and filtered by `filter`.
fn keys_screen(filter: &str) -> App {
    let mut app = first_start();
    let now = now();
    app.on_key(ctrl('g'), now);
    typed(&mut app, filter, now);
    app
}

/// 04: Ctrl+G, F1 and /help open one keys screen: every key and command in
/// groups, the approval keys dimmed while none waits, the whole list
/// fitting 80x24, and typing filters it with the matches marked.
#[test]
fn the_keys_screen_lists_every_key_and_filters() {
    let now = now();
    let cases: [Case; 4] = [
        ("keys-80x24", frame!("keys-80x24"), || keys_screen(""), 0),
        ("keys-120x24", frame!("keys-120x24"), || keys_screen(""), 0),
        ("keys-120x40", frame!("keys-120x40"), || keys_screen(""), 0),
        (
            "keys-filtered-80x24",
            frame!("keys-filtered-80x24"),
            || keys_screen("scroll"),
            0,
        ),
    ];
    for (name, design, make, _) in cases {
        assert_drawn(name, &render(&make(), now, design.w, design.h), &design);
    }
    // F1 and /help open the same screen, and Esc closes it.
    let mut app = first_start();
    app.on_key(key(crossterm::event::KeyCode::F(1)), now);
    assert!(app.keys.is_some());
    app.on_key(key(crossterm::event::KeyCode::Esc), now);
    typed(&mut app, "/help", now);
    app.on_key(key(crossterm::event::KeyCode::Enter), now);
    assert!(app.keys.is_some() && app.entries.is_empty());
}

const SHORT_COMMAND: &str = r#"{"command":"find /workspace/logs -name '*.log' -mtime +7 -print0 | xargs -0 grep -l 'ERROR' | sort | uniq | wc -l"}"#;
const LONG_COMMAND: &str = r#"{"command":"find /workspace/data -type f -name '*.csv' -newer /workspace/.last_run -print0 | xargs -0 -n 1 -P 4 sh -c 'python3 /workspace/tools/clean.py --input \"$0\" --output \"${0%.csv}.clean.csv\" --drop-empty --trim --dedupe --encoding utf-8 --delimiter \",\" --quote minimal --on-error skip >> /workspace/logs/clean.log 2>&1' ; for f in /workspace/data/*.clean.csv; do mv \"$f\" \"${f%.clean.csv}.csv\"; done ; sort -u /workspace/logs/clean.log | grep -v '^DEBUG' | awk -F: '{count[$1]++} END {for (k in count) print count[k], k}' | sort -rn | head -n 25 | tee /workspace/reports/clean-summary.txt ; touch /workspace/.last_run ; wc -l /workspace/reports/clean-summary.txt"}"#;

/// A Tier 3 exec waiting on its card, asked at `t0`, which the frames
/// draw a second later with 42 seconds left.
fn waiting_card(asked: &str, command: &str, claim: &str, t0: Instant) -> App {
    let mut app = app_with(1470, 14, 1);
    app.entries.push(Entry::User(asked.into()));
    app.entries.push(Entry::Tool {
        id: "call_1".into(),
        name: "exec".into(),
        arguments: command.into(),
        outcome: None,
        output: String::new(),
    });
    app.on_server(
        super::wire::ServerEvent::Approval(super::wire::ApprovalAsk {
            request_id: "r1".into(),
            tool_name: "exec".into(),
            action_key: "shell::pipeline:".into(),
            tier: "tier3".into(),
            agent: "default".into(),
            trigger: asked.into(),
            exec_location: "runs in sandbox container (exec_only, read-only root, workspace at \
                            /workspace, no network)"
                .into(),
            arguments: command.into(),
            assistant_text: claim.into(),
            // The chat closes a card three seconds before the gateway.
            timeout_secs: 46,
            exec_runtime: "docker".into(),
        }),
        t0,
    );
    app
}

fn tier3_card(t0: Instant) -> App {
    waiting_card(
        "How many of the old log files have errors in them?",
        SHORT_COMMAND,
        "I'll count the log files older than a week that mention an error, so we know how much \
         there is to clean up. This only reads files; nothing is changed or deleted.",
        t0,
    )
}

fn long_card(t0: Instant) -> App {
    waiting_card(
        "Clean up the new CSV exports and tell me what you changed.",
        LONG_COMMAND,
        "I'll clean the CSV files that changed since the last run, then show a summary of what \
         was fixed. Each original is replaced only after its file cleans without errors.",
        t0,
    )
}

/// A card frame, the card's state, and whether it takes only a refusal.
type CardCase = (&'static str, Design, fn(Instant) -> App, bool);

/// 05: a card spans the window at every width, its fields wrapped and
/// none cut, the model's claim last under its own rule, the answer rule
/// once, and the countdown on the rule over the answer. A card that does
/// not fit says how many rows it cut and takes only a refusal; under 15
/// rows it is one line.
#[test]
fn the_card_spans_the_window_and_says_when_it_cannot_be_approved() {
    let t0 = Instant::now();
    let later = t0 + Duration::from_secs(1);
    let cases: [CardCase; 7] = [
        ("card-80x24", frame!("card-80x24"), tier3_card, false),
        ("card-120x24", frame!("card-120x24"), tier3_card, false),
        ("card-120x40", frame!("card-120x40"), tier3_card, false),
        (
            "long-card-cut-80x24",
            frame!("long-card-cut-80x24"),
            long_card,
            true,
        ),
        (
            "long-card-120x24",
            frame!("long-card-120x24"),
            long_card,
            false,
        ),
        (
            "long-card-120x40",
            frame!("long-card-120x40"),
            long_card,
            false,
        ),
        ("short-80x10", frame!("short-80x10"), tier3_card, true),
    ];
    for (name, design, make, refusal_only) in cases {
        let mut app = make(t0);
        assert_drawn(name, &render(&app, later, design.w, design.h), &design);
        assert_eq!(app.card_cut.get(), refusal_only, "{name}");
        // A card drawn whole takes y; one cut or one line does not.
        typed(&mut app, "y", later);
        let sent = app.on_key(key(crossterm::event::KeyCode::Enter), later);
        let approved = matches!(
            sent,
            Some(super::app::Outgoing::Decision { approve: true, .. })
        );
        assert_eq!(approved, !refusal_only, "{name}: {sent:?}");
    }
    // The one line refuses on Enter alone, with no reason.
    let mut app = tier3_card(t0);
    render(&app, later, 80, 10);
    let sent = app.on_key(key(crossterm::event::KeyCode::Enter), later);
    assert!(
        matches!(
            sent,
            Some(super::app::Outgoing::Decision {
                approve: false,
                reason: None,
                ..
            })
        ),
        "{sent:?}"
    );
}

/// 06: a card that does not fit gives up the transcript's rows, then its
/// spacer, then rows of its long values in order: the reply-to, the runs,
/// the claim, the arguments last. The title, the first row of every
/// field, the countdown and the answer field stay at every height down
/// to 15 rows, and a cut card takes a refusal only.
#[test]
fn a_card_that_does_not_fit_cuts_in_order_and_keeps_what_never_drops() {
    let t0 = Instant::now();
    let later = t0 + Duration::from_secs(1);
    let text = |b: &Buffer| -> String {
        (0..b.area.height)
            .map(|y| {
                (0..b.area.width)
                    .map(|x| b[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    // The long card at 80 columns is 29 rows whole and 28 without its
    // spacer. Cut, the two-row notice takes the one-row instruction's
    // place, so the first cut is two rows.
    let row_of = |shown: &str, label: &str| -> String {
        shown
            .lines()
            .find(|l| l.contains(label))
            .unwrap_or_default()
            .to_string()
    };
    for (h, runs, claim, args) in [
        (30, "", "", ""),
        (29, "", "", ""),
        (28, "… +1 row", "… +1 row", ""),
        (27, "… +1 row", "… +2 rows", ""),
        (26, "… +1 row", "… +2 rows", "… +1 row"),
    ] {
        let app = long_card(t0);
        let shown = text(&render(&app, later, 80, h));
        assert_eq!(app.card_cut.get(), !runs.is_empty(), "80x{h}:\n{shown}");
        let claim_row: String = shown
            .lines()
            .skip_while(|l| !l.contains("model's claim"))
            .skip(1)
            .take_while(|l| !l.contains("Card cut") && !l.contains("Type y"))
            .collect();
        let args_rows: String = shown
            .lines()
            .skip_while(|l| !l.contains("arguments:"))
            .take_while(|l| !l.contains("runs:"))
            .collect();
        for (what, row, want) in [
            ("runs", row_of(&shown, "runs:"), runs),
            ("claim", claim_row, claim),
            ("arguments", args_rows, args),
        ] {
            if want.is_empty() {
                assert!(!row.contains("… +"), "80x{h}: {what} cut:\n{shown}");
            } else {
                assert!(row.contains(want), "80x{h}: {what} not {want:?}:\n{shown}");
            }
        }
    }
    // Every height from 15 rows keeps the title, the first row of each
    // field, the countdown and the answer field.
    for h in 15..=40 {
        let app = long_card(t0);
        let shown = text(&render(&app, later, 80, h));
        for kept in [
            "approval needed · tier 3 · exec",
            "request:",
            "action key:",
            "arguments:",
            "runs:",
            "runtime:",
            "in reply to:",
            "model's claim (unverified):",
            "your answer",
            "Closes in 42s.",
        ] {
            assert!(shown.contains(kept), "80x{h}: {kept:?} dropped:\n{shown}");
        }
    }
    // The reply-to gives up its rows before anything else.
    let mut app = waiting_card(
        "Clean up the new CSV exports, tell me what you changed, and keep a copy of every \
         original file somewhere I can find it afterward.",
        LONG_COMMAND,
        "I'll clean the files.",
        t0,
    );
    let shown = text(&render(&app, later, 80, 24));
    assert!(
        row_of(&shown, "in reply to:").contains("… +1 row"),
        "{shown}"
    );
    assert!(shown.contains("Card cut: "), "{shown}");
    app.cards.clear();
}

/// 07: beside the transcript the panels are one frame, a rule per
/// section, the exec runtime wrapped under its label, and a Tools list
/// that does not fit ends in how many more there are.
#[test]
fn the_panels_are_one_frame() {
    let now = now();
    let cases: [Case; 6] = [
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
        ("long-120x24", frame!("long-120x24"), long_conversation, 10),
        ("long-120x40", frame!("long-120x40"), long_conversation, 10),
        ("refusal-120x24", frame!("refusal-120x24"), refusal, 0),
        ("refusal-120x40", frame!("refusal-120x40"), refusal, 0),
    ];
    for (name, design, make, scroll) in cases {
        let mut app = make();
        app.scroll = scroll;
        assert_drawn(name, &render(&app, now, design.w, design.h), &design);
    }
    let names = [
        "exec",
        "generate_image",
        "http_request",
        "list_files",
        "read_file",
        "write_file",
        "web_search",
        "web_fetch",
        "spawn_subagent",
        "memory_read",
        "memory_write",
        "schedule",
        "send_message",
    ];
    let rows = super::view::tool_names(&names, 34, 3);
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(rows[2].ends_with("more"), "{rows:?}");
    let shown: usize = rows.join(" ").matches(',').count();
    assert!(
        rows[2].contains(&format!("+{} more", names.len() - shown)),
        "{rows:?}"
    );
    assert_eq!(super::view::tool_names(&names[..6], 34, 3).len(), 3);
}

/// 08: an empty conversation teaches the keys a newcomer needs and the
/// empty draft says what to do; both go with the first message.
#[test]
fn a_first_screen_teaches_until_the_first_message() {
    let now = now();
    let cases: [Case; 3] = [
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
    ];
    for (name, design, make, _) in cases {
        assert_drawn(name, &render(&make(), now, design.w, design.h), &design);
    }
    let mut app = first_start();
    typed(&mut app, "hello", now);
    app.on_key(key(crossterm::event::KeyCode::Enter), now);
    let b = render(&app, now, 80, 24);
    let text: String = (0..24)
        .flat_map(|y| (0..80).map(move |x| (x, y)))
        .map(|(x, y)| b[(x, y)].symbol().to_string())
        .collect();
    assert!(
        !text.contains("Type a message") && !text.contains("type a message"),
        "{text}"
    );
}

/// 09: the sidebar cuts text only when it does not fit, with one "…",
/// cuts model names in the middle, keeps times in a right column, and a
/// search that matches nothing says so.
#[test]
fn the_sidebar_uses_its_width() {
    let now = now();
    let cases: [Case; 7] = [
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
        ("long-120x24", frame!("long-120x24"), long_conversation, 10),
        ("long-120x40", frame!("long-120x40"), long_conversation, 10),
        ("refusal-120x24", frame!("refusal-120x24"), refusal, 0),
        ("refusal-120x40", frame!("refusal-120x40"), refusal, 0),
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
    // In the docked sidebar the no-match keys fit its width.
    let mut app = app_with(0, 0, 0);
    app.set_columns(120);
    app.on_key(ctrl('f'), now);
    typed(&mut app, "zzz", now);
    let b = render(&app, now, 120, 40);
    let side: Vec<String> = (0..40)
        .map(|y| (0..30).map(|x| b[(x, y)].symbol().to_string()).collect())
        .collect();
    assert!(
        side.iter().any(|r| r.contains("Esc     clear the search")),
        "{side:#?}"
    );
    use super::view::{cut_end, cut_middle};
    assert_eq!(cut_end("ollama/llama3.2:3b", 18), "ollama/llama3.2:3b");
    assert_eq!(cut_end("Summarize the report", 18), "Summarize the rep…");
    assert_eq!(
        cut_middle("exampleai/sample-medium-4-5", 21),
        "exampleai/…medium-4-5"
    );
    assert_eq!(cut_middle("ollama/llama3.2:3b", 21), "ollama/llama3.2:3b");
}

/// 10: the keys that hide the columns and verify the chain sit on the
/// frames they act on; in the compact layout the keys to the columns put
/// away sit on the transcript's bottom border.
#[test]
fn hints_sit_on_the_borders_they_act_on() {
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

/// 12: one chain head is singular, a tool call waiting on a card reads
/// "needs approval" and wraps whole under itself, and PgUp and PgDn move
/// a screen less two rows.
#[test]
fn small_corrections_hold() {
    let t0 = now();
    let later = t0 + super::app::ARMING;
    let cards: [(&str, Design); 3] = [
        ("card-80x24", frame!("card-80x24")),
        ("card-120x24", frame!("card-120x24")),
        ("card-120x40", frame!("card-120x40")),
    ];
    for (name, design) in cards {
        assert_drawn(
            name,
            &render(&tier3_card(t0), later, design.w, design.h),
            &design,
        );
    }
    let design = frame!("long-120x24");
    let mut app = long_conversation();
    app.scroll = 10;
    assert_drawn(
        "long-120x24",
        &render(&app, t0, design.w, design.h),
        &design,
    );

    // A call the gateway has not asked about yet is running.
    let mut app = tier3_card(t0);
    app.entries.push(Entry::Tool {
        id: "call_2".into(),
        name: "exec".into(),
        arguments: r#"{"command":"ls"}"#.into(),
        outcome: None,
        output: String::new(),
    });
    let b = render(&app, later, 120, 24);
    let shown: String = (0..24)
        .map(|y| {
            (0..120)
                .map(|x| b[(x, y)].symbol().to_string())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(shown.contains(r#"{"command":"ls"} running"#), "{shown}");
    // With no card the call is running.
    app.entries.pop();
    app.cards.clear();
    let b = render(&app, later, 120, 24);
    let row = |y: u16| -> String { (0..120).map(|x| b[(x, y)].symbol().to_string()).collect() };
    let shown: String = (0..24).map(row).collect::<Vec<_>>().join("\n");
    assert!(
        shown.contains("} running") && !shown.contains("needs approval"),
        "{shown}"
    );

    // A page is the rows drawn less two.
    let mut app = long_conversation();
    render(&app, t0, 120, 40);
    let rows = app.page_rows.get();
    app.on_key(key(crossterm::event::KeyCode::PageUp), t0);
    assert_eq!(app.scroll, rows - 2);
}

/// A: a card whose time ran out stays in front, dimmed in a gray single
/// rule, all seven fields in order and no answer field, until Esc puts it
/// away; Enter does nothing, and the transcript says what became of it
/// only then.
#[test]
fn an_expired_card_holds_until_esc() {
    use crossterm::event::KeyCode;
    let t0 = now();
    let late = t0 + Duration::from_secs(60);
    let make = || {
        let mut app = tier3_card(t0);
        app.on_server(
            super::wire::ServerEvent::Approval(super::wire::ApprovalAsk {
                request_id: "r2".into(),
                tool_name: "exec".into(),
                action_key: "shell:ls".into(),
                tier: "tier3".into(),
                agent: "default".into(),
                trigger: String::new(),
                exec_location: String::new(),
                arguments: r#"{"command":"ls"}"#.into(),
                assistant_text: String::new(),
                timeout_secs: 600,
                exec_runtime: "docker".into(),
            }),
            t0,
        );
        app.tick(late);
        app
    };
    for design in [frame!("expired-80x24"), frame!("expired-120x24")] {
        // The live card behind it waits, unseen.
        let app = make();
        let name = format!("expired-{}x{}", design.w, design.h);
        assert_drawn(&name, &render(&app, late, design.w, design.h), &design);
    }
    let mut app = make();
    let entries = app.entries.len();
    typed(&mut app, "y", late);
    assert_eq!(app.on_key(key(KeyCode::Enter), late), None);
    assert!(app.expired.is_some() && app.entries.len() == entries);
    assert_eq!(app.on_key(key(KeyCode::Esc), late), None);
    assert!(app.expired.is_none());
    assert!(
        matches!(app.entries.last(), Some(Entry::Note(n)) if n.ends_with("the gateway records it as refused."))
    );
    assert_eq!(
        app.front_card().map(|c| c.ask.request_id.as_str()),
        Some("r2")
    );
}

/// B: with more than one card waiting, the card in front says how many
/// more on its bottom border, the countdown stays alone on the answer's
/// rule, and every waiting call reads "needs approval".
#[test]
fn more_than_one_card_says_so_on_the_bottom_border() {
    let t0 = now();
    let later = t0 + super::app::ARMING;
    let make = || {
        let mut app = tier3_card(t0);
        for (n, command) in [
            (2, r#"{"command":"ls -la"}"#),
            (3, r#"{"command":"ls | wc -l"}"#),
        ] {
            app.entries.push(Entry::Tool {
                id: format!("call_{n}"),
                name: "exec".into(),
                arguments: command.into(),
                outcome: None,
                output: String::new(),
            });
            app.on_server(
                super::wire::ServerEvent::Approval(super::wire::ApprovalAsk {
                    request_id: format!("r{n}"),
                    tool_name: "exec".into(),
                    action_key: "shell:ls".into(),
                    tier: "tier3".into(),
                    agent: "default".into(),
                    trigger: String::new(),
                    exec_location: String::new(),
                    arguments: command.into(),
                    assistant_text: String::new(),
                    timeout_secs: 46,
                    exec_runtime: "docker".into(),
                }),
                t0,
            );
        }
        app
    };
    for design in [frame!("waiting-80x24"), frame!("waiting-120x24")] {
        let name = format!("waiting-{}x{}", design.w, design.h);
        assert_drawn(&name, &render(&make(), later, design.w, design.h), &design);
    }
}

/// C: Ctrl+P under 120 columns opens the panels over the transcript, in
/// two columns at 80 and three at 119, and says so when all six are
/// shown. In a shorter window they scroll, with the transcript's thumb
/// and the rows below on the bottom border.
#[test]
fn the_panels_overlay_fits_its_columns_and_scrolls_when_short() {
    use crossterm::event::KeyCode;
    let now = now();
    let make = |w: u16| {
        let mut app = app_with(1470, 14, 1);
        app.set_columns(w);
        app.on_key(ctrl('p'), now);
        app
    };
    for design in [frame!("panels-over-80x24"), frame!("panels-over-119x24")] {
        let name = format!("panels-over-{}x{}", design.w, design.h);
        assert_drawn(
            &name,
            &render(&make(design.w), now, design.w, design.h),
            &design,
        );
    }
    let mut app = make(80);
    let text = |b: &Buffer| -> String {
        (0..b.area.height)
            .map(|y| {
                (0..b.area.width)
                    .map(|x| b[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let b = render(&app, now, 80, 12);
    let shown = text(&b);
    assert!(
        shown.contains("↓ ") && shown.contains(" below") && !shown.contains("all six"),
        "{shown}"
    );
    assert!((1..10).any(|y| b[(79, y)].symbol() == "█"), "{shown}");
    assert!(shown.contains("↑↓ scroll"), "{shown}");
    for _ in 0..20 {
        app.on_key(key(KeyCode::Down), now);
    }
    let shown = text(&render(&app, now, 80, 12));
    assert!(
        shown.contains("write_file") && shown.contains(" above"),
        "{shown}"
    );
    // Down past the end goes no further, so Up moves at once.
    let end = app.panels_scroll;
    app.on_key(key(KeyCode::Up), now);
    assert_eq!(app.panels_scroll, end - 1);
}

/// D: under 120 columns Ctrl+B and Ctrl+F open the same conversations
/// over the transcript, the search at the bottom, each model and time at
/// the right edge, the selection on the open conversation.
#[test]
fn ctrl_b_and_ctrl_f_open_the_same_conversations_overlay() {
    let now = now();
    for design in [
        frame!("conversations-over-80x24"),
        frame!("conversations-over-119x24"),
    ] {
        let name = format!("conversations-over-{}x{}", design.w, design.h);
        for key in ['b', 'f'] {
            let mut app = app_with(0, 0, 0);
            app.set_columns(design.w);
            app.on_key(ctrl(key), now);
            assert_drawn(&name, &render(&app, now, design.w, design.h), &design);
        }
    }
    // The selection starts on the open conversation, not the newest.
    let mut app = App::new(Some("default".into()), "c-2".into());
    app.on_answer(Query::Conversations, directory());
    app.set_columns(80);
    app.on_key(ctrl('b'), now);
    let b = render(&app, now, 80, 24);
    let row: String = (0..80).map(|x| b[(x, 4)].symbol().to_string()).collect();
    assert!(row.contains("> Write a file named notes.txt"), "{row}");
}

/// 11: a "/" in an empty draft lists the ten commands above the draft,
/// and what is typed after it narrows the list, set apart as the keys
/// screen's filter sets it apart.
#[test]
fn a_slash_lists_the_commands_and_typing_narrows_them() {
    let now = now();
    let text = |b: &Buffer, y: u16| -> String {
        (0..b.area.width)
            .map(|x| b[(x, y)].symbol().to_string())
            .collect()
    };
    for (w, h) in [(80, 24), (120, 24), (120, 40)] {
        let mut app = long_conversation();
        app.set_columns(w);
        typed(&mut app, "/", now);
        let b = render(&app, now, w, h);
        let rule = (0..h)
            .find(|y| text(&b, *y).contains("┤") && text(&b, *y).contains("message"))
            .unwrap();
        let listed: Vec<String> = (rule - 10..rule).map(|y| text(&b, y)).collect();
        for ((name, what), row) in super::slash::COMMANDS.iter().zip(&listed) {
            assert!(row.contains(name) && row.contains(what), "{w}x{h}: {row}");
        }
        typed(&mut app, "c", now);
        let b = render(&app, now, w, h);
        let rows: Vec<String> = (rule - 3..rule).map(|y| text(&b, y)).collect();
        for (row, name) in rows.iter().zip(["/context", "/cost", "/clear"]) {
            assert!(row.contains(name), "{w}x{h}: {rows:?}");
        }
        // The typed part is set apart, as the keys screen's filter is.
        let x = u16::try_from(rows[0].chars().position(|c| c == '/').unwrap()).unwrap();
        assert_eq!(b[(x, rule - 3)].bg, palette::AMBER);
        assert!(!text(&b, rule - 4).contains("/status"), "{w}x{h}");
        typed(&mut app, "x", now);
        let b = render(&app, now, w, h);
        assert!(text(&b, rule - 1).contains("No command starts with \"/cx\"."));
    }
    // Not a command's start: no list.
    let mut app = long_conversation();
    app.set_columns(80);
    typed(&mut app, "/status now", now);
    assert!(super::view::command_list(&app.draft).is_none());
    assert!(super::view::command_list("hello").is_none());
    app.on_key(key(crossterm::event::KeyCode::Enter), now);
    assert!(super::view::command_list(&app.draft).is_none());
}
