//! The chat screen's state: the transcript, the draft, the approval
//! cards, the panels and the sidebar, and what each key and each frame
//! from the gateway does to them. No terminal I/O here; `mod.rs` drives
//! it.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::panels::{Directory, History, SideItem, Status, Verified, side_items, verified_line};
use super::text::{Answer, next_boundary, parse_answer, prev_boundary, sanitize};
use super::wire::{ApprovalAsk, Query, ServerEvent};

/// How long a card is on screen before it takes an answer, so a key
/// pressed for something else does not answer a card nobody read.
pub(crate) const ARMING: Duration = Duration::from_millis(700);

/// How long before the gateway gives up that the card closes, so an
/// answer sent at the last moment still reaches it in time.
const EXPIRY_MARGIN: Duration = Duration::from_secs(3);

/// One entry in the transcript. Text is kept as it arrived and
/// sanitized when drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Entry {
    User(String),
    Agent(String),
    Tool {
        id: String,
        name: String,
        arguments: String,
        /// `None` while it runs.
        outcome: Option<bool>,
        /// What it returned, as the chain records it. Empty while it
        /// runs.
        output: String,
    },
    Note(String),
}

/// An approval request waiting for the operator.
#[derive(Debug, Clone)]
pub(crate) struct Card {
    pub ask: ApprovalAsk,
    /// When it takes an answer. Set when it is first on screen.
    pub armed_at: Option<Instant>,
    /// When the screen closes it, if the gateway said how long it waits.
    pub expires_at: Option<Instant>,
}

/// What is drawn over the transcript in the compact layout, where the
/// sidebar and the panels have no columns of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Overlay {
    /// The agents and conversations, with the search.
    Conversations,
    Panels,
}

/// What the screen sends the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outgoing {
    Message(String),
    Decision {
        request_id: String,
        approve: bool,
        reason: Option<String>,
    },
    /// Ask the gateway about the current conversation.
    Ask(Query),
    /// Move to `conversation` with `agent` (`None` for the router's
    /// choice), reconnecting when the agent is not the connection's.
    /// `resume` asks for its messages.
    Open {
        agent: Option<String>,
        conversation: String,
        resume: bool,
    },
}

/// One group of the keys screen: a heading, and each key or keys with
/// what it does.
pub(crate) struct KeyGroup {
    pub title: &'static str,
    pub keys: &'static [(&'static str, &'static str)],
}

/// Every key the chat takes, by group, as the keys screen lists it;
/// `docs/cli.md` names each in its key table, which a test holds it to.
/// The commands are the slash commands' own table.
pub(crate) const KEYS: &[KeyGroup] = &[
    KeyGroup {
        title: "SCROLL",
        keys: &[
            ("PgUp PgDn", "scroll 10 rows"),
            ("↑ ↓ wheel", "scroll 3 rows"),
            ("End", "back to the latest row"),
        ],
    },
    KeyGroup {
        title: "WRITE",
        keys: &[
            ("Enter", "send"),
            ("Ctrl+J", "new line"),
            ("Home Ctrl+A", "start of the draft"),
            ("End Ctrl+E", "end of the draft"),
            ("Ctrl+U", "clear the draft or answer"),
        ],
    },
    KeyGroup {
        title: "CONVERSATIONS",
        keys: &[
            ("Ctrl+N", "new conversation"),
            ("Ctrl+F", "search conversations"),
        ],
    },
    KeyGroup {
        title: "APPROVALS",
        keys: &[
            ("y Enter", "approve the card"),
            ("n or Enter", "refuse; so does a reason"),
            ("Esc", "put away an expired card"),
            ("Ctrl+K", "verify the audit chain"),
        ],
    },
    KeyGroup {
        title: "SCREEN",
        keys: &[
            ("Ctrl+B", "toggle conversations"),
            ("Ctrl+P", "toggle panels"),
            ("Ctrl+G F1", "this screen"),
            ("Esc", "close this or the search"),
            ("Ctrl+C", "quit"),
        ],
    },
    KeyGroup {
        title: "COMMANDS",
        keys: super::slash::COMMANDS,
    },
];

/// What the keys screen says of the mouse, one entry: the first line
/// always, the second where there is room for it.
pub(crate) const MOUSE: (&str, &str) = (
    "wheel scrolls · drag selects text",
    "the chat does not capture the mouse",
);

/// The keys screen: what is typed to filter it, and how far its list is
/// scrolled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KeysScreen {
    pub filter: String,
    pub scroll: usize,
}

pub(crate) fn new_conversation_id() -> String {
    let hex: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(12)
        .collect();
    format!("c-{hex}")
}

/// What the transcript says when `y` is typed on a card that was not
/// drawn whole.
pub(crate) const CUT_CARD_NOTE: &str = "Not approved: the request is not shown in full on this \
     screen. Refuse it, or enlarge the terminal and answer again.";

pub(crate) struct App {
    /// The agent the header names: as asked for until the gateway says
    /// which agent the conversation is routed to.
    pub agent: String,
    /// The agent the connection asked for, `None` for the router's.
    pub requested_agent: Option<String>,
    pub conversation: String,
    /// What the gateway last said about this conversation.
    pub status: Option<Status>,
    pub verified: Option<Verified>,
    pub directory: Directory,
    pub show_sidebar: bool,
    pub show_panels: bool,
    /// The sidebar has the keys: typing filters, arrows select.
    pub searching: bool,
    /// The screen's width at the last draw, 0 before the first.
    pub columns: u16,
    /// Open over the transcript in the compact layout.
    pub overlay: Option<Overlay>,
    /// Every key and command, over the whole screen, while it is open.
    pub keys: Option<KeysScreen>,
    pub search: String,
    /// Index into the sidebar's filtered rows.
    pub selected: usize,
    pub entries: Vec<Entry>,
    /// The last entry is an agent reply still streaming.
    streaming: bool,
    /// A message was sent and its reply has not come back.
    pub busy: bool,
    pub draft: String,
    /// Byte offset in `draft`, on a grapheme boundary.
    pub cursor: usize,
    /// The draft set aside while cards are answered.
    set_aside: Option<(String, usize)>,
    /// The answer being typed on the card in front.
    pub answer: String,
    pub cards: VecDeque<Card>,
    /// A card the gateway stopped waiting for, shown until dismissed
    /// so a late answer lands on it and goes nowhere.
    pub expired: Option<ApprovalAsk>,
    /// Rows scrolled up from the bottom of the transcript.
    pub scroll: usize,
    pub quit: bool,
    /// The panel command waiting for the gateway's status answer.
    pub pending_panel: Option<super::slash::Command>,
    /// Whether the card in front was last drawn with its arguments cut
    /// or its bottom off the screen. Set by the view on each draw. A
    /// card in that state takes a refusal and no approval.
    pub card_cut: std::cell::Cell<bool>,
}

impl App {
    pub fn new(requested_agent: Option<String>, conversation: String) -> Self {
        Self {
            agent: requested_agent
                .clone()
                .unwrap_or_else(|| "routed agent".into()),
            requested_agent,
            conversation,
            status: None,
            verified: None,
            directory: Directory::default(),
            show_sidebar: true,
            show_panels: true,
            pending_panel: None,
            card_cut: std::cell::Cell::new(false),
            searching: false,
            columns: 0,
            overlay: None,
            keys: None,
            search: String::new(),
            selected: 0,
            entries: Vec::new(),
            streaming: false,
            busy: false,
            draft: String::new(),
            cursor: 0,
            set_aside: None,
            answer: String::new(),
            cards: VecDeque::new(),
            expired: None,
            scroll: 0,
            quit: false,
        }
    }

    /// Take the width the screen was last drawn at. A search open in
    /// the sidebar moves over the transcript when the window narrows to
    /// the compact layout, and back when it widens, so what is typed is
    /// always on screen.
    pub fn set_columns(&mut self, columns: u16) {
        self.columns = columns;
        if self.compact() {
            if self.searching {
                self.overlay = Some(Overlay::Conversations);
            }
        } else {
            self.overlay = None;
        }
    }

    /// Whether the window is narrower than the side-by-side layout.
    pub fn compact(&self) -> bool {
        self.columns > 0 && self.columns < super::view::WIDE_COLS
    }

    /// Open the conversations, searching, over the transcript or in the
    /// sidebar, as the width has room.
    fn search_conversations(&mut self) {
        if self.compact() {
            self.overlay = Some(Overlay::Conversations);
        } else {
            self.show_sidebar = true;
        }
        self.searching = true;
        self.selected = 0;
    }

    fn close_search(&mut self) {
        self.searching = false;
        self.search.clear();
        if self.overlay == Some(Overlay::Conversations) {
            self.overlay = None;
        }
    }

    /// The card that takes keys now, if one does.
    pub fn front_card(&self) -> Option<&Card> {
        if self.expired.is_some() {
            None
        } else {
            self.cards.front()
        }
    }

    /// The turn is over, by its reply or by a refusal: the screen takes
    /// a message again, and nothing the turn asked is still asked.
    /// Returns what the turn changed to ask for: the panels and the list.
    fn end_turn(&mut self, now: Instant) -> Vec<Outgoing> {
        self.streaming = false;
        self.busy = false;
        if !self.cards.is_empty() {
            self.cards.clear();
            self.answer.clear();
            self.entries.push(Entry::Note(
                "The turn ended; its open approval requests closed with it.".into(),
            ));
        }
        self.show_next(now);
        vec![
            Outgoing::Ask(Query::Status),
            Outgoing::Ask(Query::Conversations),
        ]
    }

    /// Take in a frame from the gateway. Returns what to ask next.
    pub fn on_server(&mut self, event: ServerEvent, now: Instant) -> Vec<Outgoing> {
        match event {
            ServerEvent::Chunk(text) => {
                match (self.streaming, self.entries.last_mut()) {
                    (true, Some(Entry::Agent(reply))) => reply.push_str(&text),
                    _ => self.entries.push(Entry::Agent(text)),
                }
                self.streaming = true;
            }
            ServerEvent::StreamError(error) => {
                self.streaming = false;
                self.entries
                    .push(Entry::Note(format!("the model's stream failed: {error}")));
            }
            ServerEvent::ToolCall {
                id,
                name,
                arguments,
            } => {
                self.streaming = false;
                self.entries.push(Entry::Tool {
                    id,
                    name,
                    arguments,
                    outcome: None,
                    output: String::new(),
                });
            }
            ServerEvent::ToolResult {
                id,
                success,
                output: returned,
                ..
            } => {
                if let Some(Entry::Tool {
                    outcome, output, ..
                }) = self
                    .entries
                    .iter_mut()
                    .rev()
                    .find(|e| matches!(e, Entry::Tool { id: i, .. } if *i == id))
                {
                    *outcome = Some(success);
                    *output = returned;
                }
            }
            ServerEvent::Approval(ask) => {
                // A card is answered where it is seen: nothing stays over it.
                self.keys = None;
                if self.overlay.is_some() {
                    self.close_search();
                    self.overlay = None;
                }
                let expires_at = (ask.timeout_secs > 0).then(|| {
                    now + Duration::from_secs(u64::from(ask.timeout_secs))
                        .saturating_sub(EXPIRY_MARGIN)
                });
                self.cards.push_back(Card {
                    ask,
                    armed_at: None,
                    expires_at,
                });
                self.show_next(now);
            }
            ServerEvent::Reply(text) => {
                // The recorded reply replaces what streamed for the
                // last round: it is the same text unless the gateway
                // withheld some of it.
                match (self.streaming, self.entries.last_mut()) {
                    (true, Some(Entry::Agent(reply))) => *reply = text,
                    _ => self.entries.push(Entry::Agent(text)),
                }
                return self.end_turn(now);
            }
            // No turn ran, or a stop ended the one running: the wait is
            // over all the same, and the next message can be sent.
            ServerEvent::Refused { reason, detail } => {
                self.entries.push(Entry::Note(if detail.is_empty() {
                    format!("The gateway refused this message ({reason}).")
                } else {
                    format!("The gateway refused this message ({reason}): {detail}.")
                }));
                return self.end_turn(now);
            }
            // Answers are matched to their query by the caller.
            ServerEvent::Answer { .. } | ServerEvent::Other => {}
        }
        Vec::new()
    }

    /// Run a slash command. The gateway is asked where the command needs
    /// its answer, and the note is written when the answer arrives.
    fn run_command(&mut self, command: super::slash::Command) -> Option<Outgoing> {
        use super::slash::Command;
        match command {
            Command::Status | Command::Panel(_) => {
                self.pending_panel = Some(command);
                Some(Outgoing::Ask(Query::Status))
            }
            Command::Verify => Some(Outgoing::Ask(Query::Verify)),
            Command::Help => {
                self.overlay = None;
                self.keys = Some(KeysScreen::default());
                None
            }
            Command::Clear => self.open(self.requested_agent.clone(), new_conversation_id(), false),
            Command::Quit => {
                self.quit = true;
                None
            }
        }
    }

    /// Take in the gateway's answer to `query`.
    pub fn on_answer(&mut self, query: Query, body: serde_json::Value) {
        match query {
            Query::Status => {
                if let Ok(status) = serde_json::from_value::<Status>(body) {
                    if !status.agent.is_empty() {
                        self.agent = status.agent.clone();
                    }
                    self.status = Some(status);
                }
                if let (Some(command), Some(status)) = (self.pending_panel.take(), &self.status) {
                    let panels = super::panels::panels(status, self.verified.as_ref());
                    let wanted = match command {
                        super::slash::Command::Panel(title) => Some(title),
                        _ => None,
                    };
                    for panel in panels
                        .iter()
                        .filter(|p| wanted.is_none_or(|title| p.title == title))
                    {
                        self.entries.push(Entry::Note(format!(
                            "{}\n{}",
                            panel.title,
                            panel.lines.join("\n")
                        )));
                    }
                }
            }
            Query::Verify => {
                let verified = serde_json::from_value::<Verified>(body).unwrap_or_default();
                self.entries.push(Entry::Note(verified_line(&verified)));
                self.verified = Some(verified);
            }
            Query::Conversations => {
                if let Ok(dir) = serde_json::from_value::<Directory>(body) {
                    self.directory = dir;
                }
            }
            Query::History => {
                let history = serde_json::from_value::<History>(body).unwrap_or_default();
                self.entries = history
                    .entries
                    .into_iter()
                    .filter_map(|e| match e.kind.as_str() {
                        "user" => Some(Entry::User(e.text)),
                        "agent" => Some(Entry::Agent(e.text)),
                        "tool" => Some(Entry::Tool {
                            id: e.id,
                            name: e.name,
                            arguments: e.arguments,
                            outcome: e.success,
                            output: e.output,
                        }),
                        _ => None,
                    })
                    .collect();
            }
        }
    }

    /// Move to another conversation. Refused while a turn runs or a
    /// card waits, since both belong to this one.
    fn open(
        &mut self,
        agent: Option<String>,
        conversation: String,
        resume: bool,
    ) -> Option<Outgoing> {
        if self.busy || !self.cards.is_empty() || self.expired.is_some() {
            self.entries.push(Entry::Note(
                "Finish this turn before moving to another conversation.".into(),
            ));
            return None;
        }
        self.entries.clear();
        self.streaming = false;
        self.scroll = 0;
        self.status = None;
        self.verified = None;
        self.searching = false;
        self.search.clear();
        self.overlay = None;
        if let Some(a) = &agent {
            self.agent = a.clone();
        }
        self.requested_agent = agent.clone();
        self.conversation = conversation.clone();
        Some(Outgoing::Open {
            agent,
            conversation,
            resume,
        })
    }

    /// The sidebar's rows under the current filter.
    pub fn side_items(&self) -> Vec<SideItem> {
        side_items(&self.directory, &self.search)
    }

    fn open_selected(&mut self) -> Option<Outgoing> {
        let items = self.side_items();
        match items.get(self.selected.min(items.len().saturating_sub(1)))? {
            SideItem::NewChat => {
                self.open(self.requested_agent.clone(), new_conversation_id(), false)
            }
            SideItem::Agent(i) => {
                let agent = self.directory.agents.get(*i)?.id.clone();
                self.open(Some(agent), new_conversation_id(), false)
            }
            SideItem::Conversation(i) => {
                let c = self.directory.conversations.get(*i)?.clone();
                self.open(Some(c.agent), c.conversation, true)
            }
        }
    }

    /// Close a card whose time is up.
    pub fn tick(&mut self, now: Instant) {
        let due = self
            .front_card()
            .and_then(|c| c.expires_at)
            .is_some_and(|at| now >= at);
        if due && let Some(card) = self.cards.pop_front() {
            self.answer.clear();
            self.entries.push(Entry::Note(format!(
                "The approval for {} expired without an answer; the gateway records it as \
                 refused.",
                card.ask.tool_name
            )));
            self.expired = Some(card.ask);
        }
    }

    /// Arm the card now in front, or give the draft back when none is.
    fn show_next(&mut self, now: Instant) {
        if self.expired.is_some() {
            return;
        }
        match self.cards.front_mut() {
            Some(card) => {
                if card.armed_at.is_none() {
                    card.armed_at = Some(now + ARMING);
                }
                if self.set_aside.is_none() && !self.draft.is_empty() {
                    self.set_aside = Some((
                        std::mem::take(&mut self.draft),
                        std::mem::replace(&mut self.cursor, 0),
                    ));
                }
            }
            None => {
                if let Some((draft, cursor)) = self.set_aside.take() {
                    self.draft = draft;
                    self.cursor = cursor;
                }
            }
        }
    }

    pub fn on_paste(&mut self, text: &str, now: Instant) {
        if self.expired.is_some() {
            return;
        }
        let clean = sanitize(text);
        if let Some(card) = self.front_card() {
            // Dropped while the card arms, as a key is.
            if card.armed_at.is_none_or(|at| now < at) {
                return;
            }
            // An answer is one line.
            self.answer.push_str(&clean.replace('\n', " "));
            return;
        }
        self.draft.insert_str(self.cursor, &clean);
        self.cursor += clean.len();
    }

    pub fn on_key(&mut self, key: KeyEvent, now: Instant) -> Option<Outgoing> {
        if key.kind == KeyEventKind::Release {
            return None;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        // The keys screen takes every key while it is open: typing
        // filters it, the arrows scroll it, Esc or Ctrl+G closes it.
        if let Some(screen) = &mut self.keys {
            match key.code {
                KeyCode::Esc => self.keys = None,
                KeyCode::Char('g') if ctrl => self.keys = None,
                KeyCode::Char('c') if ctrl => self.quit = true,
                KeyCode::Char('u') if ctrl => {
                    screen.filter.clear();
                    screen.scroll = 0;
                }
                KeyCode::Up => screen.scroll = screen.scroll.saturating_sub(1),
                KeyCode::Down => screen.scroll = screen.scroll.saturating_add(1),
                KeyCode::PageUp => screen.scroll = screen.scroll.saturating_sub(10),
                KeyCode::PageDown => screen.scroll = screen.scroll.saturating_add(10),
                KeyCode::Backspace => {
                    screen.filter.pop();
                    screen.scroll = 0;
                }
                KeyCode::Char(c) if !ctrl => {
                    screen.filter.push(c);
                    screen.scroll = 0;
                }
                _ => {}
            }
            return None;
        }
        // The panels over the transcript take only the keys that close
        // them, the keys screen and quitting.
        if self.overlay == Some(Overlay::Panels) {
            match key.code {
                KeyCode::Esc => self.overlay = None,
                KeyCode::Char('p') if ctrl => self.overlay = None,
                KeyCode::Char('c') if ctrl => self.quit = true,
                KeyCode::Char('g') if ctrl => {
                    self.overlay = None;
                    return self.run_command(super::slash::Command::Help);
                }
                _ => {}
            }
            return None;
        }
        match key.code {
            KeyCode::Char('c') if ctrl => {
                self.quit = true;
                return None;
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_add(10);
                return None;
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_sub(10);
                return None;
            }
            // Arrows scroll a few rows. They are also what most terminals
            // send for the mouse wheel and the trackpad on a full-screen
            // app, so scrolling the way one scrolls a terminal works. In
            // the sidebar search they move the selection instead.
            KeyCode::Up if !self.searching => {
                self.scroll = self.scroll.saturating_add(3);
                return None;
            }
            KeyCode::Down if !self.searching => {
                self.scroll = self.scroll.saturating_sub(3);
                return None;
            }
            // Scrolled up, End is back to the latest row. At the latest
            // row it falls through to the draft: the end of the line.
            KeyCode::End if !self.searching && self.scroll > 0 => {
                self.scroll = 0;
                return None;
            }
            // In the compact layout the sidebar and the panels open over
            // the transcript; side by side, the keys show or hide them.
            KeyCode::Char('b') if ctrl => {
                if self.compact() {
                    if self.overlay == Some(Overlay::Conversations) {
                        self.close_search();
                    } else {
                        self.search_conversations();
                    }
                } else {
                    self.show_sidebar = !self.show_sidebar;
                    if !self.show_sidebar {
                        self.close_search();
                    }
                }
                return None;
            }
            KeyCode::Char('p') if ctrl => {
                if self.compact() {
                    self.close_search();
                    self.overlay = Some(Overlay::Panels);
                } else {
                    self.show_panels = !self.show_panels;
                }
                return None;
            }
            KeyCode::Char('k') if ctrl => return Some(Outgoing::Ask(Query::Verify)),
            // The key the bar keeps on screen: every key and command.
            KeyCode::Char('g') if ctrl => return self.run_command(super::slash::Command::Help),
            KeyCode::F(1) => return self.run_command(super::slash::Command::Help),
            _ => {}
        }

        if self.expired.is_some() {
            // Whatever was typed for the card that expired goes
            // nowhere; Enter or Esc puts it away.
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                self.expired = None;
                self.answer.clear();
                self.show_next(now);
            }
            return None;
        }

        if let Some(card) = self.cards.front() {
            if card.armed_at.is_none_or(|at| now < at) {
                return None;
            }
            match key.code {
                KeyCode::Enter => {
                    let answer = parse_answer(&std::mem::take(&mut self.answer));
                    // An approval is of what was shown. A card drawn
                    // with its arguments cut stays in front and takes a
                    // refusal only.
                    if answer == Answer::Approve && self.card_cut.get() {
                        self.entries.push(Entry::Note(CUT_CARD_NOTE.to_string()));
                        return None;
                    }
                    let card = self.cards.pop_front().expect("a card is in front");
                    let (approve, reason) = match answer {
                        Answer::Approve => (true, None),
                        Answer::Deny(reason) => (false, reason),
                    };
                    self.entries.push(Entry::Note(format!(
                        "{} {}.",
                        if approve { "Approved" } else { "Refused" },
                        card.ask.tool_name
                    )));
                    self.show_next(now);
                    return Some(Outgoing::Decision {
                        request_id: card.ask.request_id,
                        approve,
                        reason,
                    });
                }
                KeyCode::Backspace => {
                    self.answer.pop();
                }
                KeyCode::Char('u') if ctrl => self.answer.clear(),
                KeyCode::Char(c) if !ctrl => self.answer.push(c),
                _ => {}
            }
            return None;
        }

        match key.code {
            KeyCode::Char('f') if ctrl => {
                self.search_conversations();
                return None;
            }
            KeyCode::Char('n') if ctrl => {
                return self.open(self.requested_agent.clone(), new_conversation_id(), false);
            }
            _ => {}
        }

        if self.searching {
            match key.code {
                KeyCode::Esc => self.close_search(),
                KeyCode::Enter => return self.open_selected(),
                KeyCode::Up => self.selected = self.selected.saturating_sub(1),
                KeyCode::Down => {
                    self.selected =
                        (self.selected + 1).min(self.side_items().len().saturating_sub(1));
                }
                KeyCode::Backspace => {
                    self.search.pop();
                    self.selected = 0;
                }
                KeyCode::Char(c) if !ctrl => {
                    self.search.push(c);
                    self.selected = 0;
                }
                _ => {}
            }
            return None;
        }

        match key.code {
            KeyCode::Enter => {
                if self.draft.trim().is_empty() {
                    return None;
                }
                // A command runs during a turn too, and is never sent to the
                // model. Anything else waits for the turn to end.
                if let Some(command) = super::slash::parse(&self.draft) {
                    self.draft.clear();
                    self.cursor = 0;
                    return self.run_command(command);
                }
                if self.busy {
                    return None;
                }
                let text = std::mem::take(&mut self.draft);
                self.cursor = 0;
                self.scroll = 0;
                self.busy = true;
                self.entries.push(Entry::User(text.clone()));
                return Some(Outgoing::Message(text));
            }
            // Shift+Enter is not reported without keyboard enhancement,
            // which not every terminal takes; Ctrl+J is.
            KeyCode::Char('j') if ctrl => self.insert("\n"),
            KeyCode::Char('u') if ctrl => {
                self.draft.clear();
                self.cursor = 0;
            }
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.draft.len(),
            KeyCode::Char(c) if !ctrl => self.insert(c.encode_utf8(&mut [0u8; 4])),
            KeyCode::Backspace => {
                let start = prev_boundary(&self.draft, self.cursor);
                self.draft.replace_range(start..self.cursor, "");
                self.cursor = start;
            }
            KeyCode::Delete => {
                let end = next_boundary(&self.draft, self.cursor);
                self.draft.replace_range(self.cursor..end, "");
            }
            KeyCode::Left => self.cursor = prev_boundary(&self.draft, self.cursor),
            KeyCode::Right => self.cursor = next_boundary(&self.draft, self.cursor),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.draft.len(),
            _ => {}
        }
        None
    }

    fn insert(&mut self, s: &str) {
        let clean = sanitize(s);
        self.draft.insert_str(self.cursor, &clean);
        self.cursor += clean.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn typed(app: &mut App, text: &str, now: Instant) -> Vec<Outgoing> {
        text.chars()
            .filter_map(|c| app.on_key(key(KeyCode::Char(c)), now))
            .collect()
    }

    fn ask(id: &str, timeout_secs: u32) -> ServerEvent {
        ServerEvent::Approval(ApprovalAsk {
            request_id: id.into(),
            tool_name: "exec".into(),
            action_key: "shell:ls".into(),
            tier: "tier2".into(),
            agent: "default".into(),
            trigger: String::new(),
            exec_location: String::new(),
            arguments: r#"{"command":"ls"}"#.into(),
            assistant_text: String::new(),
            timeout_secs,
            exec_runtime: "docker".into(),
        })
    }

    /// Enter with nothing typed refuses: no answer is consent, and
    /// neither choice is the default the key falls to.
    #[test]
    fn an_empty_enter_refuses() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_server(ask("r1", 0), now);
        let t = now + ARMING;
        assert_eq!(
            app.on_key(key(KeyCode::Enter), t),
            Some(Outgoing::Decision {
                request_id: "r1".into(),
                approve: false,
                reason: None
            })
        );
    }

    #[test]
    fn ctrl_k_asks_the_gateway_to_verify_and_the_result_is_noted() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        assert_eq!(
            app.on_key(ctrl('k'), now),
            Some(Outgoing::Ask(Query::Verify))
        );
        app.on_answer(
            Query::Verify,
            serde_json::json!({"chain": "ok", "rows": 9, "signed_heads": 1}),
        );
        assert!(
            matches!(app.entries.last(), Some(Entry::Note(n)) if n.contains("9 rows intact")),
            "{:?}",
            app.entries
        );
    }

    #[test]
    fn the_sidebar_search_filters_and_opens_the_selected_conversation() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_answer(
            Query::Conversations,
            serde_json::json!({
                "agents": [
                    {"id": "default", "provider": "ollama", "model": "llama3.1"},
                    {"id": "research", "provider": "ollama", "model": "qwen2.5"}
                ],
                "conversations": [
                    {"agent": "research", "conversation": "c-9", "title": "Compare two suppliers", "updated": "t"}
                ]
            }),
        );
        typed(&mut app, "draft", now);
        app.on_key(ctrl('f'), now);
        assert!(app.searching);
        typed(&mut app, "suppl", now);
        assert_eq!(
            app.draft, "draft",
            "typing went to the search, not the draft"
        );
        assert_eq!(
            app.side_items(),
            [
                SideItem::NewChat,
                SideItem::Agent(1),
                SideItem::Conversation(0)
            ]
        );
        app.on_key(key(KeyCode::Down), now);
        app.on_key(key(KeyCode::Down), now);
        assert_eq!(
            app.on_key(key(KeyCode::Enter), now),
            Some(Outgoing::Open {
                agent: Some("research".into()),
                conversation: "c-9".into(),
                resume: true
            })
        );
        assert_eq!(app.conversation, "c-9");
        assert!(!app.searching);

        app.on_answer(
            Query::History,
            serde_json::json!({"entries": [
                {"kind": "user", "text": "Compare two suppliers"},
                {"kind": "agent", "text": "Here is the comparison."}
            ]}),
        );
        assert_eq!(app.entries.len(), 2);
    }

    #[test]
    fn a_new_chat_is_refused_while_a_turn_runs() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        typed(&mut app, "hi", now);
        app.on_key(key(KeyCode::Enter), now);
        assert_eq!(app.on_key(ctrl('n'), now), None);
        assert_eq!(app.conversation, "c-1");
        app.on_server(ServerEvent::Reply("hello".into()), now);
        assert!(matches!(
            app.on_key(ctrl('n'), now),
            Some(Outgoing::Open { resume: false, .. })
        ));
        assert_ne!(app.conversation, "c-1");
    }

    #[test]
    fn a_refused_message_ends_the_wait_and_the_next_one_is_sent() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        typed(&mut app, "hi", now);
        assert_eq!(
            app.on_key(key(KeyCode::Enter), now),
            Some(Outgoing::Message("hi".into()))
        );
        assert!(app.busy);
        app.on_server(
            ServerEvent::Refused {
                reason: "agent_stopped".into(),
                detail: "agent 'default' is stopped".into(),
            },
            now,
        );
        assert!(!app.busy);
        assert!(
            matches!(app.entries.last(), Some(Entry::Note(n))
                if n.contains("refused") && n.contains("agent_stopped")
                    && n.contains("agent 'default' is stopped")),
            "{:?}",
            app.entries
        );
        typed(&mut app, "again", now);
        assert_eq!(
            app.on_key(key(KeyCode::Enter), now),
            Some(Outgoing::Message("again".into()))
        );
    }

    #[test]
    fn end_returns_to_the_latest_row_when_scrolled_and_ends_the_draft_otherwise() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        typed(&mut app, "hello", now);
        app.on_key(key(KeyCode::Home), now);
        assert_eq!(app.cursor, 0);

        app.on_key(key(KeyCode::Up), now);
        app.on_key(key(KeyCode::End), now);
        assert_eq!(app.scroll, 0, "scrolled up, End is the latest row");
        assert_eq!(app.cursor, 0, "and leaves the draft's cursor where it was");

        app.on_key(key(KeyCode::End), now);
        assert_eq!(
            app.cursor,
            "hello".len(),
            "at the latest row, End ends the draft"
        );
    }

    #[test]
    fn arrows_scroll_the_transcript_and_move_the_search_selection() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_key(key(KeyCode::Up), now);
        app.on_key(key(KeyCode::Up), now);
        assert_eq!(app.scroll, 6);
        app.on_key(key(KeyCode::Down), now);
        assert_eq!(app.scroll, 3);
        app.on_key(key(KeyCode::PageUp), now);
        assert_eq!(app.scroll, 13);
        app.on_key(key(KeyCode::End), now);
        assert_eq!(app.scroll, 0, "End returns to the latest row");
        app.on_key(key(KeyCode::Up), now);
        app.on_key(ctrl('f'), now);
        app.on_key(key(KeyCode::Down), now);
        assert_eq!(app.scroll, 3, "in search the arrows move the selection");
    }

    #[test]
    fn a_message_is_sent_once_and_waits_for_its_reply() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        typed(&mut app, "hi", now);
        app.on_key(ctrl('j'), now);
        typed(&mut app, "there", now);
        assert_eq!(
            app.on_key(key(KeyCode::Enter), now),
            Some(Outgoing::Message("hi\nthere".into()))
        );
        typed(&mut app, "again", now);
        assert_eq!(app.on_key(key(KeyCode::Enter), now), None, "busy");
        app.on_server(ServerEvent::Chunk("Hel".into()), now);
        app.on_server(ServerEvent::Chunk("lo".into()), now);
        app.on_server(ServerEvent::Reply("Hello".into()), now);
        assert!(!app.busy);
        assert_eq!(app.entries.last(), Some(&Entry::Agent("Hello".into())));
    }

    #[test]
    fn a_card_takes_no_key_while_arming_and_sets_the_draft_aside() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        typed(&mut app, "half a thought", now);
        app.on_server(ask("r1", 300), now);
        assert!(app.draft.is_empty(), "the draft is set aside");
        // Typed in the habit of answering something else.
        assert!(typed(&mut app, "y", now).is_empty());
        assert_eq!(app.on_key(key(KeyCode::Enter), now), None);
        assert!(app.answer.is_empty());

        let later = now + ARMING;
        typed(&mut app, "y", later);
        assert_eq!(
            app.on_key(key(KeyCode::Enter), later),
            Some(Outgoing::Decision {
                request_id: "r1".into(),
                approve: true,
                reason: None
            })
        );
        assert_eq!(app.draft, "half a thought", "and given back");
    }

    #[test]
    fn cards_are_answered_in_order_and_anything_but_y_refuses() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_server(ask("r1", 0), now);
        app.on_server(ask("r2", 0), now);
        let t = now + ARMING;
        typed(&mut app, "y please", t);
        assert_eq!(
            app.on_key(key(KeyCode::Enter), t),
            Some(Outgoing::Decision {
                request_id: "r1".into(),
                approve: false,
                reason: Some("y please".into())
            })
        );
        // The next card arms from when it came to the front.
        assert!(typed(&mut app, "y", t).is_empty());
        let t2 = t + ARMING;
        typed(&mut app, "yes", t2);
        assert_eq!(
            app.on_key(key(KeyCode::Enter), t2),
            Some(Outgoing::Decision {
                request_id: "r2".into(),
                approve: true,
                reason: None
            })
        );
    }

    #[test]
    fn an_expired_card_swallows_a_late_yes() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        typed(&mut app, "draft", now);
        app.on_server(ask("r1", 10), now);
        let t = now + ARMING;
        typed(&mut app, "y", t);
        app.tick(now + Duration::from_secs(10));
        assert!(app.expired.is_some());
        assert!(app.answer.is_empty(), "the half-typed answer is dropped");
        let late = now + Duration::from_secs(11);
        assert!(typed(&mut app, "y", late).is_empty());
        assert_eq!(
            app.on_key(key(KeyCode::Enter), late),
            None,
            "dismissed, not sent"
        );
        assert!(app.expired.is_none());
        assert_eq!(app.draft, "draft");
        assert!(matches!(app.entries.last(), Some(Entry::Note(n)) if n.contains("expired")));
    }

    #[test]
    fn tool_activity_closes_the_streamed_text_and_records_the_outcome() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_server(ServerEvent::Chunk("Checking.".into()), now);
        app.on_server(
            ServerEvent::ToolCall {
                id: "c1".into(),
                name: "exec".into(),
                arguments: "{}".into(),
            },
            now,
        );
        app.on_server(
            ServerEvent::ToolResult {
                id: "c1".into(),
                name: "exec".into(),
                success: true,
                output: "notes.txt\n".into(),
            },
            now,
        );
        app.on_server(ServerEvent::Chunk("Done.".into()), now);
        app.on_server(ServerEvent::Reply("Done.".into()), now);
        assert_eq!(
            app.entries,
            [
                Entry::Agent("Checking.".into()),
                Entry::Tool {
                    id: "c1".into(),
                    name: "exec".into(),
                    arguments: "{}".into(),
                    outcome: Some(true),
                    output: "notes.txt\n".into(),
                },
                Entry::Agent("Done.".into()),
            ]
        );
    }

    /// The model's reply after a tool round may be empty; what the tool
    /// returned stays in the transcript whatever the reply says, as it
    /// does when a conversation is resumed from the chain.
    #[test]
    fn a_tools_output_stays_when_the_reply_is_empty() {
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
        app.on_server(
            ServerEvent::ToolResult {
                id: "c1".into(),
                name: "exec".into(),
                success: true,
                output: "notes.txt\ntodo.md\n".into(),
            },
            now,
        );
        let fallback = "(no response: the model returned nothing)";
        app.on_server(ServerEvent::Reply(fallback.into()), now);
        let tool = Entry::Tool {
            id: "c1".into(),
            name: "exec".into(),
            arguments: r#"{"command":"ls"}"#.into(),
            outcome: Some(true),
            output: "notes.txt\ntodo.md\n".into(),
        };
        assert_eq!(app.entries, [tool.clone(), Entry::Agent(fallback.into())]);

        let mut resumed = App::new(Some("default".into()), "c-1".into());
        resumed.on_answer(
            Query::History,
            serde_json::json!({"entries": [
                {"kind": "tool", "id": "c1", "name": "exec", "arguments": "{\"command\":\"ls\"}",
                 "success": true, "output": "notes.txt\ntodo.md\n"},
                {"kind": "agent", "text": fallback},
            ]}),
        );
        assert_eq!(resumed.entries, app.entries);
    }

    #[test]
    fn ctrl_c_quits_from_anywhere() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_server(ask("r1", 0), now);
        app.on_key(ctrl('c'), now);
        assert!(app.quit);
    }

    #[test]
    fn the_draft_edits_by_grapheme() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_paste("a🙂b", now);
        app.on_key(key(KeyCode::Left), now);
        app.on_key(key(KeyCode::Backspace), now);
        assert_eq!(app.draft, "ab");
        assert_eq!(app.cursor, 1);
        app.on_paste("\x1b[31mred\u{202E}", now);
        assert_eq!(app.draft, "aredb");
    }

    /// A commanded draft, sent as the user would: typed, then Enter.
    fn command(app: &mut App, text: &str, now: Instant) -> Option<Outgoing> {
        typed(app, text, now);
        app.on_key(key(KeyCode::Enter), now)
    }

    #[test]
    fn status_asks_the_gateway_and_writes_every_panel_when_it_answers() {
        let mut app = App::new(Some("default".into()), "c-1".into());
        let now = Instant::now();
        assert_eq!(
            command(&mut app, "/status", now),
            Some(Outgoing::Ask(Query::Status))
        );
        assert!(
            !app.entries.iter().any(|e| matches!(e, Entry::User(_))),
            "a command is not a message"
        );
        app.on_answer(Query::Status, serde_json::json!({"agent": "default"}));
        let notes: Vec<&str> = app
            .entries
            .iter()
            .filter_map(|e| match e {
                Entry::Note(n) => Some(n.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            notes.iter().any(|n| n.starts_with("Context\n")),
            "{notes:?}"
        );
        assert!(
            notes.iter().any(|n| n.starts_with("Cost and tokens\n")),
            "{notes:?}"
        );
    }

    #[test]
    fn a_panel_command_writes_only_its_panel() {
        let mut app = App::new(Some("default".into()), "c-1".into());
        let now = Instant::now();
        assert_eq!(
            command(&mut app, "/cost", now),
            Some(Outgoing::Ask(Query::Status))
        );
        app.on_answer(Query::Status, serde_json::json!({"agent": "default"}));
        let notes: Vec<&str> = app
            .entries
            .iter()
            .filter_map(|e| match e {
                Entry::Note(n) => Some(n.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].starts_with("Cost and tokens\n"), "{notes:?}");
    }

    #[test]
    fn help_lists_every_command_and_sends_nothing() {
        let mut app = App::new(Some("default".into()), "c-1".into());
        assert_eq!(command(&mut app, "/help", Instant::now()), None);
        assert!(
            app.entries.is_empty(),
            "nothing printed into the transcript"
        );
        assert_eq!(app.keys, Some(KeysScreen::default()));
    }

    /// Every key the keys screen lists is in the key table of
    /// `docs/cli.md`, and every command in its command table.
    #[test]
    fn the_docs_name_every_key_and_command_the_keys_screen_lists() {
        let docs = include_str!("../../../../../docs/cli.md");
        let table = |head: &str| {
            let start = docs.find(head).expect(head);
            &docs[start..start + docs[start..].find("\n\n").unwrap()]
        };
        let keys = table("| Key | Action |");
        let commands = table("| Command | What it does |");
        for group in KEYS {
            let (table, what) = if group.title == "COMMANDS" {
                (commands, "command")
            } else {
                (keys, "key")
            };
            for (names, _) in group.keys {
                for name in names.split_whitespace().filter(|w| *w != "or") {
                    assert!(table.contains(name), "{what} {name} is not in docs/cli.md");
                }
            }
        }
    }

    #[test]
    fn commands_run_during_a_turn_and_are_never_sent_to_the_model() {
        let mut app = App::new(Some("default".into()), "c-1".into());
        let now = Instant::now();
        app.busy = true;
        assert_eq!(
            command(&mut app, "/status", now),
            Some(Outgoing::Ask(Query::Status))
        );
        assert_eq!(
            command(&mut app, "/verify", now),
            Some(Outgoing::Ask(Query::Verify))
        );
        assert_eq!(command(&mut app, "/clear", now), None, "refused mid-turn");
        assert!(app.entries.iter().any(|e| matches!(
            e,
            Entry::Note(n) if n.starts_with("Finish this turn")
        )));
        assert!(!app.quit);
        assert_eq!(command(&mut app, "/quit", now), None);
        assert!(app.quit);
    }

    #[test]
    fn an_unknown_slash_word_goes_to_the_gateway_as_typed() {
        let mut app = App::new(Some("default".into()), "c-1".into());
        assert_eq!(
            command(&mut app, "/summarize this week", Instant::now()),
            Some(Outgoing::Message("/summarize this week".into()))
        );
    }
}
