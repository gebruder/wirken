//! The chat screen's state: the transcript, the draft, the approval
//! cards, the panels and the sidebar, and what each key and each frame
//! from the gateway does to them. No terminal I/O here; `mod.rs` drives
//! it.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::panels::{Directory, History, SideItem, Status, Verified, side_items, verified_line};
use super::slash::{self, Command};
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

/// A new conversation's id: `c-` and 12 hex digits.
pub(crate) fn new_conversation_id() -> String {
    let hex: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(12)
        .collect();
    format!("c-{hex}")
}

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
    /// Panels a command asked for, noted when the gateway's next status
    /// answer comes, so they say what it says now. `None` is every panel.
    notes_due: Vec<Option<&'static str>>,
    pub directory: Directory,
    pub show_sidebar: bool,
    pub show_panels: bool,
    /// The sidebar has the keys: typing filters, arrows select.
    pub searching: bool,
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
            notes_due: Vec::new(),
            directory: Directory::default(),
            show_sidebar: true,
            show_panels: true,
            searching: false,
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

    /// The card that takes keys now, if one does.
    pub fn front_card(&self) -> Option<&Card> {
        if self.expired.is_some() {
            None
        } else {
            self.cards.front()
        }
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
                });
            }
            ServerEvent::ToolResult { id, success, .. } => {
                if let Some(Entry::Tool { outcome, .. }) = self
                    .entries
                    .iter_mut()
                    .rev()
                    .find(|e| matches!(e, Entry::Tool { id: i, .. } if *i == id))
                {
                    *outcome = Some(success);
                }
            }
            ServerEvent::Approval(ask) => {
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
                self.streaming = false;
                self.busy = false;
                // The turn is over, so nothing it asked is still asked.
                if !self.cards.is_empty() {
                    self.cards.clear();
                    self.answer.clear();
                    self.entries.push(Entry::Note(
                        "The turn ended; its open approval requests closed with it.".into(),
                    ));
                }
                self.show_next(now);
                // What the turn changed: the panels and the list.
                return vec![
                    Outgoing::Ask(Query::Status),
                    Outgoing::Ask(Query::Conversations),
                ];
            }
            // Answers are matched to their query by the caller.
            ServerEvent::Answer { .. } | ServerEvent::Other => {}
        }
        Vec::new()
    }

    /// Take in the gateway's answer to `query`.
    pub fn on_answer(&mut self, query: Query, body: serde_json::Value) {
        match query {
            Query::Status => match serde_json::from_value::<Status>(body) {
                Ok(status) => {
                    if !status.agent.is_empty() {
                        self.agent = status.agent.clone();
                    }
                    for title in std::mem::take(&mut self.notes_due) {
                        self.entries.push(Entry::Note(slash::panel_note(
                            &status,
                            self.verified.as_ref(),
                            title,
                        )));
                    }
                    self.status = Some(status);
                }
                Err(_) if !self.notes_due.is_empty() => {
                    self.notes_due.clear();
                    self.entries.push(Entry::Note(
                        "The gateway's status answer could not be read.".into(),
                    ));
                }
                Err(_) => {}
            },
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
        self.notes_due.clear();
        self.searching = false;
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
            KeyCode::Char('b') if ctrl => {
                self.show_sidebar = !self.show_sidebar;
                self.searching &= self.show_sidebar;
                return None;
            }
            KeyCode::Char('p') if ctrl => {
                self.show_panels = !self.show_panels;
                return None;
            }
            KeyCode::Char('k') if ctrl => return Some(Outgoing::Ask(Query::Verify)),
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
                    let card = self.cards.pop_front().expect("a card is in front");
                    let answer = parse_answer(&std::mem::take(&mut self.answer));
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
                self.show_sidebar = true;
                self.searching = true;
                self.selected = 0;
                return None;
            }
            KeyCode::Char('n') if ctrl => {
                return self.open(self.requested_agent.clone(), new_conversation_id(), false);
            }
            _ => {}
        }

        if self.searching {
            match key.code {
                KeyCode::Esc => {
                    self.searching = false;
                    self.search.clear();
                }
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
                // A chat command runs here, during a turn too; it is
                // never sent.
                if let Some(command) = slash::parse(&self.draft) {
                    self.draft.clear();
                    self.cursor = 0;
                    self.scroll = 0;
                    return self.command(command);
                }
                if self.busy || self.draft.trim().is_empty() {
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

    fn command(&mut self, command: Command) -> Option<Outgoing> {
        match command {
            Command::Help => self.entries.push(Entry::Note(slash::help())),
            Command::Panel(title) => {
                self.notes_due.push(title);
                return Some(Outgoing::Ask(Query::Status));
            }
            Command::Verify => return Some(Outgoing::Ask(Query::Verify)),
            Command::Clear => {
                return self.open(self.requested_agent.clone(), new_conversation_id(), false);
            }
            Command::Quit => self.quit = true,
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
                    outcome: Some(true)
                },
                Entry::Agent("Done.".into()),
            ]
        );
    }

    #[test]
    fn ctrl_c_quits_from_anywhere() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_server(ask("r1", 0), now);
        app.on_key(ctrl('c'), now);
        assert!(app.quit);
    }

    fn entered(app: &mut App, draft: &str, now: Instant) -> Option<Outgoing> {
        typed(app, draft, now);
        app.on_key(key(KeyCode::Enter), now)
    }

    #[test]
    fn a_panel_command_notes_what_the_gateway_says_next() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        app.on_answer(Query::Status, serde_json::json!({"cost": {"calls": 1}}));
        assert_eq!(
            entered(&mut app, "/cost", now),
            Some(Outgoing::Ask(Query::Status))
        );
        assert!(app.draft.is_empty());
        assert!(app.entries.is_empty(), "nothing sent, nothing noted yet");
        app.on_answer(Query::Status, serde_json::json!({"cost": {"calls": 4}}));
        let [Entry::Note(note)] = app.entries.as_slice() else {
            panic!("{:?}", app.entries);
        };
        assert!(note.starts_with("Cost and tokens\n  4 calls"), "{note}");
        // The next status answer, one the chat asked for itself, notes
        // nothing.
        app.on_answer(Query::Status, serde_json::json!({}));
        assert_eq!(app.entries.len(), 1);
    }

    #[test]
    fn commands_run_during_a_turn_and_only_a_message_waits() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        entered(&mut app, "hi", now);
        assert!(app.busy);
        assert_eq!(
            entered(&mut app, "/verify", now),
            Some(Outgoing::Ask(Query::Verify))
        );
        assert_eq!(entered(&mut app, "/help", now), None);
        assert!(matches!(app.entries.last(), Some(Entry::Note(n)) if n.contains("/approvals")));
        assert_eq!(entered(&mut app, "/clear", now), None, "as Ctrl+N is");
        assert_eq!(app.conversation, "c-1");
        entered(&mut app, "/exit", now);
        assert!(app.quit);
    }

    #[test]
    fn clear_starts_a_new_conversation_with_the_same_agent() {
        let now = Instant::now();
        let mut app = App::new(Some("research".into()), "c-1".into());
        assert!(matches!(
            entered(&mut app, "/clear", now),
            Some(Outgoing::Open { agent: Some(a), resume: false, .. }) if a == "research"
        ));
        assert_ne!(app.conversation, "c-1");
    }

    /// A skill, or any `/word` the chat does not own, is a message for
    /// the gateway, sent as typed.
    #[test]
    fn any_other_slash_word_is_sent_as_typed() {
        let now = Instant::now();
        let mut app = App::new(Some("default".into()), "c-1".into());
        assert_eq!(
            entered(&mut app, "/summarise this week", now),
            Some(Outgoing::Message("/summarise this week".into()))
        );
        app.on_server(ServerEvent::Reply("ok".into()), now);
        assert_eq!(
            entered(&mut app, "/HELP", now),
            Some(Outgoing::Message("/HELP".into()))
        );
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
}
