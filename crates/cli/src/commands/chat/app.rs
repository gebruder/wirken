//! State and event loop of the chat.
//!
//! One task owns the screen and the keyboard. Agents are woken through
//! one factory, as `wirken run` wakes them, so an agent can delegate to
//! the sub-agents it is allowed; a turn runs in a spawned task holding
//! the agent's lock, so the screen keeps drawing while the model works. Tool activity is read off the
//! audit chain as the runtime writes it, not from the stream, which
//! carries text only: the screen shows nothing the chain does not have.

use std::collections::VecDeque;
use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Rect;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use wirken_agent::Agent;
use wirken_agent::approval_gate::{ApprovalGate, ApprovalOutcome};
use wirken_agent::error::AgentError;
use wirken_agent::llm_stream::StreamEvent;
use wirken_agent::runtime::{InboundContext, ProcessResult};
use wirken_audit::{SessionEvent, SessionId, SessionLog as _, SqliteSessionLog};
use wirken_gateway::config::GatewayConfig;

use super::super::agent::{AgentInfo, ChatAgents, chat_agents, seal_session};
use super::super::stdin_approval::parse_decision;
use super::gate::{ApprovalAsk, ApprovalCard, ChatApprovalGate, card_answer};
use super::slash::{self, Builtin, Parsed};

/// One entry of the transcript.
pub(crate) enum Row {
    User {
        text: String,
        at: chrono::DateTime<chrono::Local>,
    },
    Assistant {
        text: String,
        open: bool,
        /// Time, duration and tokens, once the reply is complete.
        meta: Option<String>,
    },
    Tool {
        call_id: String,
        name: String,
        args: String,
        done: Option<ToolDone>,
        /// Arguments and output shown in place.
        expanded: bool,
    },
    /// A turn that failed: what it means in a sentence, and the error.
    Failure {
        explained: String,
        raw: String,
    },
    Card {
        card: ApprovalCard,
        verdict: Option<String>,
    },
    /// A run delegated to another agent with `spawn_subagent`: the child
    /// agent, the task it was given, its own lane once spawned, the
    /// ceiling it runs under, and how it ended.
    Delegation {
        call_id: String,
        agent: String,
        task: String,
        session: Option<String>,
        tools: Vec<String>,
        max_tier: Option<String>,
        end: Option<RunEnd>,
        expanded: bool,
    },
    Note(String),
    /// A log line held while the screen was up; shown with Ctrl+O.
    Log(String),
    Error(String),
    Panel(Vec<String>),
    Queued(String),
}

pub(crate) struct ToolDone {
    pub success: bool,
    pub output: String,
}

/// How a delegated run ended, from its `SubagentResult` row.
pub(crate) struct RunEnd {
    pub ok: bool,
    /// "done", "failed", "timed out", "ran out of rounds", "nested too deep".
    pub word: &'static str,
    /// What the child answered, or why it stopped.
    pub output: String,
}

/// A status word for a delegated run's end.
pub(crate) fn run_word(status: &wirken_audit::SubagentStatus) -> &'static str {
    use wirken_audit::SubagentStatus as S;
    match status {
        S::Ok => "done",
        S::Error => "failed",
        S::RoundsExceeded => "ran out of rounds",
        S::DepthExceeded => "nested too deep",
        S::Timeout => "timed out",
    }
}

/// The child's answer out of a `spawn_subagent` envelope
/// (`{child_session_id, status, output}`), or the text as it is.
pub(crate) fn envelope_output(text: &str) -> String {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("output").and_then(|o| o.as_str()).map(str::to_string))
        .unwrap_or_else(|| text.to_string())
}

/// The child agent and task out of `spawn_subagent` arguments.
pub(crate) fn spawn_args(arguments: &str) -> (String, String) {
    let v: serde_json::Value = serde_json::from_str(arguments).unwrap_or_default();
    (
        v["agent_id"].as_str().unwrap_or("?").to_string(),
        v["prompt"].as_str().unwrap_or_default().to_string(),
    )
}

/// What the status line shows. Read once at build, refreshed where the
/// value can move (the budget after a turn, the row count on each poll).
pub(crate) struct Status {
    pub agent: String,
    pub provider: String,
    pub model: String,
    pub exec: &'static str,
    pub budget: String,
    /// Share of the window's ceiling spent, when a budget is active.
    pub budget_pct: Option<u8>,
    pub signed: bool,
    pub rows: u64,
    pub cost_micros: u64,
    pub skills: usize,
    /// Operator decisions on this conversation's chain.
    pub approved: u32,
    pub denied: u32,
    /// Tokens the model takes.
    pub context_window: usize,
    /// Size of the last turn request on the chain.
    pub last_request_bytes: Option<u64>,
    /// Model calls on this conversation and their token counts.
    pub llm_calls: u32,
    pub tokens_in: u64,
    pub tokens_out: u64,
    /// A call had no price for its provider and model.
    pub uncosted: bool,
    /// The last on-demand verification: whether it held, what it said,
    /// and how many rows it covered.
    pub verify: Option<(bool, String, u64)>,
    /// What is set that weakens a guarantee, with how to undo it.
    pub issues: Vec<Issue>,
    /// Stored grants for the agent and the soonest expiry.
    pub grants: Option<(usize, Option<chrono::DateTime<chrono::Utc>>)>,
}

/// Something set that weakens a guarantee, and how to undo it.
pub(crate) struct Issue {
    pub what: String,
    pub fix: String,
}

/// One operator decision recorded on this conversation's chain.
pub(crate) struct Decision {
    pub key: String,
    pub approved: bool,
    pub detail: String,
}

/// How a tool reaches the tier gate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Asks {
    /// Tier 1, or handled before the gate.
    Never,
    /// Tier 2: asks until a grant is stored.
    Once,
    /// Tier 3: asks every time.
    Always,
    /// The arguments decide the tier.
    Depends,
}

pub(crate) struct ToolRow {
    pub name: String,
    pub asks: Asks,
    pub rule: String,
}

/// The panel's cards; each one is a click target.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CardKind {
    Environment,
    Safety,
    Context,
    Cost,
    Audit,
    Approvals,
    Tools,
    Delegations,
}

/// A run another chat delegated, as the sidebar nests it under that
/// chat: its lane, the agent and task, how deep it sits (a child's own
/// child is 2), and how it ended, if it has.
#[derive(Clone)]
pub(crate) struct ChildRun {
    pub session_id: String,
    pub agent: String,
    pub task: String,
    pub depth: usize,
    pub end: Option<(bool, &'static str)>,
}

/// A delegated run open for reading: the chat it belongs to, and the
/// agent that ran it.
pub(crate) struct RunView {
    /// The lane Esc goes back to: the run that spawned this one, or the
    /// chat.
    pub parent: String,
    pub agent: String,
    /// The agent this run works for.
    pub for_agent: String,
}

/// One chat conversation, as the sidebar lists it under its agent.
pub(crate) struct Conversation {
    pub children: Vec<ChildRun>,
    pub session_id: String,
    pub agent: String,
    pub title: String,
    pub last: chrono::DateTime<chrono::Utc>,
}

/// A configured agent and the provider/model it runs, for the sidebar's
/// group headers. The model is operator configuration; the chat only
/// shows it.
pub(crate) struct AgentEntry {
    pub id: String,
    pub model: String,
}

/// What a click landed on. The view records the areas as it draws.
#[derive(Clone)]
pub(crate) enum Hit {
    New,
    Search,
    Composer,
    Open(String),
    Agent(String),
    Card(CardKind),
    Approve,
    Deny,
    Retry,
    /// Copy the reply at this row.
    Copy(usize),
    /// Expand or fold the tool row at this row.
    Tool(usize),
    Starter(usize),
    /// Back to the latest output.
    Jump,
}

#[derive(PartialEq, Eq)]
pub(crate) enum Focus {
    Composer,
    Search,
}

/// What a turn's task hands back: the agent, and how the turn went.
type TurnResult = Result<ProcessResult, AgentError>;
/// A finished turn, or the task that ran it having died.
type TurnOutcome = Result<TurnResult, tokio::task::JoinError>;

enum Pending {
    Quit,
    Redraw,
    Clear,
    Setup,
}

/// What the event loop woke up for.
enum Step {
    Input(Option<Event>),
    Stream(StreamEvent),
    StreamClosed,
    /// Boxed: the agent inside is large, and this variant is rare.
    TurnDone(Box<TurnOutcome>),
    Ask(Option<ApprovalAsk>),
    Tick,
}

pub(crate) struct App {
    pub(crate) cfg: GatewayConfig,
    pub(crate) requested_agent: String,
    pub(crate) session_id: String,
    pub(crate) operator: String,
    /// The agent this conversation runs on, as the factory woke it.
    agent: Option<Arc<tokio::sync::Mutex<Agent>>>,
    factory: Arc<wirken_agent::AgentFactory>,
    /// Provider, model, window and workspace of each agent the factory
    /// knows.
    agent_info: std::collections::BTreeMap<String, AgentInfo>,
    /// Agents left out of the factory, with why.
    unavailable: Vec<(String, String)>,
    /// Set while a delegated run is open for reading.
    pub(crate) viewing: Option<RunView>,
    /// Text the chain has already placed that the stream has yet to
    /// deliver; see `cut_reply`.
    owed: String,
    /// Lanes of the cards still waiting; see `track_waiting`.
    waiting_lanes: Vec<String>,
    /// Sidebar summaries by lane, with the length each was read at.
    lane_cache: std::collections::HashMap<String, (u64, LaneSummary)>,
    /// Replies already laid out, by a hash of their text, width and
    /// mode: a long reply is laid out once, not on every frame.
    pub(crate) laid_out: std::cell::RefCell<
        std::collections::HashMap<(u64, usize, bool), Vec<ratatui::text::Line<'static>>>,
    >,
    /// Whether the last frame had room for the sidebar.
    pub(crate) wide: bool,
    log: Arc<SqliteSessionLog>,
    signed: bool,
    gate: Arc<ChatApprovalGate>,
    asks: mpsc::Receiver<ApprovalAsk>,

    pub(crate) rows: Vec<Row>,
    pub(crate) draft: String,
    /// Cursor as a character index into `draft`.
    pub(crate) cursor: usize,
    history: Vec<String>,
    history_at: Option<usize>,
    stash: String,
    queue: VecDeque<String>,
    /// Replies to the approval cards still waiting, oldest first; `y` or
    /// `n` answers the oldest. A turn's delegated runs go one after
    /// another today, but a second ask must queue, not replace the first:
    /// a dropped reply is a denial nobody gave.
    pub(crate) pending: VecDeque<oneshot::Sender<String>>,
    /// The draft set aside when a card arrived, given back once every
    /// card is answered: half a message must not become an answer.
    held_draft: Option<String>,
    /// No approval is taken before this: the oldest card has just come
    /// up, and a double click or a typed-ahead Enter must not approve a
    /// card nobody has read.
    armed_at: Instant,
    /// Set once the conversation and its runs are sealed on the way out.
    closed: bool,

    pub(crate) follow: bool,
    pub(crate) scroll: usize,
    pub(crate) pane_height: usize,
    pub(crate) verbose: bool,
    pub(crate) spinner: usize,
    pub(crate) status: Status,
    pub(crate) turn_started: Option<Instant>,
    pub(crate) skills: Vec<String>,
    skill_lines: Vec<String>,

    turn_rx: Option<mpsc::Receiver<StreamEvent>>,
    turn_task: Option<JoinHandle<TurnResult>>,
    next_seq: u64,
    last_esc: Option<Instant>,
    quit_armed: bool,
    action: Option<Pending>,
    /// Log messages already shown, so a warning repeated every turn is
    /// shown once.
    logs_seen: std::collections::HashSet<String>,

    pub(crate) conversations: Vec<Conversation>,
    pub(crate) agents: Vec<AgentEntry>,
    pub(crate) sidebar: bool,
    pub(crate) focus: Focus,
    pub(crate) filter: String,
    /// Clickable areas of the last frame.
    pub(crate) hits: Vec<(Rect, Hit)>,
    pub(crate) decisions: Vec<Decision>,
    pub(crate) tools: Vec<ToolRow>,
    /// The tool list is read again when the agent next sits idle.
    tools_stale: bool,
    /// Tokens on the chain when the running turn started.
    turn_tokens_start: u64,
    /// Whether the terminal has focus, for notifications.
    focused: bool,
    /// A short message for the footer, and when it was set.
    pub(crate) flash: Option<(String, Instant)>,
    /// Highlighted entry of the `/` menu.
    pub(crate) menu_at: usize,
    /// What the transcript held when the operator scrolled up: rows, and
    /// the length of the last reply; see `content_mark`.
    pub(crate) content_when_scrolled: (usize, usize),
    /// The agent's workspace, its file tools' root.
    workspace: std::path::PathBuf,
    /// Ways to start, for the empty screen.
    pub(crate) starters: Vec<String>,
}

impl Drop for App {
    fn drop(&mut self) {
        self.close_out();
    }
}

pub(crate) async fn run(
    cfg: GatewayConfig,
    requested_agent: String,
    first_message: Option<String>,
) -> Result<()> {
    let (ask_tx, ask_rx) = mpsc::channel(4);
    let operator = super::super::local_operator();
    let gate = Arc::new(ChatApprovalGate::new(ask_tx, operator.clone()));
    let session_id = new_session_id(&requested_agent);
    // Every agent is resolved here, before the screen is up, so a vault
    // passphrase prompt reaches a plain terminal.
    let agents = chat_agents(&cfg, gate.clone() as Arc<dyn ApprovalGate>)?;
    let mut app = App::new(
        cfg,
        requested_agent.clone(),
        session_id.clone(),
        operator,
        agents,
        gate,
        ask_rx,
    );
    app.wake(&requested_agent, &session_id)?;
    app.refresh_lists();

    restore_on_panic();
    let mut screen = Screen::enter()?;
    let paused = Arc::new(AtomicBool::new(false));
    let (key_tx, key_rx) = mpsc::channel(64);
    spawn_input_thread(key_tx, paused.clone());

    if let Some(text) = first_message {
        app.history.push(text.clone());
        app.start_turn(text);
    }

    let outcome = app.event_loop(&mut screen, key_rx, paused).await;
    for line in screen.leave() {
        eprintln!("{line}");
    }
    // A turn still running is stopped before the lanes are sealed, so
    // nothing it would write lands after the closing head.
    if let Some(task) = app.turn_task.take() {
        task.abort();
        let _ = task.await;
    }
    app.close_out();
    outcome
}

/// How long a card is on screen before it can be approved.
const ARMING: Duration = Duration::from_millis(700);

/// `{agent}/chat/c-<12 hex>`: the chat's own lane, one per conversation.
fn new_session_id(agent: &str) -> String {
    let hex: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(12)
        .collect();
    format!("{agent}/chat/c-{hex}")
}

/// Keyboard reader. `crossterm::event::read` blocks, so it lives on its
/// own thread; `paused` keeps it away from the terminal while the setup
/// wizard reads keys itself.
fn spawn_input_thread(tx: mpsc::Sender<Event>, paused: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        loop {
            if paused.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            match crossterm::event::poll(Duration::from_millis(100)) {
                Ok(true) => match crossterm::event::read() {
                    Ok(ev) => {
                        if tx.blocking_send(ev).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                },
                Ok(false) => {}
                Err(_) => return,
            }
        }
    });
}

/// The terminal in chat shape: raw mode on the alternate screen.
struct Screen {
    terminal: ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
}

impl Screen {
    fn enter() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("raw mode")?;
        let mut out = std::io::stdout();
        crossterm::execute!(
            out,
            crossterm::terminal::EnterAlternateScreen,
            crossterm::event::EnableBracketedPaste,
            crossterm::event::EnableMouseCapture,
            crossterm::event::EnableFocusChange
        )
        .context("alternate screen")?;
        let terminal = ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(out))
            .context("terminal")?;
        super::hold_logs();
        Ok(Self { terminal })
    }

    /// Wipe the screen and draw every cell again on the next frame.
    ///
    /// Not `Terminal::clear`: that snapshots the cursor with a query
    /// the terminal answers on stdin, which the key reader thread is
    /// reading, so the answer can be taken before it is seen and the
    /// chat would exit on the timeout. A fresh `Terminal` has no frame
    /// to diff against, so its first draw is the full repaint.
    fn repaint(&mut self) -> Result<()> {
        use ratatui::backend::{Backend as _, ClearType};
        self.terminal
            .backend_mut()
            .clear_region(ClearType::All)
            .context("clear")?;
        self.terminal =
            ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(std::io::stdout()))
                .context("terminal")?;
        Ok(())
    }

    /// Give the terminal back. Log lines held and not yet shown are
    /// returned for the caller to print or show.
    fn leave(&mut self) -> Vec<String> {
        leave_terminal();
        let _ = self.terminal.show_cursor();
        super::release_logs()
    }
}

fn leave_terminal() {
    let _ = crossterm::execute!(
        std::io::stdout(),
        crossterm::event::DisableFocusChange,
        crossterm::event::DisableMouseCapture,
        crossterm::event::DisableBracketedPaste,
        crossterm::terminal::LeaveAlternateScreen
    );
    let _ = crossterm::terminal::disable_raw_mode();
}

/// A panic inside the loop must not leave the terminal raw on the
/// alternate screen with the message drawn where nobody sees it.
fn restore_on_panic() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Only a panic on the main thread ends the chat; a turn task's
        // panic comes back as a failed turn and the screen carries on, so
        // the terminal must stay in the chat's mode for it.
        if std::thread::current().name() == Some("main") {
            leave_terminal();
            previous(info);
        } else if !super::hold_line(&format!(
            "{} ERROR panic in a background task: {}",
            chrono::Local::now().format("%H:%M:%S"),
            info.to_string().replace('\n', " ")
        )) {
            // Not holding: the screen is not up, so print as usual.
            previous(info);
        }
    }));
}

/// Text as the screen, the clipboard and an export may carry it: escape
/// sequences gone whole, and the invisible formatting characters that
/// make text read differently from what it is (bidirectional overrides
/// and isolates, zero-width spaces) dropped. Joiners stay: emoji
/// sequences need them.
pub(crate) fn plain(text: &str) -> String {
    wirken_agent::ansi::strip_control_sequences(text)
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{061C}'
                    | '\u{200B}'
                    | '\u{2060}'
                    | '\u{FEFF}'
            )
        })
        .collect()
}

/// Keep the draft to what a terminal can show: [`plain`], then any
/// control character other than newline and tab, C1 included.
pub(crate) fn scrub(text: &str) -> String {
    plain(text)
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

fn byte_index(s: &str, char_idx: usize) -> usize {
    s.char_indices().nth(char_idx).map_or(s.len(), |(i, _)| i)
}

pub(crate) fn usd(micros: u64) -> String {
    format!(
        "${}.{:02}",
        micros / 1_000_000,
        (micros % 1_000_000) / 10_000
    )
}

fn exec_label(cfg: &GatewayConfig) -> &'static str {
    use wirken_agent::sandbox::SandboxMode;
    match super::super::load_sandbox_config(&cfg.data_dir).mode {
        SandboxMode::Off => "exec: host",
        SandboxMode::ExecOnly => "exec: container",
        SandboxMode::GVisor => "exec: gvisor",
    }
}

/// The agent's budget line and the share spent, as WebChat's status
/// computes them: the resolved ceiling for the window, minus what the
/// ledger holds.
fn budget_info(cfg: &GatewayConfig, agent: &str) -> (String, Option<u8>) {
    use wirken_gateway::budget::{BudgetStore, load_budget_config};
    let Some(b) = load_budget_config(&cfg.budget_config_path())
        .ok()
        .and_then(|c| c.resolve(agent))
        .filter(|b| b.is_active())
    else {
        return ("budget off".to_string(), None);
    };
    let now = chrono::Utc::now().timestamp();
    let spent = BudgetStore::open(&cfg.budget_db_path())
        .ok()
        .and_then(|store| store.window_spend(agent, b.window.window_start(now)).ok());
    match spent {
        Some(spent) => (
            format!(
                "budget {} left this {}",
                usd(b.ceiling_usd_micros.saturating_sub(spent)),
                b.window.label()
            ),
            Some(spent_pct(spent, b.ceiling_usd_micros)),
        ),
        None => (
            format!(
                "budget {} per {}",
                usd(b.ceiling_usd_micros),
                b.window.label()
            ),
            None,
        ),
    }
}

/// Percent of `ceiling` that `spent` is, capped at 100.
fn spent_pct(spent: u64, ceiling: u64) -> u8 {
    if ceiling == 0 {
        return 100;
    }
    (spent.saturating_mul(100) / ceiling).min(100) as u8
}

/// Seal `lane` unless there is nothing to seal: no rows at all (a chat
/// opened and left), or a closing head already last (a conversation
/// opened only to read it). A lane is never written to just for being
/// looked at.
fn seal_if_open(log: &Arc<SqliteSessionLog>, lane: &str) {
    let handle = log.handle_for(SessionId::new(lane.to_string()));
    let Ok(Some(last)) = log.last_index(&handle) else {
        return;
    };
    let closed = log
        .get_since(&handle, last)
        .ok()
        .and_then(|rows| rows.into_iter().last())
        .is_some_and(|r| {
            matches!(
                r.event,
                SessionEvent::ChainHead {
                    reason: wirken_audit::ChainHeadReason::SessionEnd,
                    ..
                }
            )
        });
    if !closed {
        seal_session(log, lane);
    }
}

/// The agent a chat lane belongs to, from `{agent}/chat/c-<id>`. A
/// delegated run's lane (`{parent}#sub-N`) is not a chat of its own.
pub(crate) fn chat_owner(session_id: &str) -> Option<&str> {
    let (agent, rest) = session_id.split_once("/chat/")?;
    (!agent.is_empty() && !rest.is_empty() && !rest.contains("#sub-")).then_some(agent)
}

/// What the sidebar needs from one lane, kept until the lane grows.
#[derive(Clone, Default)]
pub(crate) struct LaneSummary {
    first_message: Option<String>,
    first_ts: Option<chrono::DateTime<chrono::Utc>>,
    last_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// The agent a delegated run's binding row names.
    bound_agent: Option<String>,
    /// How each run this lane spawned ended.
    ends: Vec<(String, bool, &'static str)>,
    /// The runs this lane spawned, with the agent each was given.
    spawned: Vec<(String, String)>,
}

/// Read one lane's summary, unless the cache has it at this length.
fn lane_summary(
    log: &SqliteSessionLog,
    cache: &mut std::collections::HashMap<String, (u64, LaneSummary)>,
    id: &str,
) -> Option<LaneSummary> {
    let handle = log.handle_for(SessionId::new(id.to_string()));
    let last = log.last_index(&handle).ok()??;
    if let Some((seen, summary)) = cache.get(id)
        && *seen == last
    {
        return Some(summary.clone());
    }
    let rows = log.get_since(&handle, 0).ok()?;
    let mut summary = LaneSummary {
        first_ts: rows.first().map(|r| r.ts),
        last_ts: rows.last().map(|r| r.ts),
        ..LaneSummary::default()
    };
    for r in &rows {
        match &r.event {
            SessionEvent::UserMessage { content, .. } if summary.first_message.is_none() => {
                summary.first_message = Some(content.clone());
            }
            SessionEvent::SubagentSessionBound { agent_id, .. } => {
                summary.bound_agent = Some(agent_id.clone());
            }
            SessionEvent::SubagentSpawned {
                child_session_id,
                child_agent_id,
                ..
            } => summary
                .spawned
                .push((child_session_id.clone(), child_agent_id.clone())),
            SessionEvent::SubagentResult {
                child_session_id,
                status,
                ..
            } => summary.ends.push((
                child_session_id.clone(),
                matches!(status, wirken_audit::SubagentStatus::Ok),
                run_word(status),
            )),
            _ => {}
        }
    }
    cache.insert(id.to_string(), (last, summary.clone()));
    Some(summary)
}

/// Every configured agent's chat conversations on the chain, newest
/// first, each titled by its first message, with the runs it delegated
/// nested under it. Lanes with no message (a chat opened and left) and
/// lanes of agents no longer configured are not listed. A lane is read
/// again only when it has grown since the last refresh.
fn list_conversations(
    log: &SqliteSessionLog,
    agents: &[AgentEntry],
    cache: &mut std::collections::HashMap<String, (u64, LaneSummary)>,
) -> Vec<Conversation> {
    let known = |agent: &str| agents.iter().any(|a| a.id == agent);
    let mut out: Vec<Conversation> = Vec::new();
    let mut runs: std::collections::HashMap<
        String,
        Vec<(chrono::DateTime<chrono::Utc>, ChildRun)>,
    > = std::collections::HashMap::new();
    let mut ends: std::collections::HashMap<String, (bool, &'static str)> =
        std::collections::HashMap::new();
    // A run's agent from the row that spawned it, for a lane with no
    // binding row of its own (the runtime's parallel spawn path does not
    // write one).
    let mut spawned: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for id in log.list_session_ids().unwrap_or_default() {
        let top = id.split_once("#sub-").map_or(id.as_str(), |(top, _)| top);
        let Some(agent) = chat_owner(top) else {
            continue;
        };
        if !known(agent) {
            continue;
        }
        let agent = agent.to_string();
        let Some(summary) = lane_summary(log, cache, &id) else {
            continue;
        };
        for (child, ok, word) in &summary.ends {
            ends.insert(child.clone(), (*ok, *word));
        }
        for (child, agent) in &summary.spawned {
            spawned.insert(child.clone(), agent.clone());
        }
        if top != id {
            let Some(first) = summary.first_ts else {
                continue;
            };
            runs.entry(top.to_string()).or_default().push((
                first,
                ChildRun {
                    depth: id.matches("#sub-").count(),
                    session_id: id.clone(),
                    agent: summary.bound_agent.clone().unwrap_or_default(),
                    task: summary.first_message.clone().unwrap_or_default(),
                    end: None,
                },
            ));
            continue;
        }
        let (Some(title), Some(last)) = (summary.first_message, summary.last_ts) else {
            continue;
        };
        out.push(Conversation {
            children: Vec::new(),
            session_id: id,
            agent,
            title,
            last,
        });
    }
    for c in &mut out {
        if let Some(mut kids) = runs.remove(&c.session_id) {
            kids.sort_by_key(|(at, _)| *at);
            c.children = kids
                .into_iter()
                .map(|(_, mut run)| {
                    run.end = ends.get(&run.session_id).copied();
                    if run.agent.is_empty() {
                        run.agent = spawned
                            .get(&run.session_id)
                            .cloned()
                            .unwrap_or_else(|| "run".to_string());
                    }
                    run
                })
                .collect();
        }
    }
    out.sort_by_key(|c| std::cmp::Reverse(c.last));
    out
}

/// The configured agents with their provider/model, `default` first
/// when it runs from the legacy `provider.json`.
fn list_agents(cfg: &GatewayConfig) -> Vec<AgentEntry> {
    let path = cfg.agent_config_db_path();
    let mut out: Vec<AgentEntry> = if path.exists() {
        wirken_gateway::agent_config::AgentConfigStore::open(&path)
            .and_then(|store| store.list())
            .map(|agents| {
                agents
                    .into_iter()
                    .map(|a| AgentEntry {
                        model: format!("{}/{}", a.provider, a.model),
                        id: a.id,
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let legacy = cfg.data_dir.join("provider.json");
    if !out.iter().any(|a| a.id == "default") && legacy.exists() {
        // The same defaults the builder applies to a sparse provider.json.
        let json: serde_json::Value = std::fs::read_to_string(&legacy)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        out.insert(
            0,
            AgentEntry {
                id: "default".to_string(),
                model: format!(
                    "{}/{}",
                    json["provider"].as_str().unwrap_or("ollama"),
                    json["model"].as_str().unwrap_or("llama3")
                ),
            },
        );
    }
    out
}

async fn recv_or_pending<T>(rx: &mut Option<mpsc::Receiver<T>>) -> Option<T> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

async fn join_or_pending<T>(task: &mut Option<JoinHandle<T>>) -> Result<T, tokio::task::JoinError> {
    match task {
        Some(task) => task.await,
        None => std::future::pending().await,
    }
}

impl App {
    fn new(
        cfg: GatewayConfig,
        requested_agent: String,
        session_id: String,
        operator: String,
        agents: ChatAgents,
        gate: Arc<ChatApprovalGate>,
        asks: mpsc::Receiver<ApprovalAsk>,
    ) -> Self {
        Self {
            cfg,
            requested_agent,
            session_id,
            operator,
            agent: None,
            factory: agents.factory,
            agent_info: agents.info,
            unavailable: agents.unavailable,
            viewing: None,
            owed: String::new(),
            waiting_lanes: Vec::new(),
            lane_cache: std::collections::HashMap::new(),
            laid_out: std::cell::RefCell::new(std::collections::HashMap::new()),
            wide: true,
            log: agents.log,
            signed: agents.signed,
            gate,
            asks,
            rows: Vec::new(),
            draft: String::new(),
            cursor: 0,
            history: Vec::new(),
            history_at: None,
            stash: String::new(),
            queue: VecDeque::new(),
            pending: VecDeque::new(),
            held_draft: None,
            armed_at: Instant::now(),
            closed: false,
            follow: true,
            scroll: 0,
            pane_height: 20,
            verbose: false,
            spinner: 0,
            status: Status {
                agent: String::new(),
                provider: String::new(),
                model: String::new(),
                exec: "",
                budget: String::new(),
                budget_pct: None,
                signed: false,
                rows: 0,
                cost_micros: 0,
                skills: 0,
                approved: 0,
                denied: 0,
                context_window: 0,
                last_request_bytes: None,
                llm_calls: 0,
                tokens_in: 0,
                tokens_out: 0,
                uncosted: false,
                verify: None,
                issues: Vec::new(),
                grants: None,
            },
            turn_started: None,
            skills: Vec::new(),
            skill_lines: Vec::new(),
            turn_rx: None,
            turn_task: None,
            next_seq: 0,
            last_esc: None,
            quit_armed: false,
            action: None,
            logs_seen: std::collections::HashSet::new(),
            conversations: Vec::new(),
            agents: Vec::new(),
            sidebar: true,
            focus: Focus::Composer,
            filter: String::new(),
            hits: Vec::new(),
            decisions: Vec::new(),
            tools: Vec::new(),
            tools_stale: true,
            turn_tokens_start: 0,
            focused: true,
            flash: None,
            menu_at: 0,
            content_when_scrolled: (0, 0),
            workspace: std::path::PathBuf::new(),
            starters: Vec::new(),
        }
    }

    /// Seal this conversation and every run it delegated, once, on the
    /// way out, also when the chat unwinds from a panic.
    fn close_out(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(task) = self.turn_task.take() {
            task.abort();
        }
        self.seal();
        self.seal_runs(true);
    }

    /// Take the agents of a fresh factory, after setup changed them.
    fn adopt_agents(&mut self, agents: ChatAgents) {
        self.factory = agents.factory;
        self.agent_info = agents.info;
        self.unavailable = agents.unavailable;
        self.log = agents.log;
        self.signed = agents.signed;
    }

    /// Wake `agent_id` on `session_id` through the factory: a lane with
    /// rows is replayed into the agent, an empty one starts fresh. An
    /// agent added since the chat started is picked up by reading the
    /// agents again once.
    fn wake(&mut self, agent_id: &str, session_id: &str) -> Result<()> {
        // Agents are read once, before the screen is up: reading them
        // again here could prompt for the vault passphrase under it.
        if let Some((_, why)) = self.unavailable.iter().find(|(id, _)| id == agent_id) {
            anyhow::bail!("agent '{agent_id}' is unavailable: {why}");
        }
        if !self.agent_info.contains_key(agent_id) {
            anyhow::bail!(
                "agent '{agent_id}' is not one this chat knows; `wirken agents list` shows the \
                 configured ones, and one added since the chat started appears when it is \
                 started again"
            );
        }
        let handle = self
            .factory
            .wake(agent_id, session_id)
            .with_context(|| format!("could not wake agent '{agent_id}'"))?;
        self.adopt(handle, agent_id);
        Ok(())
    }

    /// Take a freshly woken agent as the one this chat drives.
    fn adopt(&mut self, handle: Arc<tokio::sync::Mutex<Agent>>, agent_id: &str) {
        let info = self.agent_info.get(agent_id);
        let (provider, model, context_window) = info.map_or_else(
            || (String::new(), String::new(), 0),
            |i| (i.provider.clone(), i.model.clone(), i.context_window),
        );
        if let Some(i) = info {
            self.workspace = i.workspace.clone();
        }
        let agent_id = agent_id.to_string();
        let signed = self.signed;
        let log = self.log.clone();
        // Nothing holds a freshly woken agent: no turn runs yet.
        let skills = handle
            .try_lock()
            .map(|agent| agent.skills().to_vec())
            .unwrap_or_default();
        self.skills = skills.iter().map(|s| s.name.clone()).collect();
        self.skill_lines = skills
            .iter()
            .map(|s| {
                format!(
                    "/{:<20} {}{}  {}",
                    s.name,
                    if s.available { "" } else { "(unavailable) " },
                    if s.disable_model_invocation {
                        "slash-only"
                    } else {
                        "auto"
                    },
                    s.description
                )
            })
            .collect();
        let rows = log
            .handle_for(SessionId::new(self.session_id.clone()))
            .pipe(|h| log.last_index(&h).ok().flatten())
            .map_or(0, |i| i + 1);
        let (budget, budget_pct) = budget_info(&self.cfg, &agent_id);
        self.status = Status {
            agent: agent_id.clone(),
            provider,
            model,
            exec: exec_label(&self.cfg),
            budget,
            budget_pct,
            signed,
            rows,
            cost_micros: 0,
            skills: self.skills.len(),
            approved: 0,
            denied: 0,
            context_window,
            last_request_bytes: None,
            llm_calls: 0,
            tokens_in: 0,
            tokens_out: 0,
            uncosted: false,
            verify: None,
            issues: Vec::new(),
            grants: None,
        };
        self.next_seq = rows;
        self.agent = Some(handle);
        self.decisions.clear();
        self.tools_stale = true;
        self.refresh_checks();
    }

    /// Re-read what weakens a guarantee and the stored grants.
    fn refresh_checks(&mut self) {
        self.status.issues = issues(&self.cfg, self.status.signed, self.status.exec);
        self.status.grants = super::super::open_permission_store(&self.cfg)
            .ok()
            .and_then(|store| store.list(&self.status.agent).ok())
            .map(|grants| {
                let soonest = grants.iter().map(|g| g.expires_at).min();
                (grants.len(), soonest)
            });
    }

    fn seal(&self) {
        // A delegated run open for reading is not this chat's to close.
        if self.viewing.is_none() {
            seal_if_open(&self.log, &self.session_id);
        }
    }

    /// The agent behind a lane: a delegated run's own, from its binding
    /// row, else the chat's.
    fn lane_agent(&self, lane: &str) -> String {
        if !lane.contains("#sub-") {
            return chat_owner(lane).unwrap_or("its chat").to_string();
        }
        let rows_of = |id: &str| {
            let handle = self.log.handle_for(SessionId::new(id.to_string()));
            self.log.get_since(&handle, 0).unwrap_or_default()
        };
        let bound = rows_of(lane).into_iter().find_map(|r| match r.event {
            SessionEvent::SubagentSessionBound { agent_id, .. } => Some(agent_id),
            _ => None,
        });
        // A lane with no binding row of its own (the runtime's parallel
        // spawn path writes none): the row that spawned it names it.
        bound
            .or_else(|| {
                let parent = lane.rsplit_once("#sub-")?.0;
                rows_of(parent).into_iter().find_map(|r| match r.event {
                    SessionEvent::SubagentSpawned {
                        child_session_id,
                        child_agent_id,
                        ..
                    } if child_session_id == lane => Some(child_agent_id),
                    _ => None,
                })
            })
            .unwrap_or_else(|| "delegated run".to_string())
    }

    pub(crate) fn busy(&self) -> bool {
        self.turn_task.is_some()
    }

    fn note(&mut self, text: impl Into<String>) {
        self.rows.push(Row::Note(text.into()));
        self.follow = true;
    }

    async fn event_loop(
        &mut self,
        screen: &mut Screen,
        mut keys: mpsc::Receiver<Event>,
        paused: Arc<AtomicBool>,
    ) -> Result<()> {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        // A terminal closed, `kill` or a session ending leave as /quit
        // does: the screen restored and the lanes sealed.
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let mut hup = signal(SignalKind::hangup())?;
        let mut int = signal(SignalKind::interrupt())?;
        // Drawn when something changed, not on every event: a moving
        // mouse reports each cell it crosses, and an idle tick changes
        // nothing on screen.
        let mut dirty = true;
        loop {
            if dirty {
                screen
                    .terminal
                    .draw(|frame| super::view::draw(frame, self))?;
            }
            let rows_before = self.rows.len();
            let waiting_before = self.pending.len();

            let step = tokio::select! {
                ev = keys.recv() => Step::Input(ev),
                ev = recv_or_pending(&mut self.turn_rx) => match ev {
                    Some(ev) => Step::Stream(ev),
                    None => Step::StreamClosed,
                },
                done = join_or_pending(&mut self.turn_task) => Step::TurnDone(Box::new(done)),
                ask = self.asks.recv() => Step::Ask(ask),
                _ = tick.tick() => Step::Tick,
                _ = term.recv() => return Ok(()),
                _ = hup.recv() => return Ok(()),
                _ = int.recv() => return Ok(()),
            };

            let idle_tick = matches!(step, Step::Tick);
            dirty = !matches!(
                step,
                Step::Input(Some(Event::Mouse(MouseEvent {
                    kind: MouseEventKind::Moved | MouseEventKind::Up(_),
                    ..
                })))
            );
            match step {
                Step::Input(None) => anyhow::bail!("the terminal input closed"),
                Step::Input(Some(Event::Key(key))) => self.on_key(key),
                Step::Input(Some(Event::Paste(text))) => self.insert_str(&text),
                Step::Input(Some(Event::Mouse(mouse))) => self.on_mouse(mouse),
                Step::Input(Some(Event::FocusGained)) => self.focused = true,
                Step::Input(Some(Event::FocusLost)) => self.focused = false,
                Step::Input(Some(_)) => {}
                Step::Stream(ev) => {
                    // Everything already queued, then one frame.
                    self.on_stream(ev);
                    self.drain_stream();
                }
                Step::StreamClosed => self.turn_rx = None,
                Step::TurnDone(done) => self.on_turn_done(*done),
                Step::Ask(None) => anyhow::bail!("the approval channel closed"),
                Step::Ask(Some(ask)) => self.on_ask(ask),
                Step::Tick => self.on_tick(),
            }
            if idle_tick {
                let flashing = self
                    .flash
                    .as_ref()
                    .is_some_and(|(_, at)| at.elapsed() < Duration::from_millis(3500));
                // A card that expired or was withdrawn on this tick
                // changes in place: the queue shrank, the rows did not.
                dirty = self.busy()
                    || !self.pending.is_empty()
                    || self.pending.len() != waiting_before
                    || flashing
                    || self.rows.len() != rows_before;
            }

            // Read while the agent sits idle: a turn holds its lock.
            if self.tools_stale
                && let Some(handle) = self.agent.clone()
                && let Ok(agent) = handle.try_lock()
            {
                self.tools = tool_rows(&agent).await;
                self.starters = starters(&self.tools, &self.skills);
                self.tools_stale = false;
                dirty = true;
            }

            match self.action.take() {
                None => {}
                Some(Pending::Quit) => return Ok(()),
                Some(Pending::Redraw) => screen.repaint()?,
                Some(Pending::Clear) => self.restart(""),
                Some(Pending::Setup) => {
                    // Ctrl+C in the wizard ends the process, as it does
                    // for `wirken setup`: close the chain first.
                    self.seal();
                    let held = screen.leave();
                    self.show_logs(held);
                    paused.store(true, Ordering::Relaxed);
                    // Let the reader thread finish the poll it is in.
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    let mut outcome = super::super::setup::run(false, None).await;
                    // The wizard can change any agent's provider: read
                    // them again, still on the plain terminal.
                    if outcome.is_ok() {
                        match chat_agents(&self.cfg, self.gate.clone() as Arc<dyn ApprovalGate>) {
                            Ok(agents) => self.adopt_agents(agents),
                            Err(e) => outcome = Err(e),
                        }
                    }
                    paused.store(false, Ordering::Relaxed);
                    *screen = Screen::enter()?;
                    match outcome {
                        Ok(()) => self.restart("setup finished"),
                        Err(e) => self.rows.push(Row::Error(format!("setup: {e:#}"))),
                    }
                }
            }
        }
    }

    /// Seal this conversation and start the next one on a rebuilt agent,
    /// so a provider changed by setup is the one that answers.
    fn restart(&mut self, why: &str) {
        self.seal();
        self.seal_runs(true);
        self.viewing = None;
        self.session_id = new_session_id(&self.requested_agent);
        self.rows.clear();
        self.queue.clear();
        self.pending.clear();
        self.track_waiting();
        self.follow = true;
        self.scroll = 0;
        let (agent, session) = (self.requested_agent.clone(), self.session_id.clone());
        match self.wake(&agent, &session) {
            Ok(()) => {
                if !why.is_empty() {
                    self.note(why.to_string());
                }
                self.refresh_lists();
            }
            Err(e) => {
                self.agent = None;
                self.rows
                    .push(Row::Error(format!("could not build the agent: {e:#}")));
                self.note("fix the configuration, then /setup or /quit");
            }
        }
    }

    // ----- keys -----

    fn on_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        if self.focus == Focus::Search {
            self.on_search_key(key);
            return;
        }
        match key.code {
            KeyCode::Char('n') if ctrl => return self.new_conversation(),
            KeyCode::Char('r') if ctrl => return self.retry(),
            KeyCode::Char('y') if ctrl => return self.copy_last(),
            KeyCode::Char('b') if ctrl => {
                self.sidebar = !self.sidebar;
                return;
            }
            KeyCode::Char('f') if ctrl => {
                if !self.wide {
                    return self.flash("search lives in the sidebar, which needs 100 columns");
                }
                self.sidebar = true;
                self.focus = Focus::Search;
                return;
            }
            KeyCode::Up if ctrl || alt => return self.step_conversation(-1),
            KeyCode::Down if ctrl || alt => return self.step_conversation(1),
            _ => {}
        }
        match (key.code, ctrl) {
            (KeyCode::Char('c'), true) => {
                if !self.draft.is_empty() {
                    self.clear_draft();
                } else if self.busy() {
                    self.note(
                        "a turn runs to completion; answer a pending approval with n to stop a tool, \
                         or /quit twice to leave anyway",
                    );
                } else {
                    self.action = Some(Pending::Quit);
                }
            }
            (KeyCode::Char('d'), true) => {
                if self.draft.is_empty() {
                    self.run_builtin(Builtin::Quit);
                }
            }
            (KeyCode::Char('l'), true) => self.action = Some(Pending::Redraw),
            (KeyCode::Char('o'), true) => self.verbose = !self.verbose,
            (KeyCode::Char('j'), true) => self.insert_char('\n'),
            (KeyCode::Char('a'), true) => self.cursor = self.line_start(),
            (KeyCode::Char('e'), true) => self.cursor = self.line_end(),
            (KeyCode::Char('u'), true) => self.clear_draft(),
            (KeyCode::Char('w'), true) => self.delete_word_back(),
            (KeyCode::Enter, _) if shift => self.insert_char('\n'),
            (KeyCode::Enter, _) if self.menu_open() && !self.menu_exact() => self.complete(),
            (KeyCode::Enter, _) => self.submit(),
            (KeyCode::Esc, _) => self.on_esc(),
            (KeyCode::Tab, _) => self.complete(),
            (KeyCode::Up, _) if self.menu_open() => self.menu_at = self.menu_at.saturating_sub(1),
            (KeyCode::Down, _) if self.menu_open() => {
                self.menu_at = (self.menu_at + 1).min(self.menu_items().len().saturating_sub(1));
            }
            (KeyCode::Up, _) => self.history_prev(),
            (KeyCode::Down, _) => self.history_next(),
            (KeyCode::PageUp, _) => self.scroll_by(-(self.pane_height as isize / 2).max(1)),
            (KeyCode::PageDown, _) => self.scroll_by((self.pane_height as isize / 2).max(1)),
            (KeyCode::Home, _) => {
                if self.follow {
                    self.content_when_scrolled = self.content_mark();
                }
                self.follow = false;
                self.scroll = 0;
            }
            (KeyCode::End, _) => self.follow = true,
            (KeyCode::Left, _) => self.cursor = self.cursor.saturating_sub(1),
            (KeyCode::Right, _) => {
                self.cursor = (self.cursor + 1).min(self.draft.chars().count());
            }
            (KeyCode::Backspace, _) => self.backspace(),
            (KeyCode::Delete, _) => self.delete_forward(),
            (KeyCode::Char('?'), false) if self.draft.is_empty() && self.pending.is_empty() => {
                self.run_builtin(Builtin::Help);
            }
            (KeyCode::Char(c), false) => self.insert_char(c),
            _ => {}
        }
    }

    fn on_esc(&mut self) {
        if !self.pending.is_empty() {
            self.answer(String::new());
            return;
        }
        if !self.draft.is_empty() {
            let now = Instant::now();
            match self.last_esc {
                Some(t) if now.duration_since(t) < Duration::from_secs(1) => {
                    self.clear_draft();
                    self.last_esc = None;
                }
                _ => self.last_esc = Some(now),
            }
            return;
        }
        if let Some(view) = &self.viewing {
            // Back up one level: to the run that spawned this one, or to
            // the chat.
            let parent = view.parent.clone();
            if parent.contains("#sub-") {
                return self.view_run(parent);
            }
            return self.open_conversation(parent);
        }
        if self.busy() {
            self.note("a turn runs to completion; answer a pending approval with n to stop a tool");
        }
    }

    fn scroll_by(&mut self, delta: isize) {
        if self.follow {
            self.content_when_scrolled = self.content_mark();
        }
        self.follow = false;
        let next = self.scroll as isize + delta;
        self.scroll = next.max(0) as usize;
    }

    // ----- draft editing -----

    fn insert_char(&mut self, c: char) {
        let at = byte_index(&self.draft, self.cursor);
        self.draft.insert(at, c);
        self.cursor += 1;
    }

    fn insert_str(&mut self, text: &str) {
        let text = scrub(text);
        let at = byte_index(&self.draft, self.cursor);
        self.draft.insert_str(at, &text);
        self.cursor += text.chars().count();
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            let at = byte_index(&self.draft, self.cursor);
            self.draft.remove(at);
        }
    }

    fn delete_forward(&mut self) {
        if self.cursor < self.draft.chars().count() {
            let at = byte_index(&self.draft, self.cursor);
            self.draft.remove(at);
        }
    }

    fn delete_word_back(&mut self) {
        let chars: Vec<char> = self.draft.chars().collect();
        let mut end = self.cursor.min(chars.len());
        while end > 0 && chars[end - 1] == ' ' {
            end -= 1;
        }
        while end > 0 && chars[end - 1] != ' ' && chars[end - 1] != '\n' {
            end -= 1;
        }
        let kept: String = chars[..end]
            .iter()
            .chain(chars[self.cursor.min(chars.len())..].iter())
            .collect();
        self.draft = kept;
        self.cursor = end;
    }

    fn clear_draft(&mut self) {
        self.draft.clear();
        self.cursor = 0;
        self.history_at = None;
    }

    fn line_start(&self) -> usize {
        let chars: Vec<char> = self.draft.chars().collect();
        let mut i = self.cursor.min(chars.len());
        while i > 0 && chars[i - 1] != '\n' {
            i -= 1;
        }
        i
    }

    fn line_end(&self) -> usize {
        let chars: Vec<char> = self.draft.chars().collect();
        let mut i = self.cursor.min(chars.len());
        while i < chars.len() && chars[i] != '\n' {
            i += 1;
        }
        i
    }

    fn history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let at = match self.history_at {
            None => {
                self.stash = self.draft.clone();
                self.history.len() - 1
            }
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.history_at = Some(at);
        self.draft = self.history[at].clone();
        self.cursor = self.draft.chars().count();
    }

    fn history_next(&mut self) {
        let Some(at) = self.history_at else {
            return;
        };
        if at + 1 < self.history.len() {
            self.history_at = Some(at + 1);
            self.draft = self.history[at + 1].clone();
        } else {
            self.history_at = None;
            self.draft = std::mem::take(&mut self.stash);
        }
        self.cursor = self.draft.chars().count();
    }

    /// The `/` menu's entries for the draft, at most six.
    pub(crate) fn menu_items(&self) -> Vec<String> {
        if !self.pending.is_empty() {
            return Vec::new();
        }
        slash::completions(&self.draft, &self.skills)
    }

    fn menu_open(&self) -> bool {
        !self.menu_items().is_empty()
    }

    /// The draft is already a whole command name.
    fn menu_exact(&self) -> bool {
        self.menu_items().contains(&self.draft)
    }

    fn complete(&mut self) {
        let items = self.menu_items();
        if let Some(pick) = items.get(self.menu_at.min(items.len().saturating_sub(1))) {
            self.draft = format!("{pick} ");
            self.cursor = self.draft.chars().count();
        }
        self.menu_at = 0;
    }

    // ----- submit -----

    fn submit(&mut self) {
        let text = scrub(&std::mem::take(&mut self.draft));
        self.cursor = 0;
        self.history_at = None;
        self.follow = true;
        if !self.pending.is_empty() {
            match card_answer(&text) {
                Some(_) if Instant::now() < self.armed_at => {
                    self.draft = text;
                    self.cursor = self.draft.chars().count();
                    self.flash("the card has just come up; read it, then answer");
                }
                Some(line) => self.answer(line),
                // The chat's own commands still work, `/quit` among them;
                // they answer no card.
                None if matches!(slash::parse(&text), Parsed::Builtin(_)) => {
                    if let Parsed::Builtin(builtin) = slash::parse(&text) {
                        self.run_builtin(builtin);
                    }
                }
                None => {
                    self.draft = text;
                    self.cursor = self.draft.chars().count();
                    self.flash("a card is waiting: y approves, n and a reason denies");
                }
            }
            return;
        }
        if text.trim().is_empty() {
            return;
        }
        if self.viewing.is_some() {
            // The chat's own commands work here; a message does not.
            if let Parsed::Builtin(builtin) = slash::parse(&text) {
                return self.run_builtin(builtin);
            }
            self.draft = text;
            self.cursor = self.draft.chars().count();
            return self.flash("a delegated run is read-only; Esc goes back to its chat");
        }
        // On the empty screen a lone 1, 2 or 3 picks that starter.
        if self.is_home()
            && let Ok(n) = text.trim().parse::<usize>()
            && (1..=self.starters.len()).contains(&n)
        {
            return self.use_starter(n - 1);
        }
        self.menu_at = 0;
        if self.history.last() != Some(&text) {
            self.history.push(text.clone());
        }
        match slash::parse(&text) {
            Parsed::Builtin(builtin) => self.run_builtin(builtin),
            Parsed::Skill(line) | Parsed::Text(line) => {
                let line = line.to_string();
                if self.busy() {
                    self.rows.push(Row::Queued(line.clone()));
                    self.queue.push_back(line);
                } else {
                    self.start_turn(line);
                }
            }
        }
    }

    fn start_turn(&mut self, text: String) {
        if self.viewing.is_some() {
            return self.flash("a delegated run is read-only; Esc goes back to its chat");
        }
        let Some(handle) = self.agent.clone() else {
            self.rows.push(Row::Error(
                "no working agent here; Ctrl+N starts a new conversation, /setup configures one"
                    .into(),
            ));
            return;
        };
        self.rows.push(Row::User {
            text: text.clone(),
            at: chrono::Local::now(),
        });
        self.rows.push(Row::Assistant {
            text: String::new(),
            open: true,
            meta: None,
        });
        self.follow = true;
        self.owed.clear();
        self.turn_tokens_start = self.status.tokens_in + self.status.tokens_out;
        let (tx, rx) = mpsc::channel(64);
        let inbound_id = format!("chat-{}", uuid::Uuid::new_v4());
        let inbound = InboundContext {
            adapter_id: Some("chat".to_string()),
            sender_id: Some(self.operator.clone()),
            channel: None,
        };
        self.turn_task = Some(tokio::spawn(async move {
            let mut agent = handle.lock().await;
            agent
                .process_message_stream_with(&text, inbound_id, tx, inbound)
                .await
        }));
        self.turn_rx = Some(rx);
        self.turn_started = Some(Instant::now());
    }

    fn on_stream(&mut self, ev: StreamEvent) {
        match ev {
            StreamEvent::TextDelta(delta) => {
                // Text the chain already put in a closed piece of the
                // reply (see `cut_reply`) is not shown twice.
                let delta = if self.owed.is_empty() {
                    delta
                } else if let Some(rest) = self.owed.strip_prefix(delta.as_str()) {
                    self.owed = rest.to_string();
                    return;
                } else if let Some(rest) = delta.strip_prefix(self.owed.as_str()) {
                    self.owed.clear();
                    rest.to_string()
                } else {
                    self.owed.clear();
                    delta
                };
                // The reply follows what was shown while it was awaited:
                // a note or a panel from the wait sits above it.
                match self
                    .rows
                    .iter()
                    .rposition(|r| matches!(r, Row::Assistant { open: true, .. }))
                {
                    Some(i) => {
                        if i + 1 != self.rows.len() {
                            let row = self.rows.remove(i);
                            self.rows.push(row);
                        }
                        if let Some(Row::Assistant { text, .. }) = self.rows.last_mut() {
                            text.push_str(&delta);
                        }
                    }
                    None => self.rows.push(Row::Assistant {
                        text: delta,
                        open: true,
                        meta: None,
                    }),
                }
            }
            StreamEvent::Done(_) => {}
            StreamEvent::Error(e) => self.push_activity(Row::Failure {
                explained: explain_error(&e),
                raw: e,
            }),
        }
    }

    fn on_turn_done(&mut self, done: TurnOutcome) {
        self.turn_task = None;
        let elapsed = self.turn_started.map(|t| t.elapsed());
        self.turn_started = None;
        self.quit_armed = false;
        // The turn can end before the screen has drawn the last of its
        // text: draw it, then let the stream go.
        self.poll_chain();
        self.turn_rx = None;
        self.seal_runs(false);
        match done {
            Err(join) => {
                // Nothing will finish the reply this turn opened.
                if let Some(i) = self
                    .rows
                    .iter()
                    .rposition(|r| matches!(r, Row::Assistant { open: true, .. }))
                {
                    if matches!(&self.rows[i], Row::Assistant { text, .. } if text.is_empty()) {
                        self.rows.remove(i);
                    } else if let Row::Assistant { open, .. } = &mut self.rows[i] {
                        *open = false;
                    }
                }
                self.rows
                    .push(Row::Error(format!("the turn did not finish: {join}")));
                // The agent may hold half a turn: nothing more goes to it.
                self.agent = None;
                if !self.queue.is_empty() {
                    self.queue.clear();
                    self.note("the queued messages were not sent");
                }
                self.note("this conversation's agent stopped; Ctrl+N starts a new conversation");
            }
            Ok(outcome) => self.close_reply(outcome, elapsed.unwrap_or_default()),
        }
        if !self.focused && elapsed.is_some_and(|e| e > Duration::from_secs(10)) {
            let failed = matches!(self.rows.last(), Some(Row::Failure { .. }));
            notify(if failed {
                "wirken: the turn failed"
            } else {
                "wirken: the agent replied"
            });
        }
        (self.status.budget, self.status.budget_pct) = budget_info(&self.cfg, &self.status.agent);
        self.refresh_lists();
        if let Some(next) = self.queue.pop_front() {
            if let Some(i) = self
                .rows
                .iter()
                .position(|r| matches!(r, Row::Queued(q) if *q == next))
            {
                self.rows.remove(i);
            }
            self.start_turn(next);
        }
    }

    fn close_reply(&mut self, outcome: Result<ProcessResult, AgentError>, took: Duration) {
        let tokens =
            (self.status.tokens_in + self.status.tokens_out).saturating_sub(self.turn_tokens_start);
        let meta = format!(
            "{} · {:.1}s · {} tokens",
            chrono::Local::now().format("%H:%M"),
            took.as_secs_f64(),
            kfmt(tokens)
        );
        let open = self
            .rows
            .iter()
            .rposition(|r| matches!(r, Row::Assistant { open: true, .. }));
        match outcome {
            Ok(result) => {
                match open {
                    Some(i) => {
                        if let Row::Assistant {
                            text,
                            open,
                            meta: m,
                        } = &mut self.rows[i]
                        {
                            if text.is_empty() {
                                *text = result.response.clone();
                            }
                            *open = false;
                            *m = Some(meta);
                        }
                    }
                    None => self.rows.push(Row::Assistant {
                        text: result.response.clone(),
                        open: false,
                        meta: Some(meta),
                    }),
                }
                for denial in result.denials {
                    self.rows.push(Row::Note(format!(
                        "denied: {} ({})",
                        denial.tool_name,
                        denial.action.approval_key()
                    )));
                }
            }
            Err(e) => {
                if let Some(i) = open {
                    if matches!(&self.rows[i], Row::Assistant { text, .. } if text.is_empty()) {
                        self.rows.remove(i);
                    } else if let Row::Assistant { open, .. } = &mut self.rows[i] {
                        *open = false;
                    }
                }
                let raw = e.to_string();
                let shown = self
                    .rows
                    .iter()
                    .rev()
                    .any(|r| matches!(r, Row::Failure { raw: r2, .. } if *r2 == raw));
                if !shown {
                    self.rows.push(Row::Failure {
                        explained: explain_error(&raw),
                        raw,
                    });
                }
            }
        }
    }

    /// New rows on this conversation's chain since the last look: tool
    /// calls and their results, compactions, operator decisions and the
    /// cost of each model call. Called on every tick of a turn and once
    /// after it.
    fn poll_chain(&mut self) {
        // The runtime streams a reply's text before it records the calls
        // in it, but the screen can be told of the record (or of the card
        // a call raised) before it has drawn that text. Draw what is
        // queued first, so text the model said before a call stays above
        // the call's row.
        self.drain_stream();
        self.read_chain(false);
    }

    /// Text and errors the turn has streamed and the screen has not drawn.
    fn drain_stream(&mut self) {
        let mut queued = Vec::new();
        if let Some(rx) = self.turn_rx.as_mut() {
            while let Ok(ev) = rx.try_recv() {
                queued.push(ev);
            }
        }
        for ev in queued {
            self.on_stream(ev);
        }
    }

    /// Read the chain from `next_seq`. `replay` also draws the messages
    /// themselves, which a live turn draws from the stream: it rebuilds a
    /// reopened conversation's transcript from its record.
    /// A finished delegated run's decisions and model calls, counted
    /// into this conversation's: its approvals were answered here, and
    /// its calls are this conversation's spend.
    fn absorb_run(&mut self, lane: &str) {
        let handle = self.log.handle_for(SessionId::new(lane.to_string()));
        let Ok(rows) = self.log.get_since(&handle, 0) else {
            return;
        };
        let who = self.lane_agent(lane);
        for row in rows {
            match row.event {
                // A run this run delegated: its own approvals and calls
                // count here too.
                SessionEvent::SubagentResult {
                    child_session_id, ..
                } if child_session_id.starts_with(&format!("{lane}#sub-")) => {
                    self.absorb_run(&child_session_id);
                }
                SessionEvent::PermissionApproved {
                    action_key,
                    approved_by,
                    ..
                } => {
                    self.status.approved += 1;
                    self.decisions.push(Decision {
                        key: format!("{who}: {action_key}"),
                        approved: true,
                        detail: format!("by {approved_by}"),
                    });
                }
                SessionEvent::PermissionDenied {
                    action_key,
                    denied_via: Some(_),
                    denial_reason,
                    ..
                } => {
                    self.status.denied += 1;
                    self.decisions.push(Decision {
                        key: format!("{who}: {action_key}"),
                        approved: false,
                        detail: denial_reason.unwrap_or_else(|| "no reason given".to_string()),
                    });
                }
                SessionEvent::LlmResponse {
                    total_cost_usd_micros,
                    input_tokens,
                    output_tokens,
                    ..
                } => {
                    self.status.llm_calls += 1;
                    self.status.tokens_in += u64::from(input_tokens);
                    self.status.tokens_out += u64::from(output_tokens);
                    match total_cost_usd_micros {
                        Some(c) => self.status.cost_micros += c,
                        None => self.status.uncosted = true,
                    }
                }
                _ => {}
            }
        }
    }

    /// How much the transcript says: rows, and the length of the last
    /// reply. A resize, a fold or Ctrl+O changes how many lines it takes,
    /// not this, so only new output makes the scroll pill say so.
    pub(crate) fn content_mark(&self) -> (usize, usize) {
        let last_reply = self
            .rows
            .iter()
            .rev()
            .find_map(|r| match r {
                Row::Assistant { text, .. } => Some(text.len()),
                _ => None,
            })
            .unwrap_or(0);
        (self.rows.len(), last_reply)
    }

    /// Whether a card from `lane` is waiting for the operator.
    pub(crate) fn needs_you(&self, lane: &str) -> bool {
        let nested = format!("{lane}#sub-");
        self.waiting_lanes
            .iter()
            .any(|s| s == lane || s.starts_with(&nested))
    }

    /// The lanes whose cards wait, kept with the rows: the view asks
    /// `needs_you` for every run row, card and sidebar entry each frame.
    fn track_waiting(&mut self) {
        self.waiting_lanes = self
            .rows
            .iter()
            .filter_map(|r| match r {
                Row::Card {
                    card,
                    verdict: None,
                } => Some(card.session.clone()),
                _ => None,
            })
            .collect();
    }

    /// Seal the lanes of this conversation's runs, and of the runs they
    /// delegated in turn: the runtime leaves a child's rows in the
    /// unsigned tail, and nothing writes to a finished child's lane again
    /// (the next spawn gets the next `#sub-N`). `all` takes unfinished
    /// runs too, on the way out, once the turn has been stopped.
    fn seal_runs(&mut self, all: bool) {
        let lanes: Vec<String> = self
            .rows
            .iter()
            .filter_map(|r| match r {
                Row::Delegation {
                    session: Some(s),
                    end,
                    ..
                } if all || end.is_some() => Some(s.clone()),
                _ => None,
            })
            .collect();
        for lane in lanes {
            let nested = format!("{lane}#sub-");
            let mut every = vec![lane.clone()];
            every.extend(
                self.log
                    .list_child_sessions(&lane)
                    .into_iter()
                    .filter(|id| id.starts_with(&nested)),
            );
            for id in every {
                seal_if_open(&self.log, &id);
            }
        }
    }

    fn read_chain(&mut self, replay: bool) {
        let handle = self.log.handle_for(SessionId::new(self.session_id.clone()));
        let Ok(rows) = self.log.get_since(&handle, self.next_seq) else {
            return;
        };
        // For a reopened conversation's footnotes: when the question was
        // asked and what the calls answering it used.
        let mut asked: Option<chrono::DateTime<chrono::Utc>> = None;
        let mut used: u64 = 0;
        for row in rows {
            self.next_seq = row.seq + 1;
            self.status.rows = row.seq + 1;
            match row.event {
                SessionEvent::UserMessage { content, .. } if replay => {
                    asked = Some(row.ts);
                    used = 0;
                    self.rows.push(Row::User {
                        text: content,
                        at: row.ts.with_timezone(&chrono::Local),
                    });
                }
                SessionEvent::AssistantMessage { content, .. } if replay => {
                    let took =
                        asked.map_or(0.0, |t| (row.ts - t).num_milliseconds() as f64 / 1000.0);
                    self.rows.push(Row::Assistant {
                        text: content,
                        open: false,
                        meta: Some(format!(
                            "{} · {took:.1}s · {} tokens",
                            row.ts.with_timezone(&chrono::Local).format("%H:%M"),
                            kfmt(used)
                        )),
                    });
                }
                SessionEvent::PermissionApproved {
                    action_key,
                    approved_by,
                    ..
                } => {
                    self.status.approved += 1;
                    if replay {
                        self.rows.push(Row::Note(format!("approved: {action_key}")));
                    }
                    self.decisions.push(Decision {
                        key: action_key,
                        approved: true,
                        detail: format!("by {approved_by}"),
                    });
                }
                SessionEvent::PermissionDenied {
                    action_key,
                    denied_via: Some(_),
                    denial_reason,
                    ..
                } => {
                    self.status.denied += 1;
                    if replay {
                        self.rows.push(Row::Note(format!("denied: {action_key}")));
                    }
                    self.decisions.push(Decision {
                        key: action_key,
                        approved: false,
                        detail: denial_reason.unwrap_or_else(|| "no reason given".to_string()),
                    });
                }
                SessionEvent::LlmRequest {
                    request_bytes,
                    purpose,
                    ..
                } if purpose.is_turn() => {
                    if request_bytes.is_some() {
                        self.status.last_request_bytes = request_bytes;
                    }
                }
                SessionEvent::AssistantToolCalls { calls, text, .. } => {
                    // Live, the reply streamed so far is cut where the
                    // chain says this round's text ended; whatever came
                    // after (the next round, already streaming) goes
                    // after the calls.
                    let after = if replay {
                        if let Some(text) = text.filter(|t| !t.is_empty()) {
                            self.rows.push(Row::Assistant {
                                text,
                                open: false,
                                meta: None,
                            });
                        }
                        None
                    } else {
                        self.cut_reply(text.unwrap_or_default())
                    };
                    for call in calls {
                        if call.name == "spawn_subagent" {
                            let (agent, task) = spawn_args(&call.arguments);
                            self.push_activity(Row::Delegation {
                                call_id: call.id,
                                agent,
                                task,
                                session: None,
                                tools: Vec::new(),
                                max_tier: None,
                                end: None,
                                expanded: false,
                            });
                            continue;
                        }
                        self.push_activity(Row::Tool {
                            call_id: call.id,
                            name: call.name,
                            args: call.arguments,
                            done: None,
                            expanded: false,
                        });
                    }
                    if let Some(rest) = after {
                        self.rows.push(Row::Assistant {
                            text: rest,
                            open: true,
                            meta: None,
                        });
                    }
                }
                // Spawns are written in call order, so each goes to the
                // first run of that agent still waiting for its lane.
                SessionEvent::SubagentSpawned {
                    child_session_id,
                    child_agent_id,
                    tools_granted,
                    max_permission_tier,
                    ..
                } => {
                    let slot = self.rows.iter_mut().find(|r| {
                        matches!(r, Row::Delegation { agent, session: None, end: None, .. } if *agent == child_agent_id)
                    });
                    match slot {
                        Some(Row::Delegation {
                            session,
                            tools,
                            max_tier,
                            ..
                        }) => {
                            *session = Some(child_session_id);
                            *tools = tools_granted;
                            *max_tier = max_permission_tier;
                        }
                        _ => self.push_activity(Row::Delegation {
                            call_id: String::new(),
                            agent: child_agent_id,
                            task: String::new(),
                            session: Some(child_session_id),
                            tools: tools_granted,
                            max_tier: max_permission_tier,
                            end: None,
                            expanded: false,
                        }),
                    }
                }
                SessionEvent::SubagentResult {
                    child_session_id,
                    output,
                    status,
                    ..
                } => {
                    let ended = RunEnd {
                        ok: matches!(status, wirken_audit::SubagentStatus::Ok),
                        word: run_word(&status),
                        output: envelope_output(&output),
                    };
                    if let Some(Row::Delegation { end, .. }) = self.rows.iter_mut().find(|r| {
                        matches!(r, Row::Delegation { session: Some(s), .. } if *s == child_session_id)
                    }) {
                        *end = Some(ended);
                    }
                    // The operator answered the child's cards here, and
                    // its calls are this conversation's spend.
                    self.absorb_run(&child_session_id);
                }
                SessionEvent::ToolResult {
                    call_id,
                    output,
                    success,
                    ..
                } => {
                    if let Some(Row::Tool { done, .. }) = self.rows.iter_mut().rev().find(
                        |r| matches!(r, Row::Tool { call_id: id, done: None, .. } if *id == call_id),
                    ) {
                        *done = Some(ToolDone { success, output });
                    } else if let Some(Row::Delegation { end, .. }) =
                        self.rows.iter_mut().rev().find(|r| {
                            matches!(r, Row::Delegation { call_id: id, end: None, .. } if *id == call_id)
                        })
                    {
                        // A spawn refused before it started (an agent
                        // this one may not reach) writes no result row:
                        // its envelope is the only word on how it went.
                        let status = serde_json::from_str::<serde_json::Value>(&output)
                            .ok()
                            .and_then(|v| v["status"].as_str().map(str::to_string))
                            .unwrap_or_default();
                        *end = Some(RunEnd {
                            ok: success && status == "ok",
                            word: match status.as_str() {
                                "ok" => "done",
                                "timeout" => "timed out",
                                "rounds_exceeded" => "ran out of rounds",
                                "depth_exceeded" => "nested too deep",
                                _ => "failed",
                            },
                            output: envelope_output(&output),
                        });
                    }
                }
                SessionEvent::Compaction { .. } => {
                    self.push_activity(Row::Note("context compacted".into()));
                }
                SessionEvent::LlmResponse {
                    total_cost_usd_micros,
                    input_tokens,
                    output_tokens,
                    ..
                } => {
                    self.status.llm_calls += 1;
                    self.status.tokens_in += u64::from(input_tokens);
                    self.status.tokens_out += u64::from(output_tokens);
                    used += u64::from(input_tokens) + u64::from(output_tokens);
                    match total_cost_usd_micros {
                        Some(c) => self.status.cost_micros += c,
                        None => self.status.uncosted = true,
                    }
                }
                _ => {}
            }
        }
    }

    /// Activity rows go before the reply that is still arriving, so
    /// the transcript reads in the order things happened: text the
    /// model said before its calls stays above them, and text it says
    /// after them lands in a new reply row below.
    /// Cut the reply in progress where a round of tool calls began: the
    /// chain records the round's own text, `said`. The piece up to there
    /// is closed with exactly that text; what is left of the open reply
    /// (text of the next round that streamed before the record was read)
    /// is returned to reopen after the calls. When the screen has not yet
    /// drawn all of `said`, the rest is owed: the deltas still on their
    /// way are dropped as they arrive. None when no reply is open.
    fn cut_reply(&mut self, said: String) -> Option<String> {
        let i = self
            .rows
            .iter()
            .rposition(|r| matches!(r, Row::Assistant { open: true, .. }))?;
        let Row::Assistant { text, open, .. } = &mut self.rows[i] else {
            return None;
        };
        let shown = std::mem::take(text);
        *open = false;
        let rest = if said.is_empty() {
            // A round with no text of its own: everything shown is the
            // next round's.
            shown
        } else if let Some(rest) = shown.strip_prefix(said.as_str()) {
            rest.to_string()
        } else if let Some(owed) = said.strip_prefix(shown.as_str()) {
            self.owed = owed.to_string();
            String::new()
        } else {
            String::new()
        };
        if said.is_empty() {
            self.rows.remove(i);
        } else if let Row::Assistant { text, .. } = &mut self.rows[i] {
            *text = said;
        }
        Some(rest)
    }

    /// Tool activity in reading order: after what the reply has said so
    /// far, before what it says next. The reply in progress is found
    /// wherever it is, since notes can follow it.
    fn push_activity(&mut self, row: Row) {
        let open = self
            .rows
            .iter()
            .rposition(|r| matches!(r, Row::Assistant { open: true, .. }));
        match open {
            Some(i) if matches!(&self.rows[i], Row::Assistant { text, .. } if text.is_empty()) => {
                let empty = self.rows.remove(i);
                self.rows.push(row);
                self.rows.push(empty);
            }
            Some(i) => {
                if let Row::Assistant { open, .. } = &mut self.rows[i] {
                    *open = false;
                }
                self.rows.push(row);
                self.rows.push(Row::Assistant {
                    text: String::new(),
                    open: true,
                    meta: None,
                });
            }
            None => self.rows.push(row),
        }
    }

    // ----- approvals -----

    fn on_ask(&mut self, mut ask: ApprovalAsk) {
        // The call is on the chain before the gate asks; read it first so
        // its row sits above the card that asks about it.
        self.poll_chain();
        if let Some((parent, _)) = ask.card.session.rsplit_once("#sub-") {
            let parent = parent.to_string();
            let handle = self.log.handle_for(SessionId::new(parent.clone()));
            let ceiling = self.log.get_since(&handle, 0).ok().and_then(|rows| {
                rows.into_iter().find_map(|r| match r.event {
                    SessionEvent::SubagentSpawned {
                        child_session_id,
                        tools_granted,
                        max_permission_tier,
                        ..
                    } if child_session_id == ask.card.session => Some(format!(
                        "up to {} · tools {}",
                        max_permission_tier.as_deref().unwrap_or("–"),
                        if tools_granted.is_empty() {
                            "none".to_string()
                        } else {
                            tools_granted.join(", ")
                        }
                    )),
                    _ => None,
                })
            });
            let for_agent = self.lane_agent(&parent);
            let ceiling =
                ceiling.map_or_else(|| for_agent.clone(), |c| format!("{for_agent} · {c}"));
            ask.card.delegated = Some((for_agent, ceiling));
        }
        // Under the call that raised it, a log line or not in between;
        // a delegated run's card goes with the activity, since its call is
        // on the run's own lane.
        let own_call = (!ask.card.session.contains("#sub-"))
            .then(|| {
                self.rows
                    .iter()
                    .rposition(|r| matches!(r, Row::Tool { done: None, .. }))
            })
            .flatten();
        match own_call {
            Some(i) => self.rows.insert(
                i + 1,
                Row::Card {
                    card: ask.card,
                    verdict: None,
                },
            ),
            None => self.push_activity(Row::Card {
                card: ask.card,
                verdict: None,
            }),
        }
        if self.pending.is_empty() {
            if !self.draft.trim().is_empty() {
                self.held_draft = Some(std::mem::take(&mut self.draft));
                self.cursor = 0;
            }
            self.armed_at = Instant::now() + ARMING;
        }
        self.pending.push_back(ask.reply);
        self.track_waiting();
        self.follow = true;
        if self.focused {
            let mut out = std::io::stdout();
            let _ = out.write_all(b"\x07");
            let _ = out.flush();
        } else {
            notify("wirken: approval needed");
        }
    }

    fn answer(&mut self, line: String) {
        let Some(reply) = self.pending.pop_front() else {
            return;
        };
        let verdict = match parse_decision(&line) {
            ApprovalOutcome::Approved { .. } => "approved".to_string(),
            ApprovalOutcome::Denied {
                reason: Some(r), ..
            } => format!("denied: {r}"),
            ApprovalOutcome::Denied { .. } => "denied".to_string(),
            ApprovalOutcome::Timeout => "expired".to_string(),
        };
        let delivered = reply.send(line).is_ok();
        self.set_verdict(if delivered {
            verdict
        } else {
            "expired before the answer arrived".to_string()
        });
        // A y or n left in the composer was for this card.
        self.drop_stale_answer();
        self.after_card();
    }

    /// A `y` or `n` typed for a card that expired or was withdrawn is not
    /// left to decide the next one.
    fn drop_stale_answer(&mut self) {
        if !self.draft.trim().is_empty() && card_answer(&self.draft).is_some() {
            self.draft.clear();
            self.cursor = 0;
        }
    }

    /// The next card is read before it can be approved; with none left,
    /// the draft set aside comes back.
    fn after_card(&mut self) {
        self.track_waiting();
        if self.pending.is_empty() {
            if let Some(held) = self.held_draft.take() {
                if self.draft.is_empty() {
                    self.cursor = held.chars().count();
                    self.draft = held;
                } else {
                    // Something else is being typed: the set-aside draft
                    // goes to the history, one Up away, rather than over it.
                    self.history.push(held);
                    self.flash("your earlier draft is one Up away");
                }
            }
        } else {
            self.armed_at = Instant::now() + ARMING;
        }
    }

    /// The verdict on the oldest card still waiting, which is the one
    /// the oldest reply in `pending` belongs to.
    fn set_verdict(&mut self, verdict: String) {
        if let Some(Row::Card { verdict: v, .. }) = self
            .rows
            .iter_mut()
            .find(|r| matches!(r, Row::Card { verdict: None, .. }))
        {
            *v = Some(verdict);
        }
    }

    /// Held log lines as notes, each distinct message once. The leading
    /// timestamp is dropped: it is what makes a repeat look new.
    fn show_logs(&mut self, lines: Vec<String>) {
        for line in lines {
            let clean = wirken_agent::ansi::strip_control_sequences(&line);
            let message = clean
                .split_once(' ')
                .map_or(clean.as_str(), |(_, rest)| rest)
                .trim()
                .to_string();
            if !message.is_empty() && self.logs_seen.insert(message.clone()) {
                // Before the reply in progress, never through it: a log
                // line is not a turn boundary.
                match self
                    .rows
                    .iter()
                    .rposition(|r| matches!(r, Row::Assistant { open: true, .. }))
                {
                    Some(i) => self.rows.insert(i, Row::Log(message)),
                    None => self.rows.push(Row::Log(message)),
                }
            }
        }
    }

    fn on_tick(&mut self) {
        self.spinner = self.spinner.wrapping_add(1);
        if self.busy() {
            self.poll_chain();
        }
        let held = super::take_logs();
        self.show_logs(held);
        // A run that ended (its runtime ran out) drops the question it
        // was asking: its card is withdrawn, not left waiting. The k-th
        // reply belongs to the k-th card still waiting.
        // A card past its deadline is the expiry below, not this.
        let mut k = 0;
        while k < self.pending.len() {
            let past_deadline = self
                .rows
                .iter()
                .filter_map(|r| match r {
                    Row::Card {
                        card,
                        verdict: None,
                    } => Some(Instant::now() > card.deadline),
                    _ => None,
                })
                .nth(k)
                .unwrap_or(true);
            if past_deadline || !self.pending[k].is_closed() {
                k += 1;
                continue;
            }
            self.pending.remove(k);
            if let Some(Row::Card { verdict, .. }) = self
                .rows
                .iter_mut()
                .filter(|r| matches!(r, Row::Card { verdict: None, .. }))
                .nth(k)
            {
                *verdict = Some("withdrawn: the run ended before an answer".into());
            }
            self.drop_stale_answer();
            self.after_card();
        }
        // Cards expire oldest first: every card gets the same deadline
        // from when it was asked.
        while !self.pending.is_empty() {
            let oldest_expired = self
                .rows
                .iter()
                .find_map(|r| match r {
                    Row::Card {
                        card,
                        verdict: None,
                    } => Some(Instant::now() > card.deadline),
                    _ => None,
                })
                .unwrap_or(true);
            if !oldest_expired {
                break;
            }
            self.pending.pop_front();
            self.set_verdict("expired: no answer within the deadline, recorded as a denial".into());
            self.drop_stale_answer();
            self.after_card();
        }
    }

    // ----- flow -----

    /// Send the last message again, after a failed turn.
    fn retry(&mut self) {
        if self.busy() {
            return self.flash("a turn is running");
        }
        // Only a turn that failed, and failed in a way another try can
        // change: resending a finished turn would run its tools again.
        let last_user = self
            .rows
            .iter()
            .rposition(|r| matches!(r, Row::User { .. }));
        let failed = last_user.is_some_and(|u| {
            self.rows[u..]
                .iter()
                .any(|r| matches!(r, Row::Failure { raw, .. } if retryable(raw)))
        });
        match last_user.and_then(|u| match &self.rows[u] {
            Row::User { text, .. } if failed => Some(text.clone()),
            _ => None,
        }) {
            Some(text) => self.start_turn(text),
            None => self.flash("nothing to retry: the last turn did not fail"),
        }
    }

    fn use_starter(&mut self, i: usize) {
        if self.busy() {
            return;
        }
        if let Some(text) = self.starters.get(i).cloned() {
            self.history.push(text.clone());
            self.start_turn(text);
        }
    }

    fn copy_last(&mut self) {
        let last = self
            .rows
            .iter()
            .rposition(|r| matches!(r, Row::Assistant { text, .. } if !text.is_empty()));
        match last {
            Some(i) => self.copy_row(i),
            None => self.flash("no reply to copy yet"),
        }
    }

    /// Put a reply on the clipboard through the terminal (OSC 52), which
    /// works over SSH and asks nothing of the host.
    fn copy_row(&mut self, i: usize) {
        let Some(Row::Assistant { text, .. }) = self.rows.get(i) else {
            return;
        };
        let clean = wirken_agent::ansi::strip_control_sequences(text);
        let mut out = std::io::stdout();
        let _ = write!(out, "\x1b]52;c;{}\x07", base64(clean.as_bytes()));
        let _ = out.flush();
        self.flash("reply copied to the clipboard");
    }

    pub(crate) fn flash(&mut self, text: &str) {
        self.flash = Some((text.to_string(), Instant::now()));
    }

    /// Write this conversation as Markdown into the agent's workspace.
    /// Write the conversation as Markdown under the data dir's
    /// `exports/`, not the agent's workspace: the workspace is the
    /// agent's to write, so a link planted there could aim an export at
    /// any file of the operator's. The file is created new, never
    /// followed or written over, and readable by the operator alone.
    fn export(&mut self) {
        use std::io::Write as _;
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
        let dir = self.cfg.data_dir.join("exports");
        let short = self
            .session_id
            .rsplit('/')
            .next()
            .unwrap_or("chat")
            .replace('#', "-");
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let path = dir.join(format!("chat-{short}-{stamp}.md"));
        let written = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .and_then(|()| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
            })
            .and_then(|mut f| f.write_all(self.markdown().as_bytes()));
        match written {
            Ok(()) => self.note(format!("exported to {}", path.display())),
            Err(e) => self.rows.push(Row::Error(format!(
                "could not write {}: {e}",
                path.display()
            ))),
        }
    }

    fn markdown(&self) -> String {
        let clean = plain;
        let title = self
            .rows
            .iter()
            .find_map(|r| match r {
                Row::User { text, .. } => Some(text.lines().next().unwrap_or("").to_string()),
                _ => None,
            })
            .unwrap_or_else(|| "New conversation".to_string());
        let mut out = format!(
            "# {}\n\nAgent `{}` on `{}/{}`, session `{}`.\n",
            clean(&title),
            self.status.agent,
            self.status.provider,
            self.status.model,
            self.session_id
        );
        for row in &self.rows {
            match row {
                Row::User { text, at } => out.push_str(&format!(
                    "\n**You**, {}\n\n{}\n",
                    at.format("%Y-%m-%d %H:%M"),
                    clean(text)
                )),
                Row::Assistant { text, meta, .. } if !text.is_empty() => {
                    out.push_str(&format!("\n**{}**", self.status.agent));
                    if let Some(meta) = meta {
                        out.push_str(&format!(", {meta}"));
                    }
                    out.push_str(&format!("\n\n{}\n", clean(text)));
                }
                Row::Tool {
                    name, args, done, ..
                } => out.push_str(&format!(
                    "\n> tool `{}` `{}`: {}\n",
                    name,
                    tool_summary(args),
                    match done {
                        None => "did not finish".to_string(),
                        Some(d) if d.success => format!("ok, {} bytes", d.output.len()),
                        Some(d) => format!("failed, {} bytes", d.output.len()),
                    }
                )),
                Row::Card { card, verdict } => out.push_str(&format!(
                    "\n> approval for `{}` asked by `{}`: {}\n",
                    card.tool,
                    card.agent,
                    verdict.as_deref().unwrap_or("unanswered")
                )),
                Row::Delegation {
                    agent,
                    task,
                    session,
                    end,
                    ..
                } => out.push_str(&format!(
                    "\n> delegated to `{agent}`: {} — {}{}\n",
                    clean(task),
                    end.as_ref().map_or("no result", |e| e.word),
                    session
                        .as_deref()
                        .map(|s| format!(" (lane `{s}`)"))
                        .unwrap_or_default()
                )),
                Row::Failure { explained, raw } => {
                    out.push_str(&format!("\n> failed: {explained} ({})\n", clean(raw)))
                }
                _ => {}
            }
        }
        // Tool names, commands and card fields come from the model too:
        // the whole file goes through the same cleaning.
        plain(&out)
    }

    // ----- sidebar -----

    /// Re-read the sidebar's lists.
    fn refresh_lists(&mut self) {
        self.refresh_agents();
        self.conversations = list_conversations(&self.log, &self.agents, &mut self.lane_cache);
        self.refresh_checks();
    }

    /// The sidebar's agents: those the factory was given, in configured
    /// order, each with its model; one that could not be resolved is
    /// listed as unavailable, so a click on it says why.
    fn refresh_agents(&mut self) {
        let order = list_agents(&self.cfg);
        self.agents = order
            .into_iter()
            .filter_map(|a| {
                if let Some(info) = self.agent_info.get(&a.id) {
                    Some(AgentEntry {
                        model: format!("{}/{}", info.provider, info.model),
                        id: a.id,
                    })
                } else if self.unavailable.iter().any(|(id, _)| *id == a.id) {
                    Some(AgentEntry {
                        model: "unavailable".to_string(),
                        id: a.id,
                    })
                } else {
                    None
                }
            })
            .collect();
    }

    /// The agents in sidebar order: as configured, with the one this
    /// chat runs added first if it is somehow not among them.
    pub(crate) fn agent_order(&self) -> Vec<&str> {
        let mut order: Vec<&str> = self.agents.iter().map(|a| a.id.as_str()).collect();
        if !order.contains(&self.requested_agent.as_str()) {
            order.insert(0, &self.requested_agent);
        }
        order
    }

    /// The conversations whose title holds the search text, in sidebar
    /// order: grouped by agent, newest first within each.
    pub(crate) fn listed(&self) -> Vec<&Conversation> {
        let needle = self.filter.to_lowercase();
        let needle = &needle;
        self.agent_order()
            .into_iter()
            .flat_map(|agent| {
                self.conversations.iter().filter(move |c| {
                    c.agent == agent
                        && (needle.is_empty() || c.title.to_lowercase().contains(needle))
                })
            })
            .collect()
    }

    /// True while the conversation has nothing to show: the screen
    /// shows the greeting, a centred composer and the suggestions. A
    /// panel, note or error moves it to the conversation view, which is
    /// where those are drawn.
    pub(crate) fn is_home(&self) -> bool {
        self.viewing.is_none() && self.rows.iter().all(|r| matches!(r, Row::Log(_)))
    }

    fn new_conversation(&mut self) {
        if self.busy() {
            self.note("wait for the turn to finish before starting a new conversation");
        } else {
            self.action = Some(Pending::Clear);
        }
    }

    /// Reopen a conversation, this agent's or another's: its lane is
    /// replayed into a rebuilt agent of the agent that owns it, and its
    /// transcript is drawn from the chain.
    fn open_conversation(&mut self, session_id: String) {
        if session_id == self.session_id {
            return;
        }
        if self.busy() {
            self.note("wait for the turn to finish before switching conversations");
            return;
        }
        if session_id.contains("#sub-") {
            return self.view_run(session_id);
        }
        let owner = chat_owner(&session_id)
            .unwrap_or(&self.requested_agent)
            .to_string();
        let was_viewing = self.viewing.is_some();
        let previous = std::mem::replace(&mut self.session_id, session_id.clone());
        match self.wake(&owner, &session_id) {
            Ok(()) => {
                // The conversation left is sealed once the next is up: a
                // failed open keeps it as it was.
                if !was_viewing {
                    seal_if_open(&self.log, &previous);
                }
                self.seal_runs(true);
                self.requested_agent = owner;
                self.viewing = None;
                self.rows.clear();
                self.queue.clear();
                self.pending.clear();
                self.track_waiting();
                self.follow = true;
                self.next_seq = 0;
                self.read_chain(true);
            }
            Err(e) => {
                self.session_id = previous;
                self.rows.push(Row::Error(format!(
                    "could not reopen that conversation: {e:#}"
                )));
            }
        }
    }

    /// Open a delegated run for reading, drawn from its own lane. No
    /// agent is woken for it: a run is finished or belongs to its
    /// parent's turn, and only the parent talks to it.
    fn view_run(&mut self, lane: String) {
        self.seal();
        self.seal_runs(true);
        let parent = lane
            .rsplit_once("#sub-")
            .map_or(lane.as_str(), |(parent, _)| parent)
            .to_string();
        let agent = self.lane_agent(&lane);
        let for_agent = self.lane_agent(&parent);
        self.viewing = Some(RunView {
            parent,
            agent,
            for_agent,
        });
        self.session_id = lane;
        self.rows.clear();
        self.queue.clear();
        self.pending.clear();
        self.track_waiting();
        self.decisions.clear();
        self.follow = true;
        self.next_seq = 0;
        let s = &mut self.status;
        (s.rows, s.cost_micros, s.approved, s.denied, s.llm_calls) = (0, 0, 0, 0, 0);
        (s.tokens_in, s.tokens_out, s.uncosted) = (0, 0, false);
        (s.last_request_bytes, s.verify) = (None, None);
        self.read_chain(true);
    }

    /// Move to the conversation `delta` places down the list.
    fn step_conversation(&mut self, delta: isize) {
        let ids: Vec<String> = self.listed().iter().map(|c| c.session_id.clone()).collect();
        if ids.is_empty() {
            return;
        }
        let at = ids.iter().position(|id| *id == self.session_id);
        // From a new conversation, either direction opens this agent's
        // newest, or the first listed when it has none.
        let next = match at {
            Some(i) => (i as isize + delta).clamp(0, ids.len() as isize - 1) as usize,
            None => ids
                .iter()
                .position(|id| chat_owner(id) == Some(self.requested_agent.as_str()))
                .unwrap_or(0),
        };
        self.open_conversation(ids[next].clone());
    }

    /// Start a new conversation with another configured agent.
    fn switch_agent(&mut self, agent: String) {
        if agent == self.requested_agent {
            return;
        }
        if self.busy() {
            self.note("wait for the turn to finish before switching agents");
            return;
        }
        // Woken first: an agent that cannot be woken leaves this
        // conversation as it is, unsealed and with the reason under it.
        let was_viewing = self.viewing.is_some();
        let previous = std::mem::replace(&mut self.session_id, new_session_id(&agent));
        let session = self.session_id.clone();
        match self.wake(&agent, &session) {
            Ok(()) => {
                if !was_viewing {
                    seal_if_open(&self.log, &previous);
                }
                self.seal_runs(true);
                self.requested_agent = agent;
                self.viewing = None;
                self.rows.clear();
                self.queue.clear();
                self.pending.clear();
                self.track_waiting();
                self.follow = true;
                self.scroll = 0;
                self.refresh_lists();
            }
            Err(e) => {
                self.session_id = previous;
                self.rows.push(Row::Error(format!("{e:#}")));
                self.follow = true;
            }
        }
    }

    fn on_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.filter.clear();
                self.focus = Focus::Composer;
            }
            KeyCode::Enter => {
                let first = self.listed().first().map(|c| c.session_id.clone());
                self.focus = Focus::Composer;
                self.filter.clear();
                if let Some(id) = first {
                    self.open_conversation(id);
                }
            }
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.filter.push(c);
            }
            _ => {}
        }
    }

    fn on_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            MouseEventKind::ScrollUp => self.scroll_by(-3),
            MouseEventKind::ScrollDown => self.scroll_by(3),
            MouseEventKind::Down(MouseButton::Left) => {
                // Later areas are drawn over earlier ones, so the last
                // match is the one on top.
                let hit = self
                    .hits
                    .iter()
                    .rev()
                    .find(|(rect, _)| {
                        mouse.column >= rect.x
                            && mouse.column < rect.x + rect.width
                            && mouse.row >= rect.y
                            && mouse.row < rect.y + rect.height
                    })
                    .map(|(_, hit)| hit.clone());
                match hit {
                    Some(Hit::New) => self.new_conversation(),
                    Some(Hit::Search) => self.focus = Focus::Search,
                    Some(Hit::Composer) => self.focus = Focus::Composer,
                    Some(Hit::Open(id)) => self.open_conversation(id),
                    // A group header: a new chat with that agent.
                    Some(Hit::Agent(id)) if id == self.requested_agent => self.new_conversation(),
                    Some(Hit::Agent(id)) => self.switch_agent(id),
                    Some(Hit::Card(kind)) => self.card_action(kind),
                    Some(Hit::Approve) if Instant::now() < self.armed_at => {
                        self.flash("the card has just come up; read it, then approve")
                    }
                    Some(Hit::Approve) => self.answer("y".to_string()),
                    Some(Hit::Deny) => self.answer(String::new()),
                    Some(Hit::Retry) => self.retry(),
                    Some(Hit::Copy(i)) => self.copy_row(i),
                    Some(Hit::Tool(i)) => {
                        if let Some(Row::Tool { expanded, .. } | Row::Delegation { expanded, .. }) =
                            self.rows.get_mut(i)
                        {
                            *expanded = !*expanded;
                        }
                    }
                    Some(Hit::Starter(i)) => self.use_starter(i),
                    Some(Hit::Jump) => self.follow = true,
                    None => {}
                }
            }
            _ => {}
        }
    }

    // ----- chat commands -----

    fn run_builtin(&mut self, builtin: Builtin) {
        match builtin {
            Builtin::Help => self.panel(self.help_lines()),
            Builtin::Status => self.panel(self.status_lines()),
            Builtin::Skills => {
                let lines = if self.skill_lines.is_empty() {
                    vec!["no skills attached; `wirken skills install <name>` adds one".to_string()]
                } else {
                    self.skill_lines.clone()
                };
                self.panel(lines);
            }
            Builtin::Agents => {
                let lines = self.agent_lines();
                self.panel(lines);
            }
            Builtin::Permissions => {
                let lines = self.permission_lines();
                self.panel(lines);
            }
            Builtin::Sessions => {
                let lines = self.session_lines();
                self.panel(lines);
            }
            Builtin::Setup => {
                if self.busy() {
                    self.note("wait for the turn to finish before /setup");
                } else {
                    self.action = Some(Pending::Setup);
                }
            }
            Builtin::Clear => {
                if self.busy() {
                    self.note("wait for the turn to finish before /clear");
                } else {
                    self.action = Some(Pending::Clear);
                }
            }
            Builtin::Context => self.card_action(CardKind::Context),
            Builtin::Cost => self.card_action(CardKind::Cost),
            Builtin::Verify => self.card_action(CardKind::Audit),
            Builtin::Tools => self.card_action(CardKind::Tools),
            Builtin::Safety => self.card_action(CardKind::Safety),
            Builtin::Runs => self.card_action(CardKind::Delegations),
            Builtin::Export => self.export(),
            Builtin::Quit => {
                if self.busy() && !self.quit_armed {
                    self.quit_armed = true;
                    self.note("a turn is running; /quit again leaves anyway");
                } else {
                    self.action = Some(Pending::Quit);
                }
            }
        }
    }

    /// What a click on a panel card does: the detail behind it, and for
    /// the audit card a verification run now.
    fn card_action(&mut self, kind: CardKind) {
        let lines = match kind {
            CardKind::Environment => self.status_lines(),
            CardKind::Safety => self.safety_lines(),
            CardKind::Context => self.context_lines(),
            CardKind::Cost => self.cost_lines(),
            CardKind::Audit => self.verify_chain(),
            CardKind::Approvals => self.approval_lines(),
            CardKind::Tools => self.tool_lines(),
            CardKind::Delegations => self.delegation_lines(),
        };
        self.panel(lines);
    }

    /// Each run this conversation delegated: agent, how it stands, the
    /// task, the ceiling, and the lane to read it on.
    fn delegation_lines(&self) -> Vec<String> {
        let mut lines = vec!["runs delegated in this conversation".to_string()];
        for row in &self.rows {
            if let Row::Delegation {
                agent,
                task,
                session,
                tools,
                max_tier,
                end,
                ..
            } = row
            {
                let state = match (end, session) {
                    (Some(e), _) => e.word.to_string(),
                    (None, Some(s)) if self.needs_you(s) => "needs you".to_string(),
                    (None, Some(_)) if self.busy() => "running".to_string(),
                    (None, Some(_)) => "no result".to_string(),
                    (None, None) => "not started".to_string(),
                };
                lines.push(format!("  {agent}  {state}  {task}"));
                lines.push(format!(
                    "    up to {} · tools {}",
                    max_tier.as_deref().unwrap_or("–"),
                    if tools.is_empty() {
                        "none".to_string()
                    } else {
                        tools.join(", ")
                    }
                ));
                if let Some(s) = session {
                    lines.push(format!("    lane {s}"));
                }
            }
        }
        if lines.len() == 1 {
            lines.push(
                "  none; an agent delegates once `wirken agents allow-subagent` lets it".into(),
            );
        } else {
            lines.push(
                "each run is listed under this chat in the sidebar; a click opens it for reading"
                    .into(),
            );
        }
        lines
    }

    /// Check this conversation's hash chain and its signed heads now.
    fn verify_chain(&mut self) -> Vec<String> {
        let handle = self.log.handle_for(SessionId::new(self.session_id.clone()));
        let chain = self.log.verify(&handle);
        let heads = self.log.verify_signatures(&handle).map(|h| HeadCheck {
            signed: h.signed_heads_count,
            tail: h.unsigned_tail_len,
            first_invalid: h.first_invalid.map(|bad| bad.seq),
        });
        let (ok, summary, detail) = verdict(chain, heads);
        self.status.verify = Some((ok, summary.clone(), self.status.rows));
        let mut lines = vec![
            format!("audit chain of {}", self.session_id),
            format!("  {summary}"),
        ];
        lines.extend(detail.into_iter().map(|l| format!("  {l}")));
        lines.push(format!(
            "  the same check from a shell: wirken sessions verify {}",
            self.session_id
        ));
        lines
    }

    fn safety_lines(&self) -> Vec<String> {
        if self.status.issues.is_empty() {
            return vec![
                "nothing weakens a guarantee: no escape hatch is set, no audit alarm is \
                 waiting, exec runs in a container, and the chain is signed"
                    .to_string(),
            ];
        }
        let mut lines = vec!["what weakens a guarantee here, and how to undo it".to_string()];
        for issue in &self.status.issues {
            lines.push(format!("  ✗ {}", issue.what));
            lines.push(format!("    {}", issue.fix));
        }
        lines
    }

    fn context_lines(&self) -> Vec<String> {
        let window = self.status.context_window;
        let mut lines = vec![format!(
            "the model takes {} tokens; Wirken fits each request to 80% of that ({})",
            kfmt(window as u64),
            kfmt(wirken_agent::context::effective_budget(window) as u64)
        )];
        match self.status.last_request_bytes {
            Some(bytes) => lines.push(format!(
                "the last request was {} bytes, about {} tokens ({}%)",
                bytes,
                kfmt(bytes / 4),
                context_pct(bytes, window)
            )),
            None => lines.push("no model call on this conversation yet".to_string()),
        }
        lines.push(
            "past the budget the oldest tool output is trimmed first, then older text; the \
             system prompt and the last three messages are never cut, and each trim is a \
             compaction row on the chain"
                .to_string(),
        );
        lines
    }

    fn cost_lines(&self) -> Vec<String> {
        let s = &self.status;
        let mut lines = vec![
            format!("{} model calls on this conversation", s.llm_calls),
            format!(
                "{} input tokens, {} output tokens",
                kfmt(s.tokens_in),
                kfmt(s.tokens_out)
            ),
        ];
        if s.uncosted {
            lines.push(format!(
                "{}/{} has no price in the pricing table, so its calls are uncosted{}",
                s.provider,
                s.model,
                if s.cost_micros > 0 {
                    format!("; priced calls came to {}", usd(s.cost_micros))
                } else {
                    String::new()
                }
            ));
        } else {
            lines.push(format!("spent {}", usd(s.cost_micros)));
        }
        lines.push(s.budget.clone());
        if s.budget_pct.is_none() {
            lines.push(
                "a ceiling is set in budget.json in the data directory: see \
                 docs/cost-monitoring.md"
                    .to_string(),
            );
        }
        lines
    }

    fn approval_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.decisions.is_empty() {
            lines.push("no approval asked on this conversation yet".to_string());
        } else {
            lines.push("decisions on this conversation".to_string());
            for d in &self.decisions {
                lines.push(format!(
                    "  {} {} · {}",
                    if d.approved { "✓" } else { "✗" },
                    d.key,
                    d.detail
                ));
            }
        }
        lines.push(String::new());
        lines.extend(self.permission_lines());
        lines
    }

    fn tool_lines(&self) -> Vec<String> {
        if self.tools.is_empty() {
            return vec!["the tool list is read when the agent is idle".to_string()];
        }
        let mut lines = Vec::new();
        for (asks, heading) in [
            (Asks::Never, "runs without asking"),
            (Asks::Depends, "depends on the command"),
            (Asks::Once, "asks until you store a grant"),
            (Asks::Always, "asks every time"),
        ] {
            let group: Vec<&ToolRow> = self.tools.iter().filter(|t| t.asks == asks).collect();
            if group.is_empty() {
                continue;
            }
            lines.push(heading.to_string());
            for t in group {
                lines.push(format!("  {:<22} {}", t.name, t.rule));
            }
        }
        lines.push(format!(
            "{} skills attached; /skills lists them",
            self.status.skills
        ));
        lines
    }

    fn panel(&mut self, lines: Vec<String>) {
        self.rows.push(Row::Panel(lines));
        self.follow = true;
    }

    fn help_lines(&self) -> Vec<String> {
        let mut lines = vec!["commands".to_string()];
        for (name, _, what) in Builtin::ALL {
            lines.push(format!("  {name:<14} {what}"));
        }
        lines.push(
            "  /<skill> …     any other /word goes to the agent as a skill invocation".to_string(),
        );
        lines.push(String::new());
        lines.push("keys".to_string());
        for (key, what) in [
            ("Enter", "send; answer an approval card"),
            ("Ctrl+J, Shift+Enter", "newline"),
            ("Tab", "complete a /command"),
            ("Up / Down", "earlier messages"),
            ("1, 2, 3", "on an empty chat, send that suggestion"),
            (
                "PgUp / PgDn, Home / End",
                "scroll the transcript; End follows new output",
            ),
            ("Ctrl+O", "full tool output, log lines and long code lines"),
            ("Ctrl+N", "new conversation"),
            ("Ctrl+F", "search conversations; Enter opens the first"),
            ("Ctrl+Up / Ctrl+Down", "previous or next conversation"),
            ("Ctrl+B", "hide or show the sidebar"),
            ("Ctrl+R", "retry the last message after an error"),
            ("Ctrl+Y", "copy the last reply"),
            (
                "Up / Down in the / menu",
                "choose a command; Enter or Tab takes it",
            ),
            ("click", "a conversation, agent, card, button or tool row"),
            ("Esc", "deny a card; twice, clear the draft"),
            ("Ctrl+C", "clear the draft; empty and idle, leave"),
            ("Ctrl+D", "with an empty draft, leave (twice during a turn)"),
            ("?", "on an empty draft, this help"),
            ("Ctrl+L", "redraw"),
        ] {
            lines.push(format!("  {key:<26} {what}"));
        }
        lines.push(String::new());
        if self.skills.is_empty() {
            lines.push("skills: none attached".to_string());
        } else {
            lines.push(format!(
                "skills (/name to invoke): {}",
                self.skills.join(", ")
            ));
        }
        lines
    }

    fn status_lines(&self) -> Vec<String> {
        let grants = super::super::open_permission_store(&self.cfg)
            .and_then(|store| store.list(&self.status.agent).map_err(Into::into))
            .map_or_else(|e| format!("unreadable ({e})"), |g| g.len().to_string());
        vec![
            format!("build        {}", crate::build_info::identity()),
            format!("data dir     {}", self.cfg.data_dir.display()),
            format!("agent        {}", self.status.agent),
            format!(
                "provider     {}/{}  (operator configuration: provider.json or `wirken agents set`)",
                self.status.provider, self.status.model
            ),
            format!("sandbox      {}  (sandbox.json)", self.status.exec),
            format!("budget       {}  (budget.json)", self.status.budget),
            format!(
                "audit        {} · {} rows on this conversation · spent {} this chat",
                if self.status.signed {
                    "signed chain heads"
                } else {
                    "unsigned (no signing key)"
                },
                self.status.rows,
                usd(self.status.cost_micros)
            ),
            format!("skills       {} attached", self.status.skills),
            format!("grants       {grants} stored for this agent (/permissions)"),
            format!("session      {}", self.session_id),
            format!(
                "safety       {}",
                if self.status.issues.is_empty() {
                    "nothing weakens a guarantee".to_string()
                } else {
                    self.status
                        .issues
                        .iter()
                        .map(|i| i.what.clone())
                        .collect::<Vec<_>>()
                        .join("; ")
                }
            ),
        ]
    }

    /// The agents this chat knows, with the provider/model each runs;
    /// from the agent store, the name and channels too.
    fn agent_lines(&self) -> Vec<String> {
        let path = self.cfg.agent_config_db_path();
        let stored = if path.exists() {
            wirken_gateway::agent_config::AgentConfigStore::open(&path)
                .and_then(|store| store.list())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut lines = vec![format!(
            "{:<12}  {:<16}  {:<24}  channels",
            "id", "name", "provider/model"
        )];
        for a in &self.agents {
            let row = stored.iter().find(|s| s.id == a.id);
            lines.push(format!(
                "{:<12}  {:<16}  {:<24}  {}{}",
                a.id,
                row.map_or("(provider.json)", |r| r.name.as_str()),
                a.model,
                row.map_or_else(
                    || "(none)".to_string(),
                    |r| if r.channels.is_empty() {
                        "(none)".to_string()
                    } else {
                        r.channels.join(", ")
                    }
                ),
                if a.id == self.status.agent {
                    "  ← this chat"
                } else {
                    ""
                }
            ));
        }
        for (id, why) in &self.unavailable {
            lines.push(format!("{id:<12}  unavailable: {why}"));
        }
        if self.agents.is_empty() {
            lines.push("no agents; `wirken agents add` registers one".to_string());
        }
        lines
    }

    fn permission_lines(&self) -> Vec<String> {
        let agent = &self.status.agent;
        let stored = match super::super::open_permission_store(&self.cfg)
            .and_then(|store| store.list(agent).map_err(Into::into))
        {
            Ok(rows) => rows,
            Err(e) => return vec![format!("could not read the permission store: {e}")],
        };
        let scoped = wirken_gateway::permissions::list_active_session_scoped_grants_for_agent(
            &self.log, agent,
        )
        .unwrap_or_default();
        if stored.is_empty() && scoped.is_empty() {
            return vec![
                format!("no grants for agent '{agent}': every Tier 2 action asks once per card"),
                "`wirken permissions approve <key>` stores one".to_string(),
            ];
        }
        let mut lines = Vec::new();
        if !stored.is_empty() {
            lines.push(format!("stored grants for agent '{agent}'"));
            for g in stored {
                lines.push(format!(
                    "  {:<32} by {:<12} until {}",
                    g.action_key,
                    g.approved_by,
                    g.expires_at.format("%Y-%m-%d")
                ));
            }
        }
        if !scoped.is_empty() {
            lines.push("session-scoped grants".to_string());
            for g in scoped {
                lines.push(format!(
                    "  {:<32} by {:<12} in {}",
                    g.action_key, g.approved_by, g.session_id
                ));
            }
        }
        lines
    }

    fn session_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "{}  this chat · {} rows",
            self.session_id, self.status.rows
        )];
        match super::super::session::active_session_rows(&self.cfg, None) {
            Ok(rows) if rows.is_empty() => {
                lines.push(
                    "no gateway sessions (none are active, or `wirken run` has not run)".into(),
                );
            }
            Ok(rows) => {
                for r in rows {
                    lines.push(format!(
                        "{}  {} · {} messages · last {}",
                        r.log_id,
                        r.channel,
                        r.message_count,
                        r.last_activity.format("%Y-%m-%d %H:%M")
                    ));
                }
            }
            Err(e) => lines.push(format!("gateway sessions unreadable: {e}")),
        }
        lines
    }
}

/// What a failed turn means, in a sentence a newcomer can act on.
pub(crate) fn explain_error(raw: &str) -> String {
    let lower = raw.to_lowercase();
    let status = lower
        .split("http ")
        .nth(1)
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse::<u16>().ok());
    if lower.contains("budget") {
        return "This agent's budget is spent for the current window; it can be raised in budget.json."
            .to_string();
    }
    if lower.starts_with("unknown skill") {
        let name = raw.split('\'').nth(1).unwrap_or("that");
        return format!("There is no skill called {name}. /skills lists the ones this agent has.");
    }
    match status {
        Some(401 | 403) => {
            "The provider refused the credentials; `wirken credentials list` shows what is stored."
                .to_string()
        }
        Some(404) => {
            "The provider does not know this model or address; check provider.json.".to_string()
        }
        Some(429) => "The provider is limiting requests; wait a moment, then retry.".to_string(),
        Some(500..=599) => {
            "The model's server had a problem. It is usually brief; retry.".to_string()
        }
        _ if ["connect", "error sending request", "dns", "timed out"]
            .iter()
            .any(|s| lower.contains(s)) =>
        {
            "Could not reach the model. Is it running, and is its address in provider.json right?"
                .to_string()
        }
        _ => "The turn did not finish.".to_string(),
    }
}

/// Whether sending the same message again could end differently. An
/// unknown skill fails the same way every time.
pub(crate) fn retryable(raw: &str) -> bool {
    !raw.to_lowercase().starts_with("unknown skill")
}

/// Ways to start, picked from what this agent can do.
pub(crate) fn starters(tools: &[ToolRow], skills: &[String]) -> Vec<String> {
    let has = |name: &str| tools.iter().any(|t| t.name == name);
    let mut out = vec!["What can you do here?".to_string()];
    if has("list_files") {
        out.push("What's in my workspace?".to_string());
    }
    if has("exec") {
        out.push("Show today's date with a shell command".to_string());
    }
    if has("web_search") {
        out.push("Search the web for this week's Rust news".to_string());
    }
    if let Some(skill) = skills.first() {
        out.push(format!("/{skill}"));
    }
    out.truncate(3);
    out
}

/// The part of a tool call a person reads: the command, path, address or
/// query when the arguments carry one, else the arguments in one line.
pub(crate) fn tool_summary(args: &str) -> String {
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(args) {
        for key in ["command", "path", "url", "query", "sql", "prompt"] {
            if let Some(serde_json::Value::String(v)) = map.get(key) {
                return v.clone();
            }
        }
    }
    args.replace(['\n', '\r', '\t'], " ")
}

/// Ring the bell and raise a desktop notification where the terminal
/// supports one (OSC 9); terminals that do not ignore the sequence.
fn notify(text: &str) {
    let mut out = std::io::stdout();
    let _ = write!(out, "\x07\x1b]9;{text}\x07");
    let _ = out.flush();
}

/// Standard base64, for the clipboard sequence.
pub(crate) fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ABC[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Environment variables that relax a check, as WebChat's status lists
/// them.
const ESCAPE_HATCHES: [&str; 6] = [
    "WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG",
    "WIRKEN_ALLOW_UNSIGNED_SKILLS",
    "WIRKEN_ALLOW_UNSIGNED_MCP",
    "WIRKEN_ALLOW_STALE_ORG_CONFIG",
    "WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN",
    "WIRKEN_ALLOW_UNREGISTERED_HOOKS",
];

/// What is set that weakens a guarantee, each with how to undo it.
fn issues(cfg: &GatewayConfig, signed: bool, exec: &str) -> Vec<Issue> {
    let mut out = Vec::new();
    for name in ESCAPE_HATCHES {
        if wirken_gateway::org::parse_boolean_escape(name) {
            out.push(Issue {
                what: format!("{name} is set"),
                fix: format!(
                    "unset {name} and restart; it relaxes a check (docs/security-properties.md)"
                ),
            });
        }
    }
    match wirken_audit::AlarmLog::new(&cfg.data_dir).unacknowledged_blocks() {
        Ok(Some(report)) => out.push(Issue {
            what: format!("{} unacknowledged audit alarm(s)", report.total),
            fix: "review audit-alarms.log, then run `wirken audit acknowledge --all`".to_string(),
        }),
        Ok(None) => {}
        Err(e) => out.push(Issue {
            what: "the audit alarm log could not be read".to_string(),
            fix: e.to_string(),
        }),
    }
    if exec == "exec: host" {
        out.push(Issue {
            what: "exec runs on the host".to_string(),
            fix: "set \"mode\": \"exec-only\" in sandbox.json to run commands in a container"
                .to_string(),
        });
    }
    // Hook processes connect to `wirken run`; the chat has none to ask,
    // so a registered veto or egress hook does not see its calls.
    let hooks = cfg.data_dir.join("hooks.db");
    if hooks.exists()
        && let Ok(registry) = wirken_gateway::hook_registry::HookRegistry::open(&hooks)
        && !registry.list().is_empty()
    {
        out.push(Issue {
            what: format!(
                "{} registered hook(s) do not run in the chat",
                registry.list().len()
            ),
            fix: "hooks run under `wirken run`; use WebChat or a channel where they must see \
                  every call"
                .to_string(),
        });
    }
    if !signed {
        out.push(Issue {
            what: "audit rows are not signed".to_string(),
            fix: "the signing key in the data directory's audit/ folder could not be loaded"
                .to_string(),
        });
    }
    out
}

/// The agent's tools with how each reaches the tier gate, by WebChat's
/// own tier table.
async fn tool_rows(agent: &Agent) -> Vec<ToolRow> {
    agent
        .snapshot_tool_defs_for(wirken_audit::ToolsHashVersion::V2)
        .await
        .into_iter()
        .map(|t| {
            let entry = super::super::webchat::tool_tier_entry(&t.name, &t.description);
            let tier = entry["tier"].as_str().unwrap_or_default();
            let depends = entry["tier_depends_on_arguments"].as_bool() == Some(true);
            let asks = match tier {
                _ if depends => Asks::Depends,
                "tier1" | "" => Asks::Never,
                "tier2" => Asks::Once,
                _ => Asks::Always,
            };
            let rule = entry["tier_rule"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| tier.replace("tier", "Tier "));
            ToolRow {
                name: t.name,
                asks,
                rule,
            }
        })
        .collect()
}

/// What the signature pass found, as far as the verdict needs it.
struct HeadCheck {
    signed: usize,
    tail: usize,
    first_invalid: Option<u64>,
}

/// The chain check and the signature check as one verdict: whether it
/// held, a one-line summary, and the lines behind it.
fn verdict(
    chain: Result<wirken_audit::SessionVerifyResult, wirken_audit::AuditError>,
    heads: Result<HeadCheck, wirken_audit::AuditError>,
) -> (bool, String, Vec<String>) {
    use wirken_audit::SessionVerifyResult as V;
    let heads = match heads {
        Ok(h) => h,
        Err(e) => {
            return (
                false,
                format!("could not check signatures: {e}"),
                Vec::new(),
            );
        }
    };
    let tail = format!(
        "{} signed head{}; {} row{} after the last one, sealed at /clear or /quit",
        heads.signed,
        if heads.signed == 1 { "" } else { "s" },
        heads.tail,
        if heads.tail == 1 { "" } else { "s" },
    );
    match chain {
        Err(e) => (false, format!("could not check the chain: {e}"), Vec::new()),
        Ok(V::Empty) => (true, "nothing on the chain yet".to_string(), Vec::new()),
        Ok(V::Broken { seq, .. }) => (
            false,
            format!("chain broken at row {seq}"),
            vec!["a row's hash does not follow from the one before it".to_string()],
        ),
        Ok(V::Ok { rows_verified }) => match heads.first_invalid {
            Some(seq) => (
                false,
                format!("bad signature on the head at row {seq}"),
                vec![tail],
            ),
            None => (true, format!("chain OK · {rows_verified} rows"), vec![tail]),
        },
    }
}

/// Percent of the context window an approximate token count of `bytes`
/// fills, at four bytes a token.
pub(crate) fn context_pct(bytes: u64, window: usize) -> u8 {
    if window == 0 {
        return 0;
    }
    ((bytes / 4).saturating_mul(100) / window as u64).min(100) as u8
}

/// A count in a few characters: 950, 3.1k, 1.2M.
pub(crate) fn kfmt(n: u64) -> String {
    match n {
        0..=999 => n.to_string(),
        1_000..=999_999 => format!("{:.1}k", n as f64 / 1_000.0),
        _ => format!("{:.1}M", n as f64 / 1_000_000.0),
    }
}

/// `x.pipe(f)` for a value that is only needed once in an expression.
trait Pipe: Sized {
    fn pipe<R>(self, f: impl FnOnce(Self) -> R) -> R {
        f(self)
    }
}
impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_keeps_newlines_and_tabs_and_drops_other_controls() {
        assert_eq!(scrub("a\x1b[2Kb\nc\td\u{85}e"), "ab\nc\tde");
    }

    #[test]
    fn a_session_id_is_the_agent_lane_with_a_fresh_conversation() {
        let id = new_session_id("alice");
        assert!(id.starts_with("alice/chat/c-"), "{id}");
        assert_eq!(id.len(), "alice/chat/c-".len() + 12);
        assert_ne!(id, new_session_id("alice"));
    }

    #[test]
    fn context_pct_counts_four_bytes_a_token_and_caps() {
        assert_eq!(context_pct(40_000, 100_000), 10);
        assert_eq!(context_pct(4_000_000, 100_000), 100);
        assert_eq!(context_pct(400, 0), 0);
    }

    #[test]
    fn kfmt_keeps_counts_short() {
        assert_eq!(kfmt(950), "950");
        assert_eq!(kfmt(3_140), "3.1k");
        assert_eq!(kfmt(1_250_000), "1.2M");
    }

    #[test]
    fn a_verdict_is_green_only_when_both_checks_hold() {
        use wirken_audit::SessionVerifyResult;
        let heads = || HeadCheck {
            signed: 2,
            tail: 0,
            first_invalid: None,
        };
        let (ok, summary, _) = verdict(
            Ok(SessionVerifyResult::Ok { rows_verified: 7 }),
            Ok(heads()),
        );
        assert!(ok, "{summary}");
        assert!(summary.contains("chain OK"), "{summary}");
        let (ok, summary, _) = verdict(
            Ok(SessionVerifyResult::Broken {
                seq: 3,
                expected_hash: "a".into(),
                actual_hash: "b".into(),
                verified_count: 3,
            }),
            Ok(heads()),
        );
        assert!(!ok);
        assert_eq!(summary, "chain broken at row 3");
        let bad = HeadCheck {
            first_invalid: Some(6),
            ..heads()
        };
        let (ok, summary, _) = verdict(Ok(SessionVerifyResult::Ok { rows_verified: 7 }), Ok(bad));
        assert!(!ok);
        assert_eq!(summary, "bad signature on the head at row 6");
    }

    #[test]
    fn exec_on_the_host_and_an_unsigned_chain_are_issues() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = GatewayConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        assert!(
            issues(&cfg, true, "exec: container")
                .iter()
                .all(|i| !i.what.contains("exec"))
        );
        let found = issues(&cfg, false, "exec: host");
        assert!(found.iter().any(|i| i.what == "exec runs on the host"));
        assert!(found.iter().any(|i| i.what == "audit rows are not signed"));
    }

    #[test]
    fn base64_matches_the_standard_vectors() {
        for (plain, coded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), coded, "{plain}");
        }
    }

    #[test]
    fn errors_are_explained_by_their_cause() {
        assert!(explain_error("llm error: HTTP 500 Internal Server Error").contains("retry"));
        assert!(explain_error("HTTP 401 Unauthorized").contains("credentials"));
        assert!(explain_error("HTTP 429 Too Many Requests").contains("wait"));
        assert!(explain_error("error sending request: tcp connect error").contains("reach"));
        assert!(explain_error("budget exceeded for agent default").contains("budget"));
        assert_eq!(explain_error("something else"), "The turn did not finish.");
        let unknown = "unknown skill '/frobnicate'; loaded skills: ";
        assert_eq!(
            explain_error(unknown),
            "There is no skill called /frobnicate. /skills lists the ones this agent has."
        );
        assert!(!retryable(unknown));
        assert!(retryable("llm error: HTTP 500 Internal Server Error"));
    }

    #[test]
    fn shown_text_loses_escapes_and_invisible_reordering() {
        assert_eq!(plain("a\x1b]0;title\x07b"), "ab");
        assert_eq!(plain("rm \u{202e}fdp.exe"), "rm fdp.exe");
        assert_eq!(plain("x\u{200b}y\u{2066}z"), "xyz");
        // A joiner inside an emoji sequence stays.
        assert_eq!(plain("👩\u{200d}💻"), "👩\u{200d}💻");
        assert_eq!(scrub("ok\x07\u{9b}2J\n"), "ok2J\n");
    }

    #[test]
    fn a_delegation_reads_its_agent_task_and_answer() {
        let (agent, task) =
            spawn_args(r#"{"agent_id":"helper","prompt":"List the workspace files"}"#);
        assert_eq!(
            (agent.as_str(), task.as_str()),
            ("helper", "List the workspace files")
        );
        assert_eq!(spawn_args("not json").0, "?");
        let envelope =
            r#"{"child_session_id":"boss/chat/c-1#sub-0","status":"ok","output":"Done."}"#;
        assert_eq!(envelope_output(envelope), "Done.");
        assert_eq!(envelope_output("plain words"), "plain words");
        assert_eq!(run_word(&wirken_audit::SubagentStatus::Ok), "done");
        assert_eq!(
            run_word(&wirken_audit::SubagentStatus::Timeout),
            "timed out"
        );
    }

    #[test]
    fn a_chat_lane_names_its_agent_and_a_delegated_run_is_not_a_chat() {
        assert_eq!(chat_owner("local/chat/c-0123456789ab"), Some("local"));
        assert_eq!(chat_owner("cloud/chat/c-0123456789ab"), Some("cloud"));
        assert_eq!(chat_owner("local/chat/c-0123456789ab#sub-0"), None);
        assert_eq!(chat_owner("local/webchat/x"), None);
        assert_eq!(chat_owner("/chat/c-1"), None);
    }

    #[test]
    fn starters_follow_the_tools_and_stop_at_three() {
        let tool = |name: &str| ToolRow {
            name: name.to_string(),
            asks: Asks::Never,
            rule: String::new(),
        };
        let only_chat = starters(&[], &[]);
        assert_eq!(only_chat, vec!["What can you do here?"]);
        let all = starters(
            &[tool("list_files"), tool("exec"), tool("web_search")],
            &["summarise".to_string()],
        );
        assert_eq!(all.len(), 3);
        assert_eq!(all[1], "What's in my workspace?");
    }

    #[test]
    fn a_tool_summary_is_the_part_a_person_reads() {
        assert_eq!(tool_summary(r#"{"command": "ls -la"}"#), "ls -la");
        assert_eq!(tool_summary(r#"{"path": "notes.md"}"#), "notes.md");
        assert_eq!(tool_summary("not json\nat all"), "not json at all");
    }

    #[test]
    fn usd_prints_micros_as_dollars() {
        assert_eq!(usd(4_120_000), "$4.12");
        assert_eq!(usd(5_000), "$0.00");
    }
}
