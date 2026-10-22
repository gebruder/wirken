//! `wirken chat`: a full-screen chat with an agent, in the terminal,
//! through the running gateway.
//!
//! The chat is a client of `wirken run`, not a second gateway. It
//! connects to the gateway socket as the `terminal` channel, answering
//! the gateway's challenge with the operator key, and from there every
//! message takes the path any channel's message takes: the injection
//! scan, the inbound row, the session store, the router, the agent's
//! session `{agent}/terminal/{conversation}`, the tier gate and the
//! session chain. What it adds is a screen. The reply streams in as
//! the model writes it, tool calls show as they are recorded, and an
//! approval the turn needs is asked on a card at this terminal.
//!
//! Everything that can stop at a prompt (the setup wizard on a first
//! run) runs before the screen is taken, in the terminal as it is.

mod app;
mod panels;
mod slash;
mod text;
mod view;
mod wire;

use std::io::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::Event;
use wirken_ipc::{BoxStream, IpcFrameWriter, split_stream};

use super::config;
use app::{App, Outgoing};

/// Log output written while the screen is up, or `None` when it is not.
static HELD_LOGS: Mutex<Option<Vec<u8>>> = Mutex::new(None);
/// Past this much, held log output is dropped rather than kept.
const HELD_LOGS_MAX: usize = 256 * 1024;
/// Set while the screen is in raw mode on the alternate screen.
static SCREEN_UP: AtomicBool = AtomicBool::new(false);
/// Set by the panic hook, so the loop stops drawing over a terminal the
/// hook has already given back.
static PANICKED: AtomicBool = AtomicBool::new(false);

/// The log writer for `wirken chat`: stdout, as for every other
/// command, except while the chat holds the screen, when it is held and
/// printed to stderr once the terminal is back. Installed only for this
/// command.
pub fn log_writer() -> LogSink {
    LogSink
}

pub struct LogSink;

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut held = HELD_LOGS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(text) = held.as_mut() {
            if text.len() < HELD_LOGS_MAX {
                text.extend_from_slice(buf);
            }
            return Ok(buf.len());
        }
        drop(held);
        std::io::stdout().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

/// `wirken chat [--agent NAME]`.
pub async fn run(agent: Option<String>) -> Result<()> {
    use std::io::IsTerminal as _;
    require_terminal(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    )?;

    let cfg = config();
    let mut just_set_up = false;
    if !cfg.data_dir.join("provider.json").exists() {
        println!();
        println!("  No AI provider is configured yet, so setup runs first.");
        super::setup::run(false, None).await?;
        if !cfg.data_dir.join("provider.json").exists() {
            anyhow::bail!("No AI provider configured. Run `wirken setup` first.");
        }
        just_set_up = true;
    }

    let socket = cfg.socket_dir().join("gateway.sock");
    // A service setup just installed may still be starting.
    let wait = if just_set_up {
        Duration::from_secs(5)
    } else {
        Duration::ZERO
    };
    let key = wirken_ipc::operator::OperatorKey::load_or_create(&cfg.data_dir)
        .context("load the operator key")?;
    let link = Link::open(&socket, wait, &key, agent.as_deref()).await?;
    chat(
        link,
        socket,
        key,
        App::new(agent, app::new_conversation_id()),
    )
    .await
}

/// The chat is a screen: it refuses a pipe or a file on either end.
fn require_terminal(stdin_is_tty: bool, stdout_is_tty: bool) -> Result<()> {
    if stdin_is_tty && stdout_is_tty {
        return Ok(());
    }
    anyhow::bail!(
        "wirken chat needs a terminal on stdin and stdout. From a script or a pipe, use \
         `wirken ask -m <message>`."
    )
}

/// Connect to the running gateway, retrying for up to `wait`. The chat
/// never starts one.
async fn connect_gateway(socket: &std::path::Path, wait: Duration) -> Result<BoxStream> {
    let deadline = Instant::now() + wait;
    loop {
        match wirken_ipc::connect(socket).await {
            Ok(stream) => return Ok(stream),
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(_) => anyhow::bail!(
                "Wirken is not running, so there is nothing to chat with. Start it with \
                 `wirken run` in another terminal, or start the service `wirken setup \
                 --install-service` installed, then run `wirken chat` again."
            ),
        }
    }
}

type Frames = tokio::sync::mpsc::Receiver<std::result::Result<wire::ServerEvent, String>>;

/// One authenticated connection to the gateway, for one agent. Moving
/// to a conversation with another agent opens a new one, since the
/// agent is fixed at the handshake.
struct Link {
    /// The agent asked for at the handshake, `None` for the router's.
    agent: Option<String>,
    frames: Frames,
    writer: IpcFrameWriter,
    reader_task: tokio::task::JoinHandle<()>,
}

impl Link {
    async fn open(
        socket: &std::path::Path,
        wait: Duration,
        key: &wirken_ipc::operator::OperatorKey,
        agent: Option<&str>,
    ) -> Result<Self> {
        let stream = connect_gateway(socket, wait).await?;
        let (mut reader, mut writer) = split_stream(stream);
        wirken_ipc::perform_terminal_handshake(&mut reader, &mut writer, key, agent.unwrap_or(""))
            .await
            .map_err(|e| match e {
                wirken_ipc::HandshakeError::Rejected(reason) => {
                    anyhow::anyhow!("The gateway refused the chat: {reason}")
                }
                other => {
                    anyhow::anyhow!("The chat could not open a session with the gateway: {other}")
                }
            })?;
        // Frames from the gateway, read on a task of their own so the
        // loop never drops one half read.
        let (frames_tx, frames) = tokio::sync::mpsc::channel(64);
        let reader_task = tokio::spawn(async move {
            loop {
                let event = match reader.read_message().await {
                    Ok(msg) => wire::parse(&msg).map_err(|e| e.to_string()),
                    Err(wirken_ipc::IpcError::ConnectionClosed) => {
                        Err("the gateway closed the connection".to_string())
                    }
                    Err(e) => Err(e.to_string()),
                };
                let last = event.is_err();
                if frames_tx.send(event).await.is_err() || last {
                    return;
                }
            }
        });
        Ok(Self {
            agent: agent.map(str::to_string),
            frames,
            writer,
            reader_task,
        })
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

async fn chat(
    link: Link,
    socket: std::path::PathBuf,
    key: wirken_ipc::operator::OperatorKey,
    app: App,
) -> Result<()> {
    restore_on_panic();
    let mut screen = Screen::enter()?;
    // `crossterm::event::read` blocks, so keys are read on a thread.
    let stop_keys = std::sync::Arc::new(AtomicBool::new(false));
    let (keys_tx, mut keys) = tokio::sync::mpsc::channel(64);
    let keys_thread = spawn_key_reader(keys_tx, stop_keys.clone());

    let outcome = event_loop(&mut screen, link, &socket, &key, &mut keys, app).await;

    stop_keys.store(true, Ordering::Relaxed);
    let _ = keys_thread.join();
    screen.leave();
    outcome
}

/// The queries in flight, by request id, so each answer goes where it
/// was asked from.
#[derive(Default)]
struct Asked {
    next: u64,
    pending: std::collections::HashMap<String, wire::Query>,
}

/// Send what the screen produced. A request goes out with an id the
/// answer is matched by; moving to another agent's conversation opens a
/// new connection first.
async fn send(
    link: &mut Link,
    asked: &mut Asked,
    app: &mut App,
    socket: &std::path::Path,
    key: &wirken_ipc::operator::OperatorKey,
    outgoing: Outgoing,
) -> Result<()> {
    let operator = super::local_operator();
    let msg = match outgoing {
        Outgoing::Message(text) => wire::message(&app.conversation, &text, &operator),
        Outgoing::Decision {
            request_id,
            approve,
            reason,
        } => wire::decision(&request_id, approve, reason.as_deref(), &operator),
        Outgoing::Ask(query) => {
            asked.next += 1;
            let id = format!("q-{}", asked.next);
            asked.pending.insert(id.clone(), query);
            wire::request(&id, &app.conversation, query)
        }
        Outgoing::Open {
            agent,
            resume,
            conversation: _,
        } => {
            if agent != link.agent {
                match Link::open(socket, Duration::ZERO, key, agent.as_deref()).await {
                    Ok(new) => {
                        *link = new;
                        asked.pending.clear();
                    }
                    Err(e) => {
                        app.entries.push(app::Entry::Note(format!("{e:#}")));
                        return Ok(());
                    }
                }
            }
            let mut asks = vec![wire::Query::Status, wire::Query::Conversations];
            if resume {
                asks.push(wire::Query::History);
            }
            for query in asks {
                Box::pin(send(link, asked, app, socket, key, Outgoing::Ask(query))).await?;
            }
            return Ok(());
        }
    };
    link.writer
        .write_message(&msg)
        .await
        .context("The chat ended: the gateway closed the connection")
}

async fn event_loop(
    screen: &mut Screen,
    mut link: Link,
    socket: &std::path::Path,
    key: &wirken_ipc::operator::OperatorKey,
    keys: &mut tokio::sync::mpsc::Receiver<Event>,
    mut app: App,
) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).context("SIGTERM handler")?;
    let mut hup = signal(SignalKind::hangup()).context("SIGHUP handler")?;
    let mut int = signal(SignalKind::interrupt()).context("SIGINT handler")?;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut asked = Asked::default();

    for query in [wire::Query::Status, wire::Query::Conversations] {
        send(
            &mut link,
            &mut asked,
            &mut app,
            socket,
            key,
            Outgoing::Ask(query),
        )
        .await?;
    }

    loop {
        if PANICKED.load(Ordering::Relaxed) {
            anyhow::bail!("the chat stopped after an internal error");
        }
        screen.draw(&app)?;
        let outgoing: Vec<Outgoing> = tokio::select! {
            frame = link.frames.recv() => match frame {
                Some(Ok(wire::ServerEvent::Answer { request_id, body })) => {
                    if let Some(query) = asked.pending.remove(&request_id) {
                        app.on_answer(query, body);
                    }
                    Vec::new()
                }
                Some(Ok(event)) => app.on_server(event, Instant::now()),
                Some(Err(reason)) => anyhow::bail!("The chat ended: {reason}."),
                None => anyhow::bail!("The chat ended: the gateway closed the connection."),
            },
            key = keys.recv() => match key {
                Some(Event::Key(key)) => app.on_key(key, Instant::now()).into_iter().collect(),
                Some(Event::Paste(text)) => {
                    app.on_paste(&text, Instant::now());
                    Vec::new()
                }
                Some(_) => Vec::new(),
                None => anyhow::bail!("the chat stopped reading the keyboard"),
            },
            _ = tick.tick() => {
                app.tick(Instant::now());
                Vec::new()
            }
            _ = term.recv() => return Ok(()),
            _ = hup.recv() => return Ok(()),
            _ = int.recv() => return Ok(()),
        };
        for out in outgoing {
            send(&mut link, &mut asked, &mut app, socket, key, out).await?;
        }
        if app.quit {
            return Ok(());
        }
    }
}

fn spawn_key_reader(
    tx: tokio::sync::mpsc::Sender<Event>,
    stop: std::sync::Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match crossterm::event::poll(Duration::from_millis(100)) {
                Ok(true) => match crossterm::event::read() {
                    Ok(event) => {
                        if tx.blocking_send(event).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                },
                Ok(false) => {}
                Err(_) => return,
            }
        }
    })
}

/// The terminal in chat shape: raw mode on the alternate screen, with
/// bracketed paste so a pasted newline is text and not Enter.
struct Screen {
    terminal: ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
}

impl Screen {
    fn enter() -> Result<Self> {
        *HELD_LOGS.lock().unwrap_or_else(|e| e.into_inner()) = Some(Vec::new());
        SCREEN_UP.store(true, Ordering::SeqCst);
        let entered = crossterm::terminal::enable_raw_mode()
            .map_err(anyhow::Error::from)
            .and_then(|()| {
                crossterm::execute!(
                    std::io::stdout(),
                    crossterm::terminal::EnterAlternateScreen,
                    crossterm::event::EnableBracketedPaste,
                )
                .map_err(anyhow::Error::from)
            })
            .and_then(|()| {
                // Never `Terminal::clear`: it asks the terminal where the
                // cursor is, and the answer arrives on stdin, where the
                // key reader takes it. A fresh terminal draws every cell
                // on its first frame anyway.
                ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(std::io::stdout()))
                    .map_err(anyhow::Error::from)
            });
        match entered {
            Ok(terminal) => Ok(Self { terminal }),
            Err(e) => {
                leave_terminal();
                Err(e.context("could not take over the terminal"))
            }
        }
    }

    fn draw(&mut self, app: &App) -> Result<()> {
        let now = Instant::now();
        self.terminal
            .draw(|frame| view::draw(frame, app, now))
            .context("draw the chat")?;
        Ok(())
    }

    fn leave(&mut self) {
        leave_terminal();
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        leave_terminal();
    }
}

/// Give the terminal back and print what was logged while it was held.
/// Safe to call more than once and from the panic hook; only the first
/// call after [`Screen::enter`] does anything.
fn leave_terminal() {
    if !SCREEN_UP.swap(false, Ordering::SeqCst) {
        return;
    }
    let mut out = std::io::stdout();
    let _ = crossterm::execute!(
        out,
        crossterm::event::DisableBracketedPaste,
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::cursor::Show,
    );
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = out.flush();
    let held = HELD_LOGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .unwrap_or_default();
    if !held.is_empty() {
        let _ = std::io::stderr().write_all(&held);
    }
}

/// A panic on any thread gives the terminal back before the panic is
/// reported, so the message is readable and the shell is usable. The
/// loop then stops, since the screen it would draw on is gone.
fn restore_on_panic() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            PANICKED.store(true, Ordering::SeqCst);
            leave_terminal();
            previous(info);
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_a_terminal_the_chat_refuses_and_points_to_ask() {
        for (stdin, stdout) in [(false, true), (true, false), (false, false)] {
            let err = require_terminal(stdin, stdout).unwrap_err().to_string();
            assert!(err.contains("wirken ask -m"), "{err}");
        }
        require_terminal(true, true).unwrap();
    }

    #[tokio::test]
    async fn without_a_gateway_the_chat_refuses_and_points_to_run() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("gateway.sock");
        let err = match connect_gateway(&socket, Duration::ZERO).await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("nothing listens there"),
        };
        assert!(err.contains("wirken run"), "{err}");
        assert!(
            !socket.exists(),
            "refusing starts nothing and creates nothing"
        );
    }

    #[test]
    fn logs_are_held_only_while_the_screen_is_up() {
        let mut sink = log_writer();
        *HELD_LOGS.lock().unwrap() = Some(Vec::new());
        sink.write_all(b"held line\n").unwrap();
        let held = HELD_LOGS.lock().unwrap().take().unwrap();
        assert_eq!(held, b"held line\n");
    }
}
