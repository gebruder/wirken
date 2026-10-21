//! Live terminal connections, by the session a turn of theirs runs on.
//!
//! `wirken chat` is a client of the running gateway on the `terminal`
//! channel. Its approvals are asked on the connection whose message
//! started the turn: the `TerminalApprovalGate` (in `wirken-agent`)
//! looks the connection up here by the turn's session and writes the
//! `ApprovalRequest` frame to it, and the gateway's message loop checks
//! a decision that comes back against the same entry, so a terminal can
//! decide only what its own turn asked.
//!
//! An entry lives for one turn. The message loop registers the session
//! when the turn starts and the guard removes it when the turn ends,
//! however it ends. Several terminals can be connected at once; each
//! turn names its own session, so they do not share entries, which is
//! why this is keyed by session and not by channel as
//! `OutboundDispatcher` is.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::watch;
use wirken_ipc::IpcFrameWriter;

/// The channel name the terminal connects as, and the segment its
/// session ids carry.
pub const TERMINAL_CHANNEL: &str = "terminal";

/// One terminal connection as the gate reaches it: the writer to send
/// on, and whether the client is still there.
#[derive(Clone)]
pub struct TerminalLink {
    writer: Arc<AsyncMutex<IpcFrameWriter>>,
    gone: watch::Receiver<bool>,
}

impl TerminalLink {
    pub fn writer(&self) -> &Arc<AsyncMutex<IpcFrameWriter>> {
        &self.writer
    }

    /// Whether the client's end of the connection has closed.
    pub fn is_gone(&self) -> bool {
        *self.gone.borrow()
    }

    /// Resolve once the client's end of the connection has closed.
    pub async fn gone(&self) {
        let mut gone = self.gone.clone();
        // An error means the connection's side was dropped, which is
        // also the end of the connection.
        let _ = gone.wait_for(|g| *g).await;
    }

    /// Whether `other` is a link to the same connection.
    pub fn same_connection(&self, other: &TerminalLink) -> bool {
        Arc::ptr_eq(&self.writer, &other.writer)
    }
}

/// The connection's own side: hands out links and says when the
/// client has gone. Dropping it says so too.
pub struct TerminalConnection {
    link: TerminalLink,
    gone: watch::Sender<bool>,
}

impl TerminalConnection {
    pub fn new(writer: Arc<AsyncMutex<IpcFrameWriter>>) -> Self {
        let (gone, rx) = watch::channel(false);
        Self {
            link: TerminalLink { writer, gone: rx },
            gone,
        }
    }

    pub fn link(&self) -> TerminalLink {
        self.link.clone()
    }

    /// The client's end closed. A gate waiting on this connection stops
    /// waiting.
    pub fn mark_gone(&self) {
        self.gone.send_replace(true);
    }
}

impl Drop for TerminalConnection {
    fn drop(&mut self) {
        self.mark_gone();
    }
}

#[derive(Default)]
pub struct TerminalSessions {
    links: Mutex<HashMap<String, TerminalLink>>,
}

impl TerminalSessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `session_id` to `link` until the returned guard drops.
    pub fn register_guard(
        self: &Arc<Self>,
        session_id: String,
        link: TerminalLink,
    ) -> TerminalSessionGuard {
        self.links
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session_id.clone(), link.clone());
        TerminalSessionGuard {
            sessions: self.clone(),
            session_id,
            link,
        }
    }

    /// The connection whose turn runs on `session_id`, if one does.
    pub fn link_for(&self, session_id: &str) -> Option<TerminalLink> {
        self.links
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(session_id)
            .cloned()
    }
}

/// Removes its session when dropped, unless another connection has
/// registered the same session since.
pub struct TerminalSessionGuard {
    sessions: Arc<TerminalSessions>,
    session_id: String,
    link: TerminalLink,
}

impl Drop for TerminalSessionGuard {
    fn drop(&mut self) {
        let mut links = self
            .sessions
            .links
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if links
            .get(&self.session_id)
            .is_some_and(|l| l.same_connection(&self.link))
        {
            links.remove(&self.session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirken_ipc::{split_stream, test_pair};

    fn connection() -> TerminalConnection {
        let (a, _b) = test_pair().unwrap();
        let (_, writer) = split_stream(a);
        TerminalConnection::new(Arc::new(AsyncMutex::new(writer)))
    }

    #[tokio::test]
    async fn a_session_is_reachable_for_the_turn_and_not_after() {
        let sessions = Arc::new(TerminalSessions::new());
        let conn = connection();
        {
            let _guard = sessions.register_guard("default/terminal/c1".into(), conn.link());
            let link = sessions
                .link_for("default/terminal/c1")
                .expect("registered");
            assert!(link.same_connection(&conn.link()));
            assert!(sessions.link_for("default/terminal/c2").is_none());
        }
        assert!(sessions.link_for("default/terminal/c1").is_none());
    }

    #[tokio::test]
    async fn a_later_registration_is_not_removed_by_an_earlier_guard() {
        let sessions = Arc::new(TerminalSessions::new());
        let (first, second) = (connection(), connection());
        let early = sessions.register_guard("s".into(), first.link());
        let _late = sessions.register_guard("s".into(), second.link());
        drop(early);
        let link = sessions.link_for("s").expect("still registered");
        assert!(link.same_connection(&second.link()));
    }

    #[tokio::test]
    async fn a_closed_connection_is_seen_as_gone() {
        let conn = connection();
        let link = conn.link();
        assert!(!link.is_gone());
        let waiting = tokio::spawn({
            let link = link.clone();
            async move { link.gone().await }
        });
        conn.mark_gone();
        waiting.await.unwrap();
        assert!(link.is_gone());

        let dropped = connection();
        let link = dropped.link();
        drop(dropped);
        link.gone().await;
        assert!(link.is_gone());
    }
}
