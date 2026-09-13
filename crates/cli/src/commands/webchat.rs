use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use wirken_agent::sse_approval_gate::resolve_webchat_timeout;
use wirken_agent::{AgentFactory, session_id_for};
use wirken_audit::{
    ActorKind, AlarmLog, AlarmVerifyStatus, AuditEvent, AuditLog, AuditWriter, SessionId,
    VerifyResult,
};
use wirken_gateway::adapter_registry::AdapterRegistry;
use wirken_gateway::injection_detect::InjectionDetector;
use wirken_gateway::pending_approvals::{PendingApprovalQueue, PendingDecision, ResolveResult};
use wirken_gateway::rate_limit::ControlPlaneRateLimiter;
use wirken_gateway::session::SessionStore;
use wirken_gateway::skill_registry::{VerifyResult as SkillSignature, verify_skill_self_signed};
use wirken_gateway::sse_approval_registry::{AckResult, SseApprovalRegistry, SseEvent};
use wirken_mcp_proxy::mcp_config::{McpAuth, McpConfig, McpServerConfig};
use wirken_vault::CredentialStore;

/// WebChat rate limit. 60 chat POSTs per minute is two orders of
/// magnitude above any plausible interactive use; sized to bound
/// runaway-tab and naive-CSRF spend on the operator's API key, not
/// to throttle a human typing fast. Also bounds the cost of an
/// authenticated-but-malicious browser tab if H-1's Origin check is
/// somehow bypassed (defence in depth).
const WEBCHAT_MAX_POSTS_PER_MIN: u32 = 60;

/// The one webchat conversation. `POST /api/chat` always wakes agent
/// `default` on channel `webchat` with this conversation id; the page
/// restores it on load. Multi-conversation is its own slice.
const WEBCHAT_CONVERSATION: &str = "webchat-default";

/// The error the chat route answers with when the conversation already
/// has a turn in flight. The page keys state 19 on this text; the body
/// also carries how long the turn has been open, from the claim, so a
/// stuck one can be told from a busy one.
const TURN_OPEN_ERROR: &str = "turn open";

/// A decision posted from a page that is not viewing the conversation
/// the request came from. The link is the whole surface for that.
const DECISION_WRONG_CONVERSATION: &str =
    "This approval belongs to another conversation. Open it to decide.";

/// A webchat conversation key as the page mints it (`c-` plus twelve
/// lowercase hex digits) or the legacy constant. `None` and the empty
/// string are the legacy conversation, which is what a page with no
/// `#c=` opens. Anything else is refused before it can become a
/// session id: the key is a path segment of the audit record.
fn conversation_key(raw: Option<&str>) -> Result<String, &'static str> {
    match raw {
        None | Some("") => Ok(WEBCHAT_CONVERSATION.to_string()),
        Some(WEBCHAT_CONVERSATION) => Ok(WEBCHAT_CONVERSATION.to_string()),
        Some(key) => {
            let hex = key.strip_prefix("c-").ok_or("bad conversation key")?;
            let shaped = hex.len() == 12
                && hex
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
            if shaped {
                Ok(key.to_string())
            } else {
                Err("bad conversation key")
            }
        }
    }
}

/// The session id a webchat conversation is logged under.
fn webchat_session_id(conversation: &str) -> String {
    session_id_for("default", "webchat", conversation)
}

/// The conversation segment of a webchat session id, if it is one.
fn conversation_of(session_id: &str) -> Option<&str> {
    let mut parts = session_id.splitn(3, '/');
    let _agent = parts.next()?;
    if parts.next()? != "webchat" {
        return None;
    }
    parts.next().filter(|c| !c.is_empty())
}

/// One query parameter from a request line, undecoded: the only
/// values read this way are conversation keys, which carry nothing to
/// decode.
fn query_param<'a>(first_line: &'a str, name: &str) -> Option<&'a str> {
    let path = first_line.split_whitespace().nth(1)?;
    let (_, query) = path.split_once('?')?;
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// The conversations with a chat turn in flight, each with when it
/// was claimed. A second send into one is refused with "turn open"
/// before anything is written, so no send ever waits on the agent
/// lock with its stream already open, and no two streams ever
/// register under one conversation. The claim outlives the tab: a
/// closed socket stops the forwarding, not the turn, and the turn's
/// outbound row still has to land, so the claim is released when the
/// turn ends, and the age says how long that has been.
#[derive(Default)]
pub struct OpenTurns {
    inner: std::sync::Mutex<std::collections::BTreeMap<String, std::time::Instant>>,
}

impl OpenTurns {
    /// Claim the conversation for one turn. `None` when a turn is
    /// already open; the guard releases it on every exit path.
    pub fn try_open(self: &Arc<Self>, conversation: &str) -> Option<OpenTurn> {
        let mut map = self.inner.lock().expect("open turns mutex");
        if map.contains_key(conversation) {
            return None;
        }
        map.insert(conversation.to_string(), std::time::Instant::now());
        Some(OpenTurn {
            turns: self.clone(),
            conversation: conversation.to_string(),
        })
    }

    /// Seconds since the open turn was claimed, or `None` when none is.
    pub fn open_age(&self, conversation: &str) -> Option<u64> {
        self.inner
            .lock()
            .expect("open turns mutex")
            .get(conversation)
            .map(|since| since.elapsed().as_secs())
    }
}

/// RAII claim on a conversation's turn; dropping it releases the
/// conversation whether the turn ended, errored, or was cancelled.
pub struct OpenTurn {
    turns: Arc<OpenTurns>,
    conversation: String,
}

impl Drop for OpenTurn {
    fn drop(&mut self) {
        self.turns
            .inner
            .lock()
            .expect("open turns mutex")
            .remove(&self.conversation);
    }
}

const HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>wirken</title>
<link rel="icon" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNyIgZmlsbD0iIzE2MTgyNiI+PC9yZWN0PjxjaXJjbGUgY3g9IjE2IiBjeT0iMTYiIHI9IjUiIGZpbGw9IiNiNWFiZmMiPjwvY2lyY2xlPjxjaXJjbGUgY3g9IjE2IiBjeT0iMTYiIHI9IjkiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzkxODRkOSIgc3Ryb2tlLW9wYWNpdHk9Ii40NSIgc3Ryb2tlLXdpZHRoPSIxLjUiPjwvY2lyY2xlPjwvc3ZnPg==">
<style>
  /* Tokens. Values from the design handoff; the page owns them so no
     bundle is fetched. */
  :root {
    --bg: #161826;
    --bg-2: #131523;
    --surface: #1b1c2c;
    --surface-2: #1b1d2c;
    --surface-user: #2b2741;
    --text: #e9e9ed;
    --accent: #9184d9;
    --accent-300: #d2cefd;
    --accent-400: #b5abfc;
    --accent-700: #5d5294;
    --accent-900: #2b2741;
    --neutral-600: #75798c;
    --neutral-800: #3f424d;
    --danger-text: #e8a19d;
    --hairline: rgba(233,233,237,.09);
    --radius-sm: 4px;
    --radius-md: 8px;
    --radius-lg: 14px;
    --mono: ui-monospace, Menlo, monospace;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  /* The UA's own [hidden] rule loses to any author rule that sets
     display. Author-level and !important so hidden always hides. */
  [hidden] { display: none !important; }
  html, body { height: 100%; }
  body {
    font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
    background: var(--bg);
    color: var(--text);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  button, textarea { font: inherit; color: inherit; }
  button { cursor: pointer; background: none; border: none; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
  code, pre, .mono { font-family: var(--mono); }

  /* Banners. Escape hatches arrive with Phase 2; the halted banner is
     raised from the 503 the chat route returns while the audit writer
     is down. */
  .banner { padding: 8px 20px; display: flex; gap: 10px; align-items: center; font-size: 12.5px; line-height: 1.45; }
  .banner-danger { background: rgba(232,161,157,.10); border-bottom: 1px solid rgba(232,161,157,.35); }
  .chip { font-size: 11px; padding: 3px 10px; border-radius: 6px; white-space: nowrap; flex: none; line-height: 1.4; }
  .chip-outline { border: 1px solid var(--accent-400); color: var(--accent-400); }
  .chip-danger { border: 1px solid var(--danger-text); color: var(--danger-text); }
  .chip-neutral { background: var(--neutral-800); color: #f3f5fe; }

  /* Status line: the wordmark, then values from the status route once
     they arrive. Nothing is drawn for a value the gateway does not
     hold; unknowns are named in the About panel instead. */
  #status { position: relative; padding: 11px 20px; border-bottom: 1px solid var(--hairline); display: flex; align-items: center; gap: 12px; min-height: 42px; flex: none; }
  #wordmark { font-size: 15px; font-weight: 500; letter-spacing: -0.01em; padding: 2px 4px; margin-left: -4px; border-radius: var(--radius-sm); }
  #wordmark:hover { background: rgba(145,132,217,.08); }
  #status-values { margin-left: auto; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; justify-content: flex-end; font-size: 12px; color: rgba(233,233,237,.62); }
  #status-values .item { display: inline-flex; gap: 10px; align-items: center; }
  #status-values .sep { color: rgba(233,233,237,.25); }
  #status-values .hedge { color: rgba(233,233,237,.38); }
  #status-values .alarm { color: var(--danger-text); }
  .writer-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--accent-400); box-shadow: 0 0 7px var(--accent); display: inline-block; flex: none; padding: 0; border: none; }
  .writer-dot.halted { background: var(--danger-text); box-shadow: none; }
  .unknown { color: var(--accent-300); }
  .banner-hatch { background: rgba(145,132,217,.12); border-bottom: 1px solid rgba(145,132,217,.35); }
  .popover { position: absolute; top: calc(100% + 6px); left: 12px; width: min(380px, calc(100vw - 24px)); max-height: calc(100vh - 70px); overflow-y: auto; background: var(--surface); border-radius: 10px; box-shadow: 0 0 0 1px #595d6c, 0 16px 40px rgba(0,0,0,.6); padding: 14px 16px; z-index: 10; font-size: 12.5px; line-height: 1.5; }
  .popover h2 { font-size: 14px; font-weight: 500; margin-bottom: 10px; display: flex; gap: 8px; align-items: baseline; }
  .popover h2 .meta { font-size: 12px; font-weight: 400; color: rgba(233,233,237,.5); }
  .kv { display: grid; grid-template-columns: 88px 1fr; gap: 6px 12px; }
  .kv .k { color: rgba(233,233,237,.45); }
  .kv .v { text-align: right; overflow-wrap: anywhere; }
  .kv .v .row { display: block; }
  .kv .v details { display: block; }
  .kv .v summary { list-style: none; cursor: pointer; text-decoration: underline dotted rgba(233,233,237,.4); text-underline-offset: 3px; }
  .kv .v summary::-webkit-details-marker { display: none; }
  .kv .v details[open] summary { text-decoration: none; }
  .cap-list { display: block; text-align: left; margin: 6px 0 2px; padding: 6px 8px; border-radius: 6px; background: rgba(255,255,255,.035); }
  .cap-list .cap { display: flex; justify-content: space-between; gap: 10px; }
  .cap-list .cap + .cap { margin-top: 3px; }
  .cap-list .hedge { display: block; font-size: 11.5px; color: rgba(233,233,237,.5); margin-bottom: 3px; }
  .popover .foot { margin-top: 12px; font-size: 11px; color: rgba(233,233,237,.45); }

  #shell { flex: 1; display: flex; min-height: 0; }
  /* Rail: exists only when there is somewhere to go. */
  #rail { width: 200px; flex: none; background: var(--bg-2); border-right: 1px solid var(--hairline); padding: 14px 10px; overflow-y: auto; }
  .rail-label { font-size: 10px; text-transform: uppercase; letter-spacing: .11em; color: rgba(233,233,237,.4); padding: 6px 9px 4px; }
  .rail-row { display: block; width: 100%; text-align: left; padding: 8px 9px; border-radius: 7px; margin-bottom: 2px; }
  .rail-row:hover { background: rgba(145,132,217,.08); }
  .rail-row.active { background: rgba(145,132,217,.13); box-shadow: inset 0 0 0 1px rgba(145,132,217,.34); }
  .rail-title { font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .rail-meta { font-size: 11px; color: rgba(233,233,237,.45); margin-top: 2px; }
  .rail-section + .rail-section { margin-top: 12px; }
  .rail-label { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
  .rail-label .link { font-size: 11px; text-transform: none; letter-spacing: 0; }
  .rail-row.awaiting .rail-meta { color: #d2cefd; }
  .rail-foot { font-size: 10.5px; line-height: 1.5; color: rgba(233,233,237,.38); padding: 8px 9px 4px; }
  .elsewhere { display: flex; gap: 10px; align-items: center; border: 1px solid rgba(233,233,237,.14); border-radius: 8px; padding: 10px 14px; font-size: 13px; line-height: 1.45; margin-top: 12px; }
  .elsewhere .glyph { color: var(--accent-300); flex: none; }
  .elsewhere .title { font-weight: 500; }
  .elsewhere .link { margin-left: auto; white-space: nowrap; flex: none; }
  .empty-state:has(+ .elsewhere) { margin-bottom: 0; }
  .elsewhere.under-empty { margin: 12px auto auto; max-width: 52ch; align-self: center; }

  #main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  #conversation { flex: 1; overflow-y: auto; padding: 22px 24px 18px; display: flex; flex-direction: column; }
  /* The reading column: bubbles right-align within it, not at the far
     edge of a wide pane. */
  #thread { flex: 1; width: 100%; max-width: 880px; display: flex; flex-direction: column; gap: 16px; }
  #thread > * { flex: none; }
  .msg-user { align-self: flex-end; max-width: 70%; padding: 10px 14px; border-radius: 14px 14px 4px 14px; background: var(--surface-user); font-size: 14.5px; line-height: 1.55; white-space: pre-wrap; word-break: break-word; }
  .msg-assistant { align-self: flex-start; max-width: 78%; width: 100%; font-size: 14.5px; line-height: 1.65; color: rgba(233,233,237,.93); }
  .msg-assistant p { margin: 0 0 .7em; white-space: pre-wrap; word-break: break-word; }
  .msg-assistant p:last-child { margin-bottom: 0; }
  .msg-assistant code { font-size: 13px; background: rgba(0,0,0,.35); padding: 1px 5px; border-radius: var(--radius-sm); }
  .code { margin: 0 0 .7em; border-radius: 7px; background: rgba(0,0,0,.4); overflow: hidden; }
  .code-head { display: flex; align-items: center; padding: 4px 8px 4px 12px; font-size: 11px; color: rgba(233,233,237,.5); border-bottom: 1px solid rgba(233,233,237,.06); }
  .code-head button { margin-left: auto; font-size: 11px; color: var(--accent-300); padding: 2px 6px; border-radius: var(--radius-sm); }
  .code-head button:hover { background: rgba(145,132,217,.12); }
  .code pre { padding: 10px 12px; font-size: 13px; line-height: 1.5; overflow-x: auto; white-space: pre; }
  .cutoff { font-size: 11.5px; color: rgba(233,233,237,.5); margin-top: 4px; }
  .cutoff .link { font-size: 11.5px; }
  .empty-state { align-self: center; margin: auto; max-width: 52ch; text-align: center; font-size: 14.5px; line-height: 1.6; color: rgba(233,233,237,.62); }

  /* Tool rows: one line per call, glyph column, expand on click. */
  .tools { align-self: flex-start; max-width: 82%; width: 100%; display: flex; flex-direction: column; gap: 6px; }
  .tool-row { display: flex; gap: 10px; align-items: baseline; padding: 5px 0; font-size: 12.5px; cursor: pointer; border-radius: var(--radius-sm); }
  .tool-row:hover { background: rgba(145,132,217,.06); }
  .tool-row .glyph { width: 14px; text-align: center; flex: none; }
  .tool-row .glyph.done { color: var(--accent-400); }
  .tool-row .glyph.failed { color: var(--danger-text); }
  .tool-row .glyph.awaiting { color: var(--accent-300); }
  .tool-row .glyph.neutral { color: var(--accent-300); }
  .tool-row .glyph.queued { color: rgba(233,233,237,.45); }
  .tool-row .glyph.running { color: var(--accent); }
  .tool-row .name { font-family: var(--mono); font-size: 12px; color: rgba(233,233,237,.75); flex: none; }
  .tool-row .args { font-family: var(--mono); font-size: 12px; color: rgba(233,233,237,.5); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0; }
  .tool-row .status { font-size: 12px; color: rgba(233,233,237,.5); flex: none; white-space: nowrap; }
  .tool-details { margin: 2px 0 6px 24px; font-size: 12px; display: grid; grid-template-columns: 64px 1fr; gap: 4px 10px; }
  .tool-details .k { color: rgba(233,233,237,.45); }
  .tool-details .v { color: rgba(233,233,237,.75); overflow-wrap: anywhere; }
  .tool-details pre { grid-column: 1 / -1; margin-top: 4px; padding: 8px 10px; background: rgba(0,0,0,.4); border-radius: 7px; font-size: 12px; line-height: 1.5; white-space: pre-wrap; word-break: break-word; max-height: 320px; overflow: auto; }
  .tool-details .link { font-size: 12px; }
  .decision .glyph.neutral { color: var(--accent-300); }
  .decision .glyph.failed { color: var(--danger-text); }
  #record { left: auto; right: 12px; }
  .verify-box { margin-top: 12px; padding: 10px 12px; border-radius: var(--radius-md); background: var(--surface-2); box-shadow: inset 0 0 0 1px var(--neutral-800); display: flex; flex-direction: column; gap: 8px; }
  .verify-head { font-weight: 500; display: flex; gap: 8px; align-items: baseline; }
  .verify-head .meta { font-weight: 400; color: rgba(233,233,237,.5); font-size: 12px; margin-left: auto; }
  .verify-caveat { font-size: 12px; color: rgba(233,233,237,.62); line-height: 1.5; }
  .verify-run { width: 100%; text-align: center; }
  .verify-note { font-size: 11px; color: rgba(233,233,237,.45); }
  .verify-line { font-size: 12px; color: rgba(233,233,237,.75); line-height: 1.5; overflow-wrap: anywhere; }
  .verify-broken { box-shadow: inset 0 0 0 1px var(--danger-text); }
  .verify-broken .verify-head { color: var(--danger-text); }
  .verify-run:disabled { opacity: .5; cursor: default; }

  /* Own blocks: refusals, errors. Never spliced into the assistant's
     sentence. */
  .block { align-self: flex-start; max-width: 82%; width: 100%; border-radius: var(--radius-md); padding: 10px 14px; background: rgba(0,0,0,.25); box-shadow: inset 0 0 0 1px var(--neutral-800); }
  .block-head { display: flex; gap: 8px; align-items: baseline; font-size: 12.5px; font-weight: 500; }
  .block-head .glyph { width: 14px; text-align: center; flex: none; }
  .block-refusal .block-head { color: var(--danger-text); }
  .block-body { font-size: 12.5px; line-height: 1.5; color: rgba(233,233,237,.72); margin-top: 6px; white-space: pre-wrap; word-break: break-word; }
  .block-foot { font-size: 11.5px; color: rgba(233,233,237,.5); margin-top: 6px; }

  /* Approval card: the one loud element. */
  .approval { align-self: flex-start; max-width: 82%; width: 100%; border-radius: 10px; background: var(--surface); box-shadow: 0 0 0 1px var(--accent-700), 0 8px 24px rgba(0,0,0,.4); padding: 14px 16px; display: flex; flex-direction: column; gap: 10px; }
  .approval-head { display: flex; flex-wrap: wrap; gap: 6px 10px; align-items: baseline; }
  .approval-sentence { font-size: 12.5px; line-height: 1.45; color: rgba(233,233,237,.62); flex: 1 1 320px; }
  .approval-age { font-size: 11.5px; color: rgba(233,233,237,.5); white-space: nowrap; margin-left: auto; }
  .approval-cmd { font-family: var(--mono); font-size: 13px; line-height: 1.5; background: rgba(0,0,0,.4); padding: 10px 12px; border-radius: 7px; overflow-x: auto; white-space: pre; }
  .approval-note { font-size: 11.5px; color: rgba(233,233,237,.5); }
  .input { width: 100%; background: rgba(0,0,0,.25); border: 1px solid var(--neutral-800); border-radius: var(--radius-md); padding: 9px 12px; font-size: 13px; color: var(--text); resize: none; }
  .input::placeholder { color: rgba(233,233,237,.38); }
  .input:focus { border-color: var(--accent); outline: none; box-shadow: 0 0 0 2px rgba(145,132,217,.25); }
  .approval-reason { min-height: 38px; }
  .approval-actions { display: flex; gap: 8px; align-items: center; }
  .btn { padding: 8px 14px; border-radius: var(--radius-md); font-size: 13px; border: 1px solid var(--neutral-800); color: rgba(233,233,237,.85); }
  .btn:hover { background: rgba(255,255,255,.04); }
  .btn:disabled { opacity: .5; cursor: default; }
  .btn-deny { border-color: var(--neutral-600); color: var(--text); font-weight: 500; }
  .btn-primary { border-color: var(--accent); color: var(--accent-300); }
  .decision { align-self: flex-start; font-size: 12.5px; color: rgba(233,233,237,.62); padding: 4px 0; }
  .decision .glyph { display: inline-block; width: 14px; text-align: center; color: var(--accent-400); }

  #turnline { display: flex; gap: 8px; align-items: center; padding: 0 24px 8px; font-size: 12.5px; color: rgba(233,233,237,.5); flex: none; }
  .dots { display: inline-flex; gap: 3px; }
  .dots i { width: 4px; height: 4px; border-radius: 50%; background: var(--accent); }
  .dots i:nth-child(2) { opacity: .5; } .dots i:nth-child(3) { opacity: .25; }
  @media (prefers-reduced-motion: no-preference) {
    .dots.pulse i { animation: pulse 1.2s infinite ease-in-out; }
    .dots.pulse i:nth-child(2) { animation-delay: .2s; } .dots.pulse i:nth-child(3) { animation-delay: .4s; }
    @keyframes pulse { 0%, 100% { opacity: .25; } 50% { opacity: 1; } }
    .approval, .block, #notice, .rail-row { transition: opacity 140ms ease-out; }
  }

  /* Notices sit directly above the composer: not-sent, connection lost. */
  #notice { margin: 0 24px 8px; padding: 8px 12px; border-radius: var(--radius-md); background: rgba(0,0,0,.25); box-shadow: inset 0 0 0 1px var(--neutral-800); font-size: 12.5px; display: flex; gap: 10px; align-items: center; flex: none; }
  #notice a, .link { color: var(--accent-300); text-decoration: none; cursor: pointer; background: none; border: none; font-size: inherit; padding: 0; }
  #notice a:hover, .link:hover { text-decoration: underline; }

  #composer { display: flex; gap: 10px; padding: 0 24px 18px; flex: none; }
  #composer.busy { opacity: .6; }
  #input { flex: 1; height: 42px; min-height: 42px; max-height: 160px; line-height: 1.5; }
  #send { height: 42px; padding: 0 16px; border-radius: var(--radius-md); border: 1px solid var(--accent); color: var(--accent-300); font-size: 13px; flex: none; }
  #send:disabled { opacity: .5; cursor: default; }
  #readonly-bar { display: flex; gap: 12px; align-items: center; padding: 12px 24px 18px; border-top: 1px solid var(--hairline); font-size: 12.5px; color: rgba(233,233,237,.62); flex: none; }
  #readonly-bar .btn { margin-left: auto; white-space: nowrap; }

  /* Archive browse view, rendered inside the conversation column. */
  .archive-head { font-size: 17px; font-weight: 500; }
  .archive-head .meta { font-size: 13px; font-weight: 400; color: rgba(233,233,237,.5); margin-left: 8px; }
  .archive-note { font-size: 13px; color: rgba(233,233,237,.5); font-style: italic; }
  .archive-row { display: flex; gap: 12px; align-items: baseline; width: 100%; text-align: left; padding: 10px 0; border-bottom: 1px solid var(--hairline); font-size: 14px; }
  .archive-row:hover { background: rgba(145,132,217,.06); }
  .archive-row .meta { margin-left: auto; font-size: 12px; color: rgba(233,233,237,.5); white-space: nowrap; }
  .archive-msg { max-width: 82%; font-size: 14px; line-height: 1.6; }
  .archive-msg .sender { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: rgba(233,233,237,.45); margin-bottom: 2px; }
  .archive-msg .text { white-space: pre-wrap; word-break: break-word; }
  .archive-msg .text.empty, .archive-attachment .meta { color: rgba(233,233,237,.45); font-style: italic; }
  .archive-attachment { padding: 4px 0 4px 16px; font-size: 13px; }

  /* When the strip is tight, values yield in this order: egress, then
     the sandbox, then the model. Chips and the writer dot never yield. */
  @media (max-width: 1040px) { #status-values .yield-1 { display: none; } }
  @media (max-width: 860px) { #status-values .yield-2 { display: none; } }
  @media (max-width: 560px) { #status-values .yield-3 { display: none; } }
  @media (max-width: 720px) {
    #shell { flex-direction: column; }
    /* Two strips: conversations, then archives. Each scrolls sideways;
       one tab per row, titles cut at 18 characters; nothing overlaps. */
    #rail { width: auto; border-right: none; border-bottom: 1px solid var(--hairline); display: flex; flex-direction: column; gap: 2px; padding: 6px 10px; overflow: hidden; }
    .rail-section { display: flex; gap: 6px; align-items: center; flex: none; overflow-x: auto; overflow-y: hidden; scrollbar-width: none; }
    .rail-section + .rail-section { margin-top: 0; }
    .rail-label { flex: none; padding: 4px 8px 4px 0; gap: 6px; position: sticky; left: 0; z-index: 1; background: var(--bg-2); }
    .rail-section.fade-right { mask-image: linear-gradient(to right, #000 calc(100% - 36px), transparent); -webkit-mask-image: linear-gradient(to right, #000 calc(100% - 36px), transparent); }
    #rail-conversations, #rail-archives { display: flex; gap: 6px; flex: none; }
    .rail-row { width: auto; flex: none; white-space: nowrap; padding: 6px 9px; margin-bottom: 0; }
    .rail-title { max-width: 18ch; }
    .rail-meta { display: none; }
    .rail-foot { display: none; }
    .rail-row.awaiting .rail-title::before { content: '○ '; color: #d2cefd; }
    .msg-user, .msg-assistant, .approval, .block { max-width: 92%; }
    #thread { max-width: none; }
    #status { flex-wrap: wrap; }
    #status-values { flex-basis: 100%; justify-content: flex-start; }
    .popover { position: fixed; top: auto; bottom: 0; left: 0; right: 0; width: auto; max-height: 80vh; border-radius: 10px 10px 0 0; }
    #conversation { padding: 16px 14px 12px; }
    #composer, #turnline, #notice { padding-left: 14px; padding-right: 14px; margin-left: 0; margin-right: 0; }
  }
</style>
</head>
<body>
<div id="halted-banner" class="banner banner-danger" role="alert" hidden>
  <span class="chip chip-danger">Audit writer halted</span>
  <span>The audit record stopped accepting rows. New turns are refused until the gateway is restarted and the record verified.</span>
</div>
<div id="banners"></div>
<header id="status">
  <button id="wordmark" type="button" aria-haspopup="dialog" aria-expanded="false" aria-controls="about">wirken</button>
  <div id="status-values" hidden></div>
  <div id="about" class="popover" role="dialog" aria-label="About this gateway" hidden></div>
  <div id="record" class="popover" role="dialog" aria-label="Record of this session" hidden></div>
</header>
<div id="shell">
  <nav id="rail" aria-label="Conversations and archives" hidden>
    <div class="rail-section"><div class="rail-label"><span>Conversations</span><button id="rail-new" class="link" type="button">+ new</button></div><div id="rail-conversations"></div><div id="rail-foot" class="rail-foot"></div></div>
    <div class="rail-section"><div class="rail-label">Archives</div><div id="rail-archives"></div></div>
  </nav>
  <main id="main">
    <h1 class="sr-only">wirken webchat</h1>
    <section id="conversation" aria-live="polite" aria-label="Conversation"><div id="thread"></div></section>
    <div id="turnline" hidden><span class="dots pulse" aria-hidden="true"><i></i><i></i><i></i></span><span id="turntext"></span></div>
    <div id="notice" role="status" hidden></div>
    <form id="composer">
      <label for="input" class="sr-only">Message</label>
      <textarea id="input" class="input" rows="1" placeholder="Message your agent"></textarea>
      <button id="send" type="submit">Send</button>
    </form>
    <div id="readonly-bar" hidden>
      <span id="readonly-text"></span>
      <button id="back-to-live" type="button" class="btn">Back to the conversation</button>
    </div>
  </main>
</div>
<script>
'use strict';
const conversation = document.getElementById('conversation');
const thread = document.getElementById('thread');
const turnline = document.getElementById('turnline');
const turntext = document.getElementById('turntext');
const notice = document.getElementById('notice');
const composer = document.getElementById('composer');
const input = document.getElementById('input');
const sendBtn = document.getElementById('send');
const readonlyBar = document.getElementById('readonly-bar');
const readonlyText = document.getElementById('readonly-text');
const backToLive = document.getElementById('back-to-live');
const rail = document.getElementById('rail');
const railConversations = document.getElementById('rail-conversations');
const railArchives = document.getElementById('rail-archives');
const railNew = document.getElementById('rail-new');
const railFoot = document.getElementById('rail-foot');
const haltedBanner = document.getElementById('halted-banner');
const banners = document.getElementById('banners');
const statusValues = document.getElementById('status-values');
const wordmark = document.getElementById('wordmark');
const about = document.getElementById('about');
const record = document.getElementById('record');

// One conversation per browser today. POST /api/chat always wakes agent
// "default" on channel "webchat", conversation "webchat-default".
const AGENT_ID = 'default';
// --- Conversations ---
// A conversation is its key. The page mints one on "+ new"; the record
// knows it only once the first message is logged. A page with no #c=
// opens the legacy key. Two tabs on one key are one conversation.
const LEGACY_CONVERSATION = 'webchat-default';
const KEY_SHAPE = /^c-[0-9a-f]{12}$/;
const TURN_OPEN_ERROR = 'turn open';
const ELSEWHERE_PLACEHOLDER = 'A turn is open in another tab — it will appear here when it ends';
const DECISION_ELSEWHERE = 'This approval belongs to another conversation. Open it to decide.';
const DRAFT_TITLE = 'New conversation';
const ELSEWHERE_POLL_MS = 3000;
let currentKey = LEGACY_CONVERSATION;   // the conversation this page writes to
let draft = null;                       // a minted key nothing has been sent to yet
let resumed = null;                     // { key, title, count }: opened by URL, not on the list
let elsewhereTurn = null;               // { age, seenAt }: the viewed conversation's turn runs in another tab
let elsewhereTimer = null;
let currentTurn = null;                 // { key, controller } while this page streams a turn
let railRows = [];                      // webchat rows from /api/sessions
let railRowsAt = 0;                     // when railRows were fetched
let switchedAt = 0;                     // when the page last changed conversation
function logIdFor(key) { return AGENT_ID + '/webchat/' + key; }
function currentLogId() { return logIdFor(currentKey); }
function keyOf(logId) { return String(logId || '').split('/')[2] || ''; }
function conversationFromHash() {
  const m = /^#c=([^&]+)$/.exec(location.hash);
  if (!m) return null;
  const key = m[1];
  return key === LEGACY_CONVERSATION || KEY_SHAPE.test(key) ? key : null;
}
function mintKey() {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  return 'c-' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
function ageWords(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + ' min';
  const h = Math.floor(m / 60);
  return h < 48 ? h + ' h' : Math.floor(h / 24) + ' d';
}
function sinceWords(iso) {
  const t = Date.parse(iso);
  if (isNaN(t)) return '';
  const s = Math.floor((Date.now() - t) / 1000);
  return s < 60 ? 'just now' : ageWords(s);
}
function windowWords(seconds) {
  if (!isSet(seconds)) return null;
  const s = Number(seconds);
  if (s % 3600 === 0) return (s / 3600) + ' h';
  if (s % 60 === 0) return (s / 60) + ' min';
  return s + ' s';
}
const REFUSAL_PREFIX = 'sandbox error: ';

// The sole path from a value to the DOM. A browser renders textContent
// as characters, so text written by anyone else (an archive, a tool, an
// agent) is inert here. Nothing in this page writes innerHTML with a
// value; the only innerHTML writes assign an empty literal to clear.
function setText(el, value) {
  el.textContent = (value === null || value === undefined) ? '' : String(value);
  return el;
}
function el(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) setText(node, value);
  return node;
}
function clear(node) {
  node.innerHTML = '';
}
function hhmm(d) {
  const t = d || new Date();
  return String(t.getHours()).padStart(2, '0') + ':' + String(t.getMinutes()).padStart(2, '0');
}
function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
}
function scrollToEnd() { conversation.scrollTop = conversation.scrollHeight; }

// --- Markdown, a deliberately small grammar rendered to nodes ---
// Paragraphs (blank-line separated), inline code (single backticks),
// fenced code (triple backticks, optional label, copy button). Nothing
// else is markup; it renders as the text it is.
function renderMarkdown(container, text) {
  clear(container);
  const lines = String(text || '').split('\n');
  let para = [];
  let fence = null;
  const flushPara = () => {
    if (para.length === 0) return;
    const p = el('p');
    renderInline(p, para.join('\n'));
    container.appendChild(p);
    para = [];
  };
  for (const line of lines) {
    if (fence) {
      if (line.trim().startsWith('```')) {
        container.appendChild(codeBlock(fence.lang, fence.lines.join('\n')));
        fence = null;
      } else {
        fence.lines.push(line);
      }
      continue;
    }
    if (line.trim().startsWith('```')) {
      flushPara();
      fence = { lang: line.trim().slice(3).trim(), lines: [] };
      continue;
    }
    if (line.trim() === '') { flushPara(); continue; }
    para.push(line);
  }
  if (fence) container.appendChild(codeBlock(fence.lang, fence.lines.join('\n')));
  flushPara();
}
function renderInline(p, text) {
  const parts = text.split('`');
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === '' ) continue;
    p.appendChild(i % 2 === 1 ? el('code', null, parts[i]) : document.createTextNode(parts[i]));
  }
}
function codeBlock(lang, body) {
  const box = el('div', 'code');
  const head = el('div', 'code-head');
  if (lang) head.appendChild(el('span', null, lang));
  const copy = el('button', null, 'copy');
  copy.type = 'button';
  copy.addEventListener('click', () => {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(body).then(
      () => { setText(copy, 'copied'); setTimeout(() => setText(copy, 'copy'), 1200); },
      () => { setText(copy, 'copy failed'); });
  });
  head.appendChild(copy);
  box.appendChild(head);
  box.appendChild(el('pre', null, body));
  return box;
}

// --- Transcript primitives ---
function addUser(text) {
  const node = el('div', 'msg-user', text);
  thread.appendChild(node);
  scrollToEnd();
  return node;
}
function addAssistant(text) {
  const node = el('div', 'msg-assistant');
  node.setAttribute('data-role', 'assistant');
  renderMarkdown(node, text || '');
  thread.appendChild(node);
  scrollToEnd();
  return node;
}
function addBlock(kind, label, glyph, body, foot) {
  const box = el('div', 'block block-' + kind);
  const head = el('div', 'block-head');
  head.appendChild(el('span', 'glyph', glyph));
  head.appendChild(el('span', null, label));
  box.appendChild(head);
  if (body) box.appendChild(el('div', 'block-body', body));
  if (foot) box.appendChild(el('div', 'block-foot', foot));
  thread.appendChild(box);
  scrollToEnd();
  return box;
}
// The agent's refusal text goes on to say how to weaken the sandbox.
// That remedy belongs in the CLI, not beside the Send button, so the
// block shows the reason only: the text up to the first clause break.
function firstClause(text) {
  const t = String(text || '').trim();
  const m = t.match(/^(.*?)(;|\.(?=\s|$)|$)/s);
  return (m ? m[1] : t).trim();
}
function addRefusal(text) {
  return addBlock('refusal', 'Refused before running', '✕', firstClause(text),
    'Nothing ran on the host. The agent was stopped at this step.');
}
function addAgentError(text) {
  return addBlock('error', 'The agent stopped', '✕', text, null);
}
function addDecision(text, glyph) {
  const line = el('div', 'decision');
  const g = glyph || '✓';
  line.appendChild(el('span', 'glyph' + (g === '✕' ? ' failed' : g === '○' ? ' neutral' : ''), g));
  line.appendChild(el('span', 'decision-text', ' ' + text));
  thread.appendChild(line);
  scrollToEnd();
  return line;
}
function showEmptyState() {
  clear(thread);
  thread.appendChild(el('div', 'empty-state',
    'Agent ' + AGENT_ID + ' answers here. This page is served to this machine only. ' +
    'Every message, tool call and decision is written to the audit record first.'));
}

// --- Turn line, composer lock, notices ---
let turnOpen = false;
let halted = false;
function setTurn(text) {
  if (text === null) { turnline.hidden = true; setText(turntext, ''); return; }
  turnline.hidden = false;
  setText(turntext, text);
}
// The field is sized to what it shows, the placeholder included: a
// locked sentence that does not fit one line gets a second, never a
// clip.
function fitComposer() {
  const held = input.value;
  if (!held) input.value = input.placeholder;
  input.style.height = 'auto';
  input.style.height = Math.min(160, input.scrollHeight) + 'px';
  if (!held) input.value = '';
}
function lockComposer(placeholder) {
  input.disabled = true; sendBtn.disabled = true; composer.classList.add('busy');
  input.placeholder = placeholder;
  fitComposer();
}
function unlockComposer() {
  if (halted || elsewhereTurn) return;
  input.disabled = false; sendBtn.disabled = false; composer.classList.remove('busy');
  input.placeholder = 'Message your agent';
  fitComposer();
}
function setHalted() {
  halted = true;
  haltedBanner.hidden = false;
  lockComposer('Turns are refused while the audit writer is halted');
}
function showNotice(chipText, text, retryFn) {
  clear(notice);
  if (chipText) notice.appendChild(el('span', 'chip chip-neutral', chipText));
  notice.appendChild(el('span', null, text));
  if (retryFn) {
    const a = el('button', 'link', 'retry');
    a.type = 'button';
    a.addEventListener('click', () => { notice.hidden = true; retryFn(); });
    notice.appendChild(a);
  }
  notice.hidden = false;
}
function hideNotice() { notice.hidden = true; clear(notice); }

// One anchor per request, set from the gateway's age the first time the
// request is seen; every surface that shows the age ticks from it, so
// the card and the rail never disagree by a second.
const askedAtByRequest = new Map();
function askedAtFor(id, ageSeconds) {
  if (!askedAtByRequest.has(id)) {
    askedAtByRequest.set(id, Date.now() - (isSet(ageSeconds) ? Number(ageSeconds) * 1000 : 0));
  }
  return askedAtByRequest.get(id);
}
function askedWords(askedAt) {
  const s = Math.max(0, Math.floor((Date.now() - askedAt) / 1000));
  return 'asked ' + (s < 60 ? s + 's' : Math.floor(s / 60) + 'm ' + (s % 60) + 's') + ' ago';
}

// --- Approval card ---
// Sequential queue: tool dispatch is serial, so a second request should
// not arrive while one is rendered; the queue keeps the UI right if it
// ever does.
const approvalQueue = [];
let approvalCurrent = null;

function tierLabel(tier) {
  const t = String(tier || '');
  if (t === 'tier3') return 'Tier 3 · always asks';
  if (t === 'tier2') return 'Tier 2 · no live grant';
  return t ? 'Tier ' + t.replace('tier', '') : 'Approval';
}
function approvalSentence(ev) {
  const key = String(ev.action_key || '');
  const tail = ' Nothing runs until you decide.';
  if (key.startsWith('shell:')) {
    return (ev.requested_tier === 'tier2'
      ? 'Read-only shell command with no live grant.'
      : 'Shell command outside the read-only allowlist.') + tail;
  }
  if (key.startsWith('mcp:')) return 'MCP tool call.' + tail;
  if (key.startsWith('wasm:')) return 'Wasm skill call.' + tail;
  if (key.startsWith('imported_')) return 'Reads an imported archive.' + tail;
  if (key.startsWith('cross_channel_memory:')) return 'Reads another channel’s memory.' + tail;
  if (key.startsWith('file:')) return 'File access outside the workspace.' + tail;
  if (ev.tool_name === 'sandbox_egress') {
    // The gate names its own reason on the event as the trigger text:
    // sandbox egress to {host}:{port} after reading {basis}. Show that,
    // not a paraphrase of it.
    const reason = String(ev.trigger_message || '').replace(/^sandbox egress to /, '');
    return 'Network egress from the sandbox' + (reason ? ' · escalated: ' + reason + '.' : '.') + tail;
  }
  return String(ev.tool_name || 'This tool') + ' needs approval.' + tail;
}

function renderApproval(ev) {
  if (approvalCurrent) { approvalQueue.push(ev); return; }
  approvalCurrent = ev;
  const askedAt = askedAtFor(ev.request_id, ev.age_seconds);
  const card = el('div', 'approval');
  card.id = 'approval-' + ev.request_id;
  card.setAttribute('role', 'group');
  card.setAttribute('aria-label', 'Approval required');

  const head = el('div', 'approval-head');
  head.appendChild(el('span', 'chip chip-outline', tierLabel(ev.requested_tier)));
  head.appendChild(el('span', 'approval-sentence', approvalSentence(ev)));
  const age = el('span', 'approval-age', askedWords(askedAt));
  head.appendChild(age);
  card.appendChild(head);

  // The approval event carries the action key, not the command line.
  // The command is on the chain: the call row was written before the
  // gate ran. When the poll has it, show it and say where it is from;
  // until then the key is what the gate computed, and that is shown.
  const cmd = el('div', 'approval-cmd', ev.action_key || ev.tool_name || '');
  const note = el('div', 'approval-note', 'action key as computed by the gate · tool ' + (ev.tool_name || ''));
  card.appendChild(cmd);
  card.appendChild(note);
  const join = () => {
    const entry = pendingToolRowFor(ev.tool_name);
    if (!entry) return false;
    setText(cmd, compactArgs(entry.call));
    setText(note, 'command as recorded in the chain, row ' + entry.seq + ' · action key ' + (ev.action_key || ''));
    markAwaiting(entry);
    return true;
  };
  if (!join()) pollEvents().then(join);
  if (turnOpen && !eventsTimer) startEventPolling();

  const reasonLabel = el('label', 'sr-only', 'Reason (optional)');
  reasonLabel.htmlFor = 'reason-' + ev.request_id;
  const reason = el('textarea', 'input approval-reason');
  reason.id = 'reason-' + ev.request_id;
  reason.placeholder = 'Reason (optional)';
  reason.rows = 1;
  card.appendChild(reasonLabel);
  card.appendChild(reason);

  const actions = el('div', 'approval-actions');
  const denyBtn = el('button', 'btn btn-deny', 'Deny');
  denyBtn.type = 'button';
  const approveBtn = el('button', 'btn btn-primary', 'Approve once');
  approveBtn.type = 'button';
  actions.appendChild(denyBtn);
  actions.appendChild(approveBtn);
  card.appendChild(actions);
  thread.appendChild(card);
  scrollToEnd();
  setTurn('turn open · agent holding on your decision');
  lockComposer('Decide on the approval above to continue');

  const ticker = setInterval(() => {
    if (!card.isConnected) { clearInterval(ticker); return; }
    setText(age, askedWords(askedAt));
  }, 1000);

  const submit = async (decision) => {
    approveBtn.disabled = true;
    denyBtn.disabled = true;
    const body = { decision, conversation: currentKey };
    const r = reason.value.trim();
    if (r) body.reason = r;
    card.dataset.decision = decision;
    card.dataset.reason = r;
    try {
      const res = await fetch('/api/approvals/' + encodeURIComponent(ev.request_id), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.status === 403) {
        // The gateway says this request was raised elsewhere. The card
        // should not have been here; the link is the way to it.
        approveBtn.disabled = false;
        denyBtn.disabled = false;
        card.appendChild(el('div', 'approval-note', DECISION_ELSEWHERE));
        return;
      }
      if (!turnOpen) {
        // No stream will carry the ack; the reply is the ack.
        let reply = null;
        try { reply = await res.json(); } catch (e2) { reply = null; }
        ackApproval(ev.request_id, reply && reply.result ? reply.result : 'unknown_key');
        pollEventsFor(30000);
      }
    } catch (e) {
      // The ack will not arrive. Say so and let the operator retry.
      approveBtn.disabled = false;
      denyBtn.disabled = false;
      card.appendChild(el('div', 'approval-note', 'Your decision did not reach the gateway: ' + e.message));
    }
  };
  approveBtn.addEventListener('click', () => submit('allow'));
  denyBtn.addEventListener('click', () => submit('deny'));
}

// The ack means the queue accepted the decision. "Recorded" is said only
// when the chain row is seen, which Phase 2 polls for.
function ackApproval(requestId, result) {
  const card = document.getElementById('approval-' + requestId);
  if (card) {
    const decision = card.dataset.decision || '';
    const reason = card.dataset.reason || '';
    let line, glyph;
    if (result === 'accepted') {
      line = (decision === 'deny' ? 'denied' : 'accepted') + ' · ' + hhmm() + (reason ? ' · ' + reason : '');
      glyph = decision === 'deny' ? '○' : '✓';
    } else {
      // The only evidence here is the gate's reply that the entry is
      // no longer pending. "Expired" needs the timeout denial row,
      // which Phase 2 reads.
      line = 'no longer pending · ' + hhmm() + ' · decided elsewhere';
      glyph = '○';
    }
    const drawn = addDecision(line, glyph);
    card.replaceWith(drawn);
    if (approvalCurrent && approvalCurrent.request_id === requestId && approvalCurrent.action_key) {
      decisionLines.set(approvalCurrent.action_key, drawn);
    }
  }
  if (approvalCurrent && approvalCurrent.request_id === requestId) {
    approvalCurrent = null;
    if (approvalQueue.length > 0) {
      renderApproval(approvalQueue.shift());
    } else if (turnOpen) {
      setTurn('turn open');
      lockComposer('Waiting for the agent…');
    } else {
      setTurn(null);
      unlockComposer();
    }
  }
}

// A turn that ends with a card still open never received an ack: the
// gate times out server-side and writes a denial row. The card cannot
// stay interactive after its stream is gone.
function settleOpenApproval() {
  if (!approvalCurrent) return;
  const card = document.getElementById('approval-' + approvalCurrent.request_id);
  if (card) card.replaceWith(addDecision('turn ended · no decision was sent from here', '○'));
  approvalCurrent = null;
  approvalQueue.length = 0;
}

// --- Sending a turn ---
let lastCutNode = null;
async function send() {
  const text = input.value.trim();
  if (!text || turnOpen || halted) return;
  input.value = '';
  hideNotice();
  const emptyState = thread.querySelector('.empty-state');
  if (emptyState) emptyState.remove();
  turnOpen = true;
  lockComposer('Waiting for the agent…');
  setTurn('thinking');
  const userNode = addUser(text);
  startEventPolling();
  const key = currentKey;
  const controller = new AbortController();
  currentTurn = { key, controller };

  liveAssistant = null;
  liveReceived = '';
  let buffer = '';
  let terminal = false;   // a done or error event arrived
  let res;
  try {
    res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text, conversation: key }),
      signal: controller.signal,
    });
  } catch (e) {
    if (controller.signal.aborted) return;
    userNode.remove();
    finishTurn();
    input.value = text;
    showNotice(null, 'Connection lost · ', () => send());
    return;
  }

  if (!res.ok) {
    // Not sent: the message goes back into the composer, not into the
    // record.
    userNode.remove();
    finishTurn();
    input.value = text;
    if (res.status === 503) { setHalted(); return; }
    if (res.status === 409) {
      // The gateway says a turn is already open in this conversation:
      // another tab's, not a guess. The text waits in the composer.
      let body = null;
      try { body = await res.json(); } catch (e) { body = null; }
      if (body && body.error === TURN_OPEN_ERROR) { setElsewhereTurn(body.age_seconds); return; }
    }
    let msg;
    if (res.status === 429) {
      const ra = parseInt(res.headers.get('Retry-After') || '', 10);
      msg = 'Too many requests.' + (ra > 0 ? ' Try again in ' + ra + 's.' : ' Try again shortly.');
    } else if (res.status === 403) {
      msg = 'This page’s origin was not accepted by the gateway. Reload from ' + location.origin + '.';
    } else {
      msg = 'The gateway refused this request (' + res.status + ').';
    }
    showNotice('Not sent', msg, null);
    return;
  }

  // The record knows this conversation now.
  if (draft === key) { draft = null; renderRail(); }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary;
      while ((boundary = buffer.indexOf('\n\n')) >= 0) {
        const block = buffer.substring(0, boundary);
        buffer = buffer.substring(boundary + 2);
        for (const line of block.split('\n')) {
          if (!line.startsWith('data: ')) continue;
          let event;
          try { event = JSON.parse(line.substring(6)); } catch (e) { continue; }
          if (event.type === 'delta') {
            if (!liveAssistant) liveAssistant = addAssistant('');
            liveReceived += event.text;
            renderMarkdown(liveAssistant, liveReceived);
            setTurn(approvalCurrent ? 'turn open · agent holding on your decision' : 'turn open');
            scrollToEnd();
          } else if (event.type === 'error') {
            terminal = true;
            const msg = String(event.text || '');
            if (msg.startsWith(REFUSAL_PREFIX)) addRefusal(msg.slice(REFUSAL_PREFIX.length));
            else addAgentError(msg);
          } else if (event.type === 'approval_request') {
            // What the agent says after the decision is a new paragraph
            // below the card, not a continuation of the one above it.
            liveAssistant = null;
            liveReceived = '';
            renderApproval(event);
          } else if (event.type === 'approval_decision_ack') {
            ackApproval(event.request_id, event.result);
          } else if (event.type === 'done') {
            terminal = true;
          }
        }
      }
    }
  } catch (e) {
    // The socket died mid-stream; fall through to the cut-off marking.
  }
  // Switched away mid-turn: the stream was abandoned, not the turn. The
  // gateway runs it to its end and the record holds what it produced.
  if (controller.signal.aborted) return;
  if (!terminal) {
    if (liveAssistant) {
      const line = el('div', 'cutoff', 'cut off — the stream ended without a done event · ');
      const retry = el('button', 'link', 'retry');
      retry.type = 'button';
      retry.addEventListener('click', () => loadTranscript(currentLogId()));
      line.appendChild(retry);
      liveAssistant.appendChild(line);
    } else {
      showNotice(null, 'Connection lost · ', () => loadTranscript(currentLogId()));
    }
  }
  settleOpenApproval();
  finishTurn();
  // One more poll after the socket closes: the rows for this turn
  // (results, decisions, the assistant row) are what turn "accepted"
  // into "recorded".
  await pollEvents();
  loadRail();
}
function finishTurn() {
  turnOpen = false;
  currentTurn = null;
  stopEventPolling();
  setTurn(null);
  unlockComposer();
  if (!halted) input.focus();
}

// --- History: the record, projected ---
// The events route serves the session log with the rows the old
// transcript dropped: tool calls and results, decisions, egress
// verdicts, budget stops, sub-agent spawns. Head and totals feed the
// Record panel. During a turn the same route is polled with `after`
// so rows land a moment behind the agent; the live text still comes
// over the stream.
let liveAssistant = null;
let liveReceived = '';
let lastSeq = -1;
let recordSummary = null;
let eventsTimer = null;
const EVENTS_POLL_MS = 1000;
const toolRows = new Map();      // call id -> entry
const decisionLines = new Map(); // action key -> decision line node

async function loadTranscript(id) {
  setReadOnly(id === currentLogId() ? null : OTHER_SESSION_NOTICE);
  let page = null;
  try {
    const res = await fetch('/api/sessions/' + encodeURIComponent(id) + '/events');
    if (res.ok) page = await res.json();
  } catch (e) {
    page = null;
  } finally {
    // The rail is refreshed however the load ends.
    loadRail();
  }
  if (!page || !Array.isArray(page.events)) return;
  clear(thread);
  toolRows.clear();
  decisionLines.clear();
  lastSeq = -1;
  recordSummary = page;
  if (id === currentLogId()) {
    if (page.events.length === 0) {
      // A key with no record is a draft, not an error.
      if (currentKey !== LEGACY_CONVERSATION) draft = currentKey;
      resumed = null;
    } else {
      // Opened by key and not on the list: the row is drawn from what
      // the record holds, and says so.
      const first = page.events.find((ev) => ev.kind === 'user_message');
      resumed = { key: currentKey, title: first ? String(first.content || '') : '', count: page.events.filter((ev) => ev.kind === 'user_message').length };
    }
  }
  if (page.events.length === 0 && id === currentLogId()) { showEmptyState(); renderRail(); renderElsewhereLine(); return; }
  for (const ev of page.events) renderEvent(ev, false);
  renderRail();
  renderElsewhereLine();
  scrollToEnd();
}

async function pollEvents() {
  let page;
  const key = currentKey;
  try {
    const res = await fetch('/api/sessions/' + encodeURIComponent(logIdFor(key)) + '/events?after=' + Math.max(lastSeq, 0));
    if (!res.ok) return;
    page = await res.json();
  } catch (e) { return; }
  if (key !== currentKey) return;
  if (!page || !Array.isArray(page.events)) return;
  recordSummary = page;
  for (const ev of page.events) {
    if (ev.seq <= lastSeq) continue;
    renderEvent(ev, true);
  }
  if (!record.hidden) renderRecord();
}
function startEventPolling() {
  if (eventsTimer) return;
  eventsTimer = setInterval(pollEvents, EVENTS_POLL_MS);
}
function stopEventPolling() {
  if (eventsTimer) { clearInterval(eventsTimer); eventsTimer = null; }
}
function pollEventsFor(ms) {
  startEventPolling();
  setTimeout(() => { if (!turnOpen) stopEventPolling(); }, ms);
}

function compactArgs(call) {
  try {
    const a = JSON.parse(call.arguments);
    if (a && typeof a.command === 'string') return a.command;
    if (a && typeof a.path === 'string') return a.path;
  } catch (e) { /* not JSON: show it as it is */ }
  return String(call.arguments || '');
}
function setGlyph(entry, glyph, cls, statusText) {
  setText(entry.glyph, glyph);
  entry.glyph.className = 'glyph ' + cls;
  setText(entry.status, statusText || '');
}
function markAwaiting(entry) { setGlyph(entry, '○', 'awaiting', 'awaiting you'); }
function pendingToolRowFor(name) {
  let found = null;
  for (const entry of toolRows.values()) {
    if (!entry.result && entry.call.name === name) found = entry;
  }
  return found;
}
function advanceBlock(block) {
  // The first uncompleted call of a round runs; the rest are queued.
  let running = false;
  for (const entry of block.entries) {
    if (entry.result) continue;
    if (entry.glyph.classList.contains('awaiting')) { running = true; continue; }
    if (!running) { setGlyph(entry, '·', 'running', 'running'); running = true; }
    else setGlyph(entry, '◌', 'queued', 'queued');
  }
}
function toolRow(block, call, seq) {
  const wrap = el('div', 'tool');
  const row = el('div', 'tool-row');
  row.setAttribute('role', 'button');
  row.tabIndex = 0;
  row.setAttribute('aria-expanded', 'false');
  const glyph = el('span', 'glyph queued', '◌');
  const name = el('span', 'name', call.name);
  const args = el('span', 'args', compactArgs(call));
  const status = el('span', 'status', 'queued');
  row.appendChild(glyph); row.appendChild(name); row.appendChild(args); row.appendChild(status);
  const details = el('div', 'tool-details');
  details.hidden = true;
  wrap.appendChild(row); wrap.appendChild(details);
  const entry = { wrap, row, glyph, status, details, call, seq, result: null, block };
  const toggle = () => {
    details.hidden = !details.hidden;
    row.setAttribute('aria-expanded', details.hidden ? 'false' : 'true');
    if (!details.hidden) renderToolDetails(entry);
  };
  row.addEventListener('click', toggle);
  row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
  toolRows.set(call.id, entry);
  return entry;
}
function renderToolDetails(entry) {
  const d = entry.details;
  clear(d);
  const kv = (k, v) => { d.appendChild(el('span', 'k', k)); const vv = el('span', 'v'); vv.appendChild(typeof v === 'string' ? document.createTextNode(v) : v); d.appendChild(vv); };
  kv('tier', entry.call.computed_tier
    ? entry.call.computed_tier.replace('tier', 'Tier ') + (entry.call.action_key ? ' · ' + entry.call.action_key : '')
    : 'not classified by the gate');
  const sb = status && status.sandbox ? status.sandbox : null;
  const eg = status && status.egress ? status.egress : null;
  kv('ran in', sb && sb.mode
    ? (sb.mode === 'off' ? 'on the host, no sandbox' : sb.mode + ' sandbox') + (eg && eg.mode ? (eg.mode === 'none' ? ' · no network' : ' · egress ' + eg.mode) : '') + ' (configured)'
    : unknownNode());
  if (entry.result) {
    const r = entry.result;
    kv('took', isSet(r.elapsed_ms_approx) ? '~' + (r.elapsed_ms_approx / 1000).toFixed(1) + 's, from row timestamps · exit code not recorded' : unknownNode());
    const out = el('span');
    out.appendChild(document.createTextNode((r.output_bytes || 0) + ' bytes' + (r.success ? '' : ' · failed') + ' '));
    const show = el('button', 'link', 'show');
    show.type = 'button';
    let pre = null;
    show.addEventListener('click', () => {
      if (pre) { pre.remove(); pre = null; setText(show, 'show'); return; }
      pre = el('pre', null, r.output || '');
      d.appendChild(pre);
      setText(show, 'hide');
    });
    out.appendChild(show);
    kv('output', out);
  } else {
    kv('result', 'none yet');
  }
}

function renderEvent(ev, live) {
  if (typeof ev.seq === 'number') lastSeq = Math.max(lastSeq, ev.seq);
  switch (ev.kind) {
    case 'user_message':
      if (!live) addUser(ev.content);
      break;
    case 'assistant_message':
      if (!live) addAssistant(ev.content);
      break;
    case 'assistant_tool_calls': {
      // Rows land before the tool runs; text after the round is a new
      // paragraph below them.
      if (live) { liveAssistant = null; liveReceived = ''; }
      const block = el('div', 'tools');
      block.entries = [];
      for (const call of ev.calls || []) {
        const entry = toolRow(block, call, ev.seq);
        block.entries.push(entry);
        block.appendChild(entry.wrap);
      }
      // The call row was written before the gate prompted, so when a
      // card is already open the row belongs above it.
      const openCard = live && approvalCurrent ? document.getElementById('approval-' + approvalCurrent.request_id) : null;
      if (openCard) thread.insertBefore(block, openCard);
      else thread.appendChild(block);
      advanceBlock(block);
      scrollToEnd();
      break;
    }
    case 'tool_result': {
      const entry = toolRows.get(ev.call_id);
      if (!entry) break;
      entry.result = ev;
      setGlyph(entry, ev.success ? '✓' : '✕', ev.success ? 'done' : 'failed', '');
      advanceBlock(entry.block);
      if (!entry.details.hidden) renderToolDetails(entry);
      break;
    }
    case 'permission_approved': {
      const line = 'approved by ' + (ev.approved_by || 'unknown') + ' · ' + hhmm(new Date(ev.ts)) + ' · recorded';
      settleDecision(ev.action_key, line, '✓', live);
      break;
    }
    case 'permission_denied': {
      const entry = pendingToolRowFor(ev.tool);
      const operatorDecision = !ev.timed_out && ev.denied_via && ev.denied_via.kind === 'sse';
      // One event, one word, one glyph: a denial is the operator's and
      // an expiry is the window's, so the call was never attempted and
      // the row takes the neutral glyph; ✕ is for failed and for the
      // gate's own fail-closed refusal.
      const notAttempted = ev.timed_out || operatorDecision;
      if (entry) setGlyph(entry, notAttempted ? '○' : '✕', notAttempted ? 'neutral' : 'failed',
        ev.timed_out ? 'expired' : operatorDecision ? 'denied' : 'refused');
      let line, glyph;
      if (ev.timed_out) {
        line = 'expired — treated as denied · ' + hhmm(new Date(ev.ts)) + ' · recorded';
        glyph = '○';
      } else if (ev.denied_via && ev.denied_via.kind === 'sse') {
        line = 'denied · ' + hhmm(new Date(ev.ts)) + (ev.denial_reason ? ' · ' + ev.denial_reason : '') + ' · recorded';
        glyph = '○';
      } else {
        line = 'refused by ' + (ev.denial_source || 'the gate') + ' · ' + (ev.action_key || ev.tool) +
          (ev.denial_reason ? ' · ' + ev.denial_reason : '') + ' · recorded';
        glyph = '✕';
      }
      settleDecision(ev.action_key, line, glyph, live);
      break;
    }
    case 'permission_renewed':
      if (!live) addDecision('grant renewed · ' + ev.action_key + ' · until ' + fmtDate(ev.expires_at) + ' · recorded', '✓');
      break;
    case 'permission_grant_expired':
      addDecision('grant expired · ' + ev.action_key + ' · recorded', '○');
      break;
    case 'permission_grant_pruned':
      addDecision('grant pruned · ' + ev.action_key + ' · recorded', '○');
      break;
    case 'sandbox_egress_verdict':
      addDecision('egress ' + (ev.allowed ? 'allowed' : 'refused') + ' · ' + ev.host + ':' + ev.port +
        (ev.reason ? ' · ' + ev.reason : '') + (ev.escalated ? ' · escalated' : '') + ' · recorded', ev.allowed ? '✓' : '✕');
      break;
    case 'budget_exceeded':
      addBlock('refusal', 'Spending limit reached', '✕',
        usd(ev.window_spend_usd_micros) + ' of ' + usd(ev.ceiling_usd_micros) + ' this ' + ev.window +
        (ev.tool ? ' · ' + ev.tool + ' not called' : ' · the model was not called'),
        'From the budget row on the record.');
      break;
    case 'subagent_spawned':
      addDecision('sub-agent ' + ev.child_agent_id + ' spawned · tools ' + ((ev.tools_granted || []).join(', ') || 'none') +
        (ev.max_permission_tier ? ' · cap ' + ev.max_permission_tier : '') + ' · recorded', '○');
      break;
    case 'subagent_result':
      addDecision('sub-agent finished · ' + (typeof ev.status === 'string' ? ev.status : JSON.stringify(ev.status)) + ' · recorded',
        ev.status === 'ok' ? '✓' : '✕');
      break;
    case 'llm_request':
    case 'llm_response':
    case 'attestation':
    case 'chain_head':
    case 'compaction':
    case 'http_request':
      // Record panel material; the totals come with the page.
      break;
    default:
      break;
  }
}
// A decision row settles whatever stood for it: the open card, the
// line the ack drew, or nothing yet. The row is what makes it recorded.
function settleDecision(actionKey, line, glyph, live) {
  if (live && approvalCurrent && approvalCurrent.action_key === actionKey) {
    const card = document.getElementById('approval-' + approvalCurrent.request_id);
    if (card) card.replaceWith(addDecision(line, glyph));
    approvalCurrent = null;
    if (turnOpen) { setTurn('turn open'); lockComposer('Waiting for the agent…'); }
    return;
  }
  const existing = decisionLines.get(actionKey);
  if (existing) {
    existing.replaceWith(addDecision(line, glyph));
    decisionLines.delete(actionKey);
    return;
  }
  addDecision(line, glyph);
}

// --- Record panel: head, totals, what has and has not been verified ---
function renderRecord() {
  clear(record);
  const r = recordSummary || {};
  const head = r.head || {};
  const t = r.totals || {};
  const h2 = el('h2', null, 'Record');
  h2.appendChild(el('span', 'meta', 'this session' + (isSet(head.seq) ? ' · ' + (head.seq + 1) + ' rows' : '')));
  record.appendChild(h2);
  const grid = el('div', 'kv');
  const audit = status && status.audit ? status.audit : {};
  const w = el('span', null, audit.writer_halted ? 'halted' : 'live');
  if (Array.isArray(audit.alarms)) w.appendChild(document.createTextNode(audit.alarms.length ? ' · ' + audit.alarms.length + ' alarms on disk' : ' · no alarms on disk'));
  // Verify is report-only and alarms come from the writer, so both can
  // be true at once; side by side they must not read as a contradiction.
  if (lastVerifyBroken()) w.appendChild(document.createTextNode(' · last verify found a break'));
  kvRow(grid, 'writer', w);
  if (isSet(head.seq)) {
    const v = el('span', null, head.seq + ' · ');
    v.appendChild(el('code', null, head.hash || ''));
    kvRow(grid, 'head', v);
  } else {
    kvRow(grid, 'head', unknownNode());
  }
  kvRow(grid, 'signed to', isSet(head.last_signed_head_seq)
    ? el('span', null, head.last_signed_head_seq + ' · ' + head.unsigned_tail_len + ' unsigned tail')
    : el('span', null, 'no signed head yet'));
  kvRow(grid, 'attestations', isSet(t.attestations) ? el('span', null, t.attestations + ' recorded, not verified') : unknownNode());
  if (isSet(t.llm_calls)) {
    const n = (count, word) => count + ' ' + word + (count === 1 ? '' : 's');
    kvRow(grid, 'this session', el('span', null, n(t.llm_calls, 'call') + ' · ' + n(t.tool_calls, 'tool call') + ' · ' +
      (t.input_tokens / 1000).toFixed(1) + 'k/' + (t.output_tokens / 1000).toFixed(1) + 'k · ' + usd(t.cost_usd_micros) + (t.cost_known ? '' : ' + unpriced calls')));
  } else {
    kvRow(grid, 'this session', unknownNode());
  }
  kvRow(grid, 'context now', unknownNode());
  const lc = r.last_compaction;
  kvRow(grid, 'compaction', lc && isSet(lc.seq) ? el('span', null, 'row ' + lc.seq + ' · ' + (lc.dropped_messages ?? '?') + ' messages dropped') : el('span', null, 'none'));
  record.appendChild(grid);
  record.appendChild(renderVerifyBox());
  record.appendChild(el('div', 'foot', 'Counts are from the record. Nothing here is verified until a verify pass says so.'));
}
// --- Verify chain: five states, one caveat ---
// idle, running, ok, broken, busy (plus the two ways a run can fail
// to start). The verdict is the gateway's; "this browser" says whose
// run it was, because the gateway keeps no record of its own passes.
let verifyState = { status: 'idle', at: null, body: null, retryAfter: null, error: null };
function ago(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return s + 's ago';
  const m = Math.floor(s / 60);
  return m < 60 ? m + ' min ago' : Math.floor(m / 60) + ' h ago';
}
function verifyLine(b) {
  switch (b.result) {
    case 'ok':
      return (b.rows_verified || 0).toLocaleString() + ' rows · ' + b.sessions_total + ' sessions · ' +
        b.signed_heads_count + ' signed heads · ' + b.invalid_signatures_count + ' invalid · chain heads only' +
        (b.sessions_with_no_signed_heads ? ' · ' + b.sessions_with_no_signed_heads + ' sessions without a signed head' : '') +
        (b.schema_drift ? ' · ' + b.schema_drift + ' rows not readable' : '');
    case 'broken':
      return 'chain broken at session ' + b.session_id + ' row ' + b.seq + ' — expected ' + b.expected_hash + ', found ' + b.actual_hash;
    case 'signature_invalid':
      return 'signature invalid at session ' + b.session_id + ' row ' + b.seq + ' — ' + b.reason + ' · key ' + b.signing_key_fingerprint;
    case 'missing_chain_head':
      return 'session ' + b.session_id + ' has no signed head (' + b.rows + ' rows)';
    case 'empty':
      return 'no session events to verify';
    default:
      return b.error || 'could not run';
  }
}
function lastVerifyBroken() {
  const st = verifyState;
  const verdict = st.body ? st.body.result : null;
  return st.status === 'done' && !!verdict && verdict !== 'ok' && verdict !== 'empty' && verdict !== 'error';
}
function renderVerifyBox() {
  const st = verifyState;
  const broken = lastVerifyBroken();
  const box = el('div', 'verify-box' + (broken ? ' verify-broken' : ''));
  const bh = el('div', 'verify-head', 'Verify chain');
  let meta;
  if (st.status === 'idle') meta = 'not run yet';
  else if (st.status === 'running') meta = 'verifying…';
  else if (st.status === 'busy') meta = 'another verify is running';
  else if (st.status === 'limited') meta = 'rate limited · try again in ' + st.retryAfter + 's';
  else if (st.status === 'error') meta = 'could not run · ' + st.error;
  else meta = 'this browser · ' + ago(Date.now() - st.at) + ' · ' + ((st.body.duration_ms || 0) / 1000).toFixed(1) + 's' + (broken ? ' · broken' : st.body.result === 'error' ? ' · error' : ' · ok');
  bh.appendChild(el('span', 'meta', meta));
  box.appendChild(bh);
  if (st.status === 'done' && st.body) box.appendChild(el('div', 'verify-line', verifyLine(st.body)));
  // The caveat is on screen in every state, idle included.
  box.appendChild(el('div', 'verify-caveat',
    'Report-only: no operator trust anchor was consulted, so a same-UID rewrite is not detected. ' +
    'Verify against a key kept off this machine for that: wirken audit verify --require-signed'));
  const run = el('button', 'btn verify-run', st.status === 'idle' ? 'Run verify' : st.status === 'running' ? 'verifying…' : 'Run again');
  run.type = 'button';
  run.disabled = st.status === 'running';
  run.addEventListener('click', (e) => { e.stopPropagation(); runVerify(); });
  box.appendChild(run);
  box.appendChild(el('div', 'verify-note', 'two full reads of the record · one run at a time'));
  return box;
}
function refreshVerifyBox() {
  if (!record.hidden) renderRecord();
}
async function runVerify() {
  if (verifyState.status === 'running') return;
  verifyState = { status: 'running', at: Date.now(), body: null, retryAfter: null, error: null };
  refreshVerifyBox();
  let res;
  try {
    res = await fetch('/api/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  } catch (e) {
    verifyState = { status: 'error', at: Date.now(), body: null, retryAfter: null, error: 'connection lost' };
    refreshVerifyBox();
    return;
  }
  if (res.status === 409) {
    verifyState = { status: 'busy', at: Date.now(), body: null, retryAfter: null, error: null };
  } else if (res.status === 429) {
    const ra = parseInt(res.headers.get('Retry-After') || '60', 10);
    verifyState = { status: 'limited', at: Date.now(), body: null, retryAfter: ra > 0 ? ra : 60, error: null };
  } else if (!res.ok) {
    verifyState = { status: 'error', at: Date.now(), body: null, retryAfter: null, error: 'the gateway refused this request (' + res.status + ')' };
  } else {
    let body = null;
    try { body = await res.json(); } catch (e) { body = null; }
    if (!body || !body.result) verifyState = { status: 'error', at: Date.now(), body: null, retryAfter: null, error: 'no verdict in the reply' };
    else if (body.result === 'error') verifyState = { status: 'error', at: Date.now(), body, retryAfter: null, error: body.error || 'verify failed' };
    else verifyState = { status: 'done', at: Date.now(), body, retryAfter: null, error: null };
  }
  refreshVerifyBox();
}
function setRecordOpen(open) {
  record.hidden = !open;
  if (open) { setAboutOpen(false); renderRecord(); }
}

// --- Composer ownership ---
// The composer belongs to the conversation this browser writes to. Any
// other view (an imported archive, another session) takes it away and
// puts a notice and the way back in its place.
const ARCHIVE_NOTICE = 'Imported archive: nothing to send to here.';
const OTHER_SESSION_NOTICE = 'Another session, shown read-only. This browser writes to its own conversation.';
function setReadOnly(text) {
  composer.hidden = text !== null;
  readonlyBar.hidden = text === null;
  if (text !== null) setText(readonlyText, text);
}
backToLive.addEventListener('click', () => { activeArchive = null; loadTranscript(currentLogId()); });

// --- Rail: only when there is somewhere to go ---
let activeArchive = null;
let railSources = [];
async function loadRail() {
  let sources = [];
  let rows = [];
  try {
    const res = await fetch('/api/imported/sources');
    if (res.ok) sources = await res.json();
  } catch (e) { sources = []; }
  try {
    const res = await fetch('/api/sessions');
    if (res.ok) rows = await res.json();
  } catch (e) { rows = []; }
  railSources = Array.isArray(sources) ? sources : [];
  railRows = Array.isArray(rows) ? rows.filter((r) => r && r.channel === 'webchat') : [];
  railRowsAt = Date.now();
  renderRail();
  renderElsewhereLine();
  syncElsewhereTurn();
}
// The rows the rail draws: a draft first, then the list newest first,
// then a key opened by URL that the list does not hold.
function railEntries() {
  const entries = [];
  if (draft) entries.push({ key: draft, draft: true });
  for (const r of railRows) {
    if (r.log_id === logIdFor(draft)) continue;
    entries.push({
      key: keyOf(r.log_id),
      title: isSet(r.first_message) ? String(r.first_message) : '',
      count: r.message_count,
      last: r.last_activity,
      turnOpen: r.turn_open === true,
    });
  }
  if (resumed && !entries.some((e) => e.key === resumed.key)) {
    entries.push({ key: resumed.key, title: resumed.title, count: resumed.count, resumed: true });
  }
  return entries;
}
// The title of a conversation as the rail shows it: its first message
// as written, or its key when there is none.
function titleFor(key) {
  const entry = railEntries().find((e) => e.key === key);
  if (!entry) return key;
  if (entry.draft) return DRAFT_TITLE;
  return entry.title || entry.key;
}
// Every conversation holding a pending request, with how long ago it
// asked: this one's from `mine`, the others' from `elsewhere`.
function pendingByKey() {
  const pending = new Map();
  if (!approvals) return pending;
  for (const m of approvals.mine || []) {
    const k = keyOf(m.agent_id);
    if (k && !pending.has(k)) pending.set(k, askedAtFor(m.request_id, m.age_seconds));
  }
  for (const e of approvals.elsewhere || []) {
    if (e.conversation && !pending.has(e.conversation)) {
      pending.set(e.conversation, askedAtFor('elsewhere:' + e.conversation + ':' + e.requested_at, e.age_seconds));
    }
  }
  return pending;
}
// The awaiting rows tick with the card, from the same anchors.
let railTicker = null;
function tickRail() {
  for (const row of railConversations.querySelectorAll('.rail-row.awaiting')) {
    const meta = row.querySelector('.rail-meta');
    if (meta && isSet(row.dataset.askedAt)) setText(meta, '○ awaiting you · ' + askedWords(Number(row.dataset.askedAt)) + (row.dataset.suffix || ''));
  }
}
function railFootnote() {
  const w = status && status.gateway ? windowWords(status.gateway.session_expiry_secs) : null;
  return 'titles are each conversation\'s first message · quiet for ' +
    (w || 'the gateway\'s window') + ' drops off this list, not out of the record';
}
function renderRail() {
  const entries = railEntries();
  // The rail exists when there is more than one destination: a second
  // conversation, a draft, or an archive.
  rail.hidden = entries.length + railSources.length < 2;
  if (rail.hidden) return;
  clear(railConversations);
  const pending = pendingByKey();
  for (const e of entries) {
    const here = e.key === currentKey && activeArchive === null;
    const row = el('button', 'rail-row' + (here ? ' active' : '') + (pending.has(e.key) ? ' awaiting' : ''));
    row.type = 'button';
    row.appendChild(el('div', 'rail-title', e.draft ? DRAFT_TITLE : (e.title || e.key)));
    let meta;
    if (e.draft) meta = 'unsent';
    else if (pending.has(e.key)) meta = '○ awaiting you · ' + askedWords(pending.get(e.key));
    else meta = (isSet(e.count) ? e.count + ' msg' : 'no messages yet') + (e.last ? ' · ' + sinceWords(e.last) : '');
    let suffix = '';
    if (e.turnOpen || (e.key === currentKey && (turnOpen || elsewhereTurn))) suffix += ' · turn open';
    if (e.resumed) suffix += ' · resumed';
    if (pending.has(e.key)) { row.dataset.askedAt = String(pending.get(e.key)); row.dataset.suffix = suffix; }
    row.appendChild(el('div', 'rail-meta', meta + suffix));
    row.addEventListener('click', () => openConversation(e.key));
    railConversations.appendChild(row);
  }
  setText(railFoot, railFootnote());
  if (pending.size && !railTicker) railTicker = setInterval(tickRail, 1000);
  if (!pending.size && railTicker) { clearInterval(railTicker); railTicker = null; }
  revealActiveRow();
  clear(railArchives);
  for (const source of railSources) {
    const row = el('button', 'rail-row' + (activeArchive === source.id ? ' active' : ''));
    row.type = 'button';
    row.appendChild(el('div', 'rail-title', source.source_account));
    row.appendChild(el('div', 'rail-meta',
      source.conversations + ' conversations · ' + (source.sealed ? 'sealed' : 'live')));
    row.addEventListener('click', () => loadArchiveConversations(source));
    railArchives.appendChild(row);
  }
}

// On the narrow layout the strip scrolls sideways; "you are here" has
// to be on screen after a switch. Only the strip moves, never the page.
function revealActiveRow() {
  const active = railConversations.querySelector('.rail-row.active');
  const strip = active ? active.closest('.rail-section') : null;
  if (active && strip && strip.scrollWidth > strip.clientWidth) {
    const r = active.getBoundingClientRect();
    const s = strip.getBoundingClientRect();
    if (r.left < s.left + 8 || r.right > s.right - 8) strip.scrollLeft += (r.left - s.left) - 8;
  }
  for (const section of rail.querySelectorAll('.rail-section')) updateStripFade(section);
}
// A strip with more tabs past its right edge fades out there, so the
// edge reads as "more", not as the end.
function updateStripFade(strip) {
  strip.classList.toggle('fade-right', strip.scrollWidth - strip.clientWidth - strip.scrollLeft > 4);
}
for (const section of rail.querySelectorAll('.rail-section')) {
  section.addEventListener('scroll', () => updateStripFade(section), { passive: true });
}

// --- Switching conversations ---
function startDraft() {
  draft = mintKey();
  openConversation(draft);
}
// The URL carries the key, so a conversation can be reopened by link.
// Navigation goes through the hash; the hashchange handler switches.
function openConversation(key) {
  activeArchive = null;
  if (conversationFromHash() !== key) { location.hash = 'c=' + key; return; }
  switchTo(key);
}
function switchTo(key) {
  // Leaving mid-turn abandons the stream, not the turn: the gateway
  // runs it to its end and writes its rows, and the rail row says
  // "turn open" from the list until then. No stream is held for a
  // conversation not being viewed.
  if (currentTurn && currentTurn.key !== key) abortTurn();
  // Leaving a draft discards it: nothing was recorded, so nothing is lost.
  if (draft && draft !== key) draft = null;
  currentKey = key;
  switchedAt = Date.now();
  resumed = null;
  elsewhereTurn = null;
  stopElsewherePolling();
  approvalCurrent = null;
  approvalQueue.length = 0;
  liveAssistant = null;
  liveReceived = '';
  hideNotice();
  setTurn(null);
  unlockComposer();
  loadTranscript(currentLogId()).then(() => loadStatus());
}
function abortTurn() {
  if (currentTurn) currentTurn.controller.abort();
  currentTurn = null;
  turnOpen = false;
  stopEventPolling();
}

// --- A turn open in another tab (state 19) ---
// Learned from the gateway: the chat route's "turn open" reply, or the
// list row's turn_open. Aged from the gateway's claim, not from now.
function setElsewhereTurn(ageSeconds) {
  elsewhereTurn = { age: Number(ageSeconds) || 0, seenAt: Date.now() };
  renderElsewhereTurn();
  renderRail();
  startElsewherePolling();
}
function renderElsewhereTurn() {
  if (!elsewhereTurn) return;
  lockComposer(ELSEWHERE_PLACEHOLDER);
  const age = elsewhereTurn.age + Math.floor((Date.now() - elsewhereTurn.seenAt) / 1000);
  setTurn('turn open · elsewhere · ' + ageWords(age));
  // Text already in the composer stays there. Nothing sends it: the
  // line says only that.
  if (input.value.trim()) showNotice(null, 'held — not sent', null);
}
// The list is the gateway's claim; the latest fetch wins, and a list
// fetched before the last switch says nothing about this conversation.
function syncElsewhereTurn() {
  if (turnOpen || railRowsAt < switchedAt) return;
  const row = railRows.find((r) => keyOf(r.log_id) === currentKey);
  if (row && row.turn_open === true) {
    const first = !elsewhereTurn;
    elsewhereTurn = { age: Number(row.turn_open_age_seconds) || 0, seenAt: Date.now() };
    renderElsewhereTurn();
    if (first) { renderRail(); startElsewherePolling(); }
  }
}
function startElsewherePolling() {
  if (elsewhereTimer) return;
  startEventPolling();
  elsewhereTimer = setInterval(checkElsewhereTurn, ELSEWHERE_POLL_MS);
}
function stopElsewherePolling() {
  if (elsewhereTimer) { clearInterval(elsewhereTimer); elsewhereTimer = null; }
  if (!turnOpen) stopEventPolling();
}
async function checkElsewhereTurn() {
  const key = currentKey;
  let rows;
  try {
    const res = await fetch('/api/sessions');
    if (!res.ok) return;
    rows = await res.json();
  } catch (e) { return; }
  if (key !== currentKey || !Array.isArray(rows)) return;
  railRows = rows.filter((r) => r && r.channel === 'webchat');
  railRowsAt = Date.now();
  const row = railRows.find((r) => keyOf(r.log_id) === key);
  if (row && row.turn_open === true) {
    elsewhereTurn = { age: Number(row.turn_open_age_seconds) || 0, seenAt: Date.now() };
    renderElsewhereTurn();
    renderRail();
    return;
  }
  // The turn ended. What it produced is in the record; draw it from there.
  elsewhereTurn = null;
  stopElsewherePolling();
  setTurn(null);
  hideNotice();
  unlockComposer();
  loadTranscript(currentLogId());
}

// --- An approval waiting in another conversation (state 18) ---
// One line in the thread that names the conversation and links to it.
// It carries no decision: the card is drawn only where it was raised.
function renderElsewhereLine() {
  const existing = document.getElementById('elsewhere-line');
  const elsewhere = approvals && Array.isArray(approvals.elsewhere) ? approvals.elsewhere : [];
  if (!elsewhere.length || activeArchive !== null) { if (existing) existing.remove(); return; }
  const target = elsewhere[0];
  const line = el('div', 'elsewhere');
  line.id = 'elsewhere-line';
  line.setAttribute('role', 'status');
  line.appendChild(el('span', 'glyph', '○'));
  const text = el('span');
  const tier = tierWord(target.requested_tier);
  text.appendChild(document.createTextNode((tier ? 'A ' + tier : 'An') + ' approval is waiting in "'));
  text.appendChild(el('span', 'title', titleFor(target.conversation)));
  text.appendChild(document.createTextNode('". It can only be decided there.'));
  line.appendChild(text);
  const link = el('button', 'link', 'open it →');
  link.type = 'button';
  link.addEventListener('click', () => openConversation(target.conversation));
  line.appendChild(link);
  if (thread.querySelector('.empty-state')) line.classList.add('under-empty');
  if (existing) existing.replaceWith(line);
  else thread.appendChild(line);
}

// --- Imported archives: read-only views ---
// Every value out of an archive reaches the DOM through setText or el.
// That text was written by whoever got a message into the imported
// account, which may be nobody the operator knows.
async function loadArchiveConversations(source) {
  let rows;
  try {
    const res = await fetch('/api/imported/sources/' + encodeURIComponent(source.id) + '/conversations');
    if (!res.ok) return;
    rows = await res.json();
  } catch (e) { return; }
  activeArchive = source.id;
  setReadOnly(ARCHIVE_NOTICE);
  loadRail();
  clear(thread);
  const head = el('div', 'archive-head', source.source_account);
  head.appendChild(el('span', 'meta',
    'imported archive · ' + source.conversations + ' conversations · ' + source.projects + ' projects · ' + (source.sealed ? 'sealed' : 'live')));
  thread.appendChild(head);
  thread.appendChild(el('div', 'archive-note',
    'A stored record, shown read-only. Text was written by whoever got a message into this account.'));
  if (!rows.length) {
    thread.appendChild(el('div', 'archive-note', 'This archive holds no conversations.'));
    return;
  }
  for (const row of rows) {
    const item = el('button', 'archive-row');
    item.type = 'button';
    // An untitled conversation is a real shape in an archive, so the
    // uuid stands in rather than an empty line.
    item.appendChild(el('span', null, row.title || 'Untitled · ' + String(row.uuid).slice(0, 8)));
    item.appendChild(el('span', 'meta', row.message_count + ' messages · ' + fmtDate(row.updated_at)));
    item.addEventListener('click', () => loadImportedConversation(source, row.uuid));
    thread.appendChild(item);
  }
  conversation.scrollTop = 0;
}

async function loadImportedConversation(source, uuid) {
  let detail;
  try {
    const res = await fetch('/api/imported/sources/' + encodeURIComponent(source.id) +
      '/conversations/' + encodeURIComponent(uuid));
    if (!res.ok) return;
    detail = await res.json();
  } catch (e) { return; }
  setReadOnly(ARCHIVE_NOTICE);
  clear(thread);
  if (!detail) {
    thread.appendChild(el('div', 'archive-note', 'That conversation is not in the store.'));
    return;
  }
  thread.appendChild(el('div', 'archive-head', detail.title || 'Untitled · ' + String(detail.uuid).slice(0, 8)));
  if (detail.summary) thread.appendChild(el('div', 'archive-note', detail.summary));
  const back = el('button', 'link', '← back to this archive');
  back.type = 'button';
  back.addEventListener('click', () => loadArchiveConversations(source));
  thread.appendChild(back);

  for (const message of detail.messages) {
    const box = el('div', 'archive-msg');
    box.appendChild(el('div', 'sender', message.sender));
    // A message the store holds no text for gets a label, not an empty
    // span: the claim is about what is stored, which is all this page
    // can check.
    if (String(message.text || '').trim() === '') {
      box.appendChild(el('div', 'text empty', 'no text stored for this message'));
    } else {
      box.appendChild(el('div', 'text', message.text));
    }
    thread.appendChild(box);
    for (const attachment of message.attachments || []) {
      const att = el('div', 'archive-attachment');
      att.appendChild(el('div', 'meta', 'attachment: ' + (attachment.file_name || 'unnamed')));
      att.appendChild(el('div', 'text', attachment.text));
      thread.appendChild(att);
    }
    // The view is a projection and says so.
    if (message.unrendered_blocks > 0) {
      thread.appendChild(el('div', 'archive-note',
        message.unrendered_blocks + ' stored content blocks are not shown here. ' +
        'This view renders the message text and its attachments.'));
    }
  }
  conversation.scrollTop = 0;
}

// --- Status: the posture strip, the banners, the About panel ---
// Everything here comes from one snapshot the gateway builds from
// files, config and in-memory lists. A null is a value the gateway
// does not hold. It is omitted from the strip and named as unknown
// inside the panel; it is never drawn as zero, false, or green.
const STATUS_POLL_MS = 15000;
let status = null;
const HATCH_COPY = {
  WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG: 'org config would be accepted unsigned.',
  WIRKEN_ALLOW_UNSIGNED_SKILLS: 'unsigned skills would load unverified.',
  WIRKEN_ALLOW_UNSIGNED_MCP: 'unsigned MCP entries would spawn.',
  WIRKEN_ALLOW_STALE_ORG_CONFIG: 'a stale org config bundle would be accepted.',
  WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN: 'the chat route accepts requests without an Origin header.',
  WIRKEN_ALLOW_UNREGISTERED_HOOKS: 'unregistered hook processes are admitted with veto power.',
};
// The variable is read from the gateway's own environment, so nothing
// outside the process changes it.
const HATCH_CLEARS = ' Clears when the gateway restarts without it.';
function usd(micros) { return '$' + (Number(micros) / 1e6).toFixed(2); }
function isSet(v) { return v !== null && v !== undefined; }
function unknownNode(text) { return el('span', 'unknown', text || 'unknown'); }
function valueOrUnknown(v, text) { return isSet(v) ? el('span', null, text) : unknownNode(); }

let approvals = null;
async function loadStatus() {
  let snapshot;
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    snapshot = await res.json();
  } catch (e) { return; }
  status = snapshot;
  const key = currentKey;
  try {
    const res = await fetch('/api/approvals?c=' + encodeURIComponent(key));
    if (res.ok) approvals = await res.json();
  } catch (e) { /* the badge and the restore wait for the next poll */ }
  if (key !== currentKey) return;
  renderStatus();
  renderRail();
  renderElsewhereLine();
  syncElsewhereTurn();
  restorePendingCards();
}
// A pending decision outlives the stream that carried it: after a
// reload the card is drawn again from the queue, aged from when the
// gate asked, not from now. Its decision goes to the same route and
// is settled from that route's reply, since no stream will ack it.
function restorePendingCards() {
  if (!approvals || !Array.isArray(approvals.mine)) return;
  for (const req of approvals.mine) {
    // Only this conversation's: a card is drawn where it was raised.
    if (keyOf(req.agent_id) !== currentKey) continue;
    if (document.getElementById('approval-' + req.request_id)) continue;
    if (approvalCurrent && approvalCurrent.request_id === req.request_id) continue;
    renderApproval(req);
  }
}
function renderStatus() {
  if (!status) return;
  renderBanners();
  renderStatusValues();
  if (!about.hidden) renderAbout();
  if (status.audit && status.audit.writer_halted && !halted) setHalted();
}
function hatchBanner(name, copy) {
  const b = el('div', 'banner banner-hatch');
  b.setAttribute('role', 'status');
  b.appendChild(el('span', 'chip chip-outline', 'Escape hatch engaged'));
  const text = el('span');
  if (name) text.appendChild(el('code', null, name + '=1'));
  text.appendChild(document.createTextNode((name ? ' — ' : '') + copy));
  b.appendChild(text);
  return b;
}
function renderBanners() {
  clear(banners);
  const h = status.escape_hatches || {};
  for (const name of Object.keys(HATCH_COPY)) {
    if (!h[name]) continue;
    // With a skill registry root pinned the loader is strict and the
    // flag does nothing; a banner would announce a hatch that is shut.
    if (name === 'WIRKEN_ALLOW_UNSIGNED_SKILLS' && h.skill_registry_root_pinned) continue;
    banners.appendChild(hatchBanner(name, HATCH_COPY[name] + HATCH_CLEARS));
  }
  if (h.sandbox_mode_off) {
    banners.appendChild(hatchBanner(null,
      'sandbox.json mode is off: exec runs on the host as the gateway user. ' +
      'Set in sandbox.json; clears when the file changes and the gateway restarts.'));
  }
}
function renderStatusValues() {
  clear(statusValues);
  const audit = status.audit || {};
  const alarms = Array.isArray(audit.alarms) ? audit.alarms : [];
  if (alarms.length) {
    // The strip becomes the alarm. It stays until the record is
    // acknowledged from the CLI; the page cannot clear it.
    const r = alarms[0];
    const parts = ['Tamper alarm', r.alarm_type];
    if (r.session_id) parts.push('session ' + r.session_id);
    if (isSet(r.seq)) parts.push('row ' + r.seq);
    if (alarms.length > 1) parts.push('+' + (alarms.length - 1) + ' more');
    parts.push('acknowledge with wirken audit acknowledge --all');
    statusValues.appendChild(el('span', 'alarm', parts.join(' · ')));
    statusValues.hidden = false;
    return;
  }
  // Each item carries its own separator so an item hidden at a narrow
  // width takes its separator with it.
  const items = [];
  const agent = status.agent || {};
  const ag = el('span', null, agent.id || 'default');
  if (agent.model) ag.appendChild(el('span', 'yield-3', ' · ' + agent.model));
  items.push({ node: ag, yield: 0 });
  const sandbox = status.sandbox || {};
  if (sandbox.mode) {
    const sb = el('span', null, sandbox.mode + ' ');
    sb.appendChild(el('span', 'hedge', '(configured)'));
    items.push({ node: sb, yield: 2 });
  }
  const egress = status.egress || {};
  if (egress.mode) items.push({ node: el('span', null, egress.mode === 'none' ? 'no egress' : 'egress: ' + egress.mode), yield: 1 });
  const budget = status.budget || {};
  if (budget.mode && budget.mode !== 'off' && isSet(budget.remaining_usd_micros)) {
    const b = el('span', 'mono', usd(budget.remaining_usd_micros) + ' left ' +
      (budget.window === 'day' ? 'today' : 'this ' + budget.window));
    b.title = 'agent budget · all channels';
    items.push({ node: b, yield: 0 });
  }
  // An approval waiting in another conversation of this page's own.
  // Absent at zero; never "0 awaiting you elsewhere".
  const elsewhere = approvals && Array.isArray(approvals.elsewhere) ? approvals.elsewhere : [];
  if (elsewhere.length > 0) {
    const chip = el('button', 'chip chip-outline', elsewhere.length + ' awaiting you elsewhere');
    chip.type = 'button';
    chip.title = 'Open the conversation holding the approval';
    chip.addEventListener('click', () => openConversation(elsewhere[0].conversation));
    items.push({ node: chip, yield: 0 });
  }
  const others = approvals && approvals.other_channels ? approvals.other_channels : { count: 0, by_channel: {} };
  if (others.count > 0) {
    const channels = Object.keys(others.by_channel || {});
    const where = channels.length === 1 ? channels[0] : 'other channels';
    const badge = el('span', 'chip chip-neutral', others.count + ' on ' + where);
    badge.title = 'pending approvals on other channels · decide there';
    items.push({ node: badge, yield: 0 });
  }
  const dot = el('button', 'writer-dot' + (audit.writer_halted ? ' halted' : ''));
  dot.type = 'button';
  dot.title = (audit.writer_halted ? 'Audit writer halted' : 'Audit writer live') + ' · open Record';
  dot.setAttribute('aria-label', dot.title);
  dot.setAttribute('aria-haspopup', 'dialog');
  dot.addEventListener('click', () => setRecordOpen(record.hidden));
  items.push({ node: dot, yield: 0 });
  items.forEach((item, i) => {
    const wrap = el('span', 'item' + (item.yield ? ' yield-' + item.yield : ''));
    if (i) wrap.appendChild(el('span', 'sep', '· '));
    wrap.appendChild(item.node);
    statusValues.appendChild(wrap);
  });
  statusValues.hidden = false;
  fixSeparators();
}
// A separator sits between two items on one row. When the strip wraps,
// the first item of the new row drops its separator: measured after
// layout, not guessed from a width.
function fixSeparators() {
  let rowTop = null;
  for (const wrap of statusValues.querySelectorAll('.item')) {
    if (wrap.offsetParent === null) continue;
    const sep = wrap.querySelector('.sep');
    if (sep) sep.hidden = rowTop !== null && wrap.offsetTop !== rowTop;
    rowTop = wrap.offsetTop;
  }
}
window.addEventListener('resize', () => requestAnimationFrame(() => { fixSeparators(); revealActiveRow(); }));
function kvRow(grid, key, valueNode) {
  grid.appendChild(el('span', 'k', key));
  const v = el('span', 'v');
  v.appendChild(valueNode);
  grid.appendChild(v);
}
function renderAbout() {
  clear(about);
  const gw = status.gateway || {};
  const head = el('h2', null, 'About');
  head.appendChild(el('span', 'meta', 'wirken ' + (gw.version || '') + ' · loopback only'));
  about.appendChild(head);
  const grid = el('div', 'kv');
  // Every value the strip may omit is named here, unknown included.
  const agent = status.agent || {};
  if (agent.model) {
    const v = el('span', null, (agent.id || 'default') + ' · ' + agent.model);
    if (agent.source) v.appendChild(el('span', 'hedge', ' · from ' + agent.source));
    kvRow(grid, 'agent', v);
  } else {
    const v = el('span', null, (agent.id || 'default') + ' · model ');
    v.appendChild(unknownNode());
    kvRow(grid, 'agent', v);
  }
  const budget = status.budget || {};
  if (budget.mode === 'off') {
    kvRow(grid, 'budget', el('span', null, 'off'));
  } else if (budget.mode && isSet(budget.ceiling_usd_micros)) {
    kvRow(grid, 'budget', el('span', null, usd(budget.ceiling_usd_micros) + ' / ' + budget.window + ' · agent, all channels'));
  } else {
    kvRow(grid, 'budget', unknownNode());
  }
  const sandbox = status.sandbox || {};
  if (sandbox.mode) {
    const v = el('span', null, sandbox.mode + (sandbox.runtime ? ' · ' + sandbox.runtime : '') + ' · configured, reachability ');
    v.appendChild(unknownNode());
    kvRow(grid, 'sandbox', v);
  } else {
    kvRow(grid, 'sandbox', unknownNode());
  }
  const adapters = Array.isArray(status.adapters) ? status.adapters : [];
  if (adapters.length) {
    const v = el('span');
    for (const a of adapters) {
      const row = el('span', 'row', a.channel + ' ');
      row.appendChild(el('code', null, a.pubkey_fingerprint || ''));
      row.appendChild(document.createTextNode(a.connected ? ' · connected' : ' · not connected'));
      v.appendChild(row);
    }
    kvRow(grid, 'adapters', v);
  } else {
    kvRow(grid, 'adapters', el('span', null, 'none registered'));
  }
  const egress = status.egress || {};
  kvRow(grid, 'egress', egress.mode
    ? el('span', null, egress.mode === 'none' ? 'none' : egress.mode + (egress.domains && egress.domains.length ? ' · ' + egress.domains.join(', ') : ''))
    : unknownNode());
  renderCapabilityRows(grid);
  renderVaultRows(grid);
  const siem = status.siem || {};
  if (siem.configured) {
    // The target only: where it ships to is an endpoint, and endpoints
    // stay in the config file.
    const v = el('span', null, siem.target + ' · last ship ');
    v.appendChild(unknownNode());
    kvRow(grid, 'SIEM', v);
  } else {
    kvRow(grid, 'SIEM', el('span', null, 'not configured'));
  }
  const org = status.org || {};
  if (org.configured) {
    const v = el('span', null, 'verifies against ');
    v.appendChild(org.pubkey_fingerprint ? el('code', null, org.pubkey_fingerprint) : unknownNode('no key pinned'));
    v.appendChild(document.createTextNode(' · ' + (org.applied || 'unknown')));
    kvRow(grid, 'org config', v);
  } else {
    kvRow(grid, 'org config', el('span', null, 'not configured'));
  }
  const audit = status.audit || {};
  const av = el('span', null, 'signing key ');
  av.appendChild(audit.signing_pubkey_fingerprint ? el('code', null, audit.signing_pubkey_fingerprint) : unknownNode('none'));
  av.appendChild(document.createTextNode(' · '));
  av.appendChild(valueOrUnknown(audit.sessions_total, audit.sessions_total + ' sessions'));
  av.appendChild(document.createTextNode(' · '));
  av.appendChild(Array.isArray(audit.alarms) ? el('span', null, audit.alarms.length + ' alarms on disk') : unknownNode());
  kvRow(grid, 'audit', av);
  kvRow(grid, 'threats', el('span', null, 'scanned on inbound messages'));
  about.appendChild(grid);
  about.appendChild(el('div', 'foot', 'Blurple = the gateway does not know. Named here, omitted from the default screen. Underlined = opens here.'));
}
// Capabilities and the vault are fetched when About opens, never on
// the default screen and never on the status poll: the capabilities
// route wakes the agent, and the panel is the only place these are
// drawn.
let capabilities = null;
let capabilitiesState = 'idle';
let vault = null;
let vaultState = 'idle';
async function fetchJson(path) {
  try {
    const res = await fetch(path);
    if (!res.ok) return null;
    return await res.json();
  } catch (e) { return null; }
}
async function loadAboutExtras() {
  capabilitiesState = 'fetching';
  vaultState = 'fetching';
  const [c, v] = await Promise.all([fetchJson('/api/capabilities'), fetchJson('/api/credentials')]);
  capabilities = c;
  capabilitiesState = c ? 'loaded' : 'failed';
  vault = v;
  vaultState = v ? 'loaded' : 'failed';
  if (!about.hidden) renderAbout();
}
function tierWord(tier) {
  if (tier === 'tier1') return 'Tier 1';
  if (tier === 'tier2') return 'Tier 2';
  if (tier === 'tier3') return 'Tier 3';
  return null;
}
// A date, never a countdown: the page's clock is not the gate's.
function ymdhm(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  const p = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}
function disclosure(summaryNode, list) {
  const d = el('details');
  const s = el('summary');
  s.appendChild(summaryNode);
  d.appendChild(s);
  d.appendChild(list);
  return d;
}
function capRow(list, nameText, rightText, hedgeText) {
  const row = el('span', 'cap');
  row.appendChild(el('code', null, nameText));
  row.appendChild(el('span', null, rightText));
  list.appendChild(row);
  if (hedgeText) list.appendChild(el('span', 'hedge', hedgeText));
}
function pendingNode(state) {
  if (state === 'fetching') return el('span', 'hedge', 'fetching');
  return unknownNode();
}
function busyOrUnknown(c) {
  if (c.busy) return unknownNode('busy · a turn holds the agent');
  if (c.available === false) return unknownNode('agent did not wake');
  return unknownNode();
}
function countWord(v) {
  if (v === '*') return 'any';
  if (Array.isArray(v)) return v.length ? String(v.length) : 'none';
  return 'unknown';
}
function renderCapabilityRows(grid) {
  if (capabilitiesState !== 'loaded') {
    kvRow(grid, 'tools', pendingNode(capabilitiesState));
    kvRow(grid, 'grants', pendingNode(capabilitiesState));
    kvRow(grid, 'skills', pendingNode(capabilitiesState));
    return;
  }
  const c = capabilities;
  // The agent-held sections are null while a turn holds the lock; the
  // grants come from the store and are drawn regardless.
  if (Array.isArray(c.tools)) {
    const byArg = c.tools.filter((t) => t.tier_depends_on_arguments).length;
    const list = el('span', 'cap-list');
    for (const t of c.tools) {
      // A tool whose tier the gate reads off the arguments is flagged,
      // not given the tier of one imagined call.
      let right = t.tier_depends_on_arguments ? 'by argument' : (tierWord(t.tier) || 'no tier');
      if (t.org_policy === 'blocked') right += ' · blocked by org';
      else if (t.org_policy === 'not allowed') right += ' · not allowed by org';
      capRow(list, t.name, right, t.tier_rule);
    }
    const summary = el('span', null, c.tools.length + ' offered' + (byArg ? ' · ' + byArg + ' decided per call' : ''));
    kvRow(grid, 'tools', disclosure(summary, list));
  } else {
    kvRow(grid, 'tools', busyOrUnknown(c));
  }
  if (Array.isArray(c.grants)) {
    if (c.grants.length) {
      const list = el('span', 'cap-list');
      for (const g of c.grants) {
        capRow(list, g.action_key, 'until ' + ymdhm(g.expires_at), 'by ' + (g.approved_by || 'unknown') + ' · ' + ymdhm(g.approved_at));
      }
      kvRow(grid, 'grants', disclosure(el('span', null, c.grants.length + ' live'), list));
    } else {
      kvRow(grid, 'grants', el('span', null, 'none live'));
    }
  } else {
    kvRow(grid, 'grants', unknownNode());
  }
  if (Array.isArray(c.skills)) {
    if (c.skills.length) {
      const list = el('span', 'cap-list');
      for (const s of c.skills) {
        // Three words, never a tick: signed carries who signed it.
        let right = s.signature;
        if (s.signature === 'signed' && s.signer) right += ' · ' + String(s.signer).slice(0, 16);
        if (s.available === false) right += ' · unavailable';
        const p = s.permissions || {};
        const eg = p.egress || {};
        const hedge = 'tools ' + countWord(p.tools) + ' · egress ' + (eg.mode || 'unknown') + ' · credentials ' + countWord(p.credentials) + (s.model_invocable === false ? ' · not model-invocable' : '');
        capRow(list, s.name, right, hedge);
      }
      kvRow(grid, 'skills', disclosure(el('span', null, c.skills.length + ' loaded'), list));
    } else {
      kvRow(grid, 'skills', el('span', null, 'none loaded'));
    }
  } else {
    kvRow(grid, 'skills', busyOrUnknown(c));
  }
}
function renderVaultRows(grid) {
  if (vaultState !== 'loaded') {
    kvRow(grid, 'vault', pendingNode(vaultState));
    kvRow(grid, 'connectors', pendingNode(vaultState));
    return;
  }
  const v = vault;
  if (Array.isArray(v.credentials)) {
    if (v.credentials.length) {
      // Names only: the store exposes no dates yet, and the row says so.
      const list = el('span', 'cap-list');
      for (const c of v.credentials) capRow(list, c.name, '');
      const summary = el('span', null, v.credentials.length + ' credentials · dates ');
      summary.appendChild(unknownNode());
      kvRow(grid, 'vault', disclosure(summary, list));
    } else {
      kvRow(grid, 'vault', el('span', null, 'none stored'));
    }
  } else {
    kvRow(grid, 'vault', unknownNode());
  }
  if (Array.isArray(v.connectors)) {
    if (v.connectors.length) {
      const list = el('span', 'cap-list');
      for (const c of v.connectors) {
        // Name and transport. What it runs or where it connects stays
        // in the config file.
        let right = c.transport + ' · ' + (c.signed ? 'signed' : 'unsigned');
        const t = c.trust;
        if (t && t.verified === true) right += ' · admitted';
        else if (t && t.verified === false) right += ' · refused';
        const parts = ['auth ' + (c.auth || 'none')];
        if (c.provider) parts.push('via ' + c.provider);
        if (Array.isArray(c.credentials) && c.credentials.length) parts.push('uses ' + c.credentials.join(', '));
        capRow(list, c.name, right, parts.join(' · '));
      }
      kvRow(grid, 'connectors', disclosure(el('span', null, v.connectors.length + ' MCP'), list));
    } else {
      kvRow(grid, 'connectors', el('span', null, 'none configured'));
    }
  } else {
    kvRow(grid, 'connectors', unknownNode());
  }
}
function setAboutOpen(open) {
  if (open && !status) return;
  if (open) record.hidden = true;
  about.hidden = !open;
  wordmark.setAttribute('aria-expanded', open ? 'true' : 'false');
  // The fetch is started first so the first draw says "fetching", not
  // unknown, for the rows it is about to fill.
  if (open) { loadAboutExtras(); renderAbout(); }
}
wordmark.addEventListener('click', () => setAboutOpen(about.hidden));
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (!about.hidden) { setAboutOpen(false); wordmark.focus(); }
  if (!record.hidden) setRecordOpen(false);
});
document.addEventListener('click', (e) => {
  // A click whose target was re-rendered away mid-click (the verify
  // button replaces its box) is not a click outside.
  if (!e.target.isConnected) return;
  if (!about.hidden && !about.contains(e.target) && !wordmark.contains(e.target)) setAboutOpen(false);
  if (!record.hidden && !record.contains(e.target) && !(e.target.closest && e.target.closest('.writer-dot'))) setRecordOpen(false);
});

// --- Wiring ---
composer.addEventListener('submit', (e) => { e.preventDefault(); send(); });
input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); }
});
input.addEventListener('input', () => {
  input.style.height = 'auto';
  input.style.height = Math.min(160, input.scrollHeight) + 'px';
});
// Restore the conversation on load so a refresh keeps the visible
// history. loadTranscript's finally also draws the rail.
// History first, then the status poll that may restore a pending
// card: the card's command joins from a call row, and that row has to
// be on screen before the join looks for it.
currentKey = conversationFromHash() || LEGACY_CONVERSATION;
window.addEventListener('hashchange', () => switchTo(conversationFromHash() || LEGACY_CONVERSATION));
railNew.addEventListener('click', startDraft);
loadTranscript(currentLogId()).then(() => {
  loadStatus();
  setInterval(loadStatus, STATUS_POLL_MS);
});
input.focus();
</script>
</body>
</html>
"#;

/// Serve the webchat UI on a TCP port.
/// Minimal HTTP server — no framework dependency.
///
/// One construction site (`run.rs`) hands over every shared handle the
/// routes read; bundling them further would only move the list.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    port: u16,
    factory: Arc<AgentFactory>,
    audit: Arc<AuditWriter>,
    sessions: Arc<Mutex<SessionStore>>,
    pending_approvals: Arc<PendingApprovalQueue>,
    sse_registry: Arc<SseApprovalRegistry>,
    status_inputs: StatusInputs,
    detector: Arc<InjectionDetector>,
) -> Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    tracing::info!("WebChat listening on http://127.0.0.1:{port}");

    // Set once the audit writer refuses a row. The writer never
    // recovers inside a process (its flush loop has exited), so the
    // flag only ever goes from false to true. The status route reports
    // it; the chat route refuses turns while it is set.
    let writer_halted = Arc::new(AtomicBool::new(false));

    // Chain verification is two full scans of the audit log with a hash
    // per row, run on the blocking pool. One at a time per process, and
    // no more often than the control-plane limit: a browser must not be
    // able to keep the gateway verifying.
    let verify_limit = Arc::new(ControlPlaneRateLimiter::new(
        super::config().control_plane_rate_limit.max(1),
    ));
    let verify_running = Arc::new(AtomicBool::new(false));
    let open_turns = Arc::new(OpenTurns::default());

    // Per-process rate limiter on the chat POST path. GCRA from
    // `wirken-gateway::rate_limit`; lock-free hot path. See
    // `WEBCHAT_MAX_POSTS_PER_MIN` for the cap rationale.
    let rate_limit = Arc::new(ControlPlaneRateLimiter::new(WEBCHAT_MAX_POSTS_PER_MIN));

    loop {
        let (mut stream, _) = listener.accept().await?;
        let factory = factory.clone();
        let audit = audit.clone();
        let sessions = sessions.clone();
        let rate_limit = rate_limit.clone();
        let pending_approvals = pending_approvals.clone();
        let sse_registry = sse_registry.clone();
        let status_inputs = status_inputs.clone();
        let detector = detector.clone();
        let writer_halted = writer_halted.clone();
        let verify_limit = verify_limit.clone();
        let verify_running = verify_running.clone();
        let open_turns = open_turns.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };

            let request = String::from_utf8_lossy(&buf[..n]);
            let first_line = request.lines().next().unwrap_or("");

            if first_line.starts_with("GET / ") || first_line.starts_with("GET /index.html") {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    HTML.len(),
                    HTML
                );
                let _ = stream.write_all(response.as_bytes()).await;
            } else if let Some((session_id, after)) = parse_session_events_path(first_line) {
                // GET /api/sessions/{id}/events[?after=N] — the session
                // log projected to what the page draws. Webchat
                // sessions only: this route exposes far more per row
                // than the transcript does, and other channels' rows
                // are theirs.
                if let Some(resp) = api_preflight(&request, port, false) {
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                if !events_route_allowed(&session_id) {
                    let _ = stream
                        .write_all(
                            json_forbidden("events are served for webchat sessions only")
                                .as_bytes(),
                        )
                        .await;
                    return;
                }
                let cfg = super::config();
                let body = session_events(&cfg, &session_id, after);
                let body = serde_json::to_string(&body).unwrap_or_else(|_| "{}".into());
                let _ = stream.write_all(json_ok(&body).as_bytes()).await;
            } else if let Some(session_id) = parse_session_path(first_line) {
                // GET /api/sessions/{id} — transcript for one session,
                // rendered into the messages pane. Safe read: the Host
                // check closes DNS-rebinding, and Origin is validated
                // only when the browser sends one (it omits it on a
                // same-origin GET).
                if let Some(resp) = api_preflight(&request, port, false) {
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                let cfg = super::config();
                let body = match super::session::session_transcript(&cfg, &session_id) {
                    Ok(turns) => serde_json::to_string(&turns).unwrap_or_else(|_| "[]".into()),
                    Err(_) => "[]".to_string(),
                };
                let _ = stream.write_all(json_ok(&body).as_bytes()).await;
            } else if let Some(route) = parse_imported_path(first_line) {
                // Imported-archive reads. Same posture as the other
                // read routes: Host is checked on every route, which
                // is what closes DNS rebinding, and a present Origin
                // is validated even though a browser omits it on a
                // same-origin GET.
                if let Some(resp) = api_preflight(&request, port, false) {
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                let cfg = super::config();
                let body = super::import::read_route_json(&cfg, &route);
                let _ = stream.write_all(json_ok(&body).as_bytes()).await;
            } else if first_line.starts_with("GET /api/approvals ") {
                // GET /api/approvals — this browser's pending decisions
                // with their trigger text, and a count of everyone
                // else's. Other channels' request ids and messages stay
                // on their channel: an id is the only thing standing
                // between a webchat tab and a Telegram user's approval.
                if let Some(resp) = api_preflight(&request, port, false) {
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                let conversation = match query_param(first_line, "c")
                    .map(|c| conversation_key(Some(c)))
                {
                    None => None,
                    Some(Ok(c)) => Some(c),
                    Some(Err(_)) => {
                        let resp = r#"{"error":"bad conversation key"}"#;
                        let response = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp.len(),
                            resp
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                };
                let body = approvals_snapshot_for(&pending_approvals, conversation.as_deref());
                let body = serde_json::to_string(&body).unwrap_or_else(|_| "{}".into());
                let _ = stream.write_all(json_ok(&body).as_bytes()).await;
            } else if first_line.starts_with("GET /api/capabilities ") {
                // GET /api/capabilities — what the default agent is
                // offered and gated by: tools with their tier rule,
                // persisted grants, skills with their permissions and
                // signature status. Wakes the agent and holds its lock
                // briefly; a turn in flight gets "busy", never a wait.
                if let Some(resp) = api_preflight(&request, port, false) {
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                let conversation = match conversation_key(query_param(first_line, "c")) {
                    Ok(c) => c,
                    Err(_) => {
                        let resp = r#"{"error":"bad conversation key"}"#;
                        let response = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp.len(),
                            resp
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                };
                let cfg = super::config();
                let body = capabilities_snapshot(&cfg, &factory, &conversation).await;
                let body = serde_json::to_string(&body).unwrap_or_else(|_| "{}".into());
                let _ = stream.write_all(json_ok(&body).as_bytes()).await;
            } else if first_line.starts_with("GET /api/credentials ") {
                // GET /api/credentials — credential names without the
                // vault key, and MCP connectors reduced to name,
                // transport, auth kind and credential names.
                if let Some(resp) = api_preflight(&request, port, false) {
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                let cfg = super::config();
                let body = credentials_snapshot(&cfg);
                let body = serde_json::to_string(&body).unwrap_or_else(|_| "{}".into());
                let _ = stream.write_all(json_ok(&body).as_bytes()).await;
            } else if first_line.starts_with("GET /api/status ") {
                // GET /api/status — one snapshot of the gateway's
                // posture for the status line, the banners and the
                // About panel. Safe read: Host checked, Origin
                // validated only when present.
                if let Some(resp) = api_preflight(&request, port, false) {
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                let cfg = super::config();
                let snapshot = status_snapshot(
                    &cfg,
                    port,
                    &status_inputs,
                    writer_halted.load(Ordering::Relaxed),
                )
                .await;
                let body = serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".into());
                let _ = stream.write_all(json_ok(&body).as_bytes()).await;
            } else if first_line.starts_with("GET /api/sessions ") {
                // GET /api/sessions — active-session list backing the
                // sidebar. Safe read, same Host-only posture as the
                // transcript route above.
                if let Some(resp) = api_preflight(&request, port, false) {
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                let cfg = super::config();
                let body = match super::session::active_session_rows(&cfg, None) {
                    Ok(rows) => serde_json::to_string(&conversation_rows(&cfg, rows, &open_turns))
                        .unwrap_or_else(|_| "[]".into()),
                    Err(_) => "[]".to_string(),
                };
                let _ = stream.write_all(json_ok(&body).as_bytes()).await;
            } else if first_line.starts_with("POST /api/chat") {
                // Rate-limit before any other work. A spinning client
                // (runaway browser tab, naive CSRF, scripted abuse)
                // would otherwise drive unbounded LLM spend on the
                // operator's API key. Burst-tolerant via GCRA.
                if let Err(retry_after) = rate_limit.check() {
                    let resp = r#"{"error":"rate limit exceeded"}"#;
                    let response = format!(
                        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        retry_after.as_secs().max(1),
                        resp.len(),
                        resp
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    return;
                }

                // CSRF defence: a browser request must carry an
                // `Origin` header matching the WebChat origin. A page
                // on attacker.com that POSTs to
                // http://127.0.0.1:18790/api/chat would carry
                // `Origin: https://attacker.com`; without this check
                // the browser's same-origin policy blocks the SSE
                // response read but the agent still runs the prompt
                // and bills the operator's API key.
                //
                // `WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN=1` opts out for
                // non-browser scripts that don't send Origin (curl,
                // shell pipelines). When that mode is active the
                // gateway logs a warning at startup; the `Origin`
                // header is still validated when present.
                if let Some(resp) = api_preflight(&request, port, true) {
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }

                // Extract JSON body
                let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                let json: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
                let message = json["message"].as_str().unwrap_or("").to_string();

                if message.is_empty() {
                    let resp = r#"{"error":"empty message"}"#;
                    let response = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp.len(),
                        resp
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    return;
                }

                // The conversation comes from the request. A page with
                // no key sends none and gets the legacy conversation;
                // a key of the wrong shape is refused before it can
                // name a session.
                let conversation = match conversation_key(json["conversation"].as_str()) {
                    Ok(c) => c,
                    Err(_) => {
                        let resp = r#"{"error":"bad conversation key"}"#;
                        let response = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp.len(),
                            resp
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                };

                // One turn per conversation. A second send while one
                // is running is answered now, before the inbound row
                // is written and before any stream is opened: nothing
                // waits on the agent lock, and the page can say "turn
                // open" instead of holding a silent stream.
                let Some(_open_turn) = open_turns.try_open(&conversation) else {
                    let body = serde_json::json!({
                        "error": TURN_OPEN_ERROR,
                        "age_seconds": open_turns.open_age(&conversation).unwrap_or(0),
                    })
                    .to_string();
                    let _ = stream.write_all(json_conflict(&body).as_bytes()).await;
                    return;
                };

                // Audit. Webchat has no platform-assigned message id;
                // synthesize one so `target` stays a stable resource
                // handle and the body lives under `detail.content`.
                let inbound_target = format!("webchat:{}", uuid::Uuid::new_v4());

                // Scan for prompt-injection signatures, the same way
                // the adapter message loop does. The detector tags; it
                // never blocks. A hit merges into the inbound row's
                // detail and also lands as its own
                // `message.threat_flagged` row for SIEM visibility.
                let mut inbound_detail = serde_json::json!({ "content": &message });
                let threat_detail = detector.scan(&message).map(|t| t.to_detail_json());
                if let Some(ref threat) = threat_detail
                    && let (Some(obj), Some(threat_obj)) =
                        (inbound_detail.as_object_mut(), threat.as_object())
                {
                    for (k, v) in threat_obj {
                        obj.insert(k.clone(), v.clone());
                    }
                }
                if threat_detail.is_some() {
                    let _ = audit
                        .log(
                            AuditEvent::new(
                                ActorKind::Service,
                                "webchat-user",
                                "message.threat_flagged",
                                &inbound_target,
                            )
                            .with_channel("webchat")
                            .with_session(conversation.as_str())
                            .with_detail(inbound_detail.clone()),
                        )
                        .await;
                }

                // A turn is not started unless its inbound row was
                // accepted. The writer returns an error only once its
                // flush loop has halted (chain break, alarm-log failure,
                // or repeated SQLite failure); from then on nothing is
                // being recorded, so the chat route refuses rather than
                // running an unrecorded turn. The page raises its
                // halted banner from this status.
                let inbound_logged = audit
                    .log(
                        AuditEvent::new(
                            ActorKind::Service,
                            "webchat-user",
                            "message.inbound",
                            &inbound_target,
                        )
                        .with_channel("webchat")
                        .with_session(conversation.as_str())
                        .with_detail(inbound_detail),
                    )
                    .await;
                if let Err(e) = inbound_logged {
                    writer_halted.store(true, Ordering::Relaxed);
                    tracing::error!(
                        "webchat: audit writer refused the inbound row; refusing the turn: {e}"
                    );
                    let resp = r#"{"error":"audit writer halted"}"#;
                    let response = format!(
                        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp.len(),
                        resp
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    return;
                }

                // Session. `get_or_create` moves `last_activity` but
                // leaves `message_count` alone; `record_message` is the
                // only statement that increments it. Calling just the
                // former, as this path used to, leaves the sidebar
                // reading `0 msg` no matter how long the conversation
                // runs, while every other channel counts correctly
                // through the pair in `run.rs`. Counter failures are
                // logged rather than propagated: a display counter is
                // not worth failing a chat turn over.
                {
                    let store = sessions.lock().await;
                    match store.get_or_create("webchat", &conversation) {
                        Ok(session) => {
                            if let Err(e) = store.record_message(&session.id) {
                                tracing::warn!("webchat message count not recorded: {e}");
                            }
                        }
                        Err(e) => {
                            tracing::warn!("webchat session not resolved: {e}");
                        }
                    }
                }

                // SSE headers — stream tokens as they arrive
                let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
                if stream.write_all(header.as_bytes()).await.is_err()
                    || stream.flush().await.is_err()
                {
                    return;
                }

                // Wake the default agent for this conversation's
                // session. Webchat synthesizes a UUID per inbound
                // message for crash-recovery dedup.
                let session_id_str = webchat_session_id(&conversation);
                let inbound_id = format!("webchat-{}", uuid::Uuid::new_v4());

                // Register the per-request SSE sender so the
                // SseApprovalGate can push ApprovalRequest events
                // into this stream when the agent hits
                // NeedsApproval mid-tool-dispatch. The RAII guard
                // unregisters on every exit path (success, error,
                // panic, early return). The slice's load-bearing
                // cleanup property — no orphan senders survive a
                // panicking handler.
                let (sse_tx, mut sse_rx) = tokio::sync::mpsc::channel::<SseEvent>(8);
                let _registry_guard =
                    sse_registry.register_guard(SessionId::new(session_id_str.clone()), sse_tx);

                match factory.wake("default", &session_id_str) {
                    Ok(agent_mutex) => {
                        let (tx, mut rx) = tokio::sync::mpsc::channel(64);

                        // Run agent streaming and SSE forwarding concurrently
                        let mut ag = agent_mutex.lock().await;
                        let inbound_ctx = wirken_agent::InboundContext {
                            adapter_id: Some("webchat".to_string()),
                            sender_id: Some("webchat-user".to_string()),
                            channel: Some("webchat".to_string()),
                        };
                        let stream_future =
                            ag.process_message_stream_with(&message, inbound_id, tx, inbound_ctx);

                        // Forward both streams to the HTTP response
                        // as SSE. `rx` carries the agent's
                        // text-delta / done / error events; `sse_rx`
                        // carries approval-request / decision-ack
                        // events from the gate. `tokio::select!`
                        // multiplexes them onto the single TCP
                        // stream as `data: {...}\n\n` lines.
                        let write_stream = &mut stream;
                        let forward_future = async {
                            loop {
                                tokio::select! {
                                    Some(event) = rx.recv() => {
                                        let line = match event {
                                            wirken_agent::llm_stream::StreamEvent::TextDelta(text) => {
                                                format!(
                                                    "data: {}\n\n",
                                                    serde_json::json!({"type": "delta", "text": text})
                                                )
                                            }
                                            wirken_agent::llm_stream::StreamEvent::Done(_) => break,
                                            wirken_agent::llm_stream::StreamEvent::Error(e) => {
                                                format!(
                                                    "data: {}\n\n",
                                                    serde_json::json!({"type": "error", "text": e})
                                                )
                                            }
                                        };
                                        if write_stream.write_all(line.as_bytes()).await.is_err()
                                            || write_stream.flush().await.is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Some(sse_event) = sse_rx.recv() => {
                                        let line = sse_event.to_sse_line();
                                        if write_stream.write_all(line.as_bytes()).await.is_err()
                                            || write_stream.flush().await.is_err()
                                        {
                                            break;
                                        }
                                    }
                                    else => break,
                                }
                            }
                        };

                        let (result, _) = tokio::join!(stream_future, forward_future);

                        match result {
                            Ok(result) => {
                                let outbound_target =
                                    format!("webchat:out:{}", uuid::Uuid::new_v4());
                                let _ = audit
                                    .log(
                                        AuditEvent::new(
                                            ActorKind::User,
                                            "default",
                                            "message.outbound",
                                            &outbound_target,
                                        )
                                        .with_channel("webchat")
                                        .with_session(conversation.as_str())
                                        .with_detail(
                                            serde_json::json!({ "content": &result.response }),
                                        ),
                                    )
                                    .await;
                                // The turn is finished and its outbound row
                                // has been offered to the writer. Say so on
                                // the stream: without this event a socket
                                // that closed mid-answer and one that closed
                                // after the last token look the same to the
                                // page, which now marks the former as cut
                                // off.
                                let done = "data: {\"type\":\"done\"}\n\n";
                                let _ = stream.write_all(done.as_bytes()).await;
                                let _ = stream.flush().await;
                            }
                            Err(e) => {
                                let err = format!(
                                    "data: {}\n\n",
                                    serde_json::json!({"type": "error", "text": e.to_string()})
                                );
                                let _ = stream.write_all(err.as_bytes()).await;
                                let _ = stream.flush().await;
                            }
                        }
                    }
                    Err(e) => {
                        let err = format!(
                            "data: {}\n\n",
                            serde_json::json!({
                                "type": "error",
                                "text": format!("factory.wake failed: {e}"),
                            })
                        );
                        let _ = stream.write_all(err.as_bytes()).await;
                    }
                }
            } else if first_line.starts_with("POST /api/verify") {
                // POST /api/verify — run the audit chain verifier and
                // return its verdict with the anchor caveat attached.
                // State-changing in cost if not in effect: Origin
                // required, rate-limited, single-flight, blocking pool.
                if let Some(resp) = api_preflight(&request, port, true) {
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                if let Err(retry_after) = verify_limit.check() {
                    let resp = r#"{"result":"rate_limited"}"#;
                    let response = format!(
                        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        retry_after.as_secs().max(1),
                        resp.len(),
                        resp
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    return;
                }
                if verify_running
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    let resp = r#"{"result":"busy"}"#;
                    let response = format!(
                        "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp.len(),
                        resp
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    return;
                }
                let cfg = super::config();
                let started_at = chrono::Utc::now();
                let started = std::time::Instant::now();
                let outcome = tokio::task::spawn_blocking(move || {
                    AuditLog::open(&cfg.audit_db_path()).and_then(|log| log.verify())
                })
                .await;
                verify_running.store(false, Ordering::Release);
                let duration_ms = started.elapsed().as_millis() as u64;
                let body = match outcome {
                    Ok(Ok(result)) => verify_result_json(&result, started_at, duration_ms),
                    Ok(Err(e)) => serde_json::json!({
                        "result": "error",
                        "error": e.to_string(),
                        "started_at": started_at.to_rfc3339(),
                        "duration_ms": duration_ms,
                        "caveat": VERIFY_CAVEAT,
                    }),
                    Err(_) => serde_json::json!({
                        "result": "error",
                        "error": "the verify task did not complete",
                        "started_at": started_at.to_rfc3339(),
                        "duration_ms": duration_ms,
                        "caveat": VERIFY_CAVEAT,
                    }),
                };
                let body = serde_json::to_string(&body).unwrap_or_else(|_| "{}".into());
                let _ = stream.write_all(json_ok(&body).as_bytes()).await;
            } else if let Some(request_id) = parse_approval_path(first_line) {
                // POST /api/approvals/{request_id}
                //
                // Operator's decision on a pending NeedsApproval
                // request. Same Origin-header CSRF posture as
                // /api/chat. The handler resolves the queue entry
                // (gateway-centralized authorization: there is no
                // per-user allowlist in webchat today, the loopback
                // bind + Origin check are the trust boundary) and
                // pushes an ApprovalDecisionAck event onto the SSE
                // stream so the browser closes the approval UI.

                // Same CSRF + DNS-rebinding preflight as /api/chat.
                if let Some(resp) = api_preflight(&request, port, true) {
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }

                let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                let json: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
                let decision_str = json["decision"].as_str().unwrap_or("");
                let reason = json["reason"]
                    .as_str()
                    .map(|s| s.to_string())
                    .filter(|s| !s.is_empty());

                let decision = match decision_str {
                    "allow" => PendingDecision::Allow {
                        actor: Some("webchat".to_string()),
                    },
                    "deny" => PendingDecision::Deny {
                        reason,
                        actor: Some("webchat".to_string()),
                    },
                    _ => {
                        let resp = r#"{"error":"decision must be allow or deny"}"#;
                        let response = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp.len(),
                            resp
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                };

                // A decision made here is made as actor "webchat" with no
                // per-operator identity. That is acceptable for this
                // browser's own conversation and for nothing else: a
                // request that belongs to another channel's session is
                // refused, whatever its id, so enumerating ids can never
                // become a way around that channel's approver list.
                if approval_belongs_to_webchat(&pending_approvals, &request_id) == Some(false) {
                    let _ = stream
                        .write_all(
                            json_forbidden("approvals are decided on their own channel").as_bytes(),
                        )
                        .await;
                    return;
                }
                // And it is made for one conversation: the caller names
                // the conversation it is viewing, and the request must
                // have come from there. A page showing conversation B
                // never decides A's request, however it learned the id.
                let conversation = match conversation_key(json["conversation"].as_str()) {
                    Ok(c) => c,
                    Err(_) => {
                        let resp = r#"{"error":"bad conversation key"}"#;
                        let response = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp.len(),
                            resp
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                };
                let viewing = webchat_session_id(&conversation);
                if approval_belongs_to_conversation(&pending_approvals, &request_id, &viewing)
                    == Some(false)
                {
                    let _ = stream
                        .write_all(json_forbidden(DECISION_WRONG_CONVERSATION).as_bytes())
                        .await;
                    return;
                }
                let resolve = pending_approvals.resolve(&request_id, decision);
                let ack = match resolve {
                    ResolveResult::Accepted => AckResult::Accepted,
                    ResolveResult::UnknownKey => AckResult::UnknownKey,
                };

                // Push the ack onto the stream of the conversation the
                // request came from, which the guard above has shown is
                // the one being viewed.
                let session_id = SessionId::new(viewing);
                if let Some(sender) = sse_registry.sender_for(&session_id) {
                    let ack_event = SseEvent::ApprovalDecisionAck {
                        request_id: request_id.clone(),
                        result: ack.clone(),
                    };
                    let _ = sender.send(ack_event).await;
                }

                let ack_str = match ack {
                    AckResult::Accepted => "accepted",
                    AckResult::UnknownKey => "unknown_key",
                    AckResult::Expired => "expired",
                };
                let resp = format!(r#"{{"result":"{ack_str}"}}"#);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp.len(),
                    resp
                );
                let _ = stream.write_all(response.as_bytes()).await;
            } else {
                let response =
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
    }
}

/// What the SIEM forwarder is pointed at, reduced to what a status
/// panel may say. Built in `run.rs` next to the full config, which
/// carries bearer tokens and an HMAC secret that must never reach a
/// route; this struct cannot carry them.
#[derive(Debug, Clone)]
pub struct SiemSummary {
    /// Target kind in lowercase: `datadog`, `splunk`, `sentinel`,
    /// `webhook`.
    pub target: String,
    /// Host of the endpoint only. The path of a Sentinel endpoint
    /// embeds the data-collection-rule id, which is topology.
    /// Whether the typed-event pipe is opted in.
    pub typed_pipe: bool,
}

impl SiemSummary {
    pub fn from_config(cfg: &wirken_audit::siem::SiemConfig) -> Self {
        Self {
            target: format!("{:?}", cfg.target).to_ascii_lowercase(),
            typed_pipe: cfg.typed_forwarding_opted_in(),
        }
    }
}

/// Live state the status route reads that is not reachable from a
/// config path: the adapter registry (the only source of "connected"),
/// the alarm log with whatever HMAC key the gateway loaded, and the
/// SIEM summary. Everything else in the snapshot is re-read from the
/// data directory on each call.
#[derive(Clone)]
pub struct StatusInputs {
    pub registry: Arc<Mutex<AdapterRegistry>>,
    pub alarm_log: Arc<AlarmLog>,
    pub alarm_key_loaded: bool,
    pub siem: Option<SiemSummary>,
}

/// First 8 bytes of an Ed25519 public key as 16 hex characters. The
/// same shape the audit rows for adapter connect/disconnect carry.
fn pubkey_fingerprint(pubkey: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(16);
    for b in pubkey.iter().take(8) {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

/// First 16 characters of a hex public-key file, or None when the file
/// is absent or empty.
fn key_file_fingerprint(path: &std::path::Path) -> Option<String> {
    let body = std::fs::read_to_string(path).ok()?;
    let fp: String = body.trim().chars().take(16).collect();
    if fp.is_empty() { None } else { Some(fp) }
}

fn micros_to_json(v: Option<u64>) -> serde_json::Value {
    match v {
        Some(n) => serde_json::Value::from(n),
        None => serde_json::Value::Null,
    }
}

/// One snapshot of the gateway's posture. Every value is a field read,
/// a file read, an environment read, or an in-memory list: nothing
/// here wakes an agent, scans the chain, or probes Docker. A value the
/// gateway does not hold is `null`, which the page renders as unknown
/// and never as zero, false, or green.
///
/// Withheld on purpose: provider base URLs and regions, key material of
/// any kind, host filesystem paths, the SIEM endpoint path, and the
/// alarm records' hostname and pid.
pub async fn status_snapshot(
    cfg: &wirken_gateway::config::GatewayConfig,
    port: u16,
    inputs: &StatusInputs,
    writer_halted: bool,
) -> serde_json::Value {
    use serde_json::{Value, json};
    use wirken_agent::sandbox::SandboxMode;
    use wirken_gateway::org::parse_boolean_escape;

    // --- agent: the registered `default` row, else provider.json ---
    let registered =
        wirken_gateway::agent_config::AgentConfigStore::open(&cfg.agent_config_db_path())
            .ok()
            .and_then(|store| store.get("default").ok());
    let (agent, egress) = match registered {
        Some(a) => {
            let llm =
                wirken_agent::llm::LlmConfig::from_provider(&a.provider, &a.base_url, &a.model);
            let webchat_egress = a.channel_egress.get("webchat");
            let mode = webchat_egress
                .map(|e| {
                    if e.mode.is_empty() {
                        "none".to_string()
                    } else {
                        e.mode.clone()
                    }
                })
                .unwrap_or_else(|| "none".to_string());
            let domains = webchat_egress
                .map(|e| e.domains.clone())
                .unwrap_or_default();
            (
                json!({
                    "id": "default",
                    "provider": a.provider,
                    "model": a.model,
                    "api_key_credential": a.api_key_credential,
                    "context_window": llm.context_window,
                    "effective_context_budget": wirken_agent::context::effective_budget(llm.context_window),
                    "tools_enabled": a.tools_enabled,
                    "source": "agent_config.db",
                }),
                json!({
                    "channel": "webchat",
                    "mode": mode,
                    "domains": domains,
                    "effective_network_mode": if mode == "allowlist" || mode == "open" { "proxied" } else { "none" },
                }),
            )
        }
        None => {
            let provider_json: Option<Value> =
                std::fs::read_to_string(cfg.data_dir.join("provider.json"))
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok());
            match provider_json {
                Some(pj) => {
                    let provider = pj["provider"].as_str().unwrap_or("ollama").to_string();
                    let model = pj["model"].as_str().unwrap_or("llama3").to_string();
                    let base_url = pj["base_url"].as_str().unwrap_or("").to_string();
                    let llm =
                        wirken_agent::llm::LlmConfig::from_provider(&provider, &base_url, &model);
                    (
                        json!({
                            "id": "default",
                            "provider": provider,
                            "model": model,
                            "api_key_credential": pj["api_key_name"].as_str(),
                            "context_window": llm.context_window,
                            "effective_context_budget": wirken_agent::context::effective_budget(llm.context_window),
                            "tools_enabled": Value::Null,
                            "source": "provider.json",
                        }),
                        // The implicit default agent carries no egress
                        // policy: sandboxed exec runs with no network.
                        json!({ "channel": "webchat", "mode": "none", "domains": [], "effective_network_mode": "none" }),
                    )
                }
                None => (
                    json!({ "id": "default", "provider": Value::Null, "model": Value::Null, "api_key_credential": Value::Null,
                            "context_window": Value::Null, "effective_context_budget": Value::Null, "tools_enabled": Value::Null, "source": Value::Null }),
                    json!({ "channel": "webchat", "mode": Value::Null, "domains": [], "effective_network_mode": Value::Null }),
                ),
            }
        }
    };

    // --- sandbox: the file as it is on disk right now ---
    let sb = super::load_sandbox_config(&cfg.data_dir);
    let (mode, runtime) = match sb.mode {
        SandboxMode::Off => ("off", Value::Null),
        SandboxMode::ExecOnly => ("exec-only", Value::from("runc")),
        SandboxMode::GVisor => ("gvisor", Value::from("runsc")),
    };
    let sandbox = json!({
        "mode": mode,
        "runtime": runtime,
        "image": sb.image,
        "legacy_network_flag": sb.network,
        "limits": {
            "memory_mb": wirken_agent::sandbox::MEMORY_LIMIT / (1024 * 1024),
            "pids": wirken_agent::sandbox::PIDS_LIMIT,
            "timeout_secs": sb.timeout_secs,
        },
        "workspace_mount": "/workspace (rw)",
        "docker_reachable": Value::Null,
        "exec_refused": Value::Null,
    });

    // --- budget: config + ledger, keyed by the base agent id ---
    let budget = match wirken_gateway::budget::load_budget_config(&cfg.budget_config_path())
        .ok()
        .and_then(|c| c.resolve("default"))
    {
        Some(b) => {
            let now = chrono::Utc::now().timestamp();
            let window_start = b.window.window_start(now);
            let spent = wirken_gateway::budget::BudgetStore::open(&cfg.budget_db_path())
                .ok()
                .and_then(|store| store.window_spend("default", window_start).ok());
            json!({
                "mode": format!("{:?}", b.mode).to_ascii_lowercase(),
                "window": b.window.label(),
                "window_start": chrono::DateTime::from_timestamp(window_start, 0).map(|d| d.to_rfc3339()),
                "ceiling_usd_micros": b.ceiling_usd_micros,
                "spent_usd_micros": micros_to_json(spent),
                "remaining_usd_micros": micros_to_json(spent.map(|s| b.ceiling_usd_micros.saturating_sub(s))),
            })
        }
        None => json!({ "mode": "off" }),
    };

    // --- escape hatches: live reads of the gateway's own environment ---
    let escape_hatches = json!({
        "WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG": parse_boolean_escape("WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG"),
        "WIRKEN_ALLOW_UNSIGNED_SKILLS": parse_boolean_escape("WIRKEN_ALLOW_UNSIGNED_SKILLS"),
        "WIRKEN_ALLOW_UNSIGNED_MCP": parse_boolean_escape("WIRKEN_ALLOW_UNSIGNED_MCP"),
        "WIRKEN_ALLOW_STALE_ORG_CONFIG": parse_boolean_escape("WIRKEN_ALLOW_STALE_ORG_CONFIG"),
        "WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN": parse_boolean_escape("WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN"),
        "WIRKEN_ALLOW_UNREGISTERED_HOOKS": parse_boolean_escape("WIRKEN_ALLOW_UNREGISTERED_HOOKS"),
        "WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES": std::env::var("WIRKEN_AUDIT_VERIFY_EVERY_FLUSHES").ok(),
        "sandbox_mode_off": sb.mode == SandboxMode::Off,
        "skill_registry_root_pinned": wirken_gateway::skill_registry::load_registry_root(&cfg.data_dir).ok().flatten().is_some(),
    });

    // --- org config: what is on disk; applied once per gateway start ---
    let org_url = wirken_gateway::org::load_org_url(&cfg.data_dir);
    let org = json!({
        "configured": org_url.is_some(),
        "pubkey_fingerprint": key_file_fingerprint(&cfg.data_dir.join(wirken_gateway::org::ORG_CONFIG_PUBKEY_FILE)),
        "unsigned_allowed": parse_boolean_escape("WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG"),
        "stale_allowed": parse_boolean_escape("WIRKEN_ALLOW_STALE_ORG_CONFIG"),
        "tool_policy": wirken_gateway::org::load_tool_policy(&cfg.data_dir).ok().flatten()
            .and_then(|p| serde_json::to_value(p).ok()),
        "applied": if org_url.is_some() { Value::from("at gateway start") } else { Value::Null },
    });

    // --- audit: alarms on disk, key id, session count, writer state ---
    let alarms = inputs.alarm_log.read_all().ok().map(|records| {
        records
            .into_iter()
            .map(|r| {
                json!({
                    "timestamp": r.record.timestamp,
                    "alarm_type": r.record.alarm_type,
                    "session_id": r.record.session_id,
                    "seq": r.record.seq,
                    "status": match r.status {
                        AlarmVerifyStatus::Verified => "verified",
                        AlarmVerifyStatus::NoKey => "no_key",
                        AlarmVerifyStatus::Unsigned => "unsigned",
                        AlarmVerifyStatus::Tampered => "tampered",
                    },
                })
            })
            .collect::<Vec<_>>()
    });
    let sessions_total = wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path())
        .ok()
        .and_then(|log| log.list_session_ids().ok())
        .map(|ids| ids.len());
    let audit = json!({
        "writer_halted": writer_halted,
        "signing_pubkey_fingerprint": key_file_fingerprint(&wirken_audit::audit_public_key_path(&cfg.data_dir)),
        "sessions_total": sessions_total,
        "alarms": alarms,
        "alarm_hmac_key_loaded": inputs.alarm_key_loaded,
    });

    let siem = match &inputs.siem {
        Some(s) => json!({
            "configured": true,
            "target": s.target,
            "typed_pipe": s.typed_pipe,
            "last_ship": Value::Null,
            "lag": Value::Null,
        }),
        None => json!({ "configured": false }),
    };

    let adapters: Vec<Value> = inputs
        .registry
        .lock()
        .await
        .list()
        .into_iter()
        .map(|a| {
            json!({
                "adapter_id": a.adapter_id,
                "channel": a.channel,
                "connected": a.connected,
                "pubkey_fingerprint": pubkey_fingerprint(&a.public_key),
                "pid": Value::Null,
                "restarts": Value::Null,
            })
        })
        .collect();

    json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "gateway": { "version": env!("CARGO_PKG_VERSION"), "loopback_only": true,
        "session_expiry_secs": cfg.session_expiry_secs, "port": port },
        "agent": agent,
        "egress": egress,
        "sandbox": sandbox,
        "budget": budget,
        "escape_hatches": escape_hatches,
        "org": org,
        "audit": audit,
        "siem": siem,
        "hooks": Value::Null,
        "adapters": adapters,
    })
}

/// Parse `GET /api/sessions/{id}/events[?after=N]`. The id is one
/// percent-encoded segment (its `/` separators arrive as `%2F`),
/// followed by the literal `/events`. Same segment rules as the
/// transcript route: no empty segment, no `..`, no control byte.
/// `after` is the last sequence the caller already holds.
fn parse_session_events_path(first_line: &str) -> Option<(String, Option<u64>)> {
    let rest = first_line.strip_prefix("GET /api/sessions/")?;
    let raw = rest.split(' ').next()?;
    let (path, query) = match raw.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw, None),
    };
    let encoded_id = path.strip_suffix("/events")?;
    if encoded_id.is_empty() || encoded_id.contains('/') {
        return None;
    }
    let decoded = percent_decode(encoded_id)?;
    if decoded.split('/').any(|seg| seg.is_empty() || seg == "..") {
        return None;
    }
    if decoded.chars().any(|c| c.is_control()) {
        return None;
    }
    let mut after = None;
    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some(v) = pair.strip_prefix("after=") {
                after = Some(v.parse::<u64>().ok()?);
            }
        }
    }
    Some((decoded, after))
}

/// The channel segment of a `{agent}/{channel}/{conversation}` id,
/// when the id has that shape.
fn session_channel(session_id: &str) -> Option<&str> {
    let mut parts = session_id.splitn(3, '/');
    let _agent = parts.next()?;
    let channel = parts.next()?;
    let conversation = parts.next()?;
    if conversation.is_empty() {
        None
    } else {
        Some(channel)
    }
}

/// The events route serves webchat sessions only. The id is
/// `{agent}/{channel}/{conversation}`; anything whose channel segment
/// is not `webchat` is another channel's record.
fn events_route_allowed(session_id: &str) -> bool {
    session_channel(session_id) == Some("webchat")
}

/// Whether a pending approval belongs to a webchat session. `None`
/// when the queue holds no such entry, which the resolve path reports
/// as an unknown key exactly as before.
fn approval_belongs_to_webchat(queue: &PendingApprovalQueue, request_id: &str) -> Option<bool> {
    queue
        .show(request_id)
        .map(|d| session_channel(&d.agent_id) == Some("webchat"))
}

/// Whether a pending approval was raised in the given webchat session.
/// `None` when the queue holds no such entry.
fn approval_belongs_to_conversation(
    queue: &PendingApprovalQueue,
    request_id: &str,
    session_id: &str,
) -> Option<bool> {
    queue.show(request_id).map(|d| d.agent_id == session_id)
}

/// The list rows the page draws its rail from: each active session
/// with, for a webchat conversation, its first user message (the title
/// the page shows; control sequences stripped and cut at 120
/// characters, otherwise verbatim) and whether a turn is open in it.
/// Another channel's first message is that channel's user's words and
/// stays null here, as it does on the approvals route.
fn conversation_rows(
    cfg: &wirken_gateway::config::GatewayConfig,
    rows: Vec<super::session::SessionRow>,
    open_turns: &OpenTurns,
) -> serde_json::Value {
    use serde_json::{Value, json};
    use wirken_audit::{SessionEvent, SessionLog};
    let audit_path = cfg.audit_db_path();
    let log = if rows.iter().any(|r| r.channel == "webchat") && audit_path.exists() {
        wirken_audit::SqliteSessionLog::open(&audit_path).ok()
    } else {
        None
    };
    json!(
        rows.into_iter()
            .map(|row| {
                let mine = row.channel == "webchat";
                let first_message = if mine {
                    log.as_ref().and_then(|log| {
                        let handle = log.handle_for(SessionId::new(row.log_id.clone()));
                        log.get_range(&handle, 0..64).ok().and_then(|events| {
                            events.into_iter().find_map(|ev| match ev.event {
                                SessionEvent::UserMessage { content, .. } => Some(
                                    wirken_agent::ansi::strip_control_sequences(&content)
                                        .chars()
                                        .take(120)
                                        .collect::<String>(),
                                ),
                                _ => None,
                            })
                        })
                    })
                } else {
                    None
                };
                let turn_age = if mine {
                    conversation_of(&row.log_id).and_then(|c| open_turns.open_age(c))
                } else {
                    None
                };
                let turn_open = if mine {
                    Value::from(turn_age.is_some())
                } else {
                    Value::Null
                };
                json!({
                    "store_id": row.store_id,
                    "log_id": row.log_id,
                    "channel": row.channel,
                    "message_count": row.message_count,
                    "last_activity": row.last_activity,
                    "first_message": first_message,
                    "turn_open": turn_open,
                    "turn_open_age_seconds": turn_age,
                })
            })
            .collect::<Vec<_>>()
    )
}

/// This browser's pending approvals, with the message that triggered
/// each, and a count of every other channel's. The trigger text of a
/// request from another channel is that channel's user's message and
/// never leaves the gateway through this route; neither does the
/// request id.
///
/// `remaining_seconds` is null: the queue stores when a request was
/// made but not the deadline the gate is waiting on, so a countdown
/// would be a guess. `timeout_seconds` is the window the webchat gate
/// applies, as configured.
/// The same list scoped to one conversation. `mine` is that
/// conversation's requests; `elsewhere` names each other webchat
/// conversation holding one, with when it asked and nothing else: no
/// request id and no trigger text, since the page navigates to it and
/// never decides from here. With no conversation given, `mine` is the
/// whole channel, as before.
fn approvals_snapshot_for(
    queue: &PendingApprovalQueue,
    conversation: Option<&str>,
) -> serde_json::Value {
    use serde_json::{Value, json};
    let timeout = resolve_webchat_timeout().as_secs();
    let viewing = conversation.map(webchat_session_id);
    let mut mine = Vec::new();
    let mut elsewhere = Vec::new();
    let mut by_channel: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for entry in queue.list() {
        if session_channel(&entry.agent_id) == Some("webchat") {
            if viewing.as_deref().is_some_and(|v| v != entry.agent_id) {
                elsewhere.push(json!({
                    "conversation": conversation_of(&entry.agent_id),
                    "requested_tier": entry.requested_tier,
                    "requested_at": entry.requested_at.to_rfc3339(),
                    "age_seconds": entry.age_seconds,
                }));
                continue;
            }
            let trigger = queue
                .show(&entry.request_id)
                .and_then(|d| d.trigger_message);
            mine.push(json!({
                "request_id": entry.request_id,
                "agent_id": entry.agent_id,
                "tool_name": entry.tool_name,
                "action_key": entry.action_key,
                "requested_tier": entry.requested_tier,
                "requested_at": entry.requested_at.to_rfc3339(),
                "age_seconds": entry.age_seconds,
                "timeout_seconds": timeout,
                "remaining_seconds": Value::Null,
                "trigger_message": trigger,
            }));
        } else {
            let channel = session_channel(&entry.agent_id)
                .unwrap_or("unknown")
                .to_string();
            *by_channel.entry(channel).or_insert(0) += 1;
        }
    }
    let count: u64 = by_channel.values().sum();
    elsewhere.sort_by_key(|e| e["age_seconds"].as_u64().unwrap_or(u64::MAX));
    json!({
        "mine": mine,
        "elsewhere": elsewhere,
        "other_channels": { "count": count, "by_channel": by_channel },
    })
}

/// First 16 characters of a hex value carried on a row, for a
/// fingerprint the page can show without the full key.
fn hex_fingerprint<T: serde::Serialize>(v: &T) -> serde_json::Value {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => {
            serde_json::Value::from(s.chars().take(16).collect::<String>())
        }
        _ => serde_json::Value::Null,
    }
}

/// The session log projected to what the page draws: the rows the
/// transcript used to drop (tool calls and results, decisions, egress
/// verdicts, budget stops, sub-agent spawns) plus a head and totals.
///
/// Whitelisted per variant. Withheld: the system prompt (it embeds
/// every skill body), request and tool hashes, raw signatures and
/// keys (a fingerprint stands in), sender ids, and any variant not
/// named here. Tool arguments and outputs are what the agent recorded,
/// verbatim, with terminal control sequences stripped from outputs.
///
/// `after` filters the rows returned; the head and totals always cover
/// the whole session so a poll during a turn sees the same figures as
/// a full load.
pub fn session_events(
    cfg: &wirken_gateway::config::GatewayConfig,
    session_id: &str,
    after: Option<u64>,
) -> serde_json::Value {
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use wirken_audit::{SessionEvent, SessionLog, SqliteSessionLog};

    let log = match SqliteSessionLog::open(&cfg.audit_db_path()) {
        Ok(l) => l,
        Err(_) => return json!({ "error": "session log unavailable" }),
    };
    let handle = log.handle_for(SessionId::new(session_id.to_string()));
    let rows = match log.get_since(&handle, 0) {
        Ok(r) => r,
        Err(_) => return json!({ "error": "session log unreadable" }),
    };

    let mut call_started: HashMap<String, chrono::DateTime<chrono::Utc>> = HashMap::new();
    let mut events: Vec<Value> = Vec::new();
    let (mut input_tokens, mut output_tokens, mut cost_micros) = (0u64, 0u64, 0u64);
    let mut cost_known = true;
    let (mut llm_calls, mut tool_calls, mut attestations) = (0u64, 0u64, 0u64);
    let mut last_signed_head_seq: Option<u64> = None;
    let mut last_chain_head_row: Option<u64> = None;
    let mut last_compaction: Value = Value::Null;
    let mut head_seq: Option<u64> = None;
    let mut head_hash: Value = Value::Null;

    for row in &rows {
        head_seq = Some(row.seq);
        head_hash = hex_fingerprint(&row.hash);
        let projected: Option<Value> = match &row.event {
            SessionEvent::UserMessage { content, .. } => {
                Some(json!({ "kind": "user_message", "content": content }))
            }
            SessionEvent::AssistantMessage { content, .. } => {
                Some(json!({ "kind": "assistant_message", "content": content }))
            }
            SessionEvent::AssistantToolCalls { calls, .. } => {
                tool_calls += calls.len() as u64;
                let calls: Vec<Value> = calls
                    .iter()
                    .map(|c| {
                        call_started.insert(c.id.clone(), row.ts);
                        let args: Value = serde_json::from_str(&c.arguments).unwrap_or(Value::Null);
                        let action = wirken_agent::tool::tool_to_action(&c.name, &args);
                        json!({
                            "id": c.id,
                            "name": c.name,
                            "arguments": c.arguments,
                            "computed_tier": action.as_ref().map(|a| a.tier().label()),
                            "action_key": action.as_ref().map(|a| a.approval_key()),
                        })
                    })
                    .collect();
                Some(json!({ "kind": "assistant_tool_calls", "calls": calls }))
            }
            SessionEvent::ToolResult {
                call_id,
                tool_name,
                output,
                success,
                ..
            } => {
                let elapsed = call_started
                    .get(call_id)
                    .map(|started| (row.ts - *started).num_milliseconds());
                Some(json!({
                    "kind": "tool_result",
                    "call_id": call_id,
                    "tool_name": tool_name,
                    "success": success,
                    "output": wirken_agent::ansi::strip_control_sequences(output),
                    "output_bytes": output.len(),
                    "elapsed_ms_approx": elapsed,
                }))
            }
            SessionEvent::LlmRequest {
                provider,
                model,
                request_id,
                ..
            } => Some(json!({
                "kind": "llm_request", "provider": provider, "model": model, "request_id": request_id,
            })),
            SessionEvent::LlmResponse {
                request_id,
                finish_reason,
                input_tokens: inp,
                output_tokens: out,
                latency_ms,
                total_cost_usd_micros,
                ..
            } => {
                llm_calls += 1;
                input_tokens += u64::from(*inp);
                output_tokens += u64::from(*out);
                match total_cost_usd_micros {
                    Some(c) => cost_micros += c,
                    None => cost_known = false,
                }
                Some(json!({
                    "kind": "llm_response",
                    "request_id": request_id,
                    "finish_reason": finish_reason,
                    "input_tokens": inp,
                    "output_tokens": out,
                    "latency_ms": latency_ms,
                    "total_cost_usd_micros": total_cost_usd_micros,
                }))
            }
            SessionEvent::BudgetExceeded {
                window_spend_usd_micros,
                ceiling_usd_micros,
                window,
                action,
                tool,
                ..
            } => Some(json!({
                "kind": "budget_exceeded",
                "action": serde_json::to_value(action).unwrap_or(Value::Null),
                "window": window,
                "window_spend_usd_micros": window_spend_usd_micros,
                "ceiling_usd_micros": ceiling_usd_micros,
                "tool": tool,
            })),
            SessionEvent::PermissionDenied {
                tool,
                action_key,
                denial_source,
                tier,
                denied_via,
                denial_reason,
                ..
            } => Some(json!({
                "kind": "permission_denied",
                "tool": tool,
                "action_key": action_key,
                "tier": tier,
                "denial_source": serde_json::to_value(denial_source).unwrap_or(Value::Null),
                "denied_via": serde_json::to_value(denied_via).unwrap_or(Value::Null),
                "denial_reason": denial_reason,
                "timed_out": denial_reason.as_deref() == Some("approval timeout"),
            })),
            SessionEvent::PermissionApproved {
                action_key,
                approved_by,
                scope,
                approved_via,
                ..
            } => Some(json!({
                "kind": "permission_approved",
                "action_key": action_key,
                "approved_by": approved_by,
                "scope": serde_json::to_value(scope).unwrap_or(Value::Null),
                "approved_via": serde_json::to_value(approved_via).unwrap_or(Value::Null),
            })),
            SessionEvent::PermissionRenewed {
                action_key,
                approved_by,
                previous_expires_at,
                expires_at,
                ..
            } => Some(json!({
                "kind": "permission_renewed",
                "action_key": action_key,
                "approved_by": approved_by,
                "previous_expires_at": previous_expires_at.to_rfc3339(),
                "expires_at": expires_at.to_rfc3339(),
            })),
            SessionEvent::PermissionGrantExpired {
                action_key,
                tool,
                tier,
                expired_at,
                detected_by,
                ..
            } => Some(json!({
                "kind": "permission_grant_expired",
                "action_key": action_key,
                "tool": tool,
                "tier": tier,
                "expired_at": expired_at.to_rfc3339(),
                "detected_by": serde_json::to_value(detected_by).unwrap_or(Value::Null),
            })),
            SessionEvent::PermissionGrantPruned {
                action_key,
                expires_at,
                ..
            } => Some(json!({
                "kind": "permission_grant_pruned",
                "action_key": action_key,
                "expires_at": expires_at.to_rfc3339(),
            })),
            SessionEvent::SandboxEgressVerdict {
                host,
                port,
                allowed,
                reason,
                mode,
                escalated,
                ..
            } => Some(json!({
                "kind": "sandbox_egress_verdict",
                "host": host,
                "port": port,
                "allowed": allowed,
                "reason": serde_json::to_value(reason).unwrap_or(Value::Null),
                "mode": serde_json::to_value(mode).unwrap_or(Value::Null),
                "escalated": escalated,
            })),
            SessionEvent::SubagentSpawned {
                child_session_id,
                child_agent_id,
                tools_granted,
                max_permission_tier,
            } => Some(json!({
                "kind": "subagent_spawned",
                "child_session_id": child_session_id,
                "child_agent_id": child_agent_id,
                "tools_granted": tools_granted,
                "max_permission_tier": max_permission_tier,
            })),
            SessionEvent::SubagentResult {
                child_session_id,
                output,
                status,
            } => Some(json!({
                "kind": "subagent_result",
                "child_session_id": child_session_id,
                "status": serde_json::to_value(status).unwrap_or(Value::Null),
                "output": output,
            })),
            SessionEvent::Attestation {
                chain_head_seq,
                signer_pubkey,
                ..
            } => {
                attestations += 1;
                Some(json!({
                    "kind": "attestation",
                    "chain_head_seq": chain_head_seq,
                    "signer_pubkey_fingerprint": hex_fingerprint(signer_pubkey),
                    "verified": Value::Null,
                }))
            }
            SessionEvent::ChainHead {
                reason,
                sequence_range_start,
                sequence_range_end,
                ..
            } => {
                last_signed_head_seq = Some(*sequence_range_end);
                last_chain_head_row = Some(row.seq);
                Some(json!({
                    "kind": "chain_head",
                    "reason": serde_json::to_value(reason).unwrap_or(Value::Null),
                    "sequence_range_start": sequence_range_start,
                    "sequence_range_end": sequence_range_end,
                }))
            }
            SessionEvent::Compaction { extracts, .. } => {
                let v = json!({
                    "kind": "compaction",
                    "trimmed_bytes": extracts.get("trimmed_bytes").cloned().unwrap_or(Value::Null),
                    "kept_messages": extracts.get("kept_messages").cloned().unwrap_or(Value::Null),
                    "dropped_messages": extracts.get("dropped_messages").cloned().unwrap_or(Value::Null),
                });
                let mut lc = v.clone();
                lc["seq"] = Value::from(row.seq);
                last_compaction = lc;
                Some(v)
            }
            SessionEvent::HttpRequest {
                method,
                host,
                status,
                ..
            } => Some(json!({
                "kind": "http_request", "method": method, "host": host, "status": status,
            })),
            _ => None,
        };
        if let Some(mut v) = projected
            && after.is_none_or(|a| row.seq > a)
        {
            v["seq"] = Value::from(row.seq);
            v["ts"] = Value::from(row.ts.to_rfc3339());
            events.push(v);
        }
    }

    let unsigned_tail_len = match (head_seq, last_chain_head_row) {
        (Some(h), Some(c)) => Value::from(h.saturating_sub(c)),
        (Some(h), None) => Value::from(h + 1),
        _ => Value::Null,
    };
    json!({
        "session_id": session_id,
        "head": {
            "seq": head_seq,
            "hash": head_hash,
            "last_signed_head_seq": last_signed_head_seq,
            "unsigned_tail_len": unsigned_tail_len,
        },
        "totals": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd_micros": cost_micros,
            "cost_known": cost_known,
            "llm_calls": llm_calls,
            "tool_calls": tool_calls,
            "attestations": attestations,
        },
        "last_compaction": last_compaction,
        "events": events,
    })
}

/// Tools whose tier the gate decides from the arguments of each call,
/// so no single tier is true of the tool. The table says so instead
/// of picking one.
const ARGUMENT_DEPENDENT_TOOLS: &[(&str, &str)] = &[
    (
        "exec",
        "Tier 2 for a read-only verb on the allowlist, Tier 3 for anything else",
    ),
    (
        "memory_read_channel",
        "Tier 3; the action names the channel it reads",
    ),
    (
        "read_imported_chat",
        "Tier 3; the action names the archive it reads",
    ),
    (
        "search_imported_chats",
        "Tier 3; the action names the archive it searches",
    ),
];

/// Tools the harness intercepts before the tier gate; they never have
/// a tier.
const INTERCEPTED_TOOLS: &[&str] = &["spawn_subagent", "wirken_enter_phase", "wirken_exit_phase"];

/// One row of the tool table: the tier the gate would compute for a
/// call with no arguments, or the rule when the arguments decide it.
fn tool_tier_entry(name: &str, description: &str) -> serde_json::Value {
    use serde_json::{Value, json};
    if let Some((_, rule)) = ARGUMENT_DEPENDENT_TOOLS.iter().find(|(n, _)| *n == name) {
        return json!({
            "name": name,
            "description": description,
            "tier": Value::Null,
            "tier_depends_on_arguments": true,
            "tier_rule": rule,
            "action_key": Value::Null,
        });
    }
    if INTERCEPTED_TOOLS.contains(&name) {
        return json!({
            "name": name,
            "description": description,
            "tier": Value::Null,
            "tier_depends_on_arguments": false,
            "tier_rule": "intercepted before the tier gate",
            "action_key": Value::Null,
        });
    }
    match wirken_agent::tool::tool_to_action(name, &Value::Null) {
        Some(action) => json!({
            "name": name,
            "description": description,
            "tier": action.tier().label(),
            "tier_depends_on_arguments": false,
            "tier_rule": Value::Null,
            "action_key": action.approval_key(),
        }),
        None => json!({
            "name": name,
            "description": description,
            "tier": "tier3",
            "tier_depends_on_arguments": false,
            "tier_rule": if name.starts_with("wasm_") { "Wasm skill call: Tier 3" } else { "not in the classifier: Tier 3 as an unknown tool" },
            "action_key": Value::Null,
        }),
    }
}

/// A skill's signature status in one of three words. "signed" carries
/// the signer; "unsigned" means no signature file; "unverified" means
/// a signature is present that could not be verified, or the check
/// itself failed. Never a tick on its own.
fn skill_signature_word(
    check: Result<SkillSignature, wirken_gateway::error::GatewayError>,
) -> (&'static str, Option<String>) {
    match check {
        Ok(SkillSignature::Valid { signer }) => ("signed", Some(signer)),
        Ok(SkillSignature::Unsigned) => ("unsigned", None),
        Ok(SkillSignature::Invalid) | Err(_) => ("unverified", None),
    }
}

fn allow_set_json(set: &wirken_agent::skill_perms::AllowSet) -> serde_json::Value {
    match set {
        wirken_agent::skill_perms::AllowSet::Wildcard => serde_json::json!("*"),
        wirken_agent::skill_perms::AllowSet::Set(s) => {
            serde_json::json!(s.iter().collect::<Vec<_>>())
        }
    }
}

/// The frontmatter of a SKILL.md as written, between its `---` fences.
/// The loader keeps only the parsed form, so this is re-read from the
/// file the skill was loaded from.
fn skill_frontmatter(path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let rest = text.strip_prefix("---")?;
    let (yaml, _) = rest.split_once("\n---")?;
    Some(format!("---{yaml}\n---"))
}

/// What the default agent is offered and gated by. Wakes the agent and
/// takes its lock only if it is free; a turn in flight answers
/// `busy: true` with the agent-held sections null rather than waiting
/// on the lock. Tool descriptions and skill bodies are text written by
/// skill authors; the page renders them as data.
pub async fn capabilities_snapshot(
    cfg: &wirken_gateway::config::GatewayConfig,
    factory: &AgentFactory,
    conversation: &str,
) -> serde_json::Value {
    use serde_json::{Value, json};
    let session_id = webchat_session_id(conversation);
    let org = wirken_gateway::org::load_tool_policy(&cfg.data_dir)
        .ok()
        .flatten();
    let org_policy_for = |name: &str| -> &'static str {
        match &org {
            Some(p) if p.blocked_tools.iter().any(|t| t == name) => "blocked",
            Some(p)
                if !p.allowed_tools.is_empty() && !p.allowed_tools.iter().any(|t| t == name) =>
            {
                "not allowed"
            }
            _ => "allowed",
        }
    };
    let grants: Value = match super::open_permission_store(cfg) {
        Ok(store) => match store.list("default") {
            Ok(rows) => json!(
                rows.iter()
                    .map(|g| json!({
                        "action_key": g.action_key,
                        "approved_at": g.approved_at.to_rfc3339(),
                        "approved_by": g.approved_by,
                        "expires_at": g.expires_at.to_rfc3339(),
                        "scope": serde_json::to_value(&g.scope).unwrap_or(Value::Null),
                    }))
                    .collect::<Vec<_>>()
            ),
            Err(_) => Value::Null,
        },
        Err(_) => Value::Null,
    };

    let agent = match factory.wake("default", &session_id) {
        Ok(a) => a,
        Err(_) => {
            return json!({ "agent_id": "default", "busy": false, "available": false, "tools": Value::Null, "skills": Value::Null, "grants": grants });
        }
    };
    let guard = match agent.try_lock() {
        Ok(g) => g,
        Err(_) => {
            return json!({ "agent_id": "default", "busy": true, "available": true, "tools": Value::Null, "skills": Value::Null, "grants": grants });
        }
    };
    let tools: Vec<Value> = guard
        .snapshot_tool_defs_for(wirken_audit::ToolsHashVersion::V2)
        .await
        .into_iter()
        .map(|t| {
            let mut entry = tool_tier_entry(&t.name, &t.description);
            entry["org_policy"] = Value::from(org_policy_for(&t.name));
            entry
        })
        .collect();
    let skills: Vec<Value> = guard
        .skills()
        .iter()
        .map(|sk| {
            let dir = sk.path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            let (signature, signer) = skill_signature_word(verify_skill_self_signed(&dir));
            let p = &sk.permissions;
            json!({
                "name": sk.name,
                "description": sk.description,
                "available": sk.available,
                "required_bins": sk.required_bins,
                "model_invocable": !sk.disable_model_invocation,
                "signature": signature,
                "signer": signer,
                "permissions": {
                    "tools": allow_set_json(&p.tools.allow),
                    "egress": {
                        "mode": match p.egress.mode { wirken_agent::skill_perms::EgressMode::Allowlist => "allowlist", wirken_agent::skill_perms::EgressMode::Deny => "deny" },
                        "domains": allow_set_json(&p.egress.domains),
                    },
                    "filesystem": { "read_paths": p.filesystem.read_paths.len(), "write_paths": p.filesystem.write_paths.len() },
                    "inference": allow_set_json(&p.inference.allow),
                    "credentials": allow_set_json(&p.credentials.allow),
                    "http_post_paths": p.http.post_paths.len(),
                },
                "frontmatter": skill_frontmatter(&sk.path),
            })
        })
        .collect();
    drop(guard);
    json!({
        "agent_id": "default",
        "busy": false,
        "available": true,
        "tools": tools,
        "grants": grants,
        "skills": skills,
        "org_policy": org.and_then(|p| serde_json::to_value(p).ok()),
    })
}

/// Credential names without the vault key, and the MCP connectors
/// reduced to what a panel may say. Withheld: every value in the vault,
/// connector URLs and commands, environment values, key material.
pub fn credentials_snapshot(cfg: &wirken_gateway::config::GatewayConfig) -> serde_json::Value {
    use serde_json::{Value, json};
    // An absent vault file is an empty store; a vault that cannot be
    // read is not, and the two are not reported alike.
    let credentials: Value = match CredentialStore::names(&cfg.vault_db_path()) {
        Ok(names) => json!(
            names
                .iter()
                .map(|n| {
                    json!({
                        "name": n,
                        "channel": Value::Null,
                        "created_at": Value::Null,
                        "expires_at": Value::Null,
                        "last_used_at": Value::Null,
                        "rotation_due_at": Value::Null,
                    })
                })
                .collect::<Vec<_>>()
        ),
        Err(_) => Value::Null,
    };

    // Trust verdicts the proxy recorded for each entry, on its own
    // sentinel session: the last row per server wins.
    let mut trust: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    let audit_path = cfg.audit_db_path();
    if audit_path.exists()
        && let Ok(log) = wirken_audit::SqliteSessionLog::open(&audit_path)
    {
        use wirken_audit::{SessionEvent, SessionLog};
        let handle = log.handle_for(SessionId::new("gateway-mcp".to_string()));
        if let Ok(rows) = log.get_since(&handle, 0) {
            for row in rows {
                match row.event {
                    SessionEvent::McpEntryVerified {
                        server_name,
                        signer,
                    } => {
                        trust.insert(server_name, json!({ "verified": true, "signer": signer }));
                    }
                    // The reason names the flag that would weaken the
                    // check; the verdict is enough, and the hatch banner
                    // covers the case where the flag is set.
                    SessionEvent::McpEntryRefused { server_name, .. } => {
                        trust.insert(server_name, json!({ "verified": false }));
                    }
                    _ => {}
                }
            }
        }
    }

    let strip = |c: &str| c.strip_prefix("vault:").unwrap_or(c).to_string();
    let fp = |k: &Option<String>| k.as_ref().map(|s| s.chars().take(16).collect::<String>());
    // A missing config file is no connectors; an unreadable one is
    // unknown.
    let connectors: Value = match McpConfig::load(&cfg.mcp_config_path("default")) {
        Ok(config) => {
            let mut names: Vec<&String> = config.servers.keys().collect();
            names.sort();
            names
                .into_iter()
                .map(|name| {
                    let server = &config.servers[name];
                    let (transport, auth, provider, credentials, signature, signer_key, priced) =
                        match server {
                            McpServerConfig::Http {
                                auth,
                                signature,
                                signer_key,
                                tool_costs,
                                ..
                            } => {
                                let (kind, provider, cred) = match auth {
                                    Some(McpAuth::Bearer { credential }) => {
                                        ("bearer", None, vec![strip(credential)])
                                    }
                                    Some(McpAuth::Oauth2 {
                                        provider,
                                        credential,
                                    }) => {
                                        ("oauth2", Some(provider.clone()), vec![strip(credential)])
                                    }
                                    None => ("none", None, vec![]),
                                };
                                (
                                    "http",
                                    kind,
                                    provider,
                                    cred,
                                    signature,
                                    signer_key,
                                    tool_costs.len(),
                                )
                            }
                            McpServerConfig::Stdio {
                                env,
                                signature,
                                signer_key,
                                tool_costs,
                                ..
                            } => {
                                let mut creds: Vec<String> = env
                                    .values()
                                    .filter_map(|v| v.strip_prefix("vault:").map(|s| s.to_string()))
                                    .collect();
                                creds.sort();
                                (
                                    "stdio",
                                    "environment",
                                    None,
                                    creds,
                                    signature,
                                    signer_key,
                                    tool_costs.len(),
                                )
                            }
                        };
                    json!({
                        "name": name,
                        "transport": transport,
                        "auth": auth,
                        "provider": provider,
                        "credentials": credentials,
                        "signed": signature.is_some(),
                        "signer_fingerprint": fp(signer_key),
                        "priced_tools": priced,
                        "trust": trust.get(name).cloned().unwrap_or(Value::Null),
                    })
                })
                .collect::<Vec<_>>()
                .into()
        }
        Err(_) => Value::Null,
    };
    json!({
        "credentials": credentials,
        "metadata_available": false,
        "connectors": connectors,
    })
}

/// What a verify result from this route means, in the words the CLI
/// uses. The route calls the verifier without an operator trust
/// anchor, so a pass says the chain is internally consistent and no
/// more; the same-UID attacker who can rewrite the chain can re-sign
/// it. The sentence travels with every verdict the page shows.
pub const VERIFY_CAVEAT: &str = "Report-only: no operator trust anchor was consulted, so a same-UID \
     rewrite is not detected. Verify against a key kept off this machine for that: \
     wirken audit verify --require-signed";

/// A `VerifyResult` as the page reads it. Hashes and key ids are cut to
/// fingerprints; the verdict is a word in `result`; the caveat rides
/// along whatever the verdict.
pub fn verify_result_json(
    result: &VerifyResult,
    started_at: chrono::DateTime<chrono::Utc>,
    duration_ms: u64,
) -> serde_json::Value {
    use serde_json::json;
    let fp = |s: &str| s.chars().take(16).collect::<String>();
    let mut v = match result {
        VerifyResult::Ok {
            rows_verified,
            sessions_total,
            signed_heads_count,
            unsigned_heads_count,
            invalid_signatures_count,
            sessions_with_no_signed_heads,
            signing_key_ids_seen,
            unsigned_tail_max_len,
            schema_drift_records,
        } => json!({
            "result": "ok",
            "rows_verified": rows_verified,
            "sessions_total": sessions_total,
            "signed_heads_count": signed_heads_count,
            "unsigned_heads_count": unsigned_heads_count,
            "invalid_signatures_count": invalid_signatures_count,
            "sessions_with_no_signed_heads": sessions_with_no_signed_heads,
            "signing_key_fingerprints": signing_key_ids_seen.iter().map(|k| fp(k)).collect::<Vec<_>>(),
            "unsigned_tail_max_len": unsigned_tail_max_len,
            "schema_drift": schema_drift_records.len(),
        }),
        VerifyResult::Broken {
            session_id,
            seq,
            expected_hash,
            actual_hash,
            verified_count,
        } => json!({
            "result": "broken",
            "session_id": session_id.as_str(),
            "seq": seq,
            "expected_hash": fp(expected_hash),
            "actual_hash": fp(actual_hash),
            "verified_count": verified_count,
        }),
        VerifyResult::SignatureInvalid {
            session_id,
            seq,
            signing_key_id,
            reason,
            verified_count,
            invalid_signatures_count,
        } => json!({
            "result": "signature_invalid",
            "session_id": session_id.as_str(),
            "seq": seq,
            "signing_key_fingerprint": fp(signing_key_id),
            "reason": reason,
            "verified_count": verified_count,
            "invalid_signatures_count": invalid_signatures_count,
        }),
        VerifyResult::MissingChainHead {
            session_id,
            rows,
            verified_count,
        } => json!({
            "result": "missing_chain_head",
            "session_id": session_id.as_str(),
            "rows": rows,
            "verified_count": verified_count,
        }),
        VerifyResult::Empty => json!({ "result": "empty" }),
    };
    v["started_at"] = serde_json::Value::from(started_at.to_rfc3339());
    v["duration_ms"] = serde_json::Value::from(duration_ms);
    v["anchor"] = serde_json::Value::from("none");
    v["caveat"] = serde_json::Value::from(VERIFY_CAVEAT);
    v
}

/// Parse `POST /api/approvals/{request_id}` and return the
/// request_id. None for any other request line shape. The path
/// segment is URL-decoded with `percent_decode` only insofar as the
/// browser sends a URL-encoded UUID (it does for safety; UUIDs
/// don't contain reserved chars but `encodeURIComponent` is the
/// client-side default). The match is exact-prefix; a slash after
/// the request_id (e.g. trailing path) is rejected.
fn parse_approval_path(first_line: &str) -> Option<String> {
    let rest = first_line.strip_prefix("POST /api/approvals/")?;
    let path = rest.split_whitespace().next()?;
    if path.is_empty() {
        return None;
    }
    // Reject extra path segments after the request_id; UUIDs
    // contain no slashes so any embedded slash is a malformed URL
    // shape.
    if path.contains('/') {
        return None;
    }
    // The browser may URL-encode characters; UUIDs don't need it
    // but `encodeURIComponent` is the default. Cheap decode: only
    // %xx hex pairs need handling, and the UUID alphabet doesn't
    // include any reserved chars beyond hyphens. Pass through.
    Some(path.to_string())
}

/// Whether an `Origin:` value names the WebChat surface itself.
/// Accepted: `http://127.0.0.1:<port>`, `http://localhost:<port>`,
/// `http://[::1]:<port>` for the bound port. No other origin is
/// permitted; in particular any `https://`, any non-loopback host,
/// and any port mismatch are rejected. The check is a string equality
/// against the three accepted forms — no parsing, no DNS, no
/// substring matching.
fn is_webchat_origin(origin: &str, port: u16) -> bool {
    let accepted = [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("http://[::1]:{port}"),
    ];
    accepted.iter().any(|a| a == origin)
}

/// Whether a `Host:` value names the WebChat loopback surface. Accepted:
/// `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>` for the bound
/// port. String equality against the three forms; no parsing, no DNS.
/// A DNS-rebinding page that resolves its own hostname to 127.0.0.1
/// still carries that hostname in `Host:`, so it fails this check.
fn is_webchat_host(host: &str, port: u16) -> bool {
    let accepted = [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ];
    accepted.iter().any(|a| a == host)
}

/// Case-insensitive lookup of a single request header value. The request
/// line has no colon, so it is skipped; header values that contain a
/// colon (like `Host: 127.0.0.1:18790`) keep everything after the first.
fn header_value(request: &str, name_lower: &str) -> Option<String> {
    request.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name_lower) {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

/// Shared preflight for the JSON API routes (`/api/chat`,
/// `/api/approvals/*`, `/api/sessions`, `/api/sessions/*`). Always
/// enforces a Host-header check against loopback names, which is what
/// closes DNS-rebinding reads: a rebound request carries the attacker's
/// hostname in `Host`, not a loopback name, so it is rejected here.
///
/// `require_origin` gates the CSRF Origin check. State-changing routes
/// (`POST /api/chat`, `POST /api/approvals/*`) pass `true`: browsers
/// always send `Origin` on those, and a missing one is rejected unless
/// `WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN` opts non-browser scripts out. Safe
/// reads (`GET /api/sessions[/{id}]`) pass `false`: browsers omit
/// `Origin` on a same-origin GET, so demanding it there 403s the very
/// page that serves the UI — which is why the session sidebar came up
/// empty. A present Origin is validated either way, so a cross-origin
/// caller that does send one is still rejected regardless of method.
///
/// Returns `Some(response)` to send back and stop, or `None` to
/// proceed. `GET /` is not routed here.
fn api_preflight(request: &str, port: u16, require_origin: bool) -> Option<String> {
    let allow_missing_origin =
        wirken_gateway::org::parse_boolean_escape("WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN");
    match header_value(request, "origin").as_deref() {
        Some(o) if is_webchat_origin(o, port) => {}
        Some(_) => return Some(json_forbidden("forbidden origin")),
        None if !require_origin || allow_missing_origin => {}
        None => return Some(json_forbidden("missing origin header")),
    }

    match header_value(request, "host").as_deref() {
        Some(h) if is_webchat_host(h, port) => {}
        Some(_) => return Some(json_forbidden("forbidden host")),
        None => return Some(json_forbidden("missing host header")),
    }

    None
}

/// A 200 response carrying a JSON body.
fn json_ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

/// A 403 response carrying `{"error":"<msg>"}`. `msg` is a fixed literal
/// at every call site, so no escaping is needed.
fn json_conflict(body: &str) -> String {
    format!(
        "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn json_forbidden(msg: &str) -> String {
    let body = format!(r#"{{"error":"{msg}"}}"#);
    format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

/// What an imported-archive read route is asking for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ImportedRoute {
    /// Every source, with what it holds.
    Sources,
    /// One source's conversations.
    Conversations { source_id: String },
    /// One conversation, projected.
    Detail {
        source_id: String,
        conversation_uuid: String,
    },
}

/// Parse the imported-archive read routes.
///
/// `GET /api/imported/sources`
/// `GET /api/imported/sources/{source_id}/conversations`
/// `GET /api/imported/sources/{source_id}/conversations/{conversation_uuid}`
///
/// Identifiers are opaque handles the store issued, so they are taken
/// as data and never as a path: nothing here reaches a filesystem. The
/// segment rules match the session route's for the same reasons, an
/// empty segment, a `..`, or a control byte is refused rather than
/// carried into a query, and the shape is fixed rather than a
/// wildcard, so a longer path is not silently a shorter one.
fn parse_imported_path(first_line: &str) -> Option<ImportedRoute> {
    let rest = first_line.strip_prefix("GET /api/imported/")?;
    let raw = rest.split(' ').next()?;
    if raw == "sources" {
        return Some(ImportedRoute::Sources);
    }
    let decoded = percent_decode(raw)?;
    if decoded.chars().any(|c| c.is_control()) {
        return None;
    }
    let segments: Vec<&str> = decoded.split('/').collect();
    if segments.iter().any(|seg| seg.is_empty() || *seg == "..") {
        return None;
    }
    match segments.as_slice() {
        ["sources", source_id, "conversations"] => Some(ImportedRoute::Conversations {
            source_id: (*source_id).to_string(),
        }),
        ["sources", source_id, "conversations", conversation_uuid] => Some(ImportedRoute::Detail {
            source_id: (*source_id).to_string(),
            conversation_uuid: (*conversation_uuid).to_string(),
        }),
        _ => None,
    }
}

/// Parse `GET /api/sessions/{id}` and return the composite session id
/// (`{agent}/{channel}/{conversation}`). The page URL-encodes the id
/// with `encodeURIComponent`, so its `/` separators arrive as `%2F`;
/// this decodes them back. Returns None for the bare `GET /api/sessions`
/// list route, an empty id, a malformed `%`-escape, or any id with an
/// empty or `..` path segment (traversal) or a control byte.
fn parse_session_path(first_line: &str) -> Option<String> {
    let rest = first_line.strip_prefix("GET /api/sessions/")?;
    // Split on the first space so an empty path (`/api/sessions/ `)
    // yields an empty token rather than skipping to the HTTP version.
    let raw = rest.split(' ').next()?;
    if raw.is_empty() {
        return None;
    }
    let decoded = percent_decode(raw)?;
    // The composite id is exactly `<agent>/<channel>/<conversation>`:
    // non-empty segments only. Reject empty segments (leading, trailing,
    // or doubled slash), `..` traversal, and control bytes.
    if decoded.is_empty() {
        return None;
    }
    if decoded.split('/').any(|seg| seg.is_empty() || seg == "..") {
        return None;
    }
    if decoded.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(decoded)
}

/// Minimal percent-decoder for the `%XX` sequences `encodeURIComponent`
/// produces. Returns None on a malformed escape or non-UTF-8 result.
/// `+` is left as a literal `+` (this is a path segment, not a query
/// string).
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = hex_val(*bytes.get(i + 1)?)?;
            let lo = hex_val(*bytes.get(i + 2)?)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Mutex;
    use wirken_audit::AlarmLog;
    use wirken_gateway::adapter_registry::AdapterRegistry;
    use wirken_gateway::pending_approvals::PendingApprovalQueue;

    use super::{
        DECISION_WRONG_CONVERSATION, HTML, ImportedRoute, OpenTurns, SiemSummary, SkillSignature,
        StatusInputs, TURN_OPEN_ERROR, VERIFY_CAVEAT, api_preflight,
        approval_belongs_to_conversation, approval_belongs_to_webchat, approvals_snapshot_for,
        capabilities_snapshot, conversation_key, conversation_of, conversation_rows,
        credentials_snapshot, events_route_allowed, is_webchat_host, is_webchat_origin,
        parse_approval_path, parse_imported_path, parse_session_events_path, parse_session_path,
        percent_decode, query_param, session_events, skill_frontmatter, skill_signature_word,
        status_snapshot, tool_tier_entry, verify_result_json, webchat_session_id,
    };

    #[test]
    fn approval_path_parses_request_id() {
        let line = "POST /api/approvals/9b8f1c0a-1234-4abc-9def-0123456789ab HTTP/1.1";
        assert_eq!(
            parse_approval_path(line).as_deref(),
            Some("9b8f1c0a-1234-4abc-9def-0123456789ab")
        );
    }

    #[test]
    fn approval_path_rejects_non_post() {
        assert!(parse_approval_path("GET /api/approvals/abc HTTP/1.1").is_none());
    }

    #[test]
    fn approval_path_rejects_unrelated_endpoints() {
        assert!(parse_approval_path("POST /api/chat HTTP/1.1").is_none());
        assert!(parse_approval_path("POST / HTTP/1.1").is_none());
    }

    #[test]
    fn approval_path_rejects_empty_request_id() {
        assert!(parse_approval_path("POST /api/approvals/ HTTP/1.1").is_none());
    }

    #[test]
    fn approval_path_rejects_extra_segments() {
        // UUIDs don't contain slashes; an embedded slash is a
        // malformed URL shape and the parser rejects it so the
        // 404 path catches the bad request instead of routing
        // into the approval handler with a corrupt id.
        assert!(parse_approval_path("POST /api/approvals/abc/extra HTTP/1.1").is_none());
    }

    #[test]
    fn accepts_loopback_origins_at_bound_port() {
        assert!(is_webchat_origin("http://127.0.0.1:18790", 18790));
        assert!(is_webchat_origin("http://localhost:18790", 18790));
        assert!(is_webchat_origin("http://[::1]:18790", 18790));
    }

    #[test]
    fn rejects_external_origins() {
        // The CSRF threat: attacker.com posts cross-origin to the
        // WebChat surface; the browser sends Origin: https://attacker.com.
        assert!(!is_webchat_origin("https://attacker.com", 18790));
        assert!(!is_webchat_origin("http://attacker.com", 18790));
        assert!(!is_webchat_origin("https://localhost:18790", 18790));
    }

    #[test]
    fn rejects_port_mismatch() {
        // An operator bound to a non-default port should not
        // accept the default-port origin.
        assert!(!is_webchat_origin("http://127.0.0.1:18790", 9999));
        assert!(!is_webchat_origin("http://localhost:18791", 18790));
    }

    #[test]
    fn rejects_substring_attacks() {
        // Defensive against substring-prefix shenanigans like
        // `http://127.0.0.1:18790.attacker.com`.
        assert!(!is_webchat_origin(
            "http://127.0.0.1:18790.attacker.com",
            18790
        ));
        assert!(!is_webchat_origin(
            "http://attacker.com/?127.0.0.1:18790",
            18790
        ));
    }

    #[test]
    fn session_path_parses_and_decodes_composite_id() {
        // The page URL-encodes the composite id, so the `/` separators
        // arrive as `%2F` and the parser decodes them back.
        let line = "GET /api/sessions/default%2Fwebchat%2Fwebchat-default HTTP/1.1";
        assert_eq!(
            parse_session_path(line).as_deref(),
            Some("default/webchat/webchat-default")
        );
    }

    /// The page script, so a test can assert about it. The page is a
    /// string constant, so nothing compiles it and no Rust error can
    /// find a mistake in it; these assertions are what stand in.
    fn page_script() -> &'static str {
        let start = HTML.find("<script>").expect("the page has a script") + "<script>".len();
        let end = HTML.find("</script>").expect("the script is closed");
        &HTML[start..end]
    }

    /// Assignments to a property, ignoring reads. `x.foo = ` and
    /// `x.foo += ` count; `y = x.foo` does not.
    fn assignments_to(script: &str, property: &str) -> Vec<String> {
        script
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//")
                    && (line.contains(&format!("{property} ="))
                        || line.contains(&format!("{property} +=")))
            })
            .map(|l| l.trim().to_string())
            .collect()
    }

    #[test]
    fn one_helper_is_the_sole_path_from_a_value_to_the_dom() {
        // The control that makes imported text inert is that it
        // becomes textContent. If a second place assigned textContent,
        // "everything goes through setText" would be a convention
        // rather than a fact, and a convention is kept by remembering.
        let script = page_script();
        let assignments = assignments_to(script, ".textContent");
        assert_eq!(
            assignments.len(),
            1,
            "textContent must be assigned in exactly one place: {assignments:#?}"
        );
        assert!(
            assignments[0].starts_with("el.textContent ="),
            "the one assignment is the helper's: {}",
            assignments[0]
        );
        assert!(
            script.contains("function setText(el, value)"),
            "the helper exists under the name the assertion assumes"
        );
    }

    #[test]
    fn no_markup_sink_ever_receives_a_value() {
        let script = page_script();

        // innerHTML clears containers and does nothing else. An empty
        // literal cannot carry a payload; anything else can.
        for line in assignments_to(script, ".innerHTML") {
            assert!(
                line.ends_with("innerHTML = '';"),
                "innerHTML may only be assigned an empty literal: {line}"
            );
        }

        // These have no safe form here, so they are absent outright
        // rather than conditionally allowed.
        for sink in ["insertAdjacentHTML", "outerHTML", "document.write"] {
            let hits: Vec<&str> = script
                .lines()
                .filter(|l| l.contains(sink) && !l.trim_start().starts_with("//"))
                .collect();
            assert!(hits.is_empty(), "{sink} appears in the page: {hits:#?}");
        }
    }

    /// The archive views say what they are. Every value out of an
    /// archive reaches the DOM through the one helper (the two
    /// assertions above cover that); these strings are the view's own
    /// claims about itself, which a redesign must keep.
    #[test]
    fn the_imported_views_say_what_they_are() {
        let script = page_script();
        assert!(
            script.contains("A stored record, shown read-only."),
            "an archive view must say it is a stored record"
        );
        assert!(
            script.contains("stored content blocks are not shown here"),
            "the detail view must say it is a projection"
        );
    }

    /// A composer under a stored record affords a send that in fact
    /// starts a live agent turn. One switch owns whether the composer
    /// is on screen; every archive view turns it off; the bar that
    /// replaces it carries the way back; and `hidden` really hides.
    #[test]
    fn a_non_writable_view_takes_the_composer_away_and_leaves_a_way_back() {
        let script = page_script();
        // One function owns both the composer and its replacement.
        let composer_writes = assignments_to(script, "composer.hidden");
        let bar_writes = assignments_to(script, "readonlyBar.hidden");
        assert_eq!(
            composer_writes.len(),
            1,
            "one place hides the composer: {composer_writes:#?}"
        );
        assert_eq!(
            bar_writes.len(),
            1,
            "one place shows the way back: {bar_writes:#?}"
        );
        // Toggled together, in opposite directions, by the same value.
        assert!(
            composer_writes[0].contains("!== null"),
            "{}",
            composer_writes[0]
        );
        assert!(bar_writes[0].contains("=== null"), "{}", bar_writes[0]);
        // Both archive views go through that switch with the notice.
        assert_eq!(
            script.matches("setReadOnly(ARCHIVE_NOTICE)").count(),
            2,
            "both archive views take the composer away"
        );
        // The property has to reach the screen: an id selector lays
        // the composer out, which outranks the UA's [hidden] rule.
        assert!(
            HTML.contains("[hidden] { display: none !important; }"),
            "an author-level [hidden] rule must outrank the id selectors"
        );
        // The way back exists and returns to the conversation this
        // browser writes to.
        assert!(
            HTML.contains("Back to the conversation"),
            "the bar carries the way back"
        );
        assert!(
            script.contains("backToLive.addEventListener('click'")
                && script.contains("loadTranscript(currentLogId())"),
            "the way back returns to the conversation this page writes to"
        );
    }

    /// Every event the gateway can push into this page's SSE stream
    /// has a branch here that does something with it.
    ///
    /// The page reads `event.type`, and `SseEvent` is tagged
    /// `#[serde(tag = "type", rename_all = "snake_case")]`, so the
    /// wire strings are the variant names in snake_case. An event the
    /// gateway sends and this page ignores is invisible from both
    /// ends: the server logs a successful write and the operator sees
    /// nothing at all.
    #[test]
    fn every_sse_event_the_gateway_sends_has_a_handler_here() {
        let script = page_script();
        for kind in [
            "approval_request",
            "approval_decision_ack",
            // Emitted by the agent loop's forwarder rather than by
            // SseEvent, on the same stream and read by the same code.
            "delta",
            "error",
            // Emitted by this handler once the outbound row has been
            // offered to the writer. Its absence is what the page
            // reads as a cut-off stream.
            "done",
        ] {
            assert!(
                script.contains(&format!("event.type === '{kind}'")),
                "the page must branch on '{kind}'; an unhandled event \
                 is dropped silently",
            );
        }
        // Branching is not handling. The approval branch has to build
        // the card, the ack branch has to resolve it, and the card has
        // to reach the document.
        assert!(script.contains("renderApproval(event)"));
        assert!(script.contains("ackApproval(event.request_id, event.result)"));
        assert!(script.contains("thread.appendChild(card)"));
        // And the handler really emits the done event the page waits
        // for, in the same wire shape as everything else.
        assert!(
            SERVER_SOURCE.contains(r#"data: {\"type\":\"done\"}\n\n"#),
            "the chat handler must emit a done event before the socket closes"
        );
    }

    /// The composer is on screen only for the conversation it writes
    /// to. `send` posts to /api/chat, which always resolves the one
    /// canonical webchat conversation whatever the pane is showing.
    #[test]
    fn the_composer_is_absent_for_a_session_it_does_not_write_to() {
        let script = page_script();
        assert!(
            script.contains("setReadOnly(id === currentLogId() ? null : OTHER_SESSION_NOTICE)"),
            "loading a transcript decides from the session it is showing",
        );
        assert!(
            script.contains("const OTHER_SESSION_NOTICE ="),
            "a session that is not the composer's says so in its own words",
        );
    }

    /// The rail is refreshed however the transcript load ends.
    ///
    /// It used to be refreshed only after a successful fetch, so a
    /// transcript that failed to load left the rail holding whatever
    /// it had. A `finally` is the one shape that covers every exit.
    #[test]
    fn a_failed_transcript_load_still_refreshes_the_rail() {
        let body = page_script()
            .split_once("async function loadTranscript(id) {")
            .expect("loadTranscript exists")
            .1
            .split_once("\n}")
            .expect("loadTranscript closes")
            .0;
        let finally = body
            .split_once("finally {")
            .expect("loadTranscript refreshes in a finally block")
            .1;
        assert!(
            finally.contains("loadRail()"),
            "the finally block refreshes the rail"
        );
    }

    /// A message the store holds no text for is labelled, not drawn
    /// blank. Real archives carry these in quantity.
    #[test]
    fn a_message_with_no_stored_text_says_so() {
        let script = page_script();
        assert!(
            script.contains(".trim() === ''"),
            "the detail view must test for a text-less message",
        );
        assert!(
            script.contains("'no text stored for this message'"),
            "and label it rather than draw an empty span",
        );
    }

    /// The handler source, so a test can pin what the server puts on
    /// the wire next to what the page expects from it.
    const SERVER_SOURCE: &str = include_str!("webchat.rs");

    /// A refusal is its own block, never red text spliced into the
    /// assistant's sentence. The page recognises a sandbox refusal by
    /// the prefix the agent crate puts on that error; if the prefix
    /// changes upstream, this is what fails.
    #[test]
    fn a_sandbox_refusal_is_recognised_by_its_prefix() {
        let script = page_script();
        let line = script
            .lines()
            .find(|l| l.contains("const REFUSAL_PREFIX ="))
            .expect("the page names the refusal prefix");
        let prefix = line
            .split_once('\'')
            .and_then(|(_, rest)| rest.split_once('\''))
            .map(|(p, _)| p)
            .expect("the prefix is a single-quoted literal");
        let rendered = wirken_agent::AgentError::Sandbox("x".into()).to_string();
        assert!(
            rendered.starts_with(prefix),
            "the agent renders a sandbox refusal as {rendered:?}; the page expects {prefix:?}"
        );
        // The block shows the reason only: the agent's text goes on to
        // say how to weaken the sandbox, and that belongs in the CLI.
        let refusal = script
            .split_once("function addRefusal(text) {")
            .expect("addRefusal exists")
            .1
            .split_once(
                "
}",
            )
            .unwrap()
            .0;
        assert!(
            refusal.contains("firstClause(text)"),
            "the refusal body is cut to its first clause: {refusal}"
        );
        assert!(script.contains("function firstClause("));
    }

    /// A refused request is not a sent message: on any non-2xx the
    /// page takes the bubble back out and returns the text to the
    /// composer, and a 503 from a halted writer locks the composer.
    #[test]
    fn a_refused_request_is_not_a_sent_message() {
        let script = page_script();
        let body = script
            .split_once("if (!res.ok) {")
            .expect("send handles a non-ok response")
            .1;
        let head: String = body.lines().take(8).collect::<Vec<_>>().join("\n");
        assert!(
            head.contains("userNode.remove()"),
            "the bubble comes back out: {head}"
        );
        assert!(
            head.contains("input.value = text"),
            "the text goes back to the composer: {head}"
        );
        assert!(
            head.contains("res.status === 503"),
            "a halted writer is its own state: {head}"
        );
        assert!(script.contains("function setHalted()"));
        // And the server really answers 503 when the writer refuses the
        // inbound row.
        assert!(SERVER_SOURCE.contains("HTTP/1.1 503 Service Unavailable"));
    }

    /// The page fetches nothing from anywhere but its own origin: no
    /// fonts, no CDN, no favicon round-trip. Air-gapped installs are a
    /// deployment target.
    #[test]
    fn the_page_makes_no_external_requests() {
        assert!(!HTML.contains("https://"), "no external URL in the page");
        assert!(!HTML.contains("http://"), "no external URL in the page");
        assert!(
            HTML.contains("rel=\"icon\" href=\"data:image/svg+xml;base64,"),
            "the favicon is inline"
        );
        assert_eq!(
            HTML.matches("<script>").count(),
            1,
            "one script block; page_script reads the first"
        );
        assert_eq!(HTML.matches("<style>").count(), 1, "one style block");
    }

    /// The literal delimiter is `r#"…"#`, so the page can never contain
    /// the two-character sequence that would end it. The failure mode
    /// without this is a compile error somewhere else entirely.
    #[test]
    fn the_page_never_contains_the_literal_terminator() {
        assert!(!HTML.contains("\"#"));
    }

    fn status_inputs_for(dir: &std::path::Path, siem: Option<SiemSummary>) -> StatusInputs {
        StatusInputs {
            registry: Arc::new(Mutex::new(
                AdapterRegistry::open(&dir.join("adapters.db")).expect("registry opens"),
            )),
            alarm_log: Arc::new(AlarmLog::new(dir)),
            alarm_key_loaded: false,
            siem,
        }
    }

    fn cfg_at(dir: &std::path::Path) -> wirken_gateway::config::GatewayConfig {
        wirken_gateway::config::GatewayConfig {
            data_dir: dir.to_path_buf(),
            ..wirken_gateway::config::GatewayConfig::default()
        }
    }

    /// A value the gateway does not hold is null, never a default that
    /// reads as an answer. On an empty data directory the snapshot
    /// says exactly what is there: a sandbox file, and nothing else.
    #[tokio::test]
    async fn status_snapshot_reports_only_what_the_gateway_holds() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("sandbox.json"), r#"{"mode":"off"}"#).unwrap();
        let cfg = cfg_at(dir.path());
        let snap = status_snapshot(&cfg, 18790, &status_inputs_for(dir.path(), None), false).await;

        assert_eq!(snap["gateway"]["port"], 18790);
        assert_eq!(snap["sandbox"]["mode"], "off");
        assert!(
            snap["sandbox"]["runtime"].is_null(),
            "no runtime when exec runs on the host"
        );
        assert!(
            snap["sandbox"]["docker_reachable"].is_null(),
            "never probed here"
        );
        assert_eq!(snap["escape_hatches"]["sandbox_mode_off"], true);
        assert!(
            snap["agent"]["provider"].is_null(),
            "no agent row and no provider.json"
        );
        assert!(snap["agent"]["source"].is_null());
        assert_eq!(snap["egress"]["channel"], "webchat");
        assert_eq!(snap["adapters"], serde_json::json!([]));
        assert_eq!(snap["siem"]["configured"], false);
        assert_eq!(snap["org"]["configured"], false);
        assert_eq!(snap["audit"]["writer_halted"], false);
        assert!(snap["audit"]["signing_pubkey_fingerprint"].is_null());
        let alarms = &snap["audit"]["alarms"];
        assert!(
            alarms.is_null() || alarms.as_array().map(|a| a.is_empty()).unwrap_or(false),
            "no alarm records on a fresh directory: {alarms}"
        );
        assert!(snap["hooks"].is_null(), "hook counts are not plumbed yet");
    }

    /// The snapshot never carries key material, provider endpoints,
    /// regions, host paths, or a SIEM endpoint path. Checked on the
    /// serialized text and on every key name in the tree.
    #[tokio::test]
    async fn status_snapshot_carries_no_secrets_or_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("provider.json"),
            r#"{"provider":"custom","model":"m-1","base_url":"https://internal.example:8443/v1",
                "api_key":"sk-live-secret","api_key_name":"provider-key","region":"eu-west-9"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("sandbox.json"),
            r#"{"mode":"exec-only","sidecar_binary":"/opt/secret/path/wirken"}"#,
        )
        .unwrap();
        let siem = Some(SiemSummary {
            target: "sentinel".into(),
            typed_pipe: true,
        });
        let cfg = cfg_at(dir.path());
        let snap = status_snapshot(&cfg, 18790, &status_inputs_for(dir.path(), siem), false).await;
        let text = serde_json::to_string(&snap).unwrap();
        for forbidden in [
            "sk-live-secret",
            "internal.example",
            "eu-west-9",
            "/opt/secret",
        ] {
            assert!(!text.contains(forbidden), "{forbidden} leaked: {text}");
        }
        assert_eq!(
            snap["agent"]["api_key_credential"], "provider-key",
            "the slot name is fine"
        );
        assert_eq!(snap["agent"]["source"], "provider.json");

        fn keys(v: &serde_json::Value, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(m) => {
                    for (k, v) in m {
                        out.push(k.clone());
                        keys(v, out);
                    }
                }
                serde_json::Value::Array(a) => a.iter().for_each(|v| keys(v, out)),
                _ => {}
            }
        }
        let mut all = Vec::new();
        keys(&snap, &mut all);
        for forbidden in [
            "api_key",
            "base_url",
            "region",
            "sidecar_binary",
            "hmac_secret",
            "endpoint",
            "endpoint_host",
            "url_host",
            "hostname",
            "gateway_pid",
        ] {
            assert!(
                !all.iter().any(|k| k == forbidden),
                "key {forbidden} present: {all:?}"
            );
        }

        // No value shaped like a hostname either: dot-separated
        // lowercase labels with a letter somewhere, that is not a
        // version number or a file name. A host is where something
        // is, and the page has no use for where anything is.
        fn strings(v: &serde_json::Value, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(m) => m.values().for_each(|v| strings(v, out)),
                serde_json::Value::Array(a) => a.iter().for_each(|v| strings(v, out)),
                serde_json::Value::String(s) => out.push(s.clone()),
                _ => {}
            }
        }
        let mut values = Vec::new();
        strings(&snap, &mut values);
        assert!(!values.is_empty());
        for value in &values {
            let labels: Vec<&str> = value.split('.').collect();
            if labels.len() < 2 {
                continue;
            }
            let label_shaped = labels.iter().all(|l| {
                !l.is_empty()
                    && l.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            });
            let last = labels[labels.len() - 1];
            let file_name = ["json", "db", "toml", "md", "log", "txt"].contains(&last);
            let version = last.chars().all(|c| c.is_ascii_digit());
            let has_letter = value.chars().any(|c| c.is_ascii_alphabetic());
            assert!(
                !(label_shaped && has_letter && !file_name && !version),
                "hostname-shaped value in the snapshot: {value}"
            );
        }
        let script = page_script();
        assert!(
            !script.contains("endpoint_host") && !script.contains("url_host"),
            "the page reads no host"
        );
    }

    /// A count of alarms is drawn only when the log was read. No file
    /// is no alarms; a file that cannot be read is unknown, and the
    /// page draws the null as such rather than as zero.
    #[tokio::test]
    async fn an_unreadable_alarm_log_is_unknown_not_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = cfg_at(dir.path());
        let snap = status_snapshot(&cfg, 18790, &status_inputs_for(dir.path(), None), false).await;
        assert_eq!(
            snap["audit"]["alarms"],
            serde_json::json!([]),
            "no file is no alarms"
        );
        std::fs::create_dir(dir.path().join("audit-alarms.log")).unwrap();
        let snap = status_snapshot(&cfg, 18790, &status_inputs_for(dir.path(), None), false).await;
        assert!(
            snap["audit"]["alarms"].is_null(),
            "an unreadable log is unknown"
        );
        assert!(page_script().contains(
            "Array.isArray(audit.alarms) ? el('span', null, audit.alarms.length + ' alarms on disk') : unknownNode()"
        ));
    }

    #[test]
    fn siem_summary_keeps_the_target_only() {
        let cfg = wirken_audit::siem::SiemConfig {
            target: wirken_audit::siem::SiemTarget::Sentinel,
            endpoint: "https://dce-abc.eastus-1.ingest.monitor.azure.com/dataCollectionRules/dcr-secret-id/streams/Custom-X?api-version=2023-01-01".into(),
            api_key: "bearer-secret".into(),
            service: "wirken".into(),
            environment: "prod".into(),
            hmac_secret: Some("hmac-secret".into()),
            sentinel_typed: None,
            typed_include_variants: None,
            typed_exclude_variants: None,
            typed_forwarding_enabled: Some(true),
            typed_poll_interval_ms: None,
        };
        let s = SiemSummary::from_config(&cfg);
        assert_eq!(s.target, "sentinel");
        assert!(s.typed_pipe);
        // Where it ships to is an endpoint: host, path and query all
        // stay in the config file.
        let debug = format!("{s:?}");
        for withheld in ["secret", "dcr-", "azure", "ingest", "eastus"] {
            assert!(!debug.contains(withheld), "{withheld} in {debug}");
        }
    }

    /// The six boolean hatches the status route reports are the six the
    /// page has copy for; a hatch added on one side without the other
    /// would be engaged and invisible.
    #[test]
    fn every_reported_escape_hatch_has_copy_on_the_page() {
        let script = page_script();
        let snapshot_fn = SERVER_SOURCE
            .split_once("pub async fn status_snapshot(")
            .expect("status_snapshot exists")
            .1;
        for name in [
            "WIRKEN_ALLOW_UNSIGNED_ORG_CONFIG",
            "WIRKEN_ALLOW_UNSIGNED_SKILLS",
            "WIRKEN_ALLOW_UNSIGNED_MCP",
            "WIRKEN_ALLOW_STALE_ORG_CONFIG",
            "WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN",
            "WIRKEN_ALLOW_UNREGISTERED_HOOKS",
        ] {
            assert!(
                snapshot_fn.contains(&format!("\"{name}\": parse_boolean_escape(\"{name}\")")),
                "route reports {name}"
            );
            assert!(
                script.contains(&format!("{name}: '")),
                "page has copy for {name}"
            );
        }
        assert!(
            script.contains("h.sandbox_mode_off"),
            "the sandbox-off hatch has its own banner"
        );
        assert!(
            script.contains("skill_registry_root_pinned"),
            "the unsigned-skills banner is suppressed under a pinned root"
        );
        assert!(script.contains("Clears when the gateway restarts without it."));
    }

    /// Unknown is one renderer, one colour, and the strip is empty until
    /// a snapshot arrives rather than drawn with defaults.
    #[test]
    fn unknown_is_one_renderer_and_the_strip_waits_for_a_snapshot() {
        let script = page_script();
        assert!(script.contains("function unknownNode("));
        assert!(HTML.contains(".unknown { color: var(--accent-300); }"));
        assert!(HTML.contains(r#"<div id="status-values" hidden>"#));
        assert!(
            script.contains("acknowledge with wirken audit acknowledge --all"),
            "the alarm strip names the CLI verb"
        );
        assert!(
            script.contains("agent budget · all channels"),
            "the budget figure says whose it is"
        );
    }

    /// The Tier 2 chip and the Tier 2 shell sentence describe one fact,
    /// the absence of a live grant, and use one term for it. The chip's
    /// wording is the gate's own.
    #[test]
    fn the_tier_two_chip_and_sentence_use_one_term() {
        let script = page_script();
        assert!(
            script.contains("'Tier 2 · no live grant'"),
            "the chip names the gate's finding"
        );
        assert!(
            script.contains("'Read-only shell command with no live grant.'"),
            "the sentence uses the chip's term"
        );
        assert!(!script.contains("standing grant"), "one term for one fact");
    }

    /// Rule 1: a value the gateway does not hold is omitted from the
    /// strip and named as unknown in the panel. The strip's renderer
    /// never reaches for the unknown node; the panel's does, and it
    /// has a row for every value the strip may leave out.
    #[test]
    fn nulls_leave_a_gap_in_the_strip_and_are_named_in_the_panel() {
        let script = page_script();
        let strip = script
            .split_once("function renderStatusValues() {")
            .expect("strip renderer exists")
            .1
            .split_once("\n}")
            .expect("strip renderer closes")
            .0;
        assert!(
            !strip.contains("unknownNode("),
            "the strip never draws unknown: {strip}"
        );
        assert!(
            !strip.contains("'unknown'"),
            "the strip never writes the word: {strip}"
        );
        for gate in [
            "if (agent.model)",
            "if (sandbox.mode)",
            "if (egress.mode)",
            "isSet(budget.remaining_usd_micros)",
        ] {
            assert!(strip.contains(gate), "the strip omits on {gate}");
        }
        let panel = script
            .split_once("function renderAbout() {")
            .expect("panel renderer exists")
            .1
            .split_once("\n}")
            .expect("panel renderer closes")
            .0;
        assert!(panel.contains("unknownNode("), "the panel names unknowns");
        for row in [
            "'agent'",
            "'budget'",
            "'sandbox'",
            "'egress'",
            "'adapters'",
            "'SIEM'",
            "'org config'",
            "'audit'",
            "'threats'",
        ] {
            assert!(
                panel.contains(&format!("kvRow(grid, {row}")),
                "the panel has a row for {row}"
            );
        }
        assert!(
            !panel.contains("el('span', null, 'unknown')"),
            "unknown goes through the one renderer"
        );
        // The vault and the capabilities are rows of the same panel,
        // drawn by their own renderers once their routes answer.
        assert!(
            panel.contains("renderCapabilityRows(grid)") && panel.contains("renderVaultRows(grid)")
        );
        for row in ["'tools'", "'grants'", "'skills'", "'vault'", "'connectors'"] {
            assert!(
                script.contains(&format!("kvRow(grid, {row}, pendingNode(")),
                "{row} is named unknown when its route does not answer"
            );
        }
        assert!(script.contains("if (state === 'fetching') return el('span', 'hedge', 'fetching');\n  return unknownNode();"));
    }

    #[test]
    fn session_events_path_parses_id_and_after() {
        assert_eq!(
            parse_session_events_path(
                "GET /api/sessions/default%2Fwebchat%2Fwebchat-default/events HTTP/1.1"
            ),
            Some(("default/webchat/webchat-default".into(), None))
        );
        assert_eq!(
            parse_session_events_path(
                "GET /api/sessions/default%2Fwebchat%2Fc1/events?after=41 HTTP/1.1"
            ),
            Some(("default/webchat/c1".into(), Some(41)))
        );
        // Not this route: the bare transcript, a malformed after, traversal.
        assert!(
            parse_session_events_path("GET /api/sessions/default%2Fwebchat%2Fc1 HTTP/1.1")
                .is_none()
        );
        assert!(
            parse_session_events_path(
                "GET /api/sessions/default%2Fwebchat%2Fc1/events?after=x HTTP/1.1"
            )
            .is_none()
        );
        assert!(
            parse_session_events_path("GET /api/sessions/..%2Fx%2Fy/events HTTP/1.1").is_none()
        );
        assert!(parse_session_events_path("GET /api/sessions//events HTTP/1.1").is_none());
    }

    #[test]
    fn session_events_are_served_for_webchat_sessions_only() {
        assert!(events_route_allowed("default/webchat/webchat-default"));
        assert!(events_route_allowed("other/webchat/c1"));
        assert!(!events_route_allowed("default/telegram/-1001234"));
        assert!(!events_route_allowed("default/webchat/"));
        assert!(!events_route_allowed("__system__"));
    }

    /// The projection carries the rows the transcript dropped, in order,
    /// with the tier recomputed from the stored arguments, outputs
    /// stripped of control sequences, a timeout denial marked as such,
    /// and totals over the whole session. The system prompt never
    /// appears.
    #[test]
    fn session_events_project_the_whitelisted_kinds() {
        use wirken_audit::{
            DenialSource, SessionEvent, SessionId, SessionLog, SqliteSessionLog, ToolCallRecord,
            TrustLevel,
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = cfg_at(dir.path());
        let log = SqliteSessionLog::open(&cfg.audit_db_path()).expect("log opens");
        let id = "default/webchat/webchat-default";
        let handle = log.handle_for(SessionId::new(id.to_string()));
        let agent = || "default".to_string();
        let rows = vec![
            (
                TrustLevel::User,
                SessionEvent::UserMessage {
                    content: "hi".into(),
                    inbound_id: None,
                    adapter_id: None,
                    sender_id: None,
                },
            ),
            (
                TrustLevel::System,
                SessionEvent::SystemPromptSet {
                    content: "PROMPT BODY".into(),
                    agent_id: agent(),
                },
            ),
            (
                TrustLevel::System,
                SessionEvent::AssistantToolCalls {
                    calls: vec![
                        ToolCallRecord {
                            id: "c1".into(),
                            name: "exec".into(),
                            arguments: r#"{"command":"ls -la /tmp"}"#.into(),
                        },
                        ToolCallRecord {
                            id: "c2".into(),
                            name: "read_file".into(),
                            arguments: r#"{"path":"notes.txt"}"#.into(),
                        },
                    ],
                    agent_id: agent(),
                    adapter_id: None,
                    sender_id: None,
                },
            ),
            (
                TrustLevel::Tool,
                SessionEvent::ToolResult {
                    call_id: "c1".into(),
                    tool_name: "exec".into(),
                    output: "\u{1b}[31mred\u{1b}[0m".into(),
                    success: true,
                    agent_id: agent(),
                    adapter_id: None,
                    sender_id: None,
                },
            ),
            (
                TrustLevel::System,
                SessionEvent::PermissionDenied {
                    tool: "exec".into(),
                    action_key: "shell:rm".into(),
                    denial_source: DenialSource::Tier,
                    tier: Some("tier3".into()),
                    agent_id: agent(),
                    trigger: None,
                    denied_via: None,
                    denial_reason: Some("approval timeout".into()),
                    adapter_id: None,
                    sender_id: None,
                },
            ),
            (
                TrustLevel::System,
                SessionEvent::LlmResponse {
                    request_id: "r1".into(),
                    finish_reason: "stop".into(),
                    input_tokens: 100,
                    output_tokens: 20,
                    cache_creation_input_tokens: 0,
                    cache_read_input_tokens: 0,
                    latency_ms: 500,
                    agent_id: agent(),
                    credential_id: None,
                    input_cost_usd_micros: Some(10),
                    output_cost_usd_micros: Some(5),
                    total_cost_usd_micros: Some(15),
                    sender_id: None,
                },
            ),
            (
                TrustLevel::System,
                SessionEvent::AssistantMessage {
                    content: "done".into(),
                    agent_id: agent(),
                },
            ),
        ];
        for (trust, ev) in rows {
            log.append(&handle, trust, ev).expect("append");
        }

        let v = session_events(&cfg, id, None);
        let kinds: Vec<&str> = v["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["kind"].as_str().unwrap())
            .collect();
        assert_eq!(
            kinds,
            [
                "user_message",
                "assistant_tool_calls",
                "tool_result",
                "permission_denied",
                "llm_response",
                "assistant_message"
            ]
        );
        let calls = &v["events"][1]["calls"];
        assert_eq!(calls[0]["computed_tier"], "tier2");
        assert_eq!(calls[0]["action_key"], "shell:ls");
        assert_eq!(calls[1]["computed_tier"], "tier1");
        assert_eq!(
            v["events"][2]["output"], "red",
            "control sequences are stripped"
        );
        assert!(
            v["events"][2]["elapsed_ms_approx"].is_number(),
            "elapsed is the row-timestamp delta"
        );
        assert_eq!(v["events"][3]["timed_out"], true);
        assert_eq!(v["totals"]["input_tokens"], 100);
        assert_eq!(v["totals"]["output_tokens"], 20);
        assert_eq!(v["totals"]["cost_usd_micros"], 15);
        assert_eq!(v["totals"]["cost_known"], true);
        assert_eq!(v["totals"]["tool_calls"], 2);
        assert_eq!(v["totals"]["llm_calls"], 1);
        assert_eq!(v["head"]["seq"], 6);
        let text = serde_json::to_string(&v).unwrap();
        assert!(
            !text.contains("PROMPT BODY"),
            "the system prompt is withheld"
        );
        for forbidden in [
            "messages_hash",
            "tools_hash",
            "\"signature\"",
            "signing_pubkey",
            "sender_id",
        ] {
            assert!(!text.contains(forbidden), "{forbidden} leaked");
        }

        // `after` filters rows but not the totals.
        let tail = session_events(&cfg, id, Some(3));
        let seqs: Vec<u64> = tail["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(seqs, [4, 5, 6]);
        assert_eq!(tail["totals"]["tool_calls"], 2);
    }

    /// Every kind the projection emits has a renderer branch on the
    /// page, and the word "recorded" is said only by the row renderer:
    /// an ack means accepted, a row means recorded.
    #[test]
    fn every_projected_kind_has_a_renderer_and_recorded_needs_a_row() {
        let script = page_script();
        let projection = SERVER_SOURCE
            .split_once("pub fn session_events(")
            .expect("session_events exists")
            .1;
        let mut kinds: Vec<&str> = projection
            .match_indices("\"kind\": \"")
            .map(|(i, _)| {
                let rest = &projection[i + 9..];
                rest.split('"').next().unwrap()
            })
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert!(kinds.len() >= 15, "found kinds: {kinds:?}");
        for kind in &kinds {
            assert!(
                script.contains(&format!("case '{kind}':")),
                "the page has no renderer for {kind}"
            );
        }
        let ack = script
            .split_once("function ackApproval(")
            .expect("ackApproval exists")
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(
            !ack.contains("recorded"),
            "an ack must not say recorded: {ack}"
        );
        assert!(script.contains("' · recorded'"), "a row says recorded");
    }

    /// The acknowledgement draws "accepted"; only a decision row on the
    /// poll can turn that into "recorded". Structurally: the ack
    /// renderer writes the accepted line, the one function that
    /// replaces a decision line is called only from the two decision
    /// row cases, and the poll loop never touches decision lines
    /// itself.
    #[test]
    fn accepted_flips_to_recorded_only_when_the_row_arrives() {
        let script = page_script();
        let body = |name: &str| {
            script
                .split_once(name)
                .unwrap_or_else(|| panic!("{name} exists"))
                .1
                .split_once("\n}")
                .unwrap()
                .0
                .to_string()
        };
        let ack = body("function ackApproval(");
        assert!(ack.contains("'accepted'"), "the ack draws accepted: {ack}");
        assert!(
            ack.contains("decisionLines.set("),
            "the ack line is kept so a row can replace it"
        );
        assert!(!ack.contains("recorded"));
        let settle_calls = script.matches("settleDecision(ev.action_key").count();
        assert_eq!(
            settle_calls, 2,
            "a line is settled from exactly the two decision row cases"
        );
        let render = body("function renderEvent(ev, live) {");
        assert_eq!(
            render.matches("settleDecision(ev.action_key").count(),
            2,
            "both calls live in the row renderer"
        );
        assert!(
            render.contains("case 'permission_approved': {")
                && render.contains("case 'permission_denied': {")
        );
        let poll = body("async function pollEvents() {");
        assert!(
            !poll.contains("decisionLines") && !poll.contains("addDecision("),
            "a poll tick alone changes no decision line: {poll}"
        );
        // The verify box is on screen with its caveat in every state, and
        // the panel names context as unknown.
        let record_panel = body("function renderRecord() {");
        assert!(record_panel.contains("kvRow(grid, 'context now', unknownNode())"));
        let verify_box = body("function renderVerifyBox() {");
        assert!(verify_box.contains("'Verify chain'") && verify_box.contains("'not run yet'"));
        assert!(verify_box.contains("Report-only: no operator trust anchor was consulted"));
        assert!(verify_box.contains("run.disabled = st.status === 'running';"));
    }

    /// One event, one word, one glyph. A call the operator denied or
    /// that expired was never attempted: its row says so in the
    /// decision's own word and takes the neutral glyph. ✕ and "refused"
    /// are the gate's, for a call that failed or that the gate closed
    /// on by itself.
    #[test]
    fn a_denied_call_is_not_drawn_as_a_failure() {
        let script = page_script();
        let case = script
            .split_once("case 'permission_denied': {")
            .expect("the denial row has a renderer")
            .1
            .split_once("break;")
            .unwrap()
            .0;
        assert!(
            case.contains("notAttempted ? '○' : '✕'"),
            "neutral glyph unless the gate itself refused: {case}"
        );
        assert!(
            case.contains("notAttempted ? 'neutral' : 'failed'"),
            "neutral colour to match"
        );
        assert!(
            case.contains("ev.timed_out ? 'expired' : operatorDecision ? 'denied' : 'refused'"),
            "one word per decision"
        );
        assert!(HTML.contains(".tool-row .glyph.neutral { color: var(--accent-300); }"));
    }

    fn pending(agent_id: &str, trigger: &str) -> wirken_gateway::pending_approvals::PendingRequest {
        wirken_gateway::pending_approvals::PendingRequest {
            agent_id: agent_id.into(),
            tool_name: "exec".into(),
            action_key: "shell:psql".into(),
            requested_tier: "tier3".into(),
            trigger_message: Some(trigger.into()),
        }
    }

    /// The list carries this browser's requests with their trigger text
    /// and only a count for everyone else's. Another channel's request
    /// id and message never appear.
    #[test]
    fn approvals_snapshot_scopes_to_webchat_and_counts_the_rest() {
        let queue = PendingApprovalQueue::new();
        let (mine_id, _rx1) =
            queue.register(pending("default/webchat/webchat-default", "clean up api-2"));
        let (telegram_id, _rx2) = queue.register(pending(
            "default/telegram/-1001234",
            "a telegram user's words",
        ));
        let (_signal_id, _rx3) =
            queue.register(pending("default/signal/+15550100", "a signal user's words"));

        let v = approvals_snapshot_for(&queue, None);
        let mine = v["mine"].as_array().unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0]["request_id"], mine_id);
        assert_eq!(mine[0]["trigger_message"], "clean up api-2");
        assert!(
            mine[0]["remaining_seconds"].is_null(),
            "no deadline is stored"
        );
        assert!(mine[0]["timeout_seconds"].as_u64().unwrap() > 0);
        assert_eq!(v["other_channels"]["count"], 2);
        assert_eq!(v["other_channels"]["by_channel"]["telegram"], 1);
        assert_eq!(v["other_channels"]["by_channel"]["signal"], 1);
        let text = serde_json::to_string(&v).unwrap();
        assert!(
            !text.contains(&telegram_id),
            "another channel's request id stays on its channel"
        );
        assert!(!text.contains("telegram user's words") && !text.contains("signal user's words"));
    }

    /// A decision posted here is refused for a request that belongs to
    /// another channel's session, and an unknown id is still unknown.
    #[test]
    fn a_decision_for_another_channel_is_refused() {
        let queue = PendingApprovalQueue::new();
        let (mine_id, _rx1) = queue.register(pending("default/webchat/webchat-default", "x"));
        let (telegram_id, _rx2) = queue.register(pending("default/telegram/-1001234", "y"));
        assert_eq!(approval_belongs_to_webchat(&queue, &mine_id), Some(true));
        assert_eq!(
            approval_belongs_to_webchat(&queue, &telegram_id),
            Some(false)
        );
        assert_eq!(approval_belongs_to_webchat(&queue, "not-a-request"), None);
        assert!(
            SERVER_SOURCE.contains(
                "approval_belongs_to_webchat(&pending_approvals, &request_id) == Some(false)"
            ),
            "the decision route consults the guard before resolving"
        );
    }

    /// The badge for other channels' pending approvals is drawn only
    /// when the count is above zero, never as "0 on telegram"; and a
    /// pending card survives a reload by being restored from the list.
    #[test]
    fn the_badge_disappears_at_zero_and_pending_cards_are_restored() {
        let script = page_script();
        let strip = script
            .split_once("function renderStatusValues() {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(
            strip.contains("if (others.count > 0)"),
            "the badge is gated on a positive count: {strip}"
        );
        assert!(strip.contains("' on '"), "the badge names the channel");
        assert!(script.contains("function restorePendingCards("));
        assert!(
            script.contains("age_seconds"),
            "a restored card's age comes from the queue, not from now"
        );
    }

    /// Every verdict the verifier can return maps to a word, carries
    /// the caveat, and shows hashes and key ids as fingerprints only.
    #[test]
    fn every_verify_verdict_maps_with_its_caveat() {
        use wirken_audit::{SessionId, VerifyResult};
        let at = chrono::Utc::now();
        let sid = SessionId::new("default/webchat/webchat-default".to_string());
        let cases = vec![
            (
                VerifyResult::Ok {
                    rows_verified: 184_223,
                    sessions_total: 41,
                    signed_heads_count: 210,
                    unsigned_heads_count: 0,
                    invalid_signatures_count: 0,
                    sessions_with_no_signed_heads: 3,
                    signing_key_ids_seen: vec!["8c1d4e2f9a0b7c63deadbeefcafef00d".into()],
                    unsigned_tail_max_len: 12,
                    schema_drift_records: vec![],
                },
                "ok",
            ),
            (
                VerifyResult::Broken {
                    session_id: sid.clone(),
                    seq: 512,
                    expected_hash: "9f3c1a7be02d44c1ffffffffffffffff".into(),
                    actual_hash: "0000000000000000aaaaaaaaaaaaaaaa".into(),
                    verified_count: 184_000,
                },
                "broken",
            ),
            (
                VerifyResult::SignatureInvalid {
                    session_id: sid.clone(),
                    seq: 500,
                    signing_key_id: "8c1d4e2f9a0b7c63deadbeefcafef00d".into(),
                    reason: "bad signature".into(),
                    verified_count: 10,
                    invalid_signatures_count: 1,
                },
                "signature_invalid",
            ),
            (
                VerifyResult::MissingChainHead {
                    session_id: sid,
                    rows: 7,
                    verified_count: 7,
                },
                "missing_chain_head",
            ),
            (VerifyResult::Empty, "empty"),
        ];
        for (result, word) in cases {
            let v = verify_result_json(&result, at, 4180);
            assert_eq!(v["result"], word);
            assert_eq!(
                v["caveat"], VERIFY_CAVEAT,
                "the caveat travels with every verdict"
            );
            assert_eq!(v["anchor"], "none");
            assert_eq!(v["duration_ms"], 4180);
            let text = serde_json::to_string(&v).unwrap();
            assert!(
                !text.contains("deadbeef"),
                "key ids are fingerprints: {text}"
            );
            assert!(
                !text.contains("ffffffff") && !text.contains("aaaaaaaa"),
                "hashes are fingerprints: {text}"
            );
        }
        let ok = verify_result_json(
            &VerifyResult::Ok {
                rows_verified: 1,
                sessions_total: 1,
                signed_heads_count: 1,
                unsigned_heads_count: 0,
                invalid_signatures_count: 0,
                sessions_with_no_signed_heads: 0,
                signing_key_ids_seen: vec!["8c1d4e2f9a0b7c63deadbeef".into()],
                unsigned_tail_max_len: 0,
                schema_drift_records: vec![],
            },
            at,
            1,
        );
        assert_eq!(ok["signing_key_fingerprints"][0], "8c1d4e2f9a0b7c63");
    }

    /// The verify route is guarded three ways before it touches the
    /// log: Origin required, the control-plane rate limit, and one run
    /// at a time. The page draws five states for it and the caveat is
    /// appended once, outside every state branch.
    #[test]
    fn verify_is_guarded_and_the_page_draws_its_states() {
        let route = SERVER_SOURCE
            .split_once("first_line.starts_with(\"POST /api/verify\")")
            .expect("verify route exists")
            .1
            .split_once("parse_approval_path(first_line)")
            .unwrap()
            .0;
        assert!(
            route.contains("api_preflight(&request, port, true)"),
            "Origin required"
        );
        assert!(route.contains("verify_limit.check()"), "rate limited");
        assert!(
            route.contains("compare_exchange(false, true"),
            "single flight"
        );
        assert!(route.contains("spawn_blocking"), "off the async runtime");
        let script = page_script();
        for state in [
            "'not run yet'",
            "'verifying…'",
            "'another verify is running'",
            "' · ok'",
            "' · broken'",
        ] {
            assert!(script.contains(state), "the page draws {state}");
        }
        assert!(script.contains("fetch('/api/verify'"));
        assert_eq!(
            script
                .matches("Report-only: no operator trust anchor was consulted")
                .count(),
            1,
            "one caveat, appended outside every state branch"
        );
    }

    /// Verify is report-only and alarms come from the writer, so a
    /// broken verify next to "no alarms on disk" is two truths. The
    /// writer line carries the verify result so they do not read as a
    /// contradiction, and the whole panel re-renders on a verify state
    /// change so the line follows.
    #[test]
    fn a_broken_verify_is_carried_on_the_writer_line() {
        let script = page_script();
        let panel = script
            .split_once("function renderRecord() {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(panel.contains("if (lastVerifyBroken()) w.appendChild(document.createTextNode(' · last verify found a break'));"));
        let refresh = script
            .split_once("function refreshVerifyBox() {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(
            refresh.contains("renderRecord()"),
            "a verify state change re-renders the panel: {refresh}"
        );
        assert!(
            script.contains("for that: wirken audit verify --require-signed'"),
            "the CLI pointer lives in the caveat"
        );
        assert!(
            script.contains("'two full reads of the record · one run at a time'"),
            "the footnote keeps cost and concurrency only"
        );
    }

    #[test]
    fn imported_routes_parse_their_three_shapes() {
        assert_eq!(
            parse_imported_path("GET /api/imported/sources HTTP/1.1"),
            Some(ImportedRoute::Sources)
        );
        assert_eq!(
            parse_imported_path("GET /api/imported/sources/src-1/conversations HTTP/1.1"),
            Some(ImportedRoute::Conversations {
                source_id: "src-1".into()
            })
        );
        assert_eq!(
            parse_imported_path("GET /api/imported/sources/src-1/conversations/c-9 HTTP/1.1"),
            Some(ImportedRoute::Detail {
                source_id: "src-1".into(),
                conversation_uuid: "c-9".into()
            })
        );
    }

    #[test]
    fn imported_routes_refuse_anything_but_those_shapes() {
        for line in [
            // Wrong method: there is no write surface here.
            "POST /api/imported/sources HTTP/1.1",
            "DELETE /api/imported/sources/src-1/conversations HTTP/1.1",
            // Traversal and empty segments.
            "GET /api/imported/sources/../secrets/conversations HTTP/1.1",
            "GET /api/imported/sources//conversations HTTP/1.1",
            "GET /api/imported/sources/src-1/conversations/ HTTP/1.1",
            // A longer path is not silently a shorter one.
            "GET /api/imported/sources/src-1/conversations/c-9/extra HTTP/1.1",
            // Unknown collection.
            "GET /api/imported/secrets HTTP/1.1",
            "GET /api/imported/ HTTP/1.1",
        ] {
            assert_eq!(parse_imported_path(line), None, "accepted: {line}");
        }
    }

    #[test]
    fn imported_routes_decode_an_encoded_identifier() {
        // The page encodes identifiers, so a uuid with reserved
        // characters arrives escaped and must decode to itself.
        assert_eq!(
            parse_imported_path("GET /api/imported/sources/src%2D1/conversations HTTP/1.1"),
            Some(ImportedRoute::Conversations {
                source_id: "src-1".into()
            })
        );
        // A malformed escape is refused rather than guessed at.
        assert_eq!(
            parse_imported_path("GET /api/imported/sources/src%2/conversations HTTP/1.1"),
            None
        );
    }

    #[test]
    fn session_path_rejects_list_route_and_non_get() {
        // The bare list route has no id and must not match the {id} form.
        assert!(parse_session_path("GET /api/sessions HTTP/1.1").is_none());
        assert!(parse_session_path("POST /api/sessions/abc HTTP/1.1").is_none());
    }

    #[test]
    fn session_path_rejects_empty_id() {
        assert!(parse_session_path("GET /api/sessions/ HTTP/1.1").is_none());
    }

    #[test]
    fn session_path_rejects_trailing_and_empty_segments() {
        // Trailing slash -> empty final segment.
        assert!(parse_session_path("GET /api/sessions/default%2Fwebchat%2F HTTP/1.1").is_none());
        // Doubled slash -> empty middle segment.
        assert!(parse_session_path("GET /api/sessions/a%2F%2Fb HTTP/1.1").is_none());
    }

    #[test]
    fn session_path_rejects_traversal() {
        assert!(parse_session_path("GET /api/sessions/..%2F..%2Fetc HTTP/1.1").is_none());
        assert!(parse_session_path("GET /api/sessions/a%2F..%2Fb HTTP/1.1").is_none());
    }

    #[test]
    fn session_path_rejects_malformed_percent_escape() {
        assert!(parse_session_path("GET /api/sessions/a%2 HTTP/1.1").is_none());
        assert!(parse_session_path("GET /api/sessions/a%zz HTTP/1.1").is_none());
    }

    #[test]
    fn percent_decode_handles_plain_and_encoded() {
        assert_eq!(percent_decode("plain").as_deref(), Some("plain"));
        assert_eq!(percent_decode("a%2Fb").as_deref(), Some("a/b"));
        assert_eq!(
            percent_decode("space%20here").as_deref(),
            Some("space here")
        );
        // A literal `+` is not a space in a path segment.
        assert_eq!(percent_decode("a+b").as_deref(), Some("a+b"));
        assert!(percent_decode("bad%").is_none());
        assert!(percent_decode("bad%2").is_none());
        assert!(percent_decode("bad%gg").is_none());
    }

    #[test]
    fn webchat_host_accepts_loopback_at_bound_port() {
        assert!(is_webchat_host("127.0.0.1:18790", 18790));
        assert!(is_webchat_host("localhost:18790", 18790));
        assert!(is_webchat_host("[::1]:18790", 18790));
    }

    #[test]
    fn webchat_host_rejects_rebinding_and_mismatch() {
        // DNS-rebinding: the page's own hostname resolved to loopback.
        assert!(!is_webchat_host("evil.com:18790", 18790));
        assert!(!is_webchat_host("127.0.0.1:9999", 18790));
        // No bare host without the bound port.
        assert!(!is_webchat_host("127.0.0.1", 18790));
    }

    #[test]
    fn preflight_get_without_origin_passes() {
        // Browsers omit Origin on a same-origin GET. A safe read
        // (require_origin = false) with a loopback Host must proceed,
        // otherwise the session sidebar and transcript routes 403 the
        // very page that serves the UI — the sidebar-empty bug.
        let req = "GET /api/sessions HTTP/1.1\r\nHost: localhost:18790\r\n\r\n";
        assert!(api_preflight(req, 18790, false).is_none());
    }

    #[test]
    fn preflight_get_with_foreign_origin_is_rejected() {
        // A present Origin is validated even on a safe read, so a
        // cross-origin caller that does send one is still rejected.
        let req = "GET /api/sessions HTTP/1.1\r\nHost: localhost:18790\r\nOrigin: http://evil.com\r\n\r\n";
        let resp = api_preflight(req, 18790, false).expect("foreign origin rejected");
        assert!(resp.contains("forbidden origin"));
    }

    #[test]
    fn preflight_get_with_rebound_host_is_rejected() {
        // DNS-rebinding read: no Origin (same-origin GET on the
        // attacker page) but the attacker's hostname rides in Host.
        // The Host check closes this, not the Origin check.
        let req = "GET /api/sessions HTTP/1.1\r\nHost: evil.com:18790\r\n\r\n";
        let resp = api_preflight(req, 18790, false).expect("rebound host rejected");
        assert!(resp.contains("forbidden host"));
    }

    #[test]
    fn preflight_post_without_origin_is_rejected() {
        // State-changing routes (require_origin = true) still demand an
        // Origin; browsers always send one on POST.
        let req = "POST /api/chat HTTP/1.1\r\nHost: localhost:18790\r\n\r\n";
        let resp = api_preflight(req, 18790, true).expect("missing origin rejected");
        assert!(resp.contains("missing origin"));
    }

    #[test]
    fn preflight_post_with_valid_origin_and_host_passes() {
        let req = "POST /api/chat HTTP/1.1\r\nHost: localhost:18790\r\nOrigin: http://localhost:18790\r\n\r\n";
        assert!(api_preflight(req, 18790, true).is_none());
    }

    /// The tool table names the rule for a tool whose tier the gate
    /// reads off the arguments, instead of the tier of one imagined
    /// call; intercepted tools have no tier; everything else carries
    /// the tier the classifier computes. The page draws the flag as
    /// "by argument" and never invents a tier for it.
    #[test]
    fn argument_dependent_tools_are_flagged_not_tiered() {
        for name in [
            "exec",
            "memory_read_channel",
            "read_imported_chat",
            "search_imported_chats",
        ] {
            let row = tool_tier_entry(name, "");
            assert!(row["tier"].is_null(), "{name} has no single tier");
            assert_eq!(row["tier_depends_on_arguments"], true, "{name}");
            assert!(
                row["tier_rule"].as_str().unwrap().contains("Tier"),
                "{name} names its rule"
            );
        }
        let read = tool_tier_entry("read_file", "");
        assert_eq!(read["tier"], "tier1");
        assert_eq!(read["tier_depends_on_arguments"], false);
        assert!(read["tier_rule"].is_null());
        let spawn = tool_tier_entry("spawn_subagent", "");
        assert!(spawn["tier"].is_null());
        assert_eq!(spawn["tier_rule"], "intercepted before the tier gate");
        assert_eq!(tool_tier_entry("mcp_github_issues", "")["tier"], "tier3");
        assert_eq!(tool_tier_entry("wasm_summarize", "")["tier"], "tier3");
        let script = page_script();
        assert!(script.contains("t.tier_depends_on_arguments ? 'by argument'"));
        assert!(
            script.contains("capRow(list, t.name, right, t.tier_rule)"),
            "the rule is drawn with the row"
        );
    }

    /// A skill's signature is one of three words. "signed" carries the
    /// signer, a failed check reads "unverified", and the page never
    /// draws a tick for any of them.
    #[test]
    fn a_skill_signature_is_one_of_three_words_never_a_tick() {
        assert_eq!(
            skill_signature_word(Ok(SkillSignature::Valid {
                signer: "abc".into()
            })),
            ("signed", Some("abc".to_string()))
        );
        assert_eq!(
            skill_signature_word(Ok(SkillSignature::Unsigned)),
            ("unsigned", None)
        );
        assert_eq!(
            skill_signature_word(Ok(SkillSignature::Invalid)),
            ("unverified", None)
        );
        assert_eq!(
            skill_signature_word(Err(wirken_gateway::error::GatewayError::Config("x".into()))),
            ("unverified", None)
        );
        let script = page_script();
        let skills = script
            .split_once("if (Array.isArray(c.skills)) {")
            .expect("skills renderer")
            .1
            .split_once("function renderVaultRows")
            .unwrap()
            .0;
        assert!(
            skills.contains("let right = s.signature;"),
            "the word is drawn as sent"
        );
        for tick in ["✓", "✔", "✅", "chip-ok", "'ok'"] {
            assert!(
                !skills.contains(tick),
                "no tick stands in for the word: {tick}"
            );
        }
    }

    /// A grant's expiry is drawn as a date from the row, never as a
    /// countdown computed on the page's clock.
    #[test]
    fn a_grant_expires_on_a_date_not_in_a_countdown() {
        let script = page_script();
        let grants = script
            .split_once("if (Array.isArray(c.grants)) {")
            .expect("grants renderer")
            .1
            .split_once("if (Array.isArray(c.skills)) {")
            .unwrap()
            .0;
        assert!(grants.contains("'until ' + ymdhm(g.expires_at)"));
        for countdown in [
            "remaining",
            "expires in",
            " left",
            "Date.now()",
            "setInterval",
        ] {
            assert!(!grants.contains(countdown), "no countdown: {countdown}");
        }
        assert!(
            script.contains("function ymdhm(iso) {") && !script.contains("ymdhm(Date.now"),
            "the formatter takes the row's timestamp"
        );
    }

    /// Credential rows are names only, and say so, until the store
    /// exposes dates. Connectors carry name, transport, auth kind and
    /// credential names; the command, its arguments, environment
    /// values and the URL never leave the config file.
    #[test]
    fn credentials_are_names_only_and_connectors_carry_no_command_or_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = cfg_at(dir.path());
        let mcp = cfg.mcp_config_path("default");
        std::fs::create_dir_all(mcp.parent().unwrap()).unwrap();
        std::fs::write(
            &mcp,
            r##"{"servers":{
              "github":{"transport":"http","url":"https://mcp.example.internal/secret-path","auth":{"type":"bearer","credential":"vault:github-token"},"signature":"c2lnbg==","signer_key":"0123456789abcdef0123456789abcdef"},
              "files":{"command":"/opt/tools/run-files-server","args":["--root","/srv/private"],"env":{"TOKEN":"vault:files-token","PLAIN":"hunter2"}}
            }}"##,
        )
        .unwrap();
        {
            use wirken_audit::{SessionEvent, SessionLog, TrustLevel};
            let log =
                wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path()).expect("log opens");
            let handle = log.handle_for(wirken_audit::SessionId::new("gateway-mcp".to_string()));
            log.append(
                &handle,
                TrustLevel::System,
                SessionEvent::McpEntryRefused {
                    server_name: "files".into(),
                    reason: "entry is unsigned and WIRKEN_ALLOW_UNSIGNED_MCP is not set".into(),
                },
            )
            .unwrap();
            log.append(
                &handle,
                TrustLevel::System,
                SessionEvent::McpEntryVerified {
                    server_name: "github".into(),
                    signer: "0123456789abcdef0123456789abcdef".into(),
                },
            )
            .unwrap();
        }
        let snap = credentials_snapshot(&cfg);
        let text = serde_json::to_string(&snap).unwrap();
        for leak in [
            "mcp.example.internal",
            "WIRKEN_ALLOW",
            "is not set",
            "refused_reason",
            "secret-path",
            "/opt/tools",
            "run-files-server",
            "/srv/private",
            "hunter2",
            "\"url\":",
            "\"command\":",
            "\"args\":",
            "\"env\":",
            "vault:",
        ] {
            assert!(!text.contains(leak), "withheld: {leak}");
        }
        assert_eq!(snap["metadata_available"], false);
        assert_eq!(
            snap["credentials"],
            serde_json::json!([]),
            "an absent vault file is an empty store"
        );
        let connectors = snap["connectors"].as_array().unwrap();
        assert_eq!(connectors.len(), 2);
        let files = &connectors[0];
        assert_eq!(files["name"], "files");
        assert_eq!(files["transport"], "stdio");
        assert_eq!(files["auth"], "environment");
        assert_eq!(files["credentials"], serde_json::json!(["files-token"]));
        assert_eq!(files["signed"], false);
        assert_eq!(
            files["trust"],
            serde_json::json!({ "verified": false }),
            "refused, and no more"
        );
        let github = &connectors[1];
        assert_eq!(github["transport"], "http");
        assert_eq!(github["auth"], "bearer");
        assert_eq!(github["credentials"], serde_json::json!(["github-token"]));
        assert_eq!(github["signed"], true);
        assert_eq!(github["signer_fingerprint"], "0123456789abcdef");
        assert_eq!(github["trust"]["verified"], true);
        assert_eq!(
            github["trust"]["signer"],
            "0123456789abcdef0123456789abcdef"
        );
        assert!(
            connectors
                .iter()
                .all(|c| c["trust"].get("refused_reason").is_none())
        );

        // An unreadable config is unknown, not "none configured".
        std::fs::write(&mcp, "{not json").unwrap();
        assert!(credentials_snapshot(&cfg)["connectors"].is_null());

        let script = page_script();
        let vault = script
            .split_once("function renderVaultRows(grid) {")
            .expect("vault renderer")
            .1
            .split_once("function setAboutOpen")
            .unwrap()
            .0;
        assert!(
            vault.contains("' credentials · dates '"),
            "the row says the dates are missing"
        );
        for field in [
            ".url",
            ".command",
            ".args",
            ".env",
            "c.created_at",
            "c.expires_at",
            "refused_reason",
        ] {
            assert!(
                !vault.contains(field),
                "not read from the connector: {field}"
            );
        }
        assert!(vault.contains("'none stored'") && vault.contains("'none configured'"));
    }

    /// The default agent's capabilities, drawn from a factory over an
    /// empty log: the argument-dependent tools are flagged, the skill
    /// is loaded with its signature word and its frontmatter as
    /// written, the grant carries its expiry as a timestamp, and no
    /// absolute path leaves the route.
    #[tokio::test]
    async fn capabilities_snapshot_lists_the_default_agent_without_paths() {
        use std::collections::{BTreeMap, HashMap};
        use wirken_agent::{AgentFactory, AgentStaticConfig};
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = cfg_at(dir.path());
        let skill_dir = dir.path().join("skills").join("demo");
        std::fs::create_dir_all(&skill_dir).unwrap();
        let frontmatter = "---\nname: demo\ndescription: A demo skill for the capabilities route.\npermissions:\n  tools:\n    allow:\n      - \"*\"\n  inference:\n    allow:\n      - ollama\n---";
        std::fs::write(
            skill_dir.join("SKILL.md"),
            format!("{frontmatter}\nDo the demo thing.\n"),
        )
        .unwrap();
        // The loader refuses an unsigned skill, so this one is signed
        // with a throwaway key; the route reports the word and the
        // signer, not the fact of a check.
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        wirken_gateway::skill_registry::sign_skill(&skill_dir, &key).expect("signs");
        let skill = wirken_agent::skill::SkillLoader::load_file(&skill_dir.join("SKILL.md"))
            .expect("skill loads");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let mut configs = HashMap::new();
        configs.insert(
            "default".to_string(),
            AgentStaticConfig {
                agent_id: "default".into(),
                workspace,
                llm_config: wirken_agent::llm::LlmConfig::ollama("local"),
                channel_overrides: HashMap::new(),
                api_key: None,
                api_key_credential: None,
                skills: vec![skill],
                wasm_skills: Vec::new(),
                mcp_client: None,
                identity: None,
                allowed_subagents: BTreeMap::new(),
                sandbox: Default::default(),
                channel_egress: Default::default(),
                extra_interceptors: vec![],
                zirkel_db_path: None,
            },
        );
        let log = wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path()).expect("log opens");
        let factory = AgentFactory::new(configs, Arc::new(log), None);
        let store = super::super::open_permission_store(&cfg).expect("store opens");
        store
            .approve(
                &wirken_gateway::permissions::Action::ShellExec {
                    pattern: "ls".into(),
                },
                "default",
                "operator",
            )
            .expect("grant persists");

        let snap = capabilities_snapshot(&cfg, &factory, super::WEBCHAT_CONVERSATION).await;
        assert_eq!(snap["busy"], false);
        let tools = snap["tools"].as_array().expect("tools listed");
        let exec = tools
            .iter()
            .find(|t| t["name"] == "exec")
            .expect("exec offered");
        assert_eq!(exec["tier_depends_on_arguments"], true);
        assert!(exec["tier"].is_null());
        let read = tools
            .iter()
            .find(|t| t["name"] == "read_file")
            .expect("read_file offered");
        assert_eq!(read["tier"], "tier1");
        assert_eq!(read["org_policy"], "allowed");
        let grants = snap["grants"].as_array().expect("grants listed");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0]["action_key"], "shell:ls");
        assert_eq!(grants[0]["approved_by"], "operator");
        assert!(
            chrono::DateTime::parse_from_rfc3339(grants[0]["expires_at"].as_str().unwrap()).is_ok(),
            "expiry is a timestamp, not a duration"
        );
        let skills = snap["skills"].as_array().expect("skills listed");
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0]["name"], "demo");
        assert_eq!(skills[0]["signature"], "signed");
        assert_eq!(
            skills[0]["signer"].as_str().map(str::len),
            Some(64),
            "the signer is the key, not a tick"
        );
        assert_eq!(skills[0]["frontmatter"], frontmatter);
        assert_eq!(skills[0]["permissions"]["egress"]["mode"], "deny");
        assert_eq!(skills[0]["permissions"]["tools"], "*");
        let text = serde_json::to_string(&snap).unwrap();
        assert!(
            !text.contains(dir.path().to_str().unwrap()),
            "no absolute path leaves the route"
        );

        // A turn in flight holds the agent: the sections it owns are
        // null and named busy, the grants still come from the store.
        let session =
            wirken_agent::session_id_for("default", "webchat", super::WEBCHAT_CONVERSATION);
        let agent = factory.wake("default", &session).expect("wake");
        let held = agent.lock().await;
        let busy = capabilities_snapshot(&cfg, &factory, super::WEBCHAT_CONVERSATION).await;
        drop(held);
        assert_eq!(busy["busy"], true);
        assert!(busy["tools"].is_null() && busy["skills"].is_null());
        assert_eq!(busy["grants"].as_array().unwrap().len(), 1);
    }

    /// Both routes sit behind the preflight, and the page asks for
    /// them only when About opens: the status poll never touches
    /// them, and nothing on the default screen draws from them.
    #[test]
    fn capabilities_and_the_vault_are_drawn_only_in_about() {
        for route in ["GET /api/capabilities ", "GET /api/credentials "] {
            let arm = SERVER_SOURCE
                .split_once(&format!("first_line.starts_with(\"{route}\")"))
                .unwrap_or_else(|| panic!("{route} route exists"))
                .1
                .split_once("} else if first_line.starts_with(")
                .unwrap()
                .0;
            assert!(
                arm.contains("api_preflight(&request, port, false)"),
                "{route} preflighted"
            );
        }
        let script = page_script();
        assert_eq!(script.matches("'/api/capabilities'").count(), 1);
        assert_eq!(script.matches("'/api/credentials'").count(), 1);
        let poll = script
            .split_once("async function loadStatus() {")
            .unwrap()
            .1
            .split_once("function restorePendingCards")
            .unwrap()
            .0;
        assert!(!poll.contains("capabilities") && !poll.contains("credentials"));
        let extras = script
            .split_once("async function loadAboutExtras() {")
            .expect("one loader")
            .1
            .split_once("\nfunction ")
            .unwrap()
            .0;
        assert!(
            extras.contains("fetchJson('/api/capabilities')")
                && extras.contains("fetchJson('/api/credentials')")
        );
        assert!(
            script.contains("if (open) { loadAboutExtras(); renderAbout(); }"),
            "fetched on open, drawn as fetching first"
        );
        // Only the About renderers read the two snapshots.
        let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
        for var in ["capabilities", "vault"] {
            let mut reads = 0;
            for (at, _) in script.match_indices(var) {
                let before = &script[..at];
                let after = &script[at + var.len()..];
                if before.chars().last().is_some_and(ident)
                    || after.chars().next().is_some_and(ident)
                {
                    continue;
                }
                let line = before.rsplit('\n').next().unwrap_or("").trim_start();
                if line.starts_with("//") || line.starts_with("let ") {
                    continue;
                }
                reads += 1;
                let fn_start = before
                    .rfind("\nfunction ")
                    .max(before.rfind("\nasync function "))
                    .unwrap();
                let fn_name = before[fn_start..].lines().nth(1).unwrap_or("");
                assert!(
                    fn_name.contains("renderCapabilityRows")
                        || fn_name.contains("renderVaultRows")
                        || fn_name.contains("loadAboutExtras"),
                    "{var} read outside About: {fn_name}"
                );
            }
            assert!(reads > 0, "{var} is read somewhere");
        }
        assert!(
            script.contains("unknownNode('busy · a turn holds the agent')"),
            "busy is named, not drawn empty"
        );
    }

    /// The frontmatter is returned as written, fences included, and
    /// nothing when the file has none.
    #[test]
    fn skill_frontmatter_is_read_between_the_fences() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("SKILL.md");
        std::fs::write(
            &p,
            "---\nname: a\ndescription: b\n---\nbody\n---\nnot frontmatter\n",
        )
        .unwrap();
        assert_eq!(
            skill_frontmatter(&p).as_deref(),
            Some("---\nname: a\ndescription: b\n---")
        );
        std::fs::write(&p, "no fences here\n").unwrap();
        assert_eq!(skill_frontmatter(&p), None);
        assert_eq!(skill_frontmatter(&dir.path().join("missing")), None);
    }

    /// (1) The conversation comes from the request. The key is the
    /// legacy constant or `c-` plus twelve lowercase hex digits, and
    /// nothing else can become a session id; the chat route, its three
    /// audit rows, the store row, the decision route and the
    /// capabilities route all read it from the request.
    #[test]
    fn the_conversation_comes_from_the_request() {
        assert_eq!(conversation_key(None).unwrap(), "webchat-default");
        assert_eq!(conversation_key(Some("")).unwrap(), "webchat-default");
        assert_eq!(
            conversation_key(Some("webchat-default")).unwrap(),
            "webchat-default"
        );
        assert_eq!(
            conversation_key(Some("c-0123456789ab")).unwrap(),
            "c-0123456789ab"
        );
        for bad in [
            "c-0123456789AB",
            "c-0123456789a",
            "c-0123456789abc",
            "x-0123456789ab",
            "../../etc",
            "default/webchat/c-0123456789ab",
            "c-0123456789ab#sub-1",
            "telegram",
        ] {
            assert!(conversation_key(Some(bad)).is_err(), "{bad} refused");
        }
        assert_eq!(
            webchat_session_id("c-0123456789ab"),
            "default/webchat/c-0123456789ab"
        );
        assert_eq!(
            conversation_of("default/webchat/c-0123456789ab"),
            Some("c-0123456789ab")
        );
        assert_eq!(conversation_of("default/telegram/-1001234"), None);
        assert_eq!(
            query_param("GET /api/approvals?c=c-0123456789ab HTTP/1.1", "c"),
            Some("c-0123456789ab")
        );
        assert_eq!(query_param("GET /api/approvals HTTP/1.1", "c"), None);

        let chat = SERVER_SOURCE
            .split_once("first_line.starts_with(\"POST /api/chat\")")
            .unwrap()
            .1
            .split_once("else if let Some(request_id) = parse_approval_path(first_line)")
            .unwrap()
            .0;
        assert!(chat.contains("conversation_key(json[\"conversation\"].as_str())"));
        assert_eq!(
            chat.matches(".with_session(conversation.as_str())").count(),
            3,
            "the threat, inbound and outbound rows carry the request's conversation"
        );
        assert!(chat.contains("store.get_or_create(\"webchat\", &conversation)"));
        assert!(chat.contains("webchat_session_id(&conversation)"));
        assert!(
            !chat.contains("WEBCHAT_CONVERSATION"),
            "the constant is not used inside the chat route"
        );
        let capabilities = SERVER_SOURCE
            .split_once("first_line.starts_with(\"GET /api/capabilities \")")
            .unwrap()
            .1
            .split_once("} else if first_line.starts_with(")
            .unwrap()
            .0;
        assert!(capabilities.contains("conversation_key(query_param(first_line, \"c\"))"));
        assert!(capabilities.contains("capabilities_snapshot(&cfg, &factory, &conversation)"));
    }

    /// (2) A send into a conversation whose turn is open is answered
    /// "turn open" at once. The claim is taken after the body is parsed
    /// and before the inbound row, the stream headers or the agent
    /// lock; the guard releases it on every exit.
    #[test]
    fn a_send_into_an_open_turn_is_refused_not_queued() {
        let turns = Arc::new(OpenTurns::default());
        let first = turns
            .try_open("c-0123456789ab")
            .expect("first send claims the turn");
        assert!(turns.open_age("c-0123456789ab").is_some());
        assert!(
            turns.try_open("c-0123456789ab").is_none(),
            "the second send is refused"
        );
        assert!(
            turns.try_open("c-ba9876543210").is_some(),
            "another conversation is free"
        );
        drop(first);
        assert!(!turns.open_age("c-0123456789ab").is_some());
        assert!(
            turns.try_open("c-0123456789ab").is_some(),
            "released on drop"
        );

        assert_eq!(
            TURN_OPEN_ERROR, "turn open",
            "the page keys state 19 on this text"
        );
        assert_eq!(turns.open_age("c-0123456789ab"), None);
        let held = turns.try_open("c-0123456789ab").unwrap();
        assert_eq!(
            turns.open_age("c-0123456789ab"),
            Some(0),
            "aged from the claim"
        );
        drop(held);
        let chat = SERVER_SOURCE
            .split_once("first_line.starts_with(\"POST /api/chat\")")
            .unwrap()
            .1
            .split_once("else if let Some(request_id) = parse_approval_path(first_line)")
            .unwrap()
            .0;
        let claim = chat
            .find("open_turns.try_open(&conversation)")
            .expect("the route claims the turn");
        let refuse = chat
            .find("\"error\": TURN_OPEN_ERROR,")
            .expect("and refuses with the body");
        assert!(
            chat.contains("\"age_seconds\": open_turns.open_age(&conversation)"),
            "the refusal carries the turn's age"
        );
        assert!(chat.contains("json_conflict(&body)"));
        let inbound = chat.find("\"message.inbound\"").unwrap();
        let headers = chat.find("text/event-stream").unwrap();
        let lock = chat.find("agent_mutex.lock().await").unwrap();
        assert!(
            claim < refuse && refuse < inbound,
            "refused before the inbound row is written"
        );
        assert!(claim < headers, "refused before any stream is opened");
        assert!(claim < lock, "nothing waits on the agent lock");
        assert!(
            SERVER_SOURCE.contains("HTTP/1.1 409 Conflict"),
            "the refusal is a 409"
        );
    }

    /// (3) A decision must name the conversation that raised the
    /// request. The channel guard still refuses other channels; the
    /// conversation guard refuses a webchat request from any other
    /// conversation, with the fixed string, and the ack goes to the
    /// stream of the conversation being viewed.
    #[test]
    fn a_decision_must_name_the_conversation_that_raised_it() {
        let queue = PendingApprovalQueue::new();
        let (a_id, _rx1) = queue.register(pending("default/webchat/c-0123456789ab", "x"));
        let (legacy_id, _rx2) = queue.register(pending("default/webchat/webchat-default", "y"));
        let a = webchat_session_id("c-0123456789ab");
        let legacy = webchat_session_id("webchat-default");
        assert_eq!(
            approval_belongs_to_conversation(&queue, &a_id, &a),
            Some(true)
        );
        assert_eq!(
            approval_belongs_to_conversation(&queue, &a_id, &legacy),
            Some(false)
        );
        assert_eq!(
            approval_belongs_to_conversation(&queue, &legacy_id, &legacy),
            Some(true)
        );
        assert_eq!(approval_belongs_to_conversation(&queue, "nope", &a), None);
        assert_eq!(
            DECISION_WRONG_CONVERSATION,
            "This approval belongs to another conversation. Open it to decide."
        );
        let route = SERVER_SOURCE
            .split_once("else if let Some(request_id) = parse_approval_path(first_line)")
            .unwrap()
            .1
            .split_once("let resolve = pending_approvals.resolve(&request_id, decision);")
            .unwrap()
            .0;
        assert!(route.contains("conversation_key(json[\"conversation\"].as_str())"));
        assert!(route.contains(
            "approval_belongs_to_conversation(&pending_approvals, &request_id, &viewing)"
        ));
        assert!(route.contains("json_forbidden(DECISION_WRONG_CONVERSATION)"));
        assert!(
            SERVER_SOURCE.contains("let session_id = SessionId::new(viewing);"),
            "the ack goes to the conversation being viewed"
        );
    }

    /// (4) Two live streams never share a conversation. The stream
    /// registers only after the turn claim, and the claim refuses a
    /// second holder, so the registry's replace-on-insert is never
    /// reached for a conversation that already has a stream.
    #[test]
    fn two_streams_cannot_share_a_conversation() {
        let turns = Arc::new(OpenTurns::default());
        let first = turns.try_open("c-0123456789ab");
        assert!(first.is_some());
        assert!(
            turns.try_open("c-0123456789ab").is_none(),
            "the second stream is never registered"
        );
        let chat = SERVER_SOURCE
            .split_once("first_line.starts_with(\"POST /api/chat\")")
            .unwrap()
            .1
            .split_once("else if let Some(request_id) = parse_approval_path(first_line)")
            .unwrap()
            .0;
        let claim = chat.find("open_turns.try_open(&conversation)").unwrap();
        let register = chat.find("sse_registry.register_guard(").unwrap();
        assert!(
            claim < register,
            "the claim comes before the stream registers"
        );
        drop(first);
        assert!(turns.try_open("c-0123456789ab").is_some());
    }

    /// (5) The approvals list is scoped to the conversation the page
    /// names. `mine` is that conversation's requests with their
    /// trigger text; `elsewhere` names each other webchat conversation
    /// holding one, with its age and nothing a page could decide with;
    /// other channels stay a count. Without a conversation the list is
    /// the whole channel, as before.
    #[test]
    fn approvals_are_listed_per_conversation() {
        let queue = PendingApprovalQueue::new();
        let (a_id, _rx1) = queue.register(pending(
            "default/webchat/c-0123456789ab",
            "roll staging back",
        ));
        let (b_id, _rx2) =
            queue.register(pending("default/webchat/c-ba9876543210", "summarise slack"));
        let (_t, _rx3) = queue.register(pending(
            "default/telegram/-1001234",
            "a telegram user's words",
        ));

        let v = approvals_snapshot_for(&queue, Some("c-0123456789ab"));
        let mine = v["mine"].as_array().unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0]["request_id"], a_id);
        assert_eq!(mine[0]["trigger_message"], "roll staging back");
        let elsewhere = v["elsewhere"].as_array().unwrap();
        assert_eq!(elsewhere.len(), 1);
        assert_eq!(elsewhere[0]["conversation"], "c-ba9876543210");
        assert_eq!(
            elsewhere[0]["requested_tier"], "tier3",
            "the tier, so the line can name it"
        );
        assert!(elsewhere[0]["age_seconds"].is_u64());
        assert!(elsewhere[0]["requested_at"].is_string());
        let text = serde_json::to_string(&elsewhere).unwrap();
        assert!(
            !text.contains(&b_id),
            "no request id leaves for another conversation"
        );
        assert!(!text.contains("summarise slack"), "nor its trigger text");
        assert_eq!(v["other_channels"]["count"], 1);

        let v = approvals_snapshot_for(&queue, Some("c-ba9876543210"));
        assert_eq!(v["mine"][0]["request_id"], b_id);
        assert_eq!(v["elsewhere"][0]["conversation"], "c-0123456789ab");

        let v = approvals_snapshot_for(&queue, None);
        assert_eq!(
            v["mine"].as_array().unwrap().len(),
            2,
            "unscoped is the whole channel"
        );
        assert_eq!(v["elsewhere"].as_array().unwrap().len(), 0);

        let route = SERVER_SOURCE
            .split_once("first_line.starts_with(\"GET /api/approvals \")")
            .unwrap()
            .1
            .split_once("} else if first_line.starts_with(")
            .unwrap()
            .0;
        assert!(
            route.contains("query_param(first_line, \"c\")")
                && route.contains("conversation_key(Some(c))")
        );
        assert!(
            route.contains("approvals_snapshot_for(&pending_approvals, conversation.as_deref())")
        );
    }

    /// (6) The list route carries each webchat conversation's first
    /// user message, control sequences stripped and cut at 120
    /// characters, and whether a turn is open in it. Another channel's
    /// first message is that channel's user's words and stays null.
    #[test]
    fn the_list_carries_each_conversations_first_message_and_turn_state() {
        use wirken_audit::{SessionEvent, SessionLog, TrustLevel};
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = cfg_at(dir.path());
        let store = wirken_gateway::session::SessionStore::open(
            &cfg.sessions_db_path(),
            cfg.session_expiry_secs,
        )
        .expect("store opens");
        let a = store.get_or_create("webchat", "c-0123456789ab").unwrap();
        store.record_message(&a.id).unwrap();
        store.get_or_create("webchat", "c-ba9876543210").unwrap();
        store.get_or_create("webchat", "webchat-default").unwrap();
        store.get_or_create("telegram", "-1001234").unwrap();

        let log = wirken_audit::SqliteSessionLog::open(&cfg.audit_db_path()).expect("log opens");
        let long = format!(
            "Roll staging \x1b[31mback\x1b[0m to last night's build {}",
            "x".repeat(200)
        );
        let handle = log.handle_for(wirken_audit::SessionId::new(
            "default/webchat/c-0123456789ab".to_string(),
        ));
        log.append(
            &handle,
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: long.clone(),
                inbound_id: None,
                adapter_id: Some("webchat".into()),
                sender_id: None,
            },
        )
        .unwrap();
        log.append(
            &handle,
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: "a second message is not the title".into(),
                inbound_id: None,
                adapter_id: Some("webchat".into()),
                sender_id: None,
            },
        )
        .unwrap();
        let legacy = log.handle_for(wirken_audit::SessionId::new(
            "default/webchat/webchat-default".to_string(),
        ));
        log.append(
            &legacy,
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: "What's in the deploy log from last night?".into(),
                inbound_id: None,
                adapter_id: Some("webchat".into()),
                sender_id: None,
            },
        )
        .unwrap();
        let telegram = log.handle_for(wirken_audit::SessionId::new(
            "default/telegram/-1001234".to_string(),
        ));
        log.append(
            &telegram,
            TrustLevel::User,
            SessionEvent::UserMessage {
                content: "a telegram user's words".into(),
                inbound_id: None,
                adapter_id: Some("telegram".into()),
                sender_id: None,
            },
        )
        .unwrap();
        drop(log);

        let turns = OpenTurns::default();
        let turns = Arc::new(turns);
        let _open = turns.try_open("c-ba9876543210").unwrap();
        let rows = super::super::session::active_session_rows(&cfg, None).expect("rows");
        let v = conversation_rows(&cfg, rows, &turns);
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 4);
        let by_id = |id: &str| {
            rows.iter()
                .find(|r| r["log_id"] == id)
                .unwrap_or_else(|| panic!("{id} listed"))
        };
        let a = by_id("default/webchat/c-0123456789ab");
        let title = a["first_message"].as_str().unwrap();
        assert!(title.starts_with("Roll staging back to last night's build "));
        assert_eq!(title.chars().count(), 120, "cut at 120 characters");
        assert!(!title.contains('\x1b'), "control sequences stripped");
        assert_eq!(a["turn_open"], false);
        assert!(a["turn_open_age_seconds"].is_null());
        assert_eq!(a["message_count"], 1);
        let b = by_id("default/webchat/c-ba9876543210");
        assert!(b["first_message"].is_null(), "nothing logged yet");
        assert_eq!(b["turn_open"], true);
        assert!(
            b["turn_open_age_seconds"].is_u64(),
            "aged from the claim, not from now"
        );
        let legacy = by_id("default/webchat/webchat-default");
        assert_eq!(
            legacy["first_message"], "What's in the deploy log from last night?",
            "the legacy conversation is titled like any other"
        );
        let t = by_id("default/telegram/-1001234");
        assert!(
            t["first_message"].is_null(),
            "another channel's words stay there"
        );
        assert!(t["turn_open"].is_null() && t["turn_open_age_seconds"].is_null());
        let text = serde_json::to_string(&v).unwrap();
        assert!(!text.contains("telegram user's words"));
        assert!(
            SERVER_SOURCE.contains("conversation_rows(&cfg, rows, &open_turns)"),
            "the list route serves these rows"
        );
    }

    /// The status snapshot carries the quiet window so the rail footnote
    /// can name it instead of assuming a day.
    #[tokio::test]
    async fn the_status_carries_the_quiet_window_for_the_rail_footnote() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = cfg_at(dir.path());
        let snap = status_snapshot(&cfg, 18790, &status_inputs_for(dir.path(), None), false).await;
        assert_eq!(
            snap["gateway"]["session_expiry_secs"],
            cfg.session_expiry_secs
        );
        assert!(page_script().contains("windowWords(status.gateway.session_expiry_secs)"));
    }

    /// The rail exists when there is more than one destination: a
    /// second conversation, a draft, or an archive. One conversation
    /// and nothing else is the default screen.
    #[test]
    fn the_rail_appears_only_with_a_second_destination() {
        let script = page_script();
        assert!(script.contains("rail.hidden = entries.length + railSources.length < 2;"));
        let entries = script
            .split_once("function railEntries() {")
            .expect("rail entries")
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(
            entries.contains("if (draft) entries.push({ key: draft, draft: true });"),
            "a draft is a destination"
        );
        assert!(
            entries.contains("resumed: true"),
            "a key opened by URL is a destination"
        );
        assert!(
            entries.contains("r.channel === 'webchat'")
                || script.contains("r.channel === 'webchat'"),
            "other channels are not destinations"
        );
    }

    /// A send names its conversation. A 409 whose error is exactly
    /// "turn open" is state 19: the text stays in the composer, the
    /// composer locks with the fixed placeholder, and the turn line
    /// ages from the gateway's claim, never from the page's clock alone.
    #[test]
    fn a_send_names_its_conversation_and_reads_turn_open() {
        let script = page_script();
        assert!(script.contains("body: JSON.stringify({ message: text, conversation: key }),"));
        assert!(script.contains("const TURN_OPEN_ERROR = 'turn open';"));
        assert!(script.contains("if (body && body.error === TURN_OPEN_ERROR) { setElsewhereTurn(body.age_seconds); return; }"));
        assert!(script.contains("const ELSEWHERE_PLACEHOLDER = 'A turn is open in another tab — it will appear here when it ends';"));
        assert!(script.contains("setTurn('turn open · elsewhere · ' + ageWords(age));"));
        let render = script
            .split_once("function renderElsewhereTurn() {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(
            render.contains(
                "elsewhereTurn.age + Math.floor((Date.now() - elsewhereTurn.seenAt) / 1000)"
            ),
            "aged from the claim"
        );
        assert!(render.contains("lockComposer(ELSEWHERE_PLACEHOLDER)"));
        assert!(
            script.contains("if (halted || elsewhereTurn) return;"),
            "the composer stays locked while the turn runs elsewhere"
        );
        assert!(
            script.contains("elsewhereTurn = { age: Number(row.turn_open_age_seconds) || 0, seenAt: Date.now() };"),
            "the list row is the other source"
        );
    }

    /// Leaving a conversation mid-turn abandons the stream, not the
    /// turn: the reader is aborted, nothing is marked cut off, and the
    /// rail row says "turn open" from the list until the record has
    /// the turn's end.
    #[test]
    fn leaving_mid_turn_abandons_the_stream_not_the_turn() {
        let script = page_script();
        assert!(script.contains("if (currentTurn && currentTurn.key !== key) abortTurn();"));
        assert!(script.contains("if (currentTurn) currentTurn.controller.abort();"));
        let send = script
            .split_once("async function send() {")
            .unwrap()
            .1
            .split_once("\nfunction finishTurn()")
            .unwrap()
            .0;
        let aborted = send
            .find("if (controller.signal.aborted) return;\n  if (!terminal) {")
            .expect("abort is checked before the cut-off marking");
        let cut = send
            .find("'cut off — the stream ended without a done event · '")
            .unwrap();
        assert!(aborted < cut);
        assert!(script.contains("if (e.turnOpen || (e.key === currentKey && (turnOpen || elsewhereTurn))) suffix += ' · turn open';"));
        assert!(
            script.contains("turnOpen: r.turn_open === true,"),
            "from the list, not a guess"
        );
    }

    /// A card is drawn only in the conversation that raised it. The
    /// list is asked per conversation, the restore filters on the key,
    /// the decision names the key, and the three other surfaces (chip,
    /// rail marker, linking line) navigate and carry no decision.
    #[test]
    fn approvals_are_drawn_only_where_they_were_raised() {
        let script = page_script();
        assert!(script.contains("fetch('/api/approvals?c=' + encodeURIComponent(key))"));
        assert!(script.contains("if (keyOf(req.agent_id) !== currentKey) continue;"));
        assert!(script.contains("const body = { decision, conversation: currentKey };"));
        assert!(
            script.contains("card.appendChild(el('div', 'approval-note', DECISION_ELSEWHERE));"),
            "a refusal is shown in the fixed words"
        );
        let line = script
            .split_once("function renderElsewhereLine() {")
            .expect("linking line")
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        for decision in [
            "btn-deny",
            "btn-allow",
            "submit(",
            "'Deny'",
            "'Approve'",
            "/api/approvals/",
        ] {
            assert!(
                !line.contains(decision),
                "the line decides nothing: {decision}"
            );
        }
        assert!(
            line.contains("openConversation(target.conversation)"),
            "the line navigates"
        );
        assert!(
            line.contains("titleFor(target.conversation)"),
            "the title comes from the rail, not the approvals route"
        );
        let strip = script
            .split_once("function renderStatusValues() {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(
            strip.contains("if (elsewhere.length > 0) {"),
            "the chip is absent at zero"
        );
        assert!(strip.contains("elsewhere.length + ' awaiting you elsewhere'"));
        assert!(strip.contains("chip.title = 'Open the conversation holding the approval';"));
        assert!(
            strip.contains("openConversation(elsewhere[0].conversation)"),
            "the chip navigates"
        );
        assert!(
            strip.contains("yield: 1 })")
                && strip.contains("yield: 2 })")
                && strip.contains("'yield-3'"),
            "egress yields first, then the sandbox, then the model"
        );
        let rail = script
            .split_once("function renderRail() {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(rail.contains("'○ awaiting you · ' + askedWords(pending.get(e.key))"));
        assert!(
            !rail.contains("/api/approvals/"),
            "the rail decides nothing"
        );
    }

    /// The fixed strings for states 17 to 21, verbatim.
    #[test]
    fn the_fixed_strings_for_states_17_to_21_are_verbatim() {
        let script = page_script();
        assert!(HTML.contains(">+ new</button>"));
        assert!(script.contains("const DRAFT_TITLE = 'New conversation';"));
        assert!(script.contains("if (e.draft) meta = 'unsent';"));
        assert!(script.contains("suffix += ' · turn open';"));
        assert!(script.contains("suffix += ' · resumed';"));
        assert!(
            script.contains("' approval is waiting in \"'")
                && script.contains("'\". It can only be decided there.'")
        );
        assert!(script.contains("el('button', 'link', 'open it →')"));
        assert!(script.contains("'titles are each conversation\\'s first message · quiet for '"));
        assert!(script.contains("' drops off this list, not out of the record'"));
        assert_eq!(
            script
                .split_once("const DECISION_ELSEWHERE = '")
                .unwrap()
                .1
                .split_once("';")
                .unwrap()
                .0,
            super::DECISION_WRONG_CONVERSATION,
            "the page's refusal text is the gateway's"
        );
    }

    /// A key is minted on the page from random bytes, carried in the
    /// URL hash, and validated on the way back in; a page with no key
    /// opens the legacy conversation, and every title reaches the DOM
    /// through the one text sink, falling back to the key.
    #[test]
    fn a_key_is_minted_locally_and_carried_in_the_hash() {
        let script = page_script();
        assert!(script.contains("crypto.getRandomValues(bytes);"));
        assert!(script.contains("const KEY_SHAPE = /^c-[0-9a-f]{12}$/;"));
        assert!(script.contains("const m = /^#c=([^&]+)$/.exec(location.hash);"));
        assert!(
            script.contains(
                "return key === LEGACY_CONVERSATION || KEY_SHAPE.test(key) ? key : null;"
            )
        );
        assert!(script.contains("currentKey = conversationFromHash() || LEGACY_CONVERSATION;"));
        assert!(script.contains("window.addEventListener('hashchange'"));
        assert!(script.contains("location.hash = 'c=' + key;"));
        assert!(script.contains(
            "row.appendChild(el('div', 'rail-title', e.draft ? DRAFT_TITLE : (e.title || e.key)));"
        ));
        assert!(
            script.contains("if (currentKey !== LEGACY_CONVERSATION) draft = currentKey;"),
            "a key with no record is a draft"
        );
        assert!(
            script.contains("if (draft && draft !== key) draft = null;"),
            "leaving a draft discards it"
        );
    }

    /// The five follow-ups from the turn-4 check: separators are
    /// measured after layout so a wrapped row never starts with one;
    /// the card and the rail tick one request's age from one anchor
    /// set from the gateway's age; text held in a locked composer is
    /// named as held and not sent; the mobile strip fades where more
    /// tabs lie past its edge; the label and "+ new" stay put while the
    /// tabs scroll.
    #[test]
    fn the_turn_four_follow_ups_hold() {
        let script = page_script();
        let seps = script
            .split_once("function fixSeparators() {")
            .expect("separators are measured")
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(seps.contains("sep.hidden = rowTop !== null && wrap.offsetTop !== rowTop;"));
        assert!(script.contains("statusValues.hidden = false;\n  fixSeparators();"));
        assert!(
            script.contains("requestAnimationFrame(() => { fixSeparators(); revealActiveRow(); })"),
            "re-measured on resize"
        );

        assert!(
            script.contains("const askedAt = askedAtFor(ev.request_id, ev.age_seconds);"),
            "the card's anchor"
        );
        assert!(
            script.contains("pending.set(k, askedAtFor(m.request_id, m.age_seconds));"),
            "the rail's anchor is the same"
        );
        assert!(script.contains(
            "askedAtFor('elsewhere:' + e.conversation + ':' + e.requested_at, e.age_seconds)"
        ));
        assert_eq!(
            script.matches("function askedWords(askedAt) {").count(),
            1,
            "one formatter"
        );
        assert!(
            script.contains("setText(age, askedWords(askedAt));")
                && script.contains("'○ awaiting you · ' + askedWords(pending.get(e.key))")
        );
        assert!(
            script.contains("railTicker = setInterval(tickRail, 1000);"),
            "the rail ticks with the card"
        );

        assert!(
            script.contains("if (input.value.trim()) showNotice(null, 'held — not sent', null);")
        );
        assert!(
            !script.contains("will be sent when"),
            "no promise the page cannot keep"
        );

        assert!(HTML.contains(".rail-label { flex: none; padding: 4px 8px 4px 0; gap: 6px; position: sticky; left: 0; z-index: 1; background: var(--bg-2); }"));
        assert!(HTML.contains(".rail-section.fade-right { mask-image: linear-gradient(to right, #000 calc(100% - 36px), transparent);"));
        assert!(script.contains("strip.classList.toggle('fade-right', strip.scrollWidth - strip.clientWidth - strip.scrollLeft > 4);"));
        assert!(script.contains(
            "section.addEventListener('scroll', () => updateStripFade(section), { passive: true });"
        ));
    }
}
