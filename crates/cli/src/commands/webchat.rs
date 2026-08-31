use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use wirken_agent::{AgentFactory, session_id_for};
use wirken_audit::{ActorKind, AuditEvent, AuditWriter, SessionId};
use wirken_gateway::pending_approvals::{PendingApprovalQueue, PendingDecision, ResolveResult};
use wirken_gateway::rate_limit::ControlPlaneRateLimiter;
use wirken_gateway::session::SessionStore;
use wirken_gateway::sse_approval_registry::{AckResult, SseApprovalRegistry, SseEvent};

/// WebChat rate limit. 60 chat POSTs per minute is two orders of
/// magnitude above any plausible interactive use; sized to bound
/// runaway-tab and naive-CSRF spend on the operator's API key, not
/// to throttle a human typing fast. Also bounds the cost of an
/// authenticated-but-malicious browser tab if H-1's Origin check is
/// somehow bypassed (defence in depth).
const WEBCHAT_MAX_POSTS_PER_MIN: u32 = 60;

const HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wirken</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #0d1117; color: #c9d1d9; height: 100vh; display: grid; grid-template-columns: 260px 1fr; overflow: hidden; }
  #sidebar { border-right: 1px solid #21262d; display: flex; flex-direction: column; min-height: 0; }
  #sidebar-header { padding: 16px 16px 10px; font-size: 12px; letter-spacing: 0.06em; text-transform: uppercase; color: #8b949e; }
  #session-list { flex: 1; overflow-y: auto; }
  .session-row { padding: 10px 16px; border-top: 1px solid #161b22; cursor: pointer; border-left: 2px solid transparent; }
  .session-row:hover { background: #161b22; }
  .session-row.active { background: #161b22; border-left-color: #58a6ff; }
  .session-row .ch { font-size: 13px; font-weight: 600; color: #c9d1d9; word-break: break-word; }
  .session-row .meta { font-size: 12px; color: #8b949e; margin-top: 2px; }
  #session-empty { padding: 12px 16px; font-size: 12px; color: #8b949e; }
  #main { display: flex; flex-direction: column; min-width: 0; overflow: hidden; }
  #header { padding: 16px 24px; border-bottom: 1px solid #21262d; font-size: 14px; color: #8b949e; }
  #header strong { color: #c9d1d9; }
  #messages { flex: 1; overflow-y: auto; padding: 16px 24px; }
  .msg { margin-bottom: 12px; line-height: 1.5; }
  .msg .role { font-weight: 600; margin-right: 8px; }
  .msg .role.user { color: #58a6ff; }
  .msg .role.assistant { color: #7ee787; }
  .msg .content { white-space: pre-wrap; word-break: break-word; }
  .msg .content.error { color: #f85149; }
  #input-area { padding: 16px 24px; border-top: 1px solid #21262d; display: flex; gap: 8px; }
  #input { flex: 1; background: #161b22; border: 1px solid #30363d; color: #c9d1d9; padding: 10px 14px; border-radius: 6px; font-size: 14px; outline: none; }
  #input:focus { border-color: #58a6ff; }
  #send { background: #238636; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; }
  #send:hover { background: #2ea043; }
  #send:disabled { opacity: 0.5; cursor: default; }
  .approval { margin: 12px 0; padding: 12px 16px; background: #161b22; border: 1px solid #d29922; border-radius: 6px; }
  .approval-title { font-weight: 600; color: #d29922; margin-bottom: 8px; }
  .approval-field { font-size: 13px; margin-bottom: 4px; }
  .approval-field .k { color: #8b949e; margin-right: 6px; }
  .approval-field .v { color: #c9d1d9; font-family: ui-monospace, monospace; }
  .approval-reason { width: 100%; background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 8px; border-radius: 4px; font-family: inherit; font-size: 13px; margin: 8px 0; resize: vertical; min-height: 36px; }
  .approval-buttons { display: flex; gap: 8px; margin-top: 8px; }
  .approval-btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; }
  .approval-btn:disabled { opacity: 0.5; cursor: default; }
  .approval-approve { background: #238636; color: #fff; }
  .approval-deny { background: #da3633; color: #fff; }
  .approval-expired { color: #8b949e; font-size: 12px; font-style: italic; }
</style>
</head>
<body>
<div id="sidebar">
  <div id="sidebar-header">Sessions</div>
  <div id="session-list"></div>
</div>
<div id="main">
  <div id="header"><strong>wirken</strong> &mdash; webchat</div>
  <div id="messages"></div>
  <div id="input-area">
    <input id="input" type="text" placeholder="Send a message..." autofocus>
    <button id="send">Send</button>
  </div>
</div>
<script>
const messages = document.getElementById('messages');
const input = document.getElementById('input');
const sendBtn = document.getElementById('send');
const sessionList = document.getElementById('session-list');
const WEBCHAT_CHANNEL = 'webchat';
// The single canonical webchat conversation. POST /api/chat always
// wakes agent "default" on channel "webchat" with conversation
// "webchat-default", so its session-log id is fixed and can be
// restored on page load.
const WEBCHAT_LOG_ID = 'default/webchat/webchat-default';
let activeSessionId = null;

function addMsg(role, text, isError) {
  const div = document.createElement('div');
  div.className = 'msg';
  const roleSpan = document.createElement('span');
  roleSpan.className = 'role ' + role;
  roleSpan.textContent = role;
  const contentSpan = document.createElement('span');
  contentSpan.className = 'content' + (isError ? ' error' : '');
  contentSpan.textContent = text || '';
  div.appendChild(roleSpan);
  div.appendChild(contentSpan);
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
  return contentSpan;
}

// Approval-UI state. Sequential queue: the agent's tool dispatch
// is serial, so a second approval request shouldn't arrive while
// one is still rendered. The queue is defensive — if a future
// agent gains parallel dispatch the UI stays correct.
const approvalQueue = [];
let approvalCurrent = null;

function renderApproval(ev) {
  if (approvalCurrent) {
    approvalQueue.push(ev);
    return;
  }
  approvalCurrent = ev;
  const card = document.createElement('div');
  card.className = 'approval';
  card.id = 'approval-' + ev.request_id;
  card.innerHTML = '';
  const title = document.createElement('div');
  title.className = 'approval-title';
  title.textContent = 'Approval required';
  card.appendChild(title);
  const fields = [
    ['agent', ev.triggering_agent],
    ['tool', ev.tool_name],
    ['action', ev.action_key],
    ['tier', ev.requested_tier],
  ];
  if (ev.trigger_message) fields.push(['trigger', ev.trigger_message]);
  for (const [k, v] of fields) {
    const row = document.createElement('div');
    row.className = 'approval-field';
    const ks = document.createElement('span');
    ks.className = 'k';
    ks.textContent = k + ':';
    const vs = document.createElement('span');
    vs.className = 'v';
    vs.textContent = v;
    row.appendChild(ks);
    row.appendChild(vs);
    card.appendChild(row);
  }
  const reason = document.createElement('textarea');
  reason.className = 'approval-reason';
  reason.placeholder = 'Optional reason (recorded on deny)';
  card.appendChild(reason);
  const btnRow = document.createElement('div');
  btnRow.className = 'approval-buttons';
  const approveBtn = document.createElement('button');
  approveBtn.className = 'approval-btn approval-approve';
  approveBtn.textContent = 'Approve';
  const denyBtn = document.createElement('button');
  denyBtn.className = 'approval-btn approval-deny';
  denyBtn.textContent = 'Deny';
  btnRow.appendChild(approveBtn);
  btnRow.appendChild(denyBtn);
  card.appendChild(btnRow);
  messages.appendChild(card);
  messages.scrollTop = messages.scrollHeight;

  const submit = async (decision) => {
    approveBtn.disabled = true;
    denyBtn.disabled = true;
    const body = { decision };
    const r = reason.value.trim();
    if (r) body.reason = r;
    try {
      await fetch('/api/approvals/' + encodeURIComponent(ev.request_id), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (e) {
      // Network error: the ack event won't arrive. Surface
      // inline so the operator knows the press didn't land and
      // can retry. The gate's own timeout will eventually
      // resolve the queue if the press never reaches us.
      approveBtn.disabled = false;
      denyBtn.disabled = false;
      const err = document.createElement('div');
      err.className = 'approval-expired';
      err.textContent = 'Network error submitting decision: ' + e.message;
      card.appendChild(err);
    }
  };
  approveBtn.addEventListener('click', () => submit('allow'));
  denyBtn.addEventListener('click', () => submit('deny'));
}

function ackApproval(requestId, result) {
  const card = document.getElementById('approval-' + requestId);
  if (card) {
    if (result === 'expired' || result === 'unknown_key') {
      const note = document.createElement('div');
      note.className = 'approval-expired';
      note.textContent = result === 'expired'
        ? 'Approval expired before your decision was applied.'
        : 'This approval is no longer pending (timeout, race, or already resolved).';
      card.appendChild(note);
      // Leave the note visible briefly, then remove the card so
      // the chat history shows the decision was acknowledged.
      setTimeout(() => card.remove(), 4000);
    } else {
      card.remove();
    }
  }
  if (approvalCurrent && approvalCurrent.request_id === requestId) {
    approvalCurrent = null;
    if (approvalQueue.length > 0) {
      renderApproval(approvalQueue.shift());
    }
  }
}

async function send() {
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  sendBtn.disabled = true;
  addMsg('user', text);

  const contentSpan = addMsg('assistant', '');

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text }),
    });

    if (!res.ok) {
      const data = await res.json();
      contentSpan.textContent = data.error || 'Request failed';
      contentSpan.classList.add('error');
      sendBtn.disabled = false;
      input.focus();
      return;
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      let boundary;
      while ((boundary = buffer.indexOf('\n\n')) >= 0) {
        const block = buffer.substring(0, boundary);
        buffer = buffer.substring(boundary + 2);

        for (const line of block.split('\n')) {
          if (line.startsWith('data: ')) {
            const json = line.substring(6);
            try {
              const event = JSON.parse(json);
              if (event.type === 'delta') {
                contentSpan.textContent += event.text;
                messages.scrollTop = messages.scrollHeight;
              } else if (event.type === 'error') {
                contentSpan.textContent += event.text;
                contentSpan.classList.add('error');
              } else if (event.type === 'approval_request') {
                renderApproval(event);
              } else if (event.type === 'approval_decision_ack') {
                ackApproval(event.request_id, event.result);
              }
            } catch(e) {}
          }
        }
      }
    }
  } catch (e) {
    contentSpan.textContent = 'Connection error: ' + e.message;
    contentSpan.classList.add('error');
  }
  sendBtn.disabled = false;
  input.focus();
  loadSessions();
}

function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

async function loadSessions() {
  let rows;
  try {
    const res = await fetch('/api/sessions');
    if (!res.ok) return;
    rows = await res.json();
  } catch (e) { return; }
  // Most recent first, then pin the current webchat session to the top.
  rows.sort((a, b) => (b.last_activity || '').localeCompare(a.last_activity || ''));
  rows.sort((a, b) => (b.channel === WEBCHAT_CHANNEL) - (a.channel === WEBCHAT_CHANNEL));
  sessionList.innerHTML = '';
  if (rows.length === 0) {
    const empty = document.createElement('div');
    empty.id = 'session-empty';
    empty.textContent = 'No active sessions';
    sessionList.appendChild(empty);
    return;
  }
  for (const row of rows) {
    const div = document.createElement('div');
    div.className = 'session-row' + (row.log_id === activeSessionId ? ' active' : '');
    const ch = document.createElement('div');
    ch.className = 'ch';
    ch.textContent = row.channel;
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = row.message_count + ' msg · last ' + fmtTime(row.last_activity);
    div.appendChild(ch);
    div.appendChild(meta);
    div.addEventListener('click', () => loadTranscript(row.log_id));
    sessionList.appendChild(div);
  }
}

async function loadTranscript(id) {
  activeSessionId = id;
  let turns;
  try {
    const res = await fetch('/api/sessions/' + encodeURIComponent(id));
    if (!res.ok) return;
    turns = await res.json();
  } catch (e) { return; }
  messages.innerHTML = '';
  for (const t of turns) addMsg(t.role, t.content);
  loadSessions();
}

sendBtn.addEventListener('click', send);
input.addEventListener('keydown', e => { if (e.key === 'Enter') send(); });
// Restore the canonical webchat conversation on load so a browser
// refresh keeps the visible history instead of dropping it.
// loadTranscript's tail call also populates the sidebar.
loadTranscript(WEBCHAT_LOG_ID);
</script>
</body>
</html>"#;

/// Serve the webchat UI on a TCP port.
/// Minimal HTTP server — no framework dependency.
pub async fn serve(
    port: u16,
    factory: Arc<AgentFactory>,
    audit: Arc<AuditWriter>,
    sessions: Arc<Mutex<SessionStore>>,
    pending_approvals: Arc<PendingApprovalQueue>,
    sse_registry: Arc<SseApprovalRegistry>,
) -> Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    tracing::info!("WebChat listening on http://127.0.0.1:{port}");

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
                    Ok(rows) => serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()),
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

                // Audit. Webchat has no platform-assigned message id;
                // synthesize one so `target` stays a stable resource
                // handle and the body lives under `detail.content`.
                let inbound_target = format!("webchat:{}", uuid::Uuid::new_v4());
                let _ = audit
                    .log(
                        AuditEvent::new(
                            ActorKind::Service,
                            "webchat-user",
                            "message.inbound",
                            &inbound_target,
                        )
                        .with_channel("webchat")
                        .with_detail(serde_json::json!({ "content": &message })),
                    )
                    .await;

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
                    match store.get_or_create("webchat", "webchat-default") {
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

                // Wake the default agent for the webchat session.
                // Webchat has a single canonical conversation
                // ("webchat-default") and synthesizes a UUID per
                // inbound message for crash-recovery dedup.
                let session_id_str = session_id_for("default", "webchat", "webchat-default");
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
                                        .with_detail(
                                            serde_json::json!({ "content": &result.response }),
                                        ),
                                    )
                                    .await;
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

                let resolve = pending_approvals.resolve(&request_id, decision);
                let ack = match resolve {
                    ResolveResult::Accepted => AckResult::Accepted,
                    ResolveResult::UnknownKey => AckResult::UnknownKey,
                };

                // Push the ack onto the session's SSE stream so the
                // browser closes the approval card. Webchat is
                // single-session today; the lookup is by the
                // canonical session id.
                let session_id =
                    SessionId::new(session_id_for("default", "webchat", "webchat-default"));
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
    use super::{
        ImportedRoute, api_preflight, is_webchat_host, is_webchat_origin, parse_approval_path,
        parse_imported_path, parse_session_path, percent_decode,
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
}
