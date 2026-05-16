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
  body { font-family: -apple-system, system-ui, sans-serif; background: #0d1117; color: #c9d1d9; height: 100vh; display: flex; flex-direction: column; }
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
<div id="header"><strong>wirken</strong> &mdash; webchat</div>
<div id="messages"></div>
<div id="input-area">
  <input id="input" type="text" placeholder="Send a message..." autofocus>
  <button id="send">Send</button>
</div>
<script>
const messages = document.getElementById('messages');
const input = document.getElementById('input');
const sendBtn = document.getElementById('send');

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
}

sendBtn.addEventListener('click', send);
input.addEventListener('keydown', e => { if (e.key === 'Enter') send(); });
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
                let origin = request
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("Origin: ")
                            .or_else(|| l.strip_prefix("origin: "))
                    })
                    .map(|s| s.trim().to_string());
                let allow_missing_origin =
                    wirken_gateway::org::parse_boolean_escape("WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN");
                match origin.as_deref() {
                    Some(o) if is_webchat_origin(o, port) => {}
                    Some(_) => {
                        let resp = r#"{"error":"forbidden origin"}"#;
                        let response = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp.len(),
                            resp
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                    None if allow_missing_origin => {}
                    None => {
                        let resp = r#"{"error":"missing origin header"}"#;
                        let response = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp.len(),
                            resp
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
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

                // Session
                let _ = sessions
                    .lock()
                    .await
                    .get_or_create("webchat", "webchat-default");

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

                // Origin gate first; same allowlist as /api/chat.
                let origin = request
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("Origin: ")
                            .or_else(|| l.strip_prefix("origin: "))
                    })
                    .map(|s| s.trim().to_string());
                let allow_missing_origin =
                    wirken_gateway::org::parse_boolean_escape("WIRKEN_WEBCHAT_ALLOW_NO_ORIGIN");
                match origin.as_deref() {
                    Some(o) if is_webchat_origin(o, port) => {}
                    Some(_) => {
                        let resp = r#"{"error":"forbidden origin"}"#;
                        let response = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp.len(),
                            resp
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                    None if allow_missing_origin => {}
                    None => {
                        let resp = r#"{"error":"missing origin header"}"#;
                        let response = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp.len(),
                            resp
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
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

#[cfg(test)]
mod tests {
    use super::{is_webchat_origin, parse_approval_path};

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
}
