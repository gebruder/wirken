use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use wirken_agent::Agent;
use wirken_audit::{AuditEvent, AuditWriter};
use wirken_gateway::session::SessionStore;

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
    agents: Arc<HashMap<String, Mutex<Agent>>>,
    audit: Arc<AuditWriter>,
    sessions: Arc<Mutex<SessionStore>>,
) -> Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    tracing::info!("WebChat listening on http://127.0.0.1:{port}");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let agents = agents.clone();
        let audit = audit.clone();
        let sessions = sessions.clone();

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

                // Audit
                let _ = audit
                    .log(
                        AuditEvent::new("webchat-user", "message.inbound", &message)
                            .with_channel("webchat"),
                    )
                    .await;

                // Session
                let _ = sessions
                    .lock()
                    .await
                    .get_or_create("webchat", "webchat-default");

                // SSE headers — stream tokens as they arrive
                let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
                if stream.write_all(header.as_bytes()).await.is_err() {
                    return;
                }

                // Process with streaming
                match agents.get("default") {
                    Some(agent_mutex) => {
                        let (tx, mut rx) = tokio::sync::mpsc::channel(64);

                        // Run agent streaming and SSE forwarding concurrently
                        let mut ag = agent_mutex.lock().await;
                        let stream_future = ag.process_message_stream(&message, tx);

                        // Forward stream events to the HTTP response as SSE
                        let write_stream = &mut stream;
                        let forward_future = async {
                            while let Some(event) = rx.recv().await {
                                let sse_data = match event {
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
                                if write_stream.write_all(sse_data.as_bytes()).await.is_err()
                                    || write_stream.flush().await.is_err()
                                {
                                    break;
                                }
                            }
                        };

                        let (result, _) = tokio::join!(stream_future, forward_future);

                        if let Ok(result) = result {
                            let _ = audit
                                .log(
                                    AuditEvent::new("default", "message.outbound", &result.response)
                                        .with_channel("webchat"),
                                )
                                .await;
                        }
                    }
                    None => {
                        let err = format!(
                            "data: {}\n\n",
                            serde_json::json!({"type": "error", "text": "no default agent configured"})
                        );
                        let _ = stream.write_all(err.as_bytes()).await;
                    }
                }
            } else {
                let response =
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
    }
}
