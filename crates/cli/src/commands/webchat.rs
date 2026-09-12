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

  /* Status line. Phase 1 carries the wordmark alone at its final height
     so Phase 2 adds values without a layout shift. */
  #status { padding: 11px 20px; border-bottom: 1px solid var(--hairline); display: flex; align-items: center; min-height: 42px; flex: none; }
  #wordmark { font-size: 15px; font-weight: 500; letter-spacing: -0.01em; }

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

  #main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  #conversation { flex: 1; overflow-y: auto; padding: 22px 24px 18px; display: flex; flex-direction: column; gap: 16px; }
  #conversation > * { flex: none; }
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
  .empty-state { align-self: center; margin: auto; max-width: 52ch; text-align: center; font-size: 14.5px; line-height: 1.6; color: rgba(233,233,237,.62); }

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
  .approval-head { display: flex; gap: 10px; align-items: flex-start; }
  .approval-sentence { font-size: 12.5px; line-height: 1.45; color: rgba(233,233,237,.62); flex: 1; }
  .approval-age { font-size: 11.5px; color: rgba(233,233,237,.5); white-space: nowrap; }
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

  @media (max-width: 720px) {
    #shell { flex-direction: column; }
    #rail { width: auto; border-right: none; border-bottom: 1px solid var(--hairline); display: flex; gap: 6px; padding: 8px 10px; overflow-x: auto; }
    .rail-section { display: flex; gap: 4px; align-items: center; }
    .rail-section + .rail-section { margin-top: 0; }
    .rail-row { width: auto; white-space: nowrap; }
    .rail-meta { display: none; }
    .msg-user, .msg-assistant, .approval, .block { max-width: 92%; }
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
<header id="status"><span id="wordmark">wirken</span></header>
<div id="shell">
  <nav id="rail" aria-label="Conversations and archives" hidden>
    <div class="rail-section"><div class="rail-label">Conversations</div><div id="rail-conversations"></div></div>
    <div class="rail-section"><div class="rail-label">Archives</div><div id="rail-archives"></div></div>
  </nav>
  <main id="main">
    <h1 class="sr-only">wirken webchat</h1>
    <section id="conversation" aria-live="polite" aria-label="Conversation"></section>
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
const haltedBanner = document.getElementById('halted-banner');

// One conversation per browser today. POST /api/chat always wakes agent
// "default" on channel "webchat", conversation "webchat-default".
const AGENT_ID = 'default';
const WEBCHAT_LOG_ID = 'default/webchat/webchat-default';
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
  head.appendChild(el('span', null, lang || 'code'));
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
  conversation.appendChild(node);
  scrollToEnd();
  return node;
}
function addAssistant(text) {
  const node = el('div', 'msg-assistant');
  node.setAttribute('data-role', 'assistant');
  renderMarkdown(node, text || '');
  conversation.appendChild(node);
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
  conversation.appendChild(box);
  scrollToEnd();
  return box;
}
function addRefusal(text) {
  return addBlock('refusal', 'Refused before running', '✕', text,
    'Nothing ran on the host. The agent was stopped at this step.');
}
function addAgentError(text) {
  return addBlock('error', 'The agent stopped', '✕', text, null);
}
function addDecision(text, glyph) {
  const line = el('div', 'decision');
  line.appendChild(el('span', 'glyph', glyph || '✓'));
  line.appendChild(el('span', null, ' ' + text));
  conversation.appendChild(line);
  scrollToEnd();
  return line;
}
function showEmptyState() {
  clear(conversation);
  conversation.appendChild(el('div', 'empty-state',
    'Agent ' + AGENT_ID + ' answers here. This page is served to this machine only. ' +
    'Every message, tool call and decision is written to the audit record before it runs.'));
}

// --- Turn line, composer lock, notices ---
let turnOpen = false;
let halted = false;
function setTurn(text) {
  if (text === null) { turnline.hidden = true; setText(turntext, ''); return; }
  turnline.hidden = false;
  setText(turntext, text);
}
function lockComposer(placeholder) {
  input.disabled = true; sendBtn.disabled = true; composer.classList.add('busy');
  input.placeholder = placeholder;
}
function unlockComposer() {
  if (halted) return;
  input.disabled = false; sendBtn.disabled = false; composer.classList.remove('busy');
  input.placeholder = 'Message your agent';
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
  const askedAt = Date.now();
  const card = el('div', 'approval');
  card.id = 'approval-' + ev.request_id;
  card.setAttribute('role', 'group');
  card.setAttribute('aria-label', 'Approval required');

  const head = el('div', 'approval-head');
  head.appendChild(el('span', 'chip chip-outline', tierLabel(ev.requested_tier)));
  head.appendChild(el('span', 'approval-sentence', approvalSentence(ev)));
  const age = el('span', 'approval-age', 'asked just now');
  head.appendChild(age);
  card.appendChild(head);

  // The approval event carries the action key, not the command line.
  // The command joins from the chain in Phase 2; until then the key is
  // what the gate computed, and that is what is shown.
  card.appendChild(el('div', 'approval-cmd', ev.action_key || ev.tool_name || ''));
  card.appendChild(el('div', 'approval-note', 'action key as computed by the gate · tool ' + (ev.tool_name || '')));

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
  conversation.appendChild(card);
  scrollToEnd();
  setTurn('turn open · agent holding on your decision');
  lockComposer('Decide on the approval above to continue');

  const ticker = setInterval(() => {
    if (!card.isConnected) { clearInterval(ticker); return; }
    const s = Math.floor((Date.now() - askedAt) / 1000);
    setText(age, 'asked ' + (s < 60 ? s + 's' : Math.floor(s / 60) + 'm ' + (s % 60) + 's') + ' ago');
  }, 1000);

  const submit = async (decision) => {
    approveBtn.disabled = true;
    denyBtn.disabled = true;
    const body = { decision };
    const r = reason.value.trim();
    if (r) body.reason = r;
    card.dataset.decision = decision;
    card.dataset.reason = r;
    try {
      await fetch('/api/approvals/' + encodeURIComponent(ev.request_id), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
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
      glyph = decision === 'deny' ? '✕' : '✓';
    } else {
      // The only evidence here is the gate's reply that the entry is
      // no longer pending. "Expired" needs the timeout denial row,
      // which Phase 2 reads.
      line = 'no longer pending · ' + hhmm() + ' · decided elsewhere';
      glyph = '○';
    }
    card.replaceWith(addDecision(line, glyph));
  }
  if (approvalCurrent && approvalCurrent.request_id === requestId) {
    approvalCurrent = null;
    if (approvalQueue.length > 0) {
      renderApproval(approvalQueue.shift());
    } else if (turnOpen) {
      setTurn('turn open');
      lockComposer('Waiting for the agent…');
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
  const emptyState = conversation.querySelector('.empty-state');
  if (emptyState) emptyState.remove();
  turnOpen = true;
  lockComposer('Waiting for the agent…');
  setTurn('thinking');
  const userNode = addUser(text);

  let assistant = null;
  let buffer = '';
  let received = '';
  let terminal = false;   // a done or error event arrived
  let res;
  try {
    res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text }),
    });
  } catch (e) {
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
            if (!assistant) assistant = addAssistant('');
            received += event.text;
            renderMarkdown(assistant, received);
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
            assistant = null;
            received = '';
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
  if (!terminal) {
    if (assistant) {
      assistant.appendChild(el('div', 'cutoff', 'cut off — the stream ended without a done event'));
    }
    showNotice(null, 'Connection lost · ', () => loadTranscript(WEBCHAT_LOG_ID));
  }
  settleOpenApproval();
  finishTurn();
  loadRail();
}
function finishTurn() {
  turnOpen = false;
  setTurn(null);
  unlockComposer();
  if (!halted) input.focus();
}

// --- History ---
async function loadTranscript(id) {
  setReadOnly(id === WEBCHAT_LOG_ID ? null : OTHER_SESSION_NOTICE);
  let turns = null;
  try {
    const res = await fetch('/api/sessions/' + encodeURIComponent(id));
    if (res.ok) turns = await res.json();
  } catch (e) {
    turns = null;
  } finally {
    // The rail is refreshed however the load ends.
    loadRail();
  }
  if (!turns) return;
  clear(conversation);
  if (turns.length === 0 && id === WEBCHAT_LOG_ID) { showEmptyState(); return; }
  for (const t of turns) {
    if (t.role === 'user') addUser(t.content);
    else addAssistant(t.content);
  }
  scrollToEnd();
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
backToLive.addEventListener('click', () => { activeArchive = null; loadTranscript(WEBCHAT_LOG_ID); });

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
  railSources = sources;
  if (!sources.length) { rail.hidden = true; return; }
  rail.hidden = false;
  clear(railConversations);
  const mine = rows.find(r => r.log_id === WEBCHAT_LOG_ID);
  const conv = el('button', 'rail-row' + (activeArchive === null ? ' active' : ''));
  conv.type = 'button';
  conv.appendChild(el('div', 'rail-title', 'webchat'));
  const bits = [];
  if (mine) bits.push(mine.message_count + ' msg');
  if (approvalCurrent) bits.push('1 awaiting you');
  conv.appendChild(el('div', 'rail-meta', bits.join(' · ') || 'no messages yet'));
  conv.addEventListener('click', () => { activeArchive = null; loadTranscript(WEBCHAT_LOG_ID); });
  railConversations.appendChild(conv);
  clear(railArchives);
  for (const source of sources) {
    const row = el('button', 'rail-row' + (activeArchive === source.id ? ' active' : ''));
    row.type = 'button';
    row.appendChild(el('div', 'rail-title', source.source_account));
    row.appendChild(el('div', 'rail-meta',
      source.conversations + ' conversations · ' + (source.sealed ? 'sealed' : 'live')));
    row.addEventListener('click', () => loadArchiveConversations(source));
    railArchives.appendChild(row);
  }
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
  clear(conversation);
  const head = el('div', 'archive-head', source.source_account);
  head.appendChild(el('span', 'meta',
    'imported archive · ' + source.conversations + ' conversations · ' + source.projects + ' projects · ' + (source.sealed ? 'sealed' : 'live')));
  conversation.appendChild(head);
  conversation.appendChild(el('div', 'archive-note',
    'A stored record, shown read-only. Text was written by whoever got a message into this account.'));
  if (!rows.length) {
    conversation.appendChild(el('div', 'archive-note', 'This archive holds no conversations.'));
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
    conversation.appendChild(item);
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
  clear(conversation);
  if (!detail) {
    conversation.appendChild(el('div', 'archive-note', 'That conversation is not in the store.'));
    return;
  }
  conversation.appendChild(el('div', 'archive-head', detail.title || 'Untitled · ' + String(detail.uuid).slice(0, 8)));
  if (detail.summary) conversation.appendChild(el('div', 'archive-note', detail.summary));
  const back = el('button', 'link', '← back to this archive');
  back.type = 'button';
  back.addEventListener('click', () => loadArchiveConversations(source));
  conversation.appendChild(back);

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
    conversation.appendChild(box);
    for (const attachment of message.attachments || []) {
      const att = el('div', 'archive-attachment');
      att.appendChild(el('div', 'meta', 'attachment: ' + (attachment.file_name || 'unnamed')));
      att.appendChild(el('div', 'text', attachment.text));
      conversation.appendChild(att);
    }
    // The view is a projection and says so.
    if (message.unrendered_blocks > 0) {
      conversation.appendChild(el('div', 'archive-note',
        message.unrendered_blocks + ' stored content blocks are not shown here. ' +
        'This view renders the message text and its attachments.'));
    }
  }
  conversation.scrollTop = 0;
}

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
loadTranscript(WEBCHAT_LOG_ID);
input.focus();
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
                        .with_detail(serde_json::json!({ "content": &message })),
                    )
                    .await;
                if let Err(e) = inbound_logged {
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
        HTML, ImportedRoute, api_preflight, is_webchat_host, is_webchat_origin,
        parse_approval_path, parse_imported_path, parse_session_path, percent_decode,
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
                && script.contains("loadTranscript(WEBCHAT_LOG_ID)"),
            "the way back returns to the live conversation"
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
        assert!(script.contains("conversation.appendChild(card)"));
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
            script.contains("setReadOnly(id === WEBCHAT_LOG_ID ? null : OTHER_SESSION_NOTICE)"),
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

    /// The Tier 2 chip and the Tier 2 shell sentence describe one fact,
    /// the absence of a live grant, and use one term for it. The chip's
    /// wording is the gate's own.
    #[test]
    fn the_tier_two_chip_and_sentence_use_one_term() {
        let script = page_script();
        assert!(script.contains("'Tier 2 · no live grant'"), "the chip names the gate's finding");
        assert!(
            script.contains("'Read-only shell command with no live grant.'"),
            "the sentence uses the chip's term"
        );
        assert!(!script.contains("standing grant"), "one term for one fact");
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
