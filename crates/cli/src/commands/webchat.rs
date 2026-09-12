use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use wirken_agent::{AgentFactory, session_id_for};
use wirken_audit::{ActorKind, AlarmLog, AlarmVerifyStatus, AuditEvent, AuditWriter, SessionId};
use wirken_gateway::adapter_registry::AdapterRegistry;
use wirken_gateway::injection_detect::InjectionDetector;
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

/// The one webchat conversation. `POST /api/chat` always wakes agent
/// `default` on channel `webchat` with this conversation id; the page
/// restores it on load. Multi-conversation is its own slice.
const WEBCHAT_CONVERSATION: &str = "webchat-default";

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
  .popover { position: absolute; top: calc(100% + 6px); left: 12px; width: min(380px, calc(100vw - 24px)); background: var(--surface); border-radius: 10px; box-shadow: 0 0 0 1px #595d6c, 0 16px 40px rgba(0,0,0,.6); padding: 14px 16px; z-index: 10; font-size: 12.5px; line-height: 1.5; }
  .popover h2 { font-size: 14px; font-weight: 500; margin-bottom: 10px; display: flex; gap: 8px; align-items: baseline; }
  .popover h2 .meta { font-size: 12px; font-weight: 400; color: rgba(233,233,237,.5); }
  .kv { display: grid; grid-template-columns: 88px 1fr; gap: 6px 12px; }
  .kv .k { color: rgba(233,233,237,.45); }
  .kv .v { text-align: right; overflow-wrap: anywhere; }
  .kv .v .row { display: block; }
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

  /* Tool rows: one line per call, glyph column, expand on click. */
  .tools { align-self: flex-start; max-width: 82%; width: 100%; display: flex; flex-direction: column; gap: 6px; }
  .tool-row { display: flex; gap: 10px; align-items: baseline; padding: 5px 0; font-size: 12.5px; cursor: pointer; border-radius: var(--radius-sm); }
  .tool-row:hover { background: rgba(145,132,217,.06); }
  .tool-row .glyph { width: 14px; text-align: center; flex: none; }
  .tool-row .glyph.done { color: var(--accent-400); }
  .tool-row .glyph.failed { color: var(--danger-text); }
  .tool-row .glyph.awaiting { color: var(--accent-300); }
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

  @media (max-width: 420px) {
    #status-values .optional { display: none; }
  }
  @media (max-width: 720px) {
    #shell { flex-direction: column; }
    #rail { width: auto; border-right: none; border-bottom: 1px solid var(--hairline); display: flex; gap: 6px; padding: 8px 10px; overflow-x: auto; }
    .rail-section { display: flex; gap: 4px; align-items: center; }
    .rail-section + .rail-section { margin-top: 0; }
    .rail-row { width: auto; white-space: nowrap; }
    .rail-meta { display: none; }
    .msg-user, .msg-assistant, .approval, .block { max-width: 92%; }
    #status { flex-wrap: wrap; }
    #status-values { flex-basis: 100%; justify-content: flex-start; }
    .popover { position: fixed; top: auto; bottom: 0; left: 0; right: 0; width: auto; border-radius: 10px 10px 0 0; }
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
const banners = document.getElementById('banners');
const statusValues = document.getElementById('status-values');
const wordmark = document.getElementById('wordmark');
const about = document.getElementById('about');
const record = document.getElementById('record');

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
  const g = glyph || '✓';
  line.appendChild(el('span', 'glyph' + (g === '✕' ? ' failed' : g === '○' ? ' neutral' : ''), g));
  line.appendChild(el('span', 'decision-text', ' ' + text));
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
  startEventPolling();

  liveAssistant = null;
  liveReceived = '';
  let buffer = '';
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
  if (!terminal) {
    if (liveAssistant) {
      liveAssistant.appendChild(el('div', 'cutoff', 'cut off — the stream ended without a done event'));
    }
    showNotice(null, 'Connection lost · ', () => loadTranscript(WEBCHAT_LOG_ID));
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
  setReadOnly(id === WEBCHAT_LOG_ID ? null : OTHER_SESSION_NOTICE);
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
  clear(conversation);
  toolRows.clear();
  decisionLines.clear();
  lastSeq = -1;
  recordSummary = page;
  if (page.events.length === 0 && id === WEBCHAT_LOG_ID) { showEmptyState(); return; }
  for (const ev of page.events) renderEvent(ev, false);
  scrollToEnd();
}

async function pollEvents() {
  let page;
  try {
    const res = await fetch('/api/sessions/' + encodeURIComponent(WEBCHAT_LOG_ID) + '/events?after=' + Math.max(lastSeq, 0));
    if (!res.ok) return;
    page = await res.json();
  } catch (e) { return; }
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
      if (openCard) conversation.insertBefore(block, openCard);
      else conversation.appendChild(block);
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
      if (entry) setGlyph(entry, '✕', 'failed', 'refused');
      let line, glyph;
      if (ev.timed_out) {
        line = 'expired — treated as denied · ' + hhmm(new Date(ev.ts)) + ' · recorded';
        glyph = '○';
      } else if (ev.denied_via && ev.denied_via.kind === 'sse') {
        line = 'denied · ' + hhmm(new Date(ev.ts)) + (ev.denial_reason ? ' · ' + ev.denial_reason : '') + ' · recorded';
        glyph = '✕';
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
  kvRow(grid, 'verify', el('span', null, 'not run from here · wirken audit verify'));
  record.appendChild(grid);
  record.appendChild(el('div', 'foot', 'Counts are from the record. Nothing here is verified until a verify pass says so.'));
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

async function loadStatus() {
  let snapshot;
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    snapshot = await res.json();
  } catch (e) { return; }
  status = snapshot;
  renderStatus();
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
  if (agent.model) items.push({ node: el('span', null, (agent.id || 'default') + ' · ' + agent.model), optional: false });
  const sandbox = status.sandbox || {};
  if (sandbox.mode) {
    const sb = el('span', null, sandbox.mode + ' ');
    sb.appendChild(el('span', 'hedge', '(configured)'));
    items.push({ node: sb, optional: false });
  }
  const egress = status.egress || {};
  if (egress.mode) items.push({ node: el('span', null, egress.mode === 'none' ? 'no egress' : 'egress: ' + egress.mode), optional: true });
  const budget = status.budget || {};
  if (budget.mode && budget.mode !== 'off' && isSet(budget.remaining_usd_micros)) {
    const b = el('span', 'mono', usd(budget.remaining_usd_micros) + ' left ' +
      (budget.window === 'day' ? 'today' : 'this ' + budget.window));
    b.title = 'agent budget · all channels';
    items.push({ node: b, optional: false });
  }
  const dot = el('button', 'writer-dot' + (audit.writer_halted ? ' halted' : ''));
  dot.type = 'button';
  dot.title = (audit.writer_halted ? 'Audit writer halted' : 'Audit writer live') + ' · open Record';
  dot.setAttribute('aria-label', dot.title);
  dot.setAttribute('aria-haspopup', 'dialog');
  dot.addEventListener('click', () => setRecordOpen(record.hidden));
  items.push({ node: dot, optional: false });
  items.forEach((item, i) => {
    const wrap = el('span', 'item' + (item.optional ? ' optional' : ''));
    if (i) wrap.appendChild(el('span', 'sep', '· '));
    wrap.appendChild(item.node);
    statusValues.appendChild(wrap);
  });
  statusValues.hidden = false;
}
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
  kvRow(grid, 'vault', unknownNode());
  const siem = status.siem || {};
  if (siem.configured) {
    const v = el('span', null, siem.target + (siem.endpoint_host ? ' · ' + siem.endpoint_host : '') + ' · last ship ');
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
  about.appendChild(el('div', 'foot', 'Blurple = the gateway does not know. Named here, omitted from the default screen.'));
}
function setAboutOpen(open) {
  if (open && !status) return;
  if (open) record.hidden = true;
  about.hidden = !open;
  wordmark.setAttribute('aria-expanded', open ? 'true' : 'false');
  if (open) renderAbout();
}
wordmark.addEventListener('click', () => setAboutOpen(about.hidden));
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (!about.hidden) { setAboutOpen(false); wordmark.focus(); }
  if (!record.hidden) setRecordOpen(false);
});
document.addEventListener('click', (e) => {
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
loadTranscript(WEBCHAT_LOG_ID);
loadStatus();
setInterval(loadStatus, STATUS_POLL_MS);
input.focus();
</script>
</body>
</html>"#;

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
                            .with_session(WEBCHAT_CONVERSATION)
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
                        .with_session(WEBCHAT_CONVERSATION)
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
                    match store.get_or_create("webchat", WEBCHAT_CONVERSATION) {
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
                let session_id_str = session_id_for("default", "webchat", WEBCHAT_CONVERSATION);
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
                                        .with_session(WEBCHAT_CONVERSATION)
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
                    SessionId::new(session_id_for("default", "webchat", WEBCHAT_CONVERSATION));
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
    pub endpoint_host: Option<String>,
    /// Whether the typed-event pipe is opted in.
    pub typed_pipe: bool,
}

impl SiemSummary {
    pub fn from_config(cfg: &wirken_audit::siem::SiemConfig) -> Self {
        Self {
            target: format!("{:?}", cfg.target).to_ascii_lowercase(),
            endpoint_host: url_host(&cfg.endpoint),
            typed_pipe: cfg.typed_forwarding_opted_in(),
        }
    }
}

/// Host part of a URL, without scheme, credentials, path or query.
fn url_host(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
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
        "url_host": org_url.as_deref().and_then(url_host),
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
            "endpoint_host": s.endpoint_host,
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
        "gateway": { "version": env!("CARGO_PKG_VERSION"), "loopback_only": true, "port": port },
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

/// The events route serves webchat sessions only. The id is
/// `{agent}/{channel}/{conversation}`; anything whose channel segment
/// is not `webchat` is another channel's record.
fn events_route_allowed(session_id: &str) -> bool {
    let mut parts = session_id.splitn(3, '/');
    let _agent = parts.next();
    let channel = parts.next();
    let conversation = parts.next();
    channel == Some("webchat") && conversation.is_some_and(|c| !c.is_empty())
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
    use std::sync::Arc;

    use tokio::sync::Mutex;
    use wirken_audit::AlarmLog;
    use wirken_gateway::adapter_registry::AdapterRegistry;

    use super::{
        HTML, ImportedRoute, SiemSummary, StatusInputs, api_preflight, events_route_allowed,
        is_webchat_host, is_webchat_origin, parse_approval_path, parse_imported_path,
        parse_session_events_path, parse_session_path, percent_decode, session_events,
        status_snapshot, url_host,
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
            endpoint_host: Some("dce.example".into()),
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
            "hostname",
            "gateway_pid",
        ] {
            assert!(
                !all.iter().any(|k| k == forbidden),
                "key {forbidden} present: {all:?}"
            );
        }
    }

    #[test]
    fn siem_summary_keeps_target_and_host_only() {
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
        assert_eq!(
            s.endpoint_host.as_deref(),
            Some("dce-abc.eastus-1.ingest.monitor.azure.com")
        );
        assert!(s.typed_pipe);
        let debug = format!("{s:?}");
        assert!(
            !debug.contains("secret") && !debug.contains("dcr-"),
            "{debug}"
        );
    }

    #[test]
    fn url_host_strips_scheme_credentials_path_and_query() {
        assert_eq!(
            url_host("https://user:pw@host.example:8443/a/b?c=d").as_deref(),
            Some("host.example:8443")
        );
        assert_eq!(
            url_host("http://localhost:18790").as_deref(),
            Some("localhost:18790")
        );
        assert_eq!(url_host("not a url"), None);
        assert_eq!(url_host("https:///path"), None);
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
            "'vault'",
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
