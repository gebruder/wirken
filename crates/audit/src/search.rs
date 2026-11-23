//! Text search over session rows and proxied bodies.
//!
//! Retrieval only: a row or a body is turned into the text it holds,
//! and a query is found in it or not. Nothing here ranks, summarizes
//! or calls a model.
//!
//! A row's text is every string in its payload. A string that is
//! itself JSON, as a tool call's arguments are, is read as its strings
//! in turn, so a search matches what was said and not how it was
//! escaped. Chain heads and attestations hold hashes and signatures
//! and have no text. A row a redaction rewrote has none either: what
//! it held is gone, and what replaced it is not what happened.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::session_log::{ProxyShape, SessionEvent, StoredSessionEvent};
use wirken_time::Timestamp;

/// The longest snippet shown around a match, in characters.
const SNIPPET_CHARS: usize = 160;

fn leaves(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => match serde_json::from_str::<Value>(text) {
            Ok(inner @ (Value::Object(_) | Value::Array(_))) => leaves(&inner, out),
            _ => out.push(text.clone()),
        },
        Value::Array(items) => items.iter().for_each(|item| leaves(item, out)),
        Value::Object(map) => map.values().for_each(|item| leaves(item, out)),
        _ => {}
    }
}

/// Every string a JSON value holds, one to a line.
pub fn value_text(value: &Value) -> String {
    let mut out = Vec::new();
    leaves(value, &mut out);
    out.join("\n")
}

/// The text of a row, or `None` for a row that has none to search.
pub fn row_text(event: &SessionEvent) -> Option<String> {
    if matches!(
        event,
        SessionEvent::ChainHead { .. } | SessionEvent::Attestation { .. }
    ) {
        return None;
    }
    let mut value = serde_json::to_value(event).ok()?;
    if let Some(map) = value.as_object_mut() {
        map.remove("kind");
    }
    Some(value_text(&value))
}

/// The text of a proxied body: the strings of a JSON body, or for a
/// streamed answer the text, reasoning and tool calls its events add
/// up to. `shape` is the shape of the call the body belongs to, when
/// it is a model call.
pub fn body_text(shape: Option<ProxyShape>, body: &[u8]) -> String {
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        return value_text(&value);
    }
    if let Some(shape) = shape
        && let Some(text) = crate::atif::streamed_text(shape, body)
    {
        return text;
    }
    String::from_utf8_lossy(body).into_owned()
}

/// The rows of a session a redaction rewrote, by sequence number.
pub fn rewritten(rows: &[StoredSessionEvent]) -> BTreeSet<u64> {
    rows.iter()
        .filter_map(|row| match &row.event {
            SessionEvent::ChainHead {
                redaction: Some(record),
                ..
            } => Some(record.seq),
            _ => None,
        })
        .collect()
}

fn fold(text: &str) -> String {
    text.chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect()
}

/// What is searched for: text, matched whatever its case.
#[derive(Debug, Clone)]
pub struct Needle(String);

impl Needle {
    /// `None` for text that is empty or only whitespace.
    pub fn new(text: &str) -> Option<Self> {
        (!text.trim().is_empty()).then(|| Self(fold(text)))
    }

    /// Where `text` holds the needle: the match with what surrounds
    /// it, on one line, control characters removed.
    pub fn find(&self, text: &str) -> Option<String> {
        let folded = fold(text);
        let at = folded.find(&self.0)?;
        let start = folded.get(..at).map_or(0, |before| before.chars().count());
        let len = self.0.chars().count();
        let room = SNIPPET_CHARS.saturating_sub(len) / 2;
        let from = start.saturating_sub(room);
        let total = text.chars().count();
        let to = (start + len + room).min(total);
        let mut snippet: String = text
            .chars()
            .skip(from)
            .take(to - from)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        if from > 0 {
            snippet.insert_str(0, "...");
        }
        if to < total {
            snippet.push_str("...");
        }
        Some(snippet)
    }
}

/// Which rows a search looks at.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// The agent on the row, or the agent of the row's session.
    pub agent: Option<String>,
    /// The id of the proxy token on the row or of the row's lane.
    pub token: Option<String>,
    /// The channel of the row's session, or the one the row names.
    pub channel: Option<String>,
    /// The tool the row names.
    pub tool: Option<String>,
    pub since: Option<Timestamp>,
    pub until: Option<Timestamp>,
}

/// The agent, channel and conversation of an `agent/channel/conversation`
/// session id.
fn session_parts(session: &str) -> Option<(&str, &str)> {
    let mut parts = session.splitn(3, '/');
    let agent = parts.next()?;
    let channel = parts.next()?;
    parts.next()?;
    Some((agent, channel))
}

impl Filter {
    /// Whether the search looks at `row`.
    pub fn admits(&self, row: &StoredSessionEvent) -> bool {
        if self.since.is_some_and(|since| row.ts < since)
            || self.until.is_some_and(|until| row.ts > until)
        {
            return false;
        }
        let session = row.session_id.as_str();
        let value = serde_json::to_value(&row.event).unwrap_or(Value::Null);
        let named = |key: &str, wanted: &str| value[key].as_str() == Some(wanted);
        if let Some(agent) = &self.agent {
            let of_session = match session_parts(session) {
                Some((of, _)) => of == agent,
                None => session == agent,
            };
            if !(of_session || named("agent_id", agent)) {
                return false;
            }
        }
        if let Some(token) = &self.token {
            let lane = crate::session_log::proxy_session(token, None);
            let of_lane = session == lane || session.starts_with(&format!("{lane}-"));
            if !(of_lane || named("token_id", token)) {
                return false;
            }
        }
        if let Some(channel) = &self.channel {
            let of_session = session_parts(session).is_some_and(|(_, of)| of == channel);
            if !(of_session || named("channel", channel)) {
                return false;
            }
        }
        if let Some(tool) = &self.tool {
            let called = value["calls"]
                .as_array()
                .is_some_and(|calls| calls.iter().any(|c| c["name"].as_str() == Some(tool)));
            if !(called || named("tool_name", tool) || named("tool", tool)) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_log::{SessionId, SessionLog, SqliteSessionLog, TrustLevel};
    use serde_json::json;

    fn event(value: Value) -> SessionEvent {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn a_rows_text_is_what_it_says_and_not_how_it_is_escaped() {
        let call = event(json!({"kind":"assistant_tool_calls","agent_id":"ops",
            "calls":[{"id":"c1","name":"write_file",
                      "arguments":"{\"path\":\"notes/plan.md\",\"content\":\"line one\\nthe \\\"heron\\\" plan\"}"}]}));
        let text = row_text(&call).unwrap();
        assert!(text.contains("notes/plan.md"), "{text}");
        assert!(text.contains("the \"heron\" plan"), "{text}");
        // The row's kind is not text it holds.
        assert!(!text.contains("assistant_tool_calls"));

        let needle = Needle::new("\"HERON\" plan").unwrap();
        assert!(needle.find(&text).unwrap().contains("the \"heron\" plan"));
        assert!(Needle::new("wren").unwrap().find(&text).is_none());
        assert!(Needle::new("  ").is_none());
    }

    #[test]
    fn a_snippet_is_one_line_around_the_match() {
        let text = format!(
            "{}\nneedle here\u{1b}[31m{}",
            "a".repeat(300),
            "b".repeat(300)
        );
        let snippet = Needle::new("NEEDLE").unwrap().find(&text).unwrap();
        assert!(snippet.starts_with("...") && snippet.ends_with("..."));
        assert!(snippet.contains(" needle here [31m"), "{snippet}");
        assert!(snippet.chars().count() <= SNIPPET_CHARS + 6);
        assert!(!snippet.chars().any(char::is_control));
    }

    #[test]
    fn a_streamed_answer_is_searched_as_the_text_it_adds_up_to() {
        let stream = concat!(
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"The her\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"on flew.\"}}\n\n",
        );
        let text = body_text(Some(ProxyShape::AnthropicMessages), stream.as_bytes());
        assert!(text.contains("The heron flew."), "{text}");
        let request =
            r#"{"model":"m","messages":[{"role":"user","content":"caf\u00e9 \"plan\""}]}"#
                .as_bytes();
        assert!(body_text(None, request).contains("caf\u{e9} \"plan\""));
        assert_eq!(body_text(None, b"not json"), "not json");
    }

    /// Chain heads have no text, and neither has a row a redaction
    /// rewrote: its sequence number is in `rewritten`.
    #[test]
    fn chain_heads_and_rewritten_rows_have_no_text() {
        let tmp = tempfile::tempdir().unwrap();
        let signer = std::sync::Arc::new(crate::signing::AuditSigningKey::generate());
        let log = SqliteSessionLog::open_with_signer(&tmp.path().join("audit.db"), signer).unwrap();
        let lane = log.handle_for(SessionId::new("ops/slack/c1".to_string()));
        let said =
            |text: &str| event(json!({"kind":"user_message","content":text,"inbound_id":"i"}));
        log.append(&lane, TrustLevel::User, said("the heron password is 1234"))
            .unwrap();
        log.append(&lane, TrustLevel::User, said("something else"))
            .unwrap();
        log.emit_chain_head(&lane, crate::session_log::ChainHeadReason::SessionEnd)
            .unwrap();
        let rows = log.get_since(&lane, 0).unwrap();
        let target = rows
            .iter()
            .find(|r| row_text(&r.event).is_some_and(|t| t.contains("heron")))
            .unwrap()
            .seq;
        assert!(rewritten(&rows).is_empty());
        assert!(
            rows.iter()
                .filter(|r| matches!(r.event, SessionEvent::ChainHead { .. }))
                .all(|r| row_text(&r.event).is_none())
        );

        log.redact(&lane, target, &said("[removed]"), "op", "test")
            .unwrap();
        let rows = log.get_since(&lane, 0).unwrap();
        assert_eq!(rewritten(&rows), [target].into());
        let needle = Needle::new("heron").unwrap();
        assert!(
            rows.iter()
                .filter(|r| !rewritten(&rows).contains(&r.seq))
                .filter_map(|r| row_text(&r.event))
                .all(|text| needle.find(&text).is_none())
        );
    }

    #[test]
    fn a_filter_reads_the_session_and_the_row() {
        let log = SqliteSessionLog::open_in_memory().unwrap();
        let put = |session: &str, value: Value| {
            let lane = log.handle_for(SessionId::new(session.to_string()));
            log.append(&lane, TrustLevel::System, event(value)).unwrap();
            log.get_since(&lane, 0).unwrap().pop().unwrap()
        };
        let result = put(
            "ops/slack/c1",
            json!({"kind":"tool_result","call_id":"c","tool_name":"exec","output":"o",
                   "success":true,"agent_id":"ops"}),
        );
        let proxied = put(
            "proxy-0a0a0a0a-work",
            json!({"kind":"proxy_tool_call","call_id":"c","token_id":"0a0a0a0a",
                   "agent_id":"default","mcp_session":"s","tool":"mcp_files_read",
                   "success":true,"latency_ms":1,
                   "request_sha256":"00","request_bytes":1,
                   "response_sha256":"00","response_bytes":1}),
        );
        let with = |f: fn(&mut Filter)| {
            let mut filter = Filter::default();
            f(&mut filter);
            (filter.admits(&result), filter.admits(&proxied))
        };
        assert_eq!(with(|_| {}), (true, true));
        assert_eq!(with(|f| f.agent = Some("ops".into())), (true, false));
        assert_eq!(with(|f| f.agent = Some("default".into())), (false, true));
        assert_eq!(with(|f| f.token = Some("0a0a0a0a".into())), (false, true));
        assert_eq!(with(|f| f.token = Some("0a0a".into())), (false, false));
        assert_eq!(with(|f| f.channel = Some("slack".into())), (true, false));
        assert_eq!(with(|f| f.tool = Some("exec".into())), (true, false));
        assert_eq!(
            with(|f| f.tool = Some("mcp_files_read".into())),
            (false, true)
        );
        assert_eq!(
            with(|f| f.since = Some(wirken_time::now() + wirken_time::days(1))),
            (false, false)
        );
        assert_eq!(
            with(|f| f.until = Some(wirken_time::now() + wirken_time::days(1))),
            (true, true)
        );
    }
}
