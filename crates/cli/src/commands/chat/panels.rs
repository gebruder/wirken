//! What the gateway says about the chat's own state, as the panels and
//! the sidebar show it. The gateway reads its stores and sends JSON on
//! the terminal connection (`super::super::terminal_queries`); this
//! module only reads that JSON and says it in words. Every string in it
//! goes through `sanitize` when drawn.

use serde::Deserialize;
use wirken_adapter_core::approval_card::runtime_words;

/// The panels for one conversation.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Status {
    pub agent: String,
    pub environment: Environment,
    pub context: Context,
    pub cost: Cost,
    pub audit: Audit,
    pub approvals: Approvals,
    pub tools: Tools,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Environment {
    pub data_dir: String,
    pub agent: String,
    pub provider: String,
    pub model: String,
    pub exec: Exec,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Exec {
    /// The sandbox mode: `exec_only`, `gvisor` or `off`.
    pub mode: String,
    /// The runtime it runs under: `gvisor`, `docker` or `host`.
    pub runtime: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Context {
    pub used_tokens: Option<u64>,
    pub window: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Cost {
    pub calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub costed_calls: u64,
    pub cost_usd_micros: Option<u64>,
    pub budget: Budget,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Budget {
    pub mode: String,
    pub window: String,
    pub ceiling_usd_micros: Option<u64>,
    pub spent_usd_micros: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Audit {
    pub rows: u64,
    pub heads: u64,
    pub unsigned_tail: u64,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Approvals {
    pub approved: u64,
    pub denied: u64,
    pub grants: Option<Vec<Grant>>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Grant {
    pub action_key: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Tools {
    pub busy: bool,
    pub count: Option<u64>,
    pub ask_first: u64,
    pub names: Vec<String>,
    pub skills: Vec<String>,
}

/// The result of a chain check.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Verified {
    /// `ok`, `empty`, `broken` or `error`.
    pub chain: String,
    pub rows: u64,
    pub broken_at: Option<u64>,
    pub signed_heads: Option<u64>,
    pub unsigned_tail: Option<u64>,
    pub invalid_signature: bool,
    pub error: Option<String>,
}

/// The agents and their terminal conversations.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Directory {
    pub agents: Vec<AgentRow>,
    pub conversations: Vec<ConversationRow>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct AgentRow {
    pub id: String,
    pub provider: String,
    pub model: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct ConversationRow {
    pub agent: String,
    pub conversation: String,
    pub title: Option<String>,
    /// RFC 3339.
    pub updated: String,
}

/// A conversation's messages, to resume it.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct History {
    pub entries: Vec<HistoryEntry>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct HistoryEntry {
    /// `user`, `agent` or `tool`.
    pub kind: String,
    pub text: String,
    pub id: String,
    pub name: String,
    pub arguments: String,
    pub success: Option<bool>,
    pub output: String,
}

fn thousands(n: u64) -> String {
    if n >= 1000 {
        format!("{}.{}k", n / 1000, (n % 1000) / 100)
    } else {
        n.to_string()
    }
}

fn usd(micros: u64) -> String {
    format!("${}.{:04}", micros / 1_000_000, (micros % 1_000_000) / 100)
}

/// One panel: its title and its lines.
pub(crate) struct Panel {
    pub title: &'static str,
    pub lines: Vec<String>,
}

/// The panels in the order they are drawn, from what the gateway sent.
/// `verified` is the last chain check, if one ran.
pub(crate) fn panels(status: &Status, verified: Option<&Verified>) -> Vec<Panel> {
    let env = &status.environment;
    let mut environment = vec![
        format!("data   {}", env.data_dir),
        format!("agent  {}", env.agent),
    ];
    if !env.model.is_empty() {
        environment.push(format!("model  {}/{}", env.provider, env.model));
    }
    if !env.exec.runtime.is_empty() {
        environment.push(format!("exec   {}", runtime_words(&env.exec.runtime)));
        environment.push(format!("       mode {}", env.exec.mode));
    }

    let context = match (status.context.used_tokens, status.context.window) {
        (Some(used), Some(window)) if window > 0 => vec![format!(
            "{}% · about {} of {} tokens",
            used.saturating_mul(100) / window,
            thousands(used),
            thousands(window)
        )],
        (None, Some(window)) => vec![format!(
            "nothing sent yet · window {} tokens",
            thousands(window)
        )],
        _ => vec!["not known".to_string()],
    };

    let c = &status.cost;
    let spend = match c.cost_usd_micros {
        _ if c.calls == 0 => "no calls yet".to_string(),
        None => "uncosted".to_string(),
        Some(m) if c.costed_calls < c.calls => {
            format!("{} for {} of {} calls", usd(m), c.costed_calls, c.calls)
        }
        Some(m) => usd(m),
    };
    let b = &c.budget;
    let budget = match b.mode.as_str() {
        "" | "off" => "budget off".to_string(),
        mode => format!(
            "budget {mode}: {} of {} per {}",
            b.spent_usd_micros.map_or_else(|| "?".to_string(), usd),
            b.ceiling_usd_micros.map_or_else(|| "?".to_string(), usd),
            b.window
        ),
    };
    let cost = vec![
        format!(
            "{} calls · {} in · {} out",
            c.calls,
            thousands(c.input_tokens),
            thousands(c.output_tokens)
        ),
        spend,
        budget,
    ];

    let a = &status.audit;
    let mut audit = vec![
        format!("{} rows · {} chain heads", a.rows, a.heads),
        format!("{} rows after the last head", a.unsigned_tail),
    ];
    audit.push(match verified {
        None => "Ctrl+K verifies the chain".to_string(),
        Some(v) => verified_line(v),
    });

    let ap = &status.approvals;
    let mut approvals = vec![format!("{} approved · {} denied", ap.approved, ap.denied)];
    approvals.push(match &ap.grants {
        None => "stored grants not known".to_string(),
        Some(g) if g.is_empty() => "no stored grants".to_string(),
        Some(g) => format!(
            "grants: {}",
            g.iter()
                .map(|g| g.action_key.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    });

    let t = &status.tools;
    let tools = match t.count {
        _ if t.busy => vec!["a turn is running; shown after it".to_string()],
        None => vec!["not known".to_string()],
        Some(n) => vec![
            format!(
                "{n} tools · {} ask first · {} skills",
                t.ask_first,
                t.skills.len()
            ),
            t.names.join(", "),
        ],
    };

    vec![
        Panel {
            title: "Environment",
            lines: environment,
        },
        Panel {
            title: "Context",
            lines: context,
        },
        Panel {
            title: "Cost and tokens",
            lines: cost,
        },
        Panel {
            title: "Audit",
            lines: audit,
        },
        Panel {
            title: "Approvals",
            lines: approvals,
        },
        Panel {
            title: "Tools",
            lines: tools,
        },
    ]
}

/// A chain check's result in one line.
pub(crate) fn verified_line(v: &Verified) -> String {
    let signed = match (v.signed_heads, v.invalid_signature) {
        (_, true) => ", a signature does NOT verify".to_string(),
        (Some(h), false) => format!(", {h} signed heads verify"),
        (None, false) => String::new(),
    };
    match v.chain.as_str() {
        "ok" => format!("chain verified: {} rows intact{signed}", v.rows),
        "empty" => "chain verified: nothing recorded yet".to_string(),
        "broken" => format!(
            "chain BROKEN at row {} after {} intact rows",
            v.broken_at.unwrap_or(0),
            v.rows
        ),
        _ => format!(
            "chain check failed: {}",
            v.error.as_deref().unwrap_or("no reason given")
        ),
    }
}

/// Whether `needle` occurs in `hay`, ignoring case.
fn contains(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(&needle.to_lowercase())
}

/// One row of the sidebar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SideItem {
    NewChat,
    /// Index into [`Directory::agents`].
    Agent(usize),
    /// Index into [`Directory::conversations`].
    Conversation(usize),
}

/// The sidebar's rows under `filter`: an agent shows when its name or
/// model matches or any of its conversations does, and a conversation
/// when it matches or its agent does.
pub(crate) fn side_items(dir: &Directory, filter: &str) -> Vec<SideItem> {
    let filter = filter.trim();
    let mut items = vec![SideItem::NewChat];
    for (i, agent) in dir.agents.iter().enumerate() {
        let agent_hit = filter.is_empty()
            || contains(&agent.id, filter)
            || contains(&format!("{}/{}", agent.provider, agent.model), filter);
        let convs: Vec<usize> = dir
            .conversations
            .iter()
            .enumerate()
            .filter(|(_, c)| c.agent == agent.id)
            .filter(|(_, c)| agent_hit || c.title.as_deref().is_some_and(|t| contains(t, filter)))
            .map(|(j, _)| j)
            .collect();
        if agent_hit || !convs.is_empty() {
            items.push(SideItem::Agent(i));
            items.extend(convs.into_iter().map(SideItem::Conversation));
        }
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> Status {
        serde_json::from_value(serde_json::json!({
            "agent": "default",
            "environment": {
                "data_dir": "~/.wirken", "agent": "default",
                "provider": "ollama", "model": "llama3.1",
                "exec": { "mode": "gvisor", "runtime": "gvisor" }
            },
            "context": { "used_tokens": 1500, "window": 32000 },
            "cost": {
                "calls": 2, "input_tokens": 1200, "output_tokens": 300,
                "costed_calls": 0, "cost_usd_micros": null,
                "budget": { "mode": "off" }
            },
            "audit": { "rows": 14, "heads": 1, "unsigned_tail": 3 },
            "approvals": {
                "approved": 1, "denied": 2,
                "grants": [{ "action_key": "shell:ls", "expires_at": "2026-11-01T00:00:00Z" }]
            },
            "tools": { "count": 13, "ask_first": 5, "names": ["exec", "read_file"], "skills": [] }
        }))
        .unwrap()
    }

    fn text(panels: &[Panel], title: &str) -> String {
        panels
            .iter()
            .find(|p| p.title == title)
            .map(|p| p.lines.join("\n"))
            .unwrap()
    }

    #[test]
    fn each_panel_says_what_the_gateway_sent() {
        let p = panels(&status(), None);
        let env = text(&p, "Environment");
        assert!(
            env.contains("~/.wirken") && env.contains("default"),
            "{env}"
        );
        assert!(env.contains("gVisor (runsc)"), "{env}");
        assert!(text(&p, "Context").contains("4% · about 1.5k of 32.0k tokens"));
        let cost = text(&p, "Cost and tokens");
        assert!(cost.contains("2 calls · 1.2k in · 300 out"), "{cost}");
        assert!(
            cost.contains("uncosted") && cost.contains("budget off"),
            "{cost}"
        );
        let audit = text(&p, "Audit");
        assert!(audit.contains("14 rows · 1 chain heads"), "{audit}");
        assert!(audit.contains("Ctrl+K"), "{audit}");
        let approvals = text(&p, "Approvals");
        assert!(approvals.contains("1 approved · 2 denied"), "{approvals}");
        assert!(approvals.contains("shell:ls"), "{approvals}");
        let tools = text(&p, "Tools");
        assert!(
            tools.contains("13 tools · 5 ask first · 0 skills"),
            "{tools}"
        );
        assert!(tools.contains("exec, read_file"), "{tools}");
    }

    #[test]
    fn the_runtime_is_named_as_the_gateway_sent_it() {
        for (sent, words) in [
            ("gvisor", "gVisor (runsc)"),
            ("docker", "Docker default runtime (runc)"),
            ("host", "this host, no container"),
        ] {
            let mut s = status();
            s.environment.exec.runtime = sent.into();
            assert!(text(&panels(&s, None), "Environment").contains(words));
        }
    }

    #[test]
    fn a_chain_check_is_shown_in_the_audit_panel() {
        let ok = Verified {
            chain: "ok".into(),
            rows: 14,
            signed_heads: Some(1),
            ..Default::default()
        };
        assert!(text(&panels(&status(), Some(&ok)), "Audit").contains("14 rows intact"));
        let broken = Verified {
            chain: "broken".into(),
            rows: 6,
            broken_at: Some(7),
            ..Default::default()
        };
        assert_eq!(
            verified_line(&broken),
            "chain BROKEN at row 7 after 6 intact rows"
        );
    }

    fn directory() -> Directory {
        serde_json::from_value(serde_json::json!({
            "agents": [
                { "id": "default", "provider": "ollama", "model": "llama3.1" },
                { "id": "research", "provider": "ollama", "model": "qwen2.5" }
            ],
            "conversations": [
                { "agent": "default", "conversation": "c-1", "title": "What can you do", "updated": "t" },
                { "agent": "research", "conversation": "c-2", "title": "Compare two suppliers", "updated": "t" },
                { "agent": "research", "conversation": "c-3", "title": "Summarise this week", "updated": "t" }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn the_sidebar_filters_by_agent_model_and_title() {
        let dir = directory();
        assert_eq!(side_items(&dir, "").len(), 1 + 2 + 3);
        assert_eq!(
            side_items(&dir, "suppl"),
            [
                SideItem::NewChat,
                SideItem::Agent(1),
                SideItem::Conversation(1)
            ]
        );
        assert_eq!(
            side_items(&dir, "QWEN"),
            [
                SideItem::NewChat,
                SideItem::Agent(1),
                SideItem::Conversation(1),
                SideItem::Conversation(2)
            ]
        );
        assert_eq!(side_items(&dir, "nothing like it"), [SideItem::NewChat]);
    }
}
