//! The approval card: the one template every approval surface renders.
//!
//! The gateway establishes what an approval is about and sends the
//! same fields to every surface: the `ApprovalRequest` frame to the
//! channel adapters and the terminal, the SSE event to the webchat,
//! the pending queue to `wirken permissions pending show`, and the
//! denial context to the stdin prompt. Each surface used to compose
//! its own text from those fields, and the texts disagreed: one
//! printed `tier tier2`, one showed where an `exec` runs and the
//! others did not, one named the container runtime. This module is
//! the card they all draw instead.
//!
//! [`ApprovalCard::lines`] is the card as ordered lines, for a surface
//! that styles them itself (the chat screen, the webchat page).
//! [`ApprovalCard::render`] is the same lines as text in one of the
//! [`CardStyle`]s the text channels send, with the escaping each one
//! needs. Every value goes through [`one_line`] first: escape
//! sequences stripped, line breaks folded and a long value cut with a
//! marker, so an argument cannot repaint the surface it is judged on
//! or write a second line that reads as part of the card.
//!
//! The arguments are what will run if approved and are never labeled
//! a claim. What the model said beside the call is its own account of
//! the call, which the gateway has not checked: it is the last line,
//! labeled `model's claim (unverified)` on a surface that cannot
//! style it and set apart on one that can.

use crate::ansi::strip_control_sequences;

/// Longest value a line shows before it is cut.
///
/// The arguments are what the operator is being asked to approve, so
/// the cut is generous: a real command is far shorter, and anything
/// near this is already a reason to answer no. The cut is marked, so
/// a decision is never made on text that silently ended.
pub const MAX_VALUE_CHARS: usize = 2000;

/// What a cut value ends with.
pub const CUT_MARKER: &str = " … (cut)";

/// The label on the model's own words. The one line that is a claim.
pub const CLAIM_LABEL: &str = "model's claim (unverified)";

/// The arguments line when the ask has no arguments. Not every gated
/// action comes from a tool call: sandbox egress asks about a
/// destination, which the action key already names.
pub const NO_ARGUMENTS: &str = "(none; the action key is the whole ask)";

/// The lines whose value is shown as code where a style has it: the
/// key the gate matched and the arguments that will run.
const CODE_LABELS: [&str; 2] = ["action key", "arguments"];

/// What an approval is about, as the gateway established it.
///
/// A `None` is a value the ask does not have: no arguments for an
/// action that is not a tool call, no location or runtime for a tool
/// other than `exec`, no triggering message for a system-driven turn,
/// no model text when the model sent calls and nothing else. The
/// frame carries each as an empty string; the surface reading it maps
/// empty to `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApprovalCard {
    /// The agent asking, by its id.
    pub agent: String,
    pub tool_name: String,
    /// The tier label as the gateway sends it, `tier2` or `tier3`.
    pub tier: String,
    /// The key the gate matched and a stored grant would be recorded
    /// under.
    pub action_key: String,
    /// The arguments the model sent, verbatim.
    pub arguments: Option<String>,
    /// Where an `exec` runs if approved, as the gateway built the line
    /// from the settings the exec will use.
    pub exec_location: Option<String>,
    /// The container runtime an `exec` runs under, as the gateway names
    /// it: `gvisor`, `docker` or `host`.
    pub exec_runtime: Option<String>,
    /// The inbound message that triggered the turn.
    pub trigger_message: Option<String>,
    /// What the model said in the same message as the call.
    pub assistant_text: Option<String>,
}

/// One line of the card: its label, its cleaned value, and whether it
/// is the model's claim rather than something the gateway established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardLine {
    pub label: &'static str,
    pub value: String,
    pub is_model_claim: bool,
}

/// The text dialect of a channel's approval message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardStyle {
    /// No markup and no escaping: Signal, WhatsApp, iMessage, Matrix.
    Plain,
    /// Markdown as Discord, Teams and Google Chat render it: `**bold**`
    /// labels, code spans and `_italic_`. Nothing is escaped, as those
    /// adapters escape nothing today.
    Markdown,
    /// Slack mrkdwn: `*bold*` labels, code spans and `_italic_`.
    /// Nothing is escaped.
    SlackMrkdwn,
    /// Telegram HTML: `<b>`, `<code>` and `<i>`, every value escaped.
    TelegramHtml,
}

impl ApprovalCard {
    /// The card's lines in order. A line whose value the ask does not
    /// have is left out, except `arguments`, which says so.
    pub fn lines(&self) -> Vec<CardLine> {
        let line = |label: &'static str, value: String| CardLine {
            label,
            value,
            is_model_claim: false,
        };
        let mut lines = vec![
            line(
                "request",
                format!(
                    "agent {} requests {} ({})",
                    one_line(&self.agent),
                    one_line(&self.tool_name),
                    one_line(&self.tier)
                ),
            ),
            line("action key", one_line(&self.action_key)),
            line(
                "arguments",
                match &self.arguments {
                    Some(arguments) => one_line(arguments),
                    None => NO_ARGUMENTS.to_string(),
                },
            ),
        ];
        if let Some(location) = present(&self.exec_location) {
            lines.push(line("runs", one_line(location)));
        }
        if let Some(runtime) = present(&self.exec_runtime) {
            lines.push(line("runtime", one_line(&runtime_words(runtime))));
        }
        if let Some(trigger) = present(&self.trigger_message) {
            lines.push(line("in reply to", one_line(trigger)));
        }
        if let Some(said) = present(&self.assistant_text) {
            lines.push(CardLine {
                label: CLAIM_LABEL,
                value: one_line(said),
                is_model_claim: true,
            });
        }
        lines
    }

    /// The card as text, one line per [`CardLine`], in `style`. The
    /// surface appends its own decision instructions after it.
    pub fn render(&self, style: CardStyle) -> String {
        self.lines()
            .iter()
            .map(|line| style.line(line))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl CardStyle {
    fn line(self, line: &CardLine) -> String {
        let code = CODE_LABELS.contains(&line.label);
        match self {
            CardStyle::Plain => format!("{}: {}", line.label, line.value),
            CardStyle::Markdown => format!(
                "**{}:** {}",
                line.label,
                span(&line.value, code, line.is_model_claim)
            ),
            CardStyle::SlackMrkdwn => format!(
                "*{}:* {}",
                line.label,
                span(&line.value, code, line.is_model_claim)
            ),
            CardStyle::TelegramHtml => {
                let value = html_escape(&line.value);
                let value = if code {
                    format!("<code>{value}</code>")
                } else if line.is_model_claim {
                    format!("<i>{value}</i>")
                } else {
                    value
                };
                format!("<b>{}:</b> {value}", line.label)
            }
        }
    }
}

/// A value in the Markdown and mrkdwn dialects, which share their code
/// span and italic markers.
fn span(value: &str, code: bool, claim: bool) -> String {
    if code {
        format!("`{value}`")
    } else if claim {
        format!("_{value}_")
    } else {
        value.to_string()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn present(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|s| !s.is_empty())
}

/// The runtime the gateway named, in words. The gateway decides it
/// from the agent's sandbox mode; this only names what it was told,
/// and shows a value it does not know as sent.
pub fn runtime_words(runtime: &str) -> String {
    match runtime {
        "gvisor" => "gVisor (runsc)".to_string(),
        "docker" => "Docker default runtime (runc)".to_string(),
        "host" => "this host, no container".to_string(),
        other => other.to_string(),
    }
}

/// A value as one printable line.
///
/// Three steps, and each is needed. [`strip_control_sequences`] takes
/// out the escapes, which is what stops a model from erasing the line
/// above or repainting the question. Folding the line breaks is what
/// stops it from writing a second line that looks like a label: an
/// argument that contains a newline would otherwise be printed as two
/// lines, the second of which the model chooses in full. The cut past
/// [`MAX_VALUE_CHARS`] is marked, so a decision is never made on text
/// that silently ended.
///
/// A literal `approve? [y/N]:` inside the argument text survives all
/// three, and should: it is part of the command being approved, and
/// it is shown after `arguments:` where the operator is looking. What
/// it cannot do is occupy a line of its own.
pub fn one_line(s: &str) -> String {
    let folded = strip_control_sequences(s)
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    if folded.chars().count() > MAX_VALUE_CHARS {
        let mut shown: String = folded.chars().take(MAX_VALUE_CHARS).collect();
        shown.push_str(CUT_MARKER);
        shown
    } else {
        folded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_card() -> ApprovalCard {
        ApprovalCard {
            agent: "default".into(),
            tool_name: "exec".into(),
            tier: "tier2".into(),
            action_key: "shell:ls".into(),
            arguments: Some(r#"{"command":"ls -la"}"#.into()),
            exec_location: Some("runs on this host as davi".into()),
            exec_runtime: Some("host".into()),
            trigger_message: Some("list the files".into()),
            assistant_text: Some("I'll list them.".into()),
        }
    }

    #[test]
    fn the_lines_come_in_order_with_their_labels() {
        let labels: Vec<&str> = exec_card().lines().iter().map(|l| l.label).collect();
        assert_eq!(
            labels,
            [
                "request",
                "action key",
                "arguments",
                "runs",
                "runtime",
                "in reply to",
                "model's claim (unverified)",
            ]
        );
    }

    #[test]
    fn the_tier_is_printed_once_from_its_label() {
        let lines = exec_card().lines();
        assert_eq!(lines[0].value, "agent default requests exec (tier2)");
        assert!(!exec_card().render(CardStyle::Plain).contains("tier tier2"));
    }

    #[test]
    fn only_the_models_words_are_a_claim() {
        let lines = exec_card().lines();
        let claims: Vec<&str> = lines
            .iter()
            .filter(|l| l.is_model_claim)
            .map(|l| l.label)
            .collect();
        assert_eq!(claims, [CLAIM_LABEL]);
        assert_eq!(lines.last().unwrap().value, "I'll list them.");
    }

    #[test]
    fn the_runtime_is_named_in_words_and_an_unknown_one_as_sent() {
        for (sent, words) in [
            ("gvisor", "gVisor (runsc)"),
            ("docker", "Docker default runtime (runc)"),
            ("host", "this host, no container"),
            ("firecracker", "firecracker"),
        ] {
            let mut card = exec_card();
            card.exec_runtime = Some(sent.into());
            let runtime = card
                .lines()
                .into_iter()
                .find(|l| l.label == "runtime")
                .unwrap();
            assert_eq!(runtime.value, words);
        }
    }

    #[test]
    fn lines_the_ask_does_not_have_are_left_out_and_absent_arguments_say_so() {
        let card = ApprovalCard {
            agent: "default".into(),
            tool_name: "sandbox_egress".into(),
            tier: "tier3".into(),
            action_key: "egress:pypi.org:443".into(),
            ..ApprovalCard::default()
        };
        let text = card.render(CardStyle::Plain);
        assert_eq!(
            text,
            "request: agent default requests sandbox_egress (tier3)\n\
             action key: egress:pypi.org:443\n\
             arguments: (none; the action key is the whole ask)"
        );
        // An empty string from a frame is an absent value too.
        let mut card = card;
        card.exec_location = Some(String::new());
        card.exec_runtime = Some(String::new());
        card.trigger_message = Some(String::new());
        card.assistant_text = Some(String::new());
        assert_eq!(card.lines().len(), 3);
    }

    #[test]
    fn plain_text_has_no_markup() {
        assert_eq!(
            exec_card().render(CardStyle::Plain),
            "request: agent default requests exec (tier2)\n\
             action key: shell:ls\n\
             arguments: {\"command\":\"ls -la\"}\n\
             runs: runs on this host as davi\n\
             runtime: this host, no container\n\
             in reply to: list the files\n\
             model's claim (unverified): I'll list them."
        );
    }

    #[test]
    fn markdown_bolds_labels_codes_the_key_and_arguments_and_italicises_the_claim() {
        let text = exec_card().render(CardStyle::Markdown);
        assert!(text.starts_with("**request:** agent default requests exec (tier2)\n"));
        assert!(text.contains("\n**action key:** `shell:ls`\n"));
        assert!(text.contains("\n**arguments:** `{\"command\":\"ls -la\"}`\n"));
        assert!(text.contains("\n**runs:** runs on this host as davi\n"));
        assert!(text.ends_with("\n**model's claim (unverified):** _I'll list them._"));
    }

    #[test]
    fn slack_mrkdwn_uses_single_asterisk_bold() {
        let text = exec_card().render(CardStyle::SlackMrkdwn);
        assert!(text.starts_with("*request:* agent default requests exec (tier2)\n"));
        assert!(text.contains("\n*arguments:* `{\"command\":\"ls -la\"}`\n"));
        assert!(text.ends_with("\n*model's claim (unverified):* _I'll list them._"));
        assert!(!text.contains("**"));
    }

    #[test]
    fn telegram_html_escapes_every_value() {
        let mut card = exec_card();
        card.arguments = Some(r#"{"command":"echo <b>&</b>"}"#.into());
        card.assistant_text = Some("a < b & c".into());
        let text = card.render(CardStyle::TelegramHtml);
        assert!(text.starts_with("<b>request:</b> agent default requests exec (tier2)\n"));
        assert!(text.contains("<b>action key:</b> <code>shell:ls</code>\n"));
        assert!(
            text.contains(
                "<b>arguments:</b> <code>{\"command\":\"echo &lt;b&gt;&amp;&lt;/b&gt;\"}</code>\n"
            ),
            "{text}"
        );
        assert!(text.ends_with("<b>model's claim (unverified):</b> <i>a &lt; b &amp; c</i>"));
    }

    #[test]
    fn a_value_is_one_line_without_its_escapes() {
        let mut card = exec_card();
        card.arguments = Some("ls\x1b[2K\r\nrm -rf /\tnow".into());
        let arguments = card
            .lines()
            .into_iter()
            .find(|l| l.label == "arguments")
            .unwrap();
        assert_eq!(arguments.value, "ls\\r\\nrm -rf /\\tnow");
        assert!(!card.render(CardStyle::Plain).contains('\x1b'));
    }

    #[test]
    fn a_long_value_is_cut_with_a_marker() {
        let shown = one_line(&"a".repeat(MAX_VALUE_CHARS * 2));
        assert_eq!(
            shown.chars().count(),
            MAX_VALUE_CHARS + CUT_MARKER.chars().count()
        );
        assert!(shown.ends_with(CUT_MARKER));
        assert!(!one_line(&"a".repeat(MAX_VALUE_CHARS)).ends_with(CUT_MARKER));
    }
}
