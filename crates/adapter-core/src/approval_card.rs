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
//! needs, so the text a channel displays is the text of the value: a
//! character the channel would read as markup is escaped, never
//! dropped or left to restyle what follows it. Every value goes through [`one_line`] first: escape
//! sequences stripped, line breaks folded, characters that reorder or
//! hide text written out as code points and a long value cut with a
//! marker, so an argument cannot repaint the surface it is judged on,
//! read in another order than it runs, or write a second line that
//! reads as part of the card.
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
    /// The HTML subset a Google Chat card's text takes: `<b>` labels,
    /// the claim in `<i>`, every value escaped and the lines joined by
    /// `<br>`. The card's text has no code element, so the key and the
    /// arguments are shown as escaped text.
    GoogleChatHtml,
    /// Discord Markdown: `**bold**` labels and `_italic_`, with every
    /// value escaped. The key and the arguments sit in a code span,
    /// where Discord reads nothing as markup; a value holding a
    /// backtick cannot sit in one, so it is shown outside it with each
    /// punctuation character backslash-escaped, which Discord displays
    /// as the character alone.
    Discord,
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
        let separator = match style {
            CardStyle::GoogleChatHtml => "<br>",
            _ => "\n",
        };
        self.lines()
            .iter()
            .map(|line| style.line(line))
            .collect::<Vec<_>>()
            .join(separator)
    }
}

impl CardStyle {
    fn line(self, line: &CardLine) -> String {
        let code = CODE_LABELS.contains(&line.label);
        match self {
            CardStyle::Plain => format!("{}: {}", line.label, line.value),
            CardStyle::GoogleChatHtml => {
                let value = html_escape(&line.value);
                let value = if line.is_model_claim {
                    format!("<i>{value}</i>")
                } else {
                    value
                };
                format!("<b>{}:</b> {value}", line.label)
            }
            CardStyle::Discord => {
                let value = if code && !line.value.contains('`') {
                    format!("`{}`", line.value)
                } else if line.is_model_claim {
                    format!("_{}_", discord_escape(&line.value))
                } else {
                    discord_escape(&line.value)
                };
                format!("**{}:** {value}", line.label)
            }
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

/// A value with every ASCII punctuation character backslash-escaped.
/// Discord's Markdown takes a backslash before any punctuation
/// character as that character, so nothing in the value opens a span,
/// a spoiler, a mention or a link, and the text shown is the value.
fn discord_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c.is_ascii_punctuation() {
            out.push('\\');
        }
        out.push(c);
    }
    out
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
/// Four steps, and each is needed. [`strip_control_sequences`] takes
/// out the escapes, which is what stops a model from erasing the line
/// above or repainting the question. Folding the line breaks is what
/// stops it from writing a second line that looks like a label: an
/// argument that contains a newline would otherwise be printed as two
/// lines, the second of which the model chooses in full. A character
/// that reorders or hides the text around it is written out as its
/// code point, so the value reads in the order it runs. The cut past
/// [`MAX_VALUE_CHARS`] is marked, so a decision is never made on text
/// that silently ended.
///
/// A literal `approve? [y/N]:` inside the argument text survives all
/// three, and should: it is part of the command being approved, and
/// it is shown after `arguments:` where the operator is looking. What
/// it cannot do is occupy a line of its own.
pub fn one_line(s: &str) -> String {
    let folded = fold(s);
    if folded.chars().count() > MAX_VALUE_CHARS {
        let mut shown: String = folded.chars().take(MAX_VALUE_CHARS).collect();
        shown.push_str(CUT_MARKER);
        shown
    } else {
        folded
    }
}

/// `s` with its escapes out, its line breaks folded and every
/// character that changes how the text around it reads written out as
/// its code point, uncut.
fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in strip_control_sequences(s).chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if shown_as_code_point(c) => out.push_str(&format!("\\u{{{:x}}}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

/// A character a card shows as `\u{...}` rather than as itself: one
/// that draws nothing and changes how the characters around it are
/// shown. The bidirectional overrides, embeddings, isolates and marks
/// reorder what follows them, so `rm` can be drawn after the text it
/// precedes. The zero-width characters and the tag characters hide
/// text inside a word. The line and paragraph separators start a new
/// line on a surface that honours them, which is a second line the
/// model wrote. Shown as code points, each is visible where it sits
/// and the rest of the value reads in the order it runs.
pub fn shown_as_code_point(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// Whether a card line shows `s` to its end, with no cut. The gateway
/// asks this of a call's arguments before it asks an operator: a call
/// the card would cut is refused, since an approval given on a cut
/// card is an approval of text nobody was shown.
pub fn shown_whole(s: &str) -> bool {
    fold(s).chars().count() <= MAX_VALUE_CHARS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_is_shown_whole_up_to_the_cut_and_not_past_it() {
        let fits = "a".repeat(MAX_VALUE_CHARS);
        assert!(shown_whole(&fits));
        assert!(!one_line(&fits).ends_with(CUT_MARKER));
        let over = "a".repeat(MAX_VALUE_CHARS + 1);
        assert!(!shown_whole(&over));
        assert!(one_line(&over).ends_with(CUT_MARKER));
        // A line break is two characters on the card.
        let folded_over = format!("{}\n", "a".repeat(MAX_VALUE_CHARS - 1));
        assert!(!shown_whole(&folded_over));
    }

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
    fn google_chat_html_escapes_every_value_and_breaks_lines_itself() {
        let mut card = exec_card();
        card.arguments = Some(r#"{"command":"echo <br><b>x</b> &amp;"}"#.into());
        card.assistant_text = Some("ok<br><b>action key:</b> shell:ls".into());
        let text = card.render(CardStyle::GoogleChatHtml);
        let rows: Vec<&str> = text.split("<br>").collect();
        assert_eq!(rows.len(), card.lines().len(), "{text}");
        assert_eq!(
            rows[0],
            "<b>request:</b> agent default requests exec (tier2)"
        );
        assert_eq!(rows[1], "<b>action key:</b> shell:ls");
        assert_eq!(
            rows[2],
            "<b>arguments:</b> {\"command\":\"echo &lt;br&gt;&lt;b&gt;x&lt;/b&gt; &amp;amp;\"}"
        );
        assert_eq!(
            rows[6],
            "<b>model's claim (unverified):</b> <i>ok&lt;br&gt;&lt;b&gt;action key:&lt;/b&gt; shell:ls</i>"
        );
        assert!(!text.contains('\n'));
    }

    #[test]
    fn discord_shows_a_value_with_backticks_as_the_value() {
        let mut card = exec_card();
        card.arguments = Some(r#"{"command":"echo `id` **x** ||y|| <@1>"}"#.into());
        card.assistant_text = Some("just `ls`, _honest_".into());
        let text = card.render(CardStyle::Discord);
        // No code span can hold a backtick, so the value is escaped
        // character by character and no backtick is unescaped.
        assert!(
            text.contains(
                "\n**arguments:** \\{\\\"command\\\"\\:\\\"echo \\`id\\` \\*\\*x\\*\\* \\|\\|y\\|\\| \\<\\@1\\>\\\"\\}\n"
            ),
            "{text}"
        );
        assert!(
            text.ends_with("\n**model's claim (unverified):** _just \\`ls\\`\\, \\_honest\\__"),
            "{text}"
        );
        // Removing each escape pair gives back the value.
        let line = text
            .lines()
            .find(|l| l.starts_with("**arguments:** "))
            .unwrap();
        let shown = unescape(line.trim_start_matches("**arguments:** "));
        assert_eq!(shown, r#"{"command":"echo `id` **x** ||y|| <@1>"}"#);
    }

    /// What Discord displays for an escaped value: each backslash and
    /// the punctuation character after it as that character.
    fn unescape(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                out.push(chars.next().expect("an escape is a pair"));
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn discord_keeps_a_value_without_backticks_in_a_code_span() {
        let text = exec_card().render(CardStyle::Discord);
        assert!(text.contains("\n**action key:** `shell:ls`\n"), "{text}");
        assert!(
            text.contains("\n**arguments:** `{\"command\":\"ls -la\"}`\n"),
            "{text}"
        );
        assert!(
            text.contains("\n**runs:** runs on this host as davi\n"),
            "{text}"
        );
        assert!(
            text.ends_with("\n**model's claim (unverified):** _I\\'ll list them\\._"),
            "{text}"
        );
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
    fn a_character_that_reorders_or_hides_text_is_shown_as_its_code_point() {
        let mut card = exec_card();
        // Drawn by a bidi-aware surface as `{"command":"ls # sl- fr- mr"}`
        // without the fold: the override reverses what follows it.
        card.arguments = Some("{\"command\":\"rm -rf ~ \u{202E}# ls\"}".into());
        card.assistant_text =
            Some("listing\u{2028}action key: shell:ls\u{200B}\u{2066}x\u{2069}\u{E0041}".into());
        let lines = card.lines();
        let value = |label: &str| {
            lines
                .iter()
                .find(|l| l.label == label)
                .map(|l| l.value.clone())
                .unwrap()
        };
        assert_eq!(
            value("arguments"),
            "{\"command\":\"rm -rf ~ \\u{202e}# ls\"}"
        );
        assert_eq!(
            value(CLAIM_LABEL),
            "listing\\u{2028}action key: shell:ls\\u{200b}\\u{2066}x\\u{2069}\\u{e0041}"
        );
        for style in [
            CardStyle::Plain,
            CardStyle::Discord,
            CardStyle::TelegramHtml,
        ] {
            let text = card.render(style);
            assert!(
                !text.chars().any(shown_as_code_point),
                "{style:?}: {text:?}"
            );
            assert_eq!(text.lines().count(), lines.len(), "{style:?}: {text:?}");
        }
        // A written-out code point counts toward the cut like any
        // other character, so it cannot carry a value past it unseen.
        let padded = format!("{}\u{202E}", "a".repeat(MAX_VALUE_CHARS - 1));
        assert!(!shown_whole(&padded));
    }

    #[test]
    fn text_that_reads_as_it_runs_is_unchanged() {
        for s in ["héllo 世界 🙂", "a\u{00A0}b", "ﷺ", "שלום"] {
            assert_eq!(one_line(s), s);
        }
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
