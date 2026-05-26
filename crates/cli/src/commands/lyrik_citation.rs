//! Citation-resolution gate for staged Lyrik findings.
//!
//! Runs between staging emission and report aggregation. For every
//! finding the runner confirms the cited file exists and the cited
//! line resolves. Beyond that, class-specific structural sub-gates
//! fire based on title/summary keywords. Each sub-gate is a parser-
//! free check on the cited line plus a small window around it. The
//! gate tag on every per-finding annotation and audit row names
//! which sub-gate ran, so a reader can see exactly what was checked.
//!
//! The five sub-gates landed today:
//!
//! 1. `literal_claim`: title/summary mentions `hardcoded`,
//!    `hard-coded`, or `literal`. The cited window must carry a
//!    string `"..."` or a numeric literal. A doc comment, a field
//!    declaration, or a type reference fails.
//! 2. `prompt_injection_deferred`: title/summary mentions `prompt
//!    injection` or `prompt-injection`. **No structural check
//!    runs.** Prompt injection is a semantic property (untrusted
//!    text reaching model context inherits surrounding prompt's
//!    authority); the failure modes do not have a structural
//!    signature an in-line, parser-free check can verify. The
//!    finding resolves under file+line existence only. The gate
//!    tag exists to disclose that the routing was deliberate for
//!    this class, not a default fallthrough, so a reader skimming
//!    `prompt_injection_deferred` counts knows the citation has
//!    not been structurally checked. **`prompt_injection_deferred.resolved`
//!    carries the same caveat as `file_line_only.resolved`**: it
//!    means the file and line exist, nothing more. Do not count
//!    it in the "verified" column when summarizing a run; if
//!    anything, the deferred bucket is weaker than file_line_only
//!    because it always resolves on existence by design, never
//!    flagging a citation as unresolved even when the model is
//!    clearly hallucinating.
//! 3. `sql_injection_structural`: title/summary mentions `sql
//!    injection`, `sql-injection`, or `sqli`. The cited window
//!    must contain a SQL keyword (`SELECT`, `INSERT`, `UPDATE`,
//!    `DELETE`, `WHERE`, `FROM`, `JOIN`, `UNION`) AND an
//!    interpolation marker (`format!`, `{}` inside a string
//!    literal, or `+` adjacent to an identifier) AND NOT a
//!    parameter-binding marker (`?` placeholder in a string, `$N`
//!    postgres placeholder, `.bind(`, `query!(` macro). A
//!    parameterized query is the negative case and does NOT
//!    resolve. Limits: multi-line queries where the SQL keyword
//!    and the interpolation are more than 2 lines apart get
//!    missed; ORM-level injection that does not surface raw SQL
//!    keywords (Diesel DSL, sea-orm builder) gets missed.
//! 4. `command_injection_structural`: title/summary mentions
//!    `command injection`, `shell injection`, `shell=true`,
//!    `subprocess`, `eval`, `sh -c`, or generic `injection`
//!    fallback after prompt and sql have been ruled out. The
//!    cited window must carry an `ident(` call shape on a
//!    non-comment line. Confirms the cited line could host a
//!    call-shaped bug; does NOT prove the call's input is
//!    attacker-controlled. **The bare-`injection` fallback
//!    inherits the call-shape check.** A finding titled simply
//!    "injection vulnerability" with no class qualifier, or a
//!    deserialization-injection / header-injection / template-
//!    injection claim that doesn't carry one of the listed
//!    keywords, lands in `command_injection_structural` and is
//!    checked against call-shape. That may resolve or fail for
//!    the wrong reason (the underlying claim is about a
//!    different interpreter sink, but the check is generic). The
//!    gate tag discloses what ran; further class-specific
//!    detectors are tracked in #143.
//! 5. `file_line_only`: no claim-class keywords matched. The file
//!    exists and the line resolves; nothing further is checked.
//!
//! Priority order on multi-keyword findings: literal > prompt >
//! sql > command > file_line_only. The most-specific matching
//! sub-gate runs.
//!
//! **Structural, not exploitability.** Every sub-gate confirms that
//! the cited line *could plausibly host* the claimed bug class. None
//! of them prove the bug is real or attacker-reachable. That is the
//! deliberate boundary: Lyrik confirms real-and-reachable, exploit
//! verification is a separate workload (Lyrik's grade-0.5 ceiling).
//!
//! Claim classes without a wired matcher (missing access check,
//! race condition, broken comparison, data leakage, etc.) fall to
//! `file_line_only`. Two prior drafts of this slice included
//! sub-gates that were dropped before commit on the same honesty
//! principle:
//!
//! - `access_control_structural`: required the cited window to
//!   carry a call site or conditional keyword. Dropped because
//!   the check resolved on nearly any code line (any call site
//!   looks like "executable code where an auth check could live"),
//!   which would pad the verified side of the header count
//!   without verifying the missing-check claim.
//! - The earlier generic `injection_structural` is now split into
//!   `sql_injection_structural`, `command_injection_structural`,
//!   and `prompt_injection_deferred` per claim class. The same
//!   generic call-shape check is reused for the command-injection
//!   sub-class only; SQL and prompt have their own routing.
//!
//! Real detectors for the remaining unmatched classes need
//! stronger discriminators than a structural in-line check can
//! provide and are tracked in GitHub issue #143.
//!
//! Failure mode: keep the finding in the report, annotate it with
//! `citation_check.status = "unresolved"`, emit an audit row, and
//! surface counts in the canonical `findings.json` top-level
//! `citation_check` block split by sub-gate:
//!
//! ```json
//! "citation_check": {
//!   "literal_claim":               { "resolved": N, "unresolved": M },
//!   "prompt_injection_deferred":   { "resolved": N, "unresolved": M },
//!   "sql_injection_structural":    { "resolved": N, "unresolved": M },
//!   "command_injection_structural":{ "resolved": N, "unresolved": M },
//!   "file_line_only":              { "resolved": N, "unresolved": M }
//! }
//! ```
//!
//! Findings are never silently dropped.

use std::path::Path;

/// Result of running the gate on one staged finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    /// Which sub-gate ran. `LiteralClaim` ran when the title/summary
    /// triggered the literal heuristic; `FileLineOnly` ran when no
    /// claim-shape keywords were present and only file+line existence
    /// was checked.
    pub gate: Gate,
    /// Human-readable reason when `status` is `Unresolved`. None on
    /// resolved outcomes.
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Resolved,
    Unresolved,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Resolved => "resolved",
            Status::Unresolved => "unresolved",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    FileLineOnly,
    LiteralClaim,
    PromptInjectionDeferred,
    SqlInjectionStructural,
    CommandInjectionStructural,
}

impl Gate {
    pub fn as_str(self) -> &'static str {
        match self {
            Gate::FileLineOnly => "file_line_only",
            Gate::LiteralClaim => "literal_claim",
            Gate::PromptInjectionDeferred => "prompt_injection_deferred",
            Gate::SqlInjectionStructural => "sql_injection_structural",
            Gate::CommandInjectionStructural => "command_injection_structural",
        }
    }
}

const STRUCTURAL_WINDOW: usize = 2;
const LITERAL_CLAIM_WORDS: &[&str] = &["hardcoded", "hard-coded", "literal"];
const PROMPT_INJECTION_CLAIM_WORDS: &[&str] = &["prompt injection", "prompt-injection"];
const SQL_INJECTION_CLAIM_WORDS: &[&str] = &["sql injection", "sql-injection", "sqli"];
const COMMAND_INJECTION_CLAIM_WORDS: &[&str] = &[
    "command injection",
    "shell injection",
    "shell=true",
    "subprocess",
    "eval",
    "sh -c",
    "injection",
];

/// Check a parsed staged finding against the citation gate. `workspace`
/// is the path the agent received as its sandbox root (the target
/// directory). Returns an [`Outcome`] regardless of where the gate
/// stopped.
pub fn check(finding: &serde_json::Value, workspace: &Path) -> Outcome {
    let loc = match finding.get("location").and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return unresolved(Gate::FileLineOnly, "missing location object".to_string()),
    };
    let file = match loc.get("file").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        Some(_) | None => {
            return unresolved(
                Gate::FileLineOnly,
                "missing or empty location.file".to_string(),
            );
        }
    };
    let line = match loc.get("line_start").and_then(|v| v.as_u64()) {
        Some(n) if n >= 1 => n,
        _ => {
            return unresolved(
                Gate::FileLineOnly,
                "missing location.line_start".to_string(),
            );
        }
    };

    let target = workspace.join(file);
    let body = match std::fs::read_to_string(&target) {
        Ok(b) => b,
        Err(_) => {
            return unresolved(Gate::FileLineOnly, format!("file not readable: {file}"));
        }
    };
    let lines: Vec<&str> = body.lines().collect();
    let line_idx = (line as usize) - 1;
    if line_idx >= lines.len() {
        return unresolved(
            Gate::FileLineOnly,
            format!(
                "line {line} out of range ({} has {} lines)",
                file,
                lines.len()
            ),
        );
    }

    let window_lo = line_idx.saturating_sub(STRUCTURAL_WINDOW);
    let window_hi = (line_idx + STRUCTURAL_WINDOW).min(lines.len() - 1);
    let snippet = lines[line_idx].trim();

    if claims_literal(finding) {
        if (window_lo..=window_hi).any(|i| line_has_literal(lines[i])) {
            return resolved(Gate::LiteralClaim);
        }
        return unresolved(
            Gate::LiteralClaim,
            format!(
                "title/summary claims a hardcoded literal but no string or numeric literal appears in {file}:{line} (line content: {snippet:?})"
            ),
        );
    }
    if claims_prompt_injection(finding) {
        // Deferred-by-design: prompt injection has no parser-free
        // structural signature. The gate tag discloses this; the
        // resolve is existence-only on file+line, identical
        // semantics to file_line_only but tagged distinctly so the
        // routing is visible.
        let _ = snippet;
        return resolved(Gate::PromptInjectionDeferred);
    }
    if claims_sql_injection(finding) {
        let has_sql = (window_lo..=window_hi).any(|i| line_has_sql_keyword(lines[i]));
        let has_param = (window_lo..=window_hi).any(|i| line_has_param_binding(lines[i]));
        let has_interp = (window_lo..=window_hi).any(|i| line_has_concat_or_interp(lines[i]));
        if has_sql && has_interp && !has_param {
            return resolved(Gate::SqlInjectionStructural);
        }
        let reason = if !has_sql {
            format!(
                "title/summary claims SQL injection but no SQL keyword appears in {file}:{line} window (line content: {snippet:?})"
            )
        } else if has_param {
            format!(
                "title/summary claims SQL injection but {file}:{line} uses parameter binding (?/$N/.bind/query!), not concatenation (line content: {snippet:?})"
            )
        } else {
            format!(
                "title/summary claims SQL injection but no interpolation marker (format!, {{}}, +) appears in {file}:{line} window (line content: {snippet:?})"
            )
        };
        return unresolved(Gate::SqlInjectionStructural, reason);
    }
    if claims_command_injection(finding) {
        if (window_lo..=window_hi).any(|i| line_has_call_or_exec(lines[i])) {
            return resolved(Gate::CommandInjectionStructural);
        }
        return unresolved(
            Gate::CommandInjectionStructural,
            format!(
                "title/summary claims a command injection vulnerability but no call/exec/spawn-shaped construct appears in {file}:{line} (line content: {snippet:?})"
            ),
        );
    }
    let _ = snippet;
    resolved(Gate::FileLineOnly)
}

fn resolved(gate: Gate) -> Outcome {
    Outcome {
        status: Status::Resolved,
        gate,
        reason: None,
    }
}

fn unresolved(gate: Gate, reason: String) -> Outcome {
    Outcome {
        status: Status::Unresolved,
        gate,
        reason: Some(reason),
    }
}

fn claim_text(finding: &serde_json::Value) -> String {
    let title = finding
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    let summary = finding
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    format!("{title} {summary}")
}

fn claims_literal(finding: &serde_json::Value) -> bool {
    let t = claim_text(finding);
    LITERAL_CLAIM_WORDS.iter().any(|w| t.contains(w))
}

fn claims_prompt_injection(finding: &serde_json::Value) -> bool {
    let t = claim_text(finding);
    PROMPT_INJECTION_CLAIM_WORDS.iter().any(|w| t.contains(w))
}

fn claims_sql_injection(finding: &serde_json::Value) -> bool {
    let t = claim_text(finding);
    SQL_INJECTION_CLAIM_WORDS.iter().any(|w| t.contains(w))
}

fn claims_command_injection(finding: &serde_json::Value) -> bool {
    let t = claim_text(finding);
    COMMAND_INJECTION_CLAIM_WORDS.iter().any(|w| t.contains(w))
}

/// True if the line contains a string or numeric literal. Permissive
/// by design: any `"x` opening counts as a string literal (catches
/// the opening line of a multi-line string), and any digit run not
/// adjacent to an identifier character counts as a numeric literal
/// (so `u32`, `Vec<u8>`, `mpsc::Receiver` do not trip it). Hex/oct/bin
/// literals (`0xABCD`) are not covered yet; the gate stays narrow
/// rather than catch every shape and risk false positives.
pub fn line_has_literal(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let mut content_len = 0usize;
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'"' {
                content_len += 1;
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    j += 2;
                } else {
                    j += 1;
                }
            }
            if content_len > 0 {
                return true;
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let run_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
            i += 1;
        }
        let prev_ok = run_start == 0 || !is_ident_char(bytes[run_start - 1]);
        let next_ok = i == bytes.len() || !is_ident_char(bytes[i]);
        if prev_ok && next_ok {
            return true;
        }
    }
    false
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

const SQL_KEYWORDS: &[&str] = &[
    "SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM", "JOIN", "UNION",
];

/// True when the line carries a SQL keyword (case-insensitive). Used
/// by the SQL-injection sub-gate as the first of three conditions
/// (SQL keyword + interpolation + no param-binding).
pub fn line_has_sql_keyword(s: &str) -> bool {
    if is_comment_line(s) {
        return false;
    }
    let upper = s.to_uppercase();
    SQL_KEYWORDS.iter().any(|kw| upper.contains(kw))
}

/// True when the line carries a string-interpolation or
/// concatenation marker that could fold caller-controlled data into
/// a constructed SQL string. Catches `format!`, `write!`,
/// `println!`-shaped macros, `{}` placeholders inside a double-quoted
/// string, and `"..." + ident` / `ident + "..."` concatenation.
pub fn line_has_concat_or_interp(s: &str) -> bool {
    if is_comment_line(s) {
        return false;
    }
    for macro_kw in ["format!", "format_args!", "write!", "writeln!"] {
        if s.contains(macro_kw) {
            return true;
        }
    }
    // `{}` inside a string literal.
    let bytes = s.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            in_string = !in_string;
            i += 1;
            continue;
        }
        if in_string && bytes[i] == b'{' && bytes.get(i + 1) != Some(&b'{') {
            return true;
        }
        i += 1;
    }
    // `"..." +` or `+ "..."` concatenation patterns.
    if s.contains("\" +") || s.contains("+ \"") {
        return true;
    }
    false
}

/// True when the line carries a parameter-binding marker that
/// indicates a parameterized (safe) query rather than concatenation.
/// `?` or `$N` placeholders inside a string literal, `.bind(` calls,
/// and the sqlx `query!`/`query_as!`/`query_scalar!` macros which
/// are parameterized by design. This is the **negative case** for
/// the SQL-injection sub-gate: a window with these markers does NOT
/// resolve as a bug site.
pub fn line_has_param_binding(s: &str) -> bool {
    if is_comment_line(s) {
        return false;
    }
    if s.contains(".bind(") || s.contains(".bind_") {
        return true;
    }
    for macro_kw in [
        "query!(",
        "query_as!(",
        "query_scalar!(",
        "query_unchecked!(",
    ] {
        if s.contains(macro_kw) {
            return true;
        }
    }
    // `?` placeholder inside a string literal.
    let bytes = s.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            in_string = !in_string;
            i += 1;
            continue;
        }
        if in_string && bytes[i] == b'?' {
            return true;
        }
        i += 1;
    }
    // `$N` postgres placeholder.
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'$' && bytes[i + 1].is_ascii_digit() {
            return true;
        }
    }
    false
}

/// Heuristic comment-line detector for Rust source. Lines starting with
/// `//`, `///`, `//!`, `/*`, `*/`, or a `* ` block-continuation count.
/// A line starting with `*` followed by an ident-char (deref) is code,
/// not a comment.
fn is_comment_line(s: &str) -> bool {
    let t = s.trim_start();
    if t.starts_with("//") || t.starts_with("/*") || t.starts_with("*/") {
        return true;
    }
    if t == "*" {
        return true;
    }
    if let Some(rest) = t.strip_prefix('*') {
        match rest.chars().next() {
            Some(c) if c.is_whitespace() => return true,
            Some('*') => return true,
            _ => {}
        }
    }
    false
}

/// True when the line carries an `ident(` call shape on a non-comment
/// line. Catches function calls, method calls, macro calls, constructor
/// calls, and exec/spawn shapes (`Command::new(...)`, `subprocess.run(...)`,
/// `eval(...)`, etc.) without parsing. Rejects comment lines and lines
/// whose `(` follows whitespace or punctuation (tuple literals,
/// parenthesized expressions, control-flow head `if (cond)` already
/// covered by [`line_has_conditional`]).
pub fn line_has_call_or_exec(s: &str) -> bool {
    if is_comment_line(s) {
        return false;
    }
    let bytes = s.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] != b'(' {
            continue;
        }
        let prev = bytes[i - 1];
        // ident/digit before `(` is the standard call shape; `!` is
        // the Rust macro-call shape (`println!(...)`, `format!(...)`).
        if is_ident_char(prev) || prev.is_ascii_digit() || prev == b'!' {
            return true;
        }
    }
    false
}

/// Annotate a parsed finding with the gate outcome. Adds a
/// `citation_check` object as an extra per-finding field (schema 1.1
/// allows extras). Idempotent: a finding that already carries
/// `citation_check` from an upstream pass is left untouched so this
/// gate never overwrites a stricter result.
pub fn annotate(finding: &mut serde_json::Value, outcome: &Outcome) {
    let obj = match finding.as_object_mut() {
        Some(o) => o,
        None => return,
    };
    if obj.contains_key("citation_check") {
        return;
    }
    let mut block = serde_json::Map::new();
    block.insert(
        "gate".to_string(),
        serde_json::Value::String(outcome.gate.as_str().to_string()),
    );
    block.insert(
        "status".to_string(),
        serde_json::Value::String(outcome.status.as_str().to_string()),
    );
    if let Some(reason) = &outcome.reason {
        block.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.clone()),
        );
    }
    obj.insert(
        "citation_check".to_string(),
        serde_json::Value::Object(block),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    fn tmpdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lyrik-citation-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_src(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, body).unwrap();
    }

    #[test]
    fn hallucinated_literal_at_field_decl_fails() {
        // The adapter-signal shape: line 105 is a Receiver field, no
        // literal anywhere within +/-2 lines, but the model claimed
        // "hardcoded phone number".
        let dir = tmpdir();
        let src = "\
struct Adapter {
    // (101)
    // (102)
    // (103)
    next_req_id: AtomicU64,
    inner: Mutex<Option<Arc<Connection>>>,
    inbound_tx: mpsc::Sender<(SignalInbound, InboundKind)>,
    inbound_rx: Mutex<Option<mpsc::Receiver<(SignalInbound, InboundKind)>>>,
    formatter: SignalFormatter,
    name: String,
}
";
        write_src(&dir, "src/adapter.rs", src);
        let finding = json!({
            "title": "Hardcoded phone number in Signal adapter configuration",
            "summary": "The Signal adapter uses a hardcoded phone number for signal-cli communication.",
            "location": {"file": "src/adapter.rs", "line_start": 8},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Unresolved);
        assert_eq!(out.gate, Gate::LiteralClaim);
        assert!(out.reason.unwrap().contains("no string or numeric literal"));
    }

    #[test]
    fn real_string_literal_passes() {
        let dir = tmpdir();
        let src = "\
const PHONE: &str = \"+15551234567\";
fn main() {}
";
        write_src(&dir, "src/lib.rs", src);
        let finding = json!({
            "title": "Hardcoded phone literal",
            "summary": "A hardcoded phone number literal is embedded in the source.",
            "location": {"file": "src/lib.rs", "line_start": 1},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
        assert_eq!(out.gate, Gate::LiteralClaim);
        assert!(out.reason.is_none());
    }

    #[test]
    fn literal_inside_macro_passes() {
        let dir = tmpdir();
        let src = "\
fn check(x: &str) {
    assert_eq!(x, \"admin\");
}
";
        write_src(&dir, "src/check.rs", src);
        let finding = json!({
            "title": "Hardcoded admin string literal",
            "summary": "The admin string is hardcoded as a literal comparison target.",
            "location": {"file": "src/check.rs", "line_start": 2},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
        assert_eq!(out.gate, Gate::LiteralClaim);
    }

    #[test]
    fn multiline_string_continuation_line_passes_via_window() {
        // Citation lands on the middle line of a multi-line string.
        // The opening `"` is two lines above; the window saves the
        // gate from a false negative.
        let dir = tmpdir();
        let src = "\
fn doc() -> &'static str {
    \"first
second
third\"
}
";
        write_src(&dir, "src/doc.rs", src);
        let finding = json!({
            "title": "Hardcoded multi-line literal",
            "summary": "The doc string is a hardcoded literal.",
            "location": {"file": "src/doc.rs", "line_start": 3},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
    }

    #[test]
    fn numeric_literal_passes() {
        let dir = tmpdir();
        let src = "\
const TIMEOUT_MS: u64 = 30000;
fn main() {}
";
        write_src(&dir, "src/lib.rs", src);
        let finding = json!({
            "title": "Hardcoded numeric literal timeout",
            "summary": "A hardcoded numeric literal sets the timeout.",
            "location": {"file": "src/lib.rs", "line_start": 1},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
    }

    #[test]
    fn missing_access_claim_routes_to_file_line_only() {
        // Access-control claims have no class-specific sub-gate
        // today (an earlier draft included one that resolved on
        // nearly any code line; dropped to keep the header honest).
        // The claim falls through to file_line_only, which the gate
        // tag discloses on every such row.
        let dir = tmpdir();
        let src = "\
fn process_request(req: Request) {
    // no auth check before privileged action
    do_privileged(req);
}
";
        write_src(&dir, "src/handler.rs", src);
        let finding = json!({
            "title": "Missing access check before privileged operation",
            "summary": "The handler invokes a privileged action without verifying caller identity.",
            "location": {"file": "src/handler.rs", "line_start": 3},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
        assert_eq!(out.gate, Gate::FileLineOnly);
    }

    #[test]
    fn missing_file_fails() {
        let dir = tmpdir();
        let finding = json!({
            "title": "Some bug",
            "summary": "A description.",
            "location": {"file": "src/does-not-exist.rs", "line_start": 10},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Unresolved);
        assert_eq!(out.gate, Gate::FileLineOnly);
        assert!(out.reason.unwrap().contains("not readable"));
    }

    #[test]
    fn line_out_of_range_fails() {
        let dir = tmpdir();
        write_src(&dir, "src/short.rs", "fn main() {}\n");
        let finding = json!({
            "title": "Out of range cite",
            "summary": "Cites a line that does not exist.",
            "location": {"file": "src/short.rs", "line_start": 9999},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Unresolved);
        assert!(out.reason.unwrap().contains("out of range"));
    }

    #[test]
    fn missing_location_fails() {
        let dir = tmpdir();
        let finding = json!({
            "title": "No location",
            "summary": "No location.",
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Unresolved);
        assert!(out.reason.unwrap().contains("missing location"));
    }

    #[test]
    fn line_has_literal_rejects_type_refs() {
        // u32, u64, Vec<u8> contain digits but are not literals.
        assert!(!line_has_literal("let x: u32 = foo();"));
        assert!(!line_has_literal("let v: Vec<u8> = Vec::new();"));
        assert!(!line_has_literal(
            "    inbound_rx: Mutex<Option<mpsc::Receiver<(SignalInbound, InboundKind)>>>,"
        ));
    }

    #[test]
    fn line_has_literal_accepts_strings_and_numbers() {
        assert!(line_has_literal("let s = \"hello\";"));
        assert!(line_has_literal("let n = 42;"));
        assert!(line_has_literal("const PORT: u16 = 8080;"));
        assert!(line_has_literal("assert_eq!(x, \"admin\");"));
        assert!(!line_has_literal("let s = \"\";"));
        assert!(!line_has_literal("// no content"));
    }

    #[test]
    fn annotate_writes_block() {
        let mut finding = json!({"id": "F001"});
        let out = Outcome {
            status: Status::Unresolved,
            gate: Gate::LiteralClaim,
            reason: Some("x".to_string()),
        };
        annotate(&mut finding, &out);
        let block = finding.get("citation_check").unwrap();
        assert_eq!(block.get("status").unwrap().as_str(), Some("unresolved"));
        assert_eq!(block.get("gate").unwrap().as_str(), Some("literal_claim"));
        assert_eq!(block.get("reason").unwrap().as_str(), Some("x"));
    }

    #[test]
    fn annotate_is_idempotent() {
        let mut finding = json!({
            "id": "F001",
            "citation_check": {"status": "unresolved", "gate": "literal_claim", "reason": "kept"}
        });
        let out = Outcome {
            status: Status::Resolved,
            gate: Gate::FileLineOnly,
            reason: None,
        };
        annotate(&mut finding, &out);
        let block = finding.get("citation_check").unwrap();
        assert_eq!(block.get("status").unwrap().as_str(), Some("unresolved"));
        assert_eq!(block.get("reason").unwrap().as_str(), Some("kept"));
    }

    /// F002-shape: HIGH command-injection finding citing a doc-comment
    /// line with no executable construct anywhere in the cited window.
    /// The probe surfaced this exact failure (`adapter.rs:125`
    /// "command injection" landing on a doc-comment line). The
    /// command_injection_structural sub-gate must flag it unresolved.
    #[test]
    fn command_injection_claim_cited_at_doc_comment_fails() {
        let dir = tmpdir();
        let src = "\
/// Reads frames from the channel adapter. The reader runs on a
/// dedicated task and feeds the gateway directly without buffering
/// across reconnects. Frames that arrive while the gateway is
/// transiently unreachable are dropped; the channel adapter is
/// expected to re-emit them when it next connects.
struct Reader {
    inner: Inner,
}
";
        write_src(&dir, "src/adapter.rs", src);
        let finding = json!({
            "title": "Potential command injection via user-controlled input in Signal adapter",
            "summary": "The send_message function may pass unsanitised input to a shell.",
            "location": {"file": "src/adapter.rs", "line_start": 3},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Unresolved);
        assert_eq!(out.gate, Gate::CommandInjectionStructural);
        assert!(
            out.reason
                .unwrap()
                .contains("no call/exec/spawn-shaped construct")
        );
    }

    #[test]
    fn command_injection_claim_at_call_site_passes() {
        let dir = tmpdir();
        let src = "\
fn run_signal(cmd: &str) {
    let output = Command::new(\"sh\").arg(\"-c\").arg(cmd).output();
    drop(output);
}
";
        write_src(&dir, "src/run.rs", src);
        let finding = json!({
            "title": "Potential command injection in run_signal",
            "summary": "subprocess invocation may accept attacker-controlled input.",
            "location": {"file": "src/run.rs", "line_start": 2},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
        assert_eq!(out.gate, Gate::CommandInjectionStructural);
        assert!(out.reason.is_none());
    }

    /// Negative case: a SQL-injection finding citing a parameterized
    /// query (sqlx `query!` macro) must NOT resolve. The structural
    /// detector sees the SQL keyword AND the parameterized-binding
    /// marker; that combination is the safe shape, not the bug
    /// shape.
    #[test]
    fn sql_injection_claim_at_parameterized_query_fails() {
        let dir = tmpdir();
        let src = "\
async fn lookup_user(pool: &PgPool, user_id: i64) -> Result<User, Error> {
    let row = sqlx::query!(\"SELECT * FROM users WHERE id = ?\", user_id)
        .fetch_one(pool)
        .await?;
    Ok(User::from_row(row))
}
";
        write_src(&dir, "src/db.rs", src);
        let finding = json!({
            "title": "Potential SQL injection in lookup_user",
            "summary": "User-controlled id appears in a database query.",
            "location": {"file": "src/db.rs", "line_start": 2},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Unresolved);
        assert_eq!(out.gate, Gate::SqlInjectionStructural);
        assert!(out.reason.unwrap().contains("parameter binding"));
    }

    /// Positive case: a SQL-injection finding citing concatenated
    /// query text resolves. The detector sees a SQL keyword AND
    /// `format!` interpolation AND no parameter-binding marker.
    #[test]
    fn sql_injection_claim_at_concatenated_query_passes() {
        let dir = tmpdir();
        let src = "\
async fn search(pool: &PgPool, keyword: &str) -> Result<Vec<Row>, Error> {
    let q = format!(\"SELECT * FROM items WHERE name = '{}'\", keyword);
    sqlx::raw(&q).fetch_all(pool).await
}
";
        write_src(&dir, "src/search.rs", src);
        let finding = json!({
            "title": "Potential SQL injection in search handler",
            "summary": "User keyword is interpolated into the query string via format!.",
            "location": {"file": "src/search.rs", "line_start": 2},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
        assert_eq!(out.gate, Gate::SqlInjectionStructural);
        assert!(out.reason.is_none());
    }

    /// SQL-injection claim cited at a line with no SQL keyword
    /// (model hallucinated a SQL bug at a non-SQL site): unresolved.
    #[test]
    fn sql_injection_claim_at_non_sql_site_fails() {
        let dir = tmpdir();
        let src = "\
fn handle_message(msg: &str) {
    log::info!(\"received message: {}\", msg);
    process(msg);
}
";
        write_src(&dir, "src/handler.rs", src);
        let finding = json!({
            "title": "Potential SQL injection in handle_message",
            "summary": "Attacker-controlled message may reach the database layer.",
            "location": {"file": "src/handler.rs", "line_start": 2},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Unresolved);
        assert_eq!(out.gate, Gate::SqlInjectionStructural);
        assert!(out.reason.unwrap().contains("no SQL keyword"));
    }

    /// Prompt-injection claim routes to the deferred sub-gate.
    /// The cited line and file just need to exist; no structural
    /// check runs. The gate tag discloses the routing.
    #[test]
    fn prompt_injection_claim_routes_to_deferred() {
        let dir = tmpdir();
        let src = "\
fn build_prompt(user_input: &str) -> String {
    format!(\"You are a helpful assistant. User says: {}\", user_input)
}
";
        write_src(&dir, "src/agent.rs", src);
        let finding = json!({
            "title": "Potential prompt injection in build_prompt",
            "summary": "Untrusted user input folded into the system prompt.",
            "location": {"file": "src/agent.rs", "line_start": 2},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
        assert_eq!(out.gate, Gate::PromptInjectionDeferred);
        assert!(out.reason.is_none());
    }

    /// Priority ordering: a finding mentioning both "prompt injection"
    /// and "command injection" routes to prompt (higher priority),
    /// not command. Regression guard on the dispatch ordering.
    #[test]
    fn prompt_injection_wins_priority_over_command_injection() {
        let dir = tmpdir();
        let src = "fn main() { let x = 1; }\n";
        write_src(&dir, "src/main.rs", src);
        let finding = json!({
            "title": "Prompt injection and command injection combined risk",
            "summary": "User input reaches both shell and model context.",
            "location": {"file": "src/main.rs", "line_start": 1},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.gate, Gate::PromptInjectionDeferred);
    }

    /// Priority ordering: a finding mentioning both "sql injection"
    /// and "command injection" routes to sql (higher priority), not
    /// command.
    #[test]
    fn sql_injection_wins_priority_over_command_injection() {
        let dir = tmpdir();
        let src = "\
fn lookup(id: &str) -> String {
    format!(\"SELECT * FROM t WHERE id = '{}'\", id)
}
";
        write_src(&dir, "src/db.rs", src);
        let finding = json!({
            "title": "SQL injection or possibly command injection in lookup",
            "summary": "User id may flow into both query and a shell call.",
            "location": {"file": "src/db.rs", "line_start": 2},
        });
        let out = check(&finding, &dir);
        // sql wins over command; window has SQL+interp+no-param, so resolved.
        assert_eq!(out.status, Status::Resolved);
        assert_eq!(out.gate, Gate::SqlInjectionStructural);
    }

    /// Regression: the literal-claim path is unchanged by the
    /// injection split. A "hardcoded shell command" finding still
    /// routes to LiteralClaim (highest priority), not command.
    #[test]
    fn literal_path_still_wins_over_command_injection() {
        let dir = tmpdir();
        let src = "\
const SHELL_PATH: &str = \"/bin/sh\";
fn run() {}
";
        write_src(&dir, "src/lib.rs", src);
        let finding = json!({
            "title": "Hardcoded shell path used in command injection sink",
            "summary": "A hardcoded literal feeds a subprocess invocation.",
            "location": {"file": "src/lib.rs", "line_start": 1},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
        assert_eq!(out.gate, Gate::LiteralClaim);
    }

    /// Regression: unrecognized claim class still falls to
    /// file_line_only. The split didn't affect the fallback path.
    #[test]
    fn unrecognized_claim_class_still_falls_to_file_line_only() {
        let dir = tmpdir();
        let src = "fn slow() { /* compute */ }\n";
        write_src(&dir, "src/perf.rs", src);
        let finding = json!({
            "title": "Possible timing side-channel via elapsed measurement",
            "summary": "Branch timing leaks information.",
            "location": {"file": "src/perf.rs", "line_start": 1},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
        assert_eq!(out.gate, Gate::FileLineOnly);
    }

    #[test]
    fn line_has_sql_keyword_accepts_common_keywords() {
        assert!(line_has_sql_keyword(
            "let q = format!(\"SELECT * FROM t WHERE id = {}\", id);"
        ));
        assert!(line_has_sql_keyword(
            "    \"INSERT INTO users (name) VALUES ($1)\","
        ));
        assert!(line_has_sql_keyword(
            "let upd = \"UPDATE t SET x = 1 WHERE id = ?\";"
        ));
        assert!(!line_has_sql_keyword("// SELECT * FROM t -- in a comment"));
        assert!(!line_has_sql_keyword("let elapsed = inst.elapsed();"));
    }

    #[test]
    fn line_has_param_binding_accepts_safe_shapes() {
        assert!(line_has_param_binding(
            "sqlx::query!(\"SELECT * FROM t WHERE id = ?\", id)"
        ));
        assert!(line_has_param_binding(
            "client.query(\"SELECT * FROM t WHERE id = $1\", &[&id])"
        ));
        assert!(line_has_param_binding("stmt.bind(0, &user_id);"));
        assert!(!line_has_param_binding(
            "let q = format!(\"SELECT * FROM t WHERE id = {}\", id);"
        ));
    }

    #[test]
    fn line_has_concat_or_interp_accepts_interpolation() {
        assert!(line_has_concat_or_interp(
            "let q = format!(\"SELECT * FROM t WHERE id = {}\", id);"
        ));
        assert!(line_has_concat_or_interp(
            "let q = \"SELECT * FROM t WHERE id = \" + &id_str;"
        ));
        assert!(!line_has_concat_or_interp(
            "sqlx::query!(\"SELECT * FROM t WHERE id = ?\", id)"
        ));
        assert!(!line_has_concat_or_interp("let x = 1;"));
    }

    // Note: an earlier draft of this slice carried two
    // access-control structural tests (cite-at-comment-fails and
    // cite-at-conditional-passes) against a Gate::AccessControlStructural
    // sub-gate. The sub-gate was dropped before commit because its
    // resolved count nearly always lit up under the "executable code"
    // check, padding the verified side of the header without
    // verifying the missing-check claim. Access-control claims now
    // route to file_line_only; see missing_access_claim_routes_to_file_line_only

    #[test]
    fn unrecognized_claim_class_falls_to_file_line_only() {
        let dir = tmpdir();
        let src = "\
fn timing_sensitive() {
    let elapsed = std::time::Instant::now().elapsed();
    drop(elapsed);
}
";
        write_src(&dir, "src/timing.rs", src);
        // Claim is a class with no matcher today: timing side-channel.
        // No literal/injection/access-control keywords in title or
        // summary, so the gate falls to file_line_only and the tag
        // discloses that.
        let finding = json!({
            "title": "Possible timing side-channel via elapsed measurement",
            "summary": "Information leak through wall-clock difference between branches.",
            "location": {"file": "src/timing.rs", "line_start": 2},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
        assert_eq!(
            out.gate,
            Gate::FileLineOnly,
            "no class matcher should fall to file_line_only and tag must say so"
        );
        assert!(out.reason.is_none());
    }

    #[test]
    fn literal_path_unchanged_by_new_gates() {
        // Regression guard: the existing literal-claim shape still
        // routes through Gate::LiteralClaim, not InjectionStructural,
        // even when the title mentions an interpreter-shaped sink.
        let dir = tmpdir();
        let src = "\
const PHONE: &str = \"+15551234567\";
fn main() {}
";
        write_src(&dir, "src/lib.rs", src);
        let finding = json!({
            "title": "Hardcoded phone number used as eval target",
            "summary": "A hardcoded literal is interpolated into a subprocess invocation.",
            "location": {"file": "src/lib.rs", "line_start": 1},
        });
        let out = check(&finding, &dir);
        assert_eq!(out.status, Status::Resolved);
        // Literal wins on priority even though `eval` and `subprocess`
        // both appear in title/summary.
        assert_eq!(out.gate, Gate::LiteralClaim);
    }

    #[test]
    fn line_has_call_or_exec_rejects_comments_and_field_decls() {
        assert!(!line_has_call_or_exec(
            "/// doc: signal-cli is invoked here"
        ));
        assert!(!line_has_call_or_exec("// run shell command"));
        assert!(!line_has_call_or_exec("    inbound_rx: Receiver<Frame>,"));
        assert!(!line_has_call_or_exec("let v: Vec<u8> = something;"));
        assert!(!line_has_call_or_exec("let x = (a, b);"));
    }

    #[test]
    fn line_has_call_or_exec_accepts_call_shapes() {
        assert!(line_has_call_or_exec(
            "let out = Command::new(\"sh\").arg(cmd).output();"
        ));
        assert!(line_has_call_or_exec("subprocess.run(user_input);"));
        assert!(line_has_call_or_exec("eval(payload);"));
        assert!(line_has_call_or_exec("self.inner.process(frame);"));
        assert!(line_has_call_or_exec("println!(\"x = {x}\");"));
    }

    /// On-demand demonstration of the F002-shape gate behaviour and
    /// audit-row content. Marked `#[ignore]` so the regular test
    /// suite does not run it; invoke manually with
    /// `cargo test -p wirken-cli --bins -- --ignored --nocapture
    /// f002_outcome_demo`.
    #[test]
    #[ignore]
    fn f002_outcome_demo() {
        let dir = tmpdir();
        let src = "\
/// Reads frames from the channel adapter. The reader runs on a
/// dedicated task and feeds the gateway directly without buffering
/// across reconnects. Frames that arrive while the gateway is
/// transiently unreachable are dropped; the channel adapter is
/// expected to re-emit them when it next connects.
struct Reader {
    inner: Inner,
}
";
        write_src(&dir, "src/adapter.rs", src);

        // F002-shape: a HIGH command-injection finding cited at a
        // doc-comment line. Reproduces the qwen3-coder hallucination
        // the gate is built to catch.
        let mut finding = json!({
            "id": "F002",
            "stable_id": "injection::src/adapter.rs:3",
            "framing": ["injection"],
            "location": {"file": "src/adapter.rs", "line_start": 3},
            "title": "Potential command injection via user-controlled input in Signal adapter",
            "summary": "The send_message function may pass unsanitised input to a shell.",
            "tier": "HIGH",
        });
        let outcome = check(&finding, &dir);
        annotate(&mut finding, &outcome);

        eprintln!("\n=== F002 outcome ===");
        eprintln!("gate:   {}", outcome.gate.as_str());
        eprintln!("status: {}", outcome.status.as_str());
        eprintln!("reason: {}", outcome.reason.as_deref().unwrap_or("(none)"));
        eprintln!("\n=== F002 audit-row payload shape ===");
        let audit_payload = json!({
            "staged_path": dir.join("staging/findings/finding-001.json").display().to_string(),
            "finding_id": finding.get("id"),
            "stable_id": finding.get("stable_id"),
            "location_file": finding.pointer("/location/file"),
            "location_line": finding.pointer("/location/line_start"),
            "gate": outcome.gate.as_str(),
            "status": outcome.status.as_str(),
            "reason": outcome.reason,
        });
        eprintln!("{}", serde_json::to_string_pretty(&audit_payload).unwrap());
        eprintln!("\n=== F002 per-finding annotation ===");
        eprintln!(
            "{}",
            serde_json::to_string_pretty(finding.get("citation_check").unwrap()).unwrap()
        );

        // Sanity asserts so the demo still functions as a regression
        // guard if someone runs it on purpose.
        assert_eq!(outcome.status, Status::Unresolved);
        assert_eq!(outcome.gate, Gate::CommandInjectionStructural);
    }
}
