//! Citation-resolution gate for staged Lyrik findings.
//!
//! Runs between staging emission and report aggregation. For each
//! finding, opens the cited file at the cited line and verifies two
//! things:
//!
//! 1. **File + line resolve.** `location.file` must exist inside the
//!    workspace and `location.line_start` must point at a real line.
//! 2. **Literal claim is honest.** If the finding's title or summary
//!    contains a hardcoded-literal claim word (`hardcoded`,
//!    `hard-coded`, `literal`), the cited line, or any line within a
//!    small window around it, must carry a string or numeric literal.
//!    A field declaration, a type reference, or a comment line carries
//!    no literal and fails the gate.
//!
//! The gate is intentionally narrow. It catches the failure shape
//! observed during the qwen3-coder local-emit run (`adapter.rs:105`
//! cited as "hardcoded phone number" when the line was an
//! `mpsc::Receiver` field) plus the immediate class around it. It
//! does NOT verify citations for other claim shapes ("missing
//! access check", "race condition", "broken comparison"). Per-finding
//! annotation names the gate that ran so consumers can read the
//! scope honestly.
//!
//! Failure mode: keep the finding in the report, annotate it with
//! `citation_check.status = "unresolved"`, emit an audit row, and
//! surface counts in the canonical `findings.json` top-level
//! `citation_check` block. Counts split by gate so a skimmer cannot
//! infer "two citations verified" from `resolved: 2` when one of the
//! two only had file+line existence checked:
//!
//! ```json
//! "citation_check": {
//!   "literal_claim":   { "resolved": N, "unresolved": M },
//!   "file_line_only":  { "resolved": N, "unresolved": M }
//! }
//! ```
//!
//! `resolved` under `literal_claim` means the literal heuristic ran
//! and the cited window carries a literal. `resolved` under
//! `file_line_only` means the file and line exist; the title/summary
//! carried no literal-claim keyword, so the heuristic was not engaged
//! and the citation is not "verified" beyond existence. Findings are
//! never silently dropped.

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
}

impl Gate {
    pub fn as_str(self) -> &'static str {
        match self {
            Gate::FileLineOnly => "file_line_only",
            Gate::LiteralClaim => "literal_claim",
        }
    }
}

const LITERAL_WINDOW: usize = 2;
const LITERAL_CLAIM_WORDS: &[&str] = &["hardcoded", "hard-coded", "literal"];

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

    if !claims_literal(finding) {
        return resolved(Gate::FileLineOnly);
    }

    let window_lo = line_idx.saturating_sub(LITERAL_WINDOW);
    let window_hi = (line_idx + LITERAL_WINDOW).min(lines.len() - 1);
    if (window_lo..=window_hi).any(|i| line_has_literal(lines[i])) {
        return resolved(Gate::LiteralClaim);
    }
    unresolved(
        Gate::LiteralClaim,
        format!(
            "title/summary claims a hardcoded literal but no string or numeric literal appears in {file}:{} (line content: {:?})",
            line,
            lines[line_idx].trim()
        ),
    )
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

fn claims_literal(finding: &serde_json::Value) -> bool {
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
    LITERAL_CLAIM_WORDS
        .iter()
        .any(|w| title.contains(w) || summary.contains(w))
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
    fn non_literal_claim_skips_heuristic() {
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
}
