//! `wirken sessions verify` reports an approval whose prompt said one
//! place for an `exec` while the command ran in another.
//!
//! The chain carries both halves: the approval row records what the
//! prompt told the operator, and the exec's result row records where the
//! command ran. The rows are written directly, the way a gateway would
//! have written them, and the real binary verifies them.

mod common;

use std::path::Path;
use std::process::Output;

use common::{ScriptedModel, register_agent, wirken};
use wirken_audit::{
    ApprovalScopeKind, ApprovalSource, ExecLocation, SandboxModeLabel, SandboxProvenance,
    SandboxRuntimeLabel, SessionEvent, SessionId, SessionLog, SqliteSessionLog, TrustLevel,
};

const TOLD: &str =
    "runs in sandbox container (exec_only, read-only root, workspace at /workspace, no network)";

fn write_session(data: &Path, ran: (SandboxModeLabel, SandboxRuntimeLabel)) {
    let model = ScriptedModel::start(Vec::new());
    register_agent(data, "narrow", &model);
    let log = SqliteSessionLog::open(&data.join("audit.db")).unwrap();
    let handle = log.handle_for(SessionId::new("narrow".to_string()));
    log.append(
        &handle,
        TrustLevel::System,
        SessionEvent::PermissionApproved {
            action_key: "shell:ls".into(),
            agent_id: "narrow".into(),
            approved_by: "davi".into(),
            scope: ApprovalScopeKind::OneShot,
            session_id: None,
            approved_via: Some(ApprovalSource::Cli),
            adapter_id: None,
            sender_id: None,
            tier: Some("tier2".into()),
            expires_at: None,
            exec_location: Some(ExecLocation {
                mode: SandboxModeLabel::ExecOnly,
                text: TOLD.into(),
            }),
        },
    )
    .unwrap();
    log.append(
        &handle,
        TrustLevel::Tool,
        SessionEvent::ToolResult {
            call_id: "call_ls".into(),
            tool_name: "exec".into(),
            output: "bin\n".into(),
            success: true,
            sandbox: Some(SandboxProvenance {
                mode: ran.0,
                runtime: ran.1,
                container_id: None,
            }),
            agent_id: "narrow".into(),
            adapter_id: None,
            sender_id: None,
        },
    )
    .unwrap();
}

fn verify(data: &Path) -> Output {
    wirken(data)
        .args(["sessions", "verify", "narrow"])
        .output()
        .unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn verify_says_so_when_the_prompt_and_the_run_disagree() {
    let data = tempfile::tempdir().unwrap();
    write_session(
        data.path(),
        (SandboxModeLabel::Off, SandboxRuntimeLabel::Host),
    );
    let out = verify(data.path());
    let report = text(&out);
    assert_eq!(out.status.code(), Some(1), "a divergence: {report}");
    assert!(report.contains("[exec_location]"), "{report}");
    assert!(
        report.contains("The approval at seq 0 told the operator:"),
        "{report}"
    );
    assert!(report.contains(TOLD), "the full line: {report}");
    assert!(
        report.contains("and the exec ran under mode off on host (seq 1)."),
        "{report}"
    );
}

#[test]
fn verify_is_clean_when_they_agree() {
    let data = tempfile::tempdir().unwrap();
    write_session(
        data.path(),
        (SandboxModeLabel::ExecOnly, SandboxRuntimeLabel::Docker),
    );
    let out = verify(data.path());
    let report = text(&out);
    assert_eq!(out.status.code(), Some(0), "{report}");
    assert!(!report.contains("exec_location"), "{report}");
}
