//! Tests for the `http_request` built-in tool. Every scenario in
//! `docs/design/http-request-tool.md` is encoded here.
//!
//! Network-exercising tests drive the real handler against a loopback
//! `TcpListener` over `http://localhost` (permitted only under
//! `cfg(test)`; production is https-only). Gate/validation tests call
//! the real gate + URL validator directly, no server.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wirken_audit::{
    SessionEvent, SessionHandle, SessionId, SessionLog, SessionVerifyResult, SqliteSessionLog,
    TrustLevel,
};
use wirken_gateway::permissions::{Action, PermissionTier};

use crate::egress::{EgressClient, EgressEnforcement};
use crate::error::AgentError;
use crate::http_tool::{
    self, CredentialError, CredentialResolver, HttpAuditCtx, ResolvedSecret, validate_url,
};
use crate::skill_perms::{EffectiveProfile, PermissionProfile, PhasedEffective, parse_block};
use crate::tool::ToolResult;

const SECRET: &str = "s3cr3t-token-DO-NOT-LEAK-9f2c";

// ---- fakes / helpers -----------------------------------------------------

/// Fake resolver for slot "tdx", bound to `bound_host`. Enforces the
/// host binding exactly as the vault-backed resolver does, so the tests
/// exercise the tool's refusal path when a skill's target host does not
/// match the credential's binding.
struct FakeResolver {
    bound_host: String,
}
impl CredentialResolver for FakeResolver {
    fn resolve(&self, name: &str, host: &str) -> Result<ResolvedSecret, CredentialError> {
        if name != "tdx" {
            return Err(CredentialError::NotFound(name.to_string()));
        }
        if !host.eq_ignore_ascii_case(&self.bound_host) {
            return Err(CredentialError::HostNotPermitted {
                name: name.to_string(),
                host: host.to_string(),
            });
        }
        Ok(ResolvedSecret::new(SECRET.to_string()))
    }
}

fn resolver() -> Arc<dyn CredentialResolver> {
    Arc::new(FakeResolver {
        bound_host: "localhost".to_string(),
    })
}

/// EgressClient allowlisting exactly the given hosts.
fn egress(hosts: &[&str]) -> EgressClient {
    let c = EgressClient::new();
    let set: BTreeSet<String> = hosts.iter().map(|h| h.to_string()).collect();
    c.set_enforcement(EgressEnforcement::Allowlist(set));
    c
}

type AuditParts = (
    Arc<dyn SessionLog>,
    SessionHandle<wirken_audit::OwnSession>,
    HttpAuditCtx,
);

fn audit() -> AuditParts {
    let log: Arc<dyn SessionLog> = Arc::new(SqliteSessionLog::open_in_memory().unwrap());
    let handle = log.handle_for(SessionId::new("test-session"));
    let ctx = HttpAuditCtx {
        log: Arc::clone(&log),
        handle: handle.clone(),
        agent_id: "agent-test".to_string(),
    };
    (log, handle, ctx)
}

fn build_response(status_line: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut s = format!("HTTP/1.1 {status_line}\r\n");
    for (k, v) in headers {
        s.push_str(&format!("{k}: {v}\r\n"));
    }
    s.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    s.push_str(body);
    s.into_bytes()
}

/// One-shot loopback server: reads the request, sends `response`, and
/// hands the raw request bytes back so a test can inspect what went out
/// on the wire (e.g. which Authorization header was sent).
async fn serve_once(response: Vec<u8>) -> (String, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let _ = tx.send(buf[..n].to_vec());
            let _ = sock.write_all(&response).await;
            let _ = sock.shutdown().await;
        }
    });
    (format!("http://localhost:{port}"), rx)
}

fn out_json(result: &ToolResult) -> serde_json::Value {
    serde_json::from_str(&result.output).expect("http_request output is JSON")
}

// ---- 1. secret never in model context ------------------------------------

#[tokio::test]
async fn secret_never_in_tool_result_or_audit_but_is_on_the_wire() {
    let (base, rx) = serve_once(build_response("200 OK", &[], "public body")).await;
    let (log, handle, ctx) = audit();
    let args = serde_json::json!({
        "method": "GET", "url": format!("{base}/lookup"), "credential": "tdx"
    });

    let result = http_tool::execute(
        &egress(&["localhost"]),
        Some(&resolver()),
        Some(&ctx),
        &args,
    )
    .await
    .unwrap();

    // Result carries the body + status but never the secret value.
    assert!(result.success, "output: {}", result.output);
    assert!(
        !result.output.contains(SECRET),
        "secret leaked into tool result"
    );
    assert_eq!(out_json(&result)["status"], 200);

    // The secret WAS injected as the auth header on the wire (host-side).
    let request = String::from_utf8(rx.await.unwrap()).unwrap();
    assert!(
        request
            .to_lowercase()
            .contains(&format!("authorization: bearer {SECRET}").to_lowercase()),
        "auth header with vault secret should be on the wire; got:\n{request}"
    );

    // Audit: exactly one HttpRequest row, credential NAME only, no value.
    let events = log.get_since(&handle, 0).unwrap();
    let http_rows: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.event, SessionEvent::HttpRequest { .. }))
        .collect();
    assert_eq!(http_rows.len(), 1);
    match &http_rows[0].event {
        SessionEvent::HttpRequest {
            credential,
            method,
            host,
            status,
            ..
        } => {
            assert_eq!(credential.as_deref(), Some("tdx"));
            assert_eq!(method, "GET");
            assert_eq!(host, "localhost");
            assert_eq!(*status, 200);
        }
        _ => unreachable!(),
    }
    let audit_json: String = events
        .iter()
        .map(|e| serde_json::to_string(&e.event).unwrap())
        .collect();
    assert!(
        !audit_json.contains(SECRET),
        "secret leaked into audit payload"
    );
}

// ---- 2. undeclared credential refused at the gate ------------------------

#[test]
fn undeclared_credential_refused_at_gate_declared_passes() {
    let declared = perms("credentials:\n  allow: [tdx]\n");
    let none = perms("credentials:\n  allow: []\n");
    let call =
        serde_json::json!({"method": "GET", "url": "https://x.example/", "credential": "tdx"})
            .to_string();

    assert!(
        http_tool::gate(&declared, &call).is_none(),
        "declared slot must pass"
    );
    let (axis, _) = http_tool::gate(&none, &call).expect("undeclared slot must refuse");
    assert_eq!(axis, "credentials");
}

// ---- 3. egress allowlist blocks non-listed host: refusal, not prompt -----

#[tokio::test]
async fn egress_blocks_non_listed_host_as_refusal() {
    let args = serde_json::json!({"method": "GET", "url": "https://blocked.example/"});
    // Allowlist does not include blocked.example: check_egress refuses
    // before any TCP, so no real network is touched.
    let err = http_tool::execute(&egress(&["allowed.example"]), None, None, &args)
        .await
        .expect_err("non-allowlisted host must be refused");
    assert!(matches!(err, AgentError::EgressDenied(_)), "got {err:?}");
    // And the tool never escalates to a prompt: its tier is Tier 1.
    assert_eq!(Action::HttpRequest.tier(), PermissionTier::Tier1);
}

// ---- 4. allowlisted GET no prompt; write verb refused --------------------

#[tokio::test]
async fn allowlisted_get_runs_without_prompt_write_verb_refused() {
    // No-prompt tier.
    assert_eq!(Action::HttpRequest.tier(), PermissionTier::Tier1);

    // A GET to an allowlisted host completes (no approval mechanism in the path).
    let (base, _rx) = serve_once(build_response("200 OK", &[], "ok")).await;
    let args = serde_json::json!({"method": "GET", "url": format!("{base}/")});
    let result = http_tool::execute(&egress(&["localhost"]), None, None, &args)
        .await
        .unwrap();
    assert!(result.success);

    // A write verb is refused at the gate and by the handler.
    let del = serde_json::json!({"method": "DELETE", "url": "https://x.example/"}).to_string();
    let (axis, _) = http_tool::gate(&perms_allow_all(), &del).expect("DELETE must refuse");
    assert_eq!(axis, "http_method");

    let put = serde_json::json!({"method": "PUT", "url": "https://x.example/"});
    let handled = http_tool::execute(&egress(&["x.example"]), None, None, &put)
        .await
        .unwrap();
    assert!(!handled.success && handled.output.contains("not allowed"));
}

// ---- 5. redaction holds on error paths -----------------------------------

#[tokio::test]
async fn redaction_holds_on_4xx_5xx_timeout_and_conn_refused() {
    // 4xx and 5xx: the server body is returned; the secret is not.
    for status in ["404 Not Found", "500 Internal Server Error"] {
        let (base, _rx) = serve_once(build_response(status, &[], "error detail")).await;
        let args = serde_json::json!({
            "method": "GET", "url": format!("{base}/"), "credential": "tdx"
        });
        let r = http_tool::execute(&egress(&["localhost"]), Some(&resolver()), None, &args)
            .await
            .unwrap();
        assert!(!r.success);
        assert!(!r.output.contains(SECRET), "{status}: secret leaked");
        assert_eq!(out_json(&r)["body"], "error detail");
    }

    // Timeout: server accepts but never responds; short per-request timeout.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut b = [0u8; 1024];
            let _ = s.read(&mut b).await;
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
    let args = serde_json::json!({
        "method": "GET", "url": format!("http://localhost:{port}/"),
        "credential": "tdx", "timeout_ms": 300
    });
    let r = http_tool::execute(&egress(&["localhost"]), Some(&resolver()), None, &args)
        .await
        .unwrap();
    assert!(
        !r.success && !r.output.contains(SECRET),
        "timeout leaked: {}",
        r.output
    );

    // Connection refused: bind then drop to free the port.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = l.local_addr().unwrap().port();
    drop(l);
    let args = serde_json::json!({
        "method": "GET", "url": format!("http://localhost:{dead}/"), "credential": "tdx"
    });
    let r = http_tool::execute(&egress(&["localhost"]), Some(&resolver()), None, &args)
        .await
        .unwrap();
    assert!(
        !r.success && !r.output.contains(SECRET),
        "conn-refused leaked: {}",
        r.output
    );
}

// ---- 6. redirects: 3xx returned, not followed ----------------------------

#[tokio::test]
async fn redirect_is_returned_not_followed_and_auth_not_forwarded() {
    let resp = build_response(
        "302 Found",
        &[("Location", "https://evil.example/")],
        "redirecting",
    );
    let (base, rx) = serve_once(resp).await;
    let args = serde_json::json!({
        "method": "GET", "url": format!("{base}/"), "credential": "tdx"
    });
    let r = http_tool::execute(&egress(&["localhost"]), Some(&resolver()), None, &args)
        .await
        .unwrap();
    // The 3xx is returned as-is (not followed to evil.example).
    assert_eq!(out_json(&r)["status"], 302);
    // Exactly one request went out, to the allowlisted host only.
    let request = String::from_utf8(rx.await.unwrap()).unwrap();
    assert!(
        request.starts_with("GET /"),
        "one request to localhost only"
    );
    // (evil.example is not allowlisted; had a follow been attempted it
    //  would have been refused, never carrying the auth header onward.)
}

// ---- 7. host matching ----------------------------------------------------

#[tokio::test]
async fn host_matching_userinfo_ip_port_subdomain() {
    // Userinfo trick: parsed host is evil.example, and the URL is refused.
    let parsed = url::Url::parse("https://allowed.example@evil.example/").unwrap();
    assert_eq!(parsed.host_str(), Some("evil.example"));
    assert!(validate_url("https://allowed.example@evil.example/").is_err());

    // IP literals refused (v4 and v6).
    assert!(validate_url("https://93.184.216.34/").is_err());
    assert!(validate_url("https://[::1]/").is_err());

    // Port-agnostic: the host component the allowlist matches excludes the port.
    let with_port = validate_url("https://allowed.example:8443/x").unwrap();
    assert_eq!(with_port.host_str(), Some("allowed.example"));

    // No implicit subdomain: allowlisting `allowed.example` does not admit
    // `sub.allowed.example` (refused pre-connection, so no real network).
    let args = serde_json::json!({"method": "GET", "url": "https://sub.allowed.example/"});
    let err = http_tool::execute(&egress(&["allowed.example"]), None, None, &args)
        .await
        .expect_err("subdomain of an allowlisted host is not allowlisted");
    assert!(matches!(err, AgentError::EgressDenied(_)));
}

// ---- 8. model-supplied Authorization refused -----------------------------

#[tokio::test]
async fn model_supplied_authorization_is_refused_not_silently_won() {
    let (base, mut rx) = serve_once(build_response("200 OK", &[], "ok")).await;
    let args = serde_json::json!({
        "method": "GET", "url": format!("{base}/"),
        "headers": {"Authorization": "Bearer attacker-value"},
        "credential": "tdx"
    });
    let r = http_tool::execute(&egress(&["localhost"]), Some(&resolver()), None, &args)
        .await
        .unwrap();
    // Loud refusal: the call fails, the attacker value never wins.
    assert!(!r.success);
    assert!(r.output.to_lowercase().contains("authorization"));
    // The request was refused before any bytes went out (non-blocking
    // check: the loopback server never receives a connection).
    assert!(
        matches!(
            rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "no request should have been sent to the server"
    );
}

// ---- 9. POST carve-out ---------------------------------------------------

#[tokio::test]
async fn post_only_to_declared_search_path() {
    let (base, _rx) = serve_once(build_response("200 OK", &[], "results")).await;
    let declared_path = format!("{base}/search");
    let perms = perms_with_post_path(&declared_path);

    // Declared path: gate allows, request succeeds.
    let ok = serde_json::json!({"method": "POST", "url": declared_path, "body": "{}"});
    assert!(
        http_tool::gate(&perms, &ok.to_string()).is_none(),
        "declared POST path must pass"
    );
    let r = http_tool::execute(&egress(&["localhost"]), None, None, &ok)
        .await
        .unwrap();
    assert!(r.success, "declared POST should succeed: {}", r.output);

    // Undeclared path on the same (allowlisted) host: refused at the gate.
    let bad = serde_json::json!({"method": "POST", "url": format!("{base}/other"), "body": "{}"});
    let (axis, _) =
        http_tool::gate(&perms, &bad.to_string()).expect("undeclared POST path refused");
    assert_eq!(axis, "http_post_path");
}

// ---- 10. caps: truncation + timeout --------------------------------------

#[tokio::test]
async fn oversized_body_truncated_at_cap() {
    let big = "a".repeat(http_tool::HTTP_TOOL_BODY_CAP + 100_000);
    let (base, _rx) = serve_once(build_response("200 OK", &[], &big)).await;
    let args = serde_json::json!({"method": "GET", "url": format!("{base}/")});
    let r = http_tool::execute(&egress(&["localhost"]), None, None, &args)
        .await
        .unwrap();
    let j = out_json(&r);
    assert_eq!(j["truncated"], true, "cap should signal truncation");
    assert_eq!(
        j["body"].as_str().unwrap().len(),
        http_tool::HTTP_TOOL_BODY_CAP,
        "body should be truncated to the cap"
    );
}

// ---- 11. audit presence + chain verifies ---------------------------------

#[tokio::test]
async fn http_request_event_lands_and_chain_verifies() {
    let (base, _rx) = serve_once(build_response("200 OK", &[], "ok")).await;
    let (log, handle, ctx) = audit();

    // Seed a prior event so the HttpRequest row is a genuine link, not
    // the chain head, and the chain must still verify after it.
    log.append(
        &handle,
        TrustLevel::System,
        SessionEvent::SystemPromptSet {
            content: String::new(),
            agent_id: "a".into(),
        },
    )
    .ok();

    let args =
        serde_json::json!({"method": "GET", "url": format!("{base}/p"), "credential": "tdx"});
    http_tool::execute(
        &egress(&["localhost"]),
        Some(&resolver()),
        Some(&ctx),
        &args,
    )
    .await
    .unwrap();

    let events = log.get_since(&handle, 0).unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e.event, SessionEvent::HttpRequest { .. }))
    );
    match log.verify(&handle).unwrap() {
        SessionVerifyResult::Ok { .. } => {}
        other => panic!("chain must verify after HttpRequest row: {other:?}"),
    }
}

// ---- 12. credential host binding cannot be widened by the skill ----------

#[tokio::test]
async fn credential_host_binding_refuses_mismatched_host() {
    // The phishing shape: a skill egress-allowlists the target host and
    // names a credential it declared, but the credential is bound (in
    // the vault, by the operator) to a different host. Injection is
    // refused, so the secret never reaches the wire even though the
    // skill's own permissions would have allowed it.
    let (base, mut rx) = serve_once(build_response("200 OK", &[], "ok")).await;
    let bound_elsewhere: Arc<dyn CredentialResolver> = Arc::new(FakeResolver {
        bound_host: "tenant.teamdynamix.com".to_string(),
    });
    let args = serde_json::json!({
        "method": "GET", "url": format!("{base}/"), "credential": "tdx"
    });
    let r = http_tool::execute(&egress(&["localhost"]), Some(&bound_elsewhere), None, &args)
        .await
        .unwrap();
    assert!(!r.success, "mismatched host binding must refuse");
    assert!(
        r.output.contains("not bound to host"),
        "output: {}",
        r.output
    );
    assert!(!r.output.contains(SECRET));
    // Nothing went out: the secret never reached the wire.
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
}

// ---- profile helpers -----------------------------------------------------

fn perms(yaml: &str) -> PhasedEffective {
    let profile = parse_block(yaml, Path::new("/tmp"), None).unwrap();
    PhasedEffective::from_base(EffectiveProfile::Resolved(profile))
}

fn perms_allow_all() -> PhasedEffective {
    perms("credentials:\n  allow: [tdx]\n")
}

/// A profile whose only grant is one POST endpoint (constructed directly
/// so the test can use an `http://localhost` path; `parse_block` requires
/// declared post_paths to be https).
fn perms_with_post_path(path: &str) -> PhasedEffective {
    let mut profile = PermissionProfile::default();
    profile.http.post_paths.insert(path.to_string());
    PhasedEffective::from_base(EffectiveProfile::Resolved(profile))
}
