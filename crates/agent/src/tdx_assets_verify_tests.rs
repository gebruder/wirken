//! Local verification for the `tdx-assets` example skill
//! (`skills/examples/tdx-assets/`). Runs the *real* committed SKILL.md
//! through the merged http_request enforcement: load + sign, slash
//! recognition, system-prompt gating, the POST-path / credential gate,
//! credential-host binding, egress allowlist, and a mock TDX auth-less
//! bearer flow. The agent's *behavioral* handling (surface ambiguous,
//! stop on 401, back off on 429) is not code-enforced and is an
//! acceptance check against a real tenant; here we verify the tool
//! surfaces each shape and never leaks the token.
//!
//! On the tdx-skill branch only (a skill-specific verification artifact),
//! not for merge to main.

use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wirken_gateway::skill_registry::sign_skill;

use crate::egress::{EgressClient, EgressEnforcement};
use crate::error::AgentError;
use crate::http_tool::{self, CredentialError, CredentialResolver, ResolvedSecret};
use crate::skill::{Skill, SkillLoader};
use crate::skill_perms::{EgressMode, PhasedEffective, effective_for_skills};
use crate::slash;
use crate::tool::ToolResult;

const SKILL_MD: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../skills/examples/tdx-assets/SKILL.md"
);
const TOKEN: &str = "eyJ.FAKE-TDX-BEARER.DO-NOT-LEAK";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32]) // throwaway; signs a temp copy only
}

/// Copy the committed SKILL.md into `<tmp>/tdx-assets/`, sign it, load it.
fn load_signed_skill(tmp: &Path) -> Vec<Skill> {
    let dir = tmp.join("tdx-assets");
    std::fs::create_dir_all(&dir).unwrap();
    let md = std::fs::read_to_string(SKILL_MD).expect("read committed SKILL.md");
    std::fs::write(dir.join("SKILL.md"), md).unwrap();
    sign_skill(&dir, &signing_key()).expect("sign_skill");
    assert!(dir.join("SKILL.sig").is_file() && dir.join("SKILL.pub").is_file());
    SkillLoader::load_dir(tmp).expect("load the signed skill")
}

#[test]
fn skill_loads_signs_and_permissions_parse() {
    let tmp = tempfile::tempdir().unwrap();
    let skills = load_signed_skill(tmp.path());
    assert_eq!(skills.len(), 1);
    let s = &skills[0];
    assert_eq!(s.name, "tdx-assets");
    assert!(!s.disable_model_invocation, "must be auto-invocable");
    assert!(s.available, "no required bins, so available");

    assert!(s.permissions.tools.allow.allows("http_request"));
    assert!(s.permissions.credentials.allow.allows("tdx-api"));
    assert!(!s.permissions.credentials.allow.allows("some-other-cred"));
    assert!(matches!(s.permissions.egress.mode, EgressMode::Allowlist));
    assert!(
        s.permissions
            .egress
            .domains
            .allows("your-tenant.teamdynamix.com"),
        "egress allowlists the tenant placeholder host"
    );
    assert_eq!(s.permissions.http.post_paths.len(), 2);
    assert!(
        s.permissions
            .http
            .post_paths
            .iter()
            .any(|p| p.ends_with("/TDWebApi/api/people/search"))
    );
    assert!(
        s.permissions
            .http
            .post_paths
            .iter()
            .any(|p| p.ends_with("/assets/search"))
    );
}

#[test]
fn slash_interceptor_recognizes_tdx_assets() {
    let tmp = tempfile::tempdir().unwrap();
    let skills = load_signed_skill(tmp.path());
    match slash::parse("/tdx-assets Jane Doe, jsmith@x.edu", &skills) {
        slash::SlashResult::Invoked { skill, remainder } => {
            assert_eq!(skill.name, "tdx-assets");
            assert!(remainder.contains("Jane Doe"));
        }
        other => panic!("expected Invoked, got {other:?}"),
    }
    assert!(matches!(
        slash::parse("/not-a-skill", &skills),
        slash::SlashResult::UnknownSkill { .. }
    ));
}

#[test]
fn system_prompt_presence_toggles_with_disable_model_invocation() {
    let tmp = tempfile::tempdir().unwrap();
    let mut skills = load_signed_skill(tmp.path());

    // disable-model-invocation:false -> present in the auto-pickable prompt.
    let prompt = SkillLoader::build_prompt(&skills);
    assert!(
        prompt.contains("tdx-assets"),
        "auto-invocable skill appears"
    );
    assert!(prompt.contains("TeamDynamix"), "its description appears");

    // Flip to true -> excluded from the system prompt entirely.
    skills[0].disable_model_invocation = true;
    let prompt2 = SkillLoader::build_prompt(&skills);
    assert!(
        !prompt2.contains("tdx-assets"),
        "disable-model-invocation:true excludes it"
    );
}

#[test]
fn gate_allows_declared_search_refuses_others_and_undeclared_credential() {
    let tmp = tempfile::tempdir().unwrap();
    let skills = load_signed_skill(tmp.path());
    let perms =
        PhasedEffective::from_base(effective_for_skills(&[skills[0].permissions.clone()]).unwrap());

    let declared = skills[0]
        .permissions
        .http
        .post_paths
        .iter()
        .find(|p| p.ends_with("/people/search"))
        .unwrap()
        .clone();

    // Declared search POST with the declared credential passes the gate.
    let ok = serde_json::json!({"method":"POST","url":declared,"credential":"tdx-api"}).to_string();
    assert!(
        http_tool::gate(&perms, &ok).is_none(),
        "declared POST passes"
    );

    // Undeclared POST path on the same host is refused.
    let bad = serde_json::json!({"method":"POST",
        "url":"https://your-tenant.teamdynamix.com/TDWebApi/api/tickets"})
    .to_string();
    assert_eq!(
        http_tool::gate(&perms, &bad)
            .expect("undeclared path refused")
            .0,
        "http_post_path"
    );

    // Undeclared credential is refused at the gate.
    let cred = serde_json::json!({"method":"POST","url":declared,"credential":"other"}).to_string();
    assert_eq!(
        http_tool::gate(&perms, &cred)
            .expect("undeclared credential refused")
            .0,
        "credentials"
    );
}

// ---- mock TDX server + bearer flow --------------------------------------

struct BearerResolver {
    host: String,
}
impl CredentialResolver for BearerResolver {
    fn resolve(&self, name: &str, host: &str) -> Result<ResolvedSecret, CredentialError> {
        if name != "tdx-api" {
            return Err(CredentialError::NotFound(name.into()));
        }
        if !host.eq_ignore_ascii_case(&self.host) {
            return Err(CredentialError::HostNotPermitted {
                name: name.into(),
                host: host.into(),
            });
        }
        Ok(ResolvedSecret::new(TOKEN.into()))
    }
}

fn egress(hosts: &[&str]) -> EgressClient {
    let c = EgressClient::new();
    c.set_enforcement(EgressEnforcement::Allowlist(
        hosts.iter().map(|h| h.to_string()).collect(),
    ));
    c
}

fn http_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

async fn serve_once(resp: Vec<u8>) -> (String, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = l.accept().await {
            let mut b = vec![0u8; 8192];
            let n = s.read(&mut b).await.unwrap_or(0);
            let _ = tx.send(b[..n].to_vec());
            let _ = s.write_all(&resp).await;
            let _ = s.shutdown().await;
        }
    });
    (format!("http://localhost:{port}"), rx)
}

fn out(r: &ToolResult) -> serde_json::Value {
    serde_json::from_str(&r.output).unwrap()
}

#[tokio::test]
async fn people_search_injects_bearer_host_side_and_hides_token() {
    let users = r#"[{"UID":"11111111-1111-1111-1111-111111111111","FullName":"Jane Doe","PrimaryEmail":"jane@x.edu","IsActive":true,"LocationName":"HQ"}]"#;
    let (base, rx) = serve_once(http_response("200 OK", users)).await;
    let resolver: Arc<dyn CredentialResolver> = Arc::new(BearerResolver {
        host: "localhost".into(),
    });
    let args = serde_json::json!({
        "method":"POST", "url": format!("{base}/TDWebApi/api/people/search"),
        "headers": {"Content-Type":"application/json"},
        "body": r#"{"SearchText":"Jane Doe","IsActive":true,"MaxResults":10}"#,
        "credential":"tdx-api"
    });
    let r = http_tool::execute(&egress(&["localhost"]), Some(&resolver), None, &args)
        .await
        .unwrap();
    assert!(r.success, "{}", r.output);
    assert_eq!(out(&r)["status"], 200);
    assert!(out(&r)["body"].as_str().unwrap().contains("Jane Doe"));
    assert!(
        !r.output.contains(TOKEN),
        "token must not appear in the tool result"
    );

    // The bearer token was injected host-side onto the wire.
    let req = String::from_utf8(rx.await.unwrap()).unwrap();
    assert!(
        req.to_lowercase()
            .contains(&format!("authorization: bearer {TOKEN}").to_lowercase()),
        "bearer token on the wire:\n{req}"
    );
    assert!(req.starts_with("POST /TDWebApi/api/people/search"));
}

async fn run_people_call(status: &str, body: &str) -> ToolResult {
    let (base, _rx) = serve_once(http_response(status, body)).await;
    let resolver: Arc<dyn CredentialResolver> = Arc::new(BearerResolver {
        host: "localhost".into(),
    });
    let args = serde_json::json!({
        "method":"POST","url":format!("{base}/TDWebApi/api/people/search"),
        "body":"{}","credential":"tdx-api"
    });
    http_tool::execute(&egress(&["localhost"]), Some(&resolver), None, &args)
        .await
        .unwrap()
}

#[tokio::test]
async fn tool_surfaces_each_scenario_shape_to_the_agent() {
    // These prove the TOOL returns each shape (status + body) without
    // leaking the token. The AGENT's handling of each is an acceptance
    // check (real LLM + tenant), not code-enforced.

    // Ambiguous: two matches.
    let amb = run_people_call(
        "200 OK",
        r#"[{"UID":"a","FullName":"A"},{"UID":"b","FullName":"B"}]"#,
    )
    .await;
    assert!(amb.success);
    let amb_body: serde_json::Value =
        serde_json::from_str(out(&amb)["body"].as_str().unwrap()).unwrap();
    assert_eq!(amb_body.as_array().unwrap().len(), 2);

    // Unresolved: empty array.
    let none = run_people_call("200 OK", "[]").await;
    assert_eq!(out(&none)["body"], "[]");

    // Expired token: 401. Non-2xx, status surfaced, no token leak.
    let exp = run_people_call("401 Unauthorized", r#"{"message":"expired"}"#).await;
    assert!(!exp.success);
    assert_eq!(out(&exp)["status"], 401);
    assert!(!exp.output.contains(TOKEN));

    // Rate limited: 429.
    let rl = run_people_call("429 Too Many Requests", r#"{"message":"slow down"}"#).await;
    assert!(!rl.success);
    assert_eq!(out(&rl)["status"], 429);

    // Asset with an Attributes array lacking any inventory attribute:
    // returned verbatim; the skill maps missing to "not available".
    let asset = run_people_call(
        "200 OK",
        r#"[{"ID":1,"Name":"Laptop","ProductModelName":"X1 Carbon","LocationName":"HQ","OwningCustomerName":"Jane Doe","StatusName":"In Use","Attributes":[]}]"#,
    )
    .await;
    assert!(asset.success);
    assert!(
        out(&asset)["body"]
            .as_str()
            .unwrap()
            .contains("\"Attributes\":[]")
    );
}

#[tokio::test]
async fn non_allowlisted_host_and_mismatched_binding_refuse_nothing_on_wire() {
    let resolver: Arc<dyn CredentialResolver> = Arc::new(BearerResolver {
        host: "localhost".into(),
    });

    // Host not on the skill's egress allowlist: refused before any TCP.
    let args = serde_json::json!({
        "method":"POST","url":"https://not-tdx.example/x","body":"{}","credential":"tdx-api"
    });
    let e = http_tool::execute(&egress(&["localhost"]), Some(&resolver), None, &args)
        .await
        .expect_err("non-allowlisted host must be refused");
    assert!(matches!(e, AgentError::EgressDenied(_)), "got {e:?}");

    // Credential bound to a different host than the request: refused at
    // injection, and nothing goes out (resolve runs after the egress
    // check but before send).
    let bound_elsewhere: Arc<dyn CredentialResolver> = Arc::new(BearerResolver {
        host: "your-tenant.teamdynamix.com".into(),
    });
    let (base, mut rx) = serve_once(http_response("200 OK", "[]")).await;
    let args2 = serde_json::json!({
        "method":"POST","url":format!("{base}/TDWebApi/api/people/search"),
        "body":"{}","credential":"tdx-api"
    });
    let r = http_tool::execute(
        &egress(&["localhost"]),
        Some(&bound_elsewhere),
        None,
        &args2,
    )
    .await
    .unwrap();
    assert!(!r.success && r.output.contains("not bound to host"));
    assert!(!r.output.contains(TOKEN));
    assert!(
        matches!(
            rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "nothing should have reached the wire"
    );
}
