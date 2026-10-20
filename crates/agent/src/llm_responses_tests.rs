use super::*;
use crate::plan_auth::tests::stub::{self, Handler, Reply, Request};
use crate::plan_auth::{Endpoints, PlanTokenSource, SCOPES};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use wirken_mcp_proxy::OAuthCredential;
use wirken_vault::{CredentialStore, VaultSecret};

fn msg(role: Role, content: &str) -> Message {
    Message {
        role,
        content: content.into(),
        tool_call_id: None,
        tool_name: None,
        tool_calls: None,
    }
}

fn now() -> u64 {
    crate::plan_auth::unix_now()
}

fn plan_entry(expires_at: u64) -> OAuthCredential {
    OAuthCredential {
        access_token: "at-live".into(),
        refresh_token: "rt-live".into(),
        expires_at,
        scope: SCOPES.join(" "),
        provider: "openai".into(),
        client_id: Some("oaiapp_x".into()),
        issuer: Some("https://issuer.example".into()),
        subject: Some("user-1".into()),
        email: None,
        id_token: None,
    }
}

/// A plan-mode client pointed at `stub`, with a token source over a
/// fresh vault holding `entry`.
fn plan_client(stub: &stub::Stub, entry: OAuthCredential) -> (tempfile::TempDir, LlmClient) {
    let dir = tempfile::tempdir().unwrap();
    let store = CredentialStore::open_with_key(
        &dir.path().join("vault.db"),
        VaultSecret::new("0".repeat(64)),
    )
    .unwrap();
    crate::plan_auth::store_plan(&store, "plan", &entry).unwrap();
    let source = PlanTokenSource::open_at(
        Endpoints::stub(&stub.base),
        store,
        dir.path(),
        "plan",
        Arc::new(wirken_gateway::leak::LeakMatcher::new()),
    )
    .unwrap();
    let mut client = LlmClient::new(LlmConfig::plan("gpt-test")).unwrap();
    client.set_plan_endpoints_for_test(Endpoints::stub(&stub.base));
    client.set_plan_token_source(source);
    (dir, client)
}

/// A stub answering `/v1/responses` with `reply`, and a token endpoint
/// that answers every refresh with a 503.
async fn route(reply: impl Fn(usize, &Request) -> Reply + Send + Sync + 'static) -> stub::Stub {
    let count = Arc::new(AtomicUsize::new(0));
    stub::serve(move |_| -> Handler {
        Arc::new(move |req: &Request| match req.path.as_str() {
            "/v1/responses" => reply(count.fetch_add(1, Ordering::SeqCst), req),
            "/api/accounts/oauth/token" => Reply::empty(503),
            _ => Reply::empty(404),
        })
    })
    .await
}

fn plan_error(err: AgentError) -> PlanRouteError {
    match err {
        AgentError::PlanRoute(e) => *e,
        other => panic!("expected a plan route error, got {other}"),
    }
}

const TEXT_STREAM: &str = "\
event: response.created\n\
data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n\n\
event: response.output_text.delta\n\
data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"delta\":\"Hello\"}\n\n\
data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"delta\":\", world\"}\n\n\
data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"input_tokens\":12,\"input_tokens_details\":{\"cached_tokens\":4},\"output_tokens\":5}}}\n\n";

#[test]
fn the_request_body_carries_instructions_and_nothing_the_route_refuses() {
    let mut assistant = msg(Role::Assistant, "Reading it.");
    assistant.tool_calls = Some(vec![ToolCallRequest {
        id: "call_1".into(),
        name: "read_file".into(),
        arguments: r#"{"path":"a.txt"}"#.into(),
    }]);
    let mut result = msg(Role::Tool, "contents");
    result.tool_call_id = Some("call_1".into());
    let messages = vec![
        msg(Role::System, "Be brief."),
        msg(Role::System, "Use tools."),
        msg(Role::Compaction, "earlier: hello"),
        msg(Role::User, "read a.txt"),
        assistant,
        result,
    ];
    let tools = vec![ToolDef {
        name: "read_file".into(),
        description: "Read a file".into(),
        parameters: serde_json::json!({"type": "object"}),
    }];
    let body = build_plan_request_body(&LlmConfig::plan("gpt-test"), &messages, &tools);

    assert_eq!(body["model"], "gpt-test");
    assert_eq!(body["instructions"], "Be brief.\n\nUse tools.");
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    for refused in [
        "temperature",
        "max_output_tokens",
        "max_tokens",
        "top_p",
        "user",
        "metadata",
        "previous_response_id",
        "background",
        "truncation",
        "prompt",
        "safety_identifier",
        "max_tool_calls",
        "top_logprobs",
        "conversation",
        "prompt_cache_retention",
    ] {
        assert!(body.get(refused).is_none(), "{refused} must not be sent");
    }
    let input = body["input"].as_array().unwrap();
    assert!(
        input.iter().all(|i| i["role"] != "system"),
        "no system items: {input:?}"
    );
    assert_eq!(input[0]["role"], "developer");
    let fenced = input[0]["content"].as_str().unwrap();
    assert!(fenced.starts_with(COMPACTION_FENCE_OPEN) && fenced.ends_with(COMPACTION_FENCE_CLOSE));
    assert_eq!(
        input[1],
        serde_json::json!({"role": "user", "content": "read a.txt"})
    );
    assert_eq!(
        input[2],
        serde_json::json!({"role": "assistant", "content": "Reading it."})
    );
    assert_eq!(
        input[3],
        serde_json::json!({"type": "function_call", "call_id": "call_1", "namespace": "agent", "name": "read_file", "arguments": r#"{"path":"a.txt"}"#})
    );
    assert_eq!(
        input[4],
        serde_json::json!({"type": "function_call_output", "call_id": "call_1", "output": "contents"})
    );
    // Function tools are grouped in one namespace.
    let tools = body["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["type"], "namespace");
    assert_eq!(tools[0]["name"], TOOL_NAMESPACE);
    // The route requires a description on the namespace.
    assert_eq!(tools[0]["description"], TOOL_NAMESPACE_DESCRIPTION);
    assert!(!TOOL_NAMESPACE_DESCRIPTION.is_empty());
    // Every replayed call names the namespace beside the plain name.
    assert!(
        input
            .iter()
            .filter(|i| i["type"] == "function_call")
            .all(|i| i["namespace"] == TOOL_NAMESPACE && i["name"] == "read_file")
    );
    assert_eq!(
        tools[0]["tools"][0],
        serde_json::json!({"type": "function", "name": "read_file", "description": "Read a file", "parameters": {"type": "object"}, "strict": false})
    );

    let bare = build_plan_request_body(&LlmConfig::plan("m"), &[msg(Role::User, "hi")], &[]);
    assert!(bare.get("tools").is_none() && bare.get("instructions").is_none());
}

#[tokio::test]
async fn a_streamed_reply_is_forwarded_assembled_and_completed() {
    let stub = route(|_, _| Reply::sse(TEXT_STREAM)).await;
    let (_dir, client) = plan_client(&stub, plan_entry(now() + 3600));
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let (response, usage) = client
        .complete_stream(&[msg(Role::User, "hi")], &[], None, tx)
        .await
        .expect("completes");
    assert!(matches!(response, LlmResponse::Text(ref t) if t == "Hello, world"));
    let usage = usage.expect("usage on completed");
    assert_eq!(
        (
            usage.input_tokens,
            usage.output_tokens,
            usage.cache_read_input_tokens
        ),
        (12, 5, 4)
    );
    let mut deltas = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let StreamEvent::TextDelta(piece) = event {
            deltas.push(piece);
        }
    }
    assert_eq!(deltas, ["Hello", ", world"]);

    let sent = stub.requests_to("/v1/responses");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].header("authorization"), Some("Bearer at-live"));
    let body = sent[0].json();
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
}

#[tokio::test]
async fn function_calls_are_assembled_by_item_id_with_their_call_ids() {
    const CALLS: &str = "\
data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"delta\":\"Reading two files.\"}\n\n\
data: {\"type\":\"response.output_item.added\",\"item\":{\"id\":\"fc_1\",\"type\":\"function_call\",\"call_id\":\"call_a\",\"namespace\":\"agent\",\"name\":\"read_file\",\"arguments\":\"\"}}\n\n\
data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_1\",\"delta\":\"{\\\"path\\\":\"}\n\n\
data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_1\",\"delta\":\"\\\"a.txt\\\"}\"}\n\n\
data: {\"type\":\"response.output_item.added\",\"item\":{\"id\":\"fc_2\",\"type\":\"function_call\",\"call_id\":\"call_b\",\"name\":\"agent.read_file\",\"namespace\":\"agent\",\"arguments\":\"\"}}\n\n\
data: {\"type\":\"response.output_item.done\",\"item\":{\"id\":\"fc_2\",\"type\":\"function_call\",\"call_id\":\"call_b\",\"name\":\"agent.read_file\",\"namespace\":\"agent\",\"arguments\":\"{\\\"path\\\":\\\"b.txt\\\"}\"}}\n\n\
data: {\"type\":\"response.output_item.done\",\"item\":{\"id\":\"fc_1\",\"type\":\"function_call\",\"call_id\":\"call_a\",\"namespace\":\"agent\",\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"a.txt\\\"}\"}}\n\n\
data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":30,\"output_tokens\":20}}}\n\n";
    let stub = route(|_, _| Reply::sse(CALLS)).await;
    let (_dir, client) = plan_client(&stub, plan_entry(now() + 3600));
    let (response, _) = client
        .complete(&[msg(Role::User, "read both")], &[], None)
        .await
        .expect("completes");
    match response {
        LlmResponse::ToolCalls { calls, text } => {
            assert_eq!(text.as_deref(), Some("Reading two files."));
            let got: Vec<(&str, &str, &str)> = calls
                .iter()
                .map(|c| (c.id.as_str(), c.name.as_str(), c.arguments.as_str()))
                .collect();
            assert_eq!(
                got,
                [
                    ("call_a", "read_file", r#"{"path":"a.txt"}"#),
                    ("call_b", "read_file", r#"{"path":"b.txt"}"#),
                ]
            );
        }
        other => panic!("expected tool calls, got {other:?}"),
    }
}

#[tokio::test]
async fn a_usage_limit_mid_stream_is_the_usage_limit_with_its_request_id() {
    const LIMIT: &str = "\
data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"delta\":\"Part\"}\n\n\
data: {\"type\":\"response.failed\",\"response\":{\"status\":\"failed\",\"error\":{\"code\":\"subscription_sharing_usage_limit_exceeded\",\"message\":\"limit\"}}}\n\n";
    let stub = route(|_, _| Reply::sse(LIMIT).with_header("x-request-id", "req_mid")).await;
    let (_dir, client) = plan_client(&stub, plan_entry(now() + 3600));
    let err = plan_error(
        client
            .complete(&[msg(Role::User, "hi")], &[], None)
            .await
            .unwrap_err(),
    );
    assert!(err.is_usage_limit(), "{err}");
    assert_eq!(err.failure().request_id.as_deref(), Some("req_mid"));
    let text = err.to_string();
    assert!(
        text.contains("Usage limit reached") && text.contains(USAGE_URL),
        "{text}"
    );
}

#[tokio::test]
async fn a_stream_that_ends_without_completed_is_an_error() {
    const CUT: &str = "\
data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_5\"}}\n\n\
data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"delta\":\"partial\"}\n\n";
    let stub = route(|_, _| Reply::sse(CUT)).await;
    let (_dir, client) = plan_client(&stub, plan_entry(now() + 3600));
    let err = plan_error(
        client
            .complete(&[msg(Role::User, "hi")], &[], None)
            .await
            .unwrap_err(),
    );
    assert!(matches!(err, PlanRouteError::StreamCut(_)), "{err}");
}

#[tokio::test]
async fn a_usage_limit_429_is_not_retried_and_keeps_status_code_and_request_id() {
    let stub = route(|_, _| {
        Reply::json(
            429,
            serde_json::json!({"error": {"code": "subscription_sharing_usage_limit_exceeded", "message": "limit"}}),
        )
        .with_header("x-request-id", "req_429")
        .with_header("retry-after", "0")
    })
    .await;
    let (_dir, client) = plan_client(&stub, plan_entry(now() + 3600));
    let err = client
        .complete(&[msg(Role::User, "hi")], &[], None)
        .await
        .unwrap_err();
    assert_eq!(stub.requests_to("/v1/responses").len(), 1, "never retried");

    // The failed call's audit row keeps what the error keeps.
    let row = crate::runtime::failed_call_row(
        "req-local",
        &err,
        5,
        &wirken_gateway::leak::LeakMatcher::new(),
        "agent".into(),
        Some("plan".into()),
        None,
    );
    match row {
        wirken_audit::SessionEvent::LlmRequestFailed { error, .. } => {
            for part in [
                "HTTP 429",
                "subscription_sharing_usage_limit_exceeded",
                "request id req_429",
                USAGE_URL,
            ] {
                assert!(error.contains(part), "{part} missing from: {error}");
            }
        }
        other => panic!("unexpected row {other:?}"),
    }
    let err = plan_error(err);
    assert!(err.is_usage_limit());
    assert_eq!(err.failure().status, Some(429));
}

#[tokio::test]
async fn a_503_gets_bounded_backoff_then_the_error() {
    let stub = route(|_, _| {
        Reply::json(
            503,
            serde_json::json!({"error": {"code": "subscription_sharing_usage_unavailable"}}),
        )
    })
    .await;
    let (_dir, client) = plan_client(&stub, plan_entry(now() + 3600));
    let err = plan_error(
        client
            .complete(&[msg(Role::User, "hi")], &[], None)
            .await
            .unwrap_err(),
    );
    assert!(matches!(err, PlanRouteError::UsageUnavailable(_)), "{err}");
    assert_eq!(
        stub.requests_to("/v1/responses").len(),
        UNAVAILABLE_BACKOFF.len() + 1
    );

    // A 503 that clears is a reply.
    let stub = route(|n, _| {
        if n < 2 {
            Reply::json(
                503,
                serde_json::json!({"error": {"code": "subscription_sharing_user_unavailable"}}),
            )
        } else {
            Reply::sse(TEXT_STREAM)
        }
    })
    .await;
    let (_dir, client) = plan_client(&stub, plan_entry(now() + 3600));
    assert!(
        client
            .complete(&[msg(Role::User, "hi")], &[], None)
            .await
            .is_ok()
    );
    assert_eq!(stub.requests_to("/v1/responses").len(), 3);
}

#[tokio::test]
async fn each_documented_code_is_its_own_variant_and_detail_bodies_are_admission() {
    let cases = [
        ("subscription_sharing_user_not_eligible", 403),
        ("subscription_sharing_unsupported_capability", 400),
        ("subscription_sharing_route_not_supported", 403),
        ("subscription_sharing_invalid_user", 401),
        ("chatpass_v2_scope_not_authorized", 403),
    ];
    for (code, status) in cases {
        let err = http_failure(
            status,
            &serde_json::json!({"error": {"code": code, "param": "tools"}}).to_string(),
            Some("req_1".into()),
        );
        let ok = match code {
            "subscription_sharing_user_not_eligible" => {
                matches!(err, PlanRouteError::UserNotEligible(_))
            }
            "subscription_sharing_unsupported_capability" => {
                matches!(err, PlanRouteError::UnsupportedCapability(_))
            }
            "subscription_sharing_route_not_supported" => {
                matches!(err, PlanRouteError::RouteNotSupported(_))
            }
            "subscription_sharing_invalid_user" => matches!(err, PlanRouteError::InvalidUser(_)),
            _ => matches!(err, PlanRouteError::PermissionContext(_)),
        };
        assert!(ok, "{code}: {err:?}");
        assert_eq!(err.failure().param.as_deref(), Some("tools"));
        assert_eq!(err.failure().status, Some(status));
    }
    let err = http_failure(403, r#"{"detail":"region not permitted"}"#, None);
    assert!(
        matches!(err, PlanRouteError::Admission(ref f) if f.message.as_deref() == Some("region not permitted"))
    );
}

#[tokio::test]
async fn without_a_token_source_or_with_an_expired_token_nothing_is_sent() {
    let stub = route(|_, _| Reply::sse(TEXT_STREAM)).await;
    let mut bare = LlmClient::new(LlmConfig::plan("m")).unwrap();
    bare.set_plan_endpoints_for_test(Endpoints::stub(&stub.base));
    let err = bare
        .complete(&[msg(Role::User, "hi")], &[], Some("sk-key"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no plan credential"), "{err}");

    // Expired, and the refresh fails: the call fails before the route.
    let (_dir, client) = plan_client(&stub, plan_entry(now().saturating_sub(10)));
    let err = client
        .complete(&[msg(Role::User, "hi")], &[], None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");
    assert!(stub.requests_to("/v1/responses").is_empty());
}

#[tokio::test]
async fn the_models_listing_keeps_listed_models_in_server_order() {
    let stub = stub::serve(|_| -> Handler {
        Arc::new(|req: &Request| match req.path.as_str() {
            "/v1/models" => {
                assert_eq!(req.header("authorization"), Some("Bearer at-live"));
                Reply::json(
                    200,
                    serde_json::json!({"models": [
                        {"slug": "b-model", "display_name": "B", "visibility": "list"},
                        {"slug": "hidden", "display_name": "H", "visibility": "hide"},
                        {"slug": "a-model", "display_name": "A", "visibility": "list"},
                    ]}),
                )
            }
            _ => Reply::empty(404),
        })
    })
    .await;
    let (_dir, client) = plan_client(&stub, plan_entry(now() + 3600));
    let source = client.plan_source().unwrap();
    let models = list_plan_models(&source).await.unwrap();
    assert_eq!(
        models,
        [
            PlanModel {
                slug: "b-model".into(),
                display_name: "B".into()
            },
            PlanModel {
                slug: "a-model".into(),
                display_name: "A".into()
            },
        ]
    );
    assert!(parse_plan_models(&serde_json::json!({"data": [{"id": "x"}]})).is_empty());
}
