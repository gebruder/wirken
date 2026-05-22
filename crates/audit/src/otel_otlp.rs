//! OTLP/HTTP+JSON serialization for projector-produced spans.
//!
//! Hand-builds the `ExportTraceServiceRequest` body documented at
//! the OTLP JSON-Protobuf encoding spec
//! (`opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding`)
//! with the Agent 365 wire-level requirements applied:
//!
//! - Every attribute value emitted as `stringValue`, including
//!   numeric fields like token counts. The projector already
//!   stamps attributes as `(String, String)` pairs for the same
//!   reason; the serializer simply wraps them.
//! - Hex trace and span ids (already lowercase from
//!   `TraceId::as_hex` / `SpanId::as_hex`).
//! - String-encoded nanosecond timestamps. `startTimeUnixNano`
//!   and `endTimeUnixNano` are serialized as decimal strings, not
//!   numbers.
//! - Integer `kind` (1-5) and `status.code` (0-2).
//! - `parentSpanId` present only on non-root spans (root has
//!   `parent_span_id == None`).
//! - `status.message` present only when `status` is `Error`. The
//!   projector enforces this coupling; the serializer respects
//!   the `Option<String>` it receives.
//!
//! ## Layer boundary
//!
//! Pure structural serialization. No batching, no
//! body-size policing, no HTTP. The batcher and HTTP transport
//! that consume this output land in follow-up commits and apply
//! policy (1 MiB cap with recursive split on 413, 429 backoff,
//! bearer-auth injection).

use serde_json::{Value, json};

use crate::otel_projector::Span;

/// Serialize a batch of spans into the OTLP/HTTP+JSON
/// `ExportTraceServiceRequest` envelope.
///
/// Returns a `serde_json::Value` the caller passes to
/// `serde_json::to_vec` for HTTP transport or inspects for
/// testing. Empty batches produce a well-formed envelope with one
/// `resourceSpans` entry and one `scopeSpans` entry whose `spans`
/// array is empty; the transport layer is expected to skip
/// POSTing empty batches rather than relying on this serializer to
/// short-circuit.
pub fn serialize_batch(spans: &[Span]) -> Value {
    let serialized_spans: Vec<Value> = spans.iter().map(serialize_span).collect();
    json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    attribute("service.name", "wirken"),
                    attribute("service.version", env!("CARGO_PKG_VERSION")),
                ]
            },
            "scopeSpans": [{
                "scope": {
                    "name": "wirken-audit",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "spans": serialized_spans,
            }]
        }]
    })
}

fn serialize_span(span: &Span) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(
        "traceId".to_string(),
        Value::String(span.trace_id.as_hex().to_string()),
    );
    object.insert(
        "spanId".to_string(),
        Value::String(span.span_id.as_hex().to_string()),
    );
    if let Some(parent) = &span.parent_span_id {
        object.insert(
            "parentSpanId".to_string(),
            Value::String(parent.as_hex().to_string()),
        );
    }
    object.insert("name".to_string(), Value::String(span.name.clone()));
    object.insert("kind".to_string(), json!(span.kind as i32));
    // String-encoded nanos: the wire shape requires decimal-string
    // values for the two timestamp fields even though they
    // semantically hold integers. A consumer that parses them as
    // JSON numbers gets the same value back; emitting them as
    // numbers fails Agent 365's encoding check.
    object.insert(
        "startTimeUnixNano".to_string(),
        Value::String(span.start_time_unix_nano.to_string()),
    );
    object.insert(
        "endTimeUnixNano".to_string(),
        Value::String(span.end_time_unix_nano.to_string()),
    );
    let attributes: Vec<Value> = span
        .attributes
        .iter()
        .map(|(k, v)| attribute(k, v))
        .collect();
    object.insert("attributes".to_string(), Value::Array(attributes));
    object.insert(
        "status".to_string(),
        serialize_status(span.status as i32, span.status_message.as_deref()),
    );
    Value::Object(object)
}

fn attribute(key: &str, value: &str) -> Value {
    json!({
        "key": key,
        "value": { "stringValue": value },
    })
}

fn serialize_status(code: i32, message: Option<&str>) -> Value {
    let mut s = serde_json::Map::new();
    s.insert("code".to_string(), json!(code));
    if let Some(msg) = message {
        s.insert("message".to_string(), Value::String(msg.to_string()));
    }
    Value::Object(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otel_projector::{SpanId, SpanKind, SpanStatus, TraceId};

    fn sample_span() -> Span {
        Span {
            trace_id: TraceId::random(),
            span_id: SpanId::random(),
            parent_span_id: None,
            name: "invoke_agent".to_string(),
            kind: SpanKind::Internal,
            start_time_unix_nano: 1_700_000_000_000_000_000,
            end_time_unix_nano: 1_700_000_010_000_000_000,
            status: SpanStatus::Ok,
            status_message: None,
            attributes: vec![
                (
                    "gen_ai.operation.name".to_string(),
                    "invoke_agent".to_string(),
                ),
                ("gen_ai.usage.input_tokens".to_string(), "42".to_string()),
            ],
        }
    }

    fn batch_root(value: &Value) -> &Value {
        &value["resourceSpans"][0]
    }

    fn batch_scope(value: &Value) -> &Value {
        &batch_root(value)["scopeSpans"][0]
    }

    fn batch_spans(value: &Value) -> &Value {
        &batch_scope(value)["spans"]
    }

    fn nth_span(value: &Value, n: usize) -> &Value {
        &batch_spans(value)[n]
    }

    #[test]
    fn empty_batch_yields_envelope_with_empty_spans_array() {
        let v = serialize_batch(&[]);
        assert!(batch_spans(&v).is_array());
        assert_eq!(batch_spans(&v).as_array().unwrap().len(), 0);
    }

    #[test]
    fn envelope_has_resource_with_service_name_wirken() {
        let v = serialize_batch(&[]);
        let resource_attrs = batch_root(&v)["resource"]["attributes"]
            .as_array()
            .expect("resource.attributes must be an array");
        let service_name = resource_attrs
            .iter()
            .find(|a| a["key"] == "service.name")
            .expect("service.name must be present on the resource");
        assert_eq!(service_name["value"]["stringValue"], "wirken");
    }

    #[test]
    fn envelope_has_scope_with_name_wirken_audit() {
        let v = serialize_batch(&[]);
        assert_eq!(batch_scope(&v)["scope"]["name"], "wirken-audit");
    }

    #[test]
    fn single_span_serializes_trace_and_span_ids_as_lowercase_hex_strings() {
        let span = sample_span();
        let trace_hex = span.trace_id.as_hex().to_string();
        let span_hex = span.span_id.as_hex().to_string();
        let v = serialize_batch(&[span]);
        assert_eq!(nth_span(&v, 0)["traceId"], trace_hex);
        assert_eq!(nth_span(&v, 0)["spanId"], span_hex);
    }

    #[test]
    fn parent_span_id_present_when_some_absent_when_none() {
        let span_without = sample_span();
        let mut span_with = sample_span();
        let parent = SpanId::random();
        span_with.parent_span_id = Some(parent.clone());

        let v_without = serialize_batch(&[span_without]);
        let v_with = serialize_batch(&[span_with]);

        assert!(nth_span(&v_without, 0).get("parentSpanId").is_none());
        assert_eq!(
            nth_span(&v_with, 0)["parentSpanId"].as_str().unwrap(),
            parent.as_hex(),
        );
    }

    #[test]
    fn timestamps_emit_as_decimal_strings_not_numbers() {
        // The wire shape requires the two timestamp fields as
        // decimal strings even though they semantically hold
        // integers. A consumer parsing the JSON number form back
        // would get the same value, but Agent 365's encoding
        // check rejects the numeric variant.
        let span = sample_span();
        let v = serialize_batch(&[span]);
        let start = &nth_span(&v, 0)["startTimeUnixNano"];
        let end = &nth_span(&v, 0)["endTimeUnixNano"];
        assert!(
            start.is_string(),
            "startTimeUnixNano must serialize as a string, got {start:?}"
        );
        assert!(
            end.is_string(),
            "endTimeUnixNano must serialize as a string, got {end:?}"
        );
        assert_eq!(start.as_str().unwrap(), "1700000000000000000");
        assert_eq!(end.as_str().unwrap(), "1700000010000000000");
    }

    #[test]
    fn kind_emits_as_integer() {
        let span = sample_span();
        let v = serialize_batch(&[span]);
        let kind = &nth_span(&v, 0)["kind"];
        assert!(
            kind.is_number(),
            "kind must serialize as a number, got {kind:?}"
        );
        assert_eq!(kind.as_i64().unwrap(), SpanKind::Internal as i64);
    }

    #[test]
    fn status_code_emits_as_integer_zero_one_or_two() {
        let mut span = sample_span();
        span.status = SpanStatus::Error;
        span.status_message = Some("boom".to_string());
        let v = serialize_batch(&[span]);
        let code = &nth_span(&v, 0)["status"]["code"];
        assert!(
            code.is_number(),
            "status.code must be a number, got {code:?}"
        );
        assert_eq!(code.as_i64().unwrap(), SpanStatus::Error as i64);
    }

    #[test]
    fn status_message_present_only_when_status_message_is_some() {
        let mut error_span = sample_span();
        error_span.status = SpanStatus::Error;
        error_span.status_message = Some("rate limited".to_string());
        let ok_span = sample_span();

        let v_error = serialize_batch(&[error_span]);
        let v_ok = serialize_batch(&[ok_span]);

        assert_eq!(
            nth_span(&v_error, 0)["status"]["message"].as_str(),
            Some("rate limited"),
        );
        assert!(nth_span(&v_ok, 0)["status"].get("message").is_none());
    }

    #[test]
    fn attribute_values_are_wrapped_as_string_value() {
        let span = sample_span();
        let v = serialize_batch(&[span]);
        let attrs = nth_span(&v, 0)["attributes"]
            .as_array()
            .expect("attributes must be an array");
        for attr in attrs {
            assert!(
                attr["value"].get("stringValue").is_some(),
                "every attribute value must be wrapped as stringValue (Agent 365 rejects intValue / doubleValue): {attr:?}",
            );
            // No other value-type keys should appear.
            assert!(attr["value"].get("intValue").is_none());
            assert!(attr["value"].get("doubleValue").is_none());
            assert!(attr["value"].get("boolValue").is_none());
        }
    }

    #[test]
    fn numeric_looking_attribute_values_still_serialize_as_strings() {
        // gen_ai.usage.input_tokens is semantically a number but
        // the wire shape requires it as a string. The projector
        // stores all attribute values as String; this test asserts
        // the serializer does not "helpfully" detect numeric
        // strings and re-emit them as intValue.
        let span = sample_span();
        let v = serialize_batch(&[span]);
        let attrs = nth_span(&v, 0)["attributes"].as_array().unwrap();
        let tokens = attrs
            .iter()
            .find(|a| a["key"] == "gen_ai.usage.input_tokens")
            .expect("token attribute must be present");
        assert_eq!(tokens["value"]["stringValue"], "42");
        assert!(tokens["value"].get("intValue").is_none());
    }

    #[test]
    fn multiple_spans_serialize_into_same_scope_spans_array() {
        let v = serialize_batch(&[sample_span(), sample_span(), sample_span()]);
        let spans = batch_spans(&v).as_array().unwrap();
        assert_eq!(spans.len(), 3);
    }

    #[test]
    fn envelope_is_serializable_to_bytes() {
        // The transport layer ultimately calls serde_json::to_vec
        // on the returned Value; assert that round-trips without
        // error for a non-trivial span set.
        let mut child = sample_span();
        child.parent_span_id = Some(SpanId::random());
        child.name = "chat".to_string();
        child.kind = SpanKind::Client;
        child.status = SpanStatus::Error;
        child.status_message = Some("provider unreachable".to_string());

        let v = serialize_batch(&[sample_span(), child]);
        let bytes = serde_json::to_vec(&v).expect("envelope must be JSON-serializable");
        assert!(!bytes.is_empty());
        // Round-trip back to Value to confirm structural validity.
        let _: Value = serde_json::from_slice(&bytes).expect("round-trip parse must succeed");
    }
}
