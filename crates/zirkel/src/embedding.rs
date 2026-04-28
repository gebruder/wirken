//! Ollama embedding helper.
//!
//! Calls Ollama's `/api/embed` endpoint through the policed
//! [`wirken_agent::egress::EgressClient`]. Per the C-LLM pre-checks
//! (Path C), this is a Zirkel-internal helper rather than an
//! abstraction in the agent crate. If a second skill ever needs
//! embeddings, the right shape becomes a small `EmbeddingClient`
//! struct in `wirken-agent`; until then, YAGNI.
//!
//! ## Egress
//!
//! Ollama runs at `127.0.0.1:11434` by default. The aggregator
//! skill's `egress.domains` allow-set must include `127.0.0.1` for
//! the embedding fetch to pass the policed transport. The bypass
//! invariant is preserved — adding a host to the allowlist expands
//! what's allowed, not how enforcement works. The `127.0.0.1` entry
//! in `preset/zirkel/skills/aggregator/SKILL.md` carries a one-line
//! comment explaining the why so future readers don't read it as a
//! generic local-network exception.
//!
//! ## API shape
//!
//! Ollama's `/api/embed` accepts a JSON body with `model` and `input`
//! (a string or array of strings). Response carries `model` and
//! `embeddings` (array of float arrays). One round-trip per call;
//! the helper exposes both single and batch forms.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use wirken_agent::egress::{EgressClient, HttpAccessDenied};

/// Default embedding model. Per `docs/zirkel/DESIGN.md`:
/// nomic-embed-text v1.5 — small (~137M params), CPU-fast, 768-dim.
pub const DEFAULT_EMBEDDING_MODEL: &str = "nomic-embed-text:v1.5";

#[derive(Debug, Error)]
pub enum EmbeddingError {
    #[error("HTTP denied for {url}: {source}")]
    Denied {
        url: String,
        #[source]
        source: HttpAccessDenied,
    },
    #[error("HTTP non-success for {url}: status {status}")]
    HttpStatus { url: String, status: u16 },
    #[error("network error for {url}: {source}")]
    Network {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("decode embed response: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("embed response shape mismatch: expected {expected} embeddings, got {actual}")]
    ShapeMismatch { expected: usize, actual: usize },
}

#[derive(Debug, Serialize)]
struct EmbedRequest<'a> {
    model: &'a str,
    input: Vec<&'a str>,
}

#[derive(Debug, Deserialize)]
struct EmbedResponse {
    embeddings: Vec<Vec<f32>>,
}

/// Embed a single text. Convenience wrapper over [`embed_batch`].
pub async fn embed_one(
    http: &EgressClient,
    ollama_base: &str,
    model: &str,
    text: &str,
) -> Result<Vec<f32>, EmbeddingError> {
    let mut vecs = embed_batch(http, ollama_base, model, &[text]).await?;
    if vecs.len() != 1 {
        return Err(EmbeddingError::ShapeMismatch {
            expected: 1,
            actual: vecs.len(),
        });
    }
    Ok(vecs.pop().unwrap())
}

/// Embed a batch of texts. Order of returned vectors matches the
/// input order. One HTTP round trip; Ollama's `/api/embed` natively
/// accepts arrays.
pub async fn embed_batch(
    http: &EgressClient,
    ollama_base: &str,
    model: &str,
    texts: &[&str],
) -> Result<Vec<Vec<f32>>, EmbeddingError> {
    if texts.is_empty() {
        return Ok(Vec::new());
    }
    let url = format!("{}/api/embed", ollama_base.trim_end_matches('/'));
    let body = EmbedRequest {
        model,
        input: texts.to_vec(),
    };
    let builder = http.post(&url).await.map_err(|e| EmbeddingError::Denied {
        url: url.clone(),
        source: e,
    })?;
    let resp = builder
        .json(&body)
        .send()
        .await
        .map_err(|e| EmbeddingError::Network {
            url: url.clone(),
            source: e,
        })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(EmbeddingError::HttpStatus {
            url,
            status: status.as_u16(),
        });
    }
    let parsed: EmbedResponse = resp.json().await.map_err(|e| EmbeddingError::Network {
        url: url.clone(),
        source: e,
    })?;
    if parsed.embeddings.len() != texts.len() {
        return Err(EmbeddingError::ShapeMismatch {
            expected: texts.len(),
            actual: parsed.embeddings.len(),
        });
    }
    Ok(parsed.embeddings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use wirken_agent::egress::EgressEnforcement;

    /// One-shot HTTP server that returns a fixed JSON body.
    async fn one_shot_json(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        url
    }

    fn allowlist_localhost() -> EgressClient {
        let c = EgressClient::new();
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "127.0.0.1".to_string()
        ])));
        c
    }

    #[tokio::test]
    async fn embed_one_returns_a_single_vector() {
        let body = r#"{"model":"nomic-embed-text:v1.5","embeddings":[[0.1, 0.2, 0.3]]}"#;
        let base = one_shot_json(body).await;
        let c = allowlist_localhost();
        let v = embed_one(&c, &base, DEFAULT_EMBEDDING_MODEL, "hello world")
            .await
            .unwrap();
        assert_eq!(v, vec![0.1, 0.2, 0.3]);
    }

    #[tokio::test]
    async fn embed_batch_preserves_order() {
        let body =
            r#"{"model":"nomic-embed-text:v1.5","embeddings":[[1.0,0.0],[0.0,1.0],[0.5,0.5]]}"#;
        let base = one_shot_json(body).await;
        let c = allowlist_localhost();
        let v = embed_batch(&c, &base, "nomic-embed-text:v1.5", &["a", "b", "c"])
            .await
            .unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], vec![1.0, 0.0]);
        assert_eq!(v[1], vec![0.0, 1.0]);
        assert_eq!(v[2], vec![0.5, 0.5]);
    }

    #[tokio::test]
    async fn embed_empty_input_is_empty_output() {
        let c = allowlist_localhost();
        let v = embed_batch(&c, "http://does-not-matter", "m", &[])
            .await
            .unwrap();
        assert!(v.is_empty());
    }

    #[tokio::test]
    async fn shape_mismatch_returns_error() {
        // Server returns 2 embeddings for 3 inputs.
        let body = r#"{"model":"x","embeddings":[[1.0],[0.0]]}"#;
        let base = one_shot_json(body).await;
        let c = allowlist_localhost();
        let err = embed_batch(&c, &base, "m", &["a", "b", "c"])
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            EmbeddingError::ShapeMismatch {
                expected: 3,
                actual: 2
            }
        ));
    }

    #[tokio::test]
    async fn egress_denial_for_non_allowlisted_host() {
        // Allowlist explicitly excludes 127.0.0.1 — the embed call
        // must fail at egress, not at the network.
        let c = EgressClient::new();
        c.set_enforcement(EgressEnforcement::Allowlist(BTreeSet::from([
            "other.example.com".to_string(),
        ])));
        let err = embed_one(&c, "http://127.0.0.1:11434", "m", "x")
            .await
            .unwrap_err();
        assert!(matches!(err, EmbeddingError::Denied { .. }));
    }
}
