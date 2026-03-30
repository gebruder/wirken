//! Minimal AWS SigV4 request signing for Bedrock.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Sign an HTTP request using AWS Signature Version 4.
/// Returns a list of (header_name, header_value) pairs to add to the request.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    region: &str,
    service: &str,
    method: &str,
    url: &url::Url,
    body: &[u8],
) -> Vec<(String, String)> {
    let now = chrono::Utc::now();
    let datestamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let payload_hash = hex_sha256(body);

    let host = url.host_str().unwrap_or("");
    let path = url.path();

    // Canonical query string (sorted)
    let mut query_pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    query_pairs.sort();
    let canonical_querystring: String = if query_pairs.is_empty() {
        String::new()
    } else {
        query_pairs
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    };

    // Signed headers (must include host and x-amz-date)
    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), host.into()),
        ("x-amz-content-sha256".into(), payload_hash.clone()),
        ("x-amz-date".into(), amz_date.clone()),
    ];
    if let Some(token) = session_token {
        headers.push(("x-amz-security-token".into(), token.into()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: String = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();

    let canonical_request = format!(
        "{method}\n{path}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let credential_scope = format!("{datestamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex_sha256(canonical_request.as_bytes())
    );

    // Derive signing key
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    let signature = hex_encode(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut result = vec![
        ("Authorization".into(), authorization),
        ("x-amz-date".into(), amz_date),
        ("x-amz-content-sha256".into(), payload_hash),
    ];
    if let Some(token) = session_token {
        result.push(("x-amz-security-token".into(), token.into()));
    }

    result
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Percent-encode per RFC 3986 (as required by SigV4).
fn uri_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                String::from(b as char)
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // AWS's published example credentials for SigV4 test vectors.
    // See: https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    const TEST_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    #[test]
    fn sigv4_produces_valid_structure() {
        let url =
            url::Url::parse("https://bedrock-runtime.us-east-1.amazonaws.com/model/test/converse")
                .unwrap();
        let body = b"{\"messages\":[]}";

        let headers = sign(
            TEST_ACCESS_KEY,
            TEST_SECRET_KEY,
            None,
            "us-east-1",
            "bedrock",
            "POST",
            &url,
            body,
        );

        let auth = headers.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert!(
            auth.1
                .starts_with(&format!("AWS4-HMAC-SHA256 Credential={TEST_ACCESS_KEY}/"))
        );
        assert!(auth.1.contains("us-east-1/bedrock/aws4_request"));
        assert!(
            auth.1
                .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date")
        );

        let date = headers.iter().find(|(k, _)| k == "x-amz-date").unwrap();
        assert_eq!(date.1.len(), 16); // YYYYMMDDTHHmmSSZ
    }

    #[test]
    fn sigv4_with_session_token() {
        let url =
            url::Url::parse("https://bedrock-runtime.us-west-2.amazonaws.com/model/test/converse")
                .unwrap();

        let headers = sign(
            "AKIDEXAMPLE",
            "SKEXAMPLEKEY",
            Some("SESSION_TOKEN_EXAMPLE"),
            "us-west-2",
            "bedrock",
            "POST",
            &url,
            b"{}",
        );

        let token = headers.iter().find(|(k, _)| k == "x-amz-security-token");
        assert!(token.is_some());
        assert_eq!(token.unwrap().1, "SESSION_TOKEN_EXAMPLE");

        let auth = headers.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert!(auth.1.contains("x-amz-security-token"));
    }

    #[test]
    fn sigv4_deterministic_for_same_inputs() {
        // Signing should be deterministic within the same second
        let url = url::Url::parse("https://example.com/path").unwrap();
        let h1 = sign(
            TEST_ACCESS_KEY,
            TEST_SECRET_KEY,
            None,
            "us-east-1",
            "s3",
            "GET",
            &url,
            b"",
        );
        let h2 = sign(
            TEST_ACCESS_KEY,
            TEST_SECRET_KEY,
            None,
            "us-east-1",
            "s3",
            "GET",
            &url,
            b"",
        );
        assert_eq!(h1, h2);
    }
}
