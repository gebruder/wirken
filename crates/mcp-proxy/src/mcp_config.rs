//! MCP server configuration parsed from `mcp.json`.
//!
//! Moved here from `crates/agent/src/mcp/config.rs` as part of the
//! out-of-process MCP proxy split. The agent process no longer parses
//! mcp.json — only the proxy does.
//!
//! ## Schema
//!
//! Item 7 slice 2 of `docs/managed-agents-parity.md` extends the
//! schema with HTTP transport and OAuth2-protected MCP servers. The
//! enum is `untagged` so existing stdio configs without an explicit
//! `transport` field still parse — backward compatibility for any
//! `mcp.json` written before this slice.
//!
//! ```jsonc
//! {
//!   "servers": {
//!     "filesystem": {
//!       // legacy form, still works
//!       "command": "npx",
//!       "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path"],
//!       "env": {}
//!     },
//!     "datadog": {
//!       // explicit stdio with vault env
//!       "transport": "stdio",
//!       "command": "npx",
//!       "args": ["-y", "@datadog/mcp-server"],
//!       "env": { "DD_API_KEY": "vault:datadog-api-key" }
//!     },
//!     "linear": {
//!       // bearer token over HTTP
//!       "transport": "http",
//!       "url": "https://mcp.linear.app/sse",
//!       "auth": { "type": "bearer", "credential": "vault:linear-token" }
//!     },
//!     "google-drive": {
//!       // OAuth2 over HTTP
//!       "transport": "http",
//!       "url": "https://mcp.google.com/drive",
//!       "auth": {
//!         "type": "oauth2",
//!         "provider": "google",
//!         "credential": "vault:google-drive-oauth"
//!       }
//!     }
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::error::ProxyError;

/// MCP configuration — lists servers to connect to.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McpConfig {
    #[serde(default)]
    pub servers: HashMap<String, McpServerConfig>,
}

/// Configuration for a single MCP server.
///
/// Untagged enum: serde tries each variant in declaration order.
/// `Http` is first because it has a discriminating `url` field;
/// `Stdio` has `command`. Configs that match neither fail to parse
/// with a clear error. Legacy stdio configs without an explicit
/// `transport` still match `Stdio` because the variant doesn't
/// require the field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum McpServerConfig {
    /// HTTP transport: send JSON-RPC over HTTP POST to a remote
    /// MCP endpoint. Optional auth.
    Http {
        /// Discriminator. Always `"http"`. Required so the untagged
        /// enum can disambiguate from a legacy stdio config that
        /// happens to have a `url`-shaped string somewhere.
        #[serde(rename = "transport")]
        transport: HttpTransportTag,
        url: String,
        #[serde(default)]
        auth: Option<McpAuth>,
    },
    /// Stdio transport: spawn a process and communicate over stdin/stdout.
    Stdio {
        /// Optional discriminator. Defaults to `"stdio"` for legacy
        /// configs. The presence of `command` is what makes this
        /// variant match.
        #[serde(default, rename = "transport")]
        transport: Option<StdioTransportTag>,
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
    },
}

/// Tag type for the HTTP transport variant. Forces the JSON value
/// `"http"` and rejects anything else, so an `Http` config without
/// `"transport": "http"` won't match the variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HttpTransportTag {
    Http,
}

/// Tag type for the stdio variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StdioTransportTag {
    Stdio,
}

/// Authentication for an HTTP MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpAuth {
    /// Static bearer token. The credential is a `vault:NAME` string
    /// pointing at a vault entry that holds the raw token. The
    /// proxy resolves it on every request and never exposes it to
    /// the agent process.
    Bearer { credential: String },
    /// OAuth2 authorization code flow. `provider` selects a
    /// hardcoded entry from the per-provider endpoint registry
    /// (`linear`, `notion`, `github`, `google` for slice 2).
    /// `credential` is a `vault:NAME` string pointing at a vault
    /// entry that holds the JSON-serialized [`OAuthCredential`]
    /// (`access_token`, `refresh_token`, `expires_at`, …). Run
    /// `wirken mcp authorize <server>` once to populate it.
    ///
    /// [`OAuthCredential`]: crate::oauth::OAuthCredential
    Oauth2 {
        provider: String,
        credential: String,
    },
}

impl McpConfig {
    /// Load MCP config from a JSON file. Returns empty config if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self, ProxyError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| ProxyError::Config(format!("read {}: {e}", path.display())))?;
        serde_json::from_str(&content)
            .map_err(|e| ProxyError::Config(format!("parse {}: {e}", path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_stdio_without_transport_field() {
        let json = r#"{
            "servers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {}
                }
            }
        }"#;
        let cfg: McpConfig = serde_json::from_str(json).unwrap();
        let s = cfg.servers.get("filesystem").unwrap();
        match s {
            McpServerConfig::Stdio {
                command,
                args,
                env,
                transport,
            } => {
                assert_eq!(command, "npx");
                assert_eq!(args.len(), 3);
                assert!(env.is_empty());
                assert!(transport.is_none());
            }
            _ => panic!("expected stdio, got {s:?}"),
        }
    }

    #[test]
    fn parses_explicit_stdio() {
        let json = r#"{
            "servers": {
                "x": {
                    "transport": "stdio",
                    "command": "echo"
                }
            }
        }"#;
        let cfg: McpConfig = serde_json::from_str(json).unwrap();
        match cfg.servers.get("x").unwrap() {
            McpServerConfig::Stdio { command, .. } => assert_eq!(command, "echo"),
            other => panic!("expected stdio, got {other:?}"),
        }
    }

    #[test]
    fn parses_http_no_auth() {
        let json = r#"{
            "servers": {
                "internal": {
                    "transport": "http",
                    "url": "https://internal.example.com/mcp"
                }
            }
        }"#;
        let cfg: McpConfig = serde_json::from_str(json).unwrap();
        match cfg.servers.get("internal").unwrap() {
            McpServerConfig::Http { url, auth, .. } => {
                assert_eq!(url, "https://internal.example.com/mcp");
                assert!(auth.is_none());
            }
            other => panic!("expected http, got {other:?}"),
        }
    }

    #[test]
    fn parses_http_bearer_auth() {
        let json = r#"{
            "servers": {
                "linear": {
                    "transport": "http",
                    "url": "https://mcp.linear.app",
                    "auth": { "type": "bearer", "credential": "vault:linear-token" }
                }
            }
        }"#;
        let cfg: McpConfig = serde_json::from_str(json).unwrap();
        match cfg.servers.get("linear").unwrap() {
            McpServerConfig::Http { auth, .. } => match auth {
                Some(McpAuth::Bearer { credential }) => {
                    assert_eq!(credential, "vault:linear-token");
                }
                other => panic!("expected bearer, got {other:?}"),
            },
            _ => panic!("expected http"),
        }
    }

    #[test]
    fn parses_http_oauth2_auth() {
        let json = r#"{
            "servers": {
                "google-drive": {
                    "transport": "http",
                    "url": "https://mcp.google.com/drive",
                    "auth": {
                        "type": "oauth2",
                        "provider": "google",
                        "credential": "vault:google-drive-oauth"
                    }
                }
            }
        }"#;
        let cfg: McpConfig = serde_json::from_str(json).unwrap();
        match cfg.servers.get("google-drive").unwrap() {
            McpServerConfig::Http { auth, .. } => match auth {
                Some(McpAuth::Oauth2 {
                    provider,
                    credential,
                }) => {
                    assert_eq!(provider, "google");
                    assert_eq!(credential, "vault:google-drive-oauth");
                }
                other => panic!("expected oauth2, got {other:?}"),
            },
            _ => panic!("expected http"),
        }
    }
}
