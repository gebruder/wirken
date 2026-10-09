//! MCP server configuration parsed from `mcp.json`.
//!
//! Moved here from `crates/agent/src/mcp/config.rs` as part of the
//! out-of-process MCP proxy split. The agent process no longer parses
//! mcp.json — only the proxy does.
//!
//! ## Schema
//!
//! The schema covers stdio, HTTP transport and OAuth2-protected MCP
//! servers. The enum is `untagged` so a stdio config with no explicit
//! `transport` field still parses: backward compatibility for any
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
        /// Hex-encoded Ed25519 signature over the canonical entry
        /// hash defined by [`crate::mcp_signing::hash_mcp_entry`].
        /// Absent on unsigned entries (legacy `mcp.json` files);
        /// when an MCP root anchor is configured at build time,
        /// absence is refused unless `WIRKEN_ALLOW_UNSIGNED_MCP=1`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        /// Hex-encoded 32-byte Ed25519 public key of the signer.
        /// Must be present whenever `signature` is present; absence
        /// with a present signature is a hard fail (the verifier
        /// has nothing to check against).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer_key: Option<String>,
        /// Hex-encoded Ed25519 signature by the compile-time
        /// bundled root over the raw 32-byte `signer_key`.
        /// Required when [`crate::mcp_signing::bundled_mcp_pubkey`]
        /// returns `Some`; ignored when the bundled root is empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer_key_delegation: Option<String>,
        /// Declared per-call cost of this server's tools, in USD
        /// micros, keyed by the bare tool name as the server reports
        /// it (no `mcp_{server}_` prefix).
        ///
        /// Spend is a budget concern, not a permission tier. A tool
        /// named here debits the agent's budget ledger through the
        /// same path an inference call does, and a call made with the
        /// window already at its ceiling is refused with a
        /// `BudgetExceeded` row. A tool absent from this map costs
        /// nothing and behaves exactly as before, which is every tool
        /// on every server until an operator says otherwise.
        ///
        /// The figure is what the operator declares, not what the
        /// vendor charges. Nothing reconciles the two; this is a
        /// budget an operator sets against calls they know to be
        /// expensive, not metering.
        #[serde(default, skip_serializing_if = "HashMap::is_empty")]
        tool_costs: HashMap<String, u64>,
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
        /// See [`Self::Http::signature`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        /// See [`Self::Http::signer_key`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer_key: Option<String>,
        /// See [`Self::Http::signer_key_delegation`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer_key_delegation: Option<String>,
        /// See [`Self::Http::tool_costs`].
        #[serde(default, skip_serializing_if = "HashMap::is_empty")]
        tool_costs: HashMap<String, u64>,
        /// Where the server runs: a container described by the block,
        /// or `"off"` for the host. Inside the signed envelope, so it
        /// cannot be widened on a signed entry without re-signing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sandbox: Option<StdioSandbox>,
    },
}

/// Where a stdio server runs.
///
/// Untagged so `"sandbox": "off"` and `"sandbox": { ... }` are both
/// accepted. Any other shape is kept as [`StdioSandbox::Invalid`]
/// rather than failing the whole file, so one malformed entry is
/// refused on its own and the rest of `mcp.json` still loads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum StdioSandbox {
    /// Run on the host, uncontained, as every stdio server did before
    /// the sandbox existed. An explicit operator choice.
    Off(SandboxOff),
    /// Run in a container.
    Container(ContainerSandbox),
    /// Neither shape. Refused at start.
    Invalid(serde_json::Value),
}

/// The literal `"off"`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SandboxOff {
    Off,
}

/// A stdio server's container. Everything not declared is closed:
/// no network, no mounts beyond `install_dir`, and the exec sandbox's
/// limits plus one CPU.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ContainerSandbox {
    /// Image the server runs in, carrying its runtime (Node, Python,
    /// ...). Required: a block without one is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Host directory the server was installed into, mounted
    /// read-only at [`INSTALL_DIR_TARGET`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_dir: Option<String>,
    /// Hosts the server may reach. Absent or empty means no network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<SandboxEgress>,
    /// Further host paths, read-only unless `writable`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<SandboxMount>,
    /// A writable scratch directory at [`SCRATCH_TARGET`], kept on the
    /// host under `<data_dir>/mcp-scratch/<agent>/<server>`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub scratch: bool,
    /// Overrides for the container's limits.
    #[serde(default, skip_serializing_if = "SandboxLimits::is_default")]
    pub limits: SandboxLimits,
    /// `vault:` values delivered as environment variables instead of
    /// files. Every other `vault:` value arrives as a file and its
    /// variable is set to `<NAME>_FILE` holding the file's path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets_in_env: Vec<String>,
}

/// Where the install directory appears inside the container.
pub const INSTALL_DIR_TARGET: &str = "/opt/mcp";
/// Where the scratch directory appears inside the container.
pub const SCRATCH_TARGET: &str = "/scratch";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxEgress {
    /// Domain patterns, as for exec egress: `api.github.com` or
    /// `*.datadoghq.com`.
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxMount {
    pub source: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub writable: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SandboxLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<f64>,
}

impl SandboxLimits {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

impl McpServerConfig {
    /// Declared per-call costs for this server's tools, in USD
    /// micros, keyed by the bare tool name.
    pub fn tool_costs(&self) -> &HashMap<String, u64> {
        match self {
            Self::Http { tool_costs, .. } | Self::Stdio { tool_costs, .. } => tool_costs,
        }
    }
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
    /// (`linear`, `notion`, `github`, `google`).
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
                ..
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

    fn sandbox_of(json: &str) -> Option<StdioSandbox> {
        let config: McpConfig = serde_json::from_str(json).unwrap();
        match config.servers.into_values().next().unwrap() {
            McpServerConfig::Stdio { sandbox, .. } => sandbox,
            McpServerConfig::Http { .. } => panic!("expected stdio"),
        }
    }

    #[test]
    fn a_stdio_entry_without_a_sandbox_block_has_none() {
        assert_eq!(sandbox_of(r#"{"servers":{"a":{"command":"x"}}}"#), None);
    }

    #[test]
    fn off_parses_as_off() {
        assert_eq!(
            sandbox_of(r#"{"servers":{"a":{"command":"x","sandbox":"off"}}}"#),
            Some(StdioSandbox::Off(SandboxOff::Off))
        );
    }

    #[test]
    fn a_container_block_parses_every_field() {
        let sandbox = sandbox_of(
            r#"{"servers":{"a":{"command":"node","sandbox":{
                "image":"node:22-slim","install_dir":"/srv/mcp/a",
                "egress":{"hosts":["api.github.com"]},
                "mounts":[{"source":"/srv/data","target":"/data","writable":true}],
                "scratch":true,
                "limits":{"memory_mb":256,"pids":64,"cpus":0.5},
                "secrets_in_env":["TOKEN"]}}}}"#,
        );
        let Some(StdioSandbox::Container(c)) = sandbox else {
            panic!("expected a container block, got {sandbox:?}");
        };
        assert_eq!(c.image.as_deref(), Some("node:22-slim"));
        assert_eq!(c.install_dir.as_deref(), Some("/srv/mcp/a"));
        assert_eq!(c.egress.unwrap().hosts, ["api.github.com"]);
        assert_eq!(
            c.mounts,
            [SandboxMount {
                source: "/srv/data".into(),
                target: "/data".into(),
                writable: true,
            }]
        );
        assert!(c.scratch);
        assert_eq!(c.limits.memory_mb, Some(256));
        assert_eq!(c.limits.pids, Some(64));
        assert_eq!(c.limits.cpus, Some(0.5));
        assert_eq!(c.secrets_in_env, ["TOKEN"]);
    }

    #[test]
    fn a_block_without_an_image_still_parses_so_it_can_be_refused() {
        let sandbox = sandbox_of(r#"{"servers":{"a":{"command":"x","sandbox":{}}}}"#);
        assert_eq!(
            sandbox,
            Some(StdioSandbox::Container(ContainerSandbox::default()))
        );
    }

    #[test]
    fn a_malformed_block_is_kept_and_the_file_still_loads() {
        let config: McpConfig = serde_json::from_str(
            r#"{"servers":{
                "bad":{"command":"x","sandbox":"none"},
                "typed":{"command":"x","sandbox":{"mounts":"not-a-list"}},
                "good":{"command":"y"}}}"#,
        )
        .unwrap();
        assert_eq!(config.servers.len(), 3);
        for name in ["bad", "typed"] {
            let McpServerConfig::Stdio { sandbox, .. } = &config.servers[name] else {
                panic!("expected stdio");
            };
            assert!(
                matches!(sandbox, Some(StdioSandbox::Invalid(_))),
                "{name}: {sandbox:?}"
            );
        }
    }
}
