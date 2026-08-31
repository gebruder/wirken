use base64::Engine;
use cap_std::ambient_authority;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, RwLock};

use crate::error::AgentError;
use crate::sandbox::{DockerSandbox, SandboxConfig, SandboxMode};
use wirken_gateway::permissions::Action;

/// Maximum bytes a built-in tool will buffer from an HTTP response
/// body. Mirrors zirkel's `MAX_FETCH_BYTES`. The cap exists so a
/// hostile or misbehaving upstream cannot drive an unbounded
/// allocation through the tool dispatcher.
const MAX_TOOL_BODY_BYTES: u64 = 32 * 1024 * 1024;

/// Stream `resp.body` into a Vec<u8>, refusing to accumulate more
/// than [`MAX_TOOL_BODY_BYTES`]. Returned errors carry the cap so a
/// caller can decide whether to surface the limit to the LLM verbatim.
async fn read_capped(resp: reqwest::Response) -> Result<Vec<u8>, AgentError> {
    use futures_util::StreamExt as _;
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AgentError::Tool(format!("read response chunk: {e}")))?;
        if (buf.len() as u64) + (chunk.len() as u64) > MAX_TOOL_BODY_BYTES {
            return Err(AgentError::Tool(format!(
                "response body exceeded {MAX_TOOL_BODY_BYTES}-byte cap; aborting"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Tool definition for the LLM (OpenAI function calling format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// Result of executing a tool.
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub output: String,
    pub success: bool,
}

/// Configuration for tools that need external services.
#[derive(Debug, Clone, Default)]
pub struct ToolConfig {
    pub api_key: Option<String>,
    pub provider: Option<String>,
    pub base_url: Option<String>,
    pub sandbox: SandboxConfig,
}

/// Built-in tool implementations.
pub struct ToolRegistry {
    /// Path form of the workspace. Kept for the `exec` tool's
    /// current-dir and sandbox bind-mount; those paths still go
    /// through the OS by filename. All file tools use
    /// [`Self::workspace_dir`] instead. Also surfaced via
    /// [`Self::workspace`] so the agent's `attach_skills` can expand
    /// the `<workspace>` token in filesystem permission paths.
    workspace: PathBuf,
    /// Capability-based handle to the agent workspace. File tools
    /// (`read_file`, `write_file`, `list_files`, `generate_image`)
    /// operate exclusively through this `Dir`. cap-std uses
    /// `openat2` with `RESOLVE_BENEATH` on Linux (and equivalent
    /// semantics on macOS/Windows) so any path that escapes the
    /// workspace via `..` or an absolute component is refused at
    /// the syscall layer. Replaces the previous `resolve_path` /
    /// `resolve_path_for_write` / `symlink_metadata` leaf check.
    workspace_dir: Arc<cap_std::fs::Dir>,
    tools: HashMap<String, ToolDef>,
    /// HTTP client used by built-in tools that touch the network
    /// (`web_search`, `generate_image`). Wrapped with the egress
    /// allowlist enforcement (#76 Phase 2.2). The agent updates the
    /// enforcement at `attach_skills` time. A future per-host
    /// rate limiter sits between this wrapper and `reqwest::Client`,
    /// not outside it — see [`crate::egress`].
    http: crate::egress::EgressClient,
    config: ToolConfig,
    /// Lazily provisioned on first use of a sandboxed tool. The outer
    /// `OnceCell` is set exactly once; the inner `Option` records whether
    /// provisioning succeeded. A failed first attempt stays failed for the
    /// lifetime of this registry — restart `wirken run` to retry.
    sandbox: tokio::sync::OnceCell<Option<DockerSandbox>>,
    sandbox_config: SandboxConfig,
    /// Path to the zirkel aggregator SQLite database, set when the
    /// agent is configured for the librarian skill. `None` means the
    /// `sqlite_query` tool is unavailable for this agent (it returns
    /// a clear error rather than silently failing). Set via
    /// [`Self::set_zirkel_db_path`].
    zirkel_db_path: Option<PathBuf>,
    /// Host-side resolver for `http_request` credentials, injected by
    /// the CLI where the vault is opened. `None` means naming a
    /// `credential` returns a clear refusal. Interior-mutable, set once,
    /// mirroring [`Self::set_egress_enforcement`].
    credential_resolver: RwLock<Option<Arc<dyn crate::http_tool::CredentialResolver>>>,
    /// Audit sink for the `http_request` row, built from the agent's own
    /// session log at attach time. `None` disables the extra row (the
    /// generic ToolResult row still lands).
    http_audit: RwLock<Option<crate::http_tool::HttpAuditCtx>>,
    /// Cross-channel memory (#64): the entry store plus the origin
    /// labels this agent's writes are stamped with. `None` leaves the
    /// three memory tools out of the LLM's tool list entirely, which
    /// is the posture for any agent the gateway has not wired a store
    /// into.
    memory: RwLock<Option<crate::memory_tool::MemoryContext>>,
    /// Egress policy and attribution for sandboxed `exec`, resolved
    /// from the bound channel's `AgentConfig` entry. `None` is the
    /// deny-everything posture: the container runs with no
    /// networking, which is also what an unconfigured channel gets.
    sandbox_egress: RwLock<Option<crate::sandbox_egress::SandboxEgressContext>>,
    /// Imported-archive store and this turn's attribution. `None`
    /// leaves the imported tools reporting themselves unconfigured.
    imported: RwLock<Option<crate::imported_tool::ImportedContext>>,
}

impl ToolRegistry {
    /// Create a new tool registry with built-in tools. Opens a
    /// capability handle to `workspace`; returns `AgentError` if the
    /// directory does not exist or cannot be opened. The parent
    /// workspace directory is created if it doesn't yet exist.
    pub fn new(workspace: PathBuf, config: ToolConfig) -> Result<Self, AgentError> {
        std::fs::create_dir_all(&workspace).map_err(|e| {
            AgentError::Tool(format!(
                "workspace setup failed for {}: {e}",
                workspace.display()
            ))
        })?;
        let workspace_dir = cap_std::fs::Dir::open_ambient_dir(&workspace, ambient_authority())
            .map_err(|e| {
                AgentError::Tool(format!(
                    "opening workspace dir {} as capability failed: {e}",
                    workspace.display()
                ))
            })?;
        let workspace_dir = Arc::new(workspace_dir);
        let mut tools = HashMap::new();

        tools.insert(
            "exec".into(),
            ToolDef {
                name: "exec".into(),
                description: "Execute a shell command and return its output.".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The shell command to execute"
                        }
                    },
                    "required": ["command"]
                }),
            },
        );

        tools.insert(
            "read_file".into(),
            ToolDef {
                name: "read_file".into(),
                description: "Read the contents of a file.".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the file to read"
                        }
                    },
                    "required": ["path"]
                }),
            },
        );

        tools.insert(
            "write_file".into(),
            ToolDef {
                name: "write_file".into(),
                description: "Write content to a file.".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the file to write"
                        },
                        "content": {
                            "type": "string",
                            "description": "Content to write to the file"
                        }
                    },
                    "required": ["path", "content"]
                }),
            },
        );

        tools.insert(
            "list_files".into(),
            ToolDef {
                name: "list_files".into(),
                description: "List files in a directory.".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Directory path to list (default: workspace root)"
                        }
                    },
                    "required": []
                }),
            },
        );

        tools.insert(
            "web_search".into(),
            ToolDef {
                name: "web_search".into(),
                description: "Search the web and return results with titles, URLs, and snippets."
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The search query"
                        },
                        "num_results": {
                            "type": "integer",
                            "description": "Maximum number of results (default: 5, max: 10)"
                        }
                    },
                    "required": ["query"]
                }),
            },
        );

        tools.insert(
            "memory_write".into(),
            ToolDef {
                name: "memory_write".into(),
                description: "Record a note in this agent's memory for later recall. \
                              The note is labelled with the current channel automatically."
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "What to remember"
                        }
                    },
                    "required": ["content"]
                }),
            },
        );

        tools.insert(
            "memory_read".into(),
            ToolDef {
                name: "memory_read".into(),
                description: "Read notes this agent recorded on the current channel.".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum entries to return (default 20)"
                        }
                    }
                }),
            },
        );

        tools.insert(
            "search_imported_chats".into(),
            ToolDef {
                name: "search_imported_chats".into(),
                description: "Search imported archives of a different assistant account. \
                              Omit 'source' to search every archive, which is a wider \
                              question and asks the operator separately. Requires \
                              operator approval every time."
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Full-text query"
                        },
                        "source": {
                            "type": "string",
                            "description": "Optional import source id to search within"
                        }
                    },
                    "required": ["query"]
                }),
            },
        );

        tools.insert(
            "read_imported_chat".into(),
            ToolDef {
                name: "read_imported_chat".into(),
                description: "Read one conversation out of an imported archive of a \
                              different assistant account. An archive is that account's \
                              whole history, so this requires operator approval every \
                              time, per archive."
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "source": {
                            "type": "string",
                            "description": "Import source id the conversation belongs to"
                        },
                        "conversation": {
                            "type": "string",
                            "description": "Conversation uuid to read"
                        }
                    },
                    "required": ["source", "conversation"]
                }),
            },
        );

        tools.insert(
            "memory_read_channel".into(),
            ToolDef {
                name: "memory_read_channel".into(),
                description: "Read notes this agent recorded on a DIFFERENT channel. \
                              Channels are separate trust zones, so this requires \
                              operator approval every time."
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "channel": {
                            "type": "string",
                            "description": "Channel to read from, e.g. 'signal'"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum entries to return (default 20)"
                        }
                    },
                    "required": ["channel"]
                }),
            },
        );

        tools.insert(
            "sqlite_query".into(),
            ToolDef {
                name: "sqlite_query".into(),
                description: "Run a named query against the zirkel kept-items database. \
                              Returns structured JSON rows verbatim; do not paraphrase \
                              or summarize the results. Available named queries: \
                              kept_recent (params: days), kept_by_keyword (params: term), \
                              kept_by_theme (params: theme), kept_by_source (params: source), \
                              kept_in_run (params: run_id), recent_themes (params: days)."
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "enum": [
                                "kept_recent",
                                "kept_by_keyword",
                                "kept_by_theme",
                                "kept_by_source",
                                "kept_in_run",
                                "recent_themes"
                            ],
                            "description": "Name of the query to run"
                        },
                        "params": {
                            "type": "object",
                            "description": "Parameters per the named query's signature",
                            "additionalProperties": true
                        }
                    },
                    "required": ["query"]
                }),
            },
        );

        tools.insert(
            "generate_image".into(),
            ToolDef {
                name: "generate_image".into(),
                description: "Generate an image from a text prompt. Saves to the workspace. \
                              Requires an OpenAI-compatible provider."
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "prompt": {
                            "type": "string",
                            "description": "Text description of the image to generate"
                        },
                        "filename": {
                            "type": "string",
                            "description": "Filename (without extension). Default: auto-generated."
                        },
                        "size": {
                            "type": "string",
                            "description": "Image size: '1024x1024', '1792x1024', or '1024x1792'. Default: '1024x1024'."
                        }
                    },
                    "required": ["prompt"]
                }),
            },
        );

        tools.insert(
            "http_request".into(),
            ToolDef {
                name: "http_request".into(),
                description: "Make a scoped outbound HTTPS request to an allowlisted host, \
                              optionally attaching a vault credential by name. The credential \
                              value is resolved host-side and never visible to you. GET and HEAD \
                              are always allowed; POST only to an endpoint the skill declared as \
                              a search path. Returns status, headers, and body."
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "method": {
                            "type": "string",
                            "enum": ["GET", "HEAD", "POST"],
                            "description": "HTTP method. POST is limited to declared search paths."
                        },
                        "url": {
                            "type": "string",
                            "description": "Absolute https:// URL. The host must be on the skill's egress allowlist."
                        },
                        "headers": {
                            "type": "object",
                            "description": "Optional request headers. Authorization is refused; use 'credential'."
                        },
                        "body": {
                            "type": "string",
                            "description": "Optional request body, sent for POST only."
                        },
                        "credential": {
                            "type": "string",
                            "description": "Optional name of a vault slot declared in the skill's permissions.credentials.allow. Injected as a Bearer token host-side."
                        },
                        "timeout_ms": {
                            "type": "integer",
                            "description": "Optional request timeout in ms (default 30000, max 60000)."
                        }
                    },
                    "required": ["method", "url"]
                }),
            },
        );

        let sandbox_config = config.sandbox.clone();

        Ok(Self {
            workspace,
            workspace_dir,
            tools,
            http: crate::egress::EgressClient::new(),
            config,
            sandbox: tokio::sync::OnceCell::new(),
            sandbox_config,
            zirkel_db_path: None,
            credential_resolver: RwLock::new(None),
            http_audit: RwLock::new(None),
            sandbox_egress: RwLock::new(None),
            imported: RwLock::new(None),
            memory: RwLock::new(None),
        })
    }

    /// Inject the host-side credential resolver used by `http_request`.
    /// Called by the CLI after opening the vault. Set-once semantics.
    pub fn set_credential_resolver(&self, resolver: Arc<dyn crate::http_tool::CredentialResolver>) {
        if let Ok(mut g) = self.credential_resolver.write() {
            *g = Some(resolver);
        }
    }

    /// Push the audit context for the `http_request` row. Called by the
    /// agent at `attach_skills` time with its own session log/handle/id.
    pub fn set_http_audit(&self, ctx: crate::http_tool::HttpAuditCtx) {
        if let Ok(mut g) = self.http_audit.write() {
            *g = Some(ctx);
        }
    }

    /// Install the cross-channel memory store and this turn's origin
    /// labels. Called per turn, because the labels are per turn.
    /// Leaving it unset means the memory tools are unavailable.
    pub fn set_memory(&self, ctx: crate::memory_tool::MemoryContext) {
        if let Ok(mut g) = self.memory.write() {
            *g = Some(ctx);
        }
    }

    /// Install the sandbox egress policy and the attribution its
    /// denials are recorded under. Called by the agent once the
    /// bound channel is known. Leaving it unset denies all sandbox
    /// egress, so a wiring gap fails closed.
    /// Install the imported-archive context. Until this is called the
    /// imported tools read nothing and say so.
    pub fn set_imported(&self, ctx: crate::imported_tool::ImportedContext) {
        if let Ok(mut g) = self.imported.write() {
            *g = Some(ctx);
        }
    }

    pub fn set_sandbox_egress(&self, ctx: crate::sandbox_egress::SandboxEgressContext) {
        if let Ok(mut g) = self.sandbox_egress.write() {
            *g = Some(ctx);
        }
    }

    /// Configure the path the `sqlite_query` librarian tool opens.
    /// Called by the agent factory when the agent's static config
    /// names a zirkel-bound database. The tool itself enforces
    /// read-only access via `SQLITE_OPEN_READ_ONLY`; the path here
    /// is the only DB the tool will ever touch.
    pub fn set_zirkel_db_path(&mut self, path: PathBuf) {
        self.zirkel_db_path = Some(path);
    }

    /// Whether the sandbox `OnceCell` has been initialized. Test-only helper
    /// used to assert lazy provisioning.
    #[cfg(test)]
    pub(crate) fn sandbox_initialized(&self) -> bool {
        self.sandbox.initialized()
    }

    /// Provision the sandbox on first call, then return the cached result on
    /// every subsequent call. Returns `None` when sandbox mode is `Off` or
    /// when provisioning failed on the first attempt — failures are sticky
    /// for the lifetime of this registry.
    async fn sandbox(&self) -> Option<&DockerSandbox> {
        self.sandbox
            .get_or_init(|| async {
                if self.sandbox_config.mode == SandboxMode::Off {
                    return None;
                }

                // Probe Docker first so the operator sees a specific
                // message ("Docker not reachable") rather than a
                // generic connect error. `detect_runtime` returns None
                // if the Docker daemon is not reachable at the
                // default local socket.
                if crate::sandbox::detect_runtime().await.is_none() {
                    tracing::warn!(
                        "Sandbox mode {:?} is set but Docker is not reachable. \
                         exec is refused (fail-closed) for the lifetime of this \
                         agent. Install Docker and start the daemon, then restart; \
                         or set `\"mode\":\"off\"` in sandbox.json to run exec on \
                         the host.",
                        self.sandbox_config.mode,
                    );
                    return None;
                }

                // gVisor requested but runsc not registered as a
                // Docker runtime. Distinct from Docker-absent so the
                // operator knows which dependency to install.
                if self.sandbox_config.mode == SandboxMode::GVisor
                    && !crate::sandbox::detect_gvisor().await
                {
                    tracing::warn!(
                        "Sandbox mode gvisor is set but the `runsc` runtime is \
                         not registered with Docker. exec is refused (fail-closed) \
                         for the lifetime of this agent. Install gVisor and add \
                         `runsc` to Docker's runtimes, then restart; or set \
                         `\"mode\":\"exec-only\"` in sandbox.json."
                    );
                    return None;
                }

                match DockerSandbox::new(self.sandbox_config.clone()) {
                    Ok(s) => {
                        tracing::info!(
                            "sandbox provisioned: mode={:?} image={}",
                            self.sandbox_config.mode,
                            self.sandbox_config.image,
                        );
                        Some(s)
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Sandbox unavailable: {e}. exec is refused (fail-closed) \
                             for the lifetime of this agent. Fix the sandbox runtime \
                             (Docker / gVisor) and restart, or set `\"mode\":\"off\"` \
                             in sandbox.json to run exec on the host."
                        );
                        None
                    }
                }
            })
            .await
            .as_ref()
    }

    /// Get all tool definitions (for sending to the LLM).
    pub fn definitions(&self) -> Vec<ToolDef> {
        self.tools.values().cloned().collect()
    }

    /// Workspace directory in OS path form. The agent uses this to
    /// expand the `<workspace>` token in skill permission paths.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Update the egress enforcement policy on the registry's HTTP
    /// client. Called by the agent at `attach_skills` time.
    pub fn set_egress_enforcement(&self, enforcement: crate::egress::EgressEnforcement) {
        self.http.set_enforcement(enforcement);
    }

    /// Slice-6 phase-overlay sync. Push a phase deny set onto the
    /// HTTP client so subsequent egress checks consult the overlay
    /// before the base enforcement. Called from
    /// `Agent::sync_phase_overlay_to_egress` after every phase
    /// transition (enter, exit, turn-end auto-clear, wake-replay).
    pub fn set_phase_overlay_egress(&self, deny: crate::egress::PhaseEgressDeny) {
        self.http.set_phase_overlay_deny(deny);
    }

    /// Slice-6 phase-overlay clear. Drop any installed phase deny
    /// from the HTTP client. Pair with [`Self::set_phase_overlay_egress`].
    pub fn clear_phase_overlay_egress(&self) {
        self.http.clear_phase_overlay_deny();
    }

    /// Execute a tool by name with the given JSON arguments.
    pub async fn execute(&self, name: &str, arguments: &str) -> Result<ToolResult, AgentError> {
        let arg_str = if arguments.is_empty() {
            "{}"
        } else {
            arguments
        };
        let args: serde_json::Value = serde_json::from_str(arg_str)
            .map_err(|e| AgentError::Tool(format!("invalid arguments: {e}")))?;

        match name {
            "exec" => self.exec_command(&args).await,
            "read_file" => self.read_file(&args).await,
            "write_file" => self.write_file(&args).await,
            "list_files" => self.list_files(&args).await,
            "web_search" => self.web_search(&args).await,
            "http_request" => self.http_request(&args).await,
            "sqlite_query" => self.sqlite_query(&args).await,
            "memory_write" | "memory_read" | "memory_read_channel" => {
                let ctx = self.memory.read().ok().and_then(|g| g.clone());
                match ctx {
                    Some(ctx) => crate::memory_tool::execute(&ctx, name, &args).await,
                    None => Ok(ToolResult {
                        output: "memory is not configured for this agent".into(),
                        success: false,
                    }),
                }
            }
            "read_imported_chat" | "search_imported_chats" => {
                // No context attached means no import store was
                // installed for this agent. The tool reports that and
                // reads nothing, exactly as the memory tools do when
                // memory is unconfigured. This is what makes the tool
                // unreachable on a path that installs no store.
                match self.imported.read().ok().and_then(|g| g.clone()) {
                    Some(ctx) => crate::imported_tool::execute(&ctx, name, &args).await,
                    None => Ok(ToolResult {
                        output: "imported archives are not configured for this agent".into(),
                        success: false,
                    }),
                }
            }
            "generate_image" => self.generate_image(&args).await,
            _ => Err(AgentError::ToolNotFound(name.to_string())),
        }
    }

    async fn exec_command(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let command = extract_exec_command(args)?;

        // Use sandbox if available (provisioned lazily on first call)
        if let Some(sandbox) = self.sandbox().await {
            let egress = self.sandbox_egress.read().ok().and_then(|g| g.clone());
            return sandbox
                .exec(&command, &self.workspace, egress.as_ref())
                .await;
        }

        // No sandbox. Host execution is only permitted when the
        // operator explicitly set SandboxMode::Off. Any other mode
        // means the requested sandbox runtime failed to provision;
        // silently running on the host would violate the configured
        // trust boundary. Refuse with a clear message so the operator
        // either fixes the runtime or opts in explicitly.
        if self.sandbox_config.mode != SandboxMode::Off {
            return Err(AgentError::Sandbox(format!(
                "sandbox mode is {:?} but the sandbox is unavailable; \
                 refusing to fall back to host execution. Set \
                 `\"mode\":\"off\"` in sandbox.json to opt into host execution, \
                 or fix the sandbox runtime (Docker / gVisor) and restart.",
                self.sandbox_config.mode
            )));
        }

        let resolved = self.sandbox_config.shell.resolve().ok_or_else(|| {
            AgentError::Tool(format!(
                "exec: no shell found for shell mode {:?}; install one of sh / powershell / cmd, or set `\"shell\"` in sandbox.json explicitly",
                self.sandbox_config.shell
            ))
        })?;

        let child = tokio::process::Command::new(&resolved.program)
            .arg(resolved.arg_flag)
            .arg(&command)
            .current_dir(&self.workspace)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| AgentError::Tool(format!("exec failed: {e}")))?;

        let timeout = std::time::Duration::from_secs(300);
        let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(result) => result.map_err(|e| AgentError::Tool(format!("exec failed: {e}")))?,
            Err(_) => {
                return Ok(ToolResult {
                    output: format!("Command timed out after {}s", timeout.as_secs()),
                    success: false,
                });
            }
        };

        // B3: strip ANSI / C1 control sequences from the captured
        // stdout / stderr before either is fed back into the model
        // turn. The exec sink runs untrusted commands (a Tier 3
        // prompt approves each non-allowlisted verb); their output
        // is attacker-influenced text that gets injected verbatim
        // into the next LLM turn. A response carrying a fake `sudo`
        // prompt or window-title escape can otherwise confuse the
        // model about what ran.
        //
        // The audit chain sees the same stripped string because the
        // `SessionEvent::ToolResult` emit in `runtime.rs` clones
        // `output` from the value returned here. The strip drops
        // formatting and control bytes; printable character content
        // is preserved, so an auditor reviewing `audit.db` still
        // sees what files were listed, what stdout reported, etc.,
        // just without the color codes and cursor moves.
        let stdout = crate::ansi::strip_control_sequences(&String::from_utf8_lossy(&output.stdout));
        let stderr = crate::ansi::strip_control_sequences(&String::from_utf8_lossy(&output.stderr));

        let mut result = String::new();
        if !stdout.is_empty() {
            result.push_str(&stdout);
        }
        if !stderr.is_empty() {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str("[stderr] ");
            result.push_str(&stderr);
        }
        if result.is_empty() {
            result.push_str("(no output)");
        }

        if result.len() > 32_000 {
            result.truncate(32_000);
            result.push_str("\n... (truncated)");
        }

        Ok(ToolResult {
            output: result,
            success: output.status.success(),
        })
    }

    async fn read_file(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let path_str = args["path"]
            .as_str()
            .ok_or_else(|| AgentError::Tool("missing 'path' argument".into()))?
            .to_string();

        let dir = self.workspace_dir.clone();
        let path_for_err = path_str.clone();
        let result = tokio::task::spawn_blocking(move || dir.read_to_string(&path_str))
            .await
            .map_err(|e| AgentError::Tool(format!("read_file join: {e}")))?;

        match result {
            Ok(content) => {
                let mut output = content;
                if output.len() > 64_000 {
                    output.truncate(64_000);
                    output.push_str("\n... (truncated)");
                }
                Ok(ToolResult {
                    output,
                    success: true,
                })
            }
            Err(e) => Ok(ToolResult {
                output: format!("Error reading {path_for_err}: {e}"),
                success: false,
            }),
        }
    }

    async fn write_file(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let path_str = args["path"]
            .as_str()
            .ok_or_else(|| AgentError::Tool("missing 'path' argument".into()))?
            .to_string();
        let content = args["content"]
            .as_str()
            .ok_or_else(|| AgentError::Tool("missing 'content' argument".into()))?
            .to_string();

        let dir = self.workspace_dir.clone();
        let path_for_err = path_str.clone();
        let content_len = content.len();
        let result = tokio::task::spawn_blocking(move || {
            if let Some(parent) = std::path::Path::new(&path_str).parent()
                && !parent.as_os_str().is_empty()
            {
                dir.create_dir_all(parent)?;
            }
            dir.write(&path_str, content.as_bytes())
        })
        .await
        .map_err(|e| AgentError::Tool(format!("write_file join: {e}")))?;

        match result {
            Ok(()) => Ok(ToolResult {
                output: format!("Wrote {content_len} bytes to {path_for_err}"),
                success: true,
            }),
            Err(e) => Ok(ToolResult {
                output: format!("Error writing {path_for_err}: {e}"),
                success: false,
            }),
        }
    }

    async fn list_files(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let path_str = args
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(".")
            .to_string();

        let dir = self.workspace_dir.clone();
        let path_for_err = path_str.clone();
        let result = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<String>> {
            let mut names = Vec::new();
            for entry in dir.read_dir(&path_str)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                if is_dir {
                    names.push(format!("{name}/"));
                } else {
                    names.push(name);
                }
            }
            names.sort();
            Ok(names)
        })
        .await
        .map_err(|e| AgentError::Tool(format!("list_files join: {e}")))?;

        match result {
            Ok(names) => Ok(ToolResult {
                output: names.join("\n"),
                success: true,
            }),
            Err(e) => Ok(ToolResult {
                output: format!("Error listing {path_for_err}: {e}"),
                success: false,
            }),
        }
    }

    async fn web_search(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let query = args["query"]
            .as_str()
            .ok_or_else(|| AgentError::Tool("missing 'query' argument".into()))?;

        let max_results = args
            .get("num_results")
            .and_then(|v| v.as_u64())
            .unwrap_or(5)
            .min(10) as usize;

        let resp = self
            .http
            .post("https://html.duckduckgo.com/html/")
            .await
            .map_err(map_http_access_denied)?
            .header("User-Agent", "Wirken/1.0")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("q={}", urlencoding_encode(query)))
            .send()
            .await
            .map_err(|e| AgentError::Tool(format!("web search failed: {e}")))?;

        if !resp.status().is_success() {
            return Ok(ToolResult {
                output: format!("Search failed: HTTP {}", resp.status()),
                success: false,
            });
        }

        let body = read_capped(resp).await?;
        let html = String::from_utf8(body)
            .map_err(|e| AgentError::Tool(format!("response not utf-8: {e}")))?;

        let results = parse_ddg_html(&html, max_results);

        if results.is_empty() {
            return Ok(ToolResult {
                output: format!("No results found for '{query}'."),
                success: true,
            });
        }

        let mut output = String::new();
        for (i, r) in results.iter().enumerate() {
            output.push_str(&format!("{}. {}\n   {}\n", i + 1, r.title, r.url));
            if !r.snippet.is_empty() {
                output.push_str(&format!("   {}\n", r.snippet));
            }
            output.push('\n');
        }

        Ok(ToolResult {
            output,
            success: true,
        })
    }

    /// The `http_request` built-in tool. Thin wrapper: reads the
    /// injected resolver + audit context and delegates to
    /// [`crate::http_tool::execute`], which owns URL validation,
    /// credential injection, redaction, response cap, and the audit row.
    /// Credential/method/POST-path scoping is gated upstream in
    /// `runtime.rs` before this runs.
    async fn http_request(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let resolver = self.credential_resolver.read().ok().and_then(|g| g.clone());
        let audit = self.http_audit.read().ok().and_then(|g| g.clone());
        crate::http_tool::execute(&self.http, resolver.as_ref(), audit.as_ref(), args).await
    }

    /// Run a named query against the zirkel kept-items database.
    ///
    /// Trust posture (the load-bearing decision for the C-Librarian
    /// slice): the LLM does not write SQL. It picks one of a small
    /// set of named queries and fills typed parameters; the tool
    /// runs the parameterized SQL the librarian skill committed to.
    /// Free-form SQL would let the LLM hallucinate column names,
    /// construct unbounded scans, or drift from the audit log's
    /// expected query shape — exactly the trust posture this slice
    /// rejects.
    ///
    /// The DB connection is opened with `SQLITE_OPEN_READ_ONLY`, so
    /// a write attempt is refused at the connection layer (not by
    /// string-pattern checks on the SQL). Caller must have set
    /// `zirkel_db_path` via [`Self::set_zirkel_db_path`]; otherwise
    /// the tool returns a clear error.
    ///
    /// Output is structured JSON. The librarian skill body
    /// instructs the LLM to render rows verbatim — title, source,
    /// date, url — without paraphrase. That's how retrieval-only
    /// becomes structural rather than aspirational.
    async fn sqlite_query(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let Some(db_path) = self.zirkel_db_path.clone() else {
            return Ok(ToolResult {
                output: "sqlite_query is not configured for this agent (no zirkel database path bound). \
                         Bind a librarian skill on an agent whose static config sets zirkel_db_path."
                    .into(),
                success: false,
            });
        };

        let query_name = args
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AgentError::Tool("missing required 'query' parameter".into()))?
            .to_string();
        let params = args
            .get("params")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        // Run blocking SQLite ops on a tokio blocking task so the
        // async runtime isn't held up by file I/O.
        let result =
            tokio::task::spawn_blocking(move || run_named_query(&db_path, &query_name, &params))
                .await
                .map_err(|e| AgentError::Tool(format!("sqlite_query task panic: {e}")))?;

        match result {
            Ok(rows_json) => Ok(ToolResult {
                output: rows_json,
                success: true,
            }),
            Err(e) => Ok(ToolResult {
                output: format!("sqlite_query error: {e}"),
                success: false,
            }),
        }
    }

    async fn generate_image(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let provider = self.config.provider.as_deref().unwrap_or("unknown");
        if !matches!(provider, "openai" | "custom") {
            return Ok(ToolResult {
                output: format!(
                    "Image generation not supported for provider '{provider}'. \
                     Use an OpenAI-compatible provider, or use the exec tool with curl."
                ),
                success: false,
            });
        }

        let api_key = match self.config.api_key.as_deref() {
            Some(k) => k,
            None => {
                return Ok(ToolResult {
                    output: "Image generation requires an API key.".into(),
                    success: false,
                });
            }
        };

        let base_url = self
            .config
            .base_url
            .as_deref()
            .unwrap_or("https://api.openai.com/v1");

        let prompt = args["prompt"]
            .as_str()
            .ok_or_else(|| AgentError::Tool("missing 'prompt' argument".into()))?;

        let size = args
            .get("size")
            .and_then(|v| v.as_str())
            .unwrap_or("1024x1024");

        let filename = args
            .get("filename")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("img_{}", uuid::Uuid::new_v4()));

        let url = format!("{base_url}/images/generations");
        let body = serde_json::json!({
            "model": "dall-e-3",
            "prompt": prompt,
            "n": 1,
            "size": size,
            "response_format": "b64_json",
        });

        let resp = self
            .http
            .post(&url)
            .await
            .map_err(map_http_access_denied)?
            .header("Authorization", format!("Bearer {api_key}"))
            .json(&body)
            .send()
            .await
            .map_err(|e| AgentError::Tool(format!("image generation request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Ok(ToolResult {
                output: format!("Image generation failed: HTTP {status}: {body}"),
                success: false,
            });
        }

        let body = read_capped(resp).await?;
        let resp_json: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| AgentError::Tool(format!("parse image response: {e}")))?;

        let b64_data = resp_json
            .get("data")
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.first())
            .and_then(|item| item.get("b64_json"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AgentError::Tool("no image data in response".into()))?;

        let image_bytes = base64::engine::general_purpose::STANDARD
            .decode(b64_data)
            .map_err(|e| AgentError::Tool(format!("decode image: {e}")))?;

        // Save to workspace/generated_images/. Open that directory
        // as a sub-capability so the filename cannot escape it via
        // `../`, an absolute path, or a symlink staged by `exec`.
        // cap-std's `Dir::create_dir_all` + `open_dir` + `write`
        // path is enforced by openat2(RESOLVE_BENEATH) on Linux and
        // equivalent semantics on macOS/Windows.
        let dir = self.workspace_dir.clone();
        let filename_for_err = filename.clone();
        let bytes_len = image_bytes.len();
        let write_result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            dir.create_dir_all("generated_images")?;
            let images_dir = dir.open_dir("generated_images")?;
            let leaf = format!("{filename}.png");
            images_dir.write(&leaf, &image_bytes)
        })
        .await
        .map_err(|e| AgentError::Tool(format!("generate_image join: {e}")))?;
        write_result
            .map_err(|e| AgentError::Tool(format!("write image {filename_for_err}: {e}")))?;

        let file_path = self
            .workspace
            .join("generated_images")
            .join(format!("{filename_for_err}.png"));

        Ok(ToolResult {
            output: format!("Image saved to {} ({bytes_len} bytes)", file_path.display()),
            success: true,
        })
    }
}

struct SearchResult {
    title: String,
    url: String,
    snippet: String,
}

/// Map an [`crate::egress::HttpAccessDenied`] from the wrapped HTTP
/// client into an [`AgentError`]. The agent's tool dispatcher (#76
/// Run one of the librarian's named queries against the zirkel
/// database. Read-only by construction (`SQLITE_OPEN_READ_ONLY`);
/// caller has already verified that the path is configured.
///
/// Each branch hardcodes the SQL — the LLM cannot inject column
/// names or join shape. Parameters are bound positionally so a
/// hostile param value (which a typo'd name could synthesize)
/// cannot escape into the query body.
///
/// Result is JSON-serialized as `{"rows": [...], "count": N}` for
/// item-shaped queries, or `{"themes": [...], "count": N}` for the
/// `recent_themes` query. The librarian skill body tells the LLM
/// which key to read and to relay rows verbatim — title, source,
/// date, url — without paraphrase.
/// The complete set of query names `sqlite_query` accepts. Closed by
/// construction: there is no path that takes SQL.
///
/// Load-bearing for the read-sensitivity classifier, which marks
/// `sqlite_query` non-restricting because these six can only address
/// the zirkel corpus schema and the handle is read-only. Widening this
/// set, or adding a path that accepts SQL, invalidates that
/// classification. `tool_to_read_sensitivity` points back here, and
/// `sqlite_query_accepts_exactly_the_corpus_query_names` fails if the
/// set changes.
pub const KNOWN_ZIRKEL_QUERIES: &[&str] = &[
    "kept_recent",
    "kept_by_keyword",
    "kept_by_theme",
    "kept_by_source",
    "kept_in_run",
    "recent_themes",
];

fn run_named_query(
    db_path: &Path,
    query_name: &str,
    params: &serde_json::Value,
) -> Result<String, String> {
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("open zirkel db: {e}"))?;

    match query_name {
        "kept_recent" => kept_recent(&conn, params),
        "kept_by_keyword" => kept_by_keyword(&conn, params),
        "kept_by_theme" => kept_by_theme(&conn, params),
        "kept_by_source" => kept_by_source(&conn, params),
        "kept_in_run" => kept_in_run(&conn, params),
        "recent_themes" => recent_themes(&conn, params),
        other => Err(format!(
            "unknown named query '{other}'. Known: {}",
            KNOWN_ZIRKEL_QUERIES.join(", ")
        )),
    }
}

/// Cap on rows returned per query. Bounds the response payload so
/// a query that would otherwise return thousands of rows stays
/// manageable for the LLM's context. The librarian skill explains
/// this to the operator: "if you want everything, narrow the
/// query."
const KEPT_ROW_LIMIT: i64 = 100;
const THEMES_ROW_LIMIT: i64 = 50;

fn kept_recent(conn: &rusqlite::Connection, params: &serde_json::Value) -> Result<String, String> {
    let days = extract_days(params, 7);
    let mut stmt = conn
        .prepare(
            "SELECT c.title, c.source_name, c.url, COALESCE(c.published_at, '') AS pub_date, \
                    COALESCE(c.llm_why_surfaced, '') AS why, \
                    d.resolved_at AS kept_at, COALESCE(t.name, '') AS theme \
             FROM digest_items di \
             JOIN candidates c ON c.id = di.candidate_id \
             JOIN digests d ON d.id = di.digest_id \
             LEFT JOIN themes t ON t.id = c.cluster_id \
             WHERE di.decision = 'kept' \
               AND d.resolved_at IS NOT NULL \
               AND d.resolved_at >= datetime('now', ?1 || ' days') \
             ORDER BY d.resolved_at DESC, c.llm_relevance_score DESC \
             LIMIT ?2",
        )
        .map_err(|e| format!("prepare kept_recent: {e}"))?;
    let days_arg = format!("-{days}");
    let rows = collect_kept_rows(&mut stmt, rusqlite::params![days_arg, KEPT_ROW_LIMIT])?;
    Ok(serialize_rows("rows", rows))
}

fn kept_by_keyword(
    conn: &rusqlite::Connection,
    params: &serde_json::Value,
) -> Result<String, String> {
    let term = extract_required_string(params, "term")?;
    let pattern = format!("%{}%", term.to_lowercase());
    let mut stmt = conn
        .prepare(
            "SELECT c.title, c.source_name, c.url, COALESCE(c.published_at, '') AS pub_date, \
                    COALESCE(c.llm_why_surfaced, '') AS why, \
                    d.resolved_at AS kept_at, COALESCE(t.name, '') AS theme \
             FROM digest_items di \
             JOIN candidates c ON c.id = di.candidate_id \
             JOIN digests d ON d.id = di.digest_id \
             LEFT JOIN themes t ON t.id = c.cluster_id \
             WHERE di.decision = 'kept' \
               AND d.resolved_at IS NOT NULL \
               AND (LOWER(c.title) LIKE ?1 OR LOWER(c.body) LIKE ?1) \
             ORDER BY d.resolved_at DESC \
             LIMIT ?2",
        )
        .map_err(|e| format!("prepare kept_by_keyword: {e}"))?;
    let rows = collect_kept_rows(&mut stmt, rusqlite::params![pattern, KEPT_ROW_LIMIT])?;
    Ok(serialize_rows("rows", rows))
}

fn kept_by_theme(
    conn: &rusqlite::Connection,
    params: &serde_json::Value,
) -> Result<String, String> {
    let theme = extract_required_string(params, "theme")?;
    let mut stmt = conn
        .prepare(
            "SELECT c.title, c.source_name, c.url, COALESCE(c.published_at, '') AS pub_date, \
                    COALESCE(c.llm_why_surfaced, '') AS why, \
                    d.resolved_at AS kept_at, t.name AS theme \
             FROM digest_items di \
             JOIN candidates c ON c.id = di.candidate_id \
             JOIN digests d ON d.id = di.digest_id \
             JOIN themes t ON t.id = c.cluster_id \
             WHERE di.decision = 'kept' \
               AND d.resolved_at IS NOT NULL \
               AND LOWER(t.name) = LOWER(?1) \
             ORDER BY d.resolved_at DESC \
             LIMIT ?2",
        )
        .map_err(|e| format!("prepare kept_by_theme: {e}"))?;
    let rows = collect_kept_rows(&mut stmt, rusqlite::params![theme, KEPT_ROW_LIMIT])?;
    Ok(serialize_rows("rows", rows))
}

fn kept_by_source(
    conn: &rusqlite::Connection,
    params: &serde_json::Value,
) -> Result<String, String> {
    let source = extract_required_string(params, "source")?;
    let mut stmt = conn
        .prepare(
            "SELECT c.title, c.source_name, c.url, COALESCE(c.published_at, '') AS pub_date, \
                    COALESCE(c.llm_why_surfaced, '') AS why, \
                    d.resolved_at AS kept_at, COALESCE(t.name, '') AS theme \
             FROM digest_items di \
             JOIN candidates c ON c.id = di.candidate_id \
             JOIN digests d ON d.id = di.digest_id \
             LEFT JOIN themes t ON t.id = c.cluster_id \
             WHERE di.decision = 'kept' \
               AND d.resolved_at IS NOT NULL \
               AND c.source_name = ?1 \
             ORDER BY d.resolved_at DESC \
             LIMIT ?2",
        )
        .map_err(|e| format!("prepare kept_by_source: {e}"))?;
    let rows = collect_kept_rows(&mut stmt, rusqlite::params![source, KEPT_ROW_LIMIT])?;
    Ok(serialize_rows("rows", rows))
}

fn kept_in_run(conn: &rusqlite::Connection, params: &serde_json::Value) -> Result<String, String> {
    let run_id = extract_required_string(params, "run_id")?;
    let mut stmt = conn
        .prepare(
            "SELECT c.title, c.source_name, c.url, COALESCE(c.published_at, '') AS pub_date, \
                    COALESCE(c.llm_why_surfaced, '') AS why, \
                    d.resolved_at AS kept_at, COALESCE(t.name, '') AS theme \
             FROM digest_items di \
             JOIN candidates c ON c.id = di.candidate_id \
             JOIN digests d ON d.id = di.digest_id \
             LEFT JOIN themes t ON t.id = c.cluster_id \
             WHERE di.decision = 'kept' \
               AND c.run_id = ?1 \
             ORDER BY c.llm_relevance_score DESC, c.id ASC \
             LIMIT ?2",
        )
        .map_err(|e| format!("prepare kept_in_run: {e}"))?;
    let rows = collect_kept_rows(&mut stmt, rusqlite::params![run_id, KEPT_ROW_LIMIT])?;
    Ok(serialize_rows("rows", rows))
}

fn recent_themes(
    conn: &rusqlite::Connection,
    params: &serde_json::Value,
) -> Result<String, String> {
    let days = extract_days(params, 7);
    let mut stmt = conn
        .prepare(
            "SELECT name, member_count, run_id, created_at \
             FROM themes \
             WHERE created_at >= datetime('now', ?1 || ' days') \
             ORDER BY created_at DESC, member_count DESC \
             LIMIT ?2",
        )
        .map_err(|e| format!("prepare recent_themes: {e}"))?;
    let days_arg = format!("-{days}");
    let mut rows: Vec<serde_json::Value> = Vec::new();
    let mapped = stmt
        .query_map(rusqlite::params![days_arg, THEMES_ROW_LIMIT], |row| {
            Ok(serde_json::json!({
                "name": row.get::<_, String>(0)?,
                "member_count": row.get::<_, i64>(1)?,
                "run_id": row.get::<_, String>(2)?,
                "created_at": row.get::<_, String>(3)?,
            }))
        })
        .map_err(|e| format!("query recent_themes: {e}"))?;
    for r in mapped {
        rows.push(r.map_err(|e| format!("read theme row: {e}"))?);
    }
    Ok(serialize_rows("themes", rows))
}

/// Build the JSON envelope the LLM sees. Always includes `count`
/// so the librarian skill body can say "you have 5 items kept this
/// week" without relying on the LLM to count an array.
fn serialize_rows(key: &str, rows: Vec<serde_json::Value>) -> String {
    let count = rows.len();
    let envelope = serde_json::json!({
        key: rows,
        "count": count,
    });
    serde_json::to_string(&envelope).unwrap_or_else(|_| "{}".to_string())
}

fn collect_kept_rows<P: rusqlite::Params>(
    stmt: &mut rusqlite::Statement<'_>,
    params: P,
) -> Result<Vec<serde_json::Value>, String> {
    let mapped = stmt
        .query_map(params, |row| {
            Ok(serde_json::json!({
                "title": row.get::<_, String>(0)?,
                "source": row.get::<_, String>(1)?,
                "url": row.get::<_, String>(2)?,
                "date": row.get::<_, String>(3)?,
                "why_surfaced": row.get::<_, String>(4)?,
                "kept_at": row.get::<_, String>(5)?,
                "theme": row.get::<_, String>(6)?,
            }))
        })
        .map_err(|e| format!("query: {e}"))?;
    let mut out = Vec::new();
    for r in mapped {
        out.push(r.map_err(|e| format!("read row: {e}"))?);
    }
    Ok(out)
}

fn extract_days(params: &serde_json::Value, default_days: i64) -> i64 {
    params
        .get("days")
        .and_then(|v| v.as_i64())
        .filter(|n| *n > 0 && *n <= 365)
        .unwrap_or(default_days)
}

fn extract_required_string(params: &serde_json::Value, name: &str) -> Result<String, String> {
    let s = params
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing required parameter '{name}' (expected string)"))?
        .trim()
        .to_string();
    if s.is_empty() {
        return Err(format!("parameter '{name}' must not be empty"));
    }
    Ok(s)
}

/// Phase 2.2) intercepts both variants and emits the appropriate
/// `SkillPermissionDenied` audit event before surfacing a non-success
/// `ToolResult`. The agent-tool case (web_search / generate_image)
/// runs with an unrestricted rate limit by default so the
/// `RateLimit` arm only fires when an operator has deliberately
/// installed a stricter config.
fn map_http_access_denied(e: crate::egress::HttpAccessDenied) -> AgentError {
    match e {
        crate::egress::HttpAccessDenied::Egress(d) => AgentError::EgressDenied(d),
        crate::egress::HttpAccessDenied::RateLimit(d) => AgentError::Tool(format!("{d}")),
    }
}

/// Parse DuckDuckGo HTML Lite search results.
fn parse_ddg_html(html: &str, max: usize) -> Vec<SearchResult> {
    let mut results = Vec::new();

    // DuckDuckGo HTML Lite results are in <a class="result__a"> for title/URL
    // and <a class="result__snippet"> for snippets.
    for chunk in html.split("result__body") {
        if results.len() >= max {
            break;
        }

        let title_url = extract_between(chunk, "result__a\" href=\"", "\"");
        let title_text = extract_between(chunk, "result__a\"", "</a>");
        let snippet = extract_between(chunk, "result__snippet", "</a>");

        if let (Some(url), Some(raw_title)) = (title_url, title_text) {
            // Clean the title text (remove the tag close >)
            let title = raw_title
                .split_once('>')
                .map(|(_, t)| t)
                .unwrap_or(raw_title);
            let title = strip_html_tags(title).trim().to_string();

            let snippet = snippet
                .map(|s| {
                    let s = s.split_once('>').map(|(_, t)| t).unwrap_or(s);
                    strip_html_tags(s).trim().to_string()
                })
                .unwrap_or_default();

            if !title.is_empty() && !url.is_empty() {
                // DuckDuckGo wraps URLs in a redirect — extract the actual URL
                let actual_url = if let Some(rest) = url.strip_prefix("//duckduckgo.com/l/?uddg=") {
                    urlencoding_decode(rest.split('&').next().unwrap_or(rest))
                } else {
                    url.to_string()
                };

                results.push(SearchResult {
                    title,
                    url: actual_url,
                    snippet,
                });
            }
        }
    }

    results
}

fn extract_between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let start_idx = text.find(start)? + start.len();
    let remaining = &text[start_idx..];
    let end_idx = remaining.find(end)?;
    Some(&remaining[..end_idx])
}

fn strip_html_tags(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(c),
            _ => {}
        }
    }
    // Decode common HTML entities
    result
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&nbsp;", " ")
}

fn urlencoding_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                String::from(b as char)
            }
            b' ' => "+".to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn urlencoding_decode(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
        {
            result.push(byte);
            i += 3;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

/// Extract the shell command string from an `exec` tool call's args.
/// Accepts either `command: "curl foo"` (string) or
/// `command: ["curl", "foo"]` (array of strings, space-joined for
/// both tier classification and sandbox execution).
///
/// Returns an error for missing, null, object, or array-with-
/// non-string-elements forms. This matters for tier enforcement:
/// the pre-fix code swallowed non-string `command` via `as_str()`,
/// yielding an empty pattern that fell through to Tier 2 even for
/// high-risk prefixes like `curl` or `ssh`.
pub fn extract_exec_command(args: &serde_json::Value) -> Result<String, AgentError> {
    match args.get("command") {
        Some(serde_json::Value::String(s)) => Ok(s.clone()),
        Some(serde_json::Value::Array(items)) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(s) => parts.push(s.to_string()),
                    None => {
                        return Err(AgentError::Tool(
                            "exec.command array must contain only strings".into(),
                        ));
                    }
                }
            }
            Ok(parts.join(" "))
        }
        Some(_) => Err(AgentError::Tool(
            "exec.command must be a string or array of strings".into(),
        )),
        None => Err(AgentError::Tool("missing 'command' argument".into())),
    }
}

/// Shell metacharacters that turn the command into a chained or
/// stdin-fed expression. Any of these in the raw command string lets
/// an allowlisted lead token (`echo`, `cat`, `pwd`, ...) hand control
/// to a non-allowlisted verb downstream of the tier classifier — for
/// example `echo "rm -rf /" | bash`, `pwd && curl evil.com`, or a
/// multi-line command body fed to a shell. The presence of any of
/// these forces the action to a sentinel pattern that cannot match
/// [`wirken_gateway::permissions::TIER2_ALLOWLIST`], so the tier
/// resolver lands on Tier 3 ("always prompt").
///
/// `&&` / `||` / `>>` / `<<` are covered by their single-char prefixes
/// (`&`, `|`, `>`, `<`).
///
/// Edge case not handled here: a bare shell binary as argv (`bash`
/// alone, no metacharacters, no script argument) executes whatever
/// stdin is piped to it. argv-only inspection cannot see the stdin
/// source. In practice the producer would itself contain a
/// metacharacter and be caught by this list; pure argv-only `bash`
/// with externally-attached stdin is not a shape the agent can
/// produce through `exec`.
const SHELL_METACHARS: &[&str] = &["|", ";", "&", "$(", "`", ">", "<", "\n"];

/// Sentinel pattern returned for commands containing shell
/// metacharacters. Not a real verb, not on the allowlist, so
/// [`Action::tier`] resolves it to Tier 3 and `approve_by_key`
/// refuses to store an approval for it. The leading `:` keeps it
/// from colliding with any plausible binary name.
const PIPELINE_SENTINEL: &str = ":pipeline:";

/// Map a built-in tool invocation to a permission Action for tier checking.
/// Returns None for tools that don't map to a permission-checkable action
/// (e.g., unknown MCP or Wasm tools are not subject to permission checks).
/// How confidential the data a tool reads is, for the purpose of
/// deciding whether a session that has read it may still egress
/// freely (#214, a slice of #47).
///
/// This is a **confidentiality** axis: it marks what the session has
/// seen that should not leave. It is deliberately not a trust axis.
/// "Did this session read something untrustworthy" is a different
/// question, answered by the injection detector, and a trust
/// dimension would be a second field here rather than a reuse of
/// this one.
///
/// The variants are **unordered**. Declaration order carries no rank,
/// there is no lattice, and there is no max-level reduction: session
/// state is a set of labels, and the only question asked of it is
/// which members return `true` from [`Self::restricts_egress`].
/// `Ord` is deliberately not derived so no caller can read a
/// precedence that was never designed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadSensitivity {
    /// Content the gateway itself fetched from the public network.
    /// Not a confidentiality concern on the way out.
    AggregatedExternal,
    /// This channel's own memory entries.
    ChannelMemory,
    /// Another channel's memory entries: a different trust zone.
    CrossChannelMemory,
    /// Content out of an imported archive: another account's whole
    /// conversation history, message text, attachment text and
    /// project-document text alike. All three are conversation
    /// content, so all three carry this label rather than the file
    /// ones carrying something lesser.
    ImportedArchive,
    /// The operator's workspace files.
    Workspace,
}

impl ReadSensitivity {
    /// Whether observing this source restricts the session's egress.
    /// Only `AggregatedExternal` does not, because it is already
    /// public by construction.
    pub fn restricts_egress(self) -> bool {
        !matches!(self, Self::AggregatedExternal)
    }

    /// Stable label for audit rows.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AggregatedExternal => "aggregated_external",
            Self::ChannelMemory => "channel_memory",
            Self::CrossChannelMemory => "cross_channel_memory",
            Self::ImportedArchive => "imported_archive",
            Self::Workspace => "workspace",
        }
    }
}

/// What a tool reads, if it reads anything.
///
/// Registered in the same place tools are classified for tiering, so
/// one edit site decides both. A tool absent from this match reads
/// nothing as far as the classifier knows; the dispatch site treats an
/// *unclassifiable* tool (one `tool_to_action` also rejects) as
/// `Workspace`, the most restricting value, so an unregistered name
/// cannot produce an untainted read.
///
/// `sqlite_query` is `AggregatedExternal` because it can only reach
/// the zirkel corpus: see [`KNOWN_ZIRKEL_QUERIES`], whose closed set
/// this classification depends on.
pub fn tool_to_read_sensitivity(tool_name: &str) -> Option<ReadSensitivity> {
    match tool_name {
        "read_file" | "list_files" => Some(ReadSensitivity::Workspace),
        "sqlite_query" => Some(ReadSensitivity::AggregatedExternal),
        "memory_read" => Some(ReadSensitivity::ChannelMemory),
        "memory_read_channel" => Some(ReadSensitivity::CrossChannelMemory),
        "read_imported_chat" | "search_imported_chats" => Some(ReadSensitivity::ImportedArchive),
        // Everything else is not a read of stored data. `web_search`
        // and `http_request` fetch from the public network, which is
        // the same confidentiality position as AggregatedExternal and
        // needs no marking; `exec` output is not classified here
        // because this slice is observation-level and does not inspect
        // tool output.
        _ => None,
    }
}

pub fn tool_to_action(tool_name: &str, args: &serde_json::Value) -> Option<Action> {
    match tool_name {
        "exec" => {
            // Normalize via the same extractor the dispatcher uses so
            // tier classification never disagrees with execution about
            // the command shape. A malformed or empty payload yields an
            // empty pattern, which is not on the allowlist and resolves
            // to Tier 3.
            let cmd = extract_exec_command(args).unwrap_or_default();
            if SHELL_METACHARS.iter().any(|m| cmd.contains(m)) {
                return Some(Action::ShellExec {
                    pattern: PIPELINE_SENTINEL.to_string(),
                });
            }
            // Classify on the resolved target, not the lexical
            // basename. A path-bearing first token (`/workspace/ls`,
            // `./ls`) is canonicalized so a symlink whose basename is
            // an allowlisted verb but whose target is not lands on
            // Tier 3. A bare token (`ls`, no separator) keeps its
            // lexical basename: its real resolution is the runtime PATH
            // lookup at exec time, which this classifier cannot
            // reproduce across the sandbox boundary, and the allowlist
            // is written for bare verbs. Resolution failure (broken
            // symlink, missing path) fails closed to the Tier 3
            // sentinel.
            let first = cmd.split_whitespace().next().unwrap_or("");
            Some(Action::ShellExec {
                pattern: resolve_exec_pattern(first),
            })
        }
        "read_file" | "list_files" => Some(Action::WorkspaceFileAccess),
        "write_file" => Some(Action::WorkspaceFileAccess),
        "web_search" => Some(Action::WebSearch),
        // Tier 1: the interactive approval flow adds no prompt. The
        // authorization is the skill's permissions block (tools.allow,
        // credentials.allow, http.post_paths, egress.domains), enforced
        // as hard refusals at the gate and by EgressClient, not a prompt.
        "http_request" => Some(Action::HttpRequest),
        // Read-only query against the bound zirkel database. Tier 1,
        // the same read tier as workspace files: the tool opens the DB
        // read-only and is unavailable when no DB path is bound.
        "sqlite_query" => Some(Action::WorkspaceFileAccess),
        // Cross-channel memory (#64). Writing, and reading this
        // channel's own entries, stay at the workspace read/write
        // tier: neither crosses a trust zone.
        "memory_write" | "memory_read" => Some(Action::WorkspaceFileAccess),
        // Reading another channel's entries is a trust-zone crossing
        // and is Tier 3, keyed by the channel being read *from* so
        // approving one channel's history approves no other. A
        // missing or empty `channel` argument yields an empty key,
        // which is not a channel any entry carries, so it denies
        // rather than widening.
        "memory_read_channel" => Some(Action::CrossChannelMemoryRead {
            from_channel: args
                .get("channel")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        // Reading an imported archive. The tier and the approval key
        // are decided here, at the same site that classifies every
        // other tool, so the gate runs in the runtime before dispatch
        // reaches the tool body. A missing or empty `source` yields a
        // key no source carries, so it denies rather than widening to
        // every archive.
        "read_imported_chat" => Some(Action::ImportedChatRead {
            source_id: args
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        // Searching imported archives. The scope is optional, and the
        // two forms take different approval keys, so an approval to
        // search one archive is never an approval to sweep them all.
        "search_imported_chats" => Some(Action::ImportedChatSearch {
            source_id: args
                .get("source")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string()),
        }),
        "generate_image" => Some(Action::NetworkRequest {
            domain: "api.openai.com".to_string(),
        }),
        // MCP tools arrive as `mcp_{server}_{tool}` (the proxy applies
        // the prefix; see crates/mcp-proxy/src/mcp_client.rs). Classify
        // on the whole prefixed name so the tier gate and dispatch
        // (runtime.rs, `name.starts_with("mcp_")`) agree. Always Tier 3.
        name if name.starts_with("mcp_") => Some(Action::McpToolCall {
            tool: name.to_string(),
        }),
        // Everything else returns None. Two cases reach the runtime
        // tier gate from here: a known Wasm skill (`wasm_{skill}`),
        // which the Wasm sandbox and the per-skill profile gate govern
        // and which the gate exempts from the residual deny; and a
        // genuinely unregistered name, which the gate default-denies.
        //
        // No built-in agent tool produces DestructiveFileOp,
        // CredentialAccess, CronCreate, ExternalFileAccess,
        // CrossConversationMessage, or ChannelConverse: destructive and
        // external-file operations are not distinct agent tools
        // (workspace writes are Tier 1, cap-std confined), credential
        // access is mediated by the vault / MCP proxy rather than an
        // agent tool, cron is created through the CLI, and the agent's
        // channel reply is the normal response path, not a gated tool.
        // Those variants stay defined for the tier model and approval
        // keys rather than as silent unreachable arms here.
        _ => None,
    }
}

/// Resolve an `exec` first token to the basename used for tier
/// classification. A token containing a path separator is canonicalized
/// to its real target (following symlinks) so the tier is decided by
/// what actually runs, not by a lexically allowlisted basename pointing
/// elsewhere. Resolution failure fails closed by returning the Tier 3
/// pipeline sentinel. A bare token (no separator) is returned unchanged
/// for lexical basename matching; resolution is host-side, so the
/// path-bearing case is the one that matters for host execution.
fn resolve_exec_pattern(first: &str) -> String {
    if first.is_empty() {
        return String::new();
    }
    let is_path = first.contains('/') || first.contains(std::path::MAIN_SEPARATOR);
    if !is_path {
        return first.to_string();
    }
    match std::fs::canonicalize(first) {
        Ok(real) => real
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::to_string)
            .unwrap_or_else(|| PIPELINE_SENTINEL.to_string()),
        Err(_) => PIPELINE_SENTINEL.to_string(),
    }
}

/// Whether a built-in tool produces deterministic output for
/// deterministic input. Used by [`crate::runtime::Agent::verify`]
/// (item 10) to decide which tools may be re-executed during a
/// reproducible-replay verification.
///
/// Slice 1 hardcodes the list rather than introducing a marker
/// trait. The set is conservative: only tools whose output is a
/// pure function of their arguments and the workspace state belong
/// here.
///
/// - `read_file` — bytes of a file in the workspace
/// - `list_files` — sorted directory listing
/// - `web_search` — `false` because the search index is not pinned
///   in time; results drift across runs even with stable inputs
/// - `exec` — `false` (side-effecting)
/// - `write_file`, `generate_image` — `false` (side-effecting)
pub fn is_deterministic_tool(name: &str) -> bool {
    matches!(name, "read_file" | "list_files")
}

#[cfg(test)]
mod read_capped_tests {
    use super::{MAX_TOOL_BODY_BYTES, read_capped};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Serves an HTTP/1.1 chunked response that streams past
    /// MAX_TOOL_BODY_BYTES so the cap engages.
    async fn one_shot_oversized_chunked() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n";
                let _ = sock.write_all(header.as_bytes()).await;
                let chunk_data = vec![b'a'; 1024 * 1024];
                let chunk_size_hex = format!("{:x}\r\n", chunk_data.len());
                let needed_chunks = (MAX_TOOL_BODY_BYTES / chunk_data.len() as u64) + 2;
                for _ in 0..needed_chunks {
                    if sock.write_all(chunk_size_hex.as_bytes()).await.is_err() {
                        return;
                    }
                    if sock.write_all(&chunk_data).await.is_err() {
                        return;
                    }
                    if sock.write_all(b"\r\n").await.is_err() {
                        return;
                    }
                }
                let _ = sock.write_all(b"0\r\n\r\n").await;
                let _ = sock.shutdown().await;
            }
        });
        url
    }

    #[tokio::test]
    async fn read_capped_rejects_body_over_limit() {
        let url = one_shot_oversized_chunked().await;
        let resp = reqwest::Client::new().get(&url).send().await.unwrap();
        let err = read_capped(resp).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("exceeded") && msg.contains(&MAX_TOOL_BODY_BYTES.to_string()),
            "expected cap error, got {msg}"
        );
    }

    #[tokio::test]
    async fn read_capped_returns_short_body_intact() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = "hello world";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        let resp = reqwest::Client::new().get(&url).send().await.unwrap();
        let body = read_capped(resp).await.unwrap();
        assert_eq!(body, b"hello world");
    }
}
