use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::error::AgentError;
use crate::sandbox::{DockerSandbox, SandboxConfig, SandboxMode};

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
    workspace: PathBuf,
    tools: HashMap<String, ToolDef>,
    http: reqwest::Client,
    config: ToolConfig,
    sandbox: Option<DockerSandbox>,
}

impl ToolRegistry {
    /// Create a new tool registry with built-in tools.
    pub fn new(workspace: PathBuf, config: ToolConfig) -> Self {
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

        let sandbox = if config.sandbox.mode != SandboxMode::Off {
            match DockerSandbox::new(config.sandbox.clone()) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("Sandbox unavailable: {e}");
                    None
                }
            }
        } else {
            None
        };

        Self {
            workspace,
            tools,
            http: reqwest::Client::new(),
            config,
            sandbox,
        }
    }

    /// Get all tool definitions (for sending to the LLM).
    pub fn definitions(&self) -> Vec<ToolDef> {
        self.tools.values().cloned().collect()
    }

    /// Execute a tool by name with the given JSON arguments.
    pub async fn execute(&self, name: &str, arguments: &str) -> Result<ToolResult, AgentError> {
        let args: serde_json::Value = serde_json::from_str(arguments)
            .map_err(|e| AgentError::Tool(format!("invalid arguments: {e}")))?;

        match name {
            "exec" => self.exec_command(&args).await,
            "read_file" => self.read_file(&args).await,
            "write_file" => self.write_file(&args).await,
            "list_files" => self.list_files(&args).await,
            "web_search" => self.web_search(&args).await,
            "generate_image" => self.generate_image(&args).await,
            _ => Err(AgentError::ToolNotFound(name.to_string())),
        }
    }

    async fn exec_command(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let command = args["command"]
            .as_str()
            .ok_or_else(|| AgentError::Tool("missing 'command' argument".into()))?;

        // Use sandbox if available
        if let Some(ref sandbox) = self.sandbox {
            return sandbox.exec(command, &self.workspace).await;
        }

        let child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
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

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

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
            .ok_or_else(|| AgentError::Tool("missing 'path' argument".into()))?;

        let path = self.resolve_path(path_str)?;

        match tokio::fs::read_to_string(&path).await {
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
                output: format!("Error reading {}: {e}", path.display()),
                success: false,
            }),
        }
    }

    async fn write_file(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let path_str = args["path"]
            .as_str()
            .ok_or_else(|| AgentError::Tool("missing 'path' argument".into()))?;
        let content = args["content"]
            .as_str()
            .ok_or_else(|| AgentError::Tool("missing 'content' argument".into()))?;

        let path = self.resolve_path_for_write(path_str)?;

        if let Some(parent) = path.parent()
            && let Err(e) = tokio::fs::create_dir_all(parent).await
        {
            return Ok(ToolResult {
                output: format!("Error creating directory: {e}"),
                success: false,
            });
        }

        match tokio::fs::write(&path, content).await {
            Ok(()) => Ok(ToolResult {
                output: format!("Wrote {} bytes to {}", content.len(), path.display()),
                success: true,
            }),
            Err(e) => Ok(ToolResult {
                output: format!("Error writing {}: {e}", path.display()),
                success: false,
            }),
        }
    }

    async fn list_files(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let path_str = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
        let path = self.resolve_path(path_str)?;

        let mut entries = match tokio::fs::read_dir(&path).await {
            Ok(rd) => rd,
            Err(e) => {
                return Ok(ToolResult {
                    output: format!("Error listing {}: {e}", path.display()),
                    success: false,
                });
            }
        };

        let mut names = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            let is_dir = entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                names.push(format!("{name}/"));
            } else {
                names.push(name);
            }
        }
        names.sort();

        Ok(ToolResult {
            output: names.join("\n"),
            success: true,
        })
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

        let html = resp
            .text()
            .await
            .map_err(|e| AgentError::Tool(format!("read response: {e}")))?;

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

        let resp_json: serde_json::Value = resp
            .json()
            .await
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

        // Save to workspace/generated_images/
        let images_dir = self.workspace.join("generated_images");
        tokio::fs::create_dir_all(&images_dir)
            .await
            .map_err(|e| AgentError::Tool(format!("create images dir: {e}")))?;

        let file_path = images_dir.join(format!("{filename}.png"));
        tokio::fs::write(&file_path, &image_bytes)
            .await
            .map_err(|e| AgentError::Tool(format!("write image: {e}")))?;

        Ok(ToolResult {
            output: format!(
                "Image saved to {} ({} bytes)",
                file_path.display(),
                image_bytes.len()
            ),
            success: true,
        })
    }

    /// Resolve a path and verify it is within the workspace boundary.
    fn resolve_path(&self, path: &str) -> Result<PathBuf, AgentError> {
        let joined = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            self.workspace.join(path)
        };

        let workspace = self
            .workspace
            .canonicalize()
            .map_err(|e| AgentError::Tool(format!("workspace resolution failed: {e}")))?;

        if joined.exists() {
            let canonical = joined.canonicalize().map_err(|e| {
                AgentError::Tool(format!("path resolution failed for '{}': {e}", path))
            })?;
            if !canonical.starts_with(&workspace) {
                return Err(AgentError::Tool(format!(
                    "access denied: '{}' is outside the workspace",
                    path
                )));
            }
            return Ok(canonical);
        }

        self.check_ancestor_in_workspace(&joined, &workspace, path)?;
        Ok(joined)
    }

    /// Resolve a path for write operations where the target may not exist yet.
    fn resolve_path_for_write(&self, path: &str) -> Result<PathBuf, AgentError> {
        let joined = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            self.workspace.join(path)
        };

        let workspace = self
            .workspace
            .canonicalize()
            .map_err(|e| AgentError::Tool(format!("workspace resolution failed: {e}")))?;

        self.check_ancestor_in_workspace(&joined, &workspace, path)?;
        Ok(joined)
    }

    fn check_ancestor_in_workspace(
        &self,
        target: &Path,
        workspace: &Path,
        original_path: &str,
    ) -> Result<(), AgentError> {
        let mut existing_ancestor = target.to_path_buf();
        while !existing_ancestor.exists() {
            if !existing_ancestor.pop() {
                return Err(AgentError::Tool(format!(
                    "no valid ancestor for '{}'",
                    original_path
                )));
            }
        }

        let canonical_ancestor = existing_ancestor
            .canonicalize()
            .map_err(|e| AgentError::Tool(format!("path resolution failed: {e}")))?;

        if !canonical_ancestor.starts_with(workspace) {
            return Err(AgentError::Tool(format!(
                "access denied: '{}' is outside the workspace",
                original_path
            )));
        }

        Ok(())
    }
}

struct SearchResult {
    title: String,
    url: String,
    snippet: String,
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
                let actual_url = if let Some(rest) = url.strip_prefix("//duckduckgo.com/l/?uddg=")
                {
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
            && let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                16,
            )
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
