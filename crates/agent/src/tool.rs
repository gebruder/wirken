use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::error::AgentError;

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

/// Built-in tool implementations.
pub struct ToolRegistry {
    workspace: PathBuf,
    tools: HashMap<String, ToolDef>,
}

impl ToolRegistry {
    /// Create a new tool registry with built-in tools.
    pub fn new(workspace: PathBuf) -> Self {
        let mut tools = HashMap::new();

        tools.insert("exec".into(), ToolDef {
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
        });

        tools.insert("read_file".into(), ToolDef {
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
        });

        tools.insert("write_file".into(), ToolDef {
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
        });

        tools.insert("list_files".into(), ToolDef {
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
        });

        Self { workspace, tools }
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
            _ => Err(AgentError::ToolNotFound(name.to_string())),
        }
    }

    async fn exec_command(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let command = args["command"].as_str()
            .ok_or_else(|| AgentError::Tool("missing 'command' argument".into()))?;

        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(&self.workspace)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| AgentError::Tool(format!("exec failed: {e}")))?;

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

        // Truncate very long output
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
        let path_str = args["path"].as_str()
            .ok_or_else(|| AgentError::Tool("missing 'path' argument".into()))?;

        let path = self.resolve_path(path_str);

        match tokio::fs::read_to_string(&path).await {
            Ok(content) => {
                let mut output = content;
                if output.len() > 64_000 {
                    output.truncate(64_000);
                    output.push_str("\n... (truncated)");
                }
                Ok(ToolResult { output, success: true })
            }
            Err(e) => Ok(ToolResult {
                output: format!("Error reading {}: {e}", path.display()),
                success: false,
            }),
        }
    }

    async fn write_file(&self, args: &serde_json::Value) -> Result<ToolResult, AgentError> {
        let path_str = args["path"].as_str()
            .ok_or_else(|| AgentError::Tool("missing 'path' argument".into()))?;
        let content = args["content"].as_str()
            .ok_or_else(|| AgentError::Tool("missing 'content' argument".into()))?;

        let path = self.resolve_path(path_str);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                return Ok(ToolResult {
                    output: format!("Error creating directory: {e}"),
                    success: false,
                });
            }
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
        let path = self.resolve_path(path_str);

        let mut entries = match tokio::fs::read_dir(&path).await {
            Ok(rd) => rd,
            Err(e) => return Ok(ToolResult {
                output: format!("Error listing {}: {e}", path.display()),
                success: false,
            }),
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

    /// Resolve a path relative to the workspace.
    fn resolve_path(&self, path: &str) -> PathBuf {
        let p = Path::new(path);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.workspace.join(p)
        }
    }
}
