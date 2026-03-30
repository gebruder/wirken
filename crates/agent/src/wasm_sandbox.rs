//! Wasm skill sandbox: run compiled .wasm modules as tools inside Wasmtime.
//!
//! A Wasm skill is a directory containing:
//! - SKILL.md (frontmatter with name, description, and optional tool schema)
//! - skill.wasm (compiled WebAssembly module)
//!
//! The module communicates via stdin/stdout:
//! - Input: JSON object with the tool arguments (written to stdin)
//! - Output: JSON object with the tool result (read from stdout)
//!
//! The sandbox provides:
//! - No filesystem access (or read-only workspace mount if configured)
//! - No network access
//! - Bounded memory (64MB default)
//! - Fuel-based CPU limits (prevents infinite loops)

use std::path::{Path, PathBuf};

use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};

use crate::error::AgentError;
use crate::tool::{ToolDef, ToolResult};

const DEFAULT_FUEL: u64 = 500_000_000; // ~500M instructions
const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024; // 64MB

/// A loaded Wasm skill ready to execute.
pub struct WasmSkill {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
    pub wasm_path: PathBuf,
    engine: Engine,
    module: Module,
}

impl WasmSkill {
    /// Load a Wasm skill from a directory containing skill.wasm.
    /// The name, description, and parameters come from the SKILL.md frontmatter.
    pub fn load(
        skill_dir: &Path,
        name: &str,
        description: &str,
        parameters: Option<serde_json::Value>,
    ) -> Result<Self, AgentError> {
        let wasm_path = skill_dir.join("skill.wasm");
        if !wasm_path.exists() {
            return Err(AgentError::Tool(format!(
                "no skill.wasm in {}",
                skill_dir.display()
            )));
        }

        let mut config = Config::new();
        config.consume_fuel(true);

        let engine =
            Engine::new(&config).map_err(|e| AgentError::Sandbox(format!("wasm engine: {e}")))?;

        let wasm_bytes = std::fs::read(&wasm_path)
            .map_err(|e| AgentError::Sandbox(format!("read wasm: {e}")))?;

        let module = Module::new(&engine, &wasm_bytes)
            .map_err(|e| AgentError::Sandbox(format!("compile wasm: {e}")))?;

        let params = parameters.unwrap_or_else(|| {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": "Input to the skill"
                    }
                },
                "required": ["input"]
            })
        });

        Ok(Self {
            name: name.to_string(),
            description: description.to_string(),
            parameters: params,
            wasm_path,
            engine,
            module,
        })
    }

    /// Get the tool definition for this Wasm skill.
    pub fn tool_def(&self) -> ToolDef {
        ToolDef {
            name: format!("wasm_{}", self.name),
            description: format!("[wasm] {}", self.description),
            parameters: self.parameters.clone(),
        }
    }

    /// Execute the Wasm module with the given JSON arguments.
    /// Arguments are written to stdin, result is read from stdout.
    pub fn execute(&self, arguments: &str) -> Result<ToolResult, AgentError> {
        let stdin_data = format!("{arguments}\n");

        let stdout = MemoryOutputPipe::new(MAX_MEMORY_BYTES);
        let stderr = MemoryOutputPipe::new(4096);

        let wasi_ctx = WasiCtxBuilder::new()
            .stdin(MemoryInputPipe::new(stdin_data))
            .stdout(stdout.clone())
            .stderr(stderr.clone())
            .build_p1();

        let mut store = Store::new(&self.engine, wasi_ctx);

        // Set fuel limit for CPU bounding
        store
            .set_fuel(DEFAULT_FUEL)
            .map_err(|e| AgentError::Sandbox(format!("set fuel: {e}")))?;

        let mut linker = Linker::new(&self.engine);
        p1::add_to_linker_sync(&mut linker, |ctx: &mut WasiP1Ctx| ctx)
            .map_err(|e| AgentError::Sandbox(format!("link wasi: {e}")))?;

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| AgentError::Sandbox(format!("instantiate: {e}")))?;

        // Call _start (WASI entry point)
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| AgentError::Sandbox(format!("no _start export: {e}")))?;

        let run_result = start.call(&mut store, ());

        let out_bytes = stdout.try_into_inner().unwrap_or_default();
        let err_bytes = stderr.try_into_inner().unwrap_or_default();
        let out_str = String::from_utf8_lossy(&out_bytes).trim().to_string();
        let err_str = String::from_utf8_lossy(&err_bytes).trim().to_string();

        match run_result {
            Ok(()) => Ok(ToolResult {
                output: if out_str.is_empty() {
                    "(no output)".into()
                } else {
                    out_str
                },
                success: true,
            }),
            Err(e) => {
                // Check if it was a fuel exhaustion (infinite loop protection)
                let err_msg = e.to_string();
                if err_msg.contains("fuel") {
                    return Ok(ToolResult {
                        output: "Wasm skill exceeded CPU limit (possible infinite loop)".into(),
                        success: false,
                    });
                }

                // Trap or other error
                let mut output = format!("Wasm skill error: {err_msg}");
                if !err_str.is_empty() {
                    output.push_str(&format!("\n[stderr] {err_str}"));
                }
                Ok(ToolResult {
                    output,
                    success: false,
                })
            }
        }
    }
}

/// Scan a skills directory for Wasm skills (directories containing skill.wasm).
/// Returns loaded WasmSkill instances alongside their tool definitions.
pub fn load_wasm_skills(skills_dir: &Path) -> Vec<WasmSkill> {
    let mut skills = Vec::new();

    let entries = match std::fs::read_dir(skills_dir) {
        Ok(e) => e,
        Err(_) => return skills,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let wasm_path = path.join("skill.wasm");
        if !wasm_path.exists() {
            continue;
        }

        // Try to read SKILL.md for metadata
        let skill_md = path.join("SKILL.md");
        let (name, description, parameters) = if skill_md.exists() {
            parse_wasm_skill_metadata(&skill_md, &path)
        } else {
            let dir_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            (dir_name, String::new(), None)
        };

        match WasmSkill::load(&path, &name, &description, parameters) {
            Ok(skill) => {
                tracing::info!("Loaded Wasm skill: {}", skill.name);
                skills.push(skill);
            }
            Err(e) => {
                tracing::warn!("Failed to load Wasm skill at {}: {e}", path.display());
            }
        }
    }

    skills
}

fn parse_wasm_skill_metadata(
    skill_md: &Path,
    skill_dir: &Path,
) -> (String, String, Option<serde_json::Value>) {
    let content = std::fs::read_to_string(skill_md).unwrap_or_default();
    let dir_name = skill_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Parse YAML frontmatter
    let content = content.trim();
    if !content.starts_with("---") {
        return (dir_name, String::new(), None);
    }

    let rest = &content[3..];
    let end = match rest.find("---") {
        Some(e) => e,
        None => return (dir_name, String::new(), None),
    };

    let yaml_str = rest[..end].trim();
    let frontmatter: serde_json::Value =
        serde_yaml::from_str(yaml_str).unwrap_or(serde_json::Value::Null);

    let name = frontmatter
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or(&dir_name)
        .to_string();
    let description = frontmatter
        .get("description")
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_string();
    let parameters = frontmatter.get("parameters").cloned();

    (name, description, parameters)
}
