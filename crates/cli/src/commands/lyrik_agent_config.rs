//! Tracked agent configuration that runs commands.
//!
//! Some files, when they sit in a repository, make an agent or editor
//! session that is opened in a checkout run a command before the
//! person at the keyboard has typed anything: a hook, a helper that
//! fetches a key, a tool server started with the session. A repository
//! that tracks one hands that command to everyone who opens it. This
//! module finds them in the scanned revision and reports each as a
//! finding: the file, the command it declares, and where.
//!
//! Nothing is executed and nothing is resolved through the network.
//! The tracked paths come from [`super::lyrik_git`], which runs no
//! program the target configures; a file is read as bytes and parsed
//! as JSON; a symlink is read with `readlink` and followed by path
//! arithmetic only, never opened through the link.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

/// The files read. A path matches when it is one of these or ends with
/// `/` and one of these, so a nested project's file is found too.
const CONFIG_PATHS: &[&str] = &[
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".cursor/hooks.json",
    ".cursor/mcp.json",
    ".gemini/settings.json",
    ".mcp.json",
    ".vscode/mcp.json",
];

/// A file larger than this is not parsed.
const MAX_BYTES: u64 = 1024 * 1024;

/// How much of a declared command a finding quotes.
const MAX_COMMAND_CHARS: usize = 400;

/// One declared command.
#[derive(Debug, Clone, PartialEq)]
pub struct Declared {
    /// The tracked file that declares it, relative to the repository
    /// top level.
    pub file: String,
    /// The 1-based line the command is on, or 1 when it is not found
    /// as written.
    pub line: u32,
    /// What kind of declaration: `hook (<event>)`, `status line
    /// command`, `key helper`, `tool server (<name>)`.
    pub kind: String,
    /// The command as declared, cut to a bounded length.
    pub command: String,
    /// Set when the file is reached through a tracked symlink: the
    /// link's path and where it points.
    pub via_symlink: Option<String>,
}

fn is_config_path(path: &str) -> bool {
    CONFIG_PATHS
        .iter()
        .any(|p| path == *p || path.ends_with(&format!("/{p}")))
}

fn cut(command: &str) -> String {
    let folded: String = command
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if folded.chars().count() > MAX_COMMAND_CHARS {
        let mut out: String = folded.chars().take(MAX_COMMAND_CHARS).collect();
        out.push_str(" ...");
        out
    } else {
        folded
    }
}

/// A command with its arguments, when the declaration gives them apart.
fn with_args(entry: &Value) -> Option<String> {
    let command = entry.get("command")?.as_str()?.trim();
    if command.is_empty() {
        return None;
    }
    let args: Vec<&str> = entry
        .get("args")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    Some(if args.is_empty() {
        command.to_string()
    } else {
        format!("{command} {}", args.join(" "))
    })
}

/// Every `command` under a hooks tree, with the event it is under.
fn hook_commands(hooks: &Value, out: &mut Vec<(String, String)>) {
    let Some(events) = hooks.as_object() else {
        return;
    };
    fn walk(value: &Value, event: &str, out: &mut Vec<(String, String)>) {
        match value {
            Value::Object(map) => {
                if let Some(command) = with_args(value) {
                    out.push((format!("hook ({event})"), command));
                }
                for (key, inner) in map {
                    if key != "command" && key != "args" {
                        walk(inner, event, out);
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|v| walk(v, event, out)),
            _ => {}
        }
    }
    for (event, value) in events {
        walk(value, event, out);
    }
}

/// The commands one configuration file declares, as `(kind, command)`.
pub fn declared_in(body: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(hooks) = body.get("hooks") {
        hook_commands(hooks, &mut out);
    }
    if let Some(command) = body.get("statusLine").and_then(with_args) {
        out.push(("status line command".to_string(), command));
    }
    for key in ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport"] {
        if let Some(command) = body.get(key).and_then(Value::as_str).map(str::trim)
            && !command.is_empty()
        {
            out.push((format!("key helper ({key})"), command.to_string()));
        }
    }
    for key in ["mcpServers", "servers"] {
        if let Some(servers) = body.get(key).and_then(Value::as_object) {
            for (name, server) in servers {
                if let Some(command) = with_args(server) {
                    out.push((format!("tool server ({name})"), command));
                }
            }
        }
    }
    out
}

/// The line of `text` a declared command is on: where the command
/// stands as the file writes it, else where its first word does.
fn line_of(text: &str, command: &str) -> u32 {
    let escaped = serde_json::to_string(command).unwrap_or_default();
    let whole = escaped.trim_matches('"');
    let first = command.split_whitespace().next().unwrap_or(command);
    [whole, first]
        .iter()
        .filter(|needle| !needle.is_empty())
        .find_map(|needle| text.lines().position(|l| l.contains(needle)))
        .map(|i| i as u32 + 1)
        .unwrap_or(1)
}

/// `link`'s target as a path from the repository top level, by path
/// arithmetic alone. `None` when it is absolute or leaves the tree.
fn resolve_link(link: &Path, target: &Path) -> Option<PathBuf> {
    if target.is_absolute() {
        return None;
    }
    let mut out: Vec<std::ffi::OsString> = link
        .parent()
        .map(|p| p.iter().map(|c| c.to_os_string()).collect())
        .unwrap_or_default();
    for part in target.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop()?;
            }
            Component::Normal(name) => out.push(name.to_os_string()),
            _ => return None,
        }
    }
    Some(out.iter().collect())
}

/// Read one tracked regular file's declarations.
fn read_declared(top: &Path, file: &str) -> Vec<(u32, String, String)> {
    let path = top.join(file);
    // A regular file only, read once. A link is never opened.
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return Vec::new();
    };
    if !meta.is_file() || meta.len() > MAX_BYTES {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(body) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    declared_in(&body)
        .into_iter()
        .map(|(kind, command)| (line_of(&text, &command), kind, cut(&command)))
        .collect()
}

/// Every command a tracked agent configuration file declares, and
/// every tracked symlink that makes such a file appear at a path a
/// session reads. `Err` when the tracked files cannot be listed.
pub fn scan(target: &Path) -> Result<Vec<Declared>, String> {
    let (top, tracked) = super::lyrik_git::tracked_files(target)?;
    let mut out: Vec<Declared> = Vec::new();
    let files: Vec<&str> = tracked
        .iter()
        .filter(|(mode, _)| mode != "120000")
        .map(|(_, p)| p.as_str())
        .collect();
    for file in files.iter().filter(|f| is_config_path(f)) {
        for (line, kind, command) in read_declared(&top, file) {
            out.push(Declared {
                file: file.to_string(),
                line,
                kind,
                command,
                via_symlink: None,
            });
        }
    }
    // A tracked symlink whose name or target makes a configuration
    // file appear where a session looks for one: the link is a file,
    // or it is a directory that holds one.
    for (_, link) in tracked.iter().filter(|(mode, _)| mode == "120000") {
        let Ok(raw) = std::fs::read_link(top.join(link)) else {
            continue;
        };
        let Some(resolved) = resolve_link(Path::new(link), &raw) else {
            // It leaves the tree or is absolute: what it reaches is
            // not in the scanned revision. Reported when the link's
            // own path is one a session reads.
            if is_config_path(link) {
                out.push(Declared {
                    file: link.clone(),
                    line: 1,
                    kind: "symlink to a file outside the repository".to_string(),
                    command: format!("(not read) -> {}", cut(&raw.to_string_lossy())),
                    via_symlink: Some(format!("{link} -> {}", raw.to_string_lossy())),
                });
            }
            continue;
        };
        let resolved = resolved.to_string_lossy().into_owned();
        for file in &files {
            // The tracked file the link reaches, and the path it is
            // seen at through the link.
            let seen_at = if *file == resolved {
                link.clone()
            } else if let Some(rest) = file.strip_prefix(&format!("{resolved}/")) {
                format!("{link}/{rest}")
            } else {
                continue;
            };
            if !is_config_path(&seen_at) && !is_config_path(file) {
                continue;
            }
            // A file already reported under its own path is reported
            // again only when the link gives it a path a session reads.
            if is_config_path(file) && !is_config_path(&seen_at) {
                continue;
            }
            for (line, kind, command) in read_declared(&top, file) {
                out.push(Declared {
                    file: file.to_string(),
                    line,
                    kind,
                    command,
                    via_symlink: Some(format!("{link} -> {}", raw.to_string_lossy())),
                });
            }
        }
    }
    out.sort_by(|a, b| (&a.file, a.line, &a.kind).cmp(&(&b.file, b.line, &b.kind)));
    out.dedup();
    Ok(out)
}

/// The finding for one declared command, in the shape a walk's
/// `finding-NNN.json` has. Its class is `agent_config`.
pub fn finding(d: &Declared, index: usize) -> Value {
    let through = match &d.via_symlink {
        Some(link) => format!(" It is reached through the tracked symlink `{link}`."),
        None => String::new(),
    };
    serde_json::json!({
        "id": format!("agent-config-{:03}", index + 1),
        "stable_id": format!("agent_config::{}:{}", d.file, d.line),
        "framing": ["agent_config"],
        "location": { "file": d.file, "line_start": d.line },
        "title": format!(
            "Tracked agent configuration runs a program when a session starts: {}",
            d.kind
        ),
        "summary": format!(
            "`{}` is tracked in this repository and declares a {} that runs `{}`.{through} An \
             agent or editor session opened in a checkout runs it as the person who opened it, \
             before they have asked for anything. The file was read; the program was not run.",
            d.file, d.kind, d.command
        ),
        "tier": "MEDIUM",
        "detection_source": "static_prescreen",
        "threat_model": {
            "attacker_capability": "can get a change to this tracked file merged, or can \
                                    publish a copy of the repository that carries it",
            "harm_path": "a developer or an automated agent opens a session in the checkout \
                          and the declared program runs with that user's privileges and \
                          credentials"
        },
        "agent_config": {
            "kind": d.kind,
            "command": d.command,
            "via_symlink": d.via_symlink,
            "executed": false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::lyrik_git::tests::{committed_repo, setup_git};
    use super::*;
    use tempfile::tempdir;

    fn commit_all(dir: &Path) {
        setup_git(dir, &["add", "-A"]);
        setup_git(dir, &["commit", "-q", "-m", "add"]);
    }

    fn write(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn tracked_hooks_helpers_and_tool_servers_are_reported_with_their_commands() {
        let tmp = tempdir().unwrap();
        committed_repo(tmp.path());
        let marker = tmp.path().join("ran");
        write(
            tmp.path(),
            ".claude/settings.json",
            &format!(
                r#"{{
  "hooks": {{
    "SessionStart": [
      {{ "hooks": [ {{ "type": "command", "command": "touch {m}" }} ] }}
    ],
    "PreToolUse": [
      {{ "matcher": "Bash", "hooks": [ {{ "type": "command", "command": "sh tools/gate.sh" }} ] }}
    ]
  }},
  "statusLine": {{ "type": "command", "command": "sh tools/status.sh" }},
  "apiKeyHelper": "sh tools/key.sh"
}}"#,
                m = marker.display()
            ),
        );
        write(
            tmp.path(),
            "sub/project/.mcp.json",
            r#"{"mcpServers": {"notes": {"command": "node", "args": ["server.js", "--all"]}}}"#,
        );
        // A settings file with no command, one that is not JSON, and an
        // untracked one: nothing to report.
        write(
            tmp.path(),
            "other/.claude/settings.json",
            r#"{"model": "x"}"#,
        );
        write(tmp.path(), "broken/.mcp.json", "{ not json");
        commit_all(tmp.path());
        write(
            tmp.path(),
            "untracked/.claude/settings.json",
            r#"{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "sh x"}]}]}}"#,
        );

        let found = scan(tmp.path()).unwrap();
        let got: Vec<(&str, u32, &str, &str)> = found
            .iter()
            .map(|d| (d.file.as_str(), d.line, d.kind.as_str(), d.command.as_str()))
            .collect();
        let touch = format!("touch {}", marker.display());
        assert_eq!(
            got,
            [
                (
                    ".claude/settings.json",
                    4,
                    "hook (SessionStart)",
                    touch.as_str()
                ),
                (
                    ".claude/settings.json",
                    7,
                    "hook (PreToolUse)",
                    "sh tools/gate.sh"
                ),
                (
                    ".claude/settings.json",
                    10,
                    "status line command",
                    "sh tools/status.sh"
                ),
                (
                    ".claude/settings.json",
                    11,
                    "key helper (apiKeyHelper)",
                    "sh tools/key.sh"
                ),
                (
                    "sub/project/.mcp.json",
                    1,
                    "tool server (notes)",
                    "node server.js --all"
                ),
            ]
        );
        assert!(found.iter().all(|d| d.via_symlink.is_none()));
        // Reading the file ran nothing it declares.
        assert!(!marker.exists(), "a declared command was executed");
    }

    #[cfg(unix)]
    #[test]
    fn a_tracked_symlink_that_resolves_to_agent_configuration_is_reported() {
        let tmp = tempdir().unwrap();
        committed_repo(tmp.path());
        let hook = r#"{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "sh boot.sh"}]}]}}"#;
        // A directory link: `.claude` is a link to a directory that
        // holds a settings file under a name nothing would look for.
        write(tmp.path(), "tools/agent/settings.json", hook);
        std::os::unix::fs::symlink("tools/agent", tmp.path().join(".claude")).unwrap();
        // A file link: an innocuous name pointing at a tool-server file.
        write(
            tmp.path(),
            "conf/servers.json",
            r#"{"mcpServers": {"s": {"command": "sh srv.sh"}}}"#,
        );
        std::os::unix::fs::symlink("conf/servers.json", tmp.path().join(".mcp.json")).unwrap();
        // A link whose own path is read by a session and that points
        // out of the repository: reported, and not followed.
        std::fs::create_dir_all(tmp.path().join("nested/.cursor")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", tmp.path().join("nested/.cursor/mcp.json"))
            .unwrap();
        // A link to an ordinary file: nothing.
        std::os::unix::fs::symlink("src/a.rs", tmp.path().join("alias.rs")).unwrap();
        commit_all(tmp.path());

        let found = scan(tmp.path()).unwrap();
        let got: Vec<(&str, &str, Option<&str>)> = found
            .iter()
            .map(|d| {
                (
                    d.file.as_str(),
                    d.command.as_str(),
                    d.via_symlink.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (
                    "conf/servers.json",
                    "sh srv.sh",
                    Some(".mcp.json -> conf/servers.json")
                ),
                (
                    "nested/.cursor/mcp.json",
                    "(not read) -> /etc/hostname",
                    Some("nested/.cursor/mcp.json -> /etc/hostname")
                ),
                (
                    "tools/agent/settings.json",
                    "sh boot.sh",
                    Some(".claude -> tools/agent")
                ),
            ]
        );
    }

    #[test]
    fn a_declared_command_becomes_a_finding_the_validator_and_the_gates_accept() {
        let tmp = tempdir().unwrap();
        committed_repo(tmp.path());
        write(
            tmp.path(),
            ".claude/settings.json",
            r#"{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "sh boot.sh"}]}]}}"#,
        );
        commit_all(tmp.path());
        let found = scan(tmp.path()).unwrap();
        assert_eq!(found.len(), 1);
        let f = finding(&found[0], 0);
        assert_eq!(f["stable_id"], "agent_config::.claude/settings.json:1");
        assert_eq!(f["framing"], serde_json::json!(["agent_config"]));
        assert_eq!(f["agent_config"]["command"], "sh boot.sh");
        assert_eq!(f["agent_config"]["executed"], false);
        assert!(f["summary"].as_str().unwrap().contains("runs `sh boot.sh`"));
        // The citation gate resolves the cited file and line.
        let outcome = super::super::lyrik_citation::check(&f, tmp.path());
        assert_eq!(
            outcome.status,
            super::super::lyrik_citation::Status::Resolved,
            "{outcome:?}"
        );
        // Rule 1's two strings are there.
        for key in ["attacker_capability", "harm_path"] {
            assert!(!f["threat_model"][key].as_str().unwrap().trim().is_empty());
        }
        // A target that is not a repository is an error, not an empty list.
        assert!(scan(&tmp.path().join("nowhere")).is_err());
    }

    #[test]
    fn a_long_or_multiline_command_is_cut_and_folded() {
        let long = format!("sh x.sh {}\nsecond line", "a".repeat(600));
        let body = serde_json::json!({"apiKeyHelper": long});
        let (_, command) = declared_in(&body).remove(0);
        let shown = cut(&command);
        assert!(shown.ends_with(" ..."));
        assert!(!shown.contains('\n'));
        assert!(shown.chars().count() <= MAX_COMMAND_CHARS + 4);
    }
}
