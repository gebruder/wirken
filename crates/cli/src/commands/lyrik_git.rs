//! Read-only git facts about a Lyrik target, gathered without running
//! anything the target repository configures.
//!
//! The rule: no program the target repo configures runs on the host.
//! A target is untrusted input, and its `.git/config`,
//! `.git/info/attributes` and `.gitattributes` can name programs that
//! ordinary git commands run: an fsmonitor hook, clean and smudge
//! filters, hooks, a pager, an external diff, an ssh command or
//! credential helper behind a lazy fetch.
//!
//! So git is asked only what it can answer from the object database
//! and refs, and the work tree is compared in-process:
//!
//! - `rev-parse` (`--show-toplevel`, `--show-object-format`,
//!   `--verify HEAD^{commit}`) and `ls-tree` read refs, config and
//!   objects. They do not refresh the index, so no fsmonitor; they do
//!   not convert content, so no clean or smudge filter; they run no
//!   hook, no diff and, with `--no-pager`, no pager.
//! - Every call also passes `core.fsmonitor=false` and
//!   `protocol.allow=never`, the latter so a partial clone missing an
//!   object fails instead of lazily fetching through a configured ssh
//!   command or credential helper, and drops inherited `GIT_*`
//!   variables so the operator's environment cannot point git
//!   elsewhere.
//! - `git status`, `git diff` and `git diff-index` are not used: they
//!   re-read changed files through the repo's clean filters, which no
//!   command-line option switches off for every driver. Whether the
//!   work tree matches HEAD is decided here instead, by hashing each
//!   tracked file as a git blob and comparing it with HEAD's tree.
//! - Where git would convert content (a filter, LFS, line-ending or
//!   encoding conversion), the work-tree bytes are not the blob's, so
//!   no comparison is made and the reason is returned instead. `git
//!   config --get` and `git check-attr` tell; both only read config
//!   and attributes files.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// HEAD and work-tree state of the repository holding a target, or
/// why it could not be read.
#[derive(Debug, Clone, PartialEq)]
pub struct Provenance {
    pub sha: Option<String>,
    /// Whether any tracked file differs from HEAD. Untracked files do
    /// not count.
    pub dirty: Option<bool>,
    /// Set when `sha` and `dirty` are `None`.
    pub unavailable: Option<String>,
}

impl Provenance {
    fn unavailable(reason: impl Into<String>) -> Self {
        Provenance {
            sha: None,
            dirty: None,
            unavailable: Some(reason.into()),
        }
    }
}

/// HEAD and tracked-file state of the repository `target` sits in.
pub fn provenance(target: &Path) -> Provenance {
    let repo = match Repo::open(target) {
        Ok(r) => r,
        Err(reason) => return Provenance::unavailable(reason),
    };
    let sha = match repo.head() {
        Ok(sha) => sha,
        Err(reason) => return Provenance::unavailable(reason),
    };
    let dirty = repo.head_entries().and_then(|entries| {
        let paths: Vec<&Path> = entries
            .iter()
            .filter(|e| e.kind == "blob")
            .map(|e| e.path.as_path())
            .collect();
        if let Some(conversion) = conversion_declared(&repo.toplevel, &paths)? {
            return Err(format!(
                "content conversion declared ({conversion}); tracked files not compared"
            ));
        }
        repo.tracked_changes(&entries)
    });
    match dirty {
        Ok(dirty) => Provenance {
            sha: Some(sha),
            dirty: Some(dirty),
            unavailable: None,
        },
        Err(reason) => Provenance {
            sha: Some(sha),
            dirty: None,
            unavailable: Some(reason),
        },
    }
}

/// Attributes under which git converts content between the work tree
/// and the object database: filters (LFS among them), line-ending
/// conversion, `$Id$` expansion, re-encoding. Where one applies, the
/// work-tree bytes are not the blob's bytes, so comparing them says
/// nothing about whether the file changed.
const CONVERSION_ATTRIBUTES: &[&str] = &[
    "filter",
    "text",
    "eol",
    "crlf",
    "ident",
    "working-tree-encoding",
];

/// The first content conversion that applies to any of `paths`
/// (relative to `dir`), through `core.autocrlf` or an attribute from
/// any attributes file. `git config` and `git check-attr` only read
/// config and attributes files; neither runs a filter.
fn conversion_declared(dir: &Path, paths: &[&Path]) -> Result<Option<String>, String> {
    let out = git(dir)
        .args(["config", "--get", "core.autocrlf"])
        .output()
        .map_err(|e| format!("run git: {e}"))?;
    match out.status.code() {
        Some(0) => {
            let value = trimmed(out.stdout);
            if value != "false" {
                return Ok(Some(format!("core.autocrlf={value}")));
            }
        }
        // Unset.
        Some(1) => {}
        _ => {
            return Err(format!(
                "git config --get core.autocrlf: {}",
                trimmed(out.stderr)
            ));
        }
    }
    if paths.is_empty() {
        return Ok(None);
    }

    let mut input = Vec::new();
    for p in paths {
        input.extend_from_slice(p.as_os_str().as_encoded_bytes());
        input.push(0);
    }
    let mut child = git(dir)
        .args(["check-attr", "-z", "--stdin"])
        .args(CONVERSION_ATTRIBUTES)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("run git: {e}"))?;
    let mut stdin = child.stdin.take().expect("stdin piped");
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        stdin.write_all(&input)
    });
    let out = child
        .wait_with_output()
        .map_err(|e| format!("run git: {e}"))?;
    let written = writer
        .join()
        .map_err(|_| "git check-attr input writer panicked")?;
    if !out.status.success() {
        return Err(format!("git check-attr: {}", trimmed(out.stderr)));
    }
    written.map_err(|e| format!("git check-attr input: {e}"))?;
    // `<path>\0<attribute>\0<value>\0` per path and attribute.
    let fields: Vec<&[u8]> = out.stdout.split(|b| *b == 0).collect();
    for [path, attribute, value] in fields.as_chunks::<3>().0 {
        let value = String::from_utf8_lossy(value);
        if value != "unspecified" && value != "unset" {
            return Ok(Some(format!(
                "{}={value} on {}",
                String::from_utf8_lossy(attribute),
                String::from_utf8_lossy(path)
            )));
        }
    }
    Ok(None)
}

/// Whether `rel` (relative to `target`) is in HEAD's tree with exactly
/// the bytes it has on disk. `Err` carries why it is not, or why that
/// could not be told.
pub fn unmodified_at_head(target: &Path, rel: &Path) -> Result<(), String> {
    let repo = Repo::open(target)?;
    repo.head()?;
    // `ls-tree` resolves the path against the working directory.
    let out = run_git(target, &["ls-tree", "-z", "HEAD", "--"], Some(rel))?;
    let entry = parse_ls_tree(&out)
        .into_iter()
        .next()
        .ok_or_else(|| "not tracked at HEAD".to_string())?;
    if entry.kind != "blob" {
        return Err(format!("tracked as {}, not a file", entry.kind));
    }
    if let Some(conversion) = conversion_declared(target, &[rel])? {
        return Err(format!(
            "content conversion declared ({conversion}); not compared with HEAD"
        ));
    }
    match repo.blob_differs(&entry, &target.join(rel))? {
        false => Ok(()),
        true => Err("modified against HEAD".to_string()),
    }
}

/// A git invocation under the rule above.
fn git(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    git_env(&mut cmd);
    cmd.current_dir(dir)
        .args([
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
        ])
        .stdin(Stdio::null());
    cmd
}

/// The environment a git child runs with: the minimal host-child set
/// (`wirken_agent::child_env::minimal`), so no `GIT_*` the operator
/// exported and nothing else from this process's environment, the
/// vault passphrase included, reaches it; plus the three `GIT_*`
/// settings the operation needs, which keep it off the network, off
/// any prompt and off the index lock.
fn git_env(cmd: &mut Command) -> &mut Command {
    cmd.env_clear()
        .envs(wirken_agent::child_env::minimal())
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
}

fn run_git(dir: &Path, args: &[&str], path: Option<&Path>) -> Result<Vec<u8>, String> {
    let mut cmd = git(dir);
    cmd.args(args);
    if let Some(p) = path {
        cmd.arg(p);
    }
    let out = cmd.output().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "git not found on PATH".to_string(),
        _ => format!("run git: {e}"),
    })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let first = stderr.lines().next().unwrap_or("").trim();
        return Err(format!("git {}: {first}", args.join(" ")));
    }
    Ok(out.stdout)
}

fn trimmed(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).trim().to_string()
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ObjectFormat {
    Sha1,
    Sha256,
}

struct Repo {
    toplevel: PathBuf,
    format: ObjectFormat,
}

impl Repo {
    fn open(target: &Path) -> Result<Self, String> {
        let toplevel = run_git(target, &["rev-parse", "--show-toplevel"], None)
            .map(|b| PathBuf::from(trimmed(b)))
            .map_err(|e| format!("not a git work tree ({e})"))?;
        let format = match run_git(target, &["rev-parse", "--show-object-format"], None)
            .map(trimmed)
            .as_deref()
        {
            Ok("sha256") => ObjectFormat::Sha256,
            Ok("sha1") => ObjectFormat::Sha1,
            Ok(other) => return Err(format!("unknown object format {other:?}")),
            // Older git without the option only knows sha1.
            Err(_) => ObjectFormat::Sha1,
        };
        Ok(Repo { toplevel, format })
    }

    fn head(&self) -> Result<String, String> {
        run_git(
            &self.toplevel,
            &["rev-parse", "--verify", "-q", "HEAD^{commit}"],
            None,
        )
        .map(trimmed)
        .map_err(|_| "HEAD has no commit".to_string())
    }

    /// Every entry of HEAD's tree, paths relative to the top level.
    fn head_entries(&self) -> Result<Vec<TreeEntry>, String> {
        let out = run_git(
            &self.toplevel,
            &["ls-tree", "-r", "-z", "--full-tree", "HEAD"],
            None,
        )?;
        Ok(parse_ls_tree(&out))
    }

    /// Whether any of `entries` differs from the work tree: missing, a
    /// different kind of file, a different executable bit, different
    /// bytes, or a submodule at a different commit.
    fn tracked_changes(&self, entries: &[TreeEntry]) -> Result<bool, String> {
        for entry in entries {
            let path = self.toplevel.join(&entry.path);
            let differs = match entry.kind.as_str() {
                "blob" => self.blob_differs(entry, &path)?,
                "commit" => submodule_differs(entry, &path)?,
                other => return Err(format!("unexpected tree entry kind {other}")),
            };
            if differs {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn blob_differs(&self, entry: &TreeEntry, path: &Path) -> Result<bool, String> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(e) => return Err(format!("stat {}: {e}", entry.path.display())),
        };
        let bytes = match entry.mode.as_str() {
            "120000" => {
                if !meta.file_type().is_symlink() {
                    return Ok(true);
                }
                let link = std::fs::read_link(path)
                    .map_err(|e| format!("readlink {}: {e}", entry.path.display()))?;
                link.into_os_string().into_encoded_bytes()
            }
            "100644" | "100755" => {
                if !meta.file_type().is_file() || executable(&meta) != (entry.mode == "100755") {
                    return Ok(true);
                }
                std::fs::read(path).map_err(|e| format!("read {}: {e}", entry.path.display()))?
            }
            other => return Err(format!("unexpected blob mode {other}")),
        };
        Ok(blob_id(self.format, &bytes) != entry.oid)
    }
}

#[cfg(unix)]
fn executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_meta: &std::fs::Metadata) -> bool {
    false
}

/// A checked-out submodule whose HEAD is not the recorded commit. An
/// uninitialised one, an empty directory, matches, as `git status`
/// treats it.
fn submodule_differs(entry: &TreeEntry, path: &Path) -> Result<bool, String> {
    if !path.join(".git").exists() {
        return Ok(false);
    }
    match run_git(
        path,
        &["rev-parse", "--verify", "-q", "HEAD^{commit}"],
        None,
    ) {
        Ok(sha) => Ok(trimmed(sha) != entry.oid),
        Err(_) => Ok(true),
    }
}

/// Object id of `bytes` stored as a git blob.
fn blob_id(format: ObjectFormat, bytes: &[u8]) -> String {
    let header = format!("blob {}\0", bytes.len());
    let digest: Vec<u8> = match format {
        ObjectFormat::Sha1 => {
            use sha1::{Digest, Sha1};
            let mut h = Sha1::new();
            h.update(header.as_bytes());
            h.update(bytes);
            h.finalize().to_vec()
        }
        ObjectFormat::Sha256 => {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(header.as_bytes());
            h.update(bytes);
            h.finalize().to_vec()
        }
    };
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        write!(&mut s, "{b:02x}").expect("write to String never fails");
    }
    s
}

#[derive(Debug, PartialEq)]
struct TreeEntry {
    mode: String,
    kind: String,
    oid: String,
    path: PathBuf,
}

/// `ls-tree -z` output: `<mode> <type> <oid>\t<path>\0` per entry.
fn parse_ls_tree(out: &[u8]) -> Vec<TreeEntry> {
    out.split(|b| *b == 0)
        .filter(|rec| !rec.is_empty())
        .filter_map(|rec| {
            let tab = rec.iter().position(|b| *b == b'\t')?;
            let (meta, path) = (&rec[..tab], &rec[tab + 1..]);
            let meta = std::str::from_utf8(meta).ok()?;
            let mut parts = meta.split(' ');
            let (mode, kind, oid) = (parts.next()?, parts.next()?, parts.next()?);
            Some(TreeEntry {
                mode: mode.to_string(),
                kind: kind.to_string(),
                oid: oid.to_string(),
                path: path_from_bytes(path),
            })
        })
        .collect()
}

#[cfg(unix)]
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
}

#[cfg(not(unix))]
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A git child starts from the minimal environment plus the three
    /// `GIT_*` settings the operation needs; what the parent exported,
    /// the vault passphrase and every other `GIT_*` included, does not
    /// reach it.
    #[cfg(unix)]
    #[test]
    fn git_child_inherits_nothing_it_is_not_named() {
        use crate::commands::child_env_tests::{SENTINELS, assert_inherits_nothing};
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "env"])
            .envs(SENTINELS.iter().copied())
            .env("GIT_CONFIG_GLOBAL", "/inherited/gitconfig")
            .stdout(Stdio::piped());
        git_env(&mut cmd);
        let env = String::from_utf8(cmd.output().unwrap().stdout).unwrap();
        assert_inherits_nothing("git", &env);
        assert!(!env.contains("GIT_CONFIG_GLOBAL="), "{env}");
        for line in [
            "GIT_NO_LAZY_FETCH=1",
            "GIT_TERMINAL_PROMPT=0",
            "GIT_OPTIONAL_LOCKS=0",
        ] {
            assert!(env.lines().any(|l| l == line), "{line} missing:\n{env}");
        }
    }

    /// Run git in `dir` for test setup, with the operator's identity
    /// and config kept out of it.
    pub(crate) fn setup_git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .current_dir(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    /// A repo with one committed file and a committed executable.
    pub(crate) fn committed_repo(dir: &Path) {
        setup_git(dir, &["init", "-q"]);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(dir.join("run.sh"), "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.join("run.sh"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        setup_git(dir, &["add", "-A"]);
        setup_git(dir, &["commit", "-q", "-m", "init"]);
    }

    /// Arm `dir`'s repo so that any of the programs it can configure
    /// writes `marker`: fsmonitor, a clean and smudge filter on every
    /// path, every hook, the pager, an external diff and an ssh
    /// command.
    pub(crate) fn arm_repo(dir: &Path, marker: &Path) {
        let touch = format!("touch {}", marker.display());
        for (key, value) in [
            ("core.fsmonitor", touch.clone()),
            ("filter.trap.clean", format!("{touch}; cat")),
            ("filter.trap.smudge", format!("{touch}; cat")),
            ("filter.trap.required", "true".to_string()),
            ("core.pager", touch.clone()),
            ("pager.status", "true".to_string()),
            ("diff.external", touch.clone()),
            ("core.sshCommand", touch.clone()),
        ] {
            setup_git(dir, &["config", key, &value]);
        }
        std::fs::write(dir.join(".git/info/attributes"), "* filter=trap\n").unwrap();
        let hooks = dir.join(".git/hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        for hook in [
            "post-checkout",
            "post-index-change",
            "pre-commit",
            "reference-transaction",
        ] {
            let p = hooks.join(hook);
            std::fs::write(&p, format!("#!/bin/sh\n{touch}\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
    }

    #[test]
    fn a_clean_repo_reports_head_and_not_dirty() {
        let tmp = tempdir().unwrap();
        committed_repo(tmp.path());
        let p = provenance(tmp.path());
        assert_eq!(p.dirty, Some(false), "{p:?}");
        assert_eq!(p.unavailable, None);
        let sha = p.sha.unwrap();
        assert_eq!(sha.len(), 40, "{sha}");
    }

    #[test]
    fn an_edited_or_deleted_or_rechmodded_tracked_file_is_dirty() {
        let tmp = tempdir().unwrap();
        committed_repo(tmp.path());
        std::fs::write(tmp.path().join("src/a.rs"), "fn b() {}\n").unwrap();
        assert_eq!(provenance(tmp.path()).dirty, Some(true));

        let tmp = tempdir().unwrap();
        committed_repo(tmp.path());
        std::fs::remove_file(tmp.path().join("src/a.rs")).unwrap();
        assert_eq!(provenance(tmp.path()).dirty, Some(true));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempdir().unwrap();
            committed_repo(tmp.path());
            std::fs::set_permissions(
                tmp.path().join("run.sh"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert_eq!(provenance(tmp.path()).dirty, Some(true));
        }
    }

    #[test]
    fn untracked_files_do_not_make_a_repo_dirty() {
        let tmp = tempdir().unwrap();
        committed_repo(tmp.path());
        std::fs::create_dir_all(tmp.path().join(".lyrik/state")).unwrap();
        std::fs::write(tmp.path().join(".lyrik/state/x"), "x").unwrap();
        std::fs::write(tmp.path().join("new.rs"), "x").unwrap();
        assert_eq!(provenance(tmp.path()).dirty, Some(false));
    }

    #[test]
    fn a_subdirectory_target_reports_the_whole_repo() {
        let tmp = tempdir().unwrap();
        committed_repo(tmp.path());
        let clean = provenance(&tmp.path().join("src"));
        assert_eq!(clean.dirty, Some(false), "{clean:?}");
        std::fs::write(tmp.path().join("run.sh"), "changed\n").unwrap();
        assert_eq!(provenance(&tmp.path().join("src")).dirty, Some(true));
    }

    #[test]
    fn a_non_git_target_says_why() {
        let tmp = tempdir().unwrap();
        let p = provenance(tmp.path());
        assert_eq!((p.sha, p.dirty), (None, None));
        assert!(
            p.unavailable
                .as_deref()
                .unwrap()
                .starts_with("not a git work tree"),
            "{:?}",
            p.unavailable
        );
    }

    #[test]
    fn a_repo_without_commits_says_why() {
        let tmp = tempdir().unwrap();
        setup_git(tmp.path(), &["init", "-q"]);
        let p = provenance(tmp.path());
        assert_eq!(p.unavailable.as_deref(), Some("HEAD has no commit"));
    }

    /// Every query, against a repo armed with each program it can
    /// configure and a work tree whose files git would re-read through
    /// the clean filter, runs none of them.
    #[test]
    fn no_repo_configured_program_runs() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        committed_repo(&repo);
        let marker = tmp.path().join("marker");
        arm_repo(&repo, &marker);
        // Changed content and a fresh mtime: git status would hash it
        // through the clean filter.
        std::fs::write(repo.join("src/a.rs"), "fn changed() {}\n").unwrap();

        // The trap is live: git status trips it.
        let _ = Command::new("git")
            .current_dir(&repo)
            .args(["status", "--porcelain"])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output();
        assert!(marker.exists(), "control: git status runs the trap");
        std::fs::remove_file(&marker).unwrap();

        // The trap's filter applies to every path, so no comparison is
        // made, and asking which attributes apply runs nothing.
        let p = provenance(&repo);
        assert_eq!(p.dirty, None, "{p:?}");
        assert!(
            p.unavailable.as_deref().unwrap().contains("filter=trap"),
            "{p:?}"
        );
        assert!(unmodified_at_head(&repo, Path::new("src/a.rs")).is_err());
        assert!(unmodified_at_head(&repo, Path::new("run.sh")).is_err());
        assert!(!marker.exists(), "a repo-configured program ran");
    }

    #[test]
    fn unmodified_at_head_tells_tracked_from_untracked_and_modified() {
        let tmp = tempdir().unwrap();
        committed_repo(tmp.path());
        assert_eq!(
            unmodified_at_head(tmp.path(), Path::new("src/a.rs")),
            Ok(())
        );
        std::fs::write(tmp.path().join("new.md"), "x").unwrap();
        assert_eq!(
            unmodified_at_head(tmp.path(), Path::new("new.md")),
            Err("not tracked at HEAD".to_string())
        );
        std::fs::write(tmp.path().join("src/a.rs"), "edited\n").unwrap();
        assert_eq!(
            unmodified_at_head(tmp.path(), Path::new("src/a.rs")),
            Err("modified against HEAD".to_string())
        );
        // Relative to the target, which may sit below the top level.
        assert_eq!(
            unmodified_at_head(&tmp.path().join("src"), Path::new("a.rs")),
            Err("modified against HEAD".to_string())
        );
    }

    /// A filter, line-ending conversion or LFS on any tracked path
    /// leaves `dirty` unknown, with the reason; `-text` does not.
    #[test]
    fn declared_content_conversion_leaves_dirty_unknown() {
        for (attributes, expected) in [
            (
                "*.rs filter=lfs diff=lfs merge=lfs -text\n",
                Some("filter=lfs on src/a.rs"),
            ),
            ("* text=auto\n", Some("text=auto on ")),
            ("*.sh eol=crlf\n", Some("eol=crlf on run.sh")),
            ("*.rs ident\n", Some("ident=set on src/a.rs")),
            ("*.rs -text\n", None),
        ] {
            let tmp = tempdir().unwrap();
            std::fs::write(tmp.path().join(".gitattributes"), attributes).unwrap();
            committed_repo(tmp.path());
            let p = provenance(tmp.path());
            match expected {
                Some(reason) => {
                    assert_eq!(p.dirty, None, "{attributes}: {p:?}");
                    assert!(p.sha.is_some());
                    let why = p.unavailable.unwrap();
                    assert!(
                        why.starts_with("content conversion declared (") && why.contains(reason),
                        "{attributes}: {why}"
                    );
                }
                None => assert_eq!(p.dirty, Some(false), "{attributes}: {p:?}"),
            }
        }

        let tmp = tempdir().unwrap();
        committed_repo(tmp.path());
        setup_git(tmp.path(), &["config", "core.autocrlf", "input"]);
        let p = provenance(tmp.path());
        assert_eq!(p.dirty, None);
        assert!(p.unavailable.unwrap().contains("core.autocrlf=input"));
    }

    /// A conversion on the compared path makes `unmodified_at_head`
    /// say so rather than compare; one on another path does not.
    #[test]
    fn unmodified_at_head_refuses_a_converted_path() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join(".gitattributes"), "*.sh text eol=crlf\n").unwrap();
        committed_repo(tmp.path());
        let err = unmodified_at_head(tmp.path(), Path::new("run.sh")).unwrap_err();
        assert!(
            err.starts_with("content conversion declared (") && err.contains("on run.sh"),
            "{err}"
        );
        assert_eq!(
            unmodified_at_head(tmp.path(), Path::new("src/a.rs")),
            Ok(())
        );
    }

    #[test]
    fn blob_id_matches_git() {
        // `printf 'hello\n' | git hash-object --stdin`
        assert_eq!(
            blob_id(ObjectFormat::Sha1, b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
    }
}
