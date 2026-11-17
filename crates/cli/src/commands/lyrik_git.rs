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
//! - Where git would convert content, the work-tree bytes need not be
//!   the blob's. A file whose bytes are the blob's is unchanged
//!   whatever is declared for it. One that differs under line-ending
//!   conversion alone is compared again with its line endings
//!   normalised, which is all that conversion does. One that differs
//!   under a filter (LFS among them), `ident` or an encoding cannot
//!   be compared without running the conversion, so it is not, and
//!   the reason is returned. `git config --get` and `git check-attr`
//!   tell which applies; both only read config and attributes files.
//! - Whether the tracked files changed between two moments needs no
//!   comparison with HEAD at all: [`tree_fingerprint`] hashes them as
//!   they are on disk, and two fingerprints are compared.

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
    let dirty = repo
        .head_entries()
        .and_then(|entries| repo.tracked_changes(&entries));
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

/// Attributes that hand content to something this process will not
/// run or reproduce: a filter program, `$Id$` expansion, re-encoding.
const EXTERNAL_CONVERSIONS: &[&str] = &["filter", "ident", "working-tree-encoding"];

/// `core.autocrlf` when it is set to anything but `false`.
fn autocrlf(dir: &Path) -> Result<Option<String>, String> {
    let out = git(dir)
        .args(["config", "--get", "core.autocrlf"])
        .output()
        .map_err(|e| format!("run git: {e}"))?;
    match out.status.code() {
        Some(0) => {
            let value = trimmed(out.stdout);
            Ok((value != "false").then_some(value))
        }
        // Unset.
        Some(1) => Ok(None),
        _ => Err(format!(
            "git config --get core.autocrlf: {}",
            trimmed(out.stderr)
        )),
    }
}

/// Every conversion attribute set on any of `paths` (relative to
/// `dir`), as `(path, attribute, value)`, in `git check-attr` order.
/// `git check-attr` only reads attributes files; it runs no filter.
fn conversion_attributes(
    dir: &Path,
    paths: &[&Path],
) -> Result<Vec<(PathBuf, String, String)>, String> {
    if paths.is_empty() {
        return Ok(Vec::new());
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
    let mut set = Vec::new();
    for [path, attribute, value] in fields.as_chunks::<3>().0 {
        let value = String::from_utf8_lossy(value);
        if value != "unspecified" && value != "unset" {
            set.push((
                path_from_bytes(path),
                String::from_utf8_lossy(attribute).into_owned(),
                value.into_owned(),
            ));
        }
    }
    Ok(set)
}

/// The first content conversion that applies to any of `paths`
/// (relative to `dir`), through `core.autocrlf` or an attribute from
/// any attributes file.
fn conversion_declared(dir: &Path, paths: &[&Path]) -> Result<Option<String>, String> {
    if let Some(value) = autocrlf(dir)? {
        return Ok(Some(format!("core.autocrlf={value}")));
    }
    Ok(conversion_attributes(dir, paths)?
        .into_iter()
        .next()
        .map(|(path, attribute, value)| format!("{attribute}={value} on {}", path.display())))
}

/// A digest of every tracked file as it is on disk now: its path, what
/// kind of thing is there and its bytes, and for a submodule the commit
/// it is at. Two digests taken at two moments are equal exactly when no
/// tracked file changed between them. Nothing is compared with HEAD
/// and no content is converted, so a filter, a line-ending rule or a
/// tree that was already modified does not stand in the way.
pub fn tree_fingerprint(target: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let repo = Repo::open(target)?;
    repo.head()?;
    let mut h = Sha256::new();
    for entry in repo.head_entries()? {
        let path = repo.toplevel.join(&entry.path);
        h.update(entry.path.as_os_str().as_encoded_bytes());
        h.update([0]);
        let state = match entry.kind.as_str() {
            "blob" => match repo.work_bytes(&entry, &path)? {
                Some(bytes) => blob_id(repo.format, &bytes),
                None => "not as tracked".to_string(),
            },
            "commit" => match path.join(".git").exists() {
                false => "not checked out".to_string(),
                true => run_git(
                    &path,
                    &["rev-parse", "--verify", "-q", "HEAD^{commit}"],
                    None,
                )
                .map(trimmed)
                .unwrap_or_else(|_| "no commit".to_string()),
            },
            other => return Err(format!("unexpected tree entry kind {other}")),
        };
        h.update(state.as_bytes());
        h.update([0]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
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
    /// bytes, or a submodule at a different commit. A file under a
    /// declared conversion is compared as the module doc says; `Err`
    /// when the only differences found are ones that cannot be told
    /// from the conversion's own doing.
    fn tracked_changes(&self, entries: &[TreeEntry]) -> Result<bool, String> {
        let blobs: Vec<&Path> = entries
            .iter()
            .filter(|e| e.kind == "blob")
            .map(|e| e.path.as_path())
            .collect();
        let autocrlf = autocrlf(&self.toplevel)?;
        let mut declared: std::collections::HashMap<PathBuf, Vec<(String, String)>> =
            std::collections::HashMap::new();
        for (path, attribute, value) in conversion_attributes(&self.toplevel, &blobs)? {
            declared.entry(path).or_default().push((attribute, value));
        }
        let mut uncompared: Vec<String> = Vec::new();
        for entry in entries {
            let path = self.toplevel.join(&entry.path);
            match entry.kind.as_str() {
                "blob" => {
                    let Some(bytes) = self.work_bytes(entry, &path)? else {
                        return Ok(true);
                    };
                    if blob_id(self.format, &bytes) == entry.oid {
                        continue;
                    }
                    let attributes = declared.get(&entry.path);
                    if let Some((attribute, value)) = attributes.and_then(|set| {
                        set.iter()
                            .find(|(a, _)| EXTERNAL_CONVERSIONS.contains(&a.as_str()))
                    }) {
                        uncompared.push(format!("{attribute}={value} on {}", entry.path.display()));
                        continue;
                    }
                    // Line-ending conversion is all that is left, and
                    // all it does is turn LF into CRLF on the way out.
                    let line_endings = attributes.is_some() || autocrlf.is_some();
                    if line_endings && blob_id(self.format, &lf_only(&bytes)) == entry.oid {
                        continue;
                    }
                    return Ok(true);
                }
                "commit" => {
                    if submodule_differs(entry, &path)? {
                        return Ok(true);
                    }
                }
                other => return Err(format!("unexpected tree entry kind {other}")),
            }
        }
        match uncompared.first() {
            None => Ok(false),
            Some(first) => Err(format!(
                "content conversion declared ({first}); {} tracked file(s) differ from HEAD's \
                 bytes and cannot be compared without running the conversion",
                uncompared.len()
            )),
        }
    }

    /// The bytes git would hash for `entry` as it is in the work tree:
    /// a file's content or a symlink's target. `None` when what is
    /// there is missing, another kind of file, or has another
    /// executable bit.
    fn work_bytes(&self, entry: &TreeEntry, path: &Path) -> Result<Option<Vec<u8>>, String> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("stat {}: {e}", entry.path.display())),
        };
        match entry.mode.as_str() {
            "120000" => {
                if !meta.file_type().is_symlink() {
                    return Ok(None);
                }
                let link = std::fs::read_link(path)
                    .map_err(|e| format!("readlink {}: {e}", entry.path.display()))?;
                Ok(Some(link.into_os_string().into_encoded_bytes()))
            }
            "100644" | "100755" => {
                if !meta.file_type().is_file() || executable(&meta) != (entry.mode == "100755") {
                    return Ok(None);
                }
                std::fs::read(path)
                    .map(Some)
                    .map_err(|e| format!("read {}: {e}", entry.path.display()))
            }
            other => Err(format!("unexpected blob mode {other}")),
        }
    }

    fn blob_differs(&self, entry: &TreeEntry, path: &Path) -> Result<bool, String> {
        Ok(match self.work_bytes(entry, path)? {
            Some(bytes) => blob_id(self.format, &bytes) != entry.oid,
            None => true,
        })
    }
}

/// `bytes` with every CRLF turned into LF.
fn lf_only(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
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

    /// A declared conversion does not leave a clean tree unknown: a
    /// file whose bytes are the blob's is unchanged whatever is
    /// declared for it.
    #[test]
    fn a_clean_tree_under_a_declared_conversion_is_not_dirty() {
        for attributes in [
            "*.rs filter=lfs diff=lfs merge=lfs -text\n",
            "* text=auto\n",
            "*.sh eol=crlf\n",
            "*.rs ident\n",
            "*.rs -text\n",
        ] {
            let tmp = tempdir().unwrap();
            std::fs::write(tmp.path().join(".gitattributes"), attributes).unwrap();
            committed_repo(tmp.path());
            let p = provenance(tmp.path());
            assert_eq!(p.dirty, Some(false), "{attributes}: {p:?}");
            assert!(p.sha.is_some());
        }
        let tmp = tempdir().unwrap();
        committed_repo(tmp.path());
        setup_git(tmp.path(), &["config", "core.autocrlf", "input"]);
        assert_eq!(provenance(tmp.path()).dirty, Some(false));
    }

    /// Under line-ending conversion a file that differs only in its
    /// line endings is unchanged and one with other bytes is dirty.
    #[test]
    fn line_ending_conversion_is_compared_with_line_endings_normalised() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join(".gitattributes"), "*.sh text eol=crlf\n").unwrap();
        committed_repo(tmp.path());
        let script = tmp.path().join("run.sh");
        let lf = std::fs::read_to_string(&script).unwrap();
        assert!(!lf.contains('\r'));
        std::fs::write(&script, lf.replace('\n', "\r\n")).unwrap();
        assert_eq!(provenance(tmp.path()).dirty, Some(false));
        std::fs::write(
            &script,
            format!("{}echo more\r\n", lf.replace('\n', "\r\n")),
        )
        .unwrap();
        assert_eq!(provenance(tmp.path()).dirty, Some(true));

        // With no conversion declared, CRLF in place of LF is a change.
        let plain = tempdir().unwrap();
        committed_repo(plain.path());
        let script = plain.path().join("run.sh");
        let lf = std::fs::read_to_string(&script).unwrap();
        std::fs::write(&script, lf.replace('\n', "\r\n")).unwrap();
        assert_eq!(provenance(plain.path()).dirty, Some(true));
    }

    /// A file that differs under a filter cannot be told from the
    /// filter's own output: unknown, with the reason. A changed file
    /// under no filter in the same tree still reads as dirty.
    #[test]
    fn a_difference_under_a_filter_is_unknown_and_one_outside_it_is_dirty() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join(".gitattributes"), "*.rs filter=lfs -text\n").unwrap();
        committed_repo(tmp.path());
        std::fs::write(tmp.path().join("src/a.rs"), "fn other() {}\n").unwrap();
        let p = provenance(tmp.path());
        assert_eq!(p.dirty, None, "{p:?}");
        let why = p.unavailable.unwrap();
        assert!(
            why.starts_with("content conversion declared (filter=lfs on src/a.rs)"),
            "{why}"
        );
        let script = tmp.path().join("run.sh");
        let body = std::fs::read_to_string(&script).unwrap();
        std::fs::write(&script, format!("{body}echo more\n")).unwrap();
        assert_eq!(provenance(tmp.path()).dirty, Some(true));
    }

    /// The fingerprint changes when a tracked file's bytes, kind or
    /// executable bit change and at no other time: not for an untracked
    /// file, and it needs no clean tree and no comparable content.
    #[test]
    fn tree_fingerprint_tells_whether_tracked_files_changed() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join(".gitattributes"), "*.rs filter=lfs -text\n").unwrap();
        committed_repo(tmp.path());
        // Already modified under a filter: HEAD comparison is unknown.
        std::fs::write(tmp.path().join("src/a.rs"), "fn other() {}\n").unwrap();
        assert_eq!(provenance(tmp.path()).dirty, None);
        let before = tree_fingerprint(tmp.path()).unwrap();
        assert_eq!(tree_fingerprint(tmp.path()).unwrap(), before);
        std::fs::write(tmp.path().join("untracked.txt"), "x").unwrap();
        assert_eq!(tree_fingerprint(tmp.path()).unwrap(), before);
        std::fs::write(tmp.path().join("src/a.rs"), "fn third() {}\n").unwrap();
        let edited = tree_fingerprint(tmp.path()).unwrap();
        assert_ne!(edited, before);
        std::fs::remove_file(tmp.path().join("run.sh")).unwrap();
        assert_ne!(tree_fingerprint(tmp.path()).unwrap(), edited);
        assert!(tree_fingerprint(&tmp.path().join("nowhere")).is_err());
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
