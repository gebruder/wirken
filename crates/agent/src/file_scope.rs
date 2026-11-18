//! A limit the harness sets on what an agent's file tools may touch,
//! inside what its skills allow.
//!
//! Skill permissions are a union over every attached skill, so they
//! cannot say "this agent, and not the one beside it under the same
//! skills". A [`FileScope`] can: writes go under one directory, and
//! reads under a masked directory are refused unless the harness says
//! the file is one the agent may read. It narrows the profile and
//! never widens it: a path the profile refuses stays refused.
//!
//! A path is compared as the file it names. `..` and `.` are folded,
//! and the part of the path that exists is resolved through symlinks,
//! so a link placed inside the writable directory does not reach
//! outside it.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// Says whether a path under a masked directory may be read.
pub type ReadableUnderMask = Arc<dyn Fn(&Path) -> bool + Send + Sync>;

#[derive(Clone)]
pub struct FileScope {
    write_root: PathBuf,
    masked: Vec<PathBuf>,
    readable_under_mask: ReadableUnderMask,
}

impl std::fmt::Debug for FileScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileScope")
            .field("write_root", &self.write_root)
            .field("masked", &self.masked)
            .finish_non_exhaustive()
    }
}

impl FileScope {
    /// Writes only under `write_root`; nothing under a `masked`
    /// directory is read unless `readable_under_mask` says so of the
    /// resolved path. The directories are absolute.
    pub fn new(
        write_root: &Path,
        masked: &[PathBuf],
        readable_under_mask: ReadableUnderMask,
    ) -> Self {
        Self {
            write_root: resolve(write_root),
            masked: masked.iter().map(|m| resolve(m)).collect(),
            readable_under_mask,
        }
    }

    pub fn allows_write(&self, path: &Path) -> bool {
        resolve(path).starts_with(&self.write_root)
    }

    pub fn allows_read(&self, path: &Path) -> bool {
        let path = resolve(path);
        if self.masked.iter().any(|m| path.starts_with(m)) {
            return (self.readable_under_mask)(&path);
        }
        true
    }
}

/// `path` as the file it names: `.` and `..` folded, and the longest
/// part of it that exists resolved through symlinks.
pub fn resolve(path: &Path) -> PathBuf {
    let mut folded = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                folded.pop();
            }
            other => folded.push(other),
        }
    }
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    let mut existing = folded.clone();
    loop {
        if let Ok(real) = existing.canonicalize() {
            let mut out = real;
            out.extend(rest.iter().rev());
            return out;
        }
        match existing.file_name() {
            Some(name) => rest.push(name.to_os_string()),
            None => return folded,
        }
        if !existing.pop() {
            return folded;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(root: &Path) -> FileScope {
        let other = root.join("staging/other");
        let listed = other.join("findings");
        FileScope::new(
            &root.join("staging/own"),
            &[other],
            Arc::new(move |p: &Path| p.parent() == Some(listed.as_path())),
        )
    }

    #[test]
    fn writes_stay_under_the_one_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("staging/own")).unwrap();
        std::fs::create_dir_all(root.join("staging/other/findings")).unwrap();
        let s = scope(&root);
        assert!(s.allows_write(&root.join("staging/own/findings/f.json")));
        assert!(!s.allows_write(&root.join("staging/other/findings/f.json")));
        assert!(!s.allows_write(&root.join("staging/index.json")));
        assert!(!s.allows_write(&root.join("src/main.rs")));
        // Folded before it is compared.
        assert!(!s.allows_write(&root.join("staging/own/../other/x")));
        assert!(!s.allows_write(&root.join("staging/own/../../src/main.rs")));
    }

    #[test]
    fn a_masked_directory_is_read_only_where_the_harness_says() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("staging/own")).unwrap();
        std::fs::create_dir_all(root.join("staging/other/findings")).unwrap();
        std::fs::create_dir_all(root.join("staging/other/harness")).unwrap();
        let s = scope(&root);
        assert!(s.allows_read(&root.join("src/main.rs")));
        assert!(s.allows_read(&root.join("staging/index.json")));
        assert!(s.allows_read(&root.join("staging/own/harness/h.sh")));
        assert!(s.allows_read(&root.join("staging/other/findings/finding-001.json")));
        assert!(!s.allows_read(&root.join("staging/other")));
        assert!(!s.allows_read(&root.join("staging/other/findings")));
        assert!(!s.allows_read(&root.join("staging/other/harness/h.sh")));
        assert!(!s.allows_read(&root.join("staging/own/../other/harness/h.sh")));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_inside_the_writable_directory_does_not_reach_outside_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("staging/own")).unwrap();
        std::fs::create_dir_all(root.join("staging/other/harness")).unwrap();
        std::os::unix::fs::symlink(root.join("staging/other"), root.join("staging/own/link"))
            .unwrap();
        let s = scope(&root);
        assert!(!s.allows_write(&root.join("staging/own/link/harness/new.sh")));
        assert!(!s.allows_read(&root.join("staging/own/link/harness/h.sh")));
    }
}
