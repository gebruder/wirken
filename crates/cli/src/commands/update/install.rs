//! Installing a verified release over the running binary, and rolling
//! back to the one it replaced.
//!
//! An install is one file, `wirken`: the gateway, the adapters and the
//! MCP proxy are its subcommands. It is replaced in place with a
//! same-directory rename, after the current file is kept beside it as
//! `wirken.prev` with a record of its version and sha256, so the swap
//! is atomic and a rollback restores exactly the bytes that ran before.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::manifest::{Manifest, Release, Version};

/// What the gate around an install looks at: whether stdin is a
/// terminal, whether this process runs inside a Wirken `exec`, and the
/// gateway's socket.
pub struct Environment<'a> {
    pub stdin_is_tty: bool,
    pub in_exec: bool,
    pub gateway_socket: &'a Path,
    /// An installed service unit, to name in the refusal when a
    /// gateway is running.
    pub service_unit: Option<ServiceUnit>,
}

/// A service unit `wirken setup --install-service` wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceUnit {
    Systemd(PathBuf),
    Launchd(PathBuf),
}

impl ServiceUnit {
    /// The unit this host has, if `--install-service` wrote one.
    pub fn installed() -> Option<Self> {
        let systemd = super::super::service::systemd_unit_path();
        if systemd.exists() {
            return Some(ServiceUnit::Systemd(systemd));
        }
        let launchd = super::super::service::launchd_plist_path();
        launchd.exists().then_some(ServiceUnit::Launchd(launchd))
    }

    fn stop_command(&self) -> String {
        match self {
            ServiceUnit::Systemd(_) => "systemctl --user stop wirken.service".to_string(),
            ServiceUnit::Launchd(p) => format!("launchctl unload {}", p.display()),
        }
    }
}

/// Refuse unless an operator is at a terminal, outside any Wirken
/// `exec`, with no gateway running.
///
/// The `exec` marker is the environment variable `exec` sets on every
/// command it runs. It stops a model's command from running an update
/// through an `exec` the operator approved for something else; the
/// boundary for what an `exec` may run at all stays the operator's
/// approval of each command.
pub fn preflight(env: &Environment) -> Result<()> {
    if env.in_exec {
        bail!(
            "wirken update refuses to run inside a Wirken exec ({} is set); run it yourself, \
             from a terminal",
            wirken_agent::tool::EXEC_MARKER_ENV
        );
    }
    if !env.stdin_is_tty {
        bail!("wirken update asks for confirmation at a terminal, and stdin is not one");
    }
    if gateway_answers(env.gateway_socket) {
        let stop = match &env.service_unit {
            Some(unit) => format!("stop the service first: {}", unit.stop_command()),
            None => "stop it first (Ctrl+C in its terminal)".to_string(),
        };
        bail!(
            "a gateway is running (it answers on {}); {stop}. Replacing the binary under a \
             running gateway would leave it re-spawning adapters from a file that changed",
            env.gateway_socket.display()
        );
    }
    Ok(())
}

/// Whether a gateway answers on `socket`. A socket file left by a
/// gateway that crashed does not answer and does not count.
pub fn gateway_answers(socket: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(socket).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = socket;
        false
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

/// The artifact name for a target.
pub fn artifact_name(target: &str) -> String {
    format!("wirken-{target}")
}

/// Refuse unless the running binary is a release binary: its sha256
/// is the manifest's for its own version and target. Returns that
/// sha256.
pub fn require_release_binary(
    manifest: &Manifest,
    current: Version,
    target: &str,
    exe: &Path,
) -> Result<String> {
    let rebuild = "it was not installed from a release (a source or local build); update it by \
                   rebuilding from source";
    let Some(release) = manifest.release(current) else {
        bail!("this binary's version, {current}, is not in releases.json, so {rebuild}");
    };
    let Some(expected) = release.artifacts.get(&artifact_name(target)) else {
        bail!("release {current} publishes no artifact for {target}, so {rebuild}");
    };
    let actual = sha256_file(exe)?;
    if &actual != expected {
        bail!(
            "{} is not the {current} release artifact for {target} (sha256 {actual}, the release \
             has {expected}), so {rebuild}",
            exe.display()
        );
    }
    Ok(actual)
}

/// The release to install: `to` if given, else the latest. `None` when
/// it is the installed version. An older version is refused unless
/// `allow_downgrade`.
pub fn choose_release(
    manifest: &Manifest,
    current: Version,
    to: Option<Version>,
    allow_downgrade: bool,
) -> Result<Option<&Release>> {
    let release = match to {
        Some(v) => manifest
            .release(v)
            .with_context(|| format!("releases.json lists no {v}"))?,
        None => manifest.latest(),
    };
    let version = release.parsed_version();
    if version == current {
        return Ok(None);
    }
    if version < current && !allow_downgrade {
        bail!(
            "{version} is older than the installed {current}; pass --allow-downgrade to install \
             it anyway"
        );
    }
    Ok(Some(release))
}

/// Refuse downloaded bytes whose sha256 is not the manifest's.
pub fn verify_artifact(bytes: &[u8], release: &Release, target: &str) -> Result<String> {
    let name = artifact_name(target);
    let expected = release
        .artifacts
        .get(&name)
        .with_context(|| format!("release {} publishes no {name}", release.version))?;
    let actual = sha256_hex(bytes);
    if &actual != expected {
        bail!(
            "downloaded {name} has sha256 {actual}, but releases.json has {expected}; nothing \
             was installed"
        );
    }
    Ok(actual)
}

/// Ask for the confirmation `expected`, typed in full.
pub fn confirm(
    prompt: &str,
    expected: &str,
    mut input: impl BufRead,
    mut out: impl Write,
) -> Result<()> {
    write!(out, "{prompt} Type {expected} to continue: ")?;
    out.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    if line.trim() != expected {
        bail!("not confirmed; nothing was changed");
    }
    Ok(())
}

/// What `wirken.prev` holds, recorded beside it as `wirken.prev.json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Kept {
    pub version: String,
    pub sha256: String,
    /// The release key whose signed manifest this binary's sha256 was
    /// checked against when it was set aside, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifying_key: Option<String>,
}

fn sibling(exe: &Path, suffix: &str) -> Result<PathBuf> {
    let name = exe
        .file_name()
        .with_context(|| format!("{} has no file name", exe.display()))?
        .to_string_lossy();
    Ok(exe.with_file_name(format!("{name}{suffix}")))
}

pub fn prev_path(exe: &Path) -> Result<PathBuf> {
    sibling(exe, ".prev")
}

fn kept_path(exe: &Path) -> Result<PathBuf> {
    sibling(exe, ".prev.json")
}

/// A same-directory temporary name, so the final rename is atomic.
fn temp_beside(exe: &Path, tag: &str) -> Result<PathBuf> {
    sibling(exe, &format!(".{tag}.{}.tmp", std::process::id()))
}

/// Keep `from`'s bytes at `to` without a window where `to` is missing:
/// a hard link (or copy) to a temporary name, then a rename over `to`.
fn keep_as(from: &Path, to: &Path, exe: &Path) -> Result<()> {
    let tmp = temp_beside(exe, "keep")?;
    let _ = std::fs::remove_file(&tmp);
    if std::fs::hard_link(from, &tmp).is_err() {
        std::fs::copy(from, &tmp)
            .with_context(|| format!("copy {} to {}", from.display(), tmp.display()))?;
    }
    std::fs::rename(&tmp, to).with_context(|| format!("rename to {}", to.display()))
}

fn write_kept(exe: &Path, kept: &Kept) -> Result<()> {
    let path = kept_path(exe)?;
    let tmp = temp_beside(exe, "kept")?;
    std::fs::write(&tmp, serde_json::to_vec_pretty(kept)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("replace {}", path.display()))
}

fn sync_dir(dir: &Path) {
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

/// Replace `exe` with `bytes`, keeping the current file as
/// `wirken.prev`, recorded as `current`.
pub fn install(exe: &Path, bytes: &[u8], current: &Kept) -> Result<()> {
    let dir = exe.parent().context("the binary has no directory")?;
    let new = temp_beside(exe, "new")?;
    let result = (|| -> Result<()> {
        {
            let mut f = std::fs::File::create(&new).with_context(|| {
                format!("create {} (is the directory writable?)", new.display())
            })?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
        }
        keep_as(exe, &prev_path(exe)?, exe)?;
        write_kept(exe, current)?;
        std::fs::rename(&new, exe).with_context(|| format!("replace {}", exe.display()))?;
        sync_dir(dir);
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&new);
    }
    result
}

/// What a rollback did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolledBack {
    /// The version that was running and is now kept.
    pub from: String,
    /// The version restored, and its sha256.
    pub to: Kept,
}

/// The kept binary, checked against its record.
pub fn kept(exe: &Path) -> Result<Kept> {
    let prev = prev_path(exe)?;
    let path = kept_path(exe)?;
    let kept: Kept = serde_json::from_slice(
        &std::fs::read(&path)
            .with_context(|| format!("no {}: nothing to roll back to", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    let actual = sha256_file(&prev)?;
    if actual != kept.sha256 {
        bail!(
            "{} has sha256 {actual}, not the {} it was kept as; refusing to restore it",
            prev.display(),
            kept.sha256
        );
    }
    Ok(kept)
}

/// Swap `wirken.prev` back in, keeping the running file as the new
/// `wirken.prev`, recorded as `current_version`.
pub fn rollback(exe: &Path, current_version: &str) -> Result<RolledBack> {
    let restored = kept(exe)?;
    let prev = prev_path(exe)?;
    let dir = exe.parent().context("the binary has no directory")?;
    let running = Kept {
        version: current_version.to_string(),
        sha256: sha256_file(exe)?,
        verifying_key: None,
    };
    let hold = temp_beside(exe, "hold")?;
    let _ = std::fs::remove_file(&hold);
    if std::fs::hard_link(exe, &hold).is_err() {
        std::fs::copy(exe, &hold).with_context(|| format!("copy {}", exe.display()))?;
    }
    std::fs::rename(&prev, exe).with_context(|| format!("restore {}", exe.display()))?;
    std::fs::rename(&hold, &prev).with_context(|| format!("keep {}", prev.display()))?;
    write_kept(exe, &running)?;
    sync_dir(dir);
    Ok(RolledBack {
        from: current_version.to_string(),
        to: restored,
    })
}

#[cfg(test)]
mod tests {
    use super::super::manifest::tests::release;
    use super::*;

    fn manifest(releases: Vec<Release>) -> Manifest {
        let mut releases = releases;
        releases.sort_by_key(|r| std::cmp::Reverse(r.parsed_version()));
        Manifest {
            issued_at: "2026-10-20T00:00:00Z".parse().unwrap(),
            releases,
        }
    }

    const T: &str = "x86_64-unknown-linux-musl";

    #[test]
    fn a_non_terminal_invocation_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("gateway.sock");
        let err = preflight(&Environment {
            stdin_is_tty: false,
            in_exec: false,
            gateway_socket: &sock,
            service_unit: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("not one"), "{err:#}");
    }

    #[test]
    fn an_invocation_inside_an_exec_is_refused_first() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("gateway.sock");
        let err = preflight(&Environment {
            stdin_is_tty: true,
            in_exec: true,
            gateway_socket: &sock,
            service_unit: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("inside a Wirken exec"), "{err:#}");
    }

    #[cfg(unix)]
    #[test]
    fn a_running_gateway_is_detected_and_a_stale_socket_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("gateway.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(gateway_answers(&sock));
        let err = preflight(&Environment {
            stdin_is_tty: true,
            in_exec: false,
            gateway_socket: &sock,
            service_unit: Some(ServiceUnit::Systemd("/x/wirken.service".into())),
        })
        .unwrap_err();
        assert!(err.to_string().contains("a gateway is running"), "{err:#}");
        assert!(
            err.to_string()
                .contains("systemctl --user stop wirken.service"),
            "{err:#}"
        );
        // The socket file left behind by a gateway that is gone.
        drop(listener);
        assert!(!gateway_answers(&sock));
        assert!(
            preflight(&Environment {
                stdin_is_tty: true,
                in_exec: false,
                gateway_socket: &sock,
                service_unit: None,
            })
            .is_ok()
        );
    }

    #[test]
    fn a_non_release_binary_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("wirken");
        std::fs::write(&exe, b"a local build").unwrap();
        let release_sha = sha256_hex(b"the release artifact");
        let m = manifest(vec![release(
            "2.2.0",
            false,
            &[(&artifact_name(T), &release_sha)],
        )]);
        let v = Version::parse("2.2.0").unwrap();
        let err = require_release_binary(&m, v, T, &exe).unwrap_err();
        assert!(
            err.to_string().contains("rebuilding from source"),
            "{err:#}"
        );
        // A version the manifest does not list, and a target it has no
        // artifact for, are refused the same way.
        assert!(require_release_binary(&m, Version::parse("9.9.9").unwrap(), T, &exe).is_err());
        assert!(require_release_binary(&m, v, "x86_64-unknown-linux-gnu", &exe).is_err());
        std::fs::write(&exe, b"the release artifact").unwrap();
        assert_eq!(require_release_binary(&m, v, T, &exe).unwrap(), release_sha);
    }

    #[test]
    fn a_downgrade_is_refused_and_allowed_with_the_flag() {
        let sha = sha256_hex(b"x");
        let a = [(artifact_name(T), sha)];
        let a: Vec<(&str, &str)> = a.iter().map(|(n, s)| (n.as_str(), s.as_str())).collect();
        let m = manifest(vec![
            release("2.2.0", false, &a),
            release("2.3.0", false, &a),
            release("2.4.0", false, &a),
        ]);
        let current = Version::parse("2.3.0").unwrap();
        assert_eq!(
            choose_release(&m, current, None, false)
                .unwrap()
                .unwrap()
                .version,
            "2.4.0"
        );
        let older = Some(Version::parse("2.2.0").unwrap());
        let err = choose_release(&m, current, older, false).unwrap_err();
        assert!(err.to_string().contains("--allow-downgrade"), "{err:#}");
        assert_eq!(
            choose_release(&m, current, older, true)
                .unwrap()
                .unwrap()
                .version,
            "2.2.0"
        );
        assert!(
            choose_release(&m, current, Some(current), false)
                .unwrap()
                .is_none()
        );
        assert!(
            choose_release(&m, current, Some(Version::parse("3.0.0").unwrap()), false).is_err()
        );
    }

    #[test]
    fn downloaded_bytes_must_match_the_manifest() {
        let good = b"release bytes";
        let r = release("2.4.0", false, &[(&artifact_name(T), &sha256_hex(good))]);
        assert!(verify_artifact(good, &r, T).is_ok());
        let err = verify_artifact(b"other bytes", &r, T).unwrap_err();
        assert!(err.to_string().contains("nothing was installed"), "{err:#}");
    }

    #[test]
    fn confirmation_must_be_typed_in_full() {
        let mut out = Vec::new();
        assert!(
            confirm(
                "Install?",
                "2.4.0",
                std::io::Cursor::new("2.4.0\n"),
                &mut out
            )
            .is_ok()
        );
        for typed in ["y\n", "yes\n", "\n", "", "2.4\n"] {
            assert!(
                confirm("Install?", "2.4.0", std::io::Cursor::new(typed), Vec::new()).is_err(),
                "{typed:?}"
            );
        }
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("Type 2.4.0 to continue")
        );
    }

    #[test]
    fn install_swaps_atomically_and_rollback_restores_the_previous_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("wirken");
        std::fs::write(&exe, b"version 2.3.0").unwrap();
        let old = Kept {
            version: "2.3.0".into(),
            sha256: sha256_hex(b"version 2.3.0"),
            verifying_key: Some("SHA256:test".into()),
        };
        install(&exe, b"version 2.4.0", &old).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"version 2.4.0");
        assert_eq!(
            std::fs::read(prev_path(&exe).unwrap()).unwrap(),
            b"version 2.3.0"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&exe).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        // No temporary file is left behind.
        let names: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");

        let back = rollback(&exe, "2.4.0").unwrap();
        assert_eq!(back.to, old);
        assert_eq!(std::fs::read(&exe).unwrap(), b"version 2.3.0");
        // And the rollback is itself reversible.
        assert_eq!(
            std::fs::read(prev_path(&exe).unwrap()).unwrap(),
            b"version 2.4.0"
        );
        assert_eq!(kept(&exe).unwrap().version, "2.4.0");
    }

    #[test]
    fn a_kept_binary_that_changed_is_not_restored() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("wirken");
        std::fs::write(&exe, b"old").unwrap();
        install(
            &exe,
            b"new",
            &Kept {
                version: "2.3.0".into(),
                sha256: sha256_hex(b"old"),
                verifying_key: None,
            },
        )
        .unwrap();
        std::fs::write(prev_path(&exe).unwrap(), b"swapped by someone").unwrap();
        let err = rollback(&exe, "2.4.0").unwrap_err();
        assert!(err.to_string().contains("refusing to restore"), "{err:#}");
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
    }

    #[test]
    fn rollback_without_a_kept_binary_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("wirken");
        std::fs::write(&exe, b"only").unwrap();
        let err = rollback(&exe, "2.4.0").unwrap_err();
        assert!(
            format!("{err:#}").contains("nothing to roll back to"),
            "{err:#}"
        );
    }
}
