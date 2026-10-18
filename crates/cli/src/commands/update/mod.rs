//! `wirken update`: an operator-run check for, and install of, a
//! signed Wirken release.
//!
//! It runs only when the operator asks. Nothing checks for updates on
//! a timer, in the background or at gateway start. A release manifest
//! is fetched through Wirken's egress client from GitHub, or from a
//! mirror the operator names, and verified against the release keys
//! compiled into this binary before anything in it is read.

pub mod fetch;
pub mod install;
pub mod manifest;

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use fetch::{Fetcher, Source};
use manifest::{Release, VerifiedManifest, Version};

/// `<data_dir>/update.json`, the operator's update settings.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    /// A local mirror of the release files, used instead of GitHub.
    pub mirror: Option<String>,
}

pub fn load_config(data_dir: &Path) -> Result<UpdateConfig> {
    let path = data_dir.join("update.json");
    match std::fs::read(&path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UpdateConfig::default()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// What `--check` found.
#[derive(Debug)]
pub struct CheckReport {
    pub source: String,
    pub current: Version,
    pub target: String,
    pub verified: VerifiedManifest,
    /// Releases newer than the current one, newest first.
    pub newer: Vec<Release>,
}

impl CheckReport {
    pub fn latest(&self) -> &Release {
        self.verified.manifest.latest()
    }

    pub fn security(&self) -> Vec<&Release> {
        self.newer.iter().filter(|r| r.security).collect()
    }

    pub fn render(&self) -> String {
        let m = &self.verified.manifest;
        let latest = self.latest();
        let mut out = format!(
            "  installed  {} ({})\n  latest     {} ({})\n  manifest   issued {} from {}, signed by {}\n",
            self.current,
            self.target,
            latest.version,
            latest.issued_at.format("%Y-%m-%d"),
            m.issued_at.format("%Y-%m-%dT%H:%M:%SZ"),
            self.source,
            self.verified.key_fingerprint,
        );
        if self.newer.is_empty() {
            out.push_str("  Up to date.\n");
            return out;
        }
        let security = self.security();
        if security.is_empty() {
            out.push_str(&format!(
                "  {} newer release(s); none carries security fixes.\n",
                self.newer.len()
            ));
        } else {
            out.push_str(&format!(
                "  Security fixes in: {}\n",
                security
                    .iter()
                    .map(|r| r.version.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            for r in security {
                out.push_str(&format!("    {}  {}\n", r.version, r.summary));
            }
        }
        if !latest
            .artifacts
            .contains_key(&format!("wirken-{}", self.target))
        {
            out.push_str(&format!(
                "  {} publishes no artifact for {}.\n",
                latest.version, self.target
            ));
        }
        out
    }
}

/// Fetch, verify and freshness-check the manifest, and compare it with
/// the running version. `keys` is the pinned release key set.
pub async fn check(
    data_dir: &Path,
    fetcher: &Fetcher,
    keys: &[[u8; 32]],
    current: &str,
    target: &str,
) -> Result<CheckReport> {
    let current = Version::parse(current)?;
    let source = fetcher.source();
    let body = fetcher
        .get(
            source.manifest_url(),
            manifest::MAX_MANIFEST_BYTES,
            Duration::from_secs(60),
        )
        .await
        .with_context(|| {
            format!(
                "fetch releases.json from {}; releases before 2.3.0 publish none",
                source.describe()
            )
        })?;
    let sig = fetcher
        .get(
            source.signature_url(),
            manifest::MAX_SIGNATURE_BYTES,
            Duration::from_secs(60),
        )
        .await?;
    let verified = manifest::verify(&body, &sig, keys)?;
    manifest::check_and_record_freshness(data_dir, &verified)?;
    let newer = verified
        .manifest
        .releases
        .iter()
        .filter(|r| r.parsed_version() > current)
        .cloned()
        .collect();
    Ok(CheckReport {
        source: source.describe(),
        current,
        target: target.to_string(),
        verified,
        newer,
    })
}

/// Refuse on a platform `wirken update` does not install on.
pub fn require_supported_platform() -> Result<()> {
    if cfg!(windows) {
        bail!("wirken update does not install on Windows; reinstall from the release page");
    }
    Ok(())
}

/// The audit lane install and rollback rows go to, outside any session.
pub const INSTALL_LANE: &str = "gateway-install";

/// Append `event` to the install lane of `log` and seal it with a chain
/// head, so the row is covered by a signature as soon as it is written.
pub fn record_on(
    log: &wirken_audit::SqliteSessionLog,
    event: wirken_audit::SessionEvent,
) -> Result<()> {
    use wirken_audit::SessionLog as _;
    let handle = log.handle_for(wirken_audit::SessionId::new(INSTALL_LANE.to_string()));
    log.append(&handle, wirken_audit::TrustLevel::User, event)
        .context("append the install row")?;
    super::seal_operator_lane(log, INSTALL_LANE);
    Ok(())
}

/// Record an install or rollback on this install's signed chain. Called
/// after the file is swapped, so the row says what happened, not what
/// was about to.
fn record(event: wirken_audit::SessionEvent) -> Result<()> {
    let cfg = super::config();
    let log = super::open_signed_session_log(&cfg)?;
    record_on(&log, event).with_context(|| {
        format!("the binary was swapped, but its {INSTALL_LANE} audit row could not be written")
    })
}

/// The largest release artifact accepted.
const MAX_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;

/// `wirken update`, `--check` or `--rollback`.
pub async fn run(
    check: bool,
    rollback: bool,
    to: Option<String>,
    allow_downgrade: bool,
    base_url: Option<&str>,
) -> Result<()> {
    if check {
        run_check(base_url).await
    } else if rollback {
        run_rollback().await
    } else {
        run_install(base_url, to.as_deref(), allow_downgrade).await
    }
}

/// The gate an install and a rollback pass before anything else.
fn operator_preflight() -> Result<()> {
    let cfg = super::config();
    let socket = cfg.socket_dir().join("gateway.sock");
    install::preflight(&install::Environment {
        stdin_is_tty: super::oauth_scope::stdin_is_tty(),
        in_exec: std::env::var_os(wirken_agent::tool::EXEC_MARKER_ENV).is_some(),
        gateway_socket: &socket,
        service_unit: install::ServiceUnit::installed(),
    })
}

fn running_binary() -> Result<std::path::PathBuf> {
    std::env::current_exe().context("resolve the running binary")
}

/// Ask for a typed confirmation on the terminal.
async fn confirm(prompt: String, expected: String) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        install::confirm(
            &prompt,
            &expected,
            std::io::stdin().lock(),
            std::io::stderr(),
        )
    })
    .await
    .context("confirmation prompt")?
}

fn restart_hint() -> String {
    match install::ServiceUnit::installed() {
        Some(install::ServiceUnit::Systemd(_)) => {
            "Start the gateway again: systemctl --user start wirken.service".to_string()
        }
        Some(install::ServiceUnit::Launchd(p)) => {
            format!("Start the gateway again: launchctl load {}", p.display())
        }
        None => "Start the gateway again with `wirken run`.".to_string(),
    }
}

/// `wirken update`: install the latest release, or `to`.
pub async fn run_install(
    base_url: Option<&str>,
    to: Option<&str>,
    allow_downgrade: bool,
) -> Result<()> {
    require_supported_platform()?;
    operator_preflight()?;
    let cfg = super::config();
    let settings = load_config(&cfg.data_dir)?;
    let source = Source::choose(base_url, settings.mirror.as_deref())?;
    let keys = wirken_gateway::release_keys::pinned(wirken_gateway::release_keys::RELEASE_KEYS)
        .context("pinned release keys")?;
    let fetcher = Fetcher::new(source);
    let target = crate::build_info::TARGET;
    let report = check(
        &cfg.data_dir,
        &fetcher,
        &keys,
        crate::build_info::VERSION,
        target,
    )
    .await?;
    let manifest = &report.verified.manifest;
    let exe = running_binary()?;
    let current_sha = install::require_release_binary(manifest, report.current, target, &exe)?;
    let to = to
        .map(|v| Version::parse(v.trim_start_matches('v')))
        .transpose()?;
    let Some(release) = install::choose_release(manifest, report.current, to, allow_downgrade)?
    else {
        println!("  wirken {} is installed already.", report.current);
        return Ok(());
    };
    print!("{}", report.render());
    confirm(
        format!(
            "Install wirken {} over {} at {}?",
            release.version,
            report.current,
            exe.display()
        ),
        release.version.clone(),
    )
    .await?;

    let name = install::artifact_name(target);
    let bytes = fetcher
        .get(
            fetcher.source().artifact_url(&release.version, &name),
            MAX_ARTIFACT_BYTES,
            Duration::from_secs(600),
        )
        .await
        .with_context(|| format!("download {name} {}", release.version))?;
    let sha = install::verify_artifact(&bytes, release, target)?;
    install::install(
        &exe,
        &bytes,
        &install::Kept {
            version: report.current.to_string(),
            sha256: current_sha,
            verifying_key: Some(report.verified.key_fingerprint.clone()),
        },
    )?;
    record(wirken_audit::SessionEvent::BinaryInstalled {
        from_version: report.current.to_string(),
        to_version: release.version.clone(),
        binary_sha256: sha.clone(),
        target: target.to_string(),
        verifying_key: Some(report.verified.key_fingerprint.clone()),
        rollback: false,
    })?;
    println!(
        "  Installed wirken {} at {} (sha256 {sha}), checked against releases.json signed by {}.",
        release.version,
        exe.display(),
        report.verified.key_fingerprint
    );
    println!(
        "  {} is kept as {}; `wirken update --rollback` restores it.",
        report.current,
        install::prev_path(&exe)?.display()
    );
    println!("  {}", restart_hint());
    Ok(())
}

/// `wirken update --rollback`: restore the binary the last update
/// replaced.
pub async fn run_rollback() -> Result<()> {
    require_supported_platform()?;
    operator_preflight()?;
    let exe = running_binary()?;
    let kept = install::kept(&exe)?;
    let current = crate::build_info::VERSION;
    confirm(
        format!(
            "Roll back wirken {current} to {} at {}?",
            kept.version,
            exe.display()
        ),
        "rollback".to_string(),
    )
    .await?;
    let back = install::rollback(&exe, current)?;
    record(wirken_audit::SessionEvent::BinaryInstalled {
        from_version: back.from.clone(),
        to_version: back.to.version.clone(),
        binary_sha256: back.to.sha256.clone(),
        target: crate::build_info::TARGET.to_string(),
        verifying_key: back.to.verifying_key.clone(),
        rollback: true,
    })?;
    println!(
        "  Restored wirken {} at {} (sha256 {}). {} is kept as {}.",
        back.to.version,
        exe.display(),
        back.to.sha256,
        back.from,
        install::prev_path(&exe)?.display()
    );
    println!("  {}", restart_hint());
    Ok(())
}

/// `wirken update --check`.
pub async fn run_check(base_url: Option<&str>) -> Result<()> {
    require_supported_platform()?;
    let cfg = super::config();
    let settings = load_config(&cfg.data_dir)?;
    let source = Source::choose(base_url, settings.mirror.as_deref())?;
    let keys = wirken_gateway::release_keys::pinned(wirken_gateway::release_keys::RELEASE_KEYS)
        .context("pinned release keys")?;
    let fetcher = Fetcher::new(source);
    let report = check(
        &cfg.data_dir,
        &fetcher,
        &keys,
        crate::build_info::VERSION,
        crate::build_info::TARGET,
    )
    .await?;
    print!("{}", report.render());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::fetch::tests::serve;
    use super::manifest::tests::{manifest_body, release, sign, test_key};
    use super::*;
    use wirken_gateway::release_keys::MANIFEST_NAMESPACE;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TARGET: &str = "x86_64-unknown-linux-musl";

    fn releases() -> Vec<Release> {
        let a = [("wirken-x86_64-unknown-linux-musl", SHA)];
        vec![
            release("2.2.0", true, &a),
            release("2.3.0", true, &a),
            release("2.4.0", false, &a),
        ]
    }

    async fn mirror_with(body: Vec<u8>, sig: String) -> super::fetch::tests::TestServer {
        serve(vec![
            ("/releases.json".into(), 200, vec![], body),
            ("/releases.json.sig".into(), 200, vec![], sig.into_bytes()),
        ])
        .await
    }

    #[tokio::test]
    async fn check_reports_latest_and_every_security_release_since_the_current_one() {
        let body = manifest_body("2026-10-20T00:00:00Z", &releases());
        let sig = sign(&test_key(1), MANIFEST_NAMESPACE, &body);
        let server = mirror_with(body, sig).await;
        let tmp = tempfile::tempdir().unwrap();
        let fetcher = Fetcher::new(Source::choose(Some(&server.base), None).unwrap());
        let keys = [test_key(1).verifying_key().to_bytes()];
        let report = check(tmp.path(), &fetcher, &keys, "2.2.0", TARGET)
            .await
            .unwrap();
        assert_eq!(report.latest().version, "2.4.0");
        assert_eq!(
            report
                .security()
                .iter()
                .map(|r| r.version.as_str())
                .collect::<Vec<_>>(),
            vec!["2.3.0"],
            "the security release between current and latest is named, not only the latest"
        );
        let text = report.render();
        assert!(text.contains("Security fixes in: 2.3.0"), "{text}");
        assert!(text.contains("installed  2.2.0"), "{text}");

        let up_to_date = check(tmp.path(), &fetcher, &keys, "2.4.0", TARGET)
            .await
            .unwrap();
        assert!(up_to_date.render().contains("Up to date."));
    }

    #[tokio::test]
    async fn check_refuses_a_manifest_signed_by_the_wrong_key() {
        let body = manifest_body("2026-10-20T00:00:00Z", &releases());
        let sig = sign(&test_key(9), MANIFEST_NAMESPACE, &body);
        let server = mirror_with(body, sig).await;
        let tmp = tempfile::tempdir().unwrap();
        let fetcher = Fetcher::new(Source::choose(Some(&server.base), None).unwrap());
        let keys = [test_key(1).verifying_key().to_bytes()];
        let err = check(tmp.path(), &fetcher, &keys, "2.2.0", TARGET)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("not a pinned key"), "{err:#}");
        // Nothing was recorded from a manifest that did not verify.
        assert!(!manifest::freeze_state_path(tmp.path()).exists());
    }

    #[tokio::test]
    async fn check_refuses_a_stale_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let keys = [test_key(1).verifying_key().to_bytes()];
        for (at, ok) in [
            ("2026-10-20T00:00:00Z", true),
            ("2026-10-10T00:00:00Z", false),
        ] {
            let body = manifest_body(at, &releases());
            let sig = sign(&test_key(1), MANIFEST_NAMESPACE, &body);
            let server = mirror_with(body, sig).await;
            let fetcher = Fetcher::new(Source::choose(Some(&server.base), None).unwrap());
            let got = check(tmp.path(), &fetcher, &keys, "2.2.0", TARGET).await;
            assert_eq!(got.is_ok(), ok, "{at}: {got:?}");
        }
    }

    /// An install row lands on the gateway-install lane, sealed by a
    /// chain head right after it, and the lane verifies.
    #[test]
    fn an_install_row_is_sealed_on_its_own_lane() {
        use wirken_audit::{SessionEvent, SessionLog as _};
        let tmp = tempfile::tempdir().unwrap();
        let signer =
            std::sync::Arc::new(wirken_audit::AuditSigningKey::load_or_create(tmp.path()).unwrap());
        let log =
            wirken_audit::SqliteSessionLog::open_with_signer(&tmp.path().join("audit.db"), signer)
                .unwrap();
        for rollback in [false, true] {
            record_on(
                &log,
                SessionEvent::BinaryInstalled {
                    from_version: "2.2.0".into(),
                    to_version: "2.3.0".into(),
                    binary_sha256: SHA.into(),
                    target: TARGET.into(),
                    verifying_key: Some("SHA256:test".into()),
                    rollback,
                },
            )
            .unwrap();
        }
        let handle = log.handle_for(wirken_audit::SessionId::new(INSTALL_LANE.to_string()));
        let rows = log.get_since(&handle, 0).unwrap();
        let kinds: Vec<&str> = rows
            .iter()
            .map(|r| match &r.event {
                SessionEvent::BinaryInstalled {
                    rollback: false, ..
                } => "install",
                SessionEvent::BinaryInstalled { rollback: true, .. } => "rollback",
                SessionEvent::ChainHead { .. } => "head",
                _ => "other",
            })
            .collect();
        // Each row is followed by a head before anything else.
        assert_eq!(kinds.last(), Some(&"head"), "{kinds:?}");
        let install = kinds.iter().position(|k| *k == "install").unwrap();
        let rollback = kinds.iter().position(|k| *k == "rollback").unwrap();
        assert_eq!(kinds[install + 1], "head", "{kinds:?}");
        assert_eq!(kinds[rollback + 1], "head", "{kinds:?}");
        assert!(matches!(
            log.verify(&handle).unwrap(),
            wirken_audit::SessionVerifyResult::Ok { .. }
        ));
    }

    #[test]
    fn update_json_rejects_unknown_keys() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("update.json"), r#"{"mirorr":"x"}"#).unwrap();
        assert!(load_config(tmp.path()).is_err());
        std::fs::write(
            tmp.path().join("update.json"),
            r#"{"mirror":"https://m.lan/"}"#,
        )
        .unwrap();
        assert_eq!(
            load_config(tmp.path()).unwrap().mirror.as_deref(),
            Some("https://m.lan/")
        );
        assert!(
            load_config(&tmp.path().join("absent"))
                .unwrap()
                .mirror
                .is_none()
        );
    }
}
