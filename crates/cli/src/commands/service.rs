use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Platform detection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Platform {
    LinuxSystemd,
    MacOsLaunchd,
    Unsupported(String),
}

/// Detect the current platform and init system.
pub fn detect_platform() -> Platform {
    let os = std::env::consts::OS;
    match os {
        "macos" => Platform::MacOsLaunchd,
        "linux" => {
            // Check for systemd
            let has_systemd = std::process::Command::new("systemctl")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            if has_systemd {
                Platform::LinuxSystemd
            } else {
                Platform::Unsupported("Linux without systemd".into())
            }
        }
        other => Platform::Unsupported(format!("unsupported OS: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Systemd
// ---------------------------------------------------------------------------

/// Path to the systemd user unit file.
pub fn systemd_unit_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".config/systemd/user/wirken.service")
}

/// Generate systemd user unit file content.
pub fn generate_systemd_unit(wirken_bin: &Path, data_dir: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=Wirken AI Agent Gateway\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={bin} run\n\
         WorkingDirectory={dir}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         Environment=WIRKEN_DATA_DIR={dir}\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        bin = wirken_bin.display(),
        dir = data_dir.display(),
    )
}

/// Install the systemd user service.
pub fn install_systemd(wirken_bin: &Path, data_dir: &Path) -> Result<()> {
    let unit_path = systemd_unit_path();

    // Ensure parent directory exists
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create systemd user directory")?;
    }

    let content = generate_systemd_unit(wirken_bin, data_dir);
    std::fs::write(&unit_path, &content)
        .context(format!("Failed to write {}", unit_path.display()))?;

    println!("  Wrote {}", unit_path.display());

    // Reload, enable, start
    run_cmd("systemctl", &["--user", "daemon-reload"])?;
    run_cmd("systemctl", &["--user", "enable", "--now", "wirken.service"])?;

    println!("  Service enabled and started.");
    println!();

    // Show status
    let _ = run_cmd("systemctl", &["--user", "status", "wirken.service"]);

    Ok(())
}

/// Uninstall the systemd user service.
pub fn uninstall_systemd() -> Result<()> {
    let _ = run_cmd("systemctl", &["--user", "stop", "wirken.service"]);
    let _ = run_cmd("systemctl", &["--user", "disable", "wirken.service"]);

    let unit_path = systemd_unit_path();
    if unit_path.exists() {
        std::fs::remove_file(&unit_path)
            .context(format!("Failed to remove {}", unit_path.display()))?;
        println!("  Removed {}", unit_path.display());
    }

    let _ = run_cmd("systemctl", &["--user", "daemon-reload"]);
    println!("  Service stopped and removed.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Launchd
// ---------------------------------------------------------------------------

/// Path to the launchd plist.
pub fn launchd_plist_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join("Library/LaunchAgents/app.ottenheimer.wirken.plist")
}

/// Generate launchd plist content.
pub fn generate_launchd_plist(wirken_bin: &Path, data_dir: &Path) -> String {
    let log_dir = data_dir.join("logs");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>app.ottenheimer.wirken</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>run</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{dir}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>WIRKEN_DATA_DIR</key>
        <string>{dir}</string>
    </dict>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log}/wirken.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{log}/wirken.stderr.log</string>
</dict>
</plist>
"#,
        bin = wirken_bin.display(),
        dir = data_dir.display(),
        log = log_dir.display(),
    )
}

/// Install the launchd service.
pub fn install_launchd(wirken_bin: &Path, data_dir: &Path) -> Result<()> {
    let plist_path = launchd_plist_path();

    // Ensure log directory exists
    let log_dir = data_dir.join("logs");
    std::fs::create_dir_all(&log_dir)
        .context("Failed to create log directory")?;

    // Ensure LaunchAgents directory exists
    if let Some(parent) = plist_path.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create LaunchAgents directory")?;
    }

    let content = generate_launchd_plist(wirken_bin, data_dir);
    std::fs::write(&plist_path, &content)
        .context(format!("Failed to write {}", plist_path.display()))?;

    println!("  Wrote {}", plist_path.display());

    run_cmd("launchctl", &["load", &plist_path.to_string_lossy()])?;
    println!("  Service loaded and started.");

    Ok(())
}

/// Uninstall the launchd service.
pub fn uninstall_launchd() -> Result<()> {
    let plist_path = launchd_plist_path();

    if plist_path.exists() {
        let _ = run_cmd("launchctl", &["unload", &plist_path.to_string_lossy()]);
        std::fs::remove_file(&plist_path)
            .context(format!("Failed to remove {}", plist_path.display()))?;
        println!("  Removed {}", plist_path.display());
    }

    println!("  Service stopped and removed.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Install the service for the detected platform.
pub fn install_service(wirken_bin: &Path, data_dir: &Path) -> Result<()> {
    match detect_platform() {
        Platform::LinuxSystemd => install_systemd(wirken_bin, data_dir),
        Platform::MacOsLaunchd => install_launchd(wirken_bin, data_dir),
        Platform::Unsupported(reason) => {
            println!("  Cannot install service automatically: {reason}");
            println!();
            println!("  To run Wirken manually:");
            println!("    wirken run");
            println!();
            println!("  Or add to your init system:");
            println!("    ExecStart: {} run", wirken_bin.display());
            println!("    WorkingDirectory: {}", data_dir.display());
            Ok(())
        }
    }
}

/// Uninstall the service for the detected platform.
pub fn uninstall_service() -> Result<()> {
    match detect_platform() {
        Platform::LinuxSystemd => uninstall_systemd(),
        Platform::MacOsLaunchd => uninstall_launchd(),
        Platform::Unsupported(reason) => {
            println!("  Cannot uninstall service automatically: {reason}");
            Ok(())
        }
    }
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(cmd)
        .args(args)
        .status()
        .context(format!("Failed to run {cmd}"))?;

    if !status.success() {
        anyhow::bail!("{cmd} exited with {status}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn systemd_unit_content() {
        let bin = PathBuf::from("/usr/local/bin/wirken");
        let dir = PathBuf::from("/home/user/.wirken");
        let unit = generate_systemd_unit(&bin, &dir);

        assert!(unit.contains("ExecStart=/usr/local/bin/wirken run"));
        assert!(unit.contains("WorkingDirectory=/home/user/.wirken"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("RestartSec=5"));
        assert!(unit.contains("WIRKEN_DATA_DIR=/home/user/.wirken"));
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn systemd_unit_path_format() {
        // Can't set HOME in Rust 2024 (set_var is unsafe), so just verify the suffix
        let path = systemd_unit_path();
        assert!(path.ends_with(".config/systemd/user/wirken.service"));
    }

    #[test]
    fn launchd_plist_content() {
        let bin = PathBuf::from("/usr/local/bin/wirken");
        let dir = PathBuf::from("/Users/user/.wirken");
        let plist = generate_launchd_plist(&bin, &dir);

        assert!(plist.contains("<string>/usr/local/bin/wirken</string>"));
        assert!(plist.contains("<string>run</string>"));
        assert!(plist.contains("<string>/Users/user/.wirken</string>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<true/>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("app.ottenheimer.wirken"));
        assert!(plist.contains("wirken.stdout.log"));
        assert!(plist.contains("wirken.stderr.log"));
        assert!(plist.contains("WIRKEN_DATA_DIR"));
    }

    #[test]
    fn launchd_plist_path_format() {
        let path = launchd_plist_path();
        assert!(path.ends_with("Library/LaunchAgents/app.ottenheimer.wirken.plist"));
    }

    #[test]
    fn platform_detection_returns_something() {
        let platform = detect_platform();
        // Just verify it doesn't panic — actual platform varies by CI/host
        match platform {
            Platform::LinuxSystemd => {}
            Platform::MacOsLaunchd => {}
            Platform::Unsupported(_) => {}
        }
    }

    #[test]
    fn systemd_unit_different_paths() {
        let bin = PathBuf::from("/opt/wirken/bin/wirken");
        let dir = PathBuf::from("/data/wirken");
        let unit = generate_systemd_unit(&bin, &dir);

        assert!(unit.contains("ExecStart=/opt/wirken/bin/wirken run"));
        assert!(unit.contains("WorkingDirectory=/data/wirken"));
    }

    #[test]
    fn launchd_plist_xml_valid() {
        let bin = PathBuf::from("/usr/local/bin/wirken");
        let dir = PathBuf::from("/Users/user/.wirken");
        let plist = generate_launchd_plist(&bin, &dir);

        // Basic XML structure checks
        assert!(plist.starts_with("<?xml"));
        assert!(plist.contains("<!DOCTYPE plist"));
        assert!(plist.contains("<plist version=\"1.0\">"));
        assert!(plist.trim_end().ends_with("</plist>"));
    }
}
