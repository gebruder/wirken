//! The environment a host-side child process starts with.
//!
//! Every process Wirken starts outside a container, a host `exec`
//! under `mode: off`, an adapter, the MCP proxy, a stdio MCP server
//! whose sandbox is off, and the `git`, `semgrep`, `curl`, `crontab`,
//! `systemctl` and `launchctl` invocations the CLI makes, is built the
//! same way: the child's environment is cleared, [`minimal`] is put
//! back, and the call site adds the variables that child is named for
//! and nothing else. The parent's environment can carry the vault
//! passphrase and whatever else the operator exported to start Wirken
//! or to run a command; none of that is a child's to read.
//!
//! A child's view is therefore decided by the call site, in code, not
//! by what happened to be exported in the shell. A variable a child
//! reads has to be named at its spawn, which is where a reviewer looks
//! for it.

use std::ffi::OsString;

/// What a process needs to find programs and run them. On unix the
/// shell basics; on Windows the system locations a shell cannot start
/// without.
#[cfg(not(windows))]
pub const BASE: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TMPDIR",
];

/// See the unix list.
#[cfg(windows)]
pub const BASE: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "SystemDrive",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "USERNAME",
];

/// What an HTTP client needs to reach the network the way the
/// operator's shell does: the proxy variables `reqwest` and `curl`
/// read, in both spellings, and the CA bundle overrides
/// `rustls-native-certs` and `curl` honour. Given to the children that
/// open outbound connections (adapters, the MCP proxy, `curl`), never
/// to one that should not.
pub const NETWORK_CLIENT: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// The pairs for `names` that are set in `parent`, in the order of
/// `names`. A name that is not set contributes nothing; nothing else
/// in `parent` is read.
pub fn inherit_from<I>(names: &[&str], parent: I) -> Vec<(String, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let parent: Vec<(OsString, OsString)> = parent.into_iter().collect();
    names
        .iter()
        .filter_map(|name| {
            parent
                .iter()
                .find(|(k, _)| k.as_os_str() == *name)
                .map(|(_, v)| ((*name).to_string(), v.clone()))
        })
        .collect()
}

/// The pairs for `names` that are set in this process's environment.
pub fn inherit(names: &[&str]) -> Vec<(String, OsString)> {
    inherit_from(names, std::env::vars_os())
}

/// [`BASE`], read from this process's environment. A call site applies
/// it as `cmd.env_clear().envs(child_env::minimal())`, then names what
/// else that child gets.
pub fn minimal() -> Vec<(String, OsString)> {
    inherit(BASE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    #[test]
    fn only_named_variables_are_read_from_the_parent() {
        let p = parent(&[
            ("PATH", "/usr/bin"),
            ("WIRKEN_VAULT_PASSPHRASE", "secret"),
            ("WIRKEN_DATA_DIR", "/x"),
            ("AWS_SECRET_ACCESS_KEY", "k"),
            ("HOME", "/home/o"),
        ]);
        let got = inherit_from(BASE, p);
        assert_eq!(
            got,
            vec![
                ("PATH".to_string(), OsString::from("/usr/bin")),
                ("HOME".to_string(), OsString::from("/home/o")),
            ]
        );
    }

    #[test]
    fn an_unset_name_contributes_nothing() {
        let got = inherit_from(&["PATH", "TMPDIR"], parent(&[("PATH", "/bin")]));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "PATH");
    }

    #[test]
    fn minimal_reads_nothing_outside_base() {
        // cargo sets CARGO_* for every test process; none of it is in
        // BASE, so none of it comes back.
        for (name, _) in minimal() {
            assert!(BASE.contains(&name.as_str()), "{name} is not in BASE");
        }
    }

    #[test]
    fn the_base_set_is_pinned() {
        // Widening what every host child starts with is a review
        // decision, taken here and nowhere else.
        #[cfg(not(windows))]
        let expected: &[&str] = &[
            "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TMPDIR",
        ];
        #[cfg(windows)]
        let expected: &[&str] = &[
            "PATH",
            "PATHEXT",
            "SystemRoot",
            "SystemDrive",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "APPDATA",
            "LOCALAPPDATA",
            "USERNAME",
        ];
        assert_eq!(BASE, expected);
        assert!(!NETWORK_CLIENT.iter().any(|n| n.starts_with("WIRKEN_")));
    }
}
