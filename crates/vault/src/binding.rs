//! Where a credential's value may go, sealed into its row's associated
//! data so that changing it takes the device key.

use serde::{Deserialize, Serialize};

/// An MCP server a credential may be handed to, pinned to the digest of
/// its signed `mcp.json` entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct McpServerGrant {
    pub name: String,
    pub entry: String,
}

/// A model provider a credential may authenticate to: its id and the
/// origin (scheme, host, port) of the base URL it is sent to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProviderGrant {
    pub provider: String,
    pub origin: String,
}

/// The destinations a credential may be sent to. An empty binding
/// permits nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Binding {
    #[serde(default = "version")]
    pub v: u32,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub mcp_servers: Vec<McpServerGrant>,
    #[serde(default)]
    pub providers: Vec<ProviderGrant>,
    #[serde(default)]
    pub adapters: Vec<String>,
    #[serde(default)]
    pub plan: bool,
}

fn version() -> u32 {
    1
}

/// One place a credential's value can go.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Destination {
    /// `http_request` to this host.
    Host(String),
    McpServer(McpServerGrant),
    Provider(ProviderGrant),
    /// A channel adapter process, by adapter id.
    Adapter(String),
    /// The pinned plan sign-in endpoints.
    Plan,
}

impl Destination {
    /// Stable name of the kind, for audit rows.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Host(_) => "host",
            Self::McpServer(_) => "mcp_server",
            Self::Provider(_) => "provider",
            Self::Adapter(_) => "adapter",
            Self::Plan => "plan",
        }
    }

    /// The destination as an operator would name it.
    pub fn describe(&self) -> String {
        match self {
            Self::Host(h) => h.clone(),
            Self::McpServer(s) => format!("{} ({})", s.name, s.entry),
            Self::Provider(p) => format!("{} at {}", p.provider, p.origin),
            Self::Adapter(a) => a.clone(),
            Self::Plan => "plan sign-in endpoints".into(),
        }
    }

    /// The `wirken credentials grant` flags that would allow it.
    pub fn grant_flags(&self) -> String {
        match self {
            Self::Host(h) => format!("--host {h}"),
            Self::McpServer(s) => format!("--mcp-server {}", s.name),
            Self::Provider(p) => format!("--provider {} --base-url {}", p.provider, p.origin),
            Self::Adapter(a) => format!("--adapter {a}"),
            Self::Plan => "--plan".into(),
        }
    }
}

impl Binding {
    /// A binding to `hosts` only.
    pub fn hosts(hosts: &[String]) -> Self {
        let mut b = Self {
            v: 1,
            hosts: hosts.to_vec(),
            ..Self::default()
        };
        b.normalize();
        b
    }

    /// A binding to one adapter.
    pub fn adapter(adapter: &str) -> Self {
        let mut b = Self {
            v: 1,
            ..Self::default()
        };
        b.grant(Destination::Adapter(adapter.to_string()));
        b
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
            && self.mcp_servers.is_empty()
            && self.providers.is_empty()
            && self.adapters.is_empty()
            && !self.plan
    }

    /// Whether `destination` is allowed. Hosts compare case-insensitively.
    pub fn permits(&self, destination: &Destination) -> bool {
        match destination {
            Destination::Host(h) => self.hosts.iter().any(|x| x.eq_ignore_ascii_case(h)),
            Destination::McpServer(s) => self.mcp_servers.contains(s),
            Destination::Provider(p) => self.providers.contains(p),
            Destination::Adapter(a) => self.adapters.iter().any(|x| x == a),
            Destination::Plan => self.plan,
        }
    }

    /// Add `destination`. Returns whether it was new.
    pub fn grant(&mut self, destination: Destination) -> bool {
        if self.permits(&destination) {
            return false;
        }
        match destination {
            Destination::Host(h) => self.hosts.push(h),
            // One pin per server name: granting it again replaces the
            // digest.
            Destination::McpServer(s) => {
                self.mcp_servers.retain(|x| x.name != s.name);
                self.mcp_servers.push(s);
            }
            Destination::Provider(p) => self.providers.push(p),
            Destination::Adapter(a) => self.adapters.push(a),
            Destination::Plan => self.plan = true,
        }
        self.normalize();
        true
    }

    /// Remove `destination`. An MCP server is removed by name, whatever
    /// its digest. Returns whether anything was removed.
    pub fn revoke(&mut self, destination: &Destination) -> bool {
        let before = self.clone();
        match destination {
            Destination::Host(h) => self.hosts.retain(|x| !x.eq_ignore_ascii_case(h)),
            Destination::McpServer(s) => self.mcp_servers.retain(|x| x.name != s.name),
            Destination::Provider(p) => self.providers.retain(|x| x != p),
            Destination::Adapter(a) => self.adapters.retain(|x| x != a),
            Destination::Plan => self.plan = false,
        }
        *self != before
    }

    /// Every destination, one per entry.
    pub fn destinations(&self) -> Vec<Destination> {
        let mut out: Vec<Destination> = Vec::new();
        out.extend(self.hosts.iter().cloned().map(Destination::Host));
        out.extend(self.mcp_servers.iter().cloned().map(Destination::McpServer));
        out.extend(self.providers.iter().cloned().map(Destination::Provider));
        out.extend(self.adapters.iter().cloned().map(Destination::Adapter));
        if self.plan {
            out.push(Destination::Plan);
        }
        out
    }

    /// Lowercase hosts; sort and deduplicate every list.
    pub fn normalize(&mut self) {
        self.v = 1;
        for h in &mut self.hosts {
            *h = h.trim().to_ascii_lowercase();
        }
        self.hosts.retain(|h| !h.is_empty());
        self.hosts.sort();
        self.hosts.dedup();
        self.mcp_servers.sort();
        self.mcp_servers.dedup();
        self.providers.sort();
        self.providers.dedup();
        self.adapters.sort();
        self.adapters.dedup();
    }

    /// The bytes stored in the `binding` column and sealed into the
    /// row's associated data.
    pub fn canonical(&self) -> String {
        let mut b = self.clone();
        b.normalize();
        serde_json::to_string(&b).expect("a binding serializes")
    }

    /// Parse a stored `binding` column.
    pub fn parse(raw: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(raw)
    }
}

/// The origin of `url`: lowercased scheme and host, and the port when
/// one is given. `None` for anything without a scheme and host.
pub fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    if authority.is_empty() {
        return None;
    }
    Some(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_binding_permits_nothing() {
        let b = Binding::default();
        assert!(b.is_empty());
        for d in [
            Destination::Host("api.example.com".into()),
            Destination::Adapter("slack".into()),
            Destination::Plan,
        ] {
            assert!(!b.permits(&d));
        }
    }

    #[test]
    fn grants_and_revokes_round_trip_through_the_canonical_form() {
        let mut b = Binding::default();
        assert!(b.grant(Destination::Host("API.Linear.app".into())));
        assert!(!b.grant(Destination::Host("api.linear.app".into())));
        b.grant(Destination::McpServer(McpServerGrant {
            name: "linear".into(),
            entry: "sha256:aa".into(),
        }));
        b.grant(Destination::McpServer(McpServerGrant {
            name: "linear".into(),
            entry: "sha256:bb".into(),
        }));
        b.grant(Destination::Provider(ProviderGrant {
            provider: "openai".into(),
            origin: "https://api.openai.com".into(),
        }));
        b.grant(Destination::Adapter("slack".into()));
        assert_eq!(b.mcp_servers.len(), 1, "one pin per server name");
        assert!(b.permits(&Destination::Host("api.linear.app".into())));

        let parsed = Binding::parse(&b.canonical()).unwrap();
        assert_eq!(parsed, b);
        assert_eq!(parsed.canonical(), b.canonical());

        assert!(b.revoke(&Destination::McpServer(McpServerGrant {
            name: "linear".into(),
            entry: String::new(),
        })));
        assert!(!b.revoke(&Destination::Plan));
        assert!(b.mcp_servers.is_empty());
    }

    #[test]
    fn origins_drop_the_path_and_credentials() {
        assert_eq!(
            origin_of("https://API.openai.com/v1/chat").as_deref(),
            Some("https://api.openai.com")
        );
        assert_eq!(
            origin_of("http://user:pw@localhost:11434/v1").as_deref(),
            Some("http://localhost:11434")
        );
        assert_eq!(origin_of("api.openai.com"), None);
    }
}
