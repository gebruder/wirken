//! Method-name → [`Fetcher`] dispatch.
//!
//! The orchestrator builds one [`FetcherRegistry`] at startup,
//! registering each available [`Fetcher`] under one or more method
//! names (the strings in `sources.toml`'s `method = "..."` field).
//! Per-source dispatch is then a registry lookup; a manifest entry
//! whose method has no registered fetcher records as unsupported and
//! the run continues.
//!
//! ## Aliases
//!
//! [`Fetcher::method`] returns the canonical name; the registry
//! lets a single fetcher serve multiple aliases. The RSS implementation
//! is the only current case (`"rss"` and `"atom-api"` both dispatch
//! to [`crate::fetcher::RssFetcher`]).

use std::collections::HashMap;
use std::sync::Arc;

use crate::fetcher::Fetcher;

/// Method-name → fetcher dispatch table.
#[derive(Default, Clone)]
pub struct FetcherRegistry {
    map: HashMap<String, Arc<dyn Fetcher>>,
}

impl FetcherRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a fetcher under one method name. Re-registering an
    /// existing method replaces the previous entry — useful for
    /// tests that swap a real fetcher for a fixture, never for
    /// production code.
    pub fn register(&mut self, method: &str, fetcher: Arc<dyn Fetcher>) {
        self.map.insert(method.to_string(), fetcher);
    }

    /// Look up the fetcher registered for `method`. `None` means
    /// the manifest entry refers to an unsupported method.
    pub fn get(&self, method: &str) -> Option<&Arc<dyn Fetcher>> {
        self.map.get(method)
    }

    /// Method names currently registered, sorted. Used in startup
    /// logging so an operator can verify their `sources.toml` matches
    /// what the binary supports.
    pub fn registered_methods(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.map.keys().cloned().collect();
        keys.sort();
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetcher::{FetchError, FetchedItem, SourceConfig};
    use async_trait::async_trait;
    use wirken_agent::egress::EgressClient;

    struct NamedFetcher(&'static str);

    #[async_trait]
    impl Fetcher for NamedFetcher {
        fn method(&self) -> &'static str {
            self.0
        }
        async fn fetch(
            &self,
            _http: &EgressClient,
            source: &SourceConfig,
        ) -> Result<Vec<FetchedItem>, FetchError> {
            Ok(vec![FetchedItem {
                source_name: source.name.clone(),
                url: source.endpoint.clone(),
                title: format!("from {}", self.0),
                ..Default::default()
            }])
        }
    }

    #[test]
    fn register_and_get() {
        let mut r = FetcherRegistry::new();
        r.register("foo", Arc::new(NamedFetcher("foo")));
        assert!(r.get("foo").is_some());
        assert!(r.get("missing").is_none());
    }

    #[test]
    fn alias_registers_same_fetcher_under_two_names() {
        let mut r = FetcherRegistry::new();
        let f = Arc::new(NamedFetcher("rss"));
        r.register("rss", f.clone());
        r.register("atom-api", f);
        // Both keys resolve.
        assert!(r.get("rss").is_some());
        assert!(r.get("atom-api").is_some());
        // And to the same Arc.
        let a = r.get("rss").unwrap();
        let b = r.get("atom-api").unwrap();
        assert!(Arc::ptr_eq(a, b));
    }

    #[test]
    fn re_register_replaces() {
        let mut r = FetcherRegistry::new();
        r.register("rss", Arc::new(NamedFetcher("first")));
        r.register("rss", Arc::new(NamedFetcher("second")));
        let f = r.get("rss").unwrap();
        assert_eq!(f.method(), "second");
    }

    #[test]
    fn registered_methods_sorted() {
        let mut r = FetcherRegistry::new();
        r.register("zeta", Arc::new(NamedFetcher("z")));
        r.register("alpha", Arc::new(NamedFetcher("a")));
        r.register("mid", Arc::new(NamedFetcher("m")));
        assert_eq!(r.registered_methods(), vec!["alpha", "mid", "zeta"]);
    }
}
