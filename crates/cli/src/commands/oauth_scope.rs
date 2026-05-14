//! Operator-facing OAuth scope selection.
//!
//! Bundle A item 3 slice 2: the interactive picker + scripted-mode
//! flag handling. Used by `wirken mcp authorize` (slice 2) and by
//! `wirken credentials rescope` (slice 3).
//!
//! The picker shows operator-pickable scopes only. Required scopes
//! (per the slice-1 catalog) are auto-included in every returned
//! `Vec<String>` regardless of how the operator submits, so a
//! deselected required scope cannot leave the function. This is
//! cleaner UX than locked checkboxes: the operator's mental model is
//! "I pick optional extras; required scopes are part of the floor".
//!
//! `default_scopes` (the pre-picker hardcoded set on `OAuthProvider`)
//! is still added by `run_authorization_code_flow` itself, so the
//! final auth URL union is `default_scopes ∪ required ∪ picker_output`.
//! Slice 3 unifies those layers; slice 2 keeps the existing
//! `extra_scopes` augment-semantics.

use std::collections::BTreeSet;
use std::io::IsTerminal;

use anyhow::{Result, anyhow};
use dialoguer::MultiSelect;
use wirken_mcp_proxy::{OAuthProvider, ScopeCategory, ScopeChoice};

/// Operator-supplied scripted-mode flags. Built from clap by the
/// CLI layer; mutual exclusion is enforced at parse time so the
/// resolver can trust at most one of `no_scopes` / `all_scopes` /
/// non-empty `scope` is set.
#[derive(Debug, Default, Clone)]
pub(crate) struct ScopeFlags {
    /// Explicit per-scope selection. Each entry must appear in the
    /// provider's catalog or the resolver errors.
    pub scope: Vec<String>,
    /// Request only the required floor. No optional scopes.
    pub no_scopes: bool,
    /// Request every scope in the provider's catalog.
    pub all_scopes: bool,
}

/// Resolve the operator's scope choice into the `Vec<String>` the
/// CLI passes as `extra_scopes` to `run_authorization_code_flow`.
///
/// Required scopes (per the catalog) are unconditionally included
/// regardless of which path the operator took. The resolver never
/// returns a list missing a required scope, even if the operator
/// explicitly excludes it via `--scope` (the required floor wins).
///
/// Path selection:
/// - `--no-scopes` set: required floor only.
/// - `--all-scopes` set: full catalog.
/// - `--scope <id>...` non-empty: required floor + named ids.
///   Errors if an id is not in the catalog.
/// - No flags + stdin is a TTY: invoke [`run_picker`].
/// - No flags + stdin is not a TTY: error with usage message.
///
/// Provider with empty catalog (Notion): the resolver short-circuits.
/// Flags are ignored with a stderr warning; the returned `Vec` is
/// empty so `run_authorization_code_flow` sends only the provider's
/// `default_scopes` (which is also empty for Notion).
pub(crate) fn resolve_scopes(
    provider: &OAuthProvider,
    flags: &ScopeFlags,
    stdin_is_tty: bool,
) -> Result<Vec<String>> {
    resolve_scopes_with_defaults(provider, flags, stdin_is_tty, &[])
}

/// Resolver variant that accepts a pre-selection for the interactive
/// picker. Used by `wirken credentials rescope` to seed the picker
/// with the credential's currently-granted optional scopes so the
/// operator sees what they have today and can add or drop without
/// retyping the whole set. Non-picker paths (`--scope`,
/// `--no-scopes`, `--all-scopes`) ignore `picker_defaults`: the
/// scripted-mode flags are the operator's explicit instruction and
/// override any prior state.
pub(crate) fn resolve_scopes_with_defaults(
    provider: &OAuthProvider,
    flags: &ScopeFlags,
    stdin_is_tty: bool,
    picker_defaults: &[String],
) -> Result<Vec<String>> {
    if provider.scopes.is_empty() {
        if !flags.scope.is_empty() || flags.no_scopes || flags.all_scopes {
            eprintln!(
                "  Note: provider '{}' has no scope catalog; scope flags have no effect.",
                provider.name
            );
        }
        eprintln!(
            "  {} grants permissions per workspace; no scope choices at OAuth time.",
            provider.name
        );
        return Ok(Vec::new());
    }

    let required_floor: Vec<String> = provider
        .scopes
        .iter()
        .filter(|s| s.required)
        .map(|s| s.id.to_string())
        .collect();

    if flags.no_scopes {
        eprintln!(
            "  --no-scopes: requesting only the {} required scope(s).",
            required_floor.len()
        );
        return Ok(required_floor);
    }

    if flags.all_scopes {
        let mut out = required_floor.clone();
        for s in provider.scopes {
            let id = s.id.to_string();
            if !out.contains(&id) {
                out.push(id);
            }
        }
        eprintln!(
            "  --all-scopes: requesting all {} scope(s) in the {} catalog.",
            out.len(),
            provider.name,
        );
        return Ok(out);
    }

    if !flags.scope.is_empty() {
        let known: BTreeSet<&str> = provider.scopes.iter().map(|s| s.id).collect();
        for s in &flags.scope {
            if !known.contains(s.as_str()) {
                anyhow::bail!(
                    "scope '{s}' is not in the {} catalog. Known scopes:\n{}",
                    provider.name,
                    known
                        .iter()
                        .map(|k| format!("  {k}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            }
        }
        let mut out = required_floor.clone();
        for s in &flags.scope {
            if !out.contains(s) {
                out.push(s.clone());
            }
        }
        return Ok(out);
    }

    if !stdin_is_tty {
        anyhow::bail!(
            "scope selection required and stdin is not a TTY. Use one of:\n  \
             --scope <id> (repeatable)\n  \
             --all-scopes\n  \
             --no-scopes\nor run interactively."
        );
    }

    run_picker_with_defaults(provider, picker_defaults)
}

/// Render the interactive picker with `default_optional_ids`
/// pre-checked. Required scopes are still auto-included separately;
/// the defaults only affect optional-scope checkbox state. Unknown
/// or required ids in the defaults slice are silently ignored (an
/// unknown default isn't an operator instruction, it's a stale
/// reference from a prior catalog or a typo). The required floor is
/// shown above the `MultiSelect` widget; the widget itself only
/// contains optional scopes.
pub(crate) fn run_picker_with_defaults(
    provider: &OAuthProvider,
    default_optional_ids: &[String],
) -> Result<Vec<String>> {
    if provider.scopes.is_empty() {
        // Defensive; `resolve_scopes` short-circuits the empty
        // catalog before reaching the picker. Keeping this branch
        // makes `run_picker` safe to call standalone.
        eprintln!(
            "  {} grants permissions per workspace; no scope choices at OAuth time.",
            provider.name
        );
        return Ok(Vec::new());
    }

    let required: Vec<&ScopeChoice> = provider.scopes.iter().filter(|s| s.required).collect();
    let optional = optional_in_category_order(provider);

    println!(
        "  Authorizing {}: {} scope choice{}, {} required.",
        provider.name,
        provider.scopes.len(),
        if provider.scopes.len() == 1 { "" } else { "s" },
        required.len(),
    );

    if !required.is_empty() {
        println!("  Required (auto-included):");
        for s in &required {
            println!("    {}: {}", s.id, s.description);
        }
    }

    if optional.is_empty() {
        // Every scope is required; nothing for the operator to pick.
        // Skip the MultiSelect, return the floor.
        return Ok(required.iter().map(|s| s.id.to_string()).collect());
    }

    let items: Vec<String> = optional
        .iter()
        .map(|s| {
            format!(
                "[{}] {}: {}",
                category_label(s.category),
                s.id,
                s.description
            )
        })
        .collect();

    // Mirror the `optional` order so `defaults[i]` lines up with
    // `items[i]`. Unknown ids in the input slice don't appear in
    // optional and are silently dropped at this stage.
    let defaults: Vec<bool> = optional
        .iter()
        .map(|s| default_optional_ids.iter().any(|d| d == s.id))
        .collect();

    let selected_idx = MultiSelect::new()
        .with_prompt("  Choose additional scopes")
        .items(&items)
        .defaults(&defaults)
        .interact_opt()
        .map_err(|e| anyhow!("picker error: {e}"))?
        .ok_or_else(|| anyhow!("OAuth authorization canceled"))?;

    let mut out: Vec<String> = required.iter().map(|s| s.id.to_string()).collect();
    for idx in selected_idx {
        out.push(optional[idx].id.to_string());
    }
    Ok(out)
}

/// Stdin-is-TTY probe. Extracted so resolver tests can pass a
/// constant rather than depending on the test harness's stdio.
pub(crate) fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

fn category_label(cat: ScopeCategory) -> &'static str {
    match cat {
        ScopeCategory::Profile => "profile",
        ScopeCategory::Read => "read",
        ScopeCategory::Write => "write",
        ScopeCategory::Admin => "admin",
    }
}

/// Order optional scopes for display: Profile, Read, Write, Admin.
/// Within a category, catalog order is preserved.
fn optional_in_category_order(provider: &OAuthProvider) -> Vec<&ScopeChoice> {
    let order = [
        ScopeCategory::Profile,
        ScopeCategory::Read,
        ScopeCategory::Write,
        ScopeCategory::Admin,
    ];
    let mut out = Vec::with_capacity(provider.scopes.len());
    for cat in order {
        for s in provider.scopes {
            if !s.required && s.category == cat {
                out.push(s);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirken_mcp_proxy::lookup_provider;

    fn google() -> &'static OAuthProvider {
        lookup_provider("google").expect("google in registry")
    }

    fn linear() -> &'static OAuthProvider {
        lookup_provider("linear").expect("linear in registry")
    }

    fn github() -> &'static OAuthProvider {
        lookup_provider("github").expect("github in registry")
    }

    fn notion() -> &'static OAuthProvider {
        lookup_provider("notion").expect("notion in registry")
    }

    #[test]
    fn no_scopes_flag_returns_required_floor_only() {
        let flags = ScopeFlags {
            no_scopes: true,
            ..Default::default()
        };
        let out = resolve_scopes(google(), &flags, /*stdin_is_tty=*/ true).unwrap();
        // Google required floor is openid + userinfo.email.
        assert!(out.contains(&"openid".to_string()));
        assert!(
            out.iter().any(|s| s.ends_with("/userinfo.email")),
            "out missing userinfo.email: {out:?}",
        );
        // Drive readonly is not required; --no-scopes excludes it.
        assert!(
            !out.iter().any(|s| s.ends_with("/drive.readonly")),
            "out contains drive.readonly under --no-scopes: {out:?}",
        );
    }

    #[test]
    fn all_scopes_flag_returns_every_catalog_scope_including_required() {
        let flags = ScopeFlags {
            all_scopes: true,
            ..Default::default()
        };
        let out = resolve_scopes(google(), &flags, true).unwrap();
        assert_eq!(out.len(), google().scopes.len());
        for s in google().scopes {
            assert!(
                out.iter().any(|got| got == s.id),
                "out missing catalog scope '{}': {out:?}",
                s.id,
            );
        }
    }

    #[test]
    fn explicit_scope_flag_adds_to_required_floor_and_dedupes() {
        let flags = ScopeFlags {
            scope: vec![
                "https://www.googleapis.com/auth/drive.readonly".to_string(),
                "openid".to_string(), // already in required floor; dedupe
            ],
            ..Default::default()
        };
        let out = resolve_scopes(google(), &flags, true).unwrap();
        // Required + drive.readonly, openid not duplicated.
        let openid_count = out.iter().filter(|s| *s == "openid").count();
        assert_eq!(openid_count, 1, "openid not deduped: {out:?}");
        assert!(
            out.iter().any(|s| s.ends_with("/drive.readonly")),
            "out missing drive.readonly: {out:?}",
        );
        assert!(out.contains(&"openid".to_string()));
    }

    #[test]
    fn explicit_scope_unknown_to_catalog_errors() {
        let flags = ScopeFlags {
            scope: vec!["fictional-scope".to_string()],
            ..Default::default()
        };
        let err = resolve_scopes(google(), &flags, true).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("fictional-scope"));
        assert!(msg.contains("Known scopes"));
    }

    #[test]
    fn no_flags_and_non_tty_errors_with_usage_message() {
        let flags = ScopeFlags::default();
        let err = resolve_scopes(github(), &flags, /*stdin_is_tty=*/ false).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not a TTY"));
        assert!(msg.contains("--scope"));
        assert!(msg.contains("--all-scopes"));
        assert!(msg.contains("--no-scopes"));
    }

    #[test]
    fn notion_short_circuits_with_empty_vec_regardless_of_flags() {
        // Bare resolve.
        let out = resolve_scopes(notion(), &ScopeFlags::default(), true).unwrap();
        assert!(out.is_empty());

        // --no-scopes still returns empty.
        let out = resolve_scopes(
            notion(),
            &ScopeFlags {
                no_scopes: true,
                ..Default::default()
            },
            true,
        )
        .unwrap();
        assert!(out.is_empty());

        // --scope on a no-catalog provider warns but does not error.
        let out = resolve_scopes(
            notion(),
            &ScopeFlags {
                scope: vec!["ignored".to_string()],
                ..Default::default()
            },
            true,
        )
        .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn linear_no_scopes_returns_just_read() {
        let flags = ScopeFlags {
            no_scopes: true,
            ..Default::default()
        };
        let out = resolve_scopes(linear(), &flags, true).unwrap();
        assert_eq!(out, vec!["read".to_string()]);
    }

    #[test]
    fn required_floor_present_in_every_path_for_github() {
        let required: Vec<&'static str> = github()
            .scopes
            .iter()
            .filter(|s| s.required)
            .map(|s| s.id)
            .collect();
        assert!(!required.is_empty());

        for flags in [
            ScopeFlags {
                no_scopes: true,
                ..Default::default()
            },
            ScopeFlags {
                all_scopes: true,
                ..Default::default()
            },
            ScopeFlags {
                scope: vec!["repo".to_string()],
                ..Default::default()
            },
        ] {
            let out = resolve_scopes(github(), &flags, true).unwrap();
            for r in &required {
                assert!(
                    out.iter().any(|s| s == r),
                    "flag set {flags:?} dropped required scope '{r}': {out:?}",
                );
            }
        }
    }

    #[test]
    fn optional_in_category_order_renders_profile_read_write_admin() {
        let ordered = optional_in_category_order(google());
        // Locate first index per category; later categories must
        // appear after earlier ones.
        let pos = |cat: ScopeCategory| -> Option<usize> {
            ordered.iter().position(|s| s.category == cat)
        };
        let profile = pos(ScopeCategory::Profile);
        let read = pos(ScopeCategory::Read);
        let write = pos(ScopeCategory::Write);
        let admin = pos(ScopeCategory::Admin);
        // Profile optional exists for Google (userinfo.profile).
        assert!(profile.is_some(), "Google has a Profile optional");
        if let (Some(p), Some(r)) = (profile, read) {
            assert!(p < r);
        }
        if let (Some(r), Some(w)) = (read, write) {
            assert!(r < w);
        }
        if let (Some(w), Some(a)) = (write, admin) {
            assert!(w < a);
        }
    }

    #[test]
    fn explicit_scope_does_not_override_required_floor() {
        // Operator passes only "repo"; required read:user must still
        // appear in the output.
        let flags = ScopeFlags {
            scope: vec!["repo".to_string()],
            ..Default::default()
        };
        let out = resolve_scopes(github(), &flags, true).unwrap();
        assert!(out.contains(&"read:user".to_string()));
        assert!(out.contains(&"repo".to_string()));
    }

    // Slice 3 picker-defaults tests. The non-picker paths
    // (`--no-scopes`, `--all-scopes`, explicit `--scope`) must ignore
    // `picker_defaults` because those flags are the operator's
    // scripted-mode instruction; the picker pre-selection is only
    // relevant when the picker actually runs.

    #[test]
    fn resolve_with_defaults_ignores_defaults_on_no_scopes() {
        let flags = ScopeFlags {
            no_scopes: true,
            ..Default::default()
        };
        let defaults = vec![
            "https://www.googleapis.com/auth/drive.readonly".to_string(),
            "https://www.googleapis.com/auth/gmail.send".to_string(),
        ];
        let out = resolve_scopes_with_defaults(google(), &flags, true, &defaults).unwrap();
        // --no-scopes returns required floor only, even if defaults
        // are non-empty.
        assert!(!out.iter().any(|s| s.ends_with("/drive.readonly")));
        assert!(!out.iter().any(|s| s.ends_with("/gmail.send")));
        assert!(out.contains(&"openid".to_string()));
    }

    #[test]
    fn resolve_with_defaults_ignores_defaults_on_all_scopes() {
        let flags = ScopeFlags {
            all_scopes: true,
            ..Default::default()
        };
        let defaults = vec!["read".to_string()];
        let out = resolve_scopes_with_defaults(linear(), &flags, true, &defaults).unwrap();
        assert_eq!(out.len(), linear().scopes.len());
    }

    #[test]
    fn resolve_with_defaults_ignores_defaults_on_explicit_scope_flag() {
        let flags = ScopeFlags {
            scope: vec!["write".to_string()],
            ..Default::default()
        };
        let defaults = vec!["admin".to_string()];
        let out = resolve_scopes_with_defaults(linear(), &flags, true, &defaults).unwrap();
        // --scope only includes the named ids plus the required
        // floor; the defaults set is irrelevant here.
        assert!(out.contains(&"read".to_string()));
        assert!(out.contains(&"write".to_string()));
        assert!(!out.contains(&"admin".to_string()));
    }

    #[test]
    fn resolve_with_defaults_non_tty_path_still_errors() {
        // No flags + non-TTY errors regardless of defaults: defaults
        // only seed the picker, and the picker cannot run without
        // a TTY.
        let flags = ScopeFlags::default();
        let defaults = vec!["read".to_string()];
        let err = resolve_scopes_with_defaults(linear(), &flags, false, &defaults).unwrap_err();
        assert!(format!("{err}").contains("not a TTY"));
    }

    #[test]
    fn resolve_thin_wrapper_passes_empty_defaults() {
        // The slice 2 entry `resolve_scopes` is a thin wrapper that
        // calls `resolve_scopes_with_defaults` with an empty slice.
        // This regression test asserts the wrapper still produces
        // identical output to the explicit-empty form so future
        // refactors do not silently introduce non-empty defaults.
        let flags = ScopeFlags {
            no_scopes: true,
            ..Default::default()
        };
        let via_wrapper = resolve_scopes(github(), &flags, true).unwrap();
        let via_full = resolve_scopes_with_defaults(github(), &flags, true, &[]).unwrap();
        assert_eq!(via_wrapper, via_full);
    }
}
