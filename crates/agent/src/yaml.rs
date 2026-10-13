//! YAML parsing for skill frontmatter, with the settings every caller
//! shares.

/// Parse YAML into `T`.
///
/// Booleans are `true` and `false` only: a YAML 1.1 `yes`, `no`, `on`
/// or `off` stays a string, so it fails a bool field rather than
/// loading as one. A duplicate mapping key is an error, so a second
/// `allow:` in a permissions block cannot replace the first.
pub fn from_str<'de, T: serde::Deserialize<'de>>(s: &'de str) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_str_with_options(
        s,
        serde_saphyr::options! {
            strict_booleans: true,
            duplicate_keys: serde_saphyr::options::DuplicateKeyPolicy::Error,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::from_str;
    use crate::skill::SkillFrontmatter;
    use crate::skill_perms::PermissionsBlock;

    #[test]
    fn a_yaml_1_1_boolean_does_not_load_as_a_bool() {
        for word in ["yes", "no", "on", "off", "Yes", "NO"] {
            let yaml = format!("name: x\ndisable-model-invocation: {word}\n");
            assert!(
                from_str::<SkillFrontmatter>(&yaml).is_err(),
                "`{word}` loaded as a bool"
            );
        }
    }

    #[test]
    fn true_and_false_load_as_bools() {
        let fm: SkillFrontmatter = from_str("disable-model-invocation: false\n").unwrap();
        assert_eq!(fm.disable_model_invocation, Some(false));
        let fm: SkillFrontmatter = from_str("disable-model-invocation: true\n").unwrap();
        assert_eq!(fm.disable_model_invocation, Some(true));
    }

    #[test]
    fn a_duplicate_key_is_an_error() {
        let yaml = "tools:\n  allow: [read_file]\n  allow: [exec]\n";
        assert!(from_str::<PermissionsBlock>(yaml).is_err());
        let yaml = "name: a\nname: b\n";
        assert!(from_str::<SkillFrontmatter>(yaml).is_err());
    }

    #[test]
    fn a_duplicate_key_inside_untyped_metadata_is_an_error() {
        let yaml = "metadata:\n  wirken:\n    a: 1\n    a: 2\n";
        assert!(from_str::<SkillFrontmatter>(yaml).is_err());
    }
}
