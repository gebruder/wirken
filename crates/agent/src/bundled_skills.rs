//! Bundled skills shipped with wirken.
//! These are installed to ~/.wirken/skills/ on first setup.

use std::path::Path;

struct BundledSkill {
    name: &'static str,
    content: &'static str,
}

const SKILLS: &[BundledSkill] = &[
    BundledSkill {
        name: "weather",
        content: include_str!("../../../skills/weather/SKILL.md"),
    },
    BundledSkill {
        name: "github",
        content: include_str!("../../../skills/github/SKILL.md"),
    },
    BundledSkill {
        name: "git",
        content: include_str!("../../../skills/git/SKILL.md"),
    },
    BundledSkill {
        name: "tmux",
        content: include_str!("../../../skills/tmux/SKILL.md"),
    },
    BundledSkill {
        name: "system-info",
        content: include_str!("../../../skills/system-info/SKILL.md"),
    },
    BundledSkill {
        name: "web-fetch",
        content: include_str!("../../../skills/web-fetch/SKILL.md"),
    },
    BundledSkill {
        name: "docker",
        content: include_str!("../../../skills/docker/SKILL.md"),
    },
    BundledSkill {
        name: "notes",
        content: include_str!("../../../skills/notes/SKILL.md"),
    },
    BundledSkill {
        name: "calculator",
        content: include_str!("../../../skills/calculator/SKILL.md"),
    },
    BundledSkill {
        name: "file-search",
        content: include_str!("../../../skills/file-search/SKILL.md"),
    },
    BundledSkill {
        name: "disk-usage",
        content: include_str!("../../../skills/disk-usage/SKILL.md"),
    },
    BundledSkill {
        name: "process-manager",
        content: include_str!("../../../skills/process-manager/SKILL.md"),
    },
    BundledSkill {
        name: "ssh",
        content: include_str!("../../../skills/ssh/SKILL.md"),
    },
    BundledSkill {
        name: "json-tools",
        content: include_str!("../../../skills/json-tools/SKILL.md"),
    },
    BundledSkill {
        name: "csv-tools",
        content: include_str!("../../../skills/csv-tools/SKILL.md"),
    },
    BundledSkill {
        name: "lyrik",
        content: include_str!("../../../skills/lyrik/SKILL.md"),
    },
];

/// Install bundled skills to a directory. Skips skills that already exist.
/// Returns the number of skills installed.
pub fn install_bundled_skills(skills_dir: &Path) -> std::io::Result<usize> {
    let mut installed = 0;

    for skill in SKILLS {
        let dir = skills_dir.join(skill.name);
        let path = dir.join("SKILL.md");

        if path.exists() {
            continue;
        }

        std::fs::create_dir_all(&dir)?;
        std::fs::write(&path, skill.content)?;
        installed += 1;
    }

    Ok(installed)
}

/// Number of bundled skills.
pub fn bundled_count() -> usize {
    SKILLS.len()
}
