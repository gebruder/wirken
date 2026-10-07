//! `wirken zirkel run` keeps its store under `WIRKEN_DATA_DIR`.
//!
//! The aggregator's store is `<data_dir>/zirkel/aggregator.db`, and the
//! store opens only inside the skill's `filesystem.write_paths`. The
//! preset grants `<data_dir>/zirkel`, so with the data directory moved
//! off `~/.wirken` the grant moves with it. `HOME` points somewhere
//! else entirely, so a grant that named the home directory would refuse
//! the store.

mod common;

use std::process::Output;

use common::wirken;

fn assert_ok(step: &str, out: &Output) {
    assert!(
        out.status.success(),
        "{step} failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn zirkel_run_opens_its_store_in_the_overridden_data_dir() {
    let data = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let out = wirken(data.path())
        .env("HOME", home.path())
        .args(["preset", "install", "zirkel"])
        .output()
        .unwrap();
    assert_ok("preset install", &out);

    // No sources, so the run reaches no network and calls no model; it
    // still opens the store, which is the step under test.
    std::fs::write(data.path().join("presets/zirkel/sources.toml"), "").unwrap();
    std::fs::create_dir_all(data.path().join("zirkel")).unwrap();
    std::fs::write(
        data.path().join("zirkel/interests.toml"),
        "keywords = [\"privacy\"]\nexclusions = []\n",
    )
    .unwrap();

    let out = wirken(data.path())
        .env("HOME", home.path())
        .args(["zirkel", "run"])
        .output()
        .unwrap();
    assert_ok("zirkel run", &out);

    assert!(
        data.path().join("zirkel/aggregator.db").is_file(),
        "the store is in the data directory"
    );
    assert!(
        !home.path().join(".wirken").exists(),
        "nothing is written under the home directory"
    );
}
