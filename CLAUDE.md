# Wirken repo rules

## What lives in this repo

The wirken repo carries:

- The wirken binary (Rust workspace under `crates/`).
- The Lyrik skill and other bundled skills (`skills/`).
- Published documentation (`docs/`, `README.md`, `CHANGELOG.md`,
  `LICENSE`, `KEYS`, `SECURITY.md`, `install.sh`).

Anything else lives in a sibling directory under `~/code/`, not in
this repo. Concrete examples:

- Benchmark harnesses (e.g. `~/code/lyrik-bench/` for AVB).
- Run outputs and audit logs.
- Model sweeps and bench artifacts.
- Private bench results.

Reasons:

- Upstream corpora (AVB and similar) are separate repos with their
  own licenses.
- Run outputs grow without bound.
- Benchmark methodology wants its own artifact for citation.
- The public wirken repo should not carry private bench results.

If you are about to create a new top-level directory in this repo,
stop and ask.
