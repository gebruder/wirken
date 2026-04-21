# Contributing

## Minimum supported Rust version

MSRV is set by CI's `clippy::incompatible_msrv` lint, not by authorial claim. If a change reaches for a newer stdlib feature, bump `rust-version` in `Cargo.toml` in the same commit and update the README badge. CI will fail fast if MSRV and the code drift apart.
