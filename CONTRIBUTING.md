# Contributing

## Minimum supported Rust version

MSRV is set by CI's `clippy::incompatible_msrv` lint, not by authorial claim. If a change reaches for a newer stdlib feature, bump `rust-version` in `Cargo.toml` in the same commit and update the README badge. CI will fail fast if MSRV and the code drift apart.

## False green

Two ways a run comes back green without the change having been exercised.

**A mechanical edit asserts its pattern matched before it writes.** A find-and-replace that matches nothing returns the input unchanged and raises nothing, so the passing run that follows tells you the edit never happened, not that it worked.

**A fixture carries a populated value of every type the code will meet.** A field left null, or a type left out of the fixture, exercises no path while looking like coverage.
