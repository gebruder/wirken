# Contributing

## Minimum supported Rust version

MSRV is set by CI's `clippy::incompatible_msrv` lint, not by authorial claim. If a change reaches for a newer stdlib feature, bump `rust-version` in `Cargo.toml` in the same commit and update the README badge. CI will fail fast if MSRV and the code drift apart.

## False green

Ways a run comes back green without the change having been exercised.

**A mechanical edit asserts its pattern matched before it writes.** A find-and-replace that matches nothing returns the input unchanged and raises nothing, so the passing run that follows tells you the edit never happened, not that it worked.

**A fixture carries a populated value of every type the code will meet.** A field left null, or a type left out of the fixture, exercises no path while looking like coverage.

**A new test is observed running, by name, in the runner's output.** A `#[test]` written inside another function's body is a legal local item that the harness never collects: it compiles, the suite passes, and the test does not exist. Passing is not evidence a test ran; seeing its name is.

**A verification claim names the check that actually ran.** "Verified" is not a property of a document, it is a record of a specific check against a specific tree. Say which check and against what, so a reader can tell a claim that was tested from one that was asserted.

**A check that cannot fail against a wrong claim is not verification.** Line-number citations in a doc were re-checked repeatedly for being in range. Files only grow, so the ranges stayed valid while the lines they pointed at moved, and the check kept passing over citations that had stopped being true. A check has to read the thing and compare it to the claim.

**Closing evidence is pasted output. A restated claim is not evidence of the thing it restates.** A slice closes on observed behaviour, so what closes it is the terminal output, the audit row, or the rendered page -- carried across verbatim. A sentence saying the observation was made, however confidently worded and whoever wrote it, is a claim about evidence and not the evidence. This holds in both directions: neither the person doing the work nor the person reviewing it can close a condition by asserting it was met.

**An assertion that a line of code exists is not an assertion that it does anything.** A test pinned `inputArea.hidden = active;` and passed for as long as the composer stayed on screen: an id selector setting `display: flex` outranks the UA stylesheet's `[hidden]` rule, so the assignment had no effect. Where a test can only see the source, assert the mechanism that makes the source matter, not just its presence.

**A gate reads the runner's exit status, not a parsed count.** A pre-commit gate summed passed and failed out of `test result` lines. A failing test binary stops cargo before the later crates run, so the sum was small and the failed count was zero, and a red commit went through on a number that described an aborted run. The count was also parsed wrong the whole time: `; ` splits into an empty field, so the failed column was never read. Cargo's exit code is the gate; counts are a display.

**A lock between the writers of a process-global does not make writing it sound.** Several tests set, read and removed the same environment variable under a mutex, after one of them once read the value a sibling had just written. The lock fixed the flake and not the problem: `std::env::set_var` is undefined behaviour while *any* other thread reads or writes the environment, and a test binary's other threads are reading it constantly (`tempfile` reads `TMPDIR`, the code under test reads its own variables). The lock orders the writers and leaves every reader alone. What the tests wanted was the resolution rule, so the rule moved into a function taking the value as an argument and the tests pass it in. Where a variable genuinely has to be set, because the code reads it somewhere deep, the test goes in its own binary as the only test in it, and the SAFETY comment says so.

**A fixture holding a value production never sends proves nothing about production.** The SSE approval gate's tests set the denial context's `agent_id` to a bare `"default"`. The runtime passes a full session id there. The gate reconstructed a session id from that field, which was correct only for the fixture's value, so four tests agreed with a lookup that missed every time in production. When a fixture stands in for a value the runtime computes, take the value the runtime computes.

## Unsafe code

Every `unsafe` block carries a `SAFETY:` comment stating the invariant that makes it sound. CI enforces it:

```bash
cargo clippy --workspace --all-targets -- -D clippy::undocumented_unsafe_blocks
```

The Win32 peer-credential path in `crates/ipc/src/stream.rs` is behind `cfg(windows)`, so a Linux run never sees it. It is the only `cfg(windows)` unsafe in the tree and is checked for that target separately:

```bash
rustup target add x86_64-pc-windows-gnu
cargo clippy -p wirken-ipc --all-targets --target x86_64-pc-windows-gnu \
    -- -D clippy::undocumented_unsafe_blocks
```

The comment has to state an invariant that actually holds. Most of the `unsafe` in this tree was `std::env::set_var` in tests, where none did: the soundness condition is that no other thread touches the environment, and a test binary's other threads touch it all the time. Those blocks are gone, replaced by functions that take the value as an argument. What remains is three `libc::geteuid()` calls, one `env::remove_var` that runs before anything is spawned, the `cfg(windows)` Win32 calls, and two integration-test binaries that each hold a single test so the single-thread claim is a fact.

If you cannot write a true invariant, the block does not get a comment. It gets replaced.

## Miri

Run per crate, over the crates that contain `unsafe`:

```bash
rustup +nightly component add miri
cargo +nightly miri test -p wirken-ipc
cargo +nightly miri test -p wirken-mcp-proxy
```

Miri interprets Rust. It has no sockets, no filesystem and no C, so a test that opens one is marked `#[cfg_attr(miri, ignore = "...")]` with the reason, rather than deleted. The reason belongs in the attribute: a bare `ignore` reads as a quarantined test.

What this covers, and what it does not. Miri checks the safe code of these crates for undefined behaviour: aliasing, alignment, uninitialised reads, out-of-bounds. It cannot execute the `unsafe` that is left, because all of it is FFI or a syscall Miri has no implementation for. So a green Miri run is evidence about the rest of the crate, not about the `unsafe` lines, and it is worth saying which when you cite one.

`wirken-cli` and `wirken-agent` are not run under Miri. Both build under it, but nearly every test in them opens a file, a socket or a subprocess, so covering them would mean marking several hundred tests ignored. What that would buy is nothing: the `unsafe` those crates hold is three `libc::geteuid()` calls and two single-test binaries that set an environment variable, none of which Miri can execute. If that changes, and one of them grows `unsafe` in code a pure test reaches, gate the I/O tests then and add the crate above.

## Fuzzing

Targets live in `fuzz/`, one per parser at a trust boundary: the IPC frame decoder, the exec classifier, `SKILL.md` frontmatter, and the injection detector. Each asserts no panic plus the invariants its own doc comment states.

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run exec_classifier -- -runs=1000000
cargo +nightly fuzz list
```

CI runs each for 60 seconds on every push. That is a tripwire, not a campaign: it says the committed corpus still passes and that a change did not open a shallow crash. Long runs happen off CI.

Seed corpora are committed under `fuzz/corpus/<target>/` and regenerated by `python3 fuzz/seed_corpus.py`, which reads them out of the tree: `tests/hostile/corpus.jsonl` where the shapes overlap, and real inputs (the bundled `SKILL.md` files, the injection detector's own fixtures) where they do not. What libFuzzer discovers during a run is not committed.

**A crash is a finding about the code under test.** The fix is never to relax the target's assertions, widen a limit, or drop the input from the corpus. `fuzz/artifacts/` keeps the reproducer and the job stays red until the code is fixed. If the assertion itself was wrong, say so in the commit that changes it and show why the property it claimed does not hold.
