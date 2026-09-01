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

**A fixture holding a value production never sends proves nothing about production.** The SSE approval gate's tests set the denial context's `agent_id` to a bare `"default"`. The runtime passes a full session id there. The gate reconstructed a session id from that field, which was correct only for the fixture's value, so four tests agreed with a lookup that missed every time in production. When a fixture stands in for a value the runtime computes, take the value the runtime computes.
