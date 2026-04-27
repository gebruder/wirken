# Lyrik FOLLOWUPS

Boundaries surfaced by real use that need design work beyond what the SKILL.md form can carry. Each entry pairs the boundary with the worked example that surfaced it, so a future decision starts with data instead of speculation.

## 1. Latent / config-dependent finding bucket

Surfaced 2026-04-28 during dogfood on `crates/cli/src/commands/webchat.rs`.

The lyrik report has two streams: `novel` and `regression`. There is no place for a finding that is **dormant under current configuration but live under a plausible config change.**

Worked example: `crates/cli/src/commands/webchat.rs:212-218`. The Origin header strip-prefix is case-sensitive — `Origin: ` and `origin: ` only. Today the bind is `127.0.0.1` (loopback), so the Origin defence has no real network role and the case-sensitivity is moot. A future operator who flips `TcpListener::bind("127.0.0.1:...")` to `0.0.0.0` (one-line change) removes the loopback defence; the case-sensitivity then becomes a CSRF bypass. A client sending `ORIGIN: https://attacker.com` (uppercase) evades the check entirely because `strip_prefix("Origin: ")` and `strip_prefix("origin: ")` both miss; the parser yields `None` and the request proceeds.

In today's report this finding scores 0 ("not a real bug now"). That under-reports the real concern: the only thing keeping it from being a HIGH-severity finding is one git diff line elsewhere in the same file.

Schema questions for whoever picks this up:

- Does `latent` get its own report stream, or extend the existing grade scheme (e.g. `0/H` — "graded zero now, would be H if condition X")?
- How does the agent identify the "condition X" that flips a finding live? Pattern-match on bind addresses and similar config? Explicit operator-named threat models in the rubric?
- How does latent interact with regression? A latent finding later realized by a config change is structurally similar to the reintroduction case the regression stream already names.
- What's the dedup story across runs? If the same latent finding is rediscovered every assessment until the underlying code is fixed, does it suppress after first sighting, or does it keep appearing as a steady-state warning?

Don't decide from one example. Collect three or four worked cases across different surfaces before picking a schema.
