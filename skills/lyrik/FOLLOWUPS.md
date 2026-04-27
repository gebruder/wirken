# Lyrik FOLLOWUPS

Boundaries surfaced by real use that need design work beyond what the SKILL.md form can carry. Each entry pairs the boundary with the worked example that surfaced it, so a future decision starts with data instead of speculation.

## 1. Latent / config-dependent finding bucket

Surfaced 2026-04-28 during dogfood on `crates/cli/src/commands/webchat.rs`.

The lyrik report has two streams: `novel` and `regression`. There is no place for a finding that is **dormant under current configuration but live under a plausible config change.**

Worked example: `crates/cli/src/commands/webchat.rs:212-218`. The Origin header strip-prefix is case-sensitive — `Origin: ` and `origin: ` only. Today the bind is `127.0.0.1` (loopback), so the Origin defence has no real network role and the case-sensitivity is moot. A future operator who flips `TcpListener::bind("127.0.0.1:...")` to `0.0.0.0` (one-line change) removes the loopback defence; the case-sensitivity then becomes a CSRF bypass. A client sending `ORIGIN: https://attacker.com` (uppercase) evades the check entirely because `strip_prefix("Origin: ")` and `strip_prefix("origin: ")` both miss; the parser yields `None` and the request proceeds.

In today's report this finding scores 0 ("not a real bug now"). That under-reports the real concern: the only thing keeping it from being a HIGH-severity finding is one git diff line elsewhere in the same file.

**Second case**, surfaced 2026-04-28 during dogfood on `crates/vault/src/crypto.rs`.

The `decrypt` function returns plaintext via `cipher.decrypt` as `Vec<u8>` that lives unzeroed for a brief window before being wrapped in `VaultSecret`. The chacha20poly1305 internal stack state inside that call is also not zeroed by the crate. Today this is graded 0 — defence-in-depth, not exploitable without an additional capability (memory read on the live operator process). Under "operator's machine compromised but keychain entry not yet read" — a real post-compromise lateral-movement threat — the residual key material in stack/heap *is* exploitable via process memory dump or core file. Same shape: graded 0 against the named threat model, would be HIGH in a slightly expanded one. Two cases now: a config-flip threat (Origin) and a threat-model-expansion threat (vault memory hygiene).

Schema questions for whoever picks this up:

- Does `latent` get its own report stream, or extend the existing grade scheme (e.g. `0/H` — "graded zero now, would be H if condition X")?
- How does the agent identify the "condition X" that flips a finding live? Pattern-match on bind addresses and similar config? Explicit operator-named threat models in the rubric?
- How does latent interact with regression? A latent finding later realized by a config change is structurally similar to the reintroduction case the regression stream already names.
- What's the dedup story across runs? If the same latent finding is rediscovered every assessment until the underlying code is fixed, does it suppress after first sighting, or does it keep appearing as a steady-state warning?

Two cases so far, both real. Keep collecting worked cases as dogfooding proceeds — three or four data points before any design lock-in.

## 2. Hardening stream alongside novel and regression

Surfaced 2026-04-28 during dogfood on `crates/vault/src/crypto.rs`.

Several findings from this assessment were not vulnerabilities but API-hardening suggestions: `derive_key_from_passphrase` accepts `&[u8]` salt without enforcing entropy or length; `passphrase: &str` (not `VaultSecret`) means the function can't participate in zeroing the buffer; the `argon2` zeroize feature is not visibly enabled in the vault's `Cargo.toml`. None of these are exploitable today. They are API shapes that make misuse possible.

The four-axis scorer is built for vulnerability findings — *is this a real bug / is the code path reachable / can attacker reach entry / blast radius*. Applied to API-hardening suggestions, the answers come out awkward ("depends on caller" / "yes always" / "depends on caller" / "depends on caller"). The scorer's signal-to-noise drops on these.

Schema questions:

- Should the report carry a third `hardening` stream alongside `novel` and `regression`?
- If yes, what scoring shape applies? Hardening findings don't have a "real bug" axis; they are proposals.
- Does the dedup gate apply? Across runs, the same hardening finding rediscovered every assessment until the underlying API is fixed is still useful as a steady-state warning, but at lower volume than novel findings.
- How is hardening prioritised in the report? Vulnerabilities first is obvious; hardening clusters second, ordered by what?

One worked case so far. Collect more before deciding.

## 3. Intra-run clustering for related-by-root-cause findings

Surfaced 2026-04-28 during dogfood on `crates/vault/src/crypto.rs`.

The vault assessment produced four LOW-tier findings, all variants of "key material may persist in memory after use" (decrypt buffer not zeroed pre-wrap; stack residue from chacha20poly1305 internals; passphrase buffer not zeroable from inside the function; argon2 zeroize feature possibly off). Different code locations, single shared root cause: memory hygiene around key material is partial.

The current dedup gate runs against `.lyrik/prior/` only — historical findings, not other candidates from the same run. Intra-run clustering does not happen. The report renders four separate items where one umbrella finding plus three concrete locations would be cleaner.

Schema questions:

- Should there be a same-run causal grouping pass before the report renders?
- If yes, where in the pipeline — before scoring (so all members of a cluster score together), after scoring (so the cluster's representative score is the max), or render-only (so the report shows umbrella + members but the audit log preserves individual findings)?
- How does the agent decide what is "same root cause" versus "different bugs of the same class"? A causal-tier model call shaped like the dedup causal tier?
- Does the umbrella inherit the highest member's grade, or get its own?

One worked case so far. Look for the pattern again on mcp-proxy and channel adapters before deciding.
